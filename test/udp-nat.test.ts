/**
 * Unit tests for src/udp-nat.ts.
 *
 * Covers spec §6 of the networking design doc: flow lifecycle, LRU eviction,
 * idle expiry, ICMP unreach generation, swap-in-progress gate, resetAll, and
 * stats accounting.
 *
 * Uses MockTun (in-memory ReadableStream/WritableStream pair) and
 * MockWispClient + MockWispStream (event-driven, synchronous) plus vitest's
 * fake timers.
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest';
import { UdpNat } from '../src/udp-nat';
import {
  buildIPv4Packet,
  buildUdpSegment,
  parseIPv4,
  parseUdp,
  ipToNum,
  IP_PROTO_UDP,
} from '../src/packet';
import { EgressPolicy } from '../src/policy';
import type { WispClient, WispStream } from '../src/wisp-client';

// ---------------------------------------------------------------------------
// Mock WispStream / WispClient
// ---------------------------------------------------------------------------

class MockWispStream {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  closed: Promise<{ reason: number }>;
  private resolveClosed!: (info: { reason: number }) => void;
  private listeners = new Map<string, Array<(...a: any[]) => void>>();
  isClosed = false;
  closeReason: number | null = null;
  /** Datagrams the NAT has sent through this stream. */
  sent: Uint8Array[] = [];

  constructor(
    public id: number,
    public type: 'tcp' | 'udp',
    public host: string,
    public port: number,
    /** When true, fire 'open' synchronously after construction. */
    autoOpen = true,
  ) {
    this.readable = new ReadableStream({ start: () => {} });
    this.writable = new WritableStream({ write: () => {} });
    this.closed = new Promise((r) => (this.resolveClosed = r));
    if (autoOpen) queueMicrotask(() => this.simulateOpen());
  }

  on(ev: string, fn: (...a: any[]) => void): void {
    let arr = this.listeners.get(ev);
    if (!arr) {
      arr = [];
      this.listeners.set(ev, arr);
    }
    arr.push(fn);
  }

  send(data: Uint8Array): void {
    if (this.isClosed) throw new Error('MockWispStream: closed');
    this.sent.push(data);
  }

  close(reason = 0x02): void {
    if (this.isClosed) return;
    this.isClosed = true;
    this.closeReason = reason;
    this.emit('close', { reason });
    this.resolveClosed({ reason });
  }

  // Test helpers --------------------------------------------------------

  simulateOpen(): void {
    this.emit('open');
  }

  simulateData(bytes: Uint8Array): void {
    this.emit('data', bytes);
  }

  simulateError(err: any): void {
    this.emit('error', err);
  }

  private emit(ev: string, ...args: any[]): void {
    for (const fn of this.listeners.get(ev) ?? []) fn(...args);
  }
}

class MockWispClient {
  udpSupported = true;
  /** All streams ever opened (insertion order). */
  streams: MockWispStream[] = [];
  private nextId = 1;
  /** When true, createStream throws. */
  shouldThrow = false;
  /** When true, new streams stay pending (don't fire 'open'). */
  manualOpen = false;

  createStream(host: string, port: number, type: 'tcp' | 'udp'): WispStream {
    if (this.shouldThrow) throw new Error('mock: createStream rejected');
    const id = this.nextId++;
    const s = new MockWispStream(id, type, host, port, !this.manualOpen);
    this.streams.push(s);
    return s as unknown as WispStream;
  }
}

// ---------------------------------------------------------------------------
// Mock TUN — a pair of streams the NAT consumes/produces
// ---------------------------------------------------------------------------

interface MockTun {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  /** Push an IPv4 packet to the NAT (as if from the guest). */
  push(pkt: Uint8Array): Promise<void>;
  /** Packets the NAT has written back to the guest. */
  written: Uint8Array[];
}

function makeMockTun(): MockTun {
  let pushController!: ReadableStreamDefaultController<Uint8Array>;
  const readable = new ReadableStream<Uint8Array>({
    start(c) {
      pushController = c;
    },
  });
  const written: Uint8Array[] = [];
  const writable = new WritableStream<Uint8Array>({
    write(chunk) {
      written.push(chunk);
    },
  });
  return {
    readable,
    writable,
    written,
    push: async (pkt: Uint8Array) => {
      pushController.enqueue(pkt);
      // Yield so the read loop processes the chunk.
      await Promise.resolve();
      await Promise.resolve();
    },
  };
}

// ---------------------------------------------------------------------------
// Helpers — build inbound IPv4+UDP packets
// ---------------------------------------------------------------------------

function makeUdpPacket(
  srcIp: string,
  srcPort: number,
  dstIp: string,
  dstPort: number,
  payload: Uint8Array,
): Uint8Array {
  const src = ipToNum(srcIp);
  const dst = ipToNum(dstIp);
  const seg = buildUdpSegment(srcPort, dstPort, payload, src, dst);
  return buildIPv4Packet(src, dst, IP_PROTO_UDP, seg);
}

const GUEST_IP = '192.168.127.2';
const RESOLVER_IP = '1.1.1.1';
const SERVER_IP = '93.184.216.34';

// ---------------------------------------------------------------------------
// Common fixture
// ---------------------------------------------------------------------------

interface Fixture {
  tun: MockTun;
  wisp: MockWispClient;
  policy: EgressPolicy;
  nat: UdpNat;
  swap: { value: boolean };
}

async function makeFixture(opts: {
  policy?: EgressPolicy;
  idleTimeoutMs?: number;
  maxFlows?: number;
  manualOpen?: boolean;
  udpSupported?: boolean;
} = {}): Promise<Fixture> {
  const tun = makeMockTun();
  const wisp = new MockWispClient();
  if (opts.manualOpen) wisp.manualOpen = true;
  if (opts.udpSupported === false) wisp.udpSupported = false;
  const policy = opts.policy ?? new EgressPolicy(); // defaults
  const swap = { value: false };
  const nat = new UdpNat({
    tun,
    getWisp: () => wisp as unknown as WispClient,
    getSwapInProgress: () => swap.value,
    policy,
    idleTimeoutMs: opts.idleTimeoutMs,
    maxFlows: opts.maxFlows,
  });
  await nat.start();
  return { tun, wisp, policy, nat, swap };
}

async function settle(): Promise<void> {
  // Allow read loop + any microtask-scheduled 'open' events to flush.
  for (let i = 0; i < 4; i++) await Promise.resolve();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('UdpNat — basic flow', () => {
  let fix: Fixture;
  beforeEach(async () => {
    fix = await makeFixture();
  });
  afterEach(async () => {
    await fix.nat.destroy();
  });

  test('DNS query path: guest → wisp.createStream + queued payload flushed on open', async () => {
    fix.wisp.manualOpen = true; // freeze 'open' so we can observe queueing
    const dnsQuery = new Uint8Array([0xab, 0xcd, 0x01, 0x00, 0, 1]);
    await fix.tun.push(makeUdpPacket(GUEST_IP, 51234, RESOLVER_IP, 53, dnsQuery));
    await settle();

    expect(fix.wisp.streams.length).toBe(1);
    const s = fix.wisp.streams[0]!;
    expect(s.host).toBe(RESOLVER_IP);
    expect(s.port).toBe(53);
    expect(s.type).toBe('udp');
    // Not yet open → payload queued, not sent.
    expect(s.sent.length).toBe(0);

    // Now fire open synchronously; queued payload must flush.
    s.simulateOpen();
    expect(s.sent.length).toBe(1);
    expect(Array.from(s.sent[0]!)).toEqual(Array.from(dnsQuery));

    expect(fix.nat.activeFlows).toBe(1);
    expect(fix.nat.getStats().totalFlowsCreated).toBe(1);
    expect(fix.nat.getStats().totalDatagramsForwarded).toBe(1);
  });

  test('response path: wisp data → IPv4+UDP packet appears on tun.writable', async () => {
    const query = new Uint8Array([1, 2, 3]);
    await fix.tun.push(makeUdpPacket(GUEST_IP, 40000, RESOLVER_IP, 53, query));
    await settle();
    const s = fix.wisp.streams[0]!;
    expect(s.sent.length).toBe(1); // forwarded after auto-open

    const response = new Uint8Array([9, 8, 7, 6, 5]);
    s.simulateData(response);
    // The write is awaited in the NAT; let it land.
    await settle();

    expect(fix.tun.written.length).toBe(1);
    const ipPkt = fix.tun.written[0]!;
    const ip = parseIPv4(ipPkt, 0)!;
    expect(ip.protocol).toBe(IP_PROTO_UDP);
    expect(ip.srcIp).toBe(ipToNum(RESOLVER_IP));
    expect(ip.dstIp).toBe(ipToNum(GUEST_IP));
    const udp = parseUdp(ipPkt, ip.payloadOffset)!;
    expect(udp.srcPort).toBe(53);
    expect(udp.dstPort).toBe(40000);
    const payload = ipPkt.slice(udp.payloadOffset, ip.payloadOffset + ip.payloadLength);
    expect(Array.from(payload)).toEqual(Array.from(response));
  });

  test('multiple datagrams before stream open are queued and flushed in order', async () => {
    fix.wisp.manualOpen = true;
    const a = new Uint8Array([0xaa]);
    const b = new Uint8Array([0xbb]);
    const c = new Uint8Array([0xcc]);
    await fix.tun.push(makeUdpPacket(GUEST_IP, 33333, RESOLVER_IP, 53, a));
    await settle();
    await fix.tun.push(makeUdpPacket(GUEST_IP, 33333, RESOLVER_IP, 53, b));
    await settle();
    await fix.tun.push(makeUdpPacket(GUEST_IP, 33333, RESOLVER_IP, 53, c));
    await settle();

    expect(fix.wisp.streams.length).toBe(1);
    const s = fix.wisp.streams[0]!;
    expect(s.sent.length).toBe(0);

    s.simulateOpen();
    expect(s.sent.length).toBe(3);
    expect(s.sent[0]![0]).toBe(0xaa);
    expect(s.sent[1]![0]).toBe(0xbb);
    expect(s.sent[2]![0]).toBe(0xcc);
  });

  test('same src port to different destinations creates two flows', async () => {
    await fix.tun.push(
      makeUdpPacket(GUEST_IP, 55555, RESOLVER_IP, 53, new Uint8Array([1])),
    );
    await settle();
    await fix.tun.push(
      makeUdpPacket(GUEST_IP, 55555, '8.8.8.8', 53, new Uint8Array([2])),
    );
    await settle();
    expect(fix.wisp.streams.length).toBe(2);
    expect(fix.nat.activeFlows).toBe(2);
  });
});

describe('UdpNat — payload buffer isolation', () => {
  test('queued payload survives caller buffer mutation', async () => {
    const fix = await makeFixture({ manualOpen: true });
    try {
      const payload = new Uint8Array([1, 2, 3, 4]);
      const pkt = makeUdpPacket(GUEST_IP, 41000, RESOLVER_IP, 53, payload);
      await fix.tun.push(pkt);
      await settle();
      // Mutate the original packet bytes after queueing.
      pkt.fill(0);
      const s = fix.wisp.streams[0]!;
      s.simulateOpen();
      expect(s.sent.length).toBe(1);
      // Sent payload must reflect the value at queue-time, not the post-mutation zeros.
      expect(Array.from(s.sent[0]!)).toEqual([1, 2, 3, 4]);
    } finally {
      await fix.nat.destroy();
    }
  });
});

describe('UdpNat — idle expiry', () => {
  test('flow is removed and stream closed after idleTimeoutMs', async () => {
    vi.useFakeTimers({ now: 0 });
    try {
      const fix = await makeFixture({ idleTimeoutMs: 60_000 });
      try {
        await fix.tun.push(
          makeUdpPacket(GUEST_IP, 60000, RESOLVER_IP, 53, new Uint8Array([1])),
        );
        await settle();
        expect(fix.nat.activeFlows).toBe(1);
        const s = fix.wisp.streams[0]!;

        vi.setSystemTime(60_001);
        // Run sweeper once. Sweeper interval = min(idle/4, 15000) = 15000.
        await vi.advanceTimersByTimeAsync(15_001);

        expect(fix.nat.activeFlows).toBe(0);
        expect(s.isClosed).toBe(true);
      } finally {
        await fix.nat.destroy();
      }
    } finally {
      vi.useRealTimers();
    }
  });

  test('flow is NOT removed when within idle window', async () => {
    vi.useFakeTimers({ now: 0 });
    try {
      const fix = await makeFixture({ idleTimeoutMs: 60_000 });
      try {
        await fix.tun.push(
          makeUdpPacket(GUEST_IP, 60001, RESOLVER_IP, 53, new Uint8Array([1])),
        );
        await settle();
        expect(fix.nat.activeFlows).toBe(1);

        vi.setSystemTime(30_000);
        await vi.advanceTimersByTimeAsync(15_000);
        expect(fix.nat.activeFlows).toBe(1);
      } finally {
        await fix.nat.destroy();
      }
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('UdpNat — max flows + LRU eviction', () => {
  test('exceeding maxFlows evicts the LRU (oldest lastActivity) flow', async () => {
    vi.useFakeTimers({ now: 1_000 });
    try {
      const fix = await makeFixture({ maxFlows: 2 });
      try {
        // Flow A at t=1000
        await fix.tun.push(
          makeUdpPacket(GUEST_IP, 1, RESOLVER_IP, 53, new Uint8Array([1])),
        );
        await settle();

        // Flow B at t=2000
        vi.setSystemTime(2_000);
        await fix.tun.push(
          makeUdpPacket(GUEST_IP, 2, RESOLVER_IP, 53, new Uint8Array([2])),
        );
        await settle();
        expect(fix.nat.activeFlows).toBe(2);

        // Flow C at t=3000 → must evict A (oldest).
        vi.setSystemTime(3_000);
        await fix.tun.push(
          makeUdpPacket(GUEST_IP, 3, RESOLVER_IP, 53, new Uint8Array([3])),
        );
        await settle();

        expect(fix.nat.activeFlows).toBe(2);
        // The first stream (A) must have been closed.
        const [a, b, c] = fix.wisp.streams;
        expect(a!.isClosed).toBe(true);
        expect(b!.isClosed).toBe(false);
        expect(c!.isClosed).toBe(false);
      } finally {
        await fix.nat.destroy();
      }
    } finally {
      vi.useRealTimers();
    }
  });

  test('LRU is by lastActivity, not creation time', async () => {
    vi.useFakeTimers({ now: 0 });
    try {
      const fix = await makeFixture({ maxFlows: 2 });
      try {
        // A at t=0
        await fix.tun.push(
          makeUdpPacket(GUEST_IP, 1, RESOLVER_IP, 53, new Uint8Array([1])),
        );
        await settle();
        // B at t=1
        vi.setSystemTime(1);
        await fix.tun.push(
          makeUdpPacket(GUEST_IP, 2, RESOLVER_IP, 53, new Uint8Array([2])),
        );
        await settle();
        // Touch A at t=2 (so A is most-recent).
        vi.setSystemTime(2);
        await fix.tun.push(
          makeUdpPacket(GUEST_IP, 1, RESOLVER_IP, 53, new Uint8Array([1, 1])),
        );
        await settle();
        // Add C at t=3 → must evict B (oldest activity).
        vi.setSystemTime(3);
        await fix.tun.push(
          makeUdpPacket(GUEST_IP, 3, RESOLVER_IP, 53, new Uint8Array([3])),
        );
        await settle();

        const [a, b, c] = fix.wisp.streams;
        expect(a!.isClosed).toBe(false);
        expect(b!.isClosed).toBe(true);
        expect(c!.isClosed).toBe(false);
      } finally {
        await fix.nat.destroy();
      }
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('UdpNat — policy denial', () => {
  test('denied destination → no Wisp stream + ICMP unreach to guest', async () => {
    // Default policy denies RFC1918 ranges.
    const fix = await makeFixture();
    try {
      const pkt = makeUdpPacket(GUEST_IP, 12345, '10.0.0.5', 53, new Uint8Array([1]));
      await fix.tun.push(pkt);
      await settle();

      expect(fix.wisp.streams.length).toBe(0);
      expect(fix.tun.written.length).toBe(1);
      const icmp = fix.tun.written[0]!;
      const ip = parseIPv4(icmp, 0)!;
      // ICMP has protocol 1.
      expect(ip.protocol).toBe(1);
      // Source is the original dst (the upstream "speaker"), dst is guest.
      expect(ip.srcIp).toBe(ipToNum('10.0.0.5'));
      expect(ip.dstIp).toBe(ipToNum(GUEST_IP));
      expect(fix.nat.getStats().totalDatagramsDropped).toBe(1);
      expect(fix.nat.getStats().totalDatagramsForwarded).toBe(0);
    } finally {
      await fix.nat.destroy();
    }
  });
});

describe('UdpNat — server does not support UDP', () => {
  test('udpSupported=false → ICMP unreach + no stream', async () => {
    const fix = await makeFixture({ udpSupported: false });
    try {
      await fix.tun.push(
        makeUdpPacket(GUEST_IP, 5353, RESOLVER_IP, 53, new Uint8Array([1])),
      );
      await settle();
      expect(fix.wisp.streams.length).toBe(0);
      expect(fix.tun.written.length).toBe(1);
      const ip = parseIPv4(fix.tun.written[0]!, 0)!;
      expect(ip.protocol).toBe(1); // ICMP
    } finally {
      await fix.nat.destroy();
    }
  });
});

describe('UdpNat — swap-in-progress gate', () => {
  test('drops packets during swap; resumes after swap clears', async () => {
    const fix = await makeFixture();
    try {
      fix.swap.value = true;
      await fix.tun.push(
        makeUdpPacket(GUEST_IP, 6000, RESOLVER_IP, 53, new Uint8Array([1])),
      );
      await settle();
      expect(fix.wisp.streams.length).toBe(0);
      expect(fix.nat.getStats().totalDatagramsDropped).toBe(1);

      // Clear swap; next packet creates a flow normally.
      fix.swap.value = false;
      await fix.tun.push(
        makeUdpPacket(GUEST_IP, 6000, RESOLVER_IP, 53, new Uint8Array([2])),
      );
      await settle();
      expect(fix.wisp.streams.length).toBe(1);
      expect(fix.nat.activeFlows).toBe(1);
    } finally {
      await fix.nat.destroy();
    }
  });
});

describe('UdpNat — resetAll', () => {
  test('closes all streams, clears flows, returns count, no guest packets', async () => {
    const fix = await makeFixture();
    try {
      await fix.tun.push(
        makeUdpPacket(GUEST_IP, 1, RESOLVER_IP, 53, new Uint8Array([1])),
      );
      await settle();
      await fix.tun.push(
        makeUdpPacket(GUEST_IP, 2, '8.8.8.8', 53, new Uint8Array([2])),
      );
      await settle();
      await fix.tun.push(
        makeUdpPacket(GUEST_IP, 3, '9.9.9.9', 53, new Uint8Array([3])),
      );
      await settle();
      expect(fix.nat.activeFlows).toBe(3);

      const writtenBefore = fix.tun.written.length;
      const n = fix.nat.resetAll();
      expect(n).toBe(3);
      expect(fix.nat.activeFlows).toBe(0);
      for (const s of fix.wisp.streams) expect(s.isClosed).toBe(true);
      // No new packets sent to guest (UDP is connectionless).
      expect(fix.tun.written.length).toBe(writtenBefore);
    } finally {
      await fix.nat.destroy();
    }
  });
});

describe('UdpNat — getStats accounting', () => {
  test('counts flows, forwarded, and dropped correctly', async () => {
    const fix = await makeFixture();
    try {
      // 1 forwarded
      await fix.tun.push(
        makeUdpPacket(GUEST_IP, 1, RESOLVER_IP, 53, new Uint8Array([1])),
      );
      await settle();
      // Same flow, another forward
      await fix.tun.push(
        makeUdpPacket(GUEST_IP, 1, RESOLVER_IP, 53, new Uint8Array([2])),
      );
      await settle();
      // Policy-denied (drop)
      await fix.tun.push(
        makeUdpPacket(GUEST_IP, 1, '10.0.0.1', 53, new Uint8Array([3])),
      );
      await settle();

      const stats = fix.nat.getStats();
      expect(stats.activeFlows).toBe(1);
      expect(stats.totalFlowsCreated).toBe(1);
      expect(stats.totalDatagramsForwarded).toBe(2);
      expect(stats.totalDatagramsDropped).toBe(1);
    } finally {
      await fix.nat.destroy();
    }
  });
});

describe('UdpNat — stream errors', () => {
  test("stream 'close' event removes the flow", async () => {
    const fix = await makeFixture();
    try {
      await fix.tun.push(
        makeUdpPacket(GUEST_IP, 1, RESOLVER_IP, 53, new Uint8Array([1])),
      );
      await settle();
      expect(fix.nat.activeFlows).toBe(1);
      const s = fix.wisp.streams[0]!;
      s.close(0x05);
      expect(fix.nat.activeFlows).toBe(0);
    } finally {
      await fix.nat.destroy();
    }
  });

  test('createStream throwing → flow not registered, datagram dropped', async () => {
    const fix = await makeFixture();
    try {
      fix.wisp.shouldThrow = true;
      await fix.tun.push(
        makeUdpPacket(GUEST_IP, 1, RESOLVER_IP, 53, new Uint8Array([1])),
      );
      await settle();
      expect(fix.nat.activeFlows).toBe(0);
      expect(fix.nat.getStats().totalDatagramsDropped).toBe(1);
      // Next datagram retries (and now succeeds).
      fix.wisp.shouldThrow = false;
      await fix.tun.push(
        makeUdpPacket(GUEST_IP, 1, RESOLVER_IP, 53, new Uint8Array([2])),
      );
      await settle();
      expect(fix.nat.activeFlows).toBe(1);
    } finally {
      await fix.nat.destroy();
    }
  });
});
