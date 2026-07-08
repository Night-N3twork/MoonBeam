/**
 * Tests for src/tcp-nat.ts. Per spec §5.
 *
 * Strategy:
 *   - MockTun: a pair of TransformStream-style queues. Tests push raw IPv4
 *     packets to `tun.readable` (via a controller) and capture outbound
 *     packets written to `tun.writable`.
 *   - MockWispClient / MockWispStream: just enough surface (createStream,
 *     confirmStreamOpen, on('open'|'data'|'close'|'error'), send, close) for
 *     TcpNat to operate against. Tests trigger events directly on the mock
 *     stream to simulate upstream behavior.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { TcpNat, type TcpNatConfig } from '../src/tcp-nat';
import { EgressPolicy } from '../src/policy';
import {
  IP_PROTO_TCP,
  TCP_ACK,
  TCP_FIN,
  TCP_PSH,
  TCP_RST,
  TCP_SYN,
  buildIPv4Packet,
  buildTcpSegment,
  ipToNum,
  parseIPv4,
  parseTcp,
} from '../src/packet';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

interface CapturedPacket {
  raw: Uint8Array;
  srcIp: number;
  dstIp: number;
  srcPort: number;
  dstPort: number;
  flags: number;
  seq: number;
  ack: number;
  payload: Uint8Array;
}

class MockTun {
  private inboundController!: ReadableStreamDefaultController<Uint8Array>;
  readonly captured: CapturedPacket[] = [];

  readable = new ReadableStream<Uint8Array>({
    start: (controller) => {
      this.inboundController = controller;
    },
  });

  writable = new WritableStream<Uint8Array>({
    write: (chunk) => {
      const ip = parseIPv4(chunk, 0);
      if (!ip) return;
      const tcp = parseTcp(chunk, ip.payloadOffset);
      if (!tcp) return;
      const payloadLen = ip.payloadOffset + ip.payloadLength - tcp.payloadOffset;
      const payload =
        payloadLen > 0 ? chunk.slice(tcp.payloadOffset, tcp.payloadOffset + payloadLen) : new Uint8Array(0);
      this.captured.push({
        raw: chunk.slice(),
        srcIp: ip.srcIp,
        dstIp: ip.dstIp,
        srcPort: tcp.srcPort,
        dstPort: tcp.dstPort,
        flags: tcp.flags,
        seq: tcp.seqNum,
        ack: tcp.ackNum,
        payload,
      });
    },
  });

  /** Push an IPv4 packet upstream as if produced by lwIP. */
  push(packet: Uint8Array): void {
    this.inboundController.enqueue(packet);
  }

  /** Signal end-of-stream; lets the read loop in TcpNat exit cleanly. */
  end(): void {
    try {
      this.inboundController.close();
    } catch {
      /* already closed */
    }
  }
}

type Listener = (...args: any[]) => void;

class MockWispStream {
  private listeners = new Map<string, Set<Listener>>();
  sent: Uint8Array[] = [];
  closed = false;
  closeReason: number | undefined;

  constructor(
    readonly host: string,
    readonly port: number,
    readonly type: 'tcp' | 'udp',
  ) {}

  on(event: string, listener: Listener): void {
    let set = this.listeners.get(event);
    if (!set) {
      set = new Set();
      this.listeners.set(event, set);
    }
    set.add(listener);
  }

  send(data: Uint8Array): void {
    if (this.closed) throw new Error('stream closed');
    this.sent.push(data);
  }

  close(reason?: number): void {
    if (this.closed) return;
    this.closed = true;
    this.closeReason = reason;
  }

  // Test helpers — drive the simulated upstream.
  _emit(event: string, ...args: any[]): void {
    const set = this.listeners.get(event);
    if (!set) return;
    for (const l of [...set]) l(...args);
  }
  fireOpen(): void {
    this._emit('open');
  }
  fireData(bytes: Uint8Array): void {
    this._emit('data', bytes);
  }
  fireClose(reason = 0x02): void {
    this.closed = true;
    this._emit('close', { reason });
  }
  fireError(err = new Error('upstream error')): void {
    this._emit('error', err);
  }
}

class MockWispClient {
  confirmStreamOpen = false;
  streams: MockWispStream[] = [];
  /** If set, createStream throws this error instead of returning a stream. */
  failNextCreate: Error | null = null;

  createStream(host: string, port: number, type: 'tcp' | 'udp'): MockWispStream {
    if (this.failNextCreate) {
      const err = this.failNextCreate;
      this.failNextCreate = null;
      throw err;
    }
    const s = new MockWispStream(host, port, type);
    this.streams.push(s);
    return s;
  }

  /** Latest stream; convenience for tests that open one. */
  get latest(): MockWispStream {
    return this.streams[this.streams.length - 1];
  }
}

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

const GUEST_IP = ipToNum('192.168.127.2');
const GUEST_PORT = 49152;
const REMOTE_IP = ipToNum('93.184.216.34');
const REMOTE_PORT = 80;
const VM_INITIAL_SEQ = 1000;

interface Fixture {
  tun: MockTun;
  wisp: MockWispClient;
  nat: TcpNat;
  swapInProgress: { value: boolean };
  startPromise: Promise<void>;
}

function makeFixture(opts: Partial<TcpNatConfig> & { policy?: EgressPolicy } = {}): Fixture {
  const tun = new MockTun();
  const wisp = new MockWispClient();
  const swapInProgress = { value: false };
  const policy = opts.policy ?? new EgressPolicy({ allow: ['*'] });
  const nat = new TcpNat({
    tun,
    getWisp: () => wisp as unknown as import('../src/wisp-client').WispClient,
    getSwapInProgress: () => swapInProgress.value,
    policy,
    maxSwapQueue: opts.maxSwapQueue,
  });
  const startPromise = nat.start();
  return { tun, wisp, nat, swapInProgress, startPromise };
}

async function teardown(f: Fixture): Promise<void> {
  f.tun.end();
  await f.nat.destroy();
  await f.startPromise.catch(() => undefined);
}

/** Build a SYN packet from guest -> remote. */
function buildSyn(seq = VM_INITIAL_SEQ): Uint8Array {
  const seg = buildTcpSegment(
    GUEST_PORT,
    REMOTE_PORT,
    seq,
    0,
    TCP_SYN,
    65535,
    new Uint8Array(0),
    GUEST_IP,
    REMOTE_IP,
  );
  return buildIPv4Packet(GUEST_IP, REMOTE_IP, IP_PROTO_TCP, seg);
}

function buildAck(
  seq: number,
  ack: number,
  payload: Uint8Array = new Uint8Array(0),
  extraFlags = 0,
): Uint8Array {
  const seg = buildTcpSegment(
    GUEST_PORT,
    REMOTE_PORT,
    seq,
    ack,
    TCP_ACK | extraFlags,
    65535,
    payload,
    GUEST_IP,
    REMOTE_IP,
  );
  return buildIPv4Packet(GUEST_IP, REMOTE_IP, IP_PROTO_TCP, seg);
}

function buildFin(seq: number, ack: number): Uint8Array {
  return buildAck(seq, ack, new Uint8Array(0), TCP_FIN);
}

function buildRst(seq: number, ack: number): Uint8Array {
  return buildAck(seq, ack, new Uint8Array(0), TCP_RST);
}

/** Yield to the event loop / microtask queue so the TcpNat read loop can
 *  consume queued packets and run handlers. */
async function flush(): Promise<void> {
  // Several macrotask hops cover stream-controller propagation + writes.
  for (let i = 0; i < 4; i++) await new Promise((r) => setTimeout(r, 0));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('TcpNat — new connection (optimistic SYN-ACK, !confirmStreamOpen)', () => {
  let f: Fixture;
  beforeEach(() => {
    f = makeFixture();
  });
  afterEach(() => teardown(f));

  it('emits SYN-ACK with correct seq/ack and opens a Wisp stream', async () => {
    f.tun.push(buildSyn(VM_INITIAL_SEQ));
    await flush();

    expect(f.wisp.streams).toHaveLength(1);
    const s = f.wisp.latest;
    expect(s.host).toBe('93.184.216.34');
    expect(s.port).toBe(REMOTE_PORT);
    expect(s.type).toBe('tcp');

    expect(f.tun.captured).toHaveLength(1);
    const synAck = f.tun.captured[0];
    // NAT transparency: guest sees src=remote, dst=guest.
    expect(synAck.srcIp).toBe(REMOTE_IP);
    expect(synAck.dstIp).toBe(GUEST_IP);
    expect(synAck.srcPort).toBe(REMOTE_PORT);
    expect(synAck.dstPort).toBe(GUEST_PORT);
    expect(synAck.flags & TCP_SYN).toBeTruthy();
    expect(synAck.flags & TCP_ACK).toBeTruthy();
    expect(synAck.ack).toBe((VM_INITIAL_SEQ + 1) >>> 0);

    expect(f.nat.activeConnections).toBe(1);
  });
});

describe('TcpNat — new connection with confirmStreamOpen', () => {
  let f: Fixture;
  beforeEach(() => {
    f = makeFixture();
    f.wisp.confirmStreamOpen = true;
  });
  afterEach(() => teardown(f));

  it('defers SYN-ACK until stream "open" fires', async () => {
    f.tun.push(buildSyn());
    await flush();

    expect(f.wisp.streams).toHaveLength(1);
    expect(f.tun.captured).toHaveLength(0); // no SYN-ACK yet

    f.wisp.latest.fireOpen();
    await flush();

    expect(f.tun.captured).toHaveLength(1);
    const synAck = f.tun.captured[0];
    expect(synAck.flags & (TCP_SYN | TCP_ACK)).toBe(TCP_SYN | TCP_ACK);
  });

  it('sends RST and drops conn when stream errors before open', async () => {
    f.tun.push(buildSyn());
    await flush();

    f.wisp.latest.fireError();
    await flush();

    expect(f.tun.captured).toHaveLength(1);
    const rst = f.tun.captured[0];
    expect(rst.flags & TCP_RST).toBeTruthy();
    expect(f.nat.activeConnections).toBe(0);
  });
});

describe('TcpNat — policy denial', () => {
  let f: Fixture;
  beforeEach(() => {
    // Default 'public' policy — REMOTE_IP (93.184.216.34) is public, so
    // we explicitly construct a policy that denies it.
    f = makeFixture({
      policy: new EgressPolicy({ allow: ['public'], deny: ['93.184.216.0/24'] }),
    });
  });
  afterEach(() => teardown(f));

  it('sends RST immediately, opens no stream, registers no conn', async () => {
    f.tun.push(buildSyn());
    await flush();

    expect(f.wisp.streams).toHaveLength(0);
    expect(f.tun.captured).toHaveLength(1);
    const rst = f.tun.captured[0];
    expect(rst.flags & TCP_RST).toBeTruthy();
    // RST per RFC 793: ack should be SYN.seq + 1 (SYN consumes 1).
    expect(rst.ack).toBe((VM_INITIAL_SEQ + 1) >>> 0);
    expect(f.nat.activeConnections).toBe(0);
  });
});

describe('TcpNat — guest-side data flow', () => {
  let f: Fixture;
  beforeEach(() => {
    f = makeFixture();
  });
  afterEach(() => teardown(f));

  it('forwards ACK+data to the Wisp stream and ACKs the guest', async () => {
    f.tun.push(buildSyn());
    await flush();
    const synAck = f.tun.captured[0];
    f.tun.captured.length = 0;

    // Guest acks our SYN-ACK and immediately sends payload.
    const payload = new TextEncoder().encode('GET / HTTP/1.0\r\n\r\n');
    f.tun.push(
      buildAck(
        (VM_INITIAL_SEQ + 1) >>> 0,
        (synAck.seq + 1) >>> 0,
        payload,
        TCP_PSH,
      ),
    );
    await flush();

    expect(f.wisp.latest.sent).toHaveLength(1);
    expect(Array.from(f.wisp.latest.sent[0])).toEqual(Array.from(payload));

    // The NAT should have ACK'd the data.
    expect(f.tun.captured.length).toBeGreaterThanOrEqual(1);
    const ackPkt = f.tun.captured[f.tun.captured.length - 1];
    expect(ackPkt.flags & TCP_ACK).toBeTruthy();
    expect(ackPkt.ack).toBe((VM_INITIAL_SEQ + 1 + payload.length) >>> 0);
  });

  it('drops out-of-order data (no buffering)', async () => {
    f.tun.push(buildSyn());
    await flush();
    const synAck = f.tun.captured[0];
    f.tun.captured.length = 0;

    // Wrong seq (skipping ahead by 100).
    const payload = new Uint8Array([1, 2, 3]);
    f.tun.push(
      buildAck(
        (VM_INITIAL_SEQ + 1 + 100) >>> 0,
        (synAck.seq + 1) >>> 0,
        payload,
        TCP_PSH,
      ),
    );
    await flush();

    expect(f.wisp.latest.sent).toHaveLength(0);
    expect(f.tun.captured).toHaveLength(0);
  });
});

describe('TcpNat — server-side data flow', () => {
  let f: Fixture;
  beforeEach(() => {
    f = makeFixture();
  });
  afterEach(() => teardown(f));

  it('delivers Wisp DATA to the guest as TCP PSH|ACK', async () => {
    f.tun.push(buildSyn());
    await flush();
    f.tun.captured.length = 0;

    const reply = new TextEncoder().encode('HTTP/1.0 200 OK\r\n');
    f.wisp.latest.fireData(reply);
    await flush();

    expect(f.tun.captured).toHaveLength(1);
    const pkt = f.tun.captured[0];
    expect(pkt.flags & TCP_PSH).toBeTruthy();
    expect(pkt.flags & TCP_ACK).toBeTruthy();
    expect(pkt.srcIp).toBe(REMOTE_IP);
    expect(pkt.dstIp).toBe(GUEST_IP);
    expect(Array.from(pkt.payload)).toEqual(Array.from(reply));
    // ack to guest: still vmSeqNext = synSeq + 1 (no data from guest yet).
    expect(pkt.ack).toBe((VM_INITIAL_SEQ + 1) >>> 0);
  });

  it('chunks an oversized Wisp DATA into MSS-sized segments (regression: QEMU virtio crashes on >MTU frames)', async () => {
    // Regression: Wisp can deliver arbitrarily-sized data chunks (a TLS
    // application record can easily be 8-16 KB), but the guest's virtio-net
    // driver expects ≤1500B frames unless we negotiate GSO offload (we
    // don't). Without chunking, the guest kernel logged "TCP: eth0:
    // Driver has suspect GRO implementation" and QEMU's wasm crashed
    // with OOB in g_main_context_dispatch.
    f.tun.push(buildSyn());
    await flush();
    f.tun.captured.length = 0;

    // 4500 bytes → expect 4 segments at MSS=1460: 1460 + 1460 + 1460 + 120.
    const big = new Uint8Array(4500);
    for (let i = 0; i < big.length; i++) big[i] = i & 0xff;
    f.wisp.latest.fireData(big);
    await flush();

    expect(f.tun.captured.length).toBe(4);

    const sizes = f.tun.captured.map((p) => p.payload.length);
    expect(sizes).toEqual([1460, 1460, 1460, 120]);

    // PSH only on the last segment; mid-burst segments are plain ACKs.
    const flagsList = f.tun.captured.map((p) => ({
      psh: !!(p.flags & TCP_PSH),
      ack: !!(p.flags & TCP_ACK),
    }));
    expect(flagsList).toEqual([
      { psh: false, ack: true },
      { psh: false, ack: true },
      { psh: false, ack: true },
      { psh: true, ack: true },
    ]);

    // Sequence numbers must advance monotonically by each segment's length.
    let expectedSeq = f.tun.captured[0]!.seq;
    for (const p of f.tun.captured) {
      expect(p.seq).toBe(expectedSeq >>> 0);
      expectedSeq = (expectedSeq + p.payload.length) >>> 0;
    }

    // Concatenated payload should be byte-for-byte identical to input.
    const stitched = new Uint8Array(big.length);
    let off = 0;
    for (const p of f.tun.captured) {
      stitched.set(p.payload, off);
      off += p.payload.length;
    }
    expect(Array.from(stitched)).toEqual(Array.from(big));
  });

  it('does not chunk payloads that fit in one MSS', async () => {
    f.tun.push(buildSyn());
    await flush();
    f.tun.captured.length = 0;

    const exactMss = new Uint8Array(1460);
    f.wisp.latest.fireData(exactMss);
    await flush();

    // Exactly 1460 bytes → one segment, PSH set (it's the last/only one).
    expect(f.tun.captured.length).toBe(1);
    expect(f.tun.captured[0]!.payload.length).toBe(1460);
    expect(f.tun.captured[0]!.flags & TCP_PSH).toBeTruthy();
  });
});

describe('TcpNat — connection teardown', () => {
  let f: Fixture;
  beforeEach(() => {
    f = makeFixture();
  });
  afterEach(() => teardown(f));

  it('FIN from guest → ACK + Wisp stream closed', async () => {
    f.tun.push(buildSyn());
    await flush();
    const synAck = f.tun.captured[0];
    f.tun.captured.length = 0;

    f.tun.push(buildFin((VM_INITIAL_SEQ + 1) >>> 0, (synAck.seq + 1) >>> 0));
    await flush();

    // The NAT ACKs the FIN.
    expect(f.tun.captured.length).toBeGreaterThanOrEqual(1);
    const ackPkt = f.tun.captured[f.tun.captured.length - 1];
    expect(ackPkt.flags & TCP_ACK).toBeTruthy();
    // ack = vmSeqNext + 1 (FIN consumes 1).
    expect(ackPkt.ack).toBe((VM_INITIAL_SEQ + 2) >>> 0);
    // Wisp stream was closed.
    expect(f.wisp.latest.closed).toBe(true);
  });

  it('RST from guest → stream closed, conn deleted', async () => {
    f.tun.push(buildSyn());
    await flush();
    const synAck = f.tun.captured[0];
    f.tun.captured.length = 0;

    f.tun.push(buildRst((VM_INITIAL_SEQ + 1) >>> 0, (synAck.seq + 1) >>> 0));
    await flush();

    expect(f.wisp.latest.closed).toBe(true);
    expect(f.nat.activeConnections).toBe(0);
    // No outbound packet (RST elicits no response).
    expect(f.tun.captured).toHaveLength(0);
  });

  it('Server stream close → FIN-ACK to guest with correct seq', async () => {
    f.tun.push(buildSyn());
    await flush();
    const synAck = f.tun.captured[0];
    f.tun.captured.length = 0;

    f.wisp.latest.fireClose();
    await flush();

    expect(f.tun.captured).toHaveLength(1);
    const fin = f.tun.captured[0];
    expect(fin.flags & TCP_FIN).toBeTruthy();
    expect(fin.flags & TCP_ACK).toBeTruthy();
    // seq should be ourSeqBase + 1 (SYN-ACK consumed 1; no data sent).
    expect(fin.seq).toBe((synAck.seq + 1) >>> 0);
  });

  it('Stream error after established → RST to guest, conn deleted', async () => {
    f.tun.push(buildSyn());
    await flush();
    f.tun.captured.length = 0;

    f.wisp.latest.fireError();
    await flush();

    expect(f.tun.captured).toHaveLength(1);
    expect(f.tun.captured[0].flags & TCP_RST).toBeTruthy();
    expect(f.nat.activeConnections).toBe(0);
  });
});

describe('TcpNat — swap-in-progress gate', () => {
  let f: Fixture;
  beforeEach(() => {
    f = makeFixture({ maxSwapQueue: 3 });
  });
  afterEach(() => teardown(f));

  it('queues SYNs while swap is in progress; opens streams after drain', async () => {
    f.swapInProgress.value = true;

    f.tun.push(buildSyn(1000));
    f.tun.push(buildSyn(2000));
    await flush();

    expect(f.wisp.streams).toHaveLength(0);
    expect(f.tun.captured).toHaveLength(0);
    expect(f.nat.swapQueueLength).toBe(2);

    // Swap completes — gateway clears the flag and triggers drain.
    f.swapInProgress.value = false;
    f.nat.drainSwapQueue();
    await flush();

    expect(f.wisp.streams).toHaveLength(2);
    expect(f.nat.swapQueueLength).toBe(0);
    // SYN-ACKs visible.
    expect(f.tun.captured.length).toBeGreaterThanOrEqual(2);
    const synAcks = f.tun.captured.filter((p) => (p.flags & (TCP_SYN | TCP_ACK)) === (TCP_SYN | TCP_ACK));
    expect(synAcks).toHaveLength(2);
  });

  it('overflow → RST to guest', async () => {
    f.swapInProgress.value = true;

    // Fill the queue (size 3).
    f.tun.push(buildSyn(1000));
    f.tun.push(buildSyn(2000));
    f.tun.push(buildSyn(3000));
    await flush();
    expect(f.nat.swapQueueLength).toBe(3);

    // Use a different src port so a 4th SYN doesn't dedupe with an existing
    // flow (none of these have flows yet — they're all queued — but a clean
    // 4th packet keeps the test direct).
    const seg = buildTcpSegment(
      GUEST_PORT + 1,
      REMOTE_PORT,
      4000,
      0,
      TCP_SYN,
      65535,
      new Uint8Array(0),
      GUEST_IP,
      REMOTE_IP,
    );
    f.tun.push(buildIPv4Packet(GUEST_IP, REMOTE_IP, IP_PROTO_TCP, seg));
    await flush();

    expect(f.nat.swapQueueLength).toBe(3); // unchanged
    expect(f.tun.captured).toHaveLength(1);
    expect(f.tun.captured[0].flags & TCP_RST).toBeTruthy();
    expect(f.tun.captured[0].ack).toBe((4000 + 1) >>> 0);
  });

  it('auto-drains when getSwapInProgress() transitions to false', async () => {
    f.swapInProgress.value = true;
    f.tun.push(buildSyn(1000));
    await flush();
    expect(f.nat.swapQueueLength).toBe(1);

    // Flip flag then trigger any packet so the auto-drain edge is observed.
    // Use an unrelated packet (a stray TCP packet that won't match any
    // conn — gets dropped, which is fine).
    f.swapInProgress.value = false;
    const stray = buildAck(0, 0); // unknown flow → ignored
    // Different src port to avoid collision with the queued SYN's tuple
    // when it eventually drains.
    const seg = buildTcpSegment(
      GUEST_PORT + 99,
      REMOTE_PORT,
      0,
      0,
      TCP_ACK,
      65535,
      new Uint8Array(0),
      GUEST_IP,
      REMOTE_IP,
    );
    void stray;
    f.tun.push(buildIPv4Packet(GUEST_IP, REMOTE_IP, IP_PROTO_TCP, seg));
    await flush();

    expect(f.nat.swapQueueLength).toBe(0);
    expect(f.wisp.streams).toHaveLength(1);
  });
});

describe('TcpNat — resetAll', () => {
  let f: Fixture;
  beforeEach(() => {
    f = makeFixture();
  });
  afterEach(() => teardown(f));

  it('RSTs every active flow, closes all streams, returns count', async () => {
    // Three flows on different src ports.
    for (let i = 0; i < 3; i++) {
      const seg = buildTcpSegment(
        GUEST_PORT + i,
        REMOTE_PORT,
        VM_INITIAL_SEQ + i * 100,
        0,
        TCP_SYN,
        65535,
        new Uint8Array(0),
        GUEST_IP,
        REMOTE_IP,
      );
      f.tun.push(buildIPv4Packet(GUEST_IP, REMOTE_IP, IP_PROTO_TCP, seg));
    }
    await flush();
    expect(f.nat.activeConnections).toBe(3);
    expect(f.wisp.streams).toHaveLength(3);
    f.tun.captured.length = 0;

    const n = f.nat.resetAll('test-swap');
    await flush();

    expect(n).toBe(3);
    expect(f.nat.activeConnections).toBe(0);
    expect(f.tun.captured).toHaveLength(3);
    for (const pkt of f.tun.captured) {
      expect(pkt.flags & TCP_RST).toBeTruthy();
    }
    for (const s of f.wisp.streams) {
      expect(s.closed).toBe(true);
    }
  });
});

describe('TcpNat — sequence number wraparound', () => {
  let f: Fixture;
  beforeEach(() => {
    f = makeFixture();
  });
  afterEach(() => teardown(f));

  it('wraps ourSeqNext correctly when crossing 2^32', async () => {
    f.tun.push(buildSyn());
    await flush();
    const synAck = f.tun.captured[0];
    f.tun.captured.length = 0;

    // Reach into the conn map and force ourSeqNext close to the wrap edge.
    // We don't expose conns directly, so we drive a series of large data
    // events that cumulatively wrap.
    const conns = (f.nat as unknown as { conns: Map<string, any> }).conns;
    expect(conns.size).toBe(1);
    const conn = [...conns.values()][0];
    conn.ourSeqNext = (0xffffffff - 5) >>> 0;

    // Send 10 bytes from server → seq should advance into the wrap zone.
    f.wisp.latest.fireData(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]));
    await flush();

    expect(f.tun.captured).toHaveLength(1);
    const pkt = f.tun.captured[0];
    // The seq we put on the wire is the value BEFORE incrementing.
    expect(pkt.seq).toBe((0xffffffff - 5) >>> 0);
    // After the increment, ourSeqNext = (0xffffffff - 5 + 10) mod 2^32 = 4.
    expect(conn.ourSeqNext).toBe(4);
  });
});

describe('TcpNat — destroy', () => {
  it('completes cleanly and stops the read loop', async () => {
    const f = makeFixture();
    f.tun.push(buildSyn());
    await flush();
    expect(f.nat.activeConnections).toBe(1);

    await f.nat.destroy();
    // After destroy, the start() promise resolves.
    await f.startPromise;
    // Idempotent.
    await f.nat.destroy();
  });
});
