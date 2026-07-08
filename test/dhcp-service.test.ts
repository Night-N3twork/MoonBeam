/**
 * Tests for src/dhcp-service.ts. Per spec §8 of
 * `docs/specs/2026-05-27-vm-wisp-networking-design.md`.
 *
 * Strategy: a MockStack exposes `openUdp()` returning a MockUdpSocket. The
 * mock socket has an inbound queue we push DHCP request frames into, and an
 * outbound queue we drain to inspect replies. We exercise the DhcpService
 * against this mock and verify reply contents byte-by-byte.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { DhcpService } from '../src/dhcp-service';
import { ipToNum } from '../src/packet';

// ---------------------------------------------------------------------------
// MockStack / MockUdpSocket
// ---------------------------------------------------------------------------

interface UdpDatagram {
  host: string;
  port: number;
  data: Uint8Array;
}

class MockUdpSocket {
  /** Datagrams the service has written. */
  readonly outbox: UdpDatagram[] = [];
  /** Resolves to the next outbound datagram. */
  private outboxWaiters: ((d: UdpDatagram) => void)[] = [];

  /** Controller for pushing inbound datagrams from tests. */
  private inboundController!: ReadableStreamDefaultController<UdpDatagram>;
  closed = false;
  readonly bindOptions: { port?: number } | undefined;

  readable: ReadableStream<UdpDatagram>;
  writable: WritableStream<UdpDatagram>;

  constructor(opts?: { port?: number }) {
    this.bindOptions = opts;
    this.readable = new ReadableStream<UdpDatagram>({
      start: (controller) => {
        this.inboundController = controller;
      },
      cancel: () => {
        this.closed = true;
      },
    });
    this.writable = new WritableStream<UdpDatagram>({
      write: (chunk) => {
        // Copy the data so later mutations don't affect captured bytes.
        const captured: UdpDatagram = {
          host: chunk.host,
          port: chunk.port,
          data: new Uint8Array(chunk.data),
        };
        this.outbox.push(captured);
        const waiter = this.outboxWaiters.shift();
        if (waiter) waiter(captured);
      },
      close: () => {
        this.closed = true;
      },
      abort: () => {
        this.closed = true;
      },
    });
  }

  /** Inject an inbound datagram (as if received over the network). */
  pushInbound(data: Uint8Array, host = '0.0.0.0', port = 68): void {
    this.inboundController.enqueue({ host, port, data });
  }

  /** Wait for the next outbound datagram (with a timeout). */
  async waitForReply(timeoutMs = 500): Promise<UdpDatagram> {
    if (this.outbox.length > 0) return this.outbox[0]!;
    return new Promise<UdpDatagram>((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this.outboxWaiters.indexOf(handler);
        if (idx >= 0) this.outboxWaiters.splice(idx, 1);
        reject(new Error(`timed out waiting ${timeoutMs}ms for DHCP reply`));
      }, timeoutMs);
      const handler = (d: UdpDatagram): void => {
        clearTimeout(timer);
        resolve(d);
      };
      this.outboxWaiters.push(handler);
    });
  }

  async close(): Promise<void> {
    this.closed = true;
    try { this.inboundController.close(); } catch { /* already closed */ }
  }
}

class MockStack {
  readonly sockets: MockUdpSocket[] = [];
  openUdpCalls: ({ port?: number; host?: string } | undefined)[] = [];

  async openUdp(opts?: { port?: number; host?: string }): Promise<MockUdpSocket> {
    this.openUdpCalls.push(opts);
    const s = new MockUdpSocket(opts);
    this.sockets.push(s);
    return s;
  }
}

// ---------------------------------------------------------------------------
// DHCP request builder helpers
// ---------------------------------------------------------------------------

const DHCP_MAGIC_COOKIE = 0x63825363;
const DHCP_OP_REQUEST = 1;
const DHCP_OP_REPLY = 2;

const DHCP_DISCOVER = 1;
const DHCP_OFFER = 2;
const DHCP_REQUEST = 3;
const DHCP_DECLINE = 4;
const DHCP_ACK = 5;
const DHCP_NAK = 6;
const DHCP_RELEASE = 7;

const DEFAULT_MAC = new Uint8Array([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);

interface BuildOpts {
  msgType: number;
  xid?: number;
  flags?: number;
  chaddr?: Uint8Array;
  ciaddr?: number;
  /** Option 50 (Requested IP). */
  requestedIp?: number;
  /** Option 54 (Server Identifier). */
  serverId?: number;
  /** Option 55 (Parameter Request List). */
  paramRequestList?: number[];
  /** Option 12 (Hostname). */
  hostname?: string;
  /** Truncate the resulting buffer to this many bytes (for malformed tests). */
  truncateTo?: number;
  /** Override the magic cookie (for malformed tests). */
  badCookie?: boolean;
  /** Override the op field (for malformed tests). */
  op?: number;
}

function buildDhcpRequest(opts: BuildOpts): Uint8Array {
  const buf = new Uint8Array(300);
  const dv = new DataView(buf.buffer);

  buf[0] = opts.op ?? DHCP_OP_REQUEST;
  buf[1] = 1; // htype: ethernet
  buf[2] = 6; // hlen: 6
  buf[3] = 0; // hops
  dv.setUint32(4, opts.xid ?? 0xdeadbeef, false);
  dv.setUint16(8, 0, false); // secs
  dv.setUint16(10, opts.flags ?? 0, false);
  dv.setUint32(12, opts.ciaddr ?? 0, false);
  // yiaddr/siaddr/giaddr left zero
  const mac = opts.chaddr ?? DEFAULT_MAC;
  buf.set(mac, 28);
  dv.setUint32(236, opts.badCookie ? 0xdeadbeef : DHCP_MAGIC_COOKIE, false);

  // Options
  let off = 240;
  // 53: Message Type
  buf[off++] = 53;
  buf[off++] = 1;
  buf[off++] = opts.msgType;

  if (opts.requestedIp !== undefined) {
    buf[off++] = 50;
    buf[off++] = 4;
    const v = opts.requestedIp >>> 0;
    buf[off++] = (v >>> 24) & 0xff;
    buf[off++] = (v >>> 16) & 0xff;
    buf[off++] = (v >>> 8) & 0xff;
    buf[off++] = v & 0xff;
  }
  if (opts.serverId !== undefined) {
    buf[off++] = 54;
    buf[off++] = 4;
    const v = opts.serverId >>> 0;
    buf[off++] = (v >>> 24) & 0xff;
    buf[off++] = (v >>> 16) & 0xff;
    buf[off++] = (v >>> 8) & 0xff;
    buf[off++] = v & 0xff;
  }
  if (opts.paramRequestList) {
    buf[off++] = 55;
    buf[off++] = opts.paramRequestList.length;
    for (const code of opts.paramRequestList) buf[off++] = code & 0xff;
  }
  if (opts.hostname) {
    const bytes = new TextEncoder().encode(opts.hostname);
    buf[off++] = 12;
    buf[off++] = bytes.length;
    for (const b of bytes) buf[off++] = b;
  }

  buf[off++] = 255; // OPT_END

  const out = buf.slice(0, Math.max(off, 300));
  if (opts.truncateTo !== undefined) return out.slice(0, opts.truncateTo);
  return out;
}

// ---------------------------------------------------------------------------
// Reply parsing helpers
// ---------------------------------------------------------------------------

interface ParsedReply {
  op: number;
  htype: number;
  hlen: number;
  xid: number;
  flags: number;
  yiaddr: number;
  siaddr: number;
  giaddr: number;
  chaddr: Uint8Array;
  magicCookie: number;
  options: Map<number, Uint8Array>;
}

function parseReply(data: Uint8Array): ParsedReply {
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const reply: ParsedReply = {
    op: data[0]!,
    htype: data[1]!,
    hlen: data[2]!,
    xid: dv.getUint32(4, false),
    flags: dv.getUint16(10, false),
    yiaddr: dv.getUint32(16, false),
    siaddr: dv.getUint32(20, false),
    giaddr: dv.getUint32(24, false),
    chaddr: data.slice(28, 44),
    magicCookie: dv.getUint32(236, false),
    options: new Map<number, Uint8Array>(),
  };
  let off = 240;
  while (off < data.byteLength) {
    const code = data[off++]!;
    if (code === 255) break;
    if (code === 0) continue;
    if (off >= data.byteLength) break;
    const len = data[off++]!;
    if (off + len > data.byteLength) break;
    reply.options.set(code, data.slice(off, off + len));
    off += len;
  }
  return reply;
}

function readU32(buf: Uint8Array): number {
  return (((buf[0]! << 24) >>> 0) | (buf[1]! << 16) | (buf[2]! << 8) | buf[3]!) >>> 0;
}

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const GATEWAY = ipToNum('192.168.127.1');
const SUBNET = ipToNum('255.255.255.0');
const VM_IP = ipToNum('192.168.127.2');
const DNS = ipToNum('1.1.1.1');
const LEASE = 86400;

interface Fixture {
  stack: MockStack;
  service: DhcpService;
  socket: MockUdpSocket;
}

async function makeService(overrides: Partial<{ dnsServer: number; leaseTime: number }> = {}): Promise<Fixture> {
  const stack = new MockStack();
  const service = new DhcpService({
    stack: stack as unknown as import('tcpip').NetworkStack,
    gatewayIp: GATEWAY,
    subnetMask: SUBNET,
    vmIp: VM_IP,
    dnsServer: overrides.dnsServer ?? DNS,
    leaseTime: overrides.leaseTime ?? LEASE,
  });
  await service.start();
  const socket = stack.sockets[0]!;
  return { stack, service, socket };
}

let active: Fixture | null = null;

beforeEach(() => {
  active = null;
});

afterEach(async () => {
  if (active) {
    await active.service.destroy();
    active = null;
  }
});

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

describe('DhcpService — lifecycle', () => {
  it('start() opens a UDP socket on port 67', async () => {
    active = await makeService();
    expect(active.stack.openUdpCalls).toHaveLength(1);
    expect(active.stack.openUdpCalls[0]).toEqual({ port: 67 });
  });

  it('destroy() closes the underlying UDP socket', async () => {
    active = await makeService();
    await active.service.destroy();
    expect(active.socket.closed).toBe(true);
    active = null;
  });

  it('destroy() is idempotent', async () => {
    active = await makeService();
    await active.service.destroy();
    await expect(active.service.destroy()).resolves.toBeUndefined();
    active = null;
  });

  it('start() is idempotent (does not open a second socket)', async () => {
    active = await makeService();
    await active.service.start();
    expect(active.stack.openUdpCalls).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// DISCOVER -> OFFER
// ---------------------------------------------------------------------------

describe('DhcpService — DISCOVER -> OFFER', () => {
  it('replies to DISCOVER with a well-formed OFFER', async () => {
    active = await makeService();
    const xid = 0x12345678;
    const req = buildDhcpRequest({ msgType: DHCP_DISCOVER, xid });
    active.socket.pushInbound(req);
    const reply = await active.socket.waitForReply();

    expect(reply.host).toBe('255.255.255.255');
    expect(reply.port).toBe(68);

    const r = parseReply(reply.data);
    expect(r.op).toBe(DHCP_OP_REPLY);
    expect(r.htype).toBe(1);
    expect(r.hlen).toBe(6);
    expect(r.xid).toBe(xid);
    expect(r.yiaddr).toBe(VM_IP);
    expect(r.giaddr).toBe(0);
    expect(r.magicCookie).toBe(DHCP_MAGIC_COOKIE);
    // chaddr first 6 bytes echo client MAC
    expect(Array.from(r.chaddr.slice(0, 6))).toEqual(Array.from(DEFAULT_MAC));
  });

  it('OFFER carries all required options (53, 1, 3, 6, 51, 54)', async () => {
    active = await makeService();
    active.socket.pushInbound(buildDhcpRequest({ msgType: DHCP_DISCOVER }));
    const reply = await active.socket.waitForReply();
    const r = parseReply(reply.data);

    // 53: DHCP Message Type = OFFER
    expect(r.options.get(53)?.[0]).toBe(DHCP_OFFER);
    // 1: Subnet Mask
    expect(readU32(r.options.get(1)!)).toBe(SUBNET);
    // 3: Router (Gateway)
    expect(readU32(r.options.get(3)!)).toBe(GATEWAY);
    // 6: DNS Server
    expect(readU32(r.options.get(6)!)).toBe(DNS);
    // 51: Lease Time
    expect(readU32(r.options.get(51)!)).toBe(LEASE);
    // 54: Server Identifier = gateway IP
    expect(readU32(r.options.get(54)!)).toBe(GATEWAY);
  });

  it('OFFER echoes the request flags (broadcast bit preserved)', async () => {
    active = await makeService();
    active.socket.pushInbound(buildDhcpRequest({ msgType: DHCP_DISCOVER, flags: 0x8000 }));
    const reply = await active.socket.waitForReply();
    const r = parseReply(reply.data);
    expect(r.flags).toBe(0x8000);
  });

  it('handles parameter request list (option 55) — assert all requested options present', async () => {
    active = await makeService();
    active.socket.pushInbound(
      buildDhcpRequest({
        msgType: DHCP_DISCOVER,
        paramRequestList: [1, 3, 6, 51],
      }),
    );
    const reply = await active.socket.waitForReply();
    const r = parseReply(reply.data);
    expect(r.options.has(1)).toBe(true);
    expect(r.options.has(3)).toBe(true);
    expect(r.options.has(6)).toBe(true);
    expect(r.options.has(51)).toBe(true);
  });

  it('handles multiple DISCOVERs in succession (no rate limiting)', async () => {
    active = await makeService();
    for (let i = 0; i < 3; i++) {
      active.socket.pushInbound(buildDhcpRequest({ msgType: DHCP_DISCOVER, xid: 0x1000 + i }));
    }
    // Drain three replies.
    let count = 0;
    for (let i = 0; i < 3; i++) {
      const reply = await active.socket.waitForReply();
      // remove what we just consumed so waitForReply observes the next one
      active.socket.outbox.shift();
      const r = parseReply(reply.data);
      expect(r.options.get(53)?.[0]).toBe(DHCP_OFFER);
      expect(r.xid).toBe(0x1000 + i);
      count++;
    }
    expect(count).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// REQUEST -> ACK / NAK
// ---------------------------------------------------------------------------

describe('DhcpService — REQUEST', () => {
  it('replies to REQUEST with matching IP -> ACK', async () => {
    active = await makeService();
    active.socket.pushInbound(
      buildDhcpRequest({ msgType: DHCP_REQUEST, requestedIp: VM_IP }),
    );
    const reply = await active.socket.waitForReply();
    const r = parseReply(reply.data);
    expect(r.options.get(53)?.[0]).toBe(DHCP_ACK);
    expect(r.yiaddr).toBe(VM_IP);
    // ACK still carries lease + network parameters
    expect(readU32(r.options.get(1)!)).toBe(SUBNET);
    expect(readU32(r.options.get(3)!)).toBe(GATEWAY);
    expect(readU32(r.options.get(6)!)).toBe(DNS);
    expect(readU32(r.options.get(51)!)).toBe(LEASE);
    expect(readU32(r.options.get(54)!)).toBe(GATEWAY);
  });

  it('replies to REQUEST with non-matching requested IP -> NAK', async () => {
    active = await makeService();
    active.socket.pushInbound(
      buildDhcpRequest({ msgType: DHCP_REQUEST, requestedIp: ipToNum('10.0.0.99') }),
    );
    const reply = await active.socket.waitForReply();
    const r = parseReply(reply.data);
    expect(r.options.get(53)?.[0]).toBe(DHCP_NAK);
    // NAK: yiaddr must be zero
    expect(r.yiaddr).toBe(0);
    // NAK still includes server identifier
    expect(readU32(r.options.get(54)!)).toBe(GATEWAY);
    // NAK doesn't carry lease params
    expect(r.options.has(51)).toBe(false);
    expect(r.options.has(1)).toBe(false);
  });

  it('REQUEST with matching ciaddr (renewing) -> ACK', async () => {
    active = await makeService();
    active.socket.pushInbound(
      buildDhcpRequest({ msgType: DHCP_REQUEST, ciaddr: VM_IP }),
    );
    const reply = await active.socket.waitForReply();
    const r = parseReply(reply.data);
    expect(r.options.get(53)?.[0]).toBe(DHCP_ACK);
  });

  it('REQUEST with serverId pointing at a different server is ignored', async () => {
    active = await makeService();
    active.socket.pushInbound(
      buildDhcpRequest({
        msgType: DHCP_REQUEST,
        requestedIp: VM_IP,
        serverId: ipToNum('10.0.0.1'),
      }),
    );
    // Should silently drop. Wait briefly and assert nothing showed up.
    await new Promise((r) => setTimeout(r, 50));
    expect(active.socket.outbox).toHaveLength(0);
  });

  it('echoes the request xid in the reply', async () => {
    active = await makeService();
    const xid = 0xa1b2c3d4;
    active.socket.pushInbound(
      buildDhcpRequest({ msgType: DHCP_REQUEST, requestedIp: VM_IP, xid }),
    );
    const reply = await active.socket.waitForReply();
    expect(parseReply(reply.data).xid).toBe(xid);
  });
});

// ---------------------------------------------------------------------------
// RELEASE / DECLINE — silent
// ---------------------------------------------------------------------------

describe('DhcpService — RELEASE / DECLINE', () => {
  it('RELEASE produces no reply', async () => {
    active = await makeService();
    active.socket.pushInbound(buildDhcpRequest({ msgType: DHCP_RELEASE }));
    await new Promise((r) => setTimeout(r, 50));
    expect(active.socket.outbox).toHaveLength(0);
  });

  it('DECLINE produces no reply but does not stop the service', async () => {
    active = await makeService();
    active.socket.pushInbound(buildDhcpRequest({ msgType: DHCP_DECLINE }));
    await new Promise((r) => setTimeout(r, 50));
    expect(active.socket.outbox).toHaveLength(0);

    // Service still serving — DISCOVER should still get an OFFER.
    active.socket.pushInbound(buildDhcpRequest({ msgType: DHCP_DISCOVER }));
    const reply = await active.socket.waitForReply();
    expect(parseReply(reply.data).options.get(53)?.[0]).toBe(DHCP_OFFER);
  });
});

// ---------------------------------------------------------------------------
// Malformed packets — silently dropped
// ---------------------------------------------------------------------------

describe('DhcpService — malformed packets are silently dropped', () => {
  it('truncated packet (smaller than fixed header) is dropped', async () => {
    active = await makeService();
    active.socket.pushInbound(new Uint8Array(50));
    await new Promise((r) => setTimeout(r, 50));
    expect(active.socket.outbox).toHaveLength(0);
  });

  it('packet with wrong magic cookie is dropped', async () => {
    active = await makeService();
    active.socket.pushInbound(buildDhcpRequest({ msgType: DHCP_DISCOVER, badCookie: true }));
    await new Promise((r) => setTimeout(r, 50));
    expect(active.socket.outbox).toHaveLength(0);
  });

  it('packet with op != BOOTREQUEST is dropped', async () => {
    active = await makeService();
    active.socket.pushInbound(buildDhcpRequest({ msgType: DHCP_DISCOVER, op: DHCP_OP_REPLY }));
    await new Promise((r) => setTimeout(r, 50));
    expect(active.socket.outbox).toHaveLength(0);
  });

  it('packet missing message-type option (53) is dropped', async () => {
    active = await makeService();
    // Build a packet that has the magic cookie + just OPT_END, no 53.
    const buf = new Uint8Array(300);
    const dv = new DataView(buf.buffer);
    buf[0] = DHCP_OP_REQUEST;
    buf[1] = 1;
    buf[2] = 6;
    buf.set(DEFAULT_MAC, 28);
    dv.setUint32(236, DHCP_MAGIC_COOKIE, false);
    buf[240] = 255;
    active.socket.pushInbound(buf);
    await new Promise((r) => setTimeout(r, 50));
    expect(active.socket.outbox).toHaveLength(0);
  });

  it('packet truncated mid-options is dropped without crashing', async () => {
    active = await makeService();
    // 240 bytes (header + magic) but no options at all (no terminator either).
    const buf = new Uint8Array(240);
    const dv = new DataView(buf.buffer);
    buf[0] = DHCP_OP_REQUEST;
    buf[1] = 1;
    buf[2] = 6;
    buf.set(DEFAULT_MAC, 28);
    dv.setUint32(236, DHCP_MAGIC_COOKIE, false);
    active.socket.pushInbound(buf);
    await new Promise((r) => setTimeout(r, 50));
    expect(active.socket.outbox).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// DNS round-trip via ipToNum('1.1.1.1')
// ---------------------------------------------------------------------------

describe('DhcpService — DNS option round-trip', () => {
  it('serves DNS option = 1.1.1.1 when configured with ipToNum("1.1.1.1")', async () => {
    active = await makeService({ dnsServer: ipToNum('1.1.1.1') });
    active.socket.pushInbound(buildDhcpRequest({ msgType: DHCP_DISCOVER }));
    const reply = await active.socket.waitForReply();
    const r = parseReply(reply.data);
    const dnsBytes = r.options.get(6)!;
    expect(dnsBytes).toHaveLength(4);
    expect(Array.from(dnsBytes)).toEqual([1, 1, 1, 1]);
    expect(readU32(dnsBytes)).toBe(ipToNum('1.1.1.1'));
  });
});
