/**
 * TCP NAT — translates IPv4/TCP packets emitted by the guest (via lwIP's
 * TunInterface) into multiplexed Wisp TCP streams, and reverse-translates
 * Wisp byte streams back into TCP/IPv4 packets injected toward the guest.
 *
 * Spec: docs/specs/2026-05-27-vm-wisp-networking-design.md §5
 *
 * Architectural notes:
 *   - Pure L3/L4: we see only IPv4 packets, no Ethernet (TunInterface strips
 *     it). Outbound packets are written as raw IPv4 back to the tun's
 *     writable; lwIP wraps them in Ethernet for the LAN side.
 *   - NAT transparency (§5.3): packets sent toward the guest carry
 *     src=remote-server, dst=guest. The guest sees responses as if they
 *     came directly from the server.
 *   - Half-close LIMITATION: Wisp `CLOSE` is bidirectional. When the guest
 *     half-closes its send side via FIN, we MUST close the entire Wisp
 *     stream; the upstream server sees a full close and any pending
 *     response bytes after that point are lost. HTTP/1.1+ generally
 *     unaffected; HTTP/1.0 close-after-request may misbehave.
 *   - Sequence-number handling: u32 modular per RFC 793; out-of-order
 *     packets from the guest are dropped (no buffering), the guest's TCP
 *     stack will retransmit.
 *   - Swap-in-progress gate (§5.6): while `getSwapInProgress()` returns true
 *     we queue incoming SYNs into a bounded buffer rather than creating
 *     streams on either the about-to-die or not-yet-installed WispClient.
 *     The gateway orchestrator calls `drainSwapQueue()` once the new
 *     client is live.
 */

import type { WispClient, WispStream } from './wisp-client';
import type { EgressPolicy } from './policy';
import {
  IP_PROTO_TCP,
  TCP_ACK,
  TCP_FIN,
  TCP_PSH,
  TCP_RST,
  TCP_SYN,
  buildIPv4Packet,
  buildTcpSegment,
  numToIp,
  parseIPv4,
  parseTcp,
  type IPv4Header,
  type TcpHeader,
} from './packet';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface TcpNatConfig {
  /** Tun interface from tcpip.js. Raw IPv4 packets (L3, no Ethernet). */
  tun: {
    readable: ReadableStream<Uint8Array>;
    writable: WritableStream<Uint8Array>;
  };
  /** Read fresh on each stream creation so swaps transparently take effect. */
  getWisp: () => WispClient;
  /** True while a Wisp swap is in progress; new SYNs queue instead of opening
   *  streams. See spec §5.6. */
  getSwapInProgress: () => boolean;
  policy: EgressPolicy;
  /** Default 256. Per spec §5.6 — overflow triggers RST to guest. */
  maxSwapQueue?: number;
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

type ConnState = 'syn-sent' | 'established' | 'closing' | 'closed';

interface TcpConnection {
  key: string;
  srcIp: number;
  srcPort: number;
  dstIp: number;
  dstPort: number;

  // Sequence-number bookkeeping (all uint32 modular).
  vmSeqNext: number;
  ourSeqBase: number;
  ourSeqNext: number;

  stream: WispStream | null;
  state: ConnState;
  /** Bytes from the guest queued while waiting for stream 'open'. */
  sendBuffer: Uint8Array[];
  /** Bytes from upstream queued for delivery to the guest. (Currently
   *  delivered synchronously, but the buffer + drain pattern leaves room
   *  for future backpressure.) */
  recvBuffer: Uint8Array[];
  /** Re-entrancy guard for recv drain. */
  draining: boolean;
}

interface QueuedSyn {
  ip: IPv4Header;
  tcp: TcpHeader;
  packet: Uint8Array;
  /** ms timestamp; useful for future age-based eviction. */
  ts: number;
}

const DEFAULT_MAX_SWAP_QUEUE = 256;
/** Window we advertise to the guest. 64 KiB is a sane default; the WispClient
 *  layer enforces its own credit-based backpressure, so this only needs to be
 *  large enough to let the guest pipeline reasonably. */
const ADVERTISED_WINDOW = 0xffff;

/**
 * Maximum TCP payload bytes per segment we deliver toward the guest.
 *
 * Standard Ethernet MTU is 1500 bytes; subtract 20B IP header + 20B TCP
 * header → 1460 bytes payload. We MUST chunk our recv path to this size
 * because Wisp chunk boundaries do not respect any MTU and we do not
 * negotiate VIRTIO_NET_F_MRG_RXBUF / GSO with the guest. Delivering an
 * oversized "TCP segment" produces an oversized Ethernet frame that
 * QEMU's virtio-net (or the guest kernel) chokes on — observed in
 * practice as "TCP: eth0: Driver has suspect GRO implementation"
 * followed by a wasm OOB crash inside g_main_context_dispatch.
 */
const MSS_TO_GUEST = 1460;

// ---------------------------------------------------------------------------
// TcpNat
// ---------------------------------------------------------------------------

export class TcpNat {
  private readonly config: TcpNatConfig;
  private readonly maxSwapQueue: number;

  private readonly conns = new Map<string, TcpConnection>();
  private readonly swapQueue: QueuedSyn[] = [];

  private writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  private reader: ReadableStreamDefaultReader<Uint8Array> | null = null;

  private destroyed = false;
  private readonly destroyedPromise: Promise<void>;
  private resolveDestroyed!: () => void;

  /** Last observed swap-in-progress value; used to auto-drain on the
   *  false-edge between packet reads. */
  private lastSwapInProgress = false;

  constructor(config: TcpNatConfig) {
    this.config = config;
    this.maxSwapQueue = config.maxSwapQueue ?? DEFAULT_MAX_SWAP_QUEUE;
    this.destroyedPromise = new Promise((resolve) => {
      this.resolveDestroyed = resolve;
    });
  }

  /** Begin the read loop on tun.readable. Resolves when the loop exits
   *  (i.e., on destroy or upstream EOF). */
  async start(): Promise<void> {
    this.writer = this.config.tun.writable.getWriter();
    this.reader = this.config.tun.readable.getReader();
    try {
      // eslint-disable-next-line no-constant-condition
      while (true) {
        if (this.destroyed) break;
        const { done, value } = await this.reader.read();
        if (done) break;
        if (!value || value.length === 0) continue;
        try {
          this._handlePacket(value);
        } catch (err) {
          // A single malformed packet must not kill the NAT.
          // eslint-disable-next-line no-console
          console.error('TcpNat: packet handler threw:', err);
        }
        // Auto-drain on swap-in-progress false-edge.
        const cur = this.config.getSwapInProgress();
        if (this.lastSwapInProgress && !cur) {
          this.drainSwapQueue();
        }
        this.lastSwapInProgress = cur;
      }
    } finally {
      this.resolveDestroyed();
    }
  }

  /** Number of currently-tracked TCP flows. */
  get activeConnections(): number {
    return this.conns.size;
  }

  /** Number of SYNs currently parked in the swap-in-progress queue. */
  get swapQueueLength(): number {
    return this.swapQueue.length;
  }

  /** Drain queued SYNs back through the normal new-connection path. The
   *  gateway swap orchestrator calls this after a successful swap (or
   *  rollback). Also auto-invoked on the next packet after
   *  `getSwapInProgress()` transitions to false. Idempotent. */
  drainSwapQueue(): void {
    if (this.swapQueue.length === 0) return;
    // Snapshot — handlers may end up re-queueing if a fresh swap starts
    // between drain start and end (unlikely but cheap to be safe).
    const drain = this.swapQueue.splice(0, this.swapQueue.length);
    for (const q of drain) {
      this._handleNewConnection(q.ip, q.tcp, q.packet);
    }
  }

  /** Reset every active TCP flow: synthesize a RST to the guest, close the
   *  upstream Wisp stream, then drop the conn entry. Used during Wisp server
   *  hot-swap (session-resilience spec §6.2). Returns the count of flows
   *  reset. The `reason` argument is currently used only for diagnostic
   *  purposes; per spec RST has no payload-carried reason on the wire. */
  resetAll(_reason: string): number {
    const n = this.conns.size;
    for (const conn of [...this.conns.values()]) {
      this._sendRstForConn(conn);
      try {
        conn.stream?.close();
      } catch {
        /* ignore */
      }
      conn.state = 'closed';
    }
    this.conns.clear();
    return n;
  }

  /** Stop the read loop, release the writer, abort any swap-queued SYNs.
   *  Streams are NOT closed here — destroy is "fast detach"; callers wanting
   *  RST-to-guest semantics should call resetAll() first. */
  async destroy(): Promise<void> {
    if (this.destroyed) return;
    this.destroyed = true;
    this.swapQueue.length = 0;

    // Release the reader so the read loop's pending read() rejects.
    if (this.reader) {
      try {
        await this.reader.cancel();
      } catch {
        /* ignore */
      }
      try {
        this.reader.releaseLock();
      } catch {
        /* ignore */
      }
      this.reader = null;
    }
    if (this.writer) {
      try {
        this.writer.releaseLock();
      } catch {
        /* ignore */
      }
      this.writer = null;
    }
    // Allow the read loop to settle.
    await this.destroyedPromise.catch(() => undefined);
  }

  // -----------------------------------------------------------------------
  // Packet dispatch
  // -----------------------------------------------------------------------

  /** @internal — exposed for tests and unusual swap orchestrations. */
  _handlePacket(packet: Uint8Array): void {
    const ip = parseIPv4(packet, 0);
    if (!ip) return;
    if (ip.protocol !== IP_PROTO_TCP) return;
    const tcp = parseTcp(packet, ip.payloadOffset);
    if (!tcp) return;

    const key = makeKey(ip.srcIp, tcp.srcPort, ip.dstIp, tcp.dstPort);
    const conn = this.conns.get(key);

    const isSyn = (tcp.flags & TCP_SYN) !== 0;
    const isAck = (tcp.flags & TCP_ACK) !== 0;
    const isRst = (tcp.flags & TCP_RST) !== 0;
    const isFin = (tcp.flags & TCP_FIN) !== 0;

    // RST from the guest: tear down hard, no response.
    if (isRst) {
      if (conn) this._teardown(conn);
      return;
    }

    // SYN (initial; no ACK bit) → new connection or swap-queued.
    if (isSyn && !isAck) {
      if (conn) {
        // Duplicate SYN for an existing flow: ignore (likely a retransmit
        // while our SYN-ACK is in flight). Could re-send SYN-ACK to be
        // helpful, but plain drop is correct — guest will retry.
        return;
      }
      if (this.config.getSwapInProgress()) {
        this._enqueueSwapSyn(ip, tcp, packet);
        return;
      }
      this._handleNewConnection(ip, tcp, packet);
      return;
    }

    if (!conn) {
      // Stray packet for unknown flow — RFC 793 says reply RST, but in
      // a NAT context this is noise from late retransmits after we
      // dropped a flow. Quietly drop.
      return;
    }

    // For an established flow: process ACK / FIN / data.
    const payloadLen = ip.payloadOffset + ip.payloadLength - tcp.payloadOffset;
    const payload =
      payloadLen > 0
        ? packet.subarray(tcp.payloadOffset, tcp.payloadOffset + payloadLen)
        : null;

    // Out-of-order check: spec §5.1 — drop, no buffering. lwIP on the guest
    // will retransmit.
    if (payload && tcp.seqNum !== conn.vmSeqNext) {
      // Pure ACK with no payload doesn't need seq validation in our model
      // (and modern stacks routinely send ACKs with stale seq when there's
      // no fresh data); only data must match.
      return;
    }

    if (payload) {
      // Forward to Wisp stream (or buffer if not open yet).
      this._forwardPayloadToWisp(conn, payload);
      conn.vmSeqNext = (conn.vmSeqNext + payload.length) >>> 0;
      // ACK the data we just consumed.
      this._sendTcpToVm(conn, TCP_ACK, conn.ourSeqNext, conn.vmSeqNext, null);
    }

    if (isFin) {
      // Half-close limitation (§5.1): close the upstream Wisp stream.
      conn.vmSeqNext = (conn.vmSeqNext + 1) >>> 0; // FIN consumes 1 seq
      this._sendTcpToVm(conn, TCP_ACK, conn.ourSeqNext, conn.vmSeqNext, null);
      try {
        conn.stream?.close();
      } catch {
        /* ignore */
      }
      // Don't delete yet — the server's close ack flow may still arrive
      // and we want to gracefully complete. But we mark closing.
      conn.state = 'closing';
    }
  }

  // -----------------------------------------------------------------------
  // New connection path
  // -----------------------------------------------------------------------

  private _handleNewConnection(ip: IPv4Header, tcp: TcpHeader, packet: Uint8Array): void {
    if (!this.config.policy.permits(ip.dstIp, tcp.dstPort, 'tcp')) {
      // Send RST per RFC 793 §3.4 against the SYN.
      this._sendUnsolicitedRst(ip, tcp);
      return;
    }

    const wisp = this.config.getWisp();

    const ourSeqBase = randomU32();
    const key = makeKey(ip.srcIp, tcp.srcPort, ip.dstIp, tcp.dstPort);

    const conn: TcpConnection = {
      key,
      srcIp: ip.srcIp,
      srcPort: tcp.srcPort,
      dstIp: ip.dstIp,
      dstPort: tcp.dstPort,
      vmSeqNext: (tcp.seqNum + 1) >>> 0, // guest SYN consumes 1
      ourSeqBase,
      ourSeqNext: ourSeqBase, // increment to base+1 once SYN-ACK is sent
      stream: null,
      state: 'syn-sent',
      sendBuffer: [],
      recvBuffer: [],
      draining: false,
    };

    this.conns.set(key, conn);

    let stream: WispStream;
    try {
      stream = wisp.createStream(numToIp(ip.dstIp), tcp.dstPort, 'tcp');
    } catch (err) {
      // Wisp client refused (e.g., not ready, exhausted, UDP-only). RST
      // and drop.
      // eslint-disable-next-line no-console
      console.warn('TcpNat: wisp.createStream threw:', err);
      this._sendUnsolicitedRst(ip, tcp);
      this.conns.delete(key);
      return;
    }
    conn.stream = stream;

    const confirmStreamOpen =
      typeof (wisp as unknown as { confirmStreamOpen?: boolean }).confirmStreamOpen === 'boolean'
        ? (wisp as unknown as { confirmStreamOpen: boolean }).confirmStreamOpen
        : false;

    if (confirmStreamOpen) {
      // Defer SYN-ACK until the upstream confirms. This gives the guest
      // ECONNREFUSED-like semantics when the destination is unreachable.
      stream.on('open', () => {
        if (conn.state !== 'syn-sent') return; // teardown raced
        conn.state = 'established';
        this._sendTcpToVm(conn, TCP_SYN | TCP_ACK, conn.ourSeqBase, conn.vmSeqNext, null);
        conn.ourSeqNext = (conn.ourSeqBase + 1) >>> 0; // SYN consumes 1
        this._flushSendBuffer(conn);
      });
      stream.on('error', () => {
        if (conn.state === 'syn-sent') {
          // Pre-open failure → RST against the SYN (looks like ECONNREFUSED).
          this._sendUnsolicitedRst(ip, tcp);
          this.conns.delete(key);
        } else if (conn.state === 'established') {
          this._sendRstForConn(conn);
          this.conns.delete(key);
        }
      });
    } else {
      // Optimistic SYN-ACK. If upstream fails later, guest sees ECONNRESET.
      conn.state = 'established';
      this._sendTcpToVm(conn, TCP_SYN | TCP_ACK, conn.ourSeqBase, conn.vmSeqNext, null);
      conn.ourSeqNext = (conn.ourSeqBase + 1) >>> 0;
      stream.on('open', () => {
        this._flushSendBuffer(conn);
      });
      stream.on('error', () => {
        if (this.conns.has(key)) {
          this._sendRstForConn(conn);
          this.conns.delete(key);
        }
      });
    }

    stream.on('data', (bytes: Uint8Array) => {
      if (conn.state === 'closed') return;
      conn.recvBuffer.push(bytes);
      this._drainRecv(conn);
    });

    stream.on('close', () => {
      if (conn.state === 'closed') return;
      // Server-side close: deliver any remaining buffered data first
      // (drain is sync), then send FIN-ACK to guest.
      this._drainRecv(conn);
      this._sendTcpToVm(conn, TCP_FIN | TCP_ACK, conn.ourSeqNext, conn.vmSeqNext, null);
      conn.ourSeqNext = (conn.ourSeqNext + 1) >>> 0; // FIN consumes 1
      conn.state = 'closing';
      // We leave the conn record around briefly to absorb the guest's
      // FIN-ACK or RST. A real implementation would TIME_WAIT; we just
      // delete on next teardown trigger.
    });
  }

  private _enqueueSwapSyn(ip: IPv4Header, tcp: TcpHeader, packet: Uint8Array): void {
    if (this.swapQueue.length >= this.maxSwapQueue) {
      // Overflow → looks like ECONNREFUSED to the guest.
      this._sendUnsolicitedRst(ip, tcp);
      return;
    }
    // Copy the packet so the underlying buffer can be reused by the source.
    this.swapQueue.push({
      ip,
      tcp,
      packet: packet.slice(),
      ts: Date.now(),
    });
  }

  // -----------------------------------------------------------------------
  // Data plane
  // -----------------------------------------------------------------------

  private _forwardPayloadToWisp(conn: TcpConnection, payload: Uint8Array): void {
    // Copy so the caller's buffer can be reused freely.
    const copy = new Uint8Array(payload.length);
    copy.set(payload);

    if (conn.state === 'syn-sent') {
      conn.sendBuffer.push(copy);
      return;
    }
    if (!conn.stream || conn.state === 'closed') return;
    try {
      conn.stream.send(copy);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.warn('TcpNat: stream.send threw:', err);
    }
  }

  private _flushSendBuffer(conn: TcpConnection): void {
    if (!conn.stream) return;
    while (conn.sendBuffer.length > 0) {
      const chunk = conn.sendBuffer.shift()!;
      try {
        conn.stream.send(chunk);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn('TcpNat: stream.send (flush) threw:', err);
        return;
      }
    }
  }

  private _drainRecv(conn: TcpConnection): void {
    if (conn.draining) return;
    conn.draining = true;
    try {
      while (conn.recvBuffer.length > 0) {
        const bytes = conn.recvBuffer.shift()!;
        if (bytes.length === 0) continue;
        // Chunk to MSS so each Ethernet frame stays at or below MTU
        // (1500B). Wisp delivers arbitrarily-sized chunks; the guest's
        // virtio-net driver expects MTU-sized frames unless we negotiate
        // GSO offload (which we don't).
        //
        // PSH is set only on the LAST segment of the chunk, matching the
        // semantics a real sender would use: PSH means "this is the end
        // of a logical write; deliver upstream now." Mid-burst segments
        // are plain ACKs so the receiver can coalesce.
        for (let off = 0; off < bytes.length; off += MSS_TO_GUEST) {
          const end = Math.min(off + MSS_TO_GUEST, bytes.length);
          const slice = bytes.subarray(off, end);
          const isLast = end === bytes.length;
          this._sendTcpToVm(
            conn,
            isLast ? (TCP_PSH | TCP_ACK) : TCP_ACK,
            conn.ourSeqNext,
            conn.vmSeqNext,
            slice,
          );
          conn.ourSeqNext = (conn.ourSeqNext + slice.length) >>> 0;
        }
      }
    } finally {
      conn.draining = false;
    }
  }

  // -----------------------------------------------------------------------
  // Wire injection
  // -----------------------------------------------------------------------

  /** Build a TCP segment + IPv4 packet (with NAT-transparent addressing —
   *  src=remote server, dst=guest) and inject it into tun.writable. */
  private _sendTcpToVm(
    conn: TcpConnection,
    flags: number,
    seq: number,
    ack: number,
    payload: Uint8Array | null,
  ): void {
    const pl = payload ?? new Uint8Array(0);
    const seg = buildTcpSegment(
      conn.dstPort, // remote (src on the wire)
      conn.srcPort, // guest (dst on the wire)
      seq,
      ack,
      flags,
      ADVERTISED_WINDOW,
      pl,
      conn.dstIp,
      conn.srcIp,
    );
    const pkt = buildIPv4Packet(conn.dstIp, conn.srcIp, IP_PROTO_TCP, seg);
    this._writeOut(pkt);
  }

  /** RFC 793 §3.4: respond to an unsolicited packet with a RST. seq is the
   *  ackNum the guest sent (the value the guest expects to be in our seq);
   *  ack is its seq + payload bytes (+ 1 if SYN, +1 if FIN). For a plain SYN
   *  payloadLen is 0 but SYN itself consumes 1. */
  private _sendUnsolicitedRst(ip: IPv4Header, tcp: TcpHeader): void {
    const payloadLen = ip.payloadOffset + ip.payloadLength - tcp.payloadOffset;
    const synBit = (tcp.flags & TCP_SYN) !== 0 ? 1 : 0;
    const finBit = (tcp.flags & TCP_FIN) !== 0 ? 1 : 0;
    const ack = (tcp.seqNum + payloadLen + synBit + finBit) >>> 0;
    // If the incoming packet had ACK, use its ackNum as our seq; otherwise
    // RST seq=0 per RFC 793.
    const seq = (tcp.flags & TCP_ACK) !== 0 ? tcp.ackNum >>> 0 : 0;

    const seg = buildTcpSegment(
      tcp.dstPort, // remote (src on wire)
      tcp.srcPort, // guest (dst on wire)
      seq,
      ack,
      TCP_RST | TCP_ACK,
      0,
      new Uint8Array(0),
      ip.dstIp,
      ip.srcIp,
    );
    const pkt = buildIPv4Packet(ip.dstIp, ip.srcIp, IP_PROTO_TCP, seg);
    this._writeOut(pkt);
  }

  private _sendRstForConn(conn: TcpConnection): void {
    this._sendTcpToVm(conn, TCP_RST | TCP_ACK, conn.ourSeqNext, conn.vmSeqNext, null);
    conn.state = 'closed';
  }

  private _writeOut(packet: Uint8Array): void {
    const w = this.writer;
    if (!w) return;
    // Fire-and-forget; the WritableStream serializes internally.
    w.write(packet).catch((err) => {
      // eslint-disable-next-line no-console
      console.warn('TcpNat: tun.writable.write rejected:', err);
    });
  }

  private _teardown(conn: TcpConnection): void {
    if (conn.state !== 'closed') {
      try {
        conn.stream?.close();
      } catch {
        /* ignore */
      }
      conn.state = 'closed';
    }
    this.conns.delete(conn.key);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeKey(srcIp: number, srcPort: number, dstIp: number, dstPort: number): string {
  return `${srcIp >>> 0}:${srcPort}->${dstIp >>> 0}:${dstPort}`;
}

/** Returns a uniformly distributed uint32. Uses crypto when available
 *  (browsers, Node 17+) and falls back to Math.random otherwise. */
function randomU32(): number {
  const c = (globalThis as unknown as { crypto?: Crypto }).crypto;
  if (c && typeof c.getRandomValues === 'function') {
    const buf = new Uint32Array(1);
    c.getRandomValues(buf);
    return buf[0] >>> 0;
  }
  return (Math.floor(Math.random() * 0x100000000) >>> 0);
}
