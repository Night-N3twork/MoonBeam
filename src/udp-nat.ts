/**
 * UdpNat — UDP NAT for guest → internet egress over Wisp.
 *
 * Per spec §6 of `docs/specs/2026-05-27-vm-wisp-networking-design.md`.
 *
 * Reads raw IPv4 packets from `tun.readable`. For UDP packets:
 *   - Consults the egress policy; on denial synthesizes ICMP port-unreachable
 *     back to the guest.
 *   - Maps each (srcIp, srcPort, dstIp, dstPort) 5-tuple to a Wisp UDP stream.
 *   - Forwards datagrams in both directions, building IPv4+UDP packets for
 *     responses delivered to `tun.writable`.
 *
 * Flows are tracked with LRU eviction by lastActivity (cap = `maxFlows`,
 * default 1024) and an idle sweeper closes flows older than `idleTimeoutMs`
 * (default 60_000ms).
 *
 * During a Wisp client hot-swap (`getSwapInProgress() === true`), inbound
 * datagrams are dropped (with optional ICMP unreachable) — UDP is simpler
 * than TCP, no queueing per spec §6.7. The next datagram retries.
 */
import {
  parseIPv4,
  parseUdp,
  buildIPv4Packet,
  buildUdpSegment,
  buildIcmpPortUnreachable,
  numToIp,
  IP_PROTO_UDP,
} from './packet';
import type { EgressPolicy } from './policy';
import type { WispClient, WispStream } from './wisp-client';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface UdpNatConfig {
  tun: {
    readable: ReadableStream<Uint8Array>;
    writable: WritableStream<Uint8Array>;
  };
  /** Returns the *current* WispClient. Re-read on each new flow so swaps land. */
  getWisp: () => WispClient;
  /** Returns true while a Wisp swap is in progress; new flows are dropped. */
  getSwapInProgress: () => boolean;
  policy: EgressPolicy;
  /** Idle flow timeout. Default: 60_000ms. */
  idleTimeoutMs?: number;
  /** Max concurrent flows. Default: 1024. */
  maxFlows?: number;
}

export interface UdpNatStats {
  activeFlows: number;
  totalFlowsCreated: number;
  totalDatagramsForwarded: number;
  totalDatagramsDropped: number;
}

// ---------------------------------------------------------------------------
// Internal flow state
// ---------------------------------------------------------------------------

interface UdpFlow {
  key: string;
  srcIp: number;
  srcPort: number;
  dstIp: number;
  dstPort: number;
  /**
   * The Wisp stream backing this flow. Null only during the brief window
   * between flow registration and successful `wisp.createStream()` (or if
   * stream creation threw — in which case the flow gets removed).
   */
  stream: WispStream | null;
  /** True after the Wisp stream's 'open' event fires. */
  ready: boolean;
  /** Datagrams buffered before `ready`. Drained in order on 'open'. */
  sendQueue: Uint8Array[];
  /** Date.now() ms of last inbound or outbound activity; drives LRU + idle. */
  lastActivity: number;
}

const DEFAULT_IDLE_TIMEOUT_MS = 60_000;
const DEFAULT_MAX_FLOWS = 1024;

function makeFlowKey(
  srcIp: number,
  srcPort: number,
  dstIp: number,
  dstPort: number,
): string {
  return `${srcIp >>> 0}:${srcPort}->${dstIp >>> 0}:${dstPort}`;
}

// ---------------------------------------------------------------------------
// UdpNat
// ---------------------------------------------------------------------------

export class UdpNat {
  private readonly tun: UdpNatConfig['tun'];
  private readonly getWisp: () => WispClient;
  private readonly getSwapInProgress: () => boolean;
  private readonly policy: EgressPolicy;
  private readonly idleTimeoutMs: number;
  private readonly maxFlows: number;

  private readonly flows = new Map<string, UdpFlow>();

  // Stats
  private statsTotalFlowsCreated = 0;
  private statsTotalDatagramsForwarded = 0;
  private statsTotalDatagramsDropped = 0;

  // Lifecycle
  private started = false;
  private destroyed = false;
  private sweeperTimer: ReturnType<typeof setInterval> | null = null;
  private tunWriter: WritableStreamDefaultWriter<Uint8Array> | null = null;
  private readLoopAbort: AbortController | null = null;
  private readLoopDone: Promise<void> | null = null;

  constructor(config: UdpNatConfig) {
    this.tun = config.tun;
    this.getWisp = config.getWisp;
    this.getSwapInProgress = config.getSwapInProgress;
    this.policy = config.policy;
    this.idleTimeoutMs = config.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS;
    this.maxFlows = config.maxFlows ?? DEFAULT_MAX_FLOWS;
  }

  // ---- public surface ----------------------------------------------------

  async start(): Promise<void> {
    if (this.started) throw new Error('UdpNat: start() called twice');
    if (this.destroyed) throw new Error('UdpNat: start() after destroy()');
    this.started = true;

    this.tunWriter = this.tun.writable.getWriter();

    // Idle sweeper. Cap interval at 15s to amortize cost on long timeouts.
    const sweepInterval = Math.min(this.idleTimeoutMs / 4, 15_000);
    this.sweeperTimer = setInterval(() => this.runSweeper(), sweepInterval);

    this.readLoopAbort = new AbortController();
    this.readLoopDone = this.runReadLoop(this.readLoopAbort.signal);
  }

  /**
   * Close every active flow's Wisp stream, then drop them.
   * No packets are sent to the guest (UDP is connectionless; the next datagram
   * opens a fresh flow on whichever WispClient is current).
   *
   * @returns The number of flows that were active.
   */
  resetAll(): number {
    const count = this.flows.size;
    for (const flow of this.flows.values()) {
      if (flow.stream) {
        try {
          flow.stream.close(0x02); // VOLUNTARY
        } catch {
          /* ignore */
        }
      }
    }
    this.flows.clear();
    return count;
  }

  get activeFlows(): number {
    return this.flows.size;
  }

  getStats(): UdpNatStats {
    return {
      activeFlows: this.flows.size,
      totalFlowsCreated: this.statsTotalFlowsCreated,
      totalDatagramsForwarded: this.statsTotalDatagramsForwarded,
      totalDatagramsDropped: this.statsTotalDatagramsDropped,
    };
  }

  async destroy(): Promise<void> {
    if (this.destroyed) return;
    this.destroyed = true;

    if (this.sweeperTimer) {
      clearInterval(this.sweeperTimer);
      this.sweeperTimer = null;
    }

    // Close all flows.
    this.resetAll();

    // Stop the read loop.
    if (this.readLoopAbort) {
      this.readLoopAbort.abort();
      this.readLoopAbort = null;
    }
    if (this.readLoopDone) {
      try {
        await this.readLoopDone;
      } catch {
        /* ignore */
      }
      this.readLoopDone = null;
    }

    if (this.tunWriter) {
      try {
        this.tunWriter.releaseLock();
      } catch {
        /* ignore */
      }
      this.tunWriter = null;
    }
  }

  // ---- read loop ---------------------------------------------------------

  private async runReadLoop(signal: AbortSignal): Promise<void> {
    const reader = this.tun.readable.getReader();
    const onAbort = () => {
      try {
        reader.cancel();
      } catch {
        /* ignore */
      }
    };
    signal.addEventListener('abort', onAbort, { once: true });
    try {
      while (!signal.aborted) {
        const { value, done } = await reader.read();
        if (done) break;
        if (!value) continue;
        try {
          this.handlePacket(value);
        } catch (err) {
          // Per-packet errors must never break the loop.
          // eslint-disable-next-line no-console
          console.error('UdpNat: handlePacket threw:', err);
        }
      }
    } catch {
      // reader cancelled or stream errored; exit cleanly.
    } finally {
      try {
        reader.releaseLock();
      } catch {
        /* ignore */
      }
    }
  }

  // ---- inbound (guest → internet) ---------------------------------------

  private handlePacket(pkt: Uint8Array): void {
    const ip = parseIPv4(pkt, 0);
    if (!ip) return;
    if (ip.protocol !== IP_PROTO_UDP) return;

    const udp = parseUdp(pkt, ip.payloadOffset);
    if (!udp) return;

    const { srcIp, dstIp } = ip;
    const { srcPort, dstPort } = udp;

    if (!this.policy.permits(dstIp, dstPort, 'udp')) {
      this.dropAndIcmp(pkt);
      return;
    }

    const wisp = this.getWisp();
    if (!wisp.udpSupported) {
      this.dropAndIcmp(pkt);
      return;
    }

    if (this.getSwapInProgress()) {
      // Per §6.7 — drop, optionally with ICMP unreach. Next packet retries.
      this.dropAndIcmp(pkt);
      return;
    }

    const key = makeFlowKey(srcIp, srcPort, dstIp, dstPort);
    let flow = this.flows.get(key);
    if (!flow) {
      // Enforce the cap with LRU-by-lastActivity eviction.
      if (this.flows.size >= this.maxFlows) {
        this.evictLru();
      }
      flow = this.createFlow(key, srcIp, srcPort, dstIp, dstPort, wisp) ?? undefined;
      if (!flow) {
        // Stream construction failed (wisp threw). Drop this datagram; the
        // next one will retry.
        this.statsTotalDatagramsDropped++;
        return;
      }
    }

    flow.lastActivity = Date.now();

    // The UDP payload spans from udp.payloadOffset to ip.payloadOffset +
    // ip.payloadLength. Slice into a stable copy: queueing keeps a reference
    // and the caller's buffer may be reused.
    const payloadEnd = ip.payloadOffset + ip.payloadLength;
    const payload = pkt.slice(udp.payloadOffset, payloadEnd);

    if (flow.ready && flow.stream) {
      try {
        flow.stream.send(payload);
        this.statsTotalDatagramsForwarded++;
      } catch {
        // Stream is dead; the close handler will clean it up. Drop this
        // datagram.
        this.statsTotalDatagramsDropped++;
      }
    } else {
      flow.sendQueue.push(payload);
    }
  }

  private createFlow(
    key: string,
    srcIp: number,
    srcPort: number,
    dstIp: number,
    dstPort: number,
    wisp: WispClient,
  ): UdpFlow | null {
    const flow: UdpFlow = {
      key,
      srcIp,
      srcPort,
      dstIp,
      dstPort,
      stream: null,
      ready: false,
      sendQueue: [],
      lastActivity: Date.now(),
    };
    // Insert into the map BEFORE creating the stream so synchronous event
    // listeners (e.g., 'open' fired via queueMicrotask) can find the flow.
    this.flows.set(key, flow);
    this.statsTotalFlowsCreated++;

    let stream: WispStream;
    try {
      stream = wisp.createStream(numToIp(dstIp), dstPort, 'udp');
    } catch {
      // E.g., wisp not ready or UDP not supported. Roll back and let the
      // next datagram retry.
      this.flows.delete(key);
      return null;
    }
    flow.stream = stream;

    stream.on('open', () => {
      // The flow may have been evicted/closed in the brief microtask window.
      if (!this.flows.has(key) || this.flows.get(key) !== flow) return;
      flow.ready = true;
      // Drain queued sends in the order received.
      const queued = flow.sendQueue;
      flow.sendQueue = [];
      for (const buf of queued) {
        try {
          stream.send(buf);
          this.statsTotalDatagramsForwarded++;
        } catch {
          this.statsTotalDatagramsDropped++;
        }
      }
    });

    stream.on('data', (bytes: Uint8Array) => {
      this.onWispData(flow, bytes).catch((err) => {
        // eslint-disable-next-line no-console
        console.error('UdpNat: onWispData failed:', err);
      });
    });

    stream.on('close', () => {
      // Forget the flow if it's still ours. (A subsequent guest datagram
      // will create a fresh flow.)
      if (this.flows.get(key) === flow) this.flows.delete(key);
    });

    stream.on('error', () => {
      if (this.flows.get(key) === flow) this.flows.delete(key);
    });

    return flow;
  }

  // ---- outbound (internet → guest) --------------------------------------

  private async onWispData(flow: UdpFlow, data: Uint8Array): Promise<void> {
    flow.lastActivity = Date.now();
    // Build IPv4+UDP packet: src = remote (dstIp from guest's perspective),
    // dst = guest (srcIp from guest's perspective).
    const udpSeg = buildUdpSegment(
      flow.dstPort,
      flow.srcPort,
      data,
      flow.dstIp,
      flow.srcIp,
    );
    const ipPkt = buildIPv4Packet(flow.dstIp, flow.srcIp, IP_PROTO_UDP, udpSeg);
    if (!this.tunWriter) return;
    try {
      await this.tunWriter.write(ipPkt);
    } catch {
      // tun is closed/errored; stop trying.
    }
  }

  // ---- ICMP unreach helper ----------------------------------------------

  private dropAndIcmp(originalPkt: Uint8Array): void {
    this.statsTotalDatagramsDropped++;
    let icmp: Uint8Array;
    try {
      icmp = buildIcmpPortUnreachable(originalPkt);
    } catch {
      return;
    }
    if (!this.tunWriter) return;
    // Fire-and-forget. Errors here are non-fatal.
    this.tunWriter.write(icmp).catch(() => {
      /* ignore */
    });
  }

  // ---- LRU eviction & idle sweeper --------------------------------------

  private evictLru(): void {
    let oldestKey: string | null = null;
    let oldestActivity = Infinity;
    for (const [key, flow] of this.flows) {
      if (flow.lastActivity < oldestActivity) {
        oldestActivity = flow.lastActivity;
        oldestKey = key;
      }
    }
    if (oldestKey == null) return;
    const flow = this.flows.get(oldestKey)!;
    if (flow.stream) {
      try {
        flow.stream.close(0x02);
      } catch {
        /* ignore */
      }
    }
    this.flows.delete(oldestKey);
  }

  private runSweeper(): void {
    const now = Date.now();
    const expired: string[] = [];
    for (const [key, flow] of this.flows) {
      if (now - flow.lastActivity > this.idleTimeoutMs) expired.push(key);
    }
    for (const key of expired) {
      const flow = this.flows.get(key);
      if (!flow) continue;
      if (flow.stream) {
        try {
          flow.stream.close(0x02);
        } catch {
          /* ignore */
        }
      }
      this.flows.delete(key);
    }
  }
}
