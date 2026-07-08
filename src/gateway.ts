/**
 * Gateway — top-level orchestrator of the network core.
 *
 * Owns the lwIP NetworkStack (via `tcpip.js`), the WispClient, and the four
 * subsystems wired off the stack:
 *   - `DhcpService` (lwIP UDP:67) — single-client lease for the VM.
 *   - `TcpNat`     — reads forwarded IPv4/TCP packets from the Tun, opens
 *                    Wisp TCP streams, NATs traffic in both directions.
 *   - `UdpNat`     — same for UDP, with per-5-tuple flow tracking.
 *   - `EgressPolicy` — pure decision function consulted by the NATs.
 *
 * Spec sections honored:
 *   §2 (architecture)            §9 (host-side service bindings)
 *   §9.7 (hot-swap support)      §12 (boot sequence)
 *   §2.4 (LIFO interface order)
 *
 * Boot sequence (§12.2 + §9.7):
 *   1. Construct EgressPolicy.
 *   2. Construct or use injected WispClient.
 *   3. await wisp.ready() — handshake complete.
 *   4. createStack({ initializeLoopback: false }) — we manage interfaces.
 *   5. Tun  (240.0.0.1/0, Class E, never-routable; spec §2.4)  — pushed FIRST.
 *   6. Loopback (127.0.0.1/8).
 *   7. Tap  (192.168.127.1/24)                                  — pushed LAST,
 *      so it ends up at lwIP's LIFO head and matches LAN first.
 *   8. DhcpService (skip if config.vmIp === null).
 *   9. TcpNat (with getWisp + getSwapInProgress getters).
 *  10. UdpNat (same).
 *  11. emit 'connect'.
 *
 * Hot-swap (§9.7): `setWispClient(newClient)` is a single-line atomic
 * reference swap. The full orchestration (resetAll, swapInProgress flagging,
 * old-client close) lives in the session-and-resilience spec; this class just
 * exposes the primitives.
 *
 * The NATs see the *current* WispClient by virtue of the `getWisp` callback
 * they were given: it returns `this._wisp`, which `setWispClient` updates.
 */

import { createStack, type NetworkStack, type TapInterface, type TunInterface } from 'tcpip';

import type { EgressPolicyConfig } from './policy';
import { EgressPolicy } from './policy';
import { WispClient } from './wisp-client';
import { TcpNat } from './tcp-nat';
import { UdpNat } from './udp-nat';
import { DhcpService } from './dhcp-service';
import { ipToNum, numToIp, parseCidr } from './packet';
import { createSoftRouter, type SoftRouter } from './soft-router';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface GatewayConfig {
  /** Wisp v2 endpoint. */
  wispUrl: string;

  /** Egress policy. Default: { allow: ['public'] }. */
  egress?: EgressPolicyConfig;

  /** LAN side: gateway IP in CIDR notation. Default: '192.168.127.1/24'. */
  gatewayIp?: string;

  /** Gateway MAC. Default: '02:00:00:00:00:01'. */
  gatewayMac?: string;

  /**
   * VM IP to hand out via DHCP. Default: gatewayIp + 1 (e.g. '192.168.127.2').
   * Pass `null` to disable DHCP entirely.
   */
  vmIp?: string | null;

  /** DNS to advertise in DHCP. Default: '1.1.1.1'. */
  dnsServer?: string;

  /** DHCP lease seconds. Default: 86400. */
  dhcpLeaseTime?: number;

  /**
   * TunInterface IP in CIDR. Default: '240.0.0.1/0' per spec §2.4 (Class E,
   * never routable, avoids collision with user-allowed CIDRs).
   */
  tunIp?: string;

  /**
   * Accept Wisp v1 servers. Default `false` (v2 only). When `true`, the
   * constructed WispClient skips the v2 INFO exchange when the server's
   * first packet is CONTINUE on stream 0. Forwarded to WispClient as-is;
   * see WispClientConfig.allowV1 for full semantics.
   */
  allowV1?: boolean;

  /**
   * Forwarded to WispClient as-is. Only meaningful when allowV1 is true.
   * Default: true (matches every observed v1 server in the wild).
   */
  udpAssumedInV1?: boolean;

  /**
   * Test-only: pre-built WispClient. If absent, Gateway constructs one from
   * `wispUrl`. Used by integration tests and by the session-resilience
   * orchestrator, which constructs WispClients itself.
   */
  _injectWisp?: WispClient;
}

/**
 * Reserved port set per spec §9.3. Host code should consult these before
 * binding services with `gateway.listenTcp` / `gateway.openUdp`.
 */
export const RESERVED_PORTS = {
  tcp: new Set<number>(),
  udp: new Set<number>([67]),
} as const;

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_GATEWAY_IP = '192.168.127.1/24';
const DEFAULT_GATEWAY_MAC = '02:00:00:00:00:01';
const DEFAULT_DNS_SERVER = '1.1.1.1';
const DEFAULT_DHCP_LEASE = 86400;
const DEFAULT_TUN_IP = '240.0.0.1/0';

// ---------------------------------------------------------------------------
// Tiny event emitter — same shape as wisp-client's, but `on` returns an
// unsubscribe function (per the shells/session spec consumer requirement).
// ---------------------------------------------------------------------------

type Listener = (...args: any[]) => void;

class TinyEmitter {
  private _listeners = new Map<string, Set<Listener>>();

  on(event: string, listener: Listener): () => void {
    let set = this._listeners.get(event);
    if (!set) {
      set = new Set();
      this._listeners.set(event, set);
    }
    set.add(listener);
    return () => {
      const s = this._listeners.get(event);
      if (s) s.delete(listener);
    };
  }

  protected _emit(event: string, ...args: any[]): void {
    const set = this._listeners.get(event);
    if (!set) return;
    for (const l of [...set]) {
      try {
        l(...args);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error(`Gateway listener for '${event}' threw:`, err);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Gateway
// ---------------------------------------------------------------------------

export class Gateway extends TinyEmitter {
  // Configuration (resolved with defaults applied).
  private readonly _config: Required<Omit<GatewayConfig, '_injectWisp' | 'egress' | 'vmIp' | 'dhcpLeaseTime'>> & {
    egress: EgressPolicyConfig | undefined;
    vmIp: string | null;
    dhcpLeaseTime: number;
  };
  private readonly _vmIpResolved: string;

  // Runtime subsystems (set by init()).
  private _wisp!: WispClient;
  private _stack: NetworkStack | null = null;
  private _tap: TapInterface | null = null;
  private _tun: TunInterface | null = null;
  private _loopback: any = null; // LoopbackInterface; not exposed publicly.
  private _softRouter: SoftRouter | null = null;
  private _dhcp: DhcpService | null = null;
  private _tcpNat: TcpNat | null = null;
  private _udpNat: UdpNat | null = null;
  private _policy: EgressPolicy | null = null;

  // Lifecycle flags.
  private _initialized = false;
  private _destroyed = false;
  private _swapInProgress = false;
  /** Tear-down hook for the tun fan-out splitter (closes per-NAT readables,
   *  cancels the upstream reader, releases the shared writer). */
  private _splitterShutdown: (() => Promise<void>) | null = null;

  constructor(config: GatewayConfig) {
    super();
    this._config = {
      wispUrl: config.wispUrl,
      egress: config.egress,
      gatewayIp: config.gatewayIp ?? DEFAULT_GATEWAY_IP,
      gatewayMac: config.gatewayMac ?? DEFAULT_GATEWAY_MAC,
      vmIp: config.vmIp === undefined ? null /* placeholder, recomputed below */ : config.vmIp,
      dnsServer: config.dnsServer ?? DEFAULT_DNS_SERVER,
      dhcpLeaseTime: config.dhcpLeaseTime ?? DEFAULT_DHCP_LEASE,
      tunIp: config.tunIp ?? DEFAULT_TUN_IP,
      // v1 is the de-facto standard; default to accepting it. Set
      // allowV1: false explicitly to enforce v2-only.
      allowV1: config.allowV1 ?? true,
      udpAssumedInV1: config.udpAssumedInV1 ?? true,
    };

    // Resolve effective VM IP. If the user explicitly passed `null`, DHCP is
    // disabled — but we still want getVmIp() to return the *intended* address
    // (gatewayIp + 1) so host code reaching into the VM has a value to use.
    const computedDefault = computeDefaultVmIp(this._config.gatewayIp);
    if (config.vmIp === null) {
      this._config.vmIp = null; // DHCP disabled
      this._vmIpResolved = computedDefault;
    } else if (config.vmIp === undefined) {
      this._config.vmIp = computedDefault;
      this._vmIpResolved = computedDefault;
    } else {
      this._config.vmIp = config.vmIp;
      this._vmIpResolved = config.vmIp;
    }

    if (config._injectWisp) {
      this._wisp = config._injectWisp;
    }
  }

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  async init(): Promise<void> {
    if (this._initialized) return;
    if (this._destroyed) {
      throw new Error('Gateway: cannot init() after destroy()');
    }

    try {
      // 1. Egress policy.
      this._policy = new EgressPolicy(this._config.egress ?? { allow: ['public'] });

      // 2. WispClient (skip if injected).
      if (!this._wisp) {
        this._wisp = new WispClient({
          url: this._config.wispUrl,
          allowV1: this._config.allowV1,
          udpAssumedInV1: this._config.udpAssumedInV1,
        });
      }

      // 3. Wait for handshake.
      await this._wisp.ready();

      // 4. Create the lwIP stack. We manage interfaces ourselves so we
      //    explicitly disable the auto-loopback.
      this._stack = await createStack({ initializeLoopback: false });

      // 5-7. Interfaces in LIFO order: Tun first (tail/catch-all), Loopback,
      //      Tap last (head/LAN match).
      this._tun = await this._stack.createTunInterface({ ip: this._config.tunIp as any });
      this._loopback = await this._stack.createLoopbackInterface({ ip: '127.0.0.1/8' as any });
      this._tap = await this._stack.createTapInterface({
        mac: this._config.gatewayMac as any,
        ip: this._config.gatewayIp as any,
      });

      // 8. DHCP (only if vmIp is not null).
      if (this._config.vmIp !== null) {
        const { ip: gwIpNum, mask: gwMask } = parseCidr(this._config.gatewayIp);
        this._dhcp = new DhcpService({
          stack: this._stack,
          gatewayIp: gwIpNum,
          subnetMask: gwMask,
          vmIp: ipToNum(this._config.vmIp),
          dnsServer: ipToNum(this._config.dnsServer),
          leaseTime: this._config.dhcpLeaseTime,
        });
        await this._dhcp.start();
      }

      // 8b. Soft-router.
      //
      // The `tcpip` library is an endpoint host stack — it doesn't forward
      // IP between interfaces. The Tun we created above is therefore
      // unreachable from the guest (lwIP just drops off-subnet packets).
      //
      // The soft-router runs in parallel with lwIP: gateway-host delivers
      // every guest-origin Ethernet frame to BOTH lwIP (so ARP/ICMP/DHCP
      // keep working) AND the router (which extracts off-subnet IP
      // packets and pushes them onto a stream the NATs read from).
      //
      // The NATs reply by writing IP packets to the router's writable
      // side; the router wraps each in an Ethernet frame and emits it via
      // the same `send` callback gateway-host uses for lwIP's outgoing
      // frames. The Tun is retained (created above) only because some
      // tests still poke at it; it's dead code at runtime.
      const { ip: gwIpNum2, mask: gwMask2 } = parseCidr(this._config.gatewayIp);
      this._softRouter = createSoftRouter({
        gatewayIp: gwIpNum2,
        subnetMask: gwMask2,
        gatewayMac: this._config.gatewayMac,
      });

      // Two NATs share the router's `outgoing` readable; we tee it and
      // give each NAT its own write side (so they can issue replies
      // without contending for a single writer). The shared writable is
      // the router's `incoming` side; we route TcpNat and UdpNat replies
      // through tee-ing wrappers.
      const { tcpView, udpView, shutdown: splitterShutdown } = makeTunSplitter(
        this._softRouter.ipDuplex,
      );
      this._splitterShutdown = splitterShutdown;

      // 9. TcpNat — getWisp/getSwapInProgress are arrow callbacks so they
      //    always read the current Gateway state, even after a swap.
      this._tcpNat = new TcpNat({
        tun: tcpView,
        getWisp: () => this._wisp,
        getSwapInProgress: () => this._swapInProgress,
        policy: this._policy,
      });
      // start() runs the read-loop; we explicitly do NOT await it (it
      // resolves only on destroy).
      void this._tcpNat.start();

      // 10. UdpNat.
      this._udpNat = new UdpNat({
        tun: udpView,
        getWisp: () => this._wisp,
        getSwapInProgress: () => this._swapInProgress,
        policy: this._policy,
      });
      void this._udpNat.start();

      // 11. Done.
      this._initialized = true;
      this._emit('connect');
    } catch (err) {
      this._emit('error', err);
      // Best-effort cleanup of anything we managed to construct so the caller
      // can retry / reconfigure without a leak.
      try {
        await this._teardownPartial();
      } catch {
        /* ignore secondary errors during cleanup */
      }
      throw err;
    }
  }

  async destroy(): Promise<void> {
    if (this._destroyed) return;
    this._destroyed = true;

    // Order matters: stop the data-plane consumers first so they don't try
    // to talk to a closing WispClient mid-shutdown.
    if (this._tcpNat) {
      try { await this._tcpNat.destroy(); } catch { /* ignore */ }
    }
    if (this._udpNat) {
      try { await this._udpNat.destroy(); } catch { /* ignore */ }
    }
    // Now safe to tear down the tun splitter (NATs no longer hold its
    // reader/writer locks).
    if (this._splitterShutdown) {
      try { await this._splitterShutdown(); } catch { /* ignore */ }
      this._splitterShutdown = null;
    }
    if (this._dhcp) {
      try { await this._dhcp.destroy(); } catch { /* ignore */ }
    }
    if (this._wisp) {
      try { this._wisp.close(); } catch { /* ignore */ }
    }

    // tcpip.js's NetworkStack does not currently expose a documented close().
    // If a future version does, we'd call it here. Until then it's a no-op.

    this._emit('disconnect');
  }

  /** Teardown helper used by init()'s catch path. Best-effort. */
  private async _teardownPartial(): Promise<void> {
    if (this._tcpNat) {
      try { await this._tcpNat.destroy(); } catch { /* ignore */ }
      this._tcpNat = null;
    }
    if (this._udpNat) {
      try { await this._udpNat.destroy(); } catch { /* ignore */ }
      this._udpNat = null;
    }
    if (this._dhcp) {
      try { await this._dhcp.destroy(); } catch { /* ignore */ }
      this._dhcp = null;
    }
    if (this._wisp) {
      try { this._wisp.close(); } catch { /* ignore */ }
    }
  }

  // -------------------------------------------------------------------------
  // Subsystem accessors
  // -------------------------------------------------------------------------

  getStack(): NetworkStack {
    if (!this._stack) throw new Error('Gateway: not initialized');
    return this._stack;
  }

  getTap(): TapInterface {
    if (!this._tap) throw new Error('Gateway: not initialized');
    return this._tap;
  }

  getTun(): TunInterface {
    if (!this._tun) throw new Error('Gateway: not initialized');
    return this._tun;
  }

  /**
   * The soft-router that runs in parallel to lwIP. Used by gateway-host to
   * tee guest frames into the off-subnet IP forwarder. Internal API; only
   * the shell consumes it.
   */
  getSoftRouter(): SoftRouter {
    if (!this._softRouter) throw new Error('Gateway: not initialized');
    return this._softRouter;
  }

  getVmIp(): string {
    return this._vmIpResolved;
  }

  /** The currently-active WispClient. Read-only; do not mutate. */
  get wisp(): WispClient {
    return this._wisp;
  }

  /** True while a Wisp swap is in progress (per spec §9.7). */
  get swapInProgress(): boolean {
    return this._swapInProgress;
  }

  // -------------------------------------------------------------------------
  // Host-side service bindings (§9.1)
  // -------------------------------------------------------------------------

  async connectTcp(host: string, port: number): Promise<any> {
    if (!this._stack) throw new Error('Gateway: not initialized');
    return this._stack.connectTcp({ host, port });
  }

  async listenTcp(port: number): Promise<any> {
    if (!this._stack) throw new Error('Gateway: not initialized');
    return this._stack.listenTcp({ port });
  }

  async openUdp(port?: number): Promise<any> {
    if (!this._stack) throw new Error('Gateway: not initialized');
    return port === undefined ? this._stack.openUdp() : this._stack.openUdp({ port });
  }

  // -------------------------------------------------------------------------
  // Hot-swap support (§9.7)
  // -------------------------------------------------------------------------

  /**
   * Atomic single-statement reference swap. The session-resilience
   * orchestrator (`switchWispServer`) is responsible for the surrounding
   * choreography (resetAll, _setSwapInProgress flagging, closing the old
   * client). Most callers should not invoke this directly.
   */
  setWispClient(newClient: WispClient): void {
    const oldClient = this._wisp;
    this._wisp = newClient;
    this._emit('wisp-changed', oldClient, newClient);
  }

  /** Set swap-in-progress flag. Internal use by orchestrator. */
  _setSwapInProgress(value: boolean): void {
    this._swapInProgress = value;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Compute a sensible default VM IP — gatewayIp + 1, preserving the host. */
function computeDefaultVmIp(gatewayCidr: string): string {
  const { ip } = parseCidr(gatewayCidr);
  return numToIp((ip + 1) >>> 0);
}

/**
 * Fan one tun's (readable, writable) pair into two logical "tun" pairs, one
 * per NAT (TCP and UDP). Spec context: §2.1 — both NATs read the same Tun.
 *
 * The constraint: WHATWG streams allow exactly one reader and one writer.
 *
 * Why not `tee()`? Cancelling one branch of a `tee()` produces a Promise
 * that never resolves until the OTHER branch is also cancelled (the source
 * stays open). The NATs' destroy() awaits `reader.cancel()`, so a tee'd
 * branch deadlocks teardown.
 *
 * Instead we run a custom dispatch loop:
 *   - readable: a single reader on the real tun feeds two `ReadableStream`s
 *     (one per NAT) we control. Each NAT sees every packet (and ignores the
 *     ones it doesn't care about — TcpNat drops non-TCP; UdpNat drops
 *     non-UDP, so duplication is semantically identical).
 *   - writable: each NAT writes into its own `WritableStream` whose `write`
 *     forwards into a single shared writer on the real tun. Cross-NAT
 *     ordering is racy but irrelevant (TCP and UDP are independent flows).
 *
 * Calling `controller.close()` on each per-NAT readable during shutdown
 * makes any pending NAT-side `reader.read()` resolve with `done:true`,
 * unblocking destroy().
 */
function makeTunSplitter(realTun: {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
}): {
  tcpView: { readable: ReadableStream<Uint8Array>; writable: WritableStream<Uint8Array> };
  udpView: { readable: ReadableStream<Uint8Array>; writable: WritableStream<Uint8Array> };
  /** Tear down the splitter: cancel the upstream reader, close the per-NAT
   *  readables, release the writer. Idempotent. */
  shutdown: () => Promise<void>;
} {
  let tcpController!: ReadableStreamDefaultController<Uint8Array>;
  let udpController!: ReadableStreamDefaultController<Uint8Array>;

  const tcpReadable = new ReadableStream<Uint8Array>({
    start: (c) => { tcpController = c; },
  });
  const udpReadable = new ReadableStream<Uint8Array>({
    start: (c) => { udpController = c; },
  });

  // Single reader on the real tun — drives the dispatch loop.
  const upstreamReader = realTun.readable.getReader();
  let stopped = false;

  const dispatchLoop = (async () => {
    try {
      // eslint-disable-next-line no-constant-condition
      while (!stopped) {
        const { value, done } = await upstreamReader.read();
        if (done) break;
        if (!value) continue;
        // Enqueue into both branches. Wrap each enqueue in try because
        // a closed controller throws.
        try { tcpController.enqueue(value); } catch { /* tcp branch closed */ }
        try { udpController.enqueue(value); } catch { /* udp branch closed */ }
      }
    } catch {
      // Upstream errored or was cancelled — fall through to cleanup.
    }
  })();

  // Single writer to the real tun, shared by both NATs.
  const writer = realTun.writable.getWriter();

  const makeFanInWritable = (): WritableStream<Uint8Array> =>
    new WritableStream<Uint8Array>({
      write: async (chunk) => {
        if (stopped) return;
        try {
          await writer.write(chunk);
        } catch {
          // Writer closed/aborted — drop silently. Splitter is being torn down.
        }
      },
      // close/abort: deliberately no-op; the OTHER NAT may still be writing.
      close: () => undefined,
      abort: () => undefined,
    });

  const tcpWritable = makeFanInWritable();
  const udpWritable = makeFanInWritable();

  const shutdown = async (): Promise<void> => {
    if (stopped) return;
    stopped = true;
    // Cancel upstream so the dispatch loop's pending read() resolves.
    try { await upstreamReader.cancel(); } catch { /* ignore */ }
    try { upstreamReader.releaseLock(); } catch { /* ignore */ }
    // Close per-NAT branches so each NAT's reader.read() resolves done.
    try { tcpController.close(); } catch { /* already closed */ }
    try { udpController.close(); } catch { /* already closed */ }
    // Release the shared writer so consumers can close the underlying tun.
    try { writer.releaseLock(); } catch { /* ignore */ }
    try { await dispatchLoop; } catch { /* ignore */ }
  };

  return {
    tcpView: { readable: tcpReadable, writable: tcpWritable },
    udpView: { readable: udpReadable, writable: udpWritable },
    shutdown,
  };
}
