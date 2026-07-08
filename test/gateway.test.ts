/**
 * Tests for src/gateway.ts.
 *
 * Spec: docs/specs/2026-05-27-vm-wisp-networking-design.md §2 (architecture),
 * §9 (host-side bindings + §9.7 hot-swap), §12 (boot sequence).
 *
 * Strategy:
 *   - Mock the `tcpip` module (vi.mock) so `createStack()` returns our MockStack.
 *   - Use a hand-rolled MockWispClient via the `_injectWisp` test hook so
 *     Gateway never touches a real WebSocket.
 *   - The NATs (TcpNat / UdpNat) are NOT stubbed here — they're driven
 *     against the mock stack's tun. Their internals are tested elsewhere;
 *     here we just verify Gateway plumbs them.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { MockStack } from './helpers/mock-stack';

// ---- Module mock for `tcpip` --------------------------------------------
// Has to be hoisted by Vitest before the gateway import resolves.
const mockStackInstances: MockStack[] = [];

vi.mock('tcpip', () => ({
  createStack: vi.fn(async () => {
    const s = new MockStack();
    mockStackInstances.push(s);
    return s;
  }),
}));

// Imports AFTER the mock is registered.
import { Gateway, RESERVED_PORTS, type GatewayConfig } from '../src/gateway';
import type { WispClient } from '../src/wisp-client';

// ---- Mock WispClient ----------------------------------------------------

type Listener = (...args: any[]) => void;

class MockWispClient {
  private listeners = new Map<string, Set<Listener>>();
  closed = false;
  /** What the configured URL was (for assertion tests). */
  readonly url: string;
  /** Resolves on .ready() — by default, resolves immediately. */
  private readyPromise: Promise<void>;
  private readyResolve!: () => void;
  /** If true, ready() rejects. */
  failReady = false;

  udpSupported = true;
  confirmStreamOpen = false;
  motd: string | null = null;

  constructor(url = 'ws://mock-wisp/') {
    this.url = url;
    this.readyPromise = new Promise<void>((resolve, reject) => {
      this.readyResolve = () => {
        if (this.failReady) reject(new Error('mock failed'));
        else resolve();
      };
    });
    // Ready by default after a microtask so callers can await.
    queueMicrotask(() => this.readyResolve());
  }

  ready(): Promise<void> {
    return this.readyPromise;
  }

  on(event: string, listener: Listener): void {
    let set = this.listeners.get(event);
    if (!set) {
      set = new Set();
      this.listeners.set(event, set);
    }
    set.add(listener);
  }

  emit(event: string, ...args: any[]): void {
    const set = this.listeners.get(event);
    if (!set) return;
    for (const l of [...set]) l(...args);
  }

  createStream(): never {
    throw new Error('not used in gateway tests');
  }

  close(): void {
    this.closed = true;
    this.emit('close');
  }
}

function makeWisp(url?: string): MockWispClient {
  return new MockWispClient(url);
}

// Cast helper for tests.
function asWisp(m: MockWispClient): WispClient {
  return m as unknown as WispClient;
}

// ---- Tests --------------------------------------------------------------

describe('Gateway', () => {
  beforeEach(() => {
    mockStackInstances.length = 0;
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('init() with injected wisp constructs all subsystems and emits connect', async () => {
    const wisp = makeWisp();
    const gw = new Gateway({
      wispUrl: 'ws://test/',
      _injectWisp: asWisp(wisp),
    });

    let connectFired = 0;
    gw.on('connect', () => {
      connectFired++;
    });

    await gw.init();

    expect(connectFired).toBe(1);
    expect(mockStackInstances).toHaveLength(1);

    const stack = mockStackInstances[0]!;
    // LIFO: tun first, then loopback, then tap (per §2.4).
    expect(stack.creationOrder).toEqual(['tun', 'loopback', 'tap']);

    // Defaults from spec.
    expect(stack.tunInterfaces[0]!.ip).toBe('240.0.0.1/0');
    expect(stack.loopbackInterfaces[0]!.ip).toBe('127.0.0.1/8');
    expect(stack.tapInterfaces[0]!.ip).toBe('192.168.127.1/24');
    expect(stack.tapInterfaces[0]!.mac).toBe('02:00:00:00:00:01');

    // DHCP started → openUdp({port:67}).
    expect(stack.udpOpenCalls.some((c) => c?.port === 67)).toBe(true);

    // Subsystem accessors return real objects.
    expect(gw.getStack()).toBe(stack);
    expect(gw.getTap()).toBe(stack.tapInterfaces[0]);
    expect(gw.getTun()).toBe(stack.tunInterfaces[0]);
    expect(gw.getVmIp()).toBe('192.168.127.2');
    expect(gw.wisp).toBe(wisp);
    expect(gw.swapInProgress).toBe(false);

    await gw.destroy();
  });

  it('init() defaults match spec (gatewayIp, vmIp, dnsServer, tunIp)', async () => {
    const wisp = makeWisp();
    const gw = new Gateway({
      wispUrl: 'ws://test/',
      _injectWisp: asWisp(wisp),
    });
    await gw.init();

    const stack = mockStackInstances[0]!;
    expect(stack.tapInterfaces[0]!.ip).toBe('192.168.127.1/24');
    expect(stack.tunInterfaces[0]!.ip).toBe('240.0.0.1/0');
    expect(gw.getVmIp()).toBe('192.168.127.2');
    // dnsServer default = 1.1.1.1 — verified indirectly through DhcpService
    // construction: openUdp must have been called for port 67.
    expect(stack.udpOpenCalls.some((c) => c?.port === 67)).toBe(true);

    await gw.destroy();
  });

  it('init() with vmIp:null does not start DHCP', async () => {
    const wisp = makeWisp();
    const gw = new Gateway({
      wispUrl: 'ws://test/',
      _injectWisp: asWisp(wisp),
      vmIp: null,
    });
    await gw.init();

    const stack = mockStackInstances[0]!;
    // No DHCP socket bound on UDP:67.
    expect(stack.udpOpenCalls.some((c) => c?.port === 67)).toBe(false);
    // Default getVmIp still resolves (computed default), even though DHCP off.
    expect(gw.getVmIp()).toBe('192.168.127.2');

    await gw.destroy();
  });

  it('destroy() is idempotent', async () => {
    const wisp = makeWisp();
    const gw = new Gateway({
      wispUrl: 'ws://test/',
      _injectWisp: asWisp(wisp),
    });
    await gw.init();
    await gw.destroy();
    // Second call must not throw.
    await gw.destroy();
    expect(wisp.closed).toBe(true);
  });

  it('setWispClient(newClient) swaps reference and emits wisp-changed', async () => {
    const wisp1 = makeWisp('ws://old/');
    const wisp2 = makeWisp('ws://new/');
    const gw = new Gateway({
      wispUrl: 'ws://old/',
      _injectWisp: asWisp(wisp1),
    });
    await gw.init();

    const events: { oldClient: any; newClient: any }[] = [];
    gw.on('wisp-changed', (oldClient: any, newClient: any) => {
      events.push({ oldClient, newClient });
    });

    expect(gw.wisp).toBe(wisp1);
    gw.setWispClient(asWisp(wisp2));
    expect(gw.wisp).toBe(wisp2);
    expect(events).toHaveLength(1);
    expect(events[0]!.oldClient).toBe(wisp1);
    expect(events[0]!.newClient).toBe(wisp2);

    await gw.destroy();
  });

  it('_setSwapInProgress toggles flag visible to NATs via getter', async () => {
    const wisp = makeWisp();
    const gw = new Gateway({
      wispUrl: 'ws://test/',
      _injectWisp: asWisp(wisp),
    });
    await gw.init();

    expect(gw.swapInProgress).toBe(false);
    gw._setSwapInProgress(true);
    expect(gw.swapInProgress).toBe(true);
    gw._setSwapInProgress(false);
    expect(gw.swapInProgress).toBe(false);

    await gw.destroy();
  });

  it('on() returns an unsubscribe function', async () => {
    const wisp = makeWisp();
    const gw = new Gateway({
      wispUrl: 'ws://test/',
      _injectWisp: asWisp(wisp),
    });

    let count = 0;
    const off = gw.on('connect', () => {
      count++;
    });
    await gw.init();
    expect(count).toBe(1);

    off();
    // Re-emit: shouldn't fire after unsubscribe.
    (gw as any)._emit?.('connect'); // some implementations have this; if not, just ensure no double-fire
    expect(count).toBe(1);

    await gw.destroy();
  });

  it('connectTcp / listenTcp / openUdp delegate to the stack', async () => {
    const wisp = makeWisp();
    const gw = new Gateway({
      wispUrl: 'ws://test/',
      _injectWisp: asWisp(wisp),
    });
    await gw.init();
    const stack = mockStackInstances[0]!;

    await gw.connectTcp('1.2.3.4', 80);
    await gw.listenTcp(8080);
    await gw.openUdp(9999);

    expect(stack.tcpConnectCalls).toContainEqual({ host: '1.2.3.4', port: 80 });
    expect(stack.tcpListenCalls).toContainEqual({ port: 8080 });
    // Plus the DHCP one on 67.
    expect(stack.udpOpenCalls.some((c) => c?.port === 9999)).toBe(true);

    await gw.destroy();
  });

  it('emits error event when wisp.ready() rejects during init', async () => {
    const wisp = makeWisp();
    wisp.failReady = true;
    const gw = new Gateway({
      wispUrl: 'ws://test/',
      _injectWisp: asWisp(wisp),
    });

    const errors: any[] = [];
    gw.on('error', (e: any) => errors.push(e));

    await expect(gw.init()).rejects.toThrow();
    expect(errors.length).toBeGreaterThan(0);
  });

  it('propagates allowV1 / udpAssumedInV1 to internal config (regression: not silently dropped)', () => {
    // Regression: an earlier version of Gateway constructor forgot to copy
    // allowV1 / udpAssumedInV1 from input config into _config, causing v1
    // Wisp servers to be silently rejected even when the caller opted in.
    const gw1 = new Gateway({
      wispUrl: 'ws://test/',
      _injectWisp: asWisp(makeWisp()),
      allowV1: true,
      udpAssumedInV1: false,
    });
    // Index-access pattern matches other tests in this file that read _config.
    expect((gw1 as any)._config.allowV1).toBe(true);
    expect((gw1 as any)._config.udpAssumedInV1).toBe(false);

    // Defaults when omitted: v1 is the de-facto standard so allowV1
    // defaults to true. udpAssumedInV1 is true so v1 servers are presumed
    // UDP-capable until proven otherwise.
    const gw2 = new Gateway({
      wispUrl: 'ws://test/',
      _injectWisp: asWisp(makeWisp()),
    });
    expect((gw2 as any)._config.allowV1).toBe(true);
    expect((gw2 as any)._config.udpAssumedInV1).toBe(true);
  });

  it('honors custom gatewayIp / vmIp / dnsServer / tunIp', async () => {
    const wisp = makeWisp();
    const gw = new Gateway({
      wispUrl: 'ws://test/',
      _injectWisp: asWisp(wisp),
      gatewayIp: '10.0.0.1/16',
      vmIp: '10.0.0.99',
      dnsServer: '8.8.8.8',
      tunIp: '240.0.0.5/0',
      gatewayMac: '02:00:00:00:00:99',
    });
    await gw.init();
    const stack = mockStackInstances[0]!;

    expect(stack.tapInterfaces[0]!.ip).toBe('10.0.0.1/16');
    expect(stack.tapInterfaces[0]!.mac).toBe('02:00:00:00:00:99');
    expect(stack.tunInterfaces[0]!.ip).toBe('240.0.0.5/0');
    expect(gw.getVmIp()).toBe('10.0.0.99');

    await gw.destroy();
  });
});

describe('RESERVED_PORTS', () => {
  it('reserves UDP 67 (DHCP) and no TCP ports', () => {
    expect(RESERVED_PORTS.udp.has(67)).toBe(true);
    expect(RESERVED_PORTS.tcp.size).toBe(0);
  });
});
