import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  FakeWebSocket,
  installFakeWebSocket,
  type FakeWebSocketHost,
} from '../src/fake-websocket';

function makeHost(overrides: Partial<FakeWebSocketHost> = {}): FakeWebSocketHost & {
  sends: Uint8Array[];
  connectCalls: number;
  closeCalls: number;
  pushBack: ((frame: Uint8Array) => void) | null;
} {
  const sends: Uint8Array[] = [];
  let connectCalls = 0;
  let closeCalls = 0;
  let pushBack: ((frame: Uint8Array) => void) | null = null;
  return {
    sends,
    connectCalls,
    closeCalls,
    get pushBack() {
      return pushBack;
    },
    set pushBack(v) {
      pushBack = v;
    },
    onConnect(send) {
      this.connectCalls = ++connectCalls;
      pushBack = send;
      this.pushBack = send;
      overrides.onConnect?.(send);
    },
    onSend(data) {
      sends.push(data);
      overrides.onSend?.(data);
    },
    onClose() {
      this.closeCalls = ++closeCalls;
      overrides.onClose?.();
    },
  };
}

// Wait for the next microtask flush.
async function flushMicrotasks(): Promise<void> {
  // Two awaits to ensure queueMicrotask callbacks have run.
  await Promise.resolve();
  await Promise.resolve();
}

describe('FakeWebSocket — construction & state', () => {
  test('readyState starts CONNECTING', () => {
    const host = makeHost();
    const ws = new FakeWebSocket('ws://wisp-gateway.local/', undefined, host);
    expect(ws.readyState).toBe(FakeWebSocket.CONNECTING);
    expect(FakeWebSocket.CONNECTING).toBe(0);
    expect(FakeWebSocket.OPEN).toBe(1);
    expect(FakeWebSocket.CLOSING).toBe(2);
    expect(FakeWebSocket.CLOSED).toBe(3);
  });

  test('default binaryType is "arraybuffer"', () => {
    const ws = new FakeWebSocket('ws://x/', undefined, makeHost());
    expect(ws.binaryType).toBe('arraybuffer');
  });

  test('url is recorded', () => {
    const ws = new FakeWebSocket('ws://wisp-gateway.local:1/', undefined, makeHost());
    expect(ws.url).toBe('ws://wisp-gateway.local:1/');
  });

  test('after microtask, transitions to OPEN and onConnect fires', async () => {
    const host = makeHost();
    const ws = new FakeWebSocket('ws://x/', undefined, host);
    expect(host.connectCalls).toBe(0);
    await flushMicrotasks();
    expect(ws.readyState).toBe(FakeWebSocket.OPEN);
    expect(host.connectCalls).toBe(1);
  });

  test('"open" event fires via addEventListener', async () => {
    const host = makeHost();
    const ws = new FakeWebSocket('ws://x/', undefined, host);
    const fn = vi.fn();
    ws.addEventListener('open', fn);
    await flushMicrotasks();
    expect(fn).toHaveBeenCalledTimes(1);
  });

  test('"open" event fires via onopen setter', async () => {
    const host = makeHost();
    const ws = new FakeWebSocket('ws://x/', undefined, host);
    const fn = vi.fn();
    ws.onopen = fn;
    await flushMicrotasks();
    expect(fn).toHaveBeenCalledTimes(1);
  });

  test('"open" event fires via BOTH addEventListener and onopen', async () => {
    const host = makeHost();
    const ws = new FakeWebSocket('ws://x/', undefined, host);
    const a = vi.fn();
    const b = vi.fn();
    ws.addEventListener('open', a);
    ws.onopen = b;
    await flushMicrotasks();
    expect(a).toHaveBeenCalledTimes(1);
    expect(b).toHaveBeenCalledTimes(1);
  });
});

describe('FakeWebSocket — send()', () => {
  test('Uint8Array passed through unchanged', async () => {
    const host = makeHost();
    const ws = new FakeWebSocket('ws://x/', undefined, host);
    await flushMicrotasks();
    const data = new Uint8Array([1, 2, 3]);
    ws.send(data);
    expect(host.sends.length).toBe(1);
    expect(host.sends[0]).toBeInstanceOf(Uint8Array);
    expect(Array.from(host.sends[0])).toEqual([1, 2, 3]);
  });

  test('ArrayBuffer is wrapped as Uint8Array view', async () => {
    const host = makeHost();
    const ws = new FakeWebSocket('ws://x/', undefined, host);
    await flushMicrotasks();
    const ab = new ArrayBuffer(3);
    new Uint8Array(ab).set([7, 8, 9]);
    ws.send(ab);
    expect(host.sends.length).toBe(1);
    expect(host.sends[0]).toBeInstanceOf(Uint8Array);
    expect(Array.from(host.sends[0])).toEqual([7, 8, 9]);
  });

  test('string is UTF-8 encoded', async () => {
    const host = makeHost();
    const ws = new FakeWebSocket('ws://x/', undefined, host);
    await flushMicrotasks();
    ws.send('hi');
    expect(host.sends.length).toBe(1);
    expect(Array.from(host.sends[0])).toEqual([0x68, 0x69]);
  });

  test('Blob throws (unsupported)', async () => {
    const host = makeHost();
    const ws = new FakeWebSocket('ws://x/', undefined, host);
    await flushMicrotasks();
    // Construct a fake Blob-like marker. If global Blob is available, use it.
    const fakeBlob =
      typeof Blob !== 'undefined' ? new Blob([new Uint8Array([1])]) : ({ size: 1, type: '' } as unknown);
    expect(() => ws.send(fakeBlob as any)).toThrow();
  });

  test('TypedArray view (Uint8Array offset) handled correctly', async () => {
    const host = makeHost();
    const ws = new FakeWebSocket('ws://x/', undefined, host);
    await flushMicrotasks();
    const big = new Uint8Array([0, 1, 2, 3, 4, 5]);
    const view = big.subarray(2, 5); // [2,3,4]
    ws.send(view);
    expect(host.sends.length).toBe(1);
    expect(Array.from(host.sends[0])).toEqual([2, 3, 4]);
  });
});

describe('FakeWebSocket — receive (host pushes frame)', () => {
  test('send fn dispatches "message" event with ArrayBuffer data via addEventListener', async () => {
    const host = makeHost();
    const ws = new FakeWebSocket('ws://x/', undefined, host);
    await flushMicrotasks();
    const received: any[] = [];
    ws.addEventListener('message', (e: any) => received.push(e));
    expect(host.pushBack).toBeTruthy();
    host.pushBack!(new Uint8Array([10, 20]));
    expect(received.length).toBe(1);
    expect(received[0].data).toBeInstanceOf(ArrayBuffer);
    expect(Array.from(new Uint8Array(received[0].data))).toEqual([10, 20]);
  });

  test('send fn dispatches "message" event via onmessage setter', async () => {
    const host = makeHost();
    const ws = new FakeWebSocket('ws://x/', undefined, host);
    await flushMicrotasks();
    const received: any[] = [];
    ws.onmessage = (e) => received.push(e);
    host.pushBack!(new Uint8Array([99]));
    expect(received.length).toBe(1);
    expect(Array.from(new Uint8Array(received[0].data))).toEqual([99]);
  });

  test('both onmessage and addEventListener fire', async () => {
    const host = makeHost();
    const ws = new FakeWebSocket('ws://x/', undefined, host);
    await flushMicrotasks();
    const a = vi.fn();
    const b = vi.fn();
    ws.addEventListener('message', a);
    ws.onmessage = b;
    host.pushBack!(new Uint8Array([1]));
    expect(a).toHaveBeenCalledTimes(1);
    expect(b).toHaveBeenCalledTimes(1);
  });
});

describe('FakeWebSocket — on* setter semantics', () => {
  test('replacing onmessage removes the previous handler', async () => {
    const host = makeHost();
    const ws = new FakeWebSocket('ws://x/', undefined, host);
    await flushMicrotasks();
    const old = vi.fn();
    const fresh = vi.fn();
    ws.onmessage = old;
    ws.onmessage = fresh;
    host.pushBack!(new Uint8Array([1]));
    expect(old).toHaveBeenCalledTimes(0);
    expect(fresh).toHaveBeenCalledTimes(1);
  });

  test('setting onmessage = null removes handler', async () => {
    const host = makeHost();
    const ws = new FakeWebSocket('ws://x/', undefined, host);
    await flushMicrotasks();
    const fn = vi.fn();
    ws.onmessage = fn;
    ws.onmessage = null;
    host.pushBack!(new Uint8Array([1]));
    expect(fn).toHaveBeenCalledTimes(0);
  });

  test('onopen replacement before microtask flush', async () => {
    const host = makeHost();
    const ws = new FakeWebSocket('ws://x/', undefined, host);
    const old = vi.fn();
    const fresh = vi.fn();
    ws.onopen = old;
    ws.onopen = fresh;
    await flushMicrotasks();
    expect(old).toHaveBeenCalledTimes(0);
    expect(fresh).toHaveBeenCalledTimes(1);
  });
});

describe('FakeWebSocket — close()', () => {
  test('close() transitions to CLOSED, fires "close", calls host.onClose', async () => {
    const host = makeHost();
    const ws = new FakeWebSocket('ws://x/', undefined, host);
    await flushMicrotasks();
    const evt = vi.fn();
    ws.addEventListener('close', evt);
    ws.close();
    expect(ws.readyState).toBe(FakeWebSocket.CLOSED);
    expect(evt).toHaveBeenCalledTimes(1);
    expect(host.closeCalls).toBe(1);
  });

  test('close() onclose setter fires', async () => {
    const host = makeHost();
    const ws = new FakeWebSocket('ws://x/', undefined, host);
    await flushMicrotasks();
    const fn = vi.fn();
    ws.onclose = fn;
    ws.close();
    expect(fn).toHaveBeenCalledTimes(1);
  });

  test('close() is idempotent', async () => {
    const host = makeHost();
    const ws = new FakeWebSocket('ws://x/', undefined, host);
    await flushMicrotasks();
    ws.close();
    ws.close();
    ws.close();
    expect(host.closeCalls).toBe(1);
  });
});

describe('installFakeWebSocket — Module.websocket primary path', () => {
  test('sets Module.websocket.WebSocketConstructor returning FakeWebSocket', () => {
    const Module: any = {};
    const host = makeHost();
    const uninstall = installFakeWebSocket(Module, host, { forceGlobalPatch: false });
    expect(typeof Module.websocket).toBe('object');
    expect(typeof Module.websocket.WebSocketConstructor).toBe('function');
    const inst = Module.websocket.WebSocketConstructor('ws://wisp-gateway.local/');
    expect(inst).toBeInstanceOf(FakeWebSocket);
    uninstall();
  });

  test('sets Module.websocket.url to ws://<sentinel>/ by default', () => {
    const Module: any = {};
    const host = makeHost();
    const uninstall = installFakeWebSocket(Module, host, { forceGlobalPatch: false });
    expect(Module.websocket.url).toBe('ws://wisp-gateway.local/');
    uninstall();
  });

  test('respects custom sentinelHost', () => {
    const Module: any = {};
    const host = makeHost();
    const uninstall = installFakeWebSocket(Module, host, {
      forceGlobalPatch: false,
      sentinelHost: 'foo.bar',
    });
    expect(Module.websocket.url).toBe('ws://foo.bar/');
    uninstall();
  });

  test('uninstall clears Module.websocket.WebSocketConstructor', () => {
    const Module: any = {};
    const host = makeHost();
    const uninstall = installFakeWebSocket(Module, host, { forceGlobalPatch: false });
    expect(Module.websocket.WebSocketConstructor).toBeTypeOf('function');
    uninstall();
    expect(Module.websocket.WebSocketConstructor).toBeUndefined();
  });

  test('preserves an existing Module.websocket object (does not clobber)', () => {
    const Module: any = { websocket: { existing: 'value' } };
    const host = makeHost();
    const uninstall = installFakeWebSocket(Module, host, { forceGlobalPatch: false });
    expect(Module.websocket.existing).toBe('value');
    expect(typeof Module.websocket.WebSocketConstructor).toBe('function');
    uninstall();
  });
});

describe('installFakeWebSocket — globalThis monkey-patch fallback', () => {
  let RealWS: any;
  beforeEach(() => {
    RealWS = function FakeRealWS(url: string, _protocols?: any) {
      // Record minimal info — we only care that this constructor is invoked
      // for non-sentinel URLs in tests.
      (this as any).url = url;
      (this as any)._real = true;
    } as any;
    RealWS.CONNECTING = 0;
    RealWS.OPEN = 1;
    RealWS.CLOSING = 2;
    RealWS.CLOSED = 3;
    (globalThis as any).WebSocket = RealWS;
  });

  afterEach(() => {
    delete (globalThis as any).WebSocket;
    delete (globalThis as any).WorkerGlobalScope;
  });

  test('forceGlobalPatch=true patches globalThis.WebSocket', () => {
    const Module: any = {};
    const host = makeHost();
    const uninstall = installFakeWebSocket(Module, host, { forceGlobalPatch: true });
    expect((globalThis as any).WebSocket).not.toBe(RealWS);
    const sentinel = new (globalThis as any).WebSocket('ws://wisp-gateway.local/');
    expect(sentinel).toBeInstanceOf(FakeWebSocket);
    const real = new (globalThis as any).WebSocket('ws://other.host/');
    expect(real._real).toBe(true);
    uninstall();
    expect((globalThis as any).WebSocket).toBe(RealWS);
  });

  test('patched WebSocket exposes static state numbers', () => {
    const Module: any = {};
    const host = makeHost();
    const uninstall = installFakeWebSocket(Module, host, { forceGlobalPatch: true });
    expect((globalThis as any).WebSocket.CONNECTING).toBe(0);
    expect((globalThis as any).WebSocket.OPEN).toBe(1);
    expect((globalThis as any).WebSocket.CLOSING).toBe(2);
    expect((globalThis as any).WebSocket.CLOSED).toBe(3);
    uninstall();
  });

  test('uninstall restores globalThis.WebSocket to RealWS', () => {
    const Module: any = {};
    const host = makeHost();
    const uninstall = installFakeWebSocket(Module, host, { forceGlobalPatch: true });
    uninstall();
    expect((globalThis as any).WebSocket).toBe(RealWS);
  });

  test('worker context (WorkerGlobalScope present) without forceGlobalPatch does NOT patch', () => {
    // Simulate worker by defining WorkerGlobalScope.
    (globalThis as any).WorkerGlobalScope = function () {};
    const Module: any = {};
    const host = makeHost();
    const uninstall = installFakeWebSocket(Module, host, {});
    expect((globalThis as any).WebSocket).toBe(RealWS);
    uninstall();
  });

  test('main thread (no WorkerGlobalScope) without forceGlobalPatch DOES patch', () => {
    delete (globalThis as any).WorkerGlobalScope;
    const Module: any = {};
    const host = makeHost();
    const uninstall = installFakeWebSocket(Module, host, {});
    expect((globalThis as any).WebSocket).not.toBe(RealWS);
    uninstall();
    expect((globalThis as any).WebSocket).toBe(RealWS);
  });

  test('worker context with forceGlobalPatch=true DOES patch (override)', () => {
    (globalThis as any).WorkerGlobalScope = function () {};
    const Module: any = {};
    const host = makeHost();
    const uninstall = installFakeWebSocket(Module, host, { forceGlobalPatch: true });
    expect((globalThis as any).WebSocket).not.toBe(RealWS);
    uninstall();
  });
});
