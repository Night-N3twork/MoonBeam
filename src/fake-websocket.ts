/**
 * FakeWebSocket — a `WebSocket`-shaped intercept for QEMU-wasm.
 *
 * QEMU-wasm uses `-netdev socket,connect=...` which Emscripten translates
 * into `new WebSocket(url)`. Rather than letting the bytes leave the page,
 * we hand QEMU a `FakeWebSocket` whose `send()` and message dispatch are
 * routed into our in-page lwIP stack via a `FakeWebSocketHost`.
 *
 * Design notes:
 * - Inherits `EventTarget` so `addEventListener('message', ...)` works.
 * - Implements `on*` setters by tracking a single handler per event and
 *   adding/removing via `addEventListener`/`removeEventListener` so that
 *   replacing or clearing them behaves like the real `WebSocket`.
 * - `binaryType` defaults to `'arraybuffer'` to match Emscripten.
 * - State transitions: `CONNECTING -> OPEN` on the next microtask (so
 *   handlers attached synchronously after `new` see the open), and
 *   `-> CLOSED` on `close()` (idempotent).
 *
 * See `2026-05-27-vm-wisp-networking-design.md` §3.
 */

export interface FakeWebSocketHost {
  /** Called once when the constructor "opens" (i.e., QEMU connects). */
  onConnect(send: (frame: Uint8Array) => void): void;
  /** Called for every frame QEMU sends out (4-byte length prefix included). */
  onSend(data: Uint8Array): void;
  /** Called when QEMU closes. */
  onClose(): void;
}

type EventName = 'open' | 'message' | 'error' | 'close';

/**
 * Construct a CloseEvent-like object. In Node `CloseEvent` may not be a
 * global, so fall back to a plain `Event` augmented with the close fields.
 */
function makeCloseEvent(code: number, reason: string): Event {
  if (typeof (globalThis as any).CloseEvent === 'function') {
    try {
      return new (globalThis as any).CloseEvent('close', {
        code,
        reason,
        wasClean: true,
      });
    } catch {
      // Fall through.
    }
  }
  const ev: any = new Event('close');
  ev.code = code;
  ev.reason = reason;
  ev.wasClean = true;
  return ev;
}

function makeMessageEvent(data: ArrayBuffer): Event {
  if (typeof MessageEvent === 'function') {
    return new MessageEvent('message', { data });
  }
  const ev: any = new Event('message');
  ev.data = data;
  return ev;
}

function isBlobLike(x: unknown): boolean {
  if (typeof Blob !== 'undefined' && x instanceof Blob) return true;
  // Duck-typing fallback for environments where Blob is not a global.
  return (
    typeof x === 'object' &&
    x !== null &&
    typeof (x as { size?: unknown }).size === 'number' &&
    typeof (x as { type?: unknown }).type === 'string'
  );
}

export class FakeWebSocket extends EventTarget {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;

  // Instance copies (the real WebSocket exposes these on instances too).
  readonly CONNECTING = 0;
  readonly OPEN = 1;
  readonly CLOSING = 2;
  readonly CLOSED = 3;

  readyState: number = FakeWebSocket.CONNECTING;
  binaryType: 'blob' | 'arraybuffer' = 'arraybuffer';
  bufferedAmount = 0;
  protocol = '';
  extensions = '';
  url: string;

  private _host: FakeWebSocketHost;
  private _onHandlers: Record<EventName, ((e: any) => void) | null> = {
    open: null,
    message: null,
    error: null,
    close: null,
  };
  private _closed = false;

  constructor(url: string, _protocols?: string | string[], host?: FakeWebSocketHost) {
    super();
    if (!host) {
      throw new Error('FakeWebSocket requires a FakeWebSocketHost');
    }
    this.url = url;
    this._host = host;

    queueMicrotask(() => {
      // Race with synchronous close().
      if (this._closed) return;
      this.readyState = FakeWebSocket.OPEN;
      this.dispatchEvent(new Event('open'));
      this._host.onConnect((frame: Uint8Array) => this._dispatchMessage(frame));
    });
  }

  /** Push an inbound frame into the WebSocket as a 'message' event. */
  private _dispatchMessage(frame: Uint8Array): void {
    if (this._closed) return;
    // Always dispatch as ArrayBuffer (binaryType = 'arraybuffer').
    // Make a tight ArrayBuffer copy so consumers see a stable buffer that
    // doesn't share memory with our internal Uint8Array views.
    const ab = frame.buffer.slice(
      frame.byteOffset,
      frame.byteOffset + frame.byteLength,
    ) as ArrayBuffer;
    this.dispatchEvent(makeMessageEvent(ab));
  }

  send(data: ArrayBuffer | ArrayBufferView | Blob | string): void {
    if (this.readyState === FakeWebSocket.CLOSED) {
      // Mirror real WebSocket behavior: silently drop after close.
      return;
    }

    let bytes: Uint8Array;
    if (typeof data === 'string') {
      bytes = new TextEncoder().encode(data);
    } else if (data instanceof Uint8Array) {
      bytes = data;
    } else if (ArrayBuffer.isView(data)) {
      const view = data as ArrayBufferView;
      bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
    } else if (data instanceof ArrayBuffer) {
      bytes = new Uint8Array(data);
    } else if (isBlobLike(data)) {
      throw new TypeError('FakeWebSocket.send(Blob) is not supported');
    } else {
      throw new TypeError('FakeWebSocket.send: unsupported data type');
    }

    this._host.onSend(bytes);
  }

  close(code = 1000, reason = ''): void {
    if (this._closed) return;
    this._closed = true;
    this.readyState = FakeWebSocket.CLOSED;
    this.dispatchEvent(makeCloseEvent(code, reason));
    try {
      this._host.onClose();
    } catch {
      // Host's close handler should not break the close path.
    }
  }

  // ---------------- on* setter accessors ----------------
  // Each setter swaps the registered listener (removeEventListener if a
  // previous one was set) so semantics match the real WebSocket.

  private _setOnHandler(name: EventName, value: ((e: any) => void) | null): void {
    const prev = this._onHandlers[name];
    if (prev) {
      this.removeEventListener(name, prev as EventListener);
    }
    this._onHandlers[name] = value;
    if (value) {
      this.addEventListener(name, value as EventListener);
    }
  }

  get onopen(): ((e: Event) => void) | null {
    return this._onHandlers.open;
  }
  set onopen(v: ((e: Event) => void) | null) {
    this._setOnHandler('open', v);
  }

  get onmessage(): ((e: MessageEvent) => void) | null {
    return this._onHandlers.message as ((e: MessageEvent) => void) | null;
  }
  set onmessage(v: ((e: MessageEvent) => void) | null) {
    this._setOnHandler('message', v);
  }

  get onerror(): ((e: Event) => void) | null {
    return this._onHandlers.error;
  }
  set onerror(v: ((e: Event) => void) | null) {
    this._setOnHandler('error', v);
  }

  get onclose(): ((e: Event) => void) | null {
    return this._onHandlers.close;
  }
  set onclose(v: ((e: Event) => void) | null) {
    this._setOnHandler('close', v);
  }
}

// ---------------------------------------------------------------------------
// installFakeWebSocket
// ---------------------------------------------------------------------------

export interface InstallOptions {
  /** URL recognized as the FakeWebSocket. Default: `wisp-gateway.local`. */
  sentinelHost?: string;
  /**
   * Force the global WebSocket monkey-patch. Default: only patch on the
   * main thread; never in workers (detected via `typeof WorkerGlobalScope`).
   */
  forceGlobalPatch?: boolean;
}

function isWorkerContext(): boolean {
  return typeof (globalThis as any).WorkerGlobalScope !== 'undefined';
}

/**
 * Install the FakeWebSocket onto Emscripten's `Module` config and (when
 * appropriate) onto `globalThis.WebSocket` as a fallback recognizer.
 *
 * Returns an uninstall function that restores both surfaces.
 */
export function installFakeWebSocket(
  Module: any,
  host: FakeWebSocketHost,
  options: InstallOptions = {},
): () => void {
  const sentinelHost = options.sentinelHost ?? 'wisp-gateway.local';
  const shouldPatchGlobal =
    options.forceGlobalPatch === true ||
    (options.forceGlobalPatch !== false && !isWorkerContext());

  // ---- Primary path: Module.websocket ----
  if (!Module.websocket) {
    Module.websocket = {};
  }
  // Don't clobber a user-supplied URL — but provide a sensible default.
  const previousModuleUrl = Module.websocket.url;
  if (previousModuleUrl === undefined) {
    Module.websocket.url = `ws://${sentinelHost}/`;
  }
  const previousModuleCtor = Module.websocket.WebSocketConstructor;
  Module.websocket.WebSocketConstructor = (url: string, protocols?: string | string[]) =>
    new FakeWebSocket(url, protocols, host);

  // ---- Fallback path: globalThis.WebSocket ----
  let previousGlobalWS: any = undefined;
  let patchedGlobal = false;
  if (shouldPatchGlobal) {
    previousGlobalWS = (globalThis as any).WebSocket;
    const RealWS = previousGlobalWS;

    function PatchedWS(this: any, url: string, protocols?: string | string[]) {
      if (typeof url === 'string' && url.includes(sentinelHost)) {
        return new FakeWebSocket(url, protocols, host);
      }
      if (typeof RealWS === 'function') {
        // Forward to the real constructor. Use Reflect.construct so `new`
        // is honored even if RealWS is a non-arrow function expression.
        return Reflect.construct(RealWS, [url, protocols], PatchedWS as any);
      }
      throw new Error('FakeWebSocket fallback: no real WebSocket available');
    }

    if (typeof RealWS === 'function') {
      try {
        Object.setPrototypeOf(PatchedWS, RealWS);
      } catch {
        // Ignore — non-extensible prototype, fine to skip.
      }
    }
    // Use defineProperty to install OWN properties on PatchedWS. Plain
    // assignment (Object.assign) can fail with TypeError if the prototype
    // (the real WebSocket constructor) exposes these as non-writable,
    // because property writes consult the prototype chain.
    for (const [key, value] of [
      ['CONNECTING', 0],
      ['OPEN', 1],
      ['CLOSING', 2],
      ['CLOSED', 3],
    ] as const) {
      try {
        Object.defineProperty(PatchedWS, key, {
          value,
          writable: true,
          configurable: true,
          enumerable: false,
        });
      } catch {
        // Best-effort: if defineProperty also fails (extremely sealed host),
        // the inherited values from the real ctor will satisfy consumers.
      }
    }

    (globalThis as any).WebSocket = PatchedWS;
    patchedGlobal = true;
  }

  return function uninstall(): void {
    // Restore Module.websocket.
    if (Module.websocket) {
      if (previousModuleCtor === undefined) {
        delete Module.websocket.WebSocketConstructor;
      } else {
        Module.websocket.WebSocketConstructor = previousModuleCtor;
      }
      if (previousModuleUrl === undefined) {
        // Only delete the URL if we are the ones who set it.
        if (Module.websocket.url === `ws://${sentinelHost}/`) {
          delete Module.websocket.url;
        }
      }
    }
    // Restore globalThis.WebSocket.
    if (patchedGlobal) {
      if (previousGlobalWS === undefined) {
        delete (globalThis as any).WebSocket;
      } else {
        (globalThis as any).WebSocket = previousGlobalWS;
      }
    }
  };
}
