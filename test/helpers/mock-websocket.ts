/**
 * MockWebSocket — a paired fake WebSocket for unit testing WispClient without
 * spinning up a real WS server.
 *
 * Why: WispClient takes `new WebSocket(url, protocols)` internally; we inject
 * a MockWebSocket via the `_injectWebSocket` test hook on the config.
 *
 * Surface compat:
 *   - `addEventListener('open'|'message'|'close'|'error', listener)`
 *   - `send(data: Uint8Array|ArrayBuffer)`
 *   - `close(code?, reason?)`
 *   - `readyState`, `binaryType`, `protocol`
 *   - dispatchEvent / EventTarget-shaped
 *
 * Test surface (NOT on real WebSocket):
 *   - `sent: Uint8Array[]` — every payload passed to `send()`, captured.
 *   - `simulateOpen()` — dispatch 'open'.
 *   - `simulateMessage(bytes)` — dispatch 'message' with the given bytes as
 *      ArrayBuffer (matches `binaryType='arraybuffer'`).
 *   - `simulateClose(code?, reason?)` — dispatch 'close' and flip state.
 *   - `simulateError()` — dispatch 'error'.
 *   - `onSend?: (data: Uint8Array) => void` — optional callback fired
 *      synchronously whenever the client `send()`s something. Used by
 *      MockWispServer to react to client traffic.
 */

const CONNECTING = 0;
const OPEN = 1;
const CLOSING = 2;
const CLOSED = 3;

type Listener = (ev: any) => void;

export class MockWebSocket {
  // Match the browser WebSocket numeric readyState contract.
  static readonly CONNECTING = CONNECTING;
  static readonly OPEN = OPEN;
  static readonly CLOSING = CLOSING;
  static readonly CLOSED = CLOSED;

  readyState: number = CONNECTING;
  binaryType: 'arraybuffer' | 'blob' = 'arraybuffer';
  protocol = '';

  /** Every payload that the client wrote, captured as a copied Uint8Array. */
  readonly sent: Uint8Array[] = [];
  /** Optional sync hook fired on each `send()`. */
  onSend?: (data: Uint8Array) => void;

  private listeners = new Map<string, Set<Listener>>();

  addEventListener(type: string, listener: Listener): void {
    let set = this.listeners.get(type);
    if (!set) {
      set = new Set();
      this.listeners.set(type, set);
    }
    set.add(listener);
  }

  removeEventListener(type: string, listener: Listener): void {
    this.listeners.get(type)?.delete(listener);
  }

  dispatchEvent(type: string, payload: any = {}): void {
    const set = this.listeners.get(type);
    if (!set) return;
    // Copy to avoid mutation-during-iteration.
    for (const l of [...set]) {
      try {
        l({ type, ...payload });
      } catch (err) {
        // Mirror real WebSocket: listener exceptions don't propagate.
        // Log for debugging.
        // eslint-disable-next-line no-console
        console.error('MockWebSocket listener threw:', err);
      }
    }
  }

  send(data: ArrayBuffer | Uint8Array): void {
    if (this.readyState !== OPEN) {
      throw new Error(`MockWebSocket.send called in state ${this.readyState}`);
    }
    const bytes =
      data instanceof Uint8Array
        ? new Uint8Array(data) // copy so subsequent caller mutation doesn't affect the capture
        : new Uint8Array(data);
    this.sent.push(bytes);
    this.onSend?.(bytes);
  }

  close(code = 1000, reason = ''): void {
    if (this.readyState === CLOSED || this.readyState === CLOSING) return;
    this.readyState = CLOSING;
    // Most browsers fire close asynchronously; we fire synchronously for
    // deterministic tests. WispClient handlers must not assume async.
    this.readyState = CLOSED;
    this.dispatchEvent('close', { code, reason, wasClean: true });
  }

  // ---- test-side controls -------------------------------------------------

  simulateOpen(protocol = ''): void {
    if (this.readyState !== CONNECTING) {
      throw new Error('simulateOpen called when not in CONNECTING state');
    }
    this.protocol = protocol;
    this.readyState = OPEN;
    this.dispatchEvent('open');
  }

  simulateMessage(bytes: Uint8Array): void {
    if (this.readyState !== OPEN) {
      throw new Error('simulateMessage called when not OPEN');
    }
    // Real WebSocket with binaryType='arraybuffer' yields an ArrayBuffer in
    // `event.data`. Copy into a fresh ArrayBuffer so tests reading `data` see
    // a standalone buffer.
    const ab = new ArrayBuffer(bytes.length);
    new Uint8Array(ab).set(bytes);
    this.dispatchEvent('message', { data: ab });
  }

  simulateClose(code = 1006, reason = '', wasClean = false): void {
    if (this.readyState === CLOSED) return;
    this.readyState = CLOSED;
    this.dispatchEvent('close', { code, reason, wasClean });
  }

  simulateError(): void {
    this.dispatchEvent('error', {});
  }
}
