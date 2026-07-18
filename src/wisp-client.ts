/**
 * WispClient — a from-scratch Wisp v2.1 client.
 *
 * Spec: /home/amplify/Projects/webVM-wisp/q-demo/docs/wisp-protocol/protocol.md
 * Design: /home/amplify/Projects/webVM-wisp/Eclipse/docs/specs/2026-05-27-vm-wisp-networking-design.md §4
 *
 * Responsibilities:
 *   - Open a WebSocket with the `wisp-v2` subprotocol.
 *   - Run the v2 handshake (server INFO → client INFO → server CONTINUE).
 *   - Multiplex stream creation/teardown over a single WebSocket.
 *   - Track per-stream credit (TCP only) for backpressure.
 *   - Surface both Streams API (readable/writable) and event API ('open',
 *     'data', 'close', 'error') for each stream.
 *
 * Out of scope (v1):
 *   - Reconnection (host code constructs a fresh client on close).
 *   - Authentication (any required-auth advertisement → fast-fail).
 *   - v1 Wisp servers (rejected at handshake).
 */

import {
  encodePacket,
  decodePacket,
  encodeConnect,
  encodeContinue,
  encodeClose,
  decodeContinue,
  decodeClose,
  encodeInfo,
  decodeInfo,
  type DecodedPacket,
  type ExtensionEntry,
} from './wisp-frame';
import {
  PACKET_TYPE,
  EXTENSION_ID,
  CLOSE_REASON,
  ECLIPSE_PROTOCOL_NAME,
  RESERVED_STREAM_ID,
  type StreamType,
} from './wisp-types';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type { StreamType };

/**
 * @internal
 * Test-only escape hatch: bypass `new WebSocket(url, protocols)` and use the
 * provided socket directly. The injected object must implement the standard
 * WebSocket EventTarget surface (addEventListener for 'open' | 'message' |
 * 'close' | 'error', `send`, `close`, and `binaryType`/`readyState` getters).
 */
export interface _TestHooks {
  /** @internal — see _TestHooks. */
  _injectWebSocket?: any;
}

export interface WispClientConfig extends _TestHooks {
  url: string;
  /** v1 of WispClient does not implement auth; advertised auth-required → reject. */
  auth?: { username: string; password: string };
  /**
   * Fallback per-stream credit if the server sends no handshake CONTINUE
   * payload (which would be malformed). Default 256. Real servers always
   * provide one; this just guards against misbehaving servers.
   */
  initialBufferSize?: number;
  /** Max ms to wait for handshake completion. Default 10_000. */
  handshakeTimeoutMs?: number;
  /**
   * Accept Wisp v1 servers. **Default `true`** — v1 is the de-facto standard
   * (every public Wisp server we've found speaks v1). Set `false` to enforce
   * v2-only and reject v1 servers with E_WISP_V1_UNSUPPORTED.
   *
   * v1 vs v2 in practice: same wire format for CONNECT/DATA/CONTINUE/CLOSE
   * post-handshake. Differences when allowV1 is on:
   *   - No INFO exchange; UDP support is assumed if `udpAssumedInV1` is true.
   *   - No MOTD, no Stream Open Confirmation.
   *   - No auth extension negotiation.
   *   - Subprotocol header is omitted (some v1 servers reject clients that
   *     advertise the v2 'wisp-v2' subprotocol).
   * Most production v1 servers (e.g., wisp-server-node, ampscat) support UDP.
   */
  allowV1?: boolean;
  /**
   * When `allowV1` is true and a v1 server is detected, assume UDP is
   * supported (i.e., `udpSupported` returns true). Default `true` because
   * every observed v1 server in the wild ships with UDP. Set `false` if you
   * know your v1 server is TCP-only.
   */
  udpAssumedInV1?: boolean;
}

export interface WispStream {
  readonly id: number;
  readonly type: StreamType;
  readonly host: string;
  readonly port: number;
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;
  send(data: Uint8Array): void;
  close(reason?: number): void;
  /** Resolves when the stream is closed (locally or by the server). */
  closed: Promise<{ reason: number }>;
  on(event: 'open' | 'data' | 'close' | 'error' | 'credit', listener: (...args: any[]) => void): void;
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

interface WispLikeSocket {
  binaryType: string;
  readyState: number;
  send(data: ArrayBuffer | Uint8Array): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: string, listener: (ev: any) => void): void;
}

// Tiny in-process emitter to keep dependencies minimal and avoid Node's
// 'events' (which we'd need to depend on in worker contexts too).
class TinyEmitter {
  private listeners = new Map<string, Set<(...args: any[]) => void>>();

  on(event: string, listener: (...args: any[]) => void): void {
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
    for (const l of [...set]) {
      try {
        l(...args);
      } catch (err) {
        // Listener exceptions don't break the event loop. Surface to console
        // so they're not silently swallowed.
        // eslint-disable-next-line no-console
        console.error('WispClient listener threw:', err);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Stream implementation
// ---------------------------------------------------------------------------

class WispStreamImpl extends TinyEmitter implements WispStream {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  closed: Promise<{ reason: number }>;

  /**
   * For TCP streams: number of DATA packets we may still send before we must
   * wait for a CONTINUE. UDP streams ignore this entirely.
   */
  creditsRemaining = 0;
  /** Outbound queue used when credits are exhausted. TCP-only. */
  sendQueue: Uint8Array[] = [];
  /**
   * True until either the first CONTINUE arrives (when stream-open
   * confirmation is enabled) or until we fire 'open' optimistically. While
   * pending we can still queue sends; we just haven't notified consumers
   * that the stream is live.
   */
  pendingOpen = true;

  /** True after the local side or server closed this stream. */
  isClosed = false;

  private readableController!: ReadableStreamDefaultController<Uint8Array>;
  private resolveClosed!: (info: { reason: number }) => void;

  constructor(
    readonly id: number,
    readonly type: StreamType,
    readonly host: string,
    readonly port: number,
    private parent: WispClient,
  ) {
    super();
    this.readable = new ReadableStream<Uint8Array>({
      start: (controller) => {
        this.readableController = controller;
      },
      // No backpressure callback — the WebSocket transport drives delivery
      // and we don't have a way to throttle the server side.
    });

    // The writable's desiredSize reflects credits so producers can backpressure.
    const stream = this;
    this.writable = new WritableStream<Uint8Array>(
      {
        write(chunk: Uint8Array): void {
          stream.send(chunk);
        },
        close(): void {
          stream.close();
        },
        abort(): void {
          stream.close(CLOSE_REASON.UNKNOWN);
        },
      },
      // Custom queuing strategy: highWaterMark = current credits so a sender
      // backpressures naturally when credits hit 0. UDP streams report
      // Infinity (no backpressure).
      {
        size: () => 1,
        highWaterMark: 1, // best-effort; updated implicitly by send() blocking
      },
    );

    this.closed = new Promise((resolve) => {
      this.resolveClosed = resolve;
    });
  }

  /** Internal: enqueue a chunk into the readable side and emit 'data'. */
  _deliverIncoming(chunk: Uint8Array): void {
    if (this.isClosed) return;
    try {
      this.readableController.enqueue(chunk);
    } catch {
      // Reader detached; drop. The event API still gets the data below.
    }
    this.emit('data', chunk);
  }

  /** Internal: fire 'open' event and mark not-pending. */
  _markOpen(): void {
    if (!this.pendingOpen) return;
    this.pendingOpen = false;
    this.emit('open');
  }

  /** Internal: receive a server CONTINUE for this stream (TCP only). */
  _receiveContinue(bufferRemaining: number): void {
    if (this.type !== 'tcp') return; // malformed, parent already filtered
    this.creditsRemaining = bufferRemaining;

    // First CONTINUE on a confirmStreamOpen-enabled stream fires 'open'.
    if (this.pendingOpen) this._markOpen();

    // Drain the queue under the new credit budget.
    while (this.sendQueue.length > 0 && this.creditsRemaining > 0) {
      const chunk = this.sendQueue.shift()!;
      this.parent._sendDataPacket(this.id, chunk);
      this.creditsRemaining--;
    }
    this._emitCredit();
  }

  /** Internal: advertise current absolute TCP send capacity. */
  _emitCredit(): void {
    if (this.type !== 'tcp' || this.isClosed) return;
    this.emit('credit', this.creditsRemaining);
  }

  /** Internal: server (or fatal-close path) closed this stream. */
  _serverClose(reason: number): void {
    if (this.isClosed) return;
    this.isClosed = true;
    try {
      this.readableController.close();
    } catch {
      // Already closed/errored; ignore.
    }
    this.emit('close', { reason });
    this.resolveClosed({ reason });
  }

  send(data: Uint8Array): void {
    if (this.isClosed) {
      throw new Error('WispStream: send on closed stream');
    }
    if (this.type === 'udp') {
      this.parent._sendDataPacket(this.id, data);
      return;
    }
    if (this.creditsRemaining > 0) {
      this.parent._sendDataPacket(this.id, data);
      this.creditsRemaining--;
    } else {
      this.sendQueue.push(data);
    }
  }

  close(reason: number = CLOSE_REASON.VOLUNTARY): void {
    if (this.isClosed) return;
    this.isClosed = true;
    this.parent._sendCloseForStream(this.id, reason);
    try {
      this.readableController.close();
    } catch {
      // Already closed; ignore.
    }
    this.emit('close', { reason });
    this.resolveClosed({ reason });
  }
}

// ---------------------------------------------------------------------------
// WispClient
// ---------------------------------------------------------------------------

export const E_WISP_HANDSHAKE = 'E_WISP_HANDSHAKE';
export const E_WISP_V1_UNSUPPORTED = 'E_WISP_V1_UNSUPPORTED';
export const E_WISP_AUTH_REQUIRED = 'E_WISP_AUTH_REQUIRED';
export const E_WISP_STREAM_ID_EXHAUSTED = 'E_WISP_STREAM_ID_EXHAUSTED';
export const E_WISP_UDP_UNSUPPORTED = 'E_WISP_UDP_UNSUPPORTED';

export class WispClient extends TinyEmitter {
  private ws: WispLikeSocket;
  private streams = new Map<number, WispStreamImpl>();
  private nextStreamId = 1;

  // Handshake state
  private handshakeDone = false;
  private handshakeTimer: ReturnType<typeof setTimeout> | null = null;
  private resolveReady!: () => void;
  private rejectReady!: (err: Error) => void;
  private readyPromise: Promise<void>;
  private readyResolved = false;

  // Negotiated state
  private _udpSupported = false;
  private _confirmStreamOpen = false;
  private _motd: string | null = null;
  private handshakeBufferSize = 0;
  private _isV1 = false;

  // Config-derived flags (set in constructor; pulled out here so the
  // handshake path doesn't have to read config repeatedly).
  // allowV1 defaults to true: v1 is the de-facto standard, and the spec'd
  // v2 isn't widely deployed. Callers wanting v2-strict opt out explicitly.
  private allowV1 = true;
  private udpAssumedInV1 = true;

  // Lifecycle
  private _connected = false;
  private wsClosed = false;

  constructor(private config: WispClientConfig) {
    super();

    this.allowV1 = config.allowV1 ?? true;
    this.udpAssumedInV1 = config.udpAssumedInV1 ?? true;

    this.readyPromise = new Promise<void>((resolve, reject) => {
      this.resolveReady = () => {
        if (this.readyResolved) return;
        this.readyResolved = true;
        resolve();
      };
      this.rejectReady = (err: Error) => {
        if (this.readyResolved) return;
        this.readyResolved = true;
        reject(err);
      };
    });
    // Suppress "unhandled rejection" warning: WebSocket failures can fire
    // synchronously from the constructor before the caller has a chance to
    // attach `.catch()` or `await`. Attach a no-op catch here; the real
    // caller's await will see the rejection because Promise rejections
    // propagate to every consumer.
    this.readyPromise.catch(() => {});

    if (config._injectWebSocket) {
      this.ws = config._injectWebSocket;
    } else {
      // Use the global WebSocket (available in browsers, web workers, and
      // Node 22+). We do NOT pull in `ws` because it's Node-only and we want
      // a single class shape across environments.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const WSCtor: any = (globalThis as any).WebSocket;
      if (typeof WSCtor !== 'function') {
        throw new Error('WispClient: no WebSocket constructor available in this environment');
      }
      // v2 servers expect Sec-WebSocket-Protocol; v1 servers in the wild
      // (e.g., wisp-server-node, ampscat) typically reject clients that
      // offer a subprotocol because they don't echo one back. When allowV1
      // is on, omit the protocols arg so the WebSocket negotiates without it.
      // We can still detect v2 by checking the first packet (INFO vs CONTINUE).
      this.ws = this.allowV1
        ? new WSCtor(config.url)
        : new WSCtor(config.url, [ECLIPSE_PROTOCOL_NAME]);
    }
    this.ws.binaryType = 'arraybuffer';

    this.ws.addEventListener('open', () => this.onOpen());
    this.ws.addEventListener('message', (ev: { data: ArrayBuffer | Uint8Array }) =>
      this.onMessage(ev.data),
    );
    this.ws.addEventListener('close', () => this.onWsClose());
    this.ws.addEventListener('error', () => this.onWsError());

    const timeoutMs = config.handshakeTimeoutMs ?? 10_000;
    this.handshakeTimer = setTimeout(() => {
      if (!this.handshakeDone) {
        this.failHandshake(E_WISP_HANDSHAKE, 'handshake timeout');
      }
    }, timeoutMs);
  }

  ready(): Promise<void> {
    return this.readyPromise;
  }

  get connected(): boolean {
    return this._connected;
  }

  get udpSupported(): boolean {
    return this._udpSupported;
  }

  get confirmStreamOpen(): boolean {
    return this._confirmStreamOpen;
  }

  get motd(): string | null {
    return this._motd;
  }

  /** True if the negotiated server is Wisp v1 (no INFO exchange). */
  get isV1(): boolean {
    return this._isV1;
  }

  createStream(host: string, port: number, type: StreamType): WispStream {
    if (!this.handshakeDone) {
      throw new Error('WispClient: createStream called before ready()');
    }
    if (type === 'udp' && !this._udpSupported) {
      throw new Error(E_WISP_UDP_UNSUPPORTED);
    }

    // Allocate id; retire 0; uint32 cap ~4e9.
    if (this.nextStreamId === 0) this.nextStreamId = 1;
    if (this.nextStreamId > 0xffffffff) {
      throw new Error(E_WISP_STREAM_ID_EXHAUSTED);
    }
    const id = this.nextStreamId;
    this.nextStreamId = (this.nextStreamId + 1) >>> 0;
    if (this.nextStreamId === RESERVED_STREAM_ID) this.nextStreamId = 1;

    const stream = new WispStreamImpl(id, type, host, port, this);
    // TCP streams start with the negotiated handshake credit. UDP doesn't
    // care.
    if (type === 'tcp') {
      stream.creditsRemaining = this.handshakeBufferSize;
      // Consumers attach listeners immediately after createStream returns.
      queueMicrotask(() => stream._emitCredit());
    }
    this.streams.set(id, stream);

    // Send the CONNECT packet.
    const connectPayload = encodeConnect(type, port, host);
    this.sendPacket(PACKET_TYPE.CONNECT, id, connectPayload);

    // Open semantics:
    //   - TCP + confirmStreamOpen → wait for CONTINUE on this id.
    //   - TCP + !confirmStreamOpen → fire 'open' optimistically (microtask
    //     so listeners attached after createStream() still fire).
    //   - UDP → fire 'open' immediately (UDP has no CONTINUE).
    if (type === 'udp' || !this._confirmStreamOpen) {
      queueMicrotask(() => stream._markOpen());
    }
    return stream;
  }

  close(): void {
    if (this.wsClosed) return;
    this.wsClosed = true;
    // Fail any unfinished handshake.
    if (!this.handshakeDone && !this.readyResolved) {
      this.rejectReady(new Error(`${E_WISP_HANDSHAKE}: client closed`));
    }
    // Close every live stream from our side with NETWORK_ERROR.
    for (const stream of [...this.streams.values()]) {
      stream._serverClose(CLOSE_REASON.NETWORK_ERROR);
    }
    this.streams.clear();
    try {
      this.ws.close();
    } catch {
      /* ignore */
    }
    this._connected = false;
    this.emit('close');
  }

  // ---- packet plumbing ---------------------------------------------------

  /** @internal Used by WispStreamImpl. */
  _sendDataPacket(streamId: number, data: Uint8Array): void {
    this.sendPacket(PACKET_TYPE.DATA, streamId, data);
  }

  /** @internal Used by WispStreamImpl on local close. */
  _sendCloseForStream(streamId: number, reason: number): void {
    this.sendPacket(PACKET_TYPE.CLOSE, streamId, encodeClose(reason));
    this.streams.delete(streamId);
  }

  private sendPacket(type: number, streamId: number, payload: Uint8Array): void {
    if (this.wsClosed) return;
    try {
      this.ws.send(encodePacket(type, streamId, payload));
    } catch (err) {
      // Send failed — likely the WS is dead. Surface and treat as fatal.
      // eslint-disable-next-line no-console
      console.warn('WispClient: WebSocket send failed:', err);
      this.onWsClose();
    }
  }

  // ---- WebSocket events --------------------------------------------------

  private onOpen(): void {
    // Nothing to do here; we wait for the server's INFO before sending
    // anything (per spec).
    this.emit('open');
  }

  private onMessage(data: ArrayBuffer | Uint8Array): void {
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    const pkt = decodePacket(bytes);
    if (!pkt) {
      // Smaller-than-header garbage; ignore.
      return;
    }

    if (!this.handshakeDone) {
      this.handleHandshakePacket(pkt);
      return;
    }

    this.handlePostHandshakePacket(pkt);
  }

  private onWsClose(): void {
    if (this.wsClosed) return;
    this.wsClosed = true;
    if (this.handshakeTimer) {
      clearTimeout(this.handshakeTimer);
      this.handshakeTimer = null;
    }
    if (!this.readyResolved) {
      this.rejectReady(new Error(`${E_WISP_HANDSHAKE}: WebSocket closed before handshake`));
    }
    // Tell every live stream the network died.
    for (const stream of [...this.streams.values()]) {
      stream._serverClose(CLOSE_REASON.NETWORK_ERROR);
    }
    this.streams.clear();
    this._connected = false;
    this.emit('close');
  }

  private onWsError(): void {
    this.emit('error', new Error('WebSocket error'));
  }

  // ---- handshake handling ------------------------------------------------

  private handleHandshakePacket(pkt: DecodedPacket): void {
    // Per spec, the very first packet from the server must be on stream 0
    // and either INFO (v2) or CONTINUE (v1).
    if (pkt.streamId !== 0) {
      // Server is misbehaving; fail fast.
      this.failHandshake(E_WISP_HANDSHAKE, `unexpected pre-handshake stream id ${pkt.streamId}`);
      return;
    }

    if (pkt.type === PACKET_TYPE.CONTINUE) {
      // Three cases:
      //   - We've already sent our INFO → this CONTINUE is the server's
      //     handshake-success signal (v2).
      //   - We haven't sent our INFO yet AND allowV1 → v1 server. Accept it
      //     by recording the buffer size and completing the handshake. No
      //     INFO exchange takes place; we assume UDP support per config.
      //   - We haven't sent our INFO yet AND !allowV1 → reject.
      if (this.sentClientInfo) {
        const buf = decodeContinue(pkt.payload);
        if (buf == null) {
          this.failHandshake(E_WISP_HANDSHAKE, 'malformed handshake CONTINUE');
          return;
        }
        this.handshakeBufferSize = buf;
        this.completeHandshake();
        return;
      }
      // v1 path
      if (this.allowV1) {
        const buf = decodeContinue(pkt.payload);
        if (buf == null) {
          this.failHandshake(E_WISP_HANDSHAKE, 'malformed v1 handshake CONTINUE');
          return;
        }
        this.handshakeBufferSize = buf;
        this._isV1 = true;
        if (this.udpAssumedInV1) this._udpSupported = true;
        // v1 has no Stream Open Confirmation; leave confirmStreamOpen=false.
        // v1 has no MOTD; leave motd=null.
        // Skip sending client INFO (server isn't expecting it).
        this.completeHandshake();
        return;
      }
      this.failHandshake(E_WISP_V1_UNSUPPORTED, 'server appears to be Wisp v1; set allowV1: true to use it');
      return;
    }

    if (pkt.type === PACKET_TYPE.INFO) {
      this.handleServerInfo(pkt);
      return;
    }

    if (pkt.type === PACKET_TYPE.CLOSE) {
      const reason = decodeClose(pkt.payload) ?? CLOSE_REASON.UNKNOWN;
      this.failHandshake(E_WISP_HANDSHAKE, `server CLOSE during handshake: 0x${reason.toString(16)}`);
      return;
    }

    // Anything else during handshake is malformed.
    this.failHandshake(E_WISP_HANDSHAKE, `unexpected packet type 0x${pkt.type.toString(16)} during handshake`);
  }

  private sentClientInfo = false;

  private handleServerInfo(pkt: DecodedPacket): void {
    if (this.sentClientInfo) {
      // INFO arriving after we already sent our INFO is malformed.
      // eslint-disable-next-line no-console
      console.warn('WispClient: duplicate INFO from server during handshake; ignoring');
      return;
    }
    const info = decodeInfo(pkt.payload);
    if (!info) {
      this.failHandshake(E_WISP_HANDSHAKE, 'malformed server INFO');
      return;
    }

    // Parse extensions.
    let passwordAuthRequired = false;
    let pubkeyAuthRequired = false;
    for (const ext of info.extensions) {
      switch (ext.id) {
        case EXTENSION_ID.UDP:
          this._udpSupported = true;
          break;
        case EXTENSION_ID.PASSWORD_AUTH:
          if (ext.metadata.length >= 1 && ext.metadata[0] === 1) passwordAuthRequired = true;
          break;
        case EXTENSION_ID.PUBKEY_AUTH:
          if (ext.metadata.length >= 1 && ext.metadata[0] === 1) pubkeyAuthRequired = true;
          break;
        case EXTENSION_ID.MOTD:
          try {
            this._motd = new TextDecoder('utf-8').decode(ext.metadata);
          } catch {
            this._motd = null;
          }
          break;
        case EXTENSION_ID.STREAM_OPEN_CONFIRMATION:
          this._confirmStreamOpen = true;
          break;
        // Unknown extension IDs ignored (forward-compat).
      }
    }

    // Auth-required check. v1 has no auth implementation — bail cleanly.
    const haveCreds = !!this.config.auth;
    if ((passwordAuthRequired || pubkeyAuthRequired) && !haveCreds) {
      // Send CLOSE 0xc2 on stream 0, then reject (failHandshake will close
      // the WebSocket). Order matters: we must reject with the
      // auth-required code BEFORE the WS-close path can race in with a
      // generic E_WISP_HANDSHAKE rejection.
      this.sendPacket(PACKET_TYPE.CLOSE, 0, encodeClose(CLOSE_REASON.AUTH_REQUIRED));
      this.failHandshake(E_WISP_AUTH_REQUIRED, 'server requires authentication');
      return;
    }

    // Send our INFO. We advertise the extensions we know how to handle:
    // UDP (so the server enables UDP for us) and Stream Open Confirmation
    // (so we get confirmed-open semantics for TCP).
    const clientExts: ExtensionEntry[] = [
      { id: EXTENSION_ID.UDP, metadata: new Uint8Array(0) },
      { id: EXTENSION_ID.STREAM_OPEN_CONFIRMATION, metadata: new Uint8Array(0) },
    ];
    this.sendPacket(PACKET_TYPE.INFO, 0, encodeInfo(2, 1, clientExts));
    this.sentClientInfo = true;

    // Now wait for the server's CONTINUE on stream 0. If both sides
    // negotiated Stream Open Confirmation, our flag was already set above.
    // The flag only matters if BOTH sides advertised it; we did, so it
    // tracks the server's advertisement directly.
  }

  private completeHandshake(): void {
    this.handshakeDone = true;
    this._connected = true;
    if (this.handshakeTimer) {
      clearTimeout(this.handshakeTimer);
      this.handshakeTimer = null;
    }
    // Apply the configured fallback if the server gave us an unreasonable 0.
    if (this.handshakeBufferSize === 0) {
      this.handshakeBufferSize = this.config.initialBufferSize ?? 256;
    }
    this.resolveReady();
  }

  private failHandshake(code: string, detail: string): void {
    if (this.handshakeTimer) {
      clearTimeout(this.handshakeTimer);
      this.handshakeTimer = null;
    }
    if (!this.readyResolved) {
      const err = new Error(`${code}: ${detail}`);
      (err as any).code = code;
      this.rejectReady(err);
    }
    if (!this.wsClosed) {
      this.wsClosed = true;
      try {
        this.ws.close();
      } catch {
        /* ignore */
      }
    }
  }

  // ---- post-handshake packet handling -----------------------------------

  private handlePostHandshakePacket(pkt: DecodedPacket): void {
    // Stream-0 packets are connection-level and special.
    if (pkt.streamId === 0) {
      switch (pkt.type) {
        case PACKET_TYPE.CLOSE: {
          const reason = decodeClose(pkt.payload) ?? CLOSE_REASON.UNKNOWN;
          this.handleFatalClose(reason);
          return;
        }
        case PACKET_TYPE.CONTINUE:
          // Spurious post-handshake CONTINUE on stream 0 — ignore (some
          // servers emit periodic ones; the spec says nothing about this).
          return;
        case PACKET_TYPE.INFO:
        case PACKET_TYPE.DATA:
        default:
          // eslint-disable-next-line no-console
          console.warn(
            `WispClient: malformed packet type 0x${pkt.type.toString(16)} on stream 0; ignoring`,
          );
          return;
      }
    }

    // Stream-N packets.
    const stream = this.streams.get(pkt.streamId);
    switch (pkt.type) {
      case PACKET_TYPE.DATA:
        if (!stream) {
          // Late packet for a closed stream. Drop silently — this happens
          // routinely when the server hasn't yet processed our CLOSE.
          return;
        }
        // Copy the payload so the caller's reference survives buffer reuse.
        stream._deliverIncoming(new Uint8Array(pkt.payload));
        return;
      case PACKET_TYPE.CONTINUE: {
        if (!stream) return;
        if (stream.type === 'udp') {
          // eslint-disable-next-line no-console
          console.warn(
            `WispClient: CONTINUE on UDP stream ${pkt.streamId}; ignoring (malformed per spec)`,
          );
          return;
        }
        const buf = decodeContinue(pkt.payload);
        if (buf == null) return;
        stream._receiveContinue(buf);
        return;
      }
      case PACKET_TYPE.CLOSE: {
        if (!stream) return;
        const reason = decodeClose(pkt.payload) ?? CLOSE_REASON.UNKNOWN;
        stream._serverClose(reason);
        this.streams.delete(pkt.streamId);
        return;
      }
      case PACKET_TYPE.INFO:
        // eslint-disable-next-line no-console
        console.warn(`WispClient: INFO on stream ${pkt.streamId}; ignoring`);
        return;
      default:
        // Unknown type: forward-compat ignore.
        return;
    }
  }

  private handleFatalClose(reason: number): void {
    if (this.wsClosed) return;
    this.wsClosed = true;
    if (this.handshakeTimer) {
      clearTimeout(this.handshakeTimer);
      this.handshakeTimer = null;
    }
    if (!this.readyResolved) {
      const err = new Error(`${E_WISP_HANDSHAKE}: server CLOSE 0x${reason.toString(16)}`);
      (err as any).code = E_WISP_HANDSHAKE;
      (err as any).reason = reason;
      this.rejectReady(err);
    }
    for (const stream of [...this.streams.values()]) {
      stream._serverClose(CLOSE_REASON.NETWORK_ERROR);
    }
    this.streams.clear();
    this._connected = false;
    try {
      this.ws.close();
    } catch {
      /* ignore */
    }
    this.emit('close');
  }
}
