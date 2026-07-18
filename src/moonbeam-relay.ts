/**
 * MoonbeamRelay — in-page wisp relay endpoint.
 *
 * Accepts wisp frames from local consumers (Nova, other WASM clients) over
 * MessagePort transports and forwards them through a shared upstream
 * WispClient to a real wisp server. Stream-level pass-through: each attached
 * client gets its own MessagePort; stream IDs are rewritten to relay-unique
 * IDs before forwarding, and rewritten back on the return path.
 */

import { WispClient, type WispClientConfig, type WispStream } from './wisp-client';
import { decodePacket, decodeConnect, decodeClose, encodePacket, encodeClose, encodeContinue } from './wisp-frame';
import { CLOSE_REASON, PACKET_TYPE, RESERVED_STREAM_ID, type StreamType } from './wisp-types';
import type { EgressPolicyConfig } from './policy';

export interface MoonbeamRelayOptions {
  /** Wisp v2.1 endpoint. */
  wispUrl: string;
  /** Optional egress policy applied to relayed CONNECT payloads. */
  egress?: EgressPolicyConfig;
  /** @internal Test hook — never set in production. */
  _injectWebSocket?: any;
}

export interface MoonbeamAttachmentMetadata {
  label?: string;
}

export interface MoonbeamClientStreamSnapshot {
  readonly id: number;
  readonly type: StreamType;
  readonly hostname: string;
  readonly port: number;
  readonly local: boolean;
}

export interface MoonbeamClientSnapshot {
  readonly id: number;
  readonly virtualIp: string;
  readonly label: string;
  readonly connectedAt: number;
  readonly streams: readonly MoonbeamClientStreamSnapshot[];
}

export interface MoonbeamListenerSnapshot {
  readonly host: string;
  readonly port: number;
  readonly activeStreams: number;
}

export interface MoonbeamLocalSocket {
  onData(listener: (data: Uint8Array) => void): () => void;
  onClose(listener: (reason: number) => void): () => void;
  send(data: Uint8Array): void;
  close(reason?: number): void;
}

export type MoonbeamLocalConnectionHandler = (socket: MoonbeamLocalSocket) => void;

interface ClientState {
  port: MessagePort;
  id: number;
  cleanedUp: boolean;
  virtualIpHost: number;
  virtualIp: string;
  label: string;
  connectedAt: number;
  /** client stream ID → upstream stream ID */
  streamIdMap: Map<number, number>;
  /** upstream stream ID → WispStream handle */
  upstreamStreams: Map<number, WispStream>;
  /** client TCP stream ID → most recently advertised absolute receive credit */
  upstreamReceiveCredits: Map<number, number>;
  localStreams: Map<number, LocalStreamState>;
  streamRecords: Map<number, MoonbeamClientStreamSnapshot>;
}

interface ListenerState {
  host: string;
  port: number;
  handler: MoonbeamLocalConnectionHandler;
  streams: Set<LocalStreamState>;
}

interface LocalStreamState {
  client: ClientState;
  listener: ListenerState;
  clientStreamId: number;
  closed: boolean;
  closeReason: number | null;
  receiveCreditsRemaining: number;
  receiveCreditResetTimer: ReturnType<typeof setTimeout> | null;
  dataListeners: Set<(data: Uint8Array) => void>;
  closeListeners: Set<(reason: number) => void>;
}

/** Completes the attached client's v1 fallback without granting stream DATA credit. */
const CLIENT_HANDSHAKE_CREDIT = 0;
/** Synchronous local handlers can accept one bounded window at a time. */
const LOCAL_STREAM_RECEIVE_WINDOW = 256;

export class MoonbeamRelay {
  private readonly upstream: WispClient;
  private readonly clients = new Map<MessagePort, ClientState>();
  private readonly listeners = new Map<string, ListenerState>();
  private readonly availableVirtualIpHosts = Array.from({ length: 254 }, (_, index) => index + 1);
  private nextClientId = 1;
  private closed = false;

  private constructor(upstream: WispClient) {
    this.upstream = upstream;
  }

  static async create(opts: MoonbeamRelayOptions): Promise<MoonbeamRelay> {
    const config: WispClientConfig = {
      url: opts.wispUrl,
      _injectWebSocket: opts._injectWebSocket,
    } as WispClientConfig;
    const upstream = new WispClient(config);
    await upstream.ready();
    return new MoonbeamRelay(upstream);
  }

  attach(metadata: MoonbeamAttachmentMetadata = {}): MessagePort {
    if (this.closed) throw new Error('MoonbeamRelay.attach: relay is closed');
    const virtualIpHost = this.availableVirtualIpHosts.shift();
    if (virtualIpHost === undefined) {
      throw new Error('MoonbeamRelay.attach: virtual IP address pool exhausted');
    }
    const channel = new MessageChannel();
    const id = this.nextClientId++;
    const state: ClientState = {
      port: channel.port1,
      id,
      cleanedUp: false,
      virtualIpHost,
      virtualIp: `100.64.0.${virtualIpHost}`,
      label: metadata.label ?? `client-${id}`,
      connectedAt: Date.now(),
      streamIdMap: new Map(),
      upstreamStreams: new Map(),
      upstreamReceiveCredits: new Map(),
      localStreams: new Map(),
      streamRecords: new Map(),
    };
    this.clients.set(channel.port2, state);
    channel.port1.addEventListener('message', (ev) => {
      this.onClientMessage(state, ev.data);
    });
    channel.port1.start();

    // Kick the client's wisp handshake. Any wisp v2 client (e.g. Nova) blocks
    // on the first recv() until it sees either server INFO or a CONTINUE on
    // stream 0. The relay speaks pass-through — it doesn't run its own v2
    // handshake per attached client — so we send a stream-0 CONTINUE
    // immediately. Nova's Mux::run_handshake recognizes this as the v1
    // fallback path and completes the handshake without an INFO exchange.
    // Credit is deliberately zero: stream 0 only completes the fallback.
    // Local TCP streams receive an explicit bounded window on CONNECT;
    // upstream TCP mirrors WispStream credit, and UDP is creditless.
    //
    // NOTE: post the underlying ArrayBuffer (not the Uint8Array view). Nova's
    // MessagePortTransport only matches ArrayBuffer on the receive side; a
    // Uint8Array would be silently dropped by structured-clone delivery.
    const handshakePacket = encodePacket(
      PACKET_TYPE.CONTINUE,
      RESERVED_STREAM_ID,
      encodeContinue(CLIENT_HANDSHAKE_CREDIT),
    );
    state.port.postMessage(handshakePacket.buffer as ArrayBuffer, [handshakePacket.buffer as ArrayBuffer]);

    return channel.port2;
  }

  detach(port: MessagePort): void {
    const state = this.clients.get(port);
    if (!state) return;
    this.clients.delete(port);
    this.cleanupClient(state);
  }

  // ------------------------------------------------------------------
  // Observability
  // ------------------------------------------------------------------

  /** Number of clients currently attached to this relay. */
  clientCount(): number {
    return this.clients.size;
  }

  /** Total number of open upstream and local streams across all attached clients. */
  streamCount(): number {
    let n = 0;
    for (const s of this.clients.values()) {
      n += s.upstreamStreams.size + s.localStreams.size;
    }
    return n;
  }

  clientsSnapshot(): readonly MoonbeamClientSnapshot[] {
    const clients = [...this.clients.values()].map((client) => {
      const streams = Object.freeze(
        [...client.streamRecords.values()].map((stream) => Object.freeze({ ...stream })),
      );
      return Object.freeze({
        id: client.id,
        virtualIp: client.virtualIp,
        label: client.label,
        connectedAt: client.connectedAt,
        streams,
      });
    });
    return Object.freeze(clients);
  }

  listenerCount(): number {
    return this.listeners.size;
  }

  listenersSnapshot(): readonly MoonbeamListenerSnapshot[] {
    return Object.freeze(
      [...this.listeners.values()].map((listener) =>
        Object.freeze({
          host: listener.host,
          port: listener.port,
          activeStreams: listener.streams.size,
        }),
      ),
    );
  }

  registerListener(
    host: string,
    port: number,
    handler: MoonbeamLocalConnectionHandler,
  ): () => void {
    if (this.closed) throw new Error('MoonbeamRelay.registerListener: relay is closed');
    const key = this.listenerKey(host, port);
    if (this.listeners.has(key)) {
      throw new Error(`MoonbeamRelay.registerListener: ${host}:${port} is already registered`);
    }
    const listener: ListenerState = { host, port, handler, streams: new Set() };
    this.listeners.set(key, listener);

    return () => {
      if (this.listeners.get(key) !== listener) return;
      this.listeners.delete(key);
      for (const stream of [...listener.streams]) {
        this.closeLocalStream(stream, CLOSE_REASON.VOLUNTARY, true);
      }
    };
  }

  /** Whether the relay is closed. */
  isClosed(): boolean {
    return this.closed;
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    const clients = [...this.clients.values()];
    this.clients.clear();
    try {
      for (const state of clients) this.cleanupClient(state);
    } finally {
      this.listeners.clear();
      this.upstream.close();
    }
  }

  private onClientMessage(state: ClientState, raw: any): void {
    const buf = raw instanceof Uint8Array ? raw : new Uint8Array(raw as ArrayBuffer);
    const pkt = decodePacket(buf);
    if (!pkt) return; // malformed — drop

    switch (pkt.type) {
      case PACKET_TYPE.CONNECT: {
        const payload = decodeConnect(pkt.payload);
        if (!payload) return;
        const existingLocalStream = state.localStreams.get(pkt.streamId);
        const existingUpstreamId = state.streamIdMap.get(pkt.streamId);
        if (existingLocalStream || existingUpstreamId !== undefined) {
          if (existingLocalStream) {
            this.closeLocalStream(existingLocalStream, CLOSE_REASON.STREAM_INVALID_INFO, true);
          } else {
            const existingUpstreamStream = state.upstreamStreams.get(existingUpstreamId!);
            state.streamIdMap.delete(pkt.streamId);
            state.upstreamStreams.delete(existingUpstreamId!);
            state.upstreamReceiveCredits.delete(pkt.streamId);
            state.streamRecords.delete(pkt.streamId);
            if (existingUpstreamStream) {
              existingUpstreamStream.close(CLOSE_REASON.STREAM_INVALID_INFO);
            } else {
              this.postClientPacket(
                state,
                PACKET_TYPE.CLOSE,
                pkt.streamId,
                encodeClose(CLOSE_REASON.STREAM_INVALID_INFO),
              );
            }
          }
          return;
        }
        const listener = payload.streamType === 'tcp'
          ? this.listeners.get(this.listenerKey(payload.hostname, payload.port))
          : undefined;
        if (listener) {
          this.openLocalStream(state, listener, pkt.streamId, payload.hostname, payload.port);
          break;
        }
        const upstreamStream = this.upstream.createStream(
          payload.hostname,
          payload.port,
          payload.streamType,
        );
        state.streamIdMap.set(pkt.streamId, upstreamStream.id);
        state.upstreamStreams.set(upstreamStream.id, upstreamStream);
        if (payload.streamType === 'tcp') state.upstreamReceiveCredits.set(pkt.streamId, 0);
        state.streamRecords.set(pkt.streamId, {
          id: pkt.streamId,
          type: payload.streamType,
          hostname: payload.hostname,
          port: payload.port,
          local: false,
        });

        const clientStreamId = pkt.streamId; // capture; avoid closure over the loop-scoped variable

        upstreamStream.on('data', (data: Uint8Array) => {
          const dataPacket = encodePacket(PACKET_TYPE.DATA, clientStreamId, data);
          state.port.postMessage(dataPacket.buffer as ArrayBuffer, [dataPacket.buffer as ArrayBuffer]);
        });

        upstreamStream.on('close', (info: { reason: number }) => {
          const closePacket = encodePacket(
            PACKET_TYPE.CLOSE,
            clientStreamId,
            encodeClose(info?.reason ?? 0),
          );
          state.port.postMessage(closePacket.buffer as ArrayBuffer, [closePacket.buffer as ArrayBuffer]);
          state.streamIdMap.delete(clientStreamId);
          state.upstreamStreams.delete(upstreamStream.id);
          state.upstreamReceiveCredits.delete(clientStreamId);
          state.streamRecords.delete(clientStreamId);
        });
        if (payload.streamType === 'tcp') {
          upstreamStream.on('credit', (creditsRemaining: number) => {
            if (state.streamIdMap.get(clientStreamId) !== upstreamStream.id) return;
            state.upstreamReceiveCredits.set(clientStreamId, creditsRemaining);
            this.postClientPacket(
              state,
              PACKET_TYPE.CONTINUE,
              clientStreamId,
              encodeContinue(creditsRemaining),
            );
          });
        }
        break;
      }
      case PACKET_TYPE.DATA: {
        const localStream = state.localStreams.get(pkt.streamId);
        if (localStream) {
          if (localStream.receiveCreditsRemaining <= 0) {
            this.closeLocalStream(localStream, CLOSE_REASON.STREAM_INVALID_INFO, true);
            return;
          }
          localStream.receiveCreditsRemaining--;
          const data = pkt.payload.slice();
          // Dispatch uses a fixed snapshot: callbacks present at dispatch start
          // all run, even if an earlier callback closes the local socket.
          for (const listener of [...localStream.dataListeners]) {
            try {
              listener(data);
            } catch {
              // A consumer callback cannot interrupt credit or stream cleanup.
            }
          }
          if (!localStream.closed && localStream.receiveCreditsRemaining === 0) {
            localStream.receiveCreditResetTimer = setTimeout(() => {
              localStream.receiveCreditResetTimer = null;
              if (localStream.closed || localStream.receiveCreditsRemaining !== 0) return;
              localStream.receiveCreditsRemaining = LOCAL_STREAM_RECEIVE_WINDOW;
              this.postClientPacket(
                state,
                PACKET_TYPE.CONTINUE,
                pkt.streamId,
                encodeContinue(LOCAL_STREAM_RECEIVE_WINDOW),
              );
            }, 0);
          }
          return;
        }
        const upstreamId = state.streamIdMap.get(pkt.streamId);
        if (upstreamId === undefined) return;
        const stream = state.upstreamStreams.get(upstreamId);
        if (!stream) return;
        if (stream.type === 'tcp') {
          const creditsRemaining = state.upstreamReceiveCredits.get(pkt.streamId) ?? 0;
          if (creditsRemaining <= 0) {
            stream.close(CLOSE_REASON.STREAM_INVALID_INFO);
            return;
          }
          state.upstreamReceiveCredits.set(pkt.streamId, creditsRemaining - 1);
        }
        stream.send(pkt.payload);
        break;
      }
      case PACKET_TYPE.CLOSE: {
        const reason = decodeClose(pkt.payload) ?? 0;
        const localStream = state.localStreams.get(pkt.streamId);
        if (localStream) {
          this.closeLocalStream(localStream, reason, false);
          return;
        }
        const upstreamId = state.streamIdMap.get(pkt.streamId);
        if (upstreamId === undefined) return;
        const stream = state.upstreamStreams.get(upstreamId);
        stream?.close(reason);
        state.streamIdMap.delete(pkt.streamId);
        state.upstreamStreams.delete(upstreamId);
        state.upstreamReceiveCredits.delete(pkt.streamId);
        state.streamRecords.delete(pkt.streamId);
        break;
      }
      // CONTINUE and INFO from clients are not expected in the relay direction
      // (upstream handles credit for us); silently ignore.
    }
  }

  private openLocalStream(
    client: ClientState,
    listener: ListenerState,
    clientStreamId: number,
    hostname: string,
    port: number,
  ): void {
    const stream: LocalStreamState = {
      client,
      listener,
      clientStreamId,
      closed: false,
      closeReason: null,
      receiveCreditsRemaining: LOCAL_STREAM_RECEIVE_WINDOW,
      receiveCreditResetTimer: null,
      dataListeners: new Set(),
      closeListeners: new Set(),
    };
    client.localStreams.set(clientStreamId, stream);
    client.streamRecords.set(clientStreamId, {
      id: clientStreamId,
      type: 'tcp',
      hostname,
      port,
      local: true,
    });
    listener.streams.add(stream);

    const socket: MoonbeamLocalSocket = {
      onData: (callback) => {
        if (stream.closed) return () => {};
        stream.dataListeners.add(callback);
        return () => stream.dataListeners.delete(callback);
      },
      onClose: (callback) => {
        if (stream.closed) {
          try {
            callback(stream.closeReason ?? CLOSE_REASON.VOLUNTARY);
          } catch {
            // Late observer exceptions are isolated like normal close callbacks.
          }
          return () => {};
        }
        stream.closeListeners.add(callback);
        return () => stream.closeListeners.delete(callback);
      },
      send: (data) => {
        if (stream.closed) throw new Error('MoonbeamLocalSocket: send on closed stream');
        this.postClientPacket(client, PACKET_TYPE.DATA, clientStreamId, data);
      },
      close: (reason = CLOSE_REASON.VOLUNTARY) => {
        this.closeLocalStream(stream, reason, true);
      },
    };

    this.postClientPacket(
      client,
      PACKET_TYPE.CONTINUE,
      clientStreamId,
      encodeContinue(LOCAL_STREAM_RECEIVE_WINDOW),
    );

    try {
      listener.handler(socket);
    } catch {
      this.closeLocalStream(stream, CLOSE_REASON.UNKNOWN, true);
      return;
    }
  }

  private closeLocalStream(stream: LocalStreamState, reason: number, notifyClient: boolean): void {
    if (stream.closed) return;
    stream.closed = true;
    stream.closeReason = reason;
    if (stream.receiveCreditResetTimer !== null) {
      clearTimeout(stream.receiveCreditResetTimer);
      stream.receiveCreditResetTimer = null;
    }
    stream.client.localStreams.delete(stream.clientStreamId);
    stream.client.streamRecords.delete(stream.clientStreamId);
    stream.listener.streams.delete(stream);
    if (notifyClient) {
      this.postClientPacket(stream.client, PACKET_TYPE.CLOSE, stream.clientStreamId, encodeClose(reason));
    }
    for (const listener of [...stream.closeListeners]) {
      try {
        listener(reason);
      } catch {
        // A consumer callback cannot interrupt transport resource cleanup.
      }
    }
    stream.dataListeners.clear();
    stream.closeListeners.clear();
  }

  private cleanupClient(state: ClientState): void {
    if (state.cleanedUp) return;
    state.cleanedUp = true;
    try {
      for (const stream of [...state.localStreams.values()]) {
        this.closeLocalStream(stream, CLOSE_REASON.VOLUNTARY, false);
      }
      for (const stream of [...state.upstreamStreams.values()]) stream.close();
    } finally {
      state.streamIdMap.clear();
      state.upstreamStreams.clear();
      state.upstreamReceiveCredits.clear();
      state.streamRecords.clear();
      try {
        state.port.close();
      } finally {
        this.availableVirtualIpHosts.push(state.virtualIpHost);
        this.availableVirtualIpHosts.sort((a, b) => a - b);
      }
    }
  }

  private postClientPacket(
    client: ClientState,
    type: number,
    streamId: number,
    payload: Uint8Array,
  ): void {
    const packet = encodePacket(type, streamId, payload);
    const buffer = packet.buffer as ArrayBuffer;
    client.port.postMessage(buffer, [buffer]);
  }

  private listenerKey(host: string, port: number): string {
    return `${host.toLowerCase()}:${port}`;
  }

}
