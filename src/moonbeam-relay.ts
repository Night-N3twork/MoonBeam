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
import { decodePacket, decodeConnect, decodeClose, encodePacket, encodeClose } from './wisp-frame';
import { PACKET_TYPE } from './wisp-types';
import type { EgressPolicyConfig } from './policy';

export interface MoonbeamRelayOptions {
  /** Wisp v2.1 endpoint. */
  wispUrl: string;
  /** Optional egress policy applied to relayed CONNECT payloads. */
  egress?: EgressPolicyConfig;
  /** @internal Test hook — never set in production. */
  _injectWebSocket?: any;
}

interface ClientState {
  port: MessagePort;
  /** client stream ID → upstream stream ID */
  streamIdMap: Map<number, number>;
  /** upstream stream ID → WispStream handle */
  upstreamStreams: Map<number, WispStream>;
}

export class MoonbeamRelay {
  private readonly upstream: WispClient;
  private readonly clients = new Map<MessagePort, ClientState>();
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

  attach(): MessagePort {
    if (this.closed) throw new Error('MoonbeamRelay.attach: relay is closed');
    const channel = new MessageChannel();
    const state: ClientState = {
      port: channel.port1,
      streamIdMap: new Map(),
      upstreamStreams: new Map(),
    };
    this.clients.set(channel.port2, state);
    channel.port1.addEventListener('message', (ev) => {
      this.onClientMessage(state, ev.data);
    });
    channel.port1.start();
    return channel.port2;
  }

  detach(port: MessagePort): void {
    const state = this.clients.get(port);
    if (!state) return;
    for (const stream of state.upstreamStreams.values()) {
      stream.close();
    }
    state.port.close();
    this.clients.delete(port);
  }

  // ------------------------------------------------------------------
  // Observability
  // ------------------------------------------------------------------

  /** Number of clients currently attached to this relay. */
  clientCount(): number {
    return this.clients.size;
  }

  /** Total number of open upstream streams across all attached clients. */
  streamCount(): number {
    let n = 0;
    for (const s of this.clients.values()) {
      n += s.upstreamStreams.size;
    }
    return n;
  }

  /** Whether the relay is closed. */
  isClosed(): boolean {
    return this.closed;
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    for (const state of this.clients.values()) {
      state.port.close();
    }
    this.clients.clear();
    this.upstream.close();
  }

  private onClientMessage(state: ClientState, raw: any): void {
    const buf = raw instanceof Uint8Array ? raw : new Uint8Array(raw as ArrayBuffer);
    const pkt = decodePacket(buf);
    if (!pkt) return; // malformed — drop

    switch (pkt.type) {
      case PACKET_TYPE.CONNECT: {
        const payload = decodeConnect(pkt.payload);
        if (!payload) return;
        const upstreamStream = this.upstream.createStream(
          payload.hostname,
          payload.port,
          payload.streamType,
        );
        state.streamIdMap.set(pkt.streamId, upstreamStream.id);
        state.upstreamStreams.set(upstreamStream.id, upstreamStream);

        const clientStreamId = pkt.streamId; // capture; avoid closure over the loop-scoped variable

        upstreamStream.on('data', (data: Uint8Array) => {
          const dataPacket = encodePacket(PACKET_TYPE.DATA, clientStreamId, data);
          state.port.postMessage(dataPacket, [dataPacket.buffer as ArrayBuffer]);
        });

        upstreamStream.on('close', (info: { reason: number }) => {
          const closePacket = encodePacket(
            PACKET_TYPE.CLOSE,
            clientStreamId,
            encodeClose(info?.reason ?? 0),
          );
          state.port.postMessage(closePacket, [closePacket.buffer as ArrayBuffer]);
          state.streamIdMap.delete(clientStreamId);
          state.upstreamStreams.delete(upstreamStream.id);
        });
        break;
      }
      case PACKET_TYPE.DATA: {
        const upstreamId = state.streamIdMap.get(pkt.streamId);
        if (upstreamId === undefined) return;
        const stream = state.upstreamStreams.get(upstreamId);
        stream?.send(pkt.payload);
        break;
      }
      case PACKET_TYPE.CLOSE: {
        const upstreamId = state.streamIdMap.get(pkt.streamId);
        if (upstreamId === undefined) return;
        const stream = state.upstreamStreams.get(upstreamId);
        const reason = decodeClose(pkt.payload) ?? 0;
        stream?.close(reason);
        state.streamIdMap.delete(pkt.streamId);
        state.upstreamStreams.delete(upstreamId);
        break;
      }
      // CONTINUE and INFO from clients are not expected in the relay direction
      // (upstream handles credit for us); silently ignore.
    }
  }
}
