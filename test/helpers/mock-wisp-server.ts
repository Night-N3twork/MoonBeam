/**
 * MockWispServer — a wire-format scripted Wisp server hung off the back of
 * a MockWebSocket.
 *
 * The server SIDE of the conversation: it observes what WispClient sends
 * (via MockWebSocket.onSend) and produces server packets back via
 * MockWebSocket.simulateMessage().
 *
 * This is a scripted helper, not a full server simulation. Tests drive it
 * step-by-step:
 *
 *   const ws = new MockWebSocket();
 *   const srv = new MockWispServer(ws);
 *   const client = new WispClient({ url: 'ws://x/', _injectWebSocket: ws });
 *
 *   ws.simulateOpen('wisp-v2');
 *   srv.sendInfo({ udp: true, motd: 'hi' });
 *   // ... client sends its INFO; srv.receivedInfo() returns it
 *   srv.sendHandshakeContinue(256);
 *   await client.ready();
 *
 * The server captures decoded packets for assertion; tests inspect
 * `srv.received` (chronological list of decoded packets observed from client).
 */

import {
  encodePacket,
  encodeContinue,
  encodeClose,
  encodeInfo,
  decodePacket,
  decodeConnect,
  decodeContinue,
  decodeClose,
  decodeInfo,
  type DecodedPacket,
  type ConnectPayload,
  type InfoPayload,
} from '../../src/wisp-frame';
import { PACKET_TYPE, EXTENSION_ID } from '../../src/wisp-types';
import type { MockWebSocket } from './mock-websocket';

export interface DecodedClientPacket {
  raw: DecodedPacket;
  /** Decoded payload, type depends on `raw.type`. */
  decoded: ConnectPayload | number | InfoPayload | Uint8Array | null;
}

export interface ServerInfoOptions {
  major?: number;
  minor?: number;
  udp?: boolean;
  motd?: string | null;
  /** Adds the password-auth extension. If `required`, sets Required=1. */
  passwordAuth?: { required: boolean };
  /** Adds the pubkey-auth extension with optional Required flag. */
  pubkeyAuth?: { required: boolean };
  streamOpenConfirmation?: boolean;
  /** Append arbitrary unknown extensions for forward-compat tests. */
  extraExtensions?: { id: number; metadata: Uint8Array }[];
}

export class MockWispServer {
  /** Decoded client→server packets in chronological order. */
  readonly received: DecodedClientPacket[] = [];

  constructor(private ws: MockWebSocket) {
    ws.onSend = (bytes) => this.onClientSend(bytes);
  }

  private onClientSend(bytes: Uint8Array): void {
    const raw = decodePacket(bytes);
    if (!raw) {
      this.received.push({ raw: { type: -1, streamId: -1, payload: bytes }, decoded: null });
      return;
    }
    let decoded: DecodedClientPacket['decoded'] = null;
    switch (raw.type) {
      case PACKET_TYPE.CONNECT:
        decoded = decodeConnect(raw.payload);
        break;
      case PACKET_TYPE.DATA:
        // Copy so server-side inspection survives buffer reuse.
        decoded = new Uint8Array(raw.payload);
        break;
      case PACKET_TYPE.CONTINUE:
        decoded = decodeContinue(raw.payload);
        break;
      case PACKET_TYPE.CLOSE:
        decoded = decodeClose(raw.payload);
        break;
      case PACKET_TYPE.INFO:
        decoded = decodeInfo(raw.payload);
        break;
    }
    this.received.push({ raw, decoded });
  }

  /** All client packets that were CONNECT, in arrival order. */
  connects(): { streamId: number; payload: ConnectPayload }[] {
    return this.received
      .filter((p) => p.raw.type === PACKET_TYPE.CONNECT && p.decoded)
      .map((p) => ({ streamId: p.raw.streamId, payload: p.decoded as ConnectPayload }));
  }

  /** All client DATA packets on a given stream, in arrival order. */
  dataPackets(streamId: number): Uint8Array[] {
    return this.received
      .filter((p) => p.raw.type === PACKET_TYPE.DATA && p.raw.streamId === streamId)
      .map((p) => p.decoded as Uint8Array);
  }

  /** The most recent client INFO packet (post-handshake), or null. */
  lastClientInfo(): InfoPayload | null {
    for (let i = this.received.length - 1; i >= 0; i--) {
      const p = this.received[i];
      if (p.raw.type === PACKET_TYPE.INFO) return p.decoded as InfoPayload | null;
    }
    return null;
  }

  /** All CLOSE packets sent by the client. */
  closes(): { streamId: number; reason: number }[] {
    return this.received
      .filter((p) => p.raw.type === PACKET_TYPE.CLOSE && p.decoded != null)
      .map((p) => ({ streamId: p.raw.streamId, reason: p.decoded as number }));
  }

  // ---- server -> client sends --------------------------------------------

  sendInfo(opts: ServerInfoOptions = {}): void {
    const major = opts.major ?? 2;
    const minor = opts.minor ?? 1;
    const exts: { id: number; metadata: Uint8Array }[] = [];
    if (opts.udp) exts.push({ id: EXTENSION_ID.UDP, metadata: new Uint8Array(0) });
    if (opts.passwordAuth) {
      exts.push({
        id: EXTENSION_ID.PASSWORD_AUTH,
        metadata: new Uint8Array([opts.passwordAuth.required ? 1 : 0]),
      });
    }
    if (opts.pubkeyAuth) {
      // Required:u8, algos:u8, challenge:[]
      exts.push({
        id: EXTENSION_ID.PUBKEY_AUTH,
        metadata: new Uint8Array([opts.pubkeyAuth.required ? 1 : 0, 0x01]),
      });
    }
    if (opts.motd !== undefined && opts.motd !== null) {
      exts.push({
        id: EXTENSION_ID.MOTD,
        metadata: new TextEncoder().encode(opts.motd),
      });
    }
    if (opts.streamOpenConfirmation) {
      exts.push({ id: EXTENSION_ID.STREAM_OPEN_CONFIRMATION, metadata: new Uint8Array(0) });
    }
    if (opts.extraExtensions) {
      for (const e of opts.extraExtensions) exts.push(e);
    }
    const payload = encodeInfo(major, minor, exts);
    const pkt = encodePacket(PACKET_TYPE.INFO, 0, payload);
    this.ws.simulateMessage(pkt);
  }

  sendHandshakeContinue(bufferSize: number): void {
    const pkt = encodePacket(PACKET_TYPE.CONTINUE, 0, encodeContinue(bufferSize));
    this.ws.simulateMessage(pkt);
  }

  sendStreamContinue(streamId: number, bufferRemaining: number): void {
    const pkt = encodePacket(PACKET_TYPE.CONTINUE, streamId, encodeContinue(bufferRemaining));
    this.ws.simulateMessage(pkt);
  }

  sendData(streamId: number, data: Uint8Array): void {
    const pkt = encodePacket(PACKET_TYPE.DATA, streamId, data);
    this.ws.simulateMessage(pkt);
  }

  sendClose(streamId: number, reason: number): void {
    const pkt = encodePacket(PACKET_TYPE.CLOSE, streamId, encodeClose(reason));
    this.ws.simulateMessage(pkt);
  }

  /** Send a raw, opaque message — useful for "first packet is CONTINUE" v1 test. */
  sendRaw(bytes: Uint8Array): void {
    this.ws.simulateMessage(bytes);
  }
}
