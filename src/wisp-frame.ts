/**
 * Wisp v2.1 packet codec: pure encode/decode for the five protocol packets,
 * plus little-endian helpers.
 *
 * Wire layout (every packet, no length prefix — WebSocket message boundaries
 * delimit packets):
 *
 *   +--------+------------------+-------------------+
 *   | Type:1 | StreamID:4 (LE)  | Payload (rest)    |
 *   +--------+------------------+-------------------+
 *
 * All multi-byte fields are little-endian.
 *
 * Spec: /home/amplify/Projects/webVM-wisp/q-demo/docs/wisp-protocol/protocol.md
 * Design: /home/amplify/Projects/webVM-wisp/Eclipse/docs/specs/2026-05-27-vm-wisp-networking-design.md §4
 */

import { STREAM_TYPE, type StreamType } from './wisp-types';

// ---------------------------------------------------------------------------
// Endianness helpers
// ---------------------------------------------------------------------------

/** Read a uint16 little-endian at `offset`. */
export function readU16LE(buf: Uint8Array, offset: number): number {
  return buf[offset] | (buf[offset + 1] << 8);
}

/** Write a uint16 little-endian at `offset`. */
export function writeU16LE(buf: Uint8Array, offset: number, value: number): void {
  buf[offset] = value & 0xff;
  buf[offset + 1] = (value >>> 8) & 0xff;
}

/**
 * Read a uint32 little-endian at `offset`. Returns a JS number with unsigned
 * semantics — the result is always in `[0, 2^32 - 1]`, never negative.
 */
export function readU32LE(buf: Uint8Array, offset: number): number {
  // `>>> 0` forces unsigned interpretation (otherwise the high bit makes the
  // result a negative int32).
  return (
    (buf[offset] |
      (buf[offset + 1] << 8) |
      (buf[offset + 2] << 16) |
      (buf[offset + 3] << 24)) >>>
    0
  );
}

/** Write a uint32 little-endian at `offset`. */
export function writeU32LE(buf: Uint8Array, offset: number, value: number): void {
  buf[offset] = value & 0xff;
  buf[offset + 1] = (value >>> 8) & 0xff;
  buf[offset + 2] = (value >>> 16) & 0xff;
  buf[offset + 3] = (value >>> 24) & 0xff;
}

// ---------------------------------------------------------------------------
// Generic packet encode/decode
// ---------------------------------------------------------------------------

export interface DecodedPacket {
  /** Packet type code (e.g. 0x01 = CONNECT). */
  type: number;
  /** Stream ID, unsigned 32-bit. 0 is reserved for connection-level messages. */
  streamId: number;
  /**
   * Packet payload. This is a subarray view into the caller's buffer; callers
   * must not mutate it without copying first if they want to retain the
   * original.
   */
  payload: Uint8Array;
}

/**
 * Decode a Wisp packet header + payload from a raw WebSocket message body.
 *
 * Returns `null` if the buffer is shorter than the 5-byte header (malformed
 * packet). The payload may be zero-length (e.g. an INFO packet with no
 * extensions and only version bytes, or a malformed CONNECT — those further
 * validations live in the type-specific decoders).
 */
export function decodePacket(buf: Uint8Array): DecodedPacket | null {
  if (buf.length < 5) return null;
  const type = buf[0];
  const streamId = readU32LE(buf, 1);
  // subarray (not slice) — no copy; caller is expected to treat as read-only
  const payload = buf.subarray(5);
  return { type, streamId, payload };
}

/**
 * Encode a Wisp packet: 1-byte type, 4-byte LE streamId, then the payload.
 * Returns a freshly-allocated buffer.
 */
export function encodePacket(
  type: number,
  streamId: number,
  payload: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(5 + payload.length);
  out[0] = type & 0xff;
  writeU32LE(out, 1, streamId);
  out.set(payload, 5);
  return out;
}

// ---------------------------------------------------------------------------
// CONNECT (0x01) — payload: [streamType:u8][port:u16 LE][hostname: utf-8]
// ---------------------------------------------------------------------------

export interface ConnectPayload {
  streamType: StreamType;
  port: number;
  hostname: string;
}

/**
 * Encode a CONNECT payload. Hostname is UTF-8, NOT null-terminated, NOT
 * length-prefixed — it fills the rest of the payload (per spec).
 */
export function encodeConnect(
  streamType: StreamType,
  port: number,
  hostname: string,
): Uint8Array {
  const typeByte = streamType === 'tcp' ? STREAM_TYPE.TCP : STREAM_TYPE.UDP;
  const hostBytes = new TextEncoder().encode(hostname);
  const out = new Uint8Array(1 + 2 + hostBytes.length);
  out[0] = typeByte;
  writeU16LE(out, 1, port);
  out.set(hostBytes, 3);
  return out;
}

/**
 * Decode a CONNECT payload. Returns `null` for:
 *   - payloads shorter than 3 bytes (need at least streamType + port);
 *   - unknown streamType bytes (anything other than 0x01 or 0x02).
 *
 * Hostname may be empty (3-byte payload).
 */
export function decodeConnect(payload: Uint8Array): ConnectPayload | null {
  if (payload.length < 3) return null;
  const typeByte = payload[0];
  let streamType: StreamType;
  if (typeByte === STREAM_TYPE.TCP) streamType = 'tcp';
  else if (typeByte === STREAM_TYPE.UDP) streamType = 'udp';
  else return null;

  const port = readU16LE(payload, 1);
  const hostname = new TextDecoder('utf-8').decode(payload.subarray(3));
  return { streamType, port, hostname };
}

// ---------------------------------------------------------------------------
// DATA (0x02) — payload is raw stream bytes; no type-specific codec needed.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CONTINUE (0x03) — payload: bufferRemaining:u32 LE
// ---------------------------------------------------------------------------

/** Encode a CONTINUE payload (4 bytes). */
export function encodeContinue(bufferRemaining: number): Uint8Array {
  const out = new Uint8Array(4);
  writeU32LE(out, 0, bufferRemaining);
  return out;
}

/**
 * Decode a CONTINUE payload. Returns `null` if payload is not exactly 4
 * bytes — CONTINUE has a fixed-size payload, anything else is malformed.
 */
export function decodeContinue(payload: Uint8Array): number | null {
  if (payload.length !== 4) return null;
  return readU32LE(payload, 0);
}

// ---------------------------------------------------------------------------
// CLOSE (0x04) — payload: reason:u8
// ---------------------------------------------------------------------------

/** Encode a CLOSE payload (1 byte). */
export function encodeClose(reason: number): Uint8Array {
  return new Uint8Array([reason & 0xff]);
}

/**
 * Decode a CLOSE payload. Returns `null` on empty payload. Extra trailing
 * bytes are silently ignored (forward-compat: future spec revisions may
 * append fields).
 */
export function decodeClose(payload: Uint8Array): number | null {
  if (payload.length < 1) return null;
  return payload[0];
}

// ---------------------------------------------------------------------------
// INFO (0x05) — payload: major:u8, minor:u8, extensions[]
//   each extension entry: [id:u8][payloadLength:u32 LE][metadata:bytes]
// ---------------------------------------------------------------------------

export interface ExtensionEntry {
  id: number;
  /** Raw metadata bytes — per-extension parser knows the format. */
  metadata: Uint8Array;
}

export interface InfoPayload {
  major: number;
  minor: number;
  extensions: ExtensionEntry[];
}

/** Encode an INFO payload. Extension order is preserved on the wire. */
export function encodeInfo(
  major: number,
  minor: number,
  extensions: ExtensionEntry[],
): Uint8Array {
  // Pre-compute total length: 2 (version) + sum of (5 + metadata.length) per extension
  let totalLen = 2;
  for (const ext of extensions) {
    totalLen += 5 + ext.metadata.length;
  }

  const out = new Uint8Array(totalLen);
  out[0] = major & 0xff;
  out[1] = minor & 0xff;

  let offset = 2;
  for (const ext of extensions) {
    out[offset] = ext.id & 0xff;
    writeU32LE(out, offset + 1, ext.metadata.length);
    out.set(ext.metadata, offset + 5);
    offset += 5 + ext.metadata.length;
  }
  return out;
}

/**
 * Decode an INFO payload. Returns `null` on:
 *   - payload < 2 bytes (no version);
 *   - any extension entry with a header truncated mid-way (< 5 bytes
 *     remaining for id+length);
 *   - any extension entry whose claimed payload length exceeds remaining
 *     buffer space.
 *
 * Unknown extension IDs are preserved as-is (forward-compat: parsers for
 * specific extensions read the metadata field themselves).
 */
export function decodeInfo(payload: Uint8Array): InfoPayload | null {
  if (payload.length < 2) return null;
  const major = payload[0];
  const minor = payload[1];
  const extensions: ExtensionEntry[] = [];

  let offset = 2;
  while (offset < payload.length) {
    // Extension header is 5 bytes: id(1) + payloadLength(4).
    if (offset + 5 > payload.length) return null;
    const id = payload[offset];
    const len = readU32LE(payload, offset + 1);
    const metaStart = offset + 5;
    const metaEnd = metaStart + len;
    if (metaEnd > payload.length) return null;
    // Copy via slice so the caller cannot inadvertently mutate the source
    // through the returned reference (matters when callers stash these for
    // later async use).
    extensions.push({ id, metadata: payload.slice(metaStart, metaEnd) });
    offset = metaEnd;
  }

  return { major, minor, extensions };
}
