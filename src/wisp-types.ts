/**
 * Wisp v2.1 protocol constants.
 *
 * Single source of truth for packet type codes, stream type codes, extension
 * IDs, and close reason codes. All multi-byte fields in the protocol are
 * little-endian (note: unusual for network protocols; deliberate per the
 * Wisp spec).
 *
 * Spec: /home/amplify/Projects/webVM-wisp/q-demo/docs/wisp-protocol/protocol.md
 */

export const PACKET_TYPE = {
  CONNECT: 0x01,
  DATA: 0x02,
  CONTINUE: 0x03,
  CLOSE: 0x04,
  INFO: 0x05,
} as const;
export type PacketType = (typeof PACKET_TYPE)[keyof typeof PACKET_TYPE];

export const STREAM_TYPE = {
  TCP: 0x01,
  UDP: 0x02,
} as const;
export type StreamType = 'tcp' | 'udp';

export const EXTENSION_ID = {
  UDP: 0x01,
  PASSWORD_AUTH: 0x02,
  PUBKEY_AUTH: 0x03,
  MOTD: 0x04,
  STREAM_OPEN_CONFIRMATION: 0x05,
} as const;

export const CLOSE_REASON = {
  // Common
  UNKNOWN: 0x01,
  VOLUNTARY: 0x02,
  NETWORK_ERROR: 0x03,
  INCOMPATIBLE_EXTENSIONS: 0x04,
  // Server only
  STREAM_INVALID_INFO: 0x41,
  STREAM_UNREACHABLE: 0x42,
  STREAM_TIMED_OUT: 0x43,
  STREAM_REFUSED: 0x44,
  TCP_DATA_TIMED_OUT: 0x47,
  STREAM_BLOCKED: 0x48,
  THROTTLED: 0x49,
  // Client only
  CLIENT_ERROR: 0x81,
  // Auth (extension)
  AUTH_INVALID_PASSWORD: 0xc0,
  AUTH_INVALID_SIGNATURE: 0xc1,
  AUTH_REQUIRED: 0xc2,
} as const;

/** Stream ID 0 is reserved for connection-level (handshake) messages. */
export const RESERVED_STREAM_ID = 0;

/**
 * Subprotocol name sent in `Sec-WebSocket-Protocol` per spec §4.4.
 * The spec only requires the header be *present*; the value is descriptive.
 */
export const ECLIPSE_PROTOCOL_NAME = 'wisp-v2';
