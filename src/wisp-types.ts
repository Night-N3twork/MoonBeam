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
export type ExtensionId = (typeof EXTENSION_ID)[keyof typeof EXTENSION_ID];

/**
 * Metadata shapes for each known Wisp extension.
 *
 * - `UdpExtension`: empty metadata (presence alone signals support).
 * - `PasswordAuthExtension`: `{ username: string; password: string }` encoded
 *   as `username:u8[]|0x00|password:u8[]` (username and password are
 *   null-terminated UTF-8 byte sequences).
 * - `PubkeyAuthExtension`: `{ publicKey: Uint8Array; signature: Uint8Array }`
 *   — two length-prefixed byte sequences.
 * - `MotdExtension`: `{ message: string }` — a UTF-8 message from the server.
 * - `StreamOpenConfirmationExtension`: empty metadata (presence alone signals
 *   support; the server sends a CONTINUE on the stream before the first DATA
 *   to confirm the upstream connection succeeded).
 */
export type ExtensionMetadataByID = {
  [EXTENSION_ID.UDP]: undefined;
  [EXTENSION_ID.PASSWORD_AUTH]: { username: string; password: string };
  [EXTENSION_ID.PUBKEY_AUTH]: { publicKey: Uint8Array; signature: Uint8Array };
  [EXTENSION_ID.MOTD]: { message: string };
  [EXTENSION_ID.STREAM_OPEN_CONFIRMATION]: undefined;
};

export type ExtensionID = keyof ExtensionMetadataByID;

/**
 * Resolved extension descriptor after parsing the raw metadata bytes.
 * `metadata` is `undefined` for extensions that carry no metadata (presence
 * alone signals support).
 */
export type ResolvedExtension<T extends ExtensionID = ExtensionID> = {
  id: T;
  metadata: ExtensionMetadataByID[T];
};

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
