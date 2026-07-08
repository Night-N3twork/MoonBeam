import { describe, test, expect } from 'vitest';
import {
  decodePacket,
  encodePacket,
  encodeConnect,
  decodeConnect,
  encodeContinue,
  decodeContinue,
  encodeClose,
  decodeClose,
  encodeInfo,
  decodeInfo,
  readU32LE,
  writeU32LE,
  readU16LE,
  writeU16LE,
  type ExtensionEntry,
} from '../src/wisp-frame';
import { PACKET_TYPE, EXTENSION_ID } from '../src/wisp-types';

// Helper: hex string to Uint8Array.
function hex(s: string): Uint8Array {
  const clean = s.replace(/\s+/g, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Endianness helpers
// ---------------------------------------------------------------------------

describe('readU16LE / writeU16LE', () => {
  test('round-trip 0', () => {
    const buf = new Uint8Array(2);
    writeU16LE(buf, 0, 0);
    expect(buf[0]).toBe(0);
    expect(buf[1]).toBe(0);
    expect(readU16LE(buf, 0)).toBe(0);
  });

  test('round-trip 443 (port number)', () => {
    const buf = new Uint8Array(2);
    writeU16LE(buf, 0, 443);
    // 443 = 0x01BB; LE bytes are 0xBB, 0x01
    expect(buf[0]).toBe(0xbb);
    expect(buf[1]).toBe(0x01);
    expect(readU16LE(buf, 0)).toBe(443);
  });

  test('round-trip 0xFFFF (boundary)', () => {
    const buf = new Uint8Array(2);
    writeU16LE(buf, 0, 0xffff);
    expect(buf[0]).toBe(0xff);
    expect(buf[1]).toBe(0xff);
    expect(readU16LE(buf, 0)).toBe(0xffff);
  });

  test('honours offset', () => {
    const buf = new Uint8Array(4);
    writeU16LE(buf, 2, 0x1234);
    expect(buf[0]).toBe(0);
    expect(buf[1]).toBe(0);
    expect(buf[2]).toBe(0x34);
    expect(buf[3]).toBe(0x12);
    expect(readU16LE(buf, 2)).toBe(0x1234);
  });
});

describe('readU32LE / writeU32LE', () => {
  test('round-trip 0', () => {
    const buf = new Uint8Array(4);
    writeU32LE(buf, 0, 0);
    expect(readU32LE(buf, 0)).toBe(0);
  });

  test('round-trip 92 (small stream id)', () => {
    const buf = new Uint8Array(4);
    writeU32LE(buf, 0, 92);
    // 92 = 0x5C; LE bytes are 0x5C, 0x00, 0x00, 0x00
    expect(buf[0]).toBe(0x5c);
    expect(buf[1]).toBe(0x00);
    expect(buf[2]).toBe(0x00);
    expect(buf[3]).toBe(0x00);
    expect(readU32LE(buf, 0)).toBe(92);
  });

  test('round-trip 0xFFFFFFFF (boundary - unsigned semantics)', () => {
    const buf = new Uint8Array(4);
    writeU32LE(buf, 0, 0xffffffff);
    expect(buf[0]).toBe(0xff);
    expect(buf[1]).toBe(0xff);
    expect(buf[2]).toBe(0xff);
    expect(buf[3]).toBe(0xff);
    // Must be unsigned (>= 0)
    expect(readU32LE(buf, 0)).toBe(0xffffffff);
    expect(readU32LE(buf, 0)).toBeGreaterThan(0);
  });

  test('round-trip 0x80000000 (high bit set, unsigned)', () => {
    const buf = new Uint8Array(4);
    writeU32LE(buf, 0, 0x80000000);
    expect(readU32LE(buf, 0)).toBe(0x80000000);
    expect(readU32LE(buf, 0)).toBeGreaterThan(0);
  });

  test('honours offset', () => {
    const buf = new Uint8Array(8);
    writeU32LE(buf, 4, 0xdeadbeef);
    expect(readU32LE(buf, 4)).toBe(0xdeadbeef);
  });
});

// ---------------------------------------------------------------------------
// Generic packet encode/decode
// ---------------------------------------------------------------------------

describe('encodePacket / decodePacket', () => {
  test('encodes a DATA packet correctly', () => {
    // type=DATA(0x02), streamId=92, payload="GET"
    const payload = new Uint8Array([0x47, 0x45, 0x54]); // "GET"
    const encoded = encodePacket(PACKET_TYPE.DATA, 92, payload);
    expect(bytesEqual(encoded, hex('02 5C 00 00 00 47 45 54'))).toBe(true);
  });

  test('round-trips through decode', () => {
    const payload = new Uint8Array([1, 2, 3, 4, 5]);
    const encoded = encodePacket(0x02, 42, payload);
    const decoded = decodePacket(encoded);
    expect(decoded).not.toBeNull();
    expect(decoded!.type).toBe(0x02);
    expect(decoded!.streamId).toBe(42);
    expect(bytesEqual(decoded!.payload, payload)).toBe(true);
  });

  test('returns null on buffer shorter than header', () => {
    expect(decodePacket(new Uint8Array(0))).toBeNull();
    expect(decodePacket(new Uint8Array(4))).toBeNull();
  });

  test('returns valid packet at exactly 5 bytes (empty payload)', () => {
    const buf = hex('04 5C 00 00 00');
    const decoded = decodePacket(buf);
    expect(decoded).not.toBeNull();
    expect(decoded!.type).toBe(0x04);
    expect(decoded!.streamId).toBe(92);
    expect(decoded!.payload.length).toBe(0);
  });

  test('handles stream ID > 2^31 (unsigned semantics)', () => {
    const buf = new Uint8Array(5);
    buf[0] = 0x02;
    // streamId = 0xFFFFFFFE (LE)
    buf[1] = 0xfe;
    buf[2] = 0xff;
    buf[3] = 0xff;
    buf[4] = 0xff;
    const decoded = decodePacket(buf);
    expect(decoded).not.toBeNull();
    expect(decoded!.streamId).toBe(0xfffffffe);
    expect(decoded!.streamId).toBeGreaterThan(0);
  });

  test('payload is a view into the input buffer (does not copy header off)', () => {
    // We don't require it to be a copy or a subarray, but it must contain
    // the right bytes regardless.
    const input = hex('02 01 00 00 00 AA BB CC');
    const decoded = decodePacket(input);
    expect(decoded).not.toBeNull();
    expect(decoded!.payload.length).toBe(3);
    expect(decoded!.payload[0]).toBe(0xaa);
    expect(decoded!.payload[1]).toBe(0xbb);
    expect(decoded!.payload[2]).toBe(0xcc);
  });
});

// ---------------------------------------------------------------------------
// CONNECT
// ---------------------------------------------------------------------------

describe('encodeConnect / decodeConnect', () => {
  test('spec vector: CONNECT TCP to example.com:443', () => {
    // Full packet from spec §3.13:
    //   01 5C 00 00 00     type=CONNECT, stream=92
    //   01                 stream type TCP
    //   BB 01              port 443
    //   65 78 61 6D 70 6C 65 2E 63 6F 6D    "example.com"
    const payload = encodeConnect('tcp', 443, 'example.com');
    const packet = encodePacket(PACKET_TYPE.CONNECT, 92, payload);
    expect(
      bytesEqual(packet, hex('01 5C 00 00 00 01 BB 01 65 78 61 6D 70 6C 65 2E 63 6F 6D')),
    ).toBe(true);
  });

  test('round-trip TCP', () => {
    const payload = encodeConnect('tcp', 8080, 'example.org');
    const decoded = decodeConnect(payload);
    expect(decoded).not.toBeNull();
    expect(decoded!.streamType).toBe('tcp');
    expect(decoded!.port).toBe(8080);
    expect(decoded!.hostname).toBe('example.org');
  });

  test('round-trip UDP', () => {
    const payload = encodeConnect('udp', 53, '1.1.1.1');
    const decoded = decodeConnect(payload);
    expect(decoded).not.toBeNull();
    expect(decoded!.streamType).toBe('udp');
    expect(decoded!.port).toBe(53);
    expect(decoded!.hostname).toBe('1.1.1.1');
  });

  test('round-trip UTF-8 hostname', () => {
    // Punycode is typical, but encoder should faithfully round-trip arbitrary UTF-8.
    const payload = encodeConnect('tcp', 80, 'xn--bcher-kva.example');
    const decoded = decodeConnect(payload);
    expect(decoded!.hostname).toBe('xn--bcher-kva.example');
  });

  test('returns null on payload < 3 bytes', () => {
    expect(decodeConnect(new Uint8Array(0))).toBeNull();
    expect(decodeConnect(new Uint8Array(1))).toBeNull();
    expect(decodeConnect(new Uint8Array(2))).toBeNull();
  });

  test('returns null on unknown stream type 0x03', () => {
    const bad = new Uint8Array([0x03, 0xbb, 0x01]); // type=3, port=443, no hostname
    expect(decodeConnect(bad)).toBeNull();
  });

  test('returns null on stream type 0x00', () => {
    const bad = new Uint8Array([0x00, 0xbb, 0x01]);
    expect(decodeConnect(bad)).toBeNull();
  });

  test('accepts empty hostname (3 bytes total, just type+port)', () => {
    // Spec says hostname fills "the rest of the payload" — zero bytes is valid.
    const payload = new Uint8Array([0x01, 0xbb, 0x01]);
    const decoded = decodeConnect(payload);
    expect(decoded).not.toBeNull();
    expect(decoded!.streamType).toBe('tcp');
    expect(decoded!.port).toBe(443);
    expect(decoded!.hostname).toBe('');
  });

  test('hostname not null-terminated and not length-prefixed', () => {
    // Build manually: TCP, port 80, hostname "a"
    const buf = new Uint8Array([0x01, 0x50, 0x00, 0x61]);
    const decoded = decodeConnect(buf);
    expect(decoded!.hostname).toBe('a');
    expect(decoded!.hostname.length).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// CONTINUE
// ---------------------------------------------------------------------------

describe('encodeContinue / decodeContinue', () => {
  test('round-trip', () => {
    const payload = encodeContinue(128);
    expect(payload.length).toBe(4);
    expect(decodeContinue(payload)).toBe(128);
  });

  test('round-trip 0', () => {
    expect(decodeContinue(encodeContinue(0))).toBe(0);
  });

  test('round-trip 0xFFFFFFFF', () => {
    expect(decodeContinue(encodeContinue(0xffffffff))).toBe(0xffffffff);
  });

  test('returns null on payload != 4 bytes', () => {
    expect(decodeContinue(new Uint8Array(0))).toBeNull();
    expect(decodeContinue(new Uint8Array(3))).toBeNull();
    expect(decodeContinue(new Uint8Array(5))).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// CLOSE
// ---------------------------------------------------------------------------

describe('encodeClose / decodeClose', () => {
  test('spec vector: CLOSE stream 92 reason 0x02', () => {
    // 04 5C 00 00 00 02
    const payload = encodeClose(0x02);
    const packet = encodePacket(PACKET_TYPE.CLOSE, 92, payload);
    expect(bytesEqual(packet, hex('04 5C 00 00 00 02'))).toBe(true);
  });

  test('round-trip', () => {
    expect(decodeClose(encodeClose(0x02))).toBe(0x02);
    expect(decodeClose(encodeClose(0xc2))).toBe(0xc2);
    expect(decodeClose(encodeClose(0xff))).toBe(0xff);
  });

  test('returns null on empty payload', () => {
    expect(decodeClose(new Uint8Array(0))).toBeNull();
  });

  test('accepts 1-byte payload (minimum)', () => {
    expect(decodeClose(new Uint8Array([0x02]))).toBe(0x02);
  });
});

// ---------------------------------------------------------------------------
// INFO
// ---------------------------------------------------------------------------

describe('encodeInfo / decodeInfo', () => {
  test('spec vector: server INFO with UDP + Stream Open Confirmation', () => {
    // 05 00 00 00 00       type=INFO, stream=0
    // 02 01                version 2.1
    // 01 00 00 00 00       extension UDP (0x01), payload length 0
    // 05 00 00 00 00       extension Stream Open Confirmation (0x05), payload length 0
    const extensions: ExtensionEntry[] = [
      { id: EXTENSION_ID.UDP, metadata: new Uint8Array(0) },
      { id: EXTENSION_ID.STREAM_OPEN_CONFIRMATION, metadata: new Uint8Array(0) },
    ];
    const payload = encodeInfo(2, 1, extensions);
    const packet = encodePacket(PACKET_TYPE.INFO, 0, payload);
    expect(
      bytesEqual(packet, hex('05 00 00 00 00 02 01 01 00 00 00 00 05 00 00 00 00')),
    ).toBe(true);
  });

  test('round-trips version + no extensions', () => {
    const encoded = encodeInfo(2, 1, []);
    const decoded = decodeInfo(encoded);
    expect(decoded).not.toBeNull();
    expect(decoded!.major).toBe(2);
    expect(decoded!.minor).toBe(1);
    expect(decoded!.extensions.length).toBe(0);
  });

  test('round-trips multiple extensions, order preserved', () => {
    const exts: ExtensionEntry[] = [
      { id: 0x01, metadata: new Uint8Array(0) },
      { id: 0x04, metadata: new TextEncoder().encode('Hello world') },
      { id: 0x05, metadata: new Uint8Array(0) },
    ];
    const encoded = encodeInfo(2, 1, exts);
    const decoded = decodeInfo(encoded);
    expect(decoded).not.toBeNull();
    expect(decoded!.extensions.length).toBe(3);
    expect(decoded!.extensions[0].id).toBe(0x01);
    expect(decoded!.extensions[1].id).toBe(0x04);
    expect(decoded!.extensions[2].id).toBe(0x05);
  });

  test('preserves non-empty extension metadata bytes', () => {
    const motd = new TextEncoder().encode('Welcome to Wisp');
    const exts: ExtensionEntry[] = [
      { id: EXTENSION_ID.MOTD, metadata: motd },
    ];
    const encoded = encodeInfo(2, 1, exts);
    const decoded = decodeInfo(encoded);
    expect(decoded).not.toBeNull();
    expect(decoded!.extensions[0].id).toBe(EXTENSION_ID.MOTD);
    expect(bytesEqual(decoded!.extensions[0].metadata, motd)).toBe(true);
    expect(new TextDecoder().decode(decoded!.extensions[0].metadata)).toBe(
      'Welcome to Wisp',
    );
  });

  test('preserves arbitrary metadata bytes (binary)', () => {
    const meta = new Uint8Array([0x01, 0x02, 0x03, 0xff, 0x00, 0x7f]);
    const exts: ExtensionEntry[] = [{ id: 0x42, metadata: meta }];
    const encoded = encodeInfo(2, 1, exts);
    const decoded = decodeInfo(encoded);
    expect(bytesEqual(decoded!.extensions[0].metadata, meta)).toBe(true);
  });

  test('returns null on payload < 2 bytes (no version)', () => {
    expect(decodeInfo(new Uint8Array(0))).toBeNull();
    expect(decodeInfo(new Uint8Array(1))).toBeNull();
  });

  test('returns null on malformed extension (claimed length > remaining)', () => {
    // version 2.1, then extension id=0x01 with claimed length=10 but no bytes follow
    const buf = new Uint8Array([
      0x02, 0x01,           // version
      0x01,                 // ext id
      0x0a, 0x00, 0x00, 0x00, // claimed length 10
      // ... missing 10 bytes
    ]);
    expect(decodeInfo(buf)).toBeNull();
  });

  test('returns null on extension header truncated (< 5 bytes for id+length)', () => {
    // version + extension id but no length field
    const buf = new Uint8Array([
      0x02, 0x01, // version
      0x01,       // ext id
      0x00, 0x00, // truncated length (need 4 bytes)
    ]);
    expect(decodeInfo(buf)).toBeNull();
  });

  test('parses unknown extension ID (forward compat)', () => {
    const meta = new Uint8Array([0xde, 0xad]);
    const exts: ExtensionEntry[] = [
      { id: 0xff, metadata: meta },                              // unknown
      { id: EXTENSION_ID.UDP, metadata: new Uint8Array(0) },     // known
    ];
    const encoded = encodeInfo(2, 1, exts);
    const decoded = decodeInfo(encoded);
    expect(decoded).not.toBeNull();
    expect(decoded!.extensions.length).toBe(2);
    expect(decoded!.extensions[0].id).toBe(0xff);
    expect(bytesEqual(decoded!.extensions[0].metadata, meta)).toBe(true);
    expect(decoded!.extensions[1].id).toBe(EXTENSION_ID.UDP);
  });

  test('decodeInfo accepts version-only payload (2 bytes exactly)', () => {
    const decoded = decodeInfo(new Uint8Array([0x02, 0x01]));
    expect(decoded).not.toBeNull();
    expect(decoded!.major).toBe(2);
    expect(decoded!.minor).toBe(1);
    expect(decoded!.extensions.length).toBe(0);
  });
});
