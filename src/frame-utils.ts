/**
 * Length-prefix codec for the QEMU `-netdev socket` wire format.
 *
 * Wire format: [length: 4 bytes BE][raw ethernet frame: length bytes][...]
 * Multiple frames may be concatenated in one WebSocket message; a single
 * frame may span multiple messages. Callers maintain a leftover buffer
 * across reads (see gateway-host).
 */

/**
 * Prepend a 4-byte big-endian length prefix to an ethernet frame.
 */
export function frameMessage(frame: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + frame.length);
  const len = frame.length;
  out[0] = (len >>> 24) & 0xff;
  out[1] = (len >>> 16) & 0xff;
  out[2] = (len >>> 8) & 0xff;
  out[3] = len & 0xff;
  out.set(frame, 4);
  return out;
}

/**
 * Parse zero or more length-prefixed frames from a buffer.
 *
 * Returns parsed frames (each a `Uint8Array` view, not a copy) plus any
 * incomplete tail bytes for the next read. If a length header is present
 * but the full payload has not arrived, the entire incomplete frame
 * (including its length header) is returned as remainder.
 */
export function extractFrames(buffer: Uint8Array): {
  frames: Uint8Array[];
  remainder: Uint8Array;
} {
  const frames: Uint8Array[] = [];
  let offset = 0;

  while (offset + 4 <= buffer.length) {
    const len =
      (buffer[offset] << 24) |
      (buffer[offset + 1] << 16) |
      (buffer[offset + 2] << 8) |
      buffer[offset + 3];
    // Use unsigned: shift-or above can produce negatives for >= 0x80000000.
    const lenU = len >>> 0;

    if (offset + 4 + lenU > buffer.length) {
      // Incomplete frame — keep from the start of this header onwards.
      break;
    }

    frames.push(buffer.subarray(offset + 4, offset + 4 + lenU));
    offset += 4 + lenU;
  }

  const remainder = buffer.subarray(offset);
  return { frames, remainder };
}

/**
 * Concatenate two `Uint8Array`s into a new buffer.
 */
export function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
