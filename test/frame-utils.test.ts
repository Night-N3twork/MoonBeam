import { describe, test, expect } from 'vitest';
import { frameMessage, extractFrames, concat } from '../src/frame-utils';

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function makeFrame(values: number[]): Uint8Array {
  return new Uint8Array(values);
}

describe('frame-utils.concat', () => {
  test('concatenates two non-empty buffers', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([4, 5]);
    const out = concat(a, b);
    expect(out.length).toBe(5);
    expect(bytesEqual(out, new Uint8Array([1, 2, 3, 4, 5]))).toBe(true);
  });

  test('concatenates with empty left', () => {
    const out = concat(new Uint8Array(0), new Uint8Array([7, 8]));
    expect(bytesEqual(out, new Uint8Array([7, 8]))).toBe(true);
  });

  test('concatenates with empty right', () => {
    const out = concat(new Uint8Array([1, 2]), new Uint8Array(0));
    expect(bytesEqual(out, new Uint8Array([1, 2]))).toBe(true);
  });
});

describe('frame-utils.frameMessage', () => {
  test('prepends 4-byte big-endian length', () => {
    const frame = makeFrame([0xaa, 0xbb, 0xcc]);
    const out = frameMessage(frame);
    expect(out.length).toBe(7);
    // Length 3 in BE: 00 00 00 03
    expect(out[0]).toBe(0x00);
    expect(out[1]).toBe(0x00);
    expect(out[2]).toBe(0x00);
    expect(out[3]).toBe(0x03);
    expect(out[4]).toBe(0xaa);
    expect(out[5]).toBe(0xbb);
    expect(out[6]).toBe(0xcc);
  });

  test('handles zero-length frame', () => {
    const out = frameMessage(new Uint8Array(0));
    expect(out.length).toBe(4);
    expect(out[0]).toBe(0);
    expect(out[1]).toBe(0);
    expect(out[2]).toBe(0);
    expect(out[3]).toBe(0);
  });

  test('encodes lengths > 255 across all four bytes', () => {
    const frame = new Uint8Array(0x010203);
    const out = frameMessage(frame);
    expect(out[0]).toBe(0x00);
    expect(out[1]).toBe(0x01);
    expect(out[2]).toBe(0x02);
    expect(out[3]).toBe(0x03);
  });
});

describe('frame-utils.extractFrames', () => {
  test('round-trips a single frame', () => {
    const original = makeFrame([1, 2, 3, 4, 5]);
    const wire = frameMessage(original);
    const { frames, remainder } = extractFrames(wire);
    expect(frames.length).toBe(1);
    expect(bytesEqual(frames[0], original)).toBe(true);
    expect(remainder.length).toBe(0);
  });

  test('extracts two concatenated frames from one buffer', () => {
    const a = makeFrame([10, 20, 30]);
    const b = makeFrame([40, 50]);
    const wire = concat(frameMessage(a), frameMessage(b));
    const { frames, remainder } = extractFrames(wire);
    expect(frames.length).toBe(2);
    expect(bytesEqual(frames[0], a)).toBe(true);
    expect(bytesEqual(frames[1], b)).toBe(true);
    expect(remainder.length).toBe(0);
  });

  test('frame with length=0 (empty payload)', () => {
    const wire = frameMessage(new Uint8Array(0));
    const { frames, remainder } = extractFrames(wire);
    expect(frames.length).toBe(1);
    expect(frames[0].length).toBe(0);
    expect(remainder.length).toBe(0);
  });

  test('buffer shorter than 4 bytes returns 0 frames + full remainder', () => {
    const buf = new Uint8Array([0x00, 0x00, 0x01]);
    const { frames, remainder } = extractFrames(buf);
    expect(frames.length).toBe(0);
    expect(remainder.length).toBe(3);
    expect(bytesEqual(remainder, buf)).toBe(true);
  });

  test('buffer with length header but missing payload returns 0 frames + full remainder', () => {
    // Length = 5, but no payload bytes follow.
    const buf = new Uint8Array([0x00, 0x00, 0x00, 0x05]);
    const { frames, remainder } = extractFrames(buf);
    expect(frames.length).toBe(0);
    expect(remainder.length).toBe(4);
    expect(bytesEqual(remainder, buf)).toBe(true);
  });

  test('buffer with partial payload returns 0 frames + full remainder', () => {
    // Length = 5, only 2 payload bytes present.
    const buf = new Uint8Array([0x00, 0x00, 0x00, 0x05, 0x11, 0x22]);
    const { frames, remainder } = extractFrames(buf);
    expect(frames.length).toBe(0);
    expect(bytesEqual(remainder, buf)).toBe(true);
  });

  test('frame spanning two concat calls (leftover mechanism)', () => {
    // Caller-side leftover pattern: emulate two arrivals.
    const fullFrame = makeFrame([0xde, 0xad, 0xbe, 0xef]);
    const wire = frameMessage(fullFrame);
    // Split the wire arbitrarily — first chunk has the prefix + 1 byte; second chunk has the rest.
    const chunkA = wire.subarray(0, 5); // 4-byte prefix + 1 byte payload
    const chunkB = wire.subarray(5);

    let leftover = new Uint8Array(0);
    leftover = concat(leftover, chunkA);
    let res = extractFrames(leftover);
    expect(res.frames.length).toBe(0);
    leftover = res.remainder;
    expect(leftover.length).toBe(5);

    leftover = concat(leftover, chunkB);
    res = extractFrames(leftover);
    expect(res.frames.length).toBe(1);
    expect(bytesEqual(res.frames[0], fullFrame)).toBe(true);
    expect(res.remainder.length).toBe(0);
  });

  test('one complete frame followed by partial second frame', () => {
    const a = makeFrame([1, 2, 3]);
    const b = makeFrame([9, 9, 9, 9, 9]);
    const wireA = frameMessage(a);
    const wireB = frameMessage(b);
    // Take only a few bytes of wireB to leave it incomplete.
    const buf = concat(wireA, wireB.subarray(0, 5));
    const { frames, remainder } = extractFrames(buf);
    expect(frames.length).toBe(1);
    expect(bytesEqual(frames[0], a)).toBe(true);
    // Remainder is the 5 partial bytes of wireB (4-byte prefix + 1 payload byte).
    expect(remainder.length).toBe(5);
    expect(bytesEqual(remainder, wireB.subarray(0, 5))).toBe(true);
  });

  test('empty buffer returns no frames and empty remainder', () => {
    const { frames, remainder } = extractFrames(new Uint8Array(0));
    expect(frames.length).toBe(0);
    expect(remainder.length).toBe(0);
  });
});
