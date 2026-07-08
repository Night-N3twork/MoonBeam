import { describe, test, expect, vi } from 'vitest';
import { makeGatewayHost, type TapInterface } from '../src/gateway-host';
import { frameMessage, extractFrames, concat } from '../src/frame-utils';

// ---------------------------------------------------------------------------
// MockTap — a TapInterface backed by manually-fed buffers.
// ---------------------------------------------------------------------------

interface MockTap extends TapInterface {
  /** Push a frame to be read by the host's pump (frames go OUT to the FakeWebSocket). */
  pushInbound(frame: Uint8Array): Promise<void>;
  /** Close the inbound side (simulates tap end-of-stream). */
  endInbound(): Promise<void>;
  /** All frames the host has written to tap.writable. */
  written: Uint8Array[];
}

function makeMockTap(): MockTap {
  const inboundQueue: Uint8Array[] = [];
  const inboundResolvers: Array<() => void> = [];
  let inboundClosed = false;
  let inboundController: ReadableStreamDefaultController<Uint8Array> | null = null;

  const readable = new ReadableStream<Uint8Array>({
    start(controller) {
      inboundController = controller;
    },
  });

  const written: Uint8Array[] = [];
  const writable = new WritableStream<Uint8Array>({
    write(chunk) {
      written.push(chunk);
    },
  });

  return {
    readable,
    writable,
    written,
    async pushInbound(frame: Uint8Array) {
      if (!inboundController) throw new Error('controller not ready');
      try {
        inboundController.enqueue(frame);
      } catch {
        // Stream was cancelled — treat as a no-op for the post-close test.
      }
      // Yield to let the pump's awaited read() resolve and run.
      await Promise.resolve();
      await Promise.resolve();
    },
    async endInbound() {
      if (inboundController && !inboundClosed) {
        inboundClosed = true;
        inboundController.close();
      }
      await Promise.resolve();
    },
  };
}

async function flush(): Promise<void> {
  for (let i = 0; i < 5; i++) await Promise.resolve();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('makeGatewayHost — onConnect / outbound (tap -> FakeWebSocket)', () => {
  test('frames from tap.readable are forwarded to send() with length prefix', async () => {
    const tap = makeMockTap();
    const host = makeGatewayHost(tap);
    const sends: Uint8Array[] = [];
    host.onConnect((frame) => sends.push(frame));

    const ethFrame = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]);
    await tap.pushInbound(ethFrame);
    await flush();

    expect(sends.length).toBe(1);
    const wire = sends[0];
    expect(wire.length).toBe(4 + ethFrame.length);
    // Length prefix BE = 4
    expect(wire[0]).toBe(0);
    expect(wire[1]).toBe(0);
    expect(wire[2]).toBe(0);
    expect(wire[3]).toBe(4);
    // Payload
    expect(wire[4]).toBe(0xaa);
    expect(wire[7]).toBe(0xdd);

    host.onClose();
  });

  test('multiple inbound frames each become separate send() calls', async () => {
    const tap = makeMockTap();
    const host = makeGatewayHost(tap);
    const sends: Uint8Array[] = [];
    host.onConnect((frame) => sends.push(frame));

    await tap.pushInbound(new Uint8Array([1, 2, 3]));
    await tap.pushInbound(new Uint8Array([9, 8]));
    await flush();

    expect(sends.length).toBe(2);
    expect(sends[0][3]).toBe(3); // length BE LSB
    expect(sends[1][3]).toBe(2);

    host.onClose();
  });
});

describe('makeGatewayHost — onSend / inbound (FakeWebSocket -> tap)', () => {
  test('single complete framed message is unwrapped and written to tap', async () => {
    const tap = makeMockTap();
    const host = makeGatewayHost(tap);
    host.onConnect(() => {});

    const original = new Uint8Array([0x11, 0x22, 0x33]);
    const wire = frameMessage(original);
    host.onSend(wire);
    await flush();

    expect(tap.written.length).toBe(1);
    expect(Array.from(tap.written[0])).toEqual([0x11, 0x22, 0x33]);

    host.onClose();
  });

  test('multiple concatenated frames in one onSend call', async () => {
    const tap = makeMockTap();
    const host = makeGatewayHost(tap);
    host.onConnect(() => {});

    const a = new Uint8Array([1, 1, 1]);
    const b = new Uint8Array([2, 2]);
    const c = new Uint8Array([3, 3, 3, 3]);
    const wire = concat(concat(frameMessage(a), frameMessage(b)), frameMessage(c));
    host.onSend(wire);
    await flush();

    expect(tap.written.length).toBe(3);
    expect(Array.from(tap.written[0])).toEqual([1, 1, 1]);
    expect(Array.from(tap.written[1])).toEqual([2, 2]);
    expect(Array.from(tap.written[2])).toEqual([3, 3, 3, 3]);

    host.onClose();
  });

  test('frame split across two onSend calls — leftover handled correctly', async () => {
    const tap = makeMockTap();
    const host = makeGatewayHost(tap);
    host.onConnect(() => {});

    const full = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const wire = frameMessage(full); // 8 bytes total: 4 header + 4 payload
    host.onSend(wire.subarray(0, 5)); // header + 1 payload byte
    await flush();
    expect(tap.written.length).toBe(0);

    host.onSend(wire.subarray(5)); // remaining 3 payload bytes
    await flush();
    expect(tap.written.length).toBe(1);
    expect(Array.from(tap.written[0])).toEqual([0xde, 0xad, 0xbe, 0xef]);

    host.onClose();
  });

  test('one complete frame followed by partial second frame across two calls', async () => {
    const tap = makeMockTap();
    const host = makeGatewayHost(tap);
    host.onConnect(() => {});

    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([3, 4, 5, 6]);
    const wireA = frameMessage(a);
    const wireB = frameMessage(b);

    // First call: complete A + first 3 bytes of B (header partial-ish)
    host.onSend(concat(wireA, wireB.subarray(0, 3)));
    await flush();
    expect(tap.written.length).toBe(1);
    expect(Array.from(tap.written[0])).toEqual([1, 2]);

    // Second call: rest of B's header + payload
    host.onSend(wireB.subarray(3));
    await flush();
    expect(tap.written.length).toBe(2);
    expect(Array.from(tap.written[1])).toEqual([3, 4, 5, 6]);

    host.onClose();
  });
});

describe('makeGatewayHost — onClose', () => {
  test('onClose stops the pump — subsequent inbound frames do not call send', async () => {
    const tap = makeMockTap();
    const host = makeGatewayHost(tap);
    const sends: Uint8Array[] = [];
    host.onConnect((f) => sends.push(f));

    await tap.pushInbound(new Uint8Array([1, 2, 3]));
    await flush();
    expect(sends.length).toBe(1);

    host.onClose();
    await flush();

    await tap.pushInbound(new Uint8Array([4, 5, 6]));
    await flush();

    // After close, no further sends should be observed.
    expect(sends.length).toBe(1);
  });

  test('onClose is idempotent', async () => {
    const tap = makeMockTap();
    const host = makeGatewayHost(tap);
    host.onConnect(() => {});
    host.onClose();
    expect(() => host.onClose()).not.toThrow();
  });

  test('inbound stream end (tap closes) does not break host', async () => {
    const tap = makeMockTap();
    const host = makeGatewayHost(tap);
    const sends: Uint8Array[] = [];
    host.onConnect((f) => sends.push(f));

    await tap.pushInbound(new Uint8Array([7]));
    await flush();
    expect(sends.length).toBe(1);

    await tap.endInbound();
    await flush();

    // Sending after the stream ends should still cleanly close.
    expect(() => host.onClose()).not.toThrow();
  });
});

describe('makeGatewayHost — leftover state is per-host instance', () => {
  test('two hosts maintain independent leftover buffers', async () => {
    const tapA = makeMockTap();
    const tapB = makeMockTap();
    const hostA = makeGatewayHost(tapA);
    const hostB = makeGatewayHost(tapB);
    hostA.onConnect(() => {});
    hostB.onConnect(() => {});

    const frameA = new Uint8Array([0xaa, 0xaa]);
    const frameB = new Uint8Array([0xbb, 0xbb]);
    const wireA = frameMessage(frameA);
    const wireB = frameMessage(frameB);

    hostA.onSend(wireA.subarray(0, 4)); // header only
    hostB.onSend(wireB); // complete
    await flush();

    expect(tapA.written.length).toBe(0); // A still buffering
    expect(tapB.written.length).toBe(1);
    expect(Array.from(tapB.written[0])).toEqual([0xbb, 0xbb]);

    hostA.onSend(wireA.subarray(4)); // rest of A
    await flush();
    expect(tapA.written.length).toBe(1);
    expect(Array.from(tapA.written[0])).toEqual([0xaa, 0xaa]);

    hostA.onClose();
    hostB.onClose();
  });
});
