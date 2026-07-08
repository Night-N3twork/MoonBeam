/**
 * Unit tests for WispClient using a paired MockWebSocket + MockWispServer.
 *
 * Covers handshake variants, packet handling table, stream lifecycle,
 * backpressure, and error paths. Wire-format conformance for individual
 * packet types lives in wisp-frame.test.ts; here we focus on protocol
 * behavior of the client state machine.
 */

import { describe, test, expect, vi, beforeEach } from 'vitest';
import {
  WispClient,
  E_WISP_HANDSHAKE,
  E_WISP_V1_UNSUPPORTED,
  E_WISP_AUTH_REQUIRED,
  E_WISP_UDP_UNSUPPORTED,
} from '../src/wisp-client';
import { PACKET_TYPE, EXTENSION_ID, CLOSE_REASON } from '../src/wisp-types';
import { encodeContinue, encodePacket } from '../src/wisp-frame';
import { MockWebSocket } from './helpers/mock-websocket';
import { MockWispServer } from './helpers/mock-wisp-server';

interface Pair {
  ws: MockWebSocket;
  srv: MockWispServer;
  client: WispClient;
}

function makePair(opts: { config?: Partial<Parameters<typeof WispClient>[0]> } = {}): Pair {
  const ws = new MockWebSocket();
  const srv = new MockWispServer(ws);
  const client = new WispClient({
    url: 'ws://test/',
    _injectWebSocket: ws,
    handshakeTimeoutMs: 500,
    ...opts.config,
  });
  return { ws, srv, client };
}

/** Run the full happy-path handshake. */
async function doHandshake(
  pair: Pair,
  options: Parameters<MockWispServer['sendInfo']>[0] = {},
  bufferSize = 256,
): Promise<void> {
  pair.ws.simulateOpen('wisp-v2');
  pair.srv.sendInfo(options);
  // Microtask boundary so client processes INFO and sends its own.
  await Promise.resolve();
  pair.srv.sendHandshakeContinue(bufferSize);
  await pair.client.ready();
}

// ---------------------------------------------------------------------------
// Handshake — happy paths
// ---------------------------------------------------------------------------

describe('WispClient handshake — happy path', () => {
  test('completes handshake when server sends INFO then CONTINUE', async () => {
    const pair = makePair();
    pair.ws.simulateOpen('wisp-v2');
    pair.srv.sendInfo({ udp: true, motd: 'hello world' });
    // Wait a tick for the client to react and send its INFO.
    await Promise.resolve();
    // After the client's INFO is processed, the server sends CONTINUE.
    pair.srv.sendHandshakeContinue(256);
    await expect(pair.client.ready()).resolves.toBeUndefined();
    expect(pair.client.connected).toBe(true);
    expect(pair.client.udpSupported).toBe(true);
    expect(pair.client.motd).toBe('hello world');
  });

  test('records confirmStreamOpen when both sides advertise extension 0x05', async () => {
    const pair = makePair();
    await doHandshake(pair, { streamOpenConfirmation: true });
    expect(pair.client.confirmStreamOpen).toBe(true);
  });

  test('confirmStreamOpen false when server omits extension 0x05', async () => {
    const pair = makePair();
    await doHandshake(pair, { udp: true });
    expect(pair.client.confirmStreamOpen).toBe(false);
  });

  test('udpSupported false when server omits extension 0x01', async () => {
    const pair = makePair();
    await doHandshake(pair, {});
    expect(pair.client.udpSupported).toBe(false);
  });

  test('motd is null when server omits extension 0x04', async () => {
    const pair = makePair();
    await doHandshake(pair, { udp: true });
    expect(pair.client.motd).toBeNull();
  });

  test('motd handles multi-byte UTF-8', async () => {
    const pair = makePair();
    await doHandshake(pair, { motd: 'héllo 🌎' });
    expect(pair.client.motd).toBe('héllo 🌎');
  });

  test('client sends INFO advertising UDP + StreamOpenConfirmation', async () => {
    const pair = makePair();
    await doHandshake(pair, { udp: true, streamOpenConfirmation: true });
    const clientInfo = pair.srv.lastClientInfo();
    expect(clientInfo).not.toBeNull();
    expect(clientInfo!.major).toBe(2);
    expect(clientInfo!.minor).toBe(1);
    const extIds = clientInfo!.extensions.map((e) => e.id).sort();
    expect(extIds).toEqual(
      [EXTENSION_ID.UDP, EXTENSION_ID.STREAM_OPEN_CONFIRMATION].sort(),
    );
  });

  test('ignores unknown extension IDs from server (forward-compat)', async () => {
    const pair = makePair();
    pair.ws.simulateOpen('wisp-v2');
    pair.srv.sendInfo({
      udp: true,
      extraExtensions: [{ id: 0xfe, metadata: new Uint8Array([1, 2, 3]) }],
    });
    await Promise.resolve();
    pair.srv.sendHandshakeContinue(256);
    await expect(pair.client.ready()).resolves.toBeUndefined();
    expect(pair.client.udpSupported).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Handshake — failure paths
// ---------------------------------------------------------------------------

describe('WispClient handshake — failures', () => {
  test('rejects with E_WISP_V1_UNSUPPORTED when first packet is CONTINUE and allowV1: false', async () => {
    // Default is allowV1: true (v1 is the de-facto standard); we
    // explicitly opt out to v2-strict to test the rejection path.
    const pair = makePair({ config: { allowV1: false } });
    pair.ws.simulateOpen();
    pair.srv.sendHandshakeContinue(256);
    await expect(pair.client.ready()).rejects.toThrow(/E_WISP_V1_UNSUPPORTED/);
  });

  test('error message hints at allowV1 when server is v1 and allowV1: false', async () => {
    const pair = makePair({ config: { allowV1: false } });
    pair.ws.simulateOpen();
    pair.srv.sendHandshakeContinue(256);
    await expect(pair.client.ready()).rejects.toThrow(/allowV1/);
  });

  test('rejects with E_WISP_HANDSHAKE when server CLOSE on stream 0', async () => {
    const pair = makePair();
    pair.ws.simulateOpen();
    pair.srv.sendInfo({ udp: true });
    await Promise.resolve();
    pair.srv.sendClose(0, CLOSE_REASON.INCOMPATIBLE_EXTENSIONS);
    await expect(pair.client.ready()).rejects.toThrow(/E_WISP_HANDSHAKE/);
  });

  test('rejects with E_WISP_AUTH_REQUIRED when server requires password auth and no creds', async () => {
    const pair = makePair();
    pair.ws.simulateOpen();
    pair.srv.sendInfo({ udp: true, passwordAuth: { required: true } });
    await expect(pair.client.ready()).rejects.toThrow(/E_WISP_AUTH_REQUIRED/);
    // Client must have sent CLOSE 0xc2 on stream 0 before closing.
    const closes = pair.srv.closes();
    const authCloses = closes.filter(
      (c) => c.streamId === 0 && c.reason === CLOSE_REASON.AUTH_REQUIRED,
    );
    expect(authCloses.length).toBe(1);
  });

  test('rejects with E_WISP_AUTH_REQUIRED when server requires pubkey auth and no creds', async () => {
    const pair = makePair();
    pair.ws.simulateOpen();
    pair.srv.sendInfo({ udp: true, pubkeyAuth: { required: true } });
    await expect(pair.client.ready()).rejects.toThrow(/E_WISP_AUTH_REQUIRED/);
  });

  test('does NOT reject when auth is advertised but not required', async () => {
    const pair = makePair();
    pair.ws.simulateOpen();
    pair.srv.sendInfo({ udp: true, passwordAuth: { required: false } });
    await Promise.resolve();
    pair.srv.sendHandshakeContinue(256);
    await expect(pair.client.ready()).resolves.toBeUndefined();
  });

  test('handshake timeout rejects with E_WISP_HANDSHAKE', async () => {
    const pair = makePair({ config: { handshakeTimeoutMs: 30 } });
    pair.ws.simulateOpen();
    // Server never sends INFO.
    await expect(pair.client.ready()).rejects.toThrow(/E_WISP_HANDSHAKE/);
  });

  test('malformed server INFO rejects handshake', async () => {
    const pair = makePair();
    pair.ws.simulateOpen();
    // Empty INFO payload (no version bytes) — malformed.
    pair.ws.simulateMessage(encodePacket(PACKET_TYPE.INFO, 0, new Uint8Array(0)));
    await expect(pair.client.ready()).rejects.toThrow(/E_WISP_HANDSHAKE/);
  });
});

// ---------------------------------------------------------------------------
// Wisp v1 compatibility (opt-in via config.allowV1)
// ---------------------------------------------------------------------------

describe('WispClient — Wisp v1 compatibility', () => {
  test('accepts v1 server when allowV1: true', async () => {
    const pair = makePair({ config: { allowV1: true } });
    pair.ws.simulateOpen();
    pair.srv.sendHandshakeContinue(128);
    await expect(pair.client.ready()).resolves.toBeUndefined();
    expect(pair.client.isV1).toBe(true);
    expect(pair.client.udpSupported).toBe(true); // default udpAssumedInV1
    expect(pair.client.confirmStreamOpen).toBe(false);
    expect(pair.client.motd).toBe(null);
  });

  test('v1 with udpAssumedInV1: false reports udpSupported=false', async () => {
    const pair = makePair({ config: { allowV1: true, udpAssumedInV1: false } });
    pair.ws.simulateOpen();
    pair.srv.sendHandshakeContinue(128);
    await pair.client.ready();
    expect(pair.client.isV1).toBe(true);
    expect(pair.client.udpSupported).toBe(false);
  });

  test('v1 does not send client INFO during handshake', async () => {
    const pair = makePair({ config: { allowV1: true } });
    pair.ws.simulateOpen();
    pair.srv.sendHandshakeContinue(128);
    await pair.client.ready();
    // No INFO should have been sent by the client (server doesn't expect one).
    expect(pair.srv.lastClientInfo()).toBe(null);
  });

  test('v1 createStream produces same CONNECT format as v2', async () => {
    const pair = makePair({ config: { allowV1: true } });
    pair.ws.simulateOpen();
    pair.srv.sendHandshakeContinue(128);
    await pair.client.ready();
    pair.client.createStream('example.com', 80, 'tcp');
    const connects = pair.srv.connects();
    expect(connects.length).toBe(1);
    expect(connects[0]!.payload.hostname).toBe('example.com');
    expect(connects[0]!.payload.port).toBe(80);
    expect(connects[0]!.payload.streamType).toBe('tcp');
  });

  test('v1 + allowV1 still rejects malformed CONTINUE', async () => {
    const pair = makePair({ config: { allowV1: true, handshakeTimeoutMs: 200 } });
    pair.ws.simulateOpen();
    // Send a CONTINUE with wrong payload length
    pair.srv.sendRaw(Buffer.from([0x03, 0, 0, 0, 0, 0x80])); // missing 3 bytes
    await expect(pair.client.ready()).rejects.toThrow(/E_WISP_HANDSHAKE/);
  });

  test('after a v2 handshake, isV1 stays false regardless of allowV1 default', async () => {
    // Default allowV1 is now true, but isV1 reflects what the SERVER spoke,
    // not the client's policy. A v2 server keeps isV1 false.
    const pair = makePair();
    await doHandshake(pair, { udp: true });
    expect(pair.client.isV1).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Stream creation
// ---------------------------------------------------------------------------

describe('createStream — TCP without confirmStreamOpen', () => {
  test('produces correct CONNECT packet on wire (spec vector)', async () => {
    const pair = makePair();
    await doHandshake(pair, { udp: true });
    pair.client.createStream('example.com', 443, 'tcp');
    const connects = pair.srv.connects();
    expect(connects.length).toBe(1);
    expect(connects[0].payload.streamType).toBe('tcp');
    expect(connects[0].payload.port).toBe(443);
    expect(connects[0].payload.hostname).toBe('example.com');
  });

  test('allocates monotonic stream IDs starting at 1', async () => {
    const pair = makePair();
    await doHandshake(pair);
    const s1 = pair.client.createStream('a.example.com', 80, 'tcp');
    const s2 = pair.client.createStream('b.example.com', 80, 'tcp');
    const s3 = pair.client.createStream('c.example.com', 80, 'tcp');
    expect(s1.id).toBe(1);
    expect(s2.id).toBe(2);
    expect(s3.id).toBe(3);
  });

  test("fires 'open' optimistically when confirmStreamOpen is false", async () => {
    const pair = makePair();
    await doHandshake(pair, { udp: true });
    const stream = pair.client.createStream('example.com', 80, 'tcp');
    const opened = await new Promise<boolean>((resolve) => {
      stream.on('open', () => resolve(true));
      setTimeout(() => resolve(false), 100);
    });
    expect(opened).toBe(true);
  });
});

describe('createStream — TCP with confirmStreamOpen', () => {
  test("does NOT fire 'open' until CONTINUE arrives", async () => {
    const pair = makePair();
    await doHandshake(pair, { udp: true, streamOpenConfirmation: true });
    const stream = pair.client.createStream('example.com', 80, 'tcp');
    let openedEarly = false;
    stream.on('open', () => {
      openedEarly = true;
    });
    // Give microtasks a chance to flush.
    await Promise.resolve();
    await Promise.resolve();
    expect(openedEarly).toBe(false);
    // Now CONTINUE → open fires.
    pair.srv.sendStreamContinue(stream.id, 10);
    expect(openedEarly).toBe(true);
  });
});

describe('createStream — UDP', () => {
  test('throws when server did not advertise UDP', async () => {
    const pair = makePair();
    await doHandshake(pair, {});
    expect(() => pair.client.createStream('1.1.1.1', 53, 'udp')).toThrow(
      /E_WISP_UDP_UNSUPPORTED/,
    );
  });

  test('produces CONNECT with stream type 0x02', async () => {
    const pair = makePair();
    await doHandshake(pair, { udp: true });
    pair.client.createStream('1.1.1.1', 53, 'udp');
    const connects = pair.srv.connects();
    expect(connects[0].payload.streamType).toBe('udp');
    expect(connects[0].payload.port).toBe(53);
  });

  test("UDP stream fires 'open' immediately even with confirmStreamOpen", async () => {
    const pair = makePair();
    await doHandshake(pair, { udp: true, streamOpenConfirmation: true });
    const stream = pair.client.createStream('1.1.1.1', 53, 'udp');
    const opened = await new Promise<boolean>((resolve) => {
      stream.on('open', () => resolve(true));
      setTimeout(() => resolve(false), 50);
    });
    expect(opened).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Data flow
// ---------------------------------------------------------------------------

describe('data flow', () => {
  test('server DATA enqueues to readable AND fires data event with same bytes', async () => {
    const pair = makePair();
    await doHandshake(pair, { udp: true });
    const stream = pair.client.createStream('example.com', 80, 'tcp');
    await Promise.resolve(); // let optimistic 'open' microtask fire

    const dataPromise = new Promise<Uint8Array>((resolve) => {
      stream.on('data', (chunk: Uint8Array) => resolve(chunk));
    });
    const reader = stream.readable.getReader();

    pair.srv.sendData(stream.id, new Uint8Array([1, 2, 3, 4]));

    const eventBytes = await dataPromise;
    const readResult = await reader.read();
    expect(Array.from(eventBytes)).toEqual([1, 2, 3, 4]);
    expect(readResult.done).toBe(false);
    expect(Array.from(readResult.value!)).toEqual([1, 2, 3, 4]);
  });

  test('stream.send produces DATA packet on the wire', async () => {
    const pair = makePair();
    await doHandshake(pair, { udp: true });
    const stream = pair.client.createStream('example.com', 80, 'tcp');
    stream.send(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
    const data = pair.srv.dataPackets(stream.id);
    expect(data.length).toBe(1);
    expect(Array.from(data[0])).toEqual([0xde, 0xad, 0xbe, 0xef]);
  });
});

// ---------------------------------------------------------------------------
// Stream close
// ---------------------------------------------------------------------------

describe('stream close', () => {
  test('server CLOSE resolves stream.closed with reason and closes readable', async () => {
    const pair = makePair();
    await doHandshake(pair, { udp: true });
    const stream = pair.client.createStream('example.com', 80, 'tcp');
    pair.srv.sendClose(stream.id, CLOSE_REASON.STREAM_REFUSED);
    const info = await stream.closed;
    expect(info.reason).toBe(CLOSE_REASON.STREAM_REFUSED);
    const reader = stream.readable.getReader();
    const r = await reader.read();
    expect(r.done).toBe(true);
  });

  test('send after server CLOSE throws', async () => {
    const pair = makePair();
    await doHandshake(pair, { udp: true });
    const stream = pair.client.createStream('example.com', 80, 'tcp');
    pair.srv.sendClose(stream.id, CLOSE_REASON.VOLUNTARY);
    await stream.closed;
    expect(() => stream.send(new Uint8Array([1]))).toThrow();
  });

  test('local close sends CLOSE packet with given reason', async () => {
    const pair = makePair();
    await doHandshake(pair, { udp: true });
    const stream = pair.client.createStream('example.com', 80, 'tcp');
    stream.close(CLOSE_REASON.CLIENT_ERROR);
    const closes = pair.srv.closes().filter((c) => c.streamId === stream.id);
    expect(closes.length).toBe(1);
    expect(closes[0].reason).toBe(CLOSE_REASON.CLIENT_ERROR);
  });
});

// ---------------------------------------------------------------------------
// Backpressure
// ---------------------------------------------------------------------------

describe('backpressure', () => {
  test('queues sends when credits exhausted; drains on CONTINUE', async () => {
    const pair = makePair();
    // handshake CONTINUE provides bufferSize=2 → per-stream credit starts at 2.
    await doHandshake(pair, { udp: true }, 2);
    const stream = pair.client.createStream('example.com', 80, 'tcp');
    stream.send(new Uint8Array([0x01]));
    stream.send(new Uint8Array([0x02]));
    stream.send(new Uint8Array([0x03])); // queued
    let data = pair.srv.dataPackets(stream.id);
    expect(data.length).toBe(2);
    expect(Array.from(data[0])).toEqual([0x01]);
    expect(Array.from(data[1])).toEqual([0x02]);

    // Server grants more credit → queued chunk goes out.
    pair.srv.sendStreamContinue(stream.id, 2);
    data = pair.srv.dataPackets(stream.id);
    expect(data.length).toBe(3);
    expect(Array.from(data[2])).toEqual([0x03]);
  });

  test('UDP streams skip credit accounting entirely', async () => {
    const pair = makePair();
    await doHandshake(pair, { udp: true }, 1);
    const stream = pair.client.createStream('1.1.1.1', 53, 'udp');
    // Send 5 packets; all should go through (no credits).
    for (let i = 0; i < 5; i++) {
      stream.send(new Uint8Array([i]));
    }
    expect(pair.srv.dataPackets(stream.id).length).toBe(5);
  });
});

// ---------------------------------------------------------------------------
// Connection-level packet edge cases
// ---------------------------------------------------------------------------

describe('connection-level packet edge cases', () => {
  test('DATA on stream 0 is logged and ignored (no crash)', async () => {
    const pair = makePair();
    await doHandshake(pair, { udp: true });
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    // Server sends DATA on stream 0.
    pair.ws.simulateMessage(encodePacket(PACKET_TYPE.DATA, 0, new Uint8Array([1, 2, 3])));
    // No throw; warning emitted.
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });

  test('CLOSE on stream 0 closes all streams with NETWORK_ERROR and emits close', async () => {
    const pair = makePair();
    await doHandshake(pair, { udp: true });
    const s1 = pair.client.createStream('a.example.com', 80, 'tcp');
    const s2 = pair.client.createStream('b.example.com', 80, 'tcp');
    let clientClosed = false;
    pair.client.on('close', () => {
      clientClosed = true;
    });
    pair.srv.sendClose(0, CLOSE_REASON.NETWORK_ERROR);
    const r1 = await s1.closed;
    const r2 = await s2.closed;
    expect(r1.reason).toBe(CLOSE_REASON.NETWORK_ERROR);
    expect(r2.reason).toBe(CLOSE_REASON.NETWORK_ERROR);
    expect(clientClosed).toBe(true);
  });

  test('WebSocket simulateClose closes all streams', async () => {
    const pair = makePair();
    await doHandshake(pair, { udp: true });
    const s1 = pair.client.createStream('example.com', 80, 'tcp');
    pair.ws.simulateClose(1006, 'abnormal', false);
    const r = await s1.closed;
    expect(r.reason).toBe(CLOSE_REASON.NETWORK_ERROR);
  });

  test('CONTINUE on UDP stream is logged and ignored', async () => {
    const pair = makePair();
    await doHandshake(pair, { udp: true });
    const stream = pair.client.createStream('1.1.1.1', 53, 'udp');
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    pair.srv.sendStreamContinue(stream.id, 10);
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });

  test('DATA on unknown stream id is silently dropped', async () => {
    const pair = makePair();
    await doHandshake(pair, { udp: true });
    // No streams created; server sends DATA on stream 99.
    pair.ws.simulateMessage(encodePacket(PACKET_TYPE.DATA, 99, new Uint8Array([1])));
    // Should not throw.
    expect(pair.client.connected).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Client close
// ---------------------------------------------------------------------------

describe('client.close()', () => {
  test('closes all streams and emits close event', async () => {
    const pair = makePair();
    await doHandshake(pair, { udp: true });
    const s1 = pair.client.createStream('a.example.com', 80, 'tcp');
    let closed = false;
    pair.client.on('close', () => {
      closed = true;
    });
    pair.client.close();
    const info = await s1.closed;
    expect(info.reason).toBe(CLOSE_REASON.NETWORK_ERROR);
    expect(closed).toBe(true);
    expect(pair.client.connected).toBe(false);
  });
});
