import { describe, it, expect } from 'vitest';
import { MoonbeamRelay } from '../src/moonbeam-relay';
import { MockWebSocket } from './helpers/mock-websocket';
import { MockWispServer } from './helpers/mock-wisp-server';
import { encodeConnect, encodePacket, decodePacket } from '../src/wisp-frame';
import { PACKET_TYPE } from '../src/wisp-types';

async function createRelayWithHandshake(): Promise<{
  relay: MoonbeamRelay;
  ws: MockWebSocket;
  server: MockWispServer;
}> {
  const ws = new MockWebSocket();
  const server = new MockWispServer(ws);

  const relayPromise = MoonbeamRelay.create({
    wispUrl: 'wss://mock/',
    // @ts-expect-error test hook
    _injectWebSocket: ws,
  });

  ws.simulateOpen('wisp-v2');
  server.sendInfo({ udp: true });
  server.sendHandshakeContinue(256);

  const relay = await relayPromise;
  return { relay, ws, server };
}

describe('MoonbeamRelay', () => {
  it('exposes the create static factory', () => {
    expect(typeof MoonbeamRelay.create).toBe('function');
  });

  it('exposes instance methods attach, detach, close', () => {
    // Type-level check via a fake instance
    const proto = MoonbeamRelay.prototype;
    expect(typeof proto.attach).toBe('function');
    expect(typeof proto.detach).toBe('function');
    expect(typeof proto.close).toBe('function');
  });
});

describe('MoonbeamRelay.create', () => {
  it('resolves after the upstream wisp handshake completes', async () => {
    const ws = new MockWebSocket();
    const server = new MockWispServer(ws);

    const relayPromise = MoonbeamRelay.create({
      wispUrl: 'wss://mock/',
      // @ts-expect-error test hook
      _injectWebSocket: ws,
    });

    // Drive the wisp v2 handshake so upstream.ready() resolves.
    ws.simulateOpen('wisp-v2');
    server.sendInfo({ udp: true });
    server.sendHandshakeContinue(256);

    const relay = await relayPromise;
    expect(relay).toBeInstanceOf(MoonbeamRelay);
    await relay.close();
  });
});

describe('MoonbeamRelay.attach', () => {
  it('returns a MessagePort per call, distinct instances', async () => {
    const { relay } = await createRelayWithHandshake();

    const port1 = relay.attach();
    const port2 = relay.attach();

    expect(port1).toBeInstanceOf(MessagePort);
    expect(port2).toBeInstanceOf(MessagePort);
    expect(port1).not.toBe(port2);

    await relay.close();
  });

  it('throws after close()', async () => {
    const { relay } = await createRelayWithHandshake();
    await relay.close();

    expect(() => relay.attach()).toThrow(/closed/i);
  });
});

describe('MoonbeamRelay pass-through', () => {
  it('forwards a client CONNECT into a new upstream stream', async () => {
    const { relay, server } = await createRelayWithHandshake();

    const port = relay.attach();
    const clientStreamId = 1;
    const connectPayload = encodeConnect('tcp', 80, 'example.com');
    const packet = encodePacket(PACKET_TYPE.CONNECT, clientStreamId, connectPayload);

    port.postMessage(packet);

    // Give the event loop a tick to route the message.
    await new Promise((r) => setTimeout(r, 10));

    // The upstream should have observed one CONNECT for example.com:80.
    const connects = server.received.filter((r) => r.raw.type === PACKET_TYPE.CONNECT);
    expect(connects.length).toBe(1);
    const decoded = connects[0].decoded as { hostname: string; port: number };
    expect(decoded.hostname).toBe('example.com');
    expect(decoded.port).toBe(80);

    await relay.close();
  });
});

describe('MoonbeamRelay upstream → client', () => {
  it('returns upstream data with the client stream ID rewritten back', async () => {
    const { relay, server } = await createRelayWithHandshake();

    const port = relay.attach();
    const clientReceived: Uint8Array[] = [];
    port.addEventListener('message', (e) => {
      clientReceived.push(new Uint8Array(e.data));
    });
    port.start();

    const clientStreamId = 42;
    const connectPayload = encodeConnect('tcp', 80, 'example.com');
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, clientStreamId, connectPayload));

    // Let CONNECT propagate; the client will send CONNECT upstream (stream ID 1
    // from WispClient's allocator).
    await new Promise((r) => setTimeout(r, 10));

    // The upstream needs a CONTINUE (credit) before it can drive DATA on
    // the stream, then we push data down.
    server.sendStreamContinue(1);
    const responseData = new TextEncoder().encode('hello');
    server.sendData(1, responseData);

    await new Promise((r) => setTimeout(r, 10));

    // Find the DATA packet emitted to the client.
    const dataPackets = clientReceived
      .map((buf) => decodePacket(buf))
      .filter((p) => p && p.type === PACKET_TYPE.DATA);
    expect(dataPackets.length).toBeGreaterThanOrEqual(1);
    const dp = dataPackets[0]!;
    expect(dp.streamId).toBe(clientStreamId); // rewritten back to client's ID
    expect(new TextDecoder().decode(dp.payload)).toBe('hello');

    await relay.close();
  });
});

describe('MoonbeamRelay.detach', () => {
  it('closes streams and reclaims resources for the detached client', async () => {
    const { relay, server } = await createRelayWithHandshake();

    const port = relay.attach();
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, 1, encodeConnect('tcp', 80, 'a.example')));
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, 2, encodeConnect('tcp', 80, 'b.example')));

    await new Promise((r) => setTimeout(r, 10));

    // Two CONNECTs should have reached the upstream.
    const connectsBeforeDetach = server.received.filter((r) => r.raw.type === PACKET_TYPE.CONNECT).length;
    expect(connectsBeforeDetach).toBe(2);

    relay.detach(port);
    await new Promise((r) => setTimeout(r, 10));

    // After detach, the upstream should have received two CLOSE frames
    // (one per open stream that was reclaimed).
    const closesAfterDetach = server.received.filter((r) => r.raw.type === PACKET_TYPE.CLOSE).length;
    expect(closesAfterDetach).toBe(2);

    await relay.close();
  });
});
