import { describe, it, expect } from 'vitest';
import { MoonbeamRelay } from '../src/moonbeam-relay';
import { MockWebSocket } from './helpers/mock-websocket';
import { MockWispServer } from './helpers/mock-wisp-server';
import { decodeContinue, encodeClose, encodeConnect, encodePacket, decodePacket } from '../src/wisp-frame';
import { PACKET_TYPE } from '../src/wisp-types';

const tick = () => new Promise((resolve) => setTimeout(resolve, 10));

async function waitFor(condition: () => boolean, timeoutMs = 1_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() >= deadline) throw new Error('timed out waiting for condition');
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
}

function collectPortPackets(port: MessagePort): { raw: unknown; packet: ReturnType<typeof decodePacket> }[] {
  const packets: { raw: unknown; packet: ReturnType<typeof decodePacket> }[] = [];
  port.addEventListener('message', (event) => {
    packets.push({ raw: event.data, packet: decodePacket(new Uint8Array(event.data)) });
  });
  port.start();
  return packets;
}

function createStreamCreditSender(
  port: MessagePort,
  streamId: number,
  frameCount: number,
): {
  readonly handshakeValues: number[];
  readonly values: number[];
  readonly rawValues: unknown[];
  sent(): number;
  completed: Promise<void>;
} {
  let available = 0;
  let sent = 0;
  let resolveCompleted!: () => void;
  const values: number[] = [];
  const handshakeValues: number[] = [];
  const rawValues: unknown[] = [];
  const dataPacket = encodePacket(PACKET_TYPE.DATA, streamId, new Uint8Array([1]));
  const completed = new Promise<void>((resolve) => {
    resolveCompleted = resolve;
  });
  const pump = () => {
    while (available > 0 && sent < frameCount) {
      available--;
      sent++;
      port.postMessage(dataPacket);
    }
    if (sent === frameCount) resolveCompleted();
  };
  const onMessage = (event: MessageEvent) => {
    const packet = decodePacket(new Uint8Array(event.data));
    if (packet?.type !== PACKET_TYPE.CONTINUE) return;
    const absolute = decodeContinue(packet.payload);
    if (absolute === null) return;
    if (packet.streamId === 0) {
      handshakeValues.push(absolute);
      return;
    }
    if (packet.streamId !== streamId) return;
    values.push(absolute);
    rawValues.push(event.data);
    available = absolute;
    pump();
  };
  port.addEventListener('message', onMessage);
  port.start();
  return { handshakeValues, values, rawValues, sent: () => sent, completed };
}

async function createRelayWithHandshake(upstreamInitialCredit = 256): Promise<{
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
  server.sendHandshakeContinue(upstreamInitialCredit);

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

  it('delivers the handshake packet as an ArrayBuffer', async () => {
    const { relay } = await createRelayWithHandshake();
    const port = relay.attach();
    const packets = collectPortPackets(port);

    await tick();

    expect(packets[0].raw).toBeInstanceOf(ArrayBuffer);
    expect(packets[0].packet?.type).toBe(PACKET_TYPE.CONTINUE);
    expect(packets[0].packet?.streamId).toBe(0);
    expect(decodeContinue(packets[0].packet!.payload)).toBe(0);
    await relay.close();
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

  it('delivers upstream DATA and CLOSE packets as ArrayBuffer', async () => {
    const { relay, server } = await createRelayWithHandshake();
    const port = relay.attach();
    const packets = collectPortPackets(port);
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, 52, encodeConnect('tcp', 80, 'example.com')));
    await tick();

    server.sendStreamContinue(1, 256);
    server.sendData(1, new TextEncoder().encode('body'));
    server.sendClose(1, 0x02);
    await tick();

    const streamPackets = packets.filter(
      ({ packet }) =>
        packet?.streamId === 52 &&
        (packet.type === PACKET_TYPE.DATA || packet.type === PACKET_TYPE.CLOSE),
    );
    expect(streamPackets.map(({ packet }) => packet?.type)).toEqual([
      PACKET_TYPE.DATA,
      PACKET_TYPE.CLOSE,
    ]);
    expect(streamPackets.every(({ raw }) => raw instanceof ArrayBuffer)).toBe(true);
    await relay.close();
  });

  it('mirrors post-drain upstream TCP credit without accepting beyond the advertised window', async () => {
    const { relay, server } = await createRelayWithHandshake();
    const port = relay.attach();
    const streamId = 53;
    const sender = createStreamCreditSender(port, streamId, 300);
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, streamId, encodeConnect('tcp', 80, 'example.com')));
    await waitFor(() => sender.values.length === 1);
    await waitFor(() => server.dataPackets(1).length === 256);

    expect(sender.values).toEqual([256]);
    expect(sender.sent()).toBe(256);
    expect(server.dataPackets(1)).toHaveLength(256);

    await tick();
    expect(sender.sent()).toBe(256);
    expect(server.dataPackets(1)).toHaveLength(256);

    server.sendStreamContinue(1, 10);
    await waitFor(() => sender.values.length === 2);
    await waitFor(() => server.dataPackets(1).length === 266);
    expect(sender.values).toEqual([256, 10]);
    expect(sender.sent()).toBe(266);
    expect(server.dataPackets(1)).toHaveLength(266);

    server.sendStreamContinue(1, 34);
    await sender.completed;
    await waitFor(() => server.dataPackets(1).length === 300);
    expect(sender.values).toEqual([256, 10, 34]);
    expect(sender.rawValues.every((raw) => raw instanceof ArrayBuffer)).toBe(true);
    expect(server.dataPackets(1)).toHaveLength(300);
    await relay.close();
  });

  it('cooperatively waits through zero handshake credit for actual upstream stream credit', async () => {
    const { relay, server } = await createRelayWithHandshake(7);
    const port = relay.attach();
    const streamId = 57;
    const sender = createStreamCreditSender(port, streamId, 10);
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, streamId, encodeConnect('tcp', 80, 'example.com')));

    await waitFor(() => sender.values.length === 1);
    await waitFor(() => server.dataPackets(1).length === 7);
    expect(sender.handshakeValues).toEqual([0]);
    expect(sender.values).toEqual([7]);
    expect(sender.sent()).toBe(7);
    expect(relay.streamCount()).toBe(1);

    server.sendStreamContinue(1, 3);
    await sender.completed;
    await waitFor(() => server.dataPackets(1).length === 10);
    expect(sender.values).toEqual([7, 3]);
    expect(server.closes()).toEqual([]);
    expect(relay.streamCount()).toBe(1);
    await relay.close();
  });

  it('never sends CONTINUE for upstream UDP streams', async () => {
    const { relay, server } = await createRelayWithHandshake();
    const port = relay.attach();
    const packets = collectPortPackets(port);
    const streamId = 54;
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, streamId, encodeConnect('udp', 53, '1.1.1.1')));
    await tick();
    port.postMessage(encodePacket(PACKET_TYPE.DATA, streamId, new Uint8Array([1])));
    await tick();

    expect(server.dataPackets(1)).toHaveLength(1);
    expect(
      packets.filter(
        ({ packet }) => packet?.type === PACKET_TYPE.CONTINUE && packet.streamId === streamId,
      ),
    ).toEqual([]);
    await relay.close();
  });

  it('closes upstream TCP when a malicious client exceeds its advertised window', async () => {
    const { relay, server } = await createRelayWithHandshake();
    const port = relay.attach();
    const packets = collectPortPackets(port);
    const streamId = 55;
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, streamId, encodeConnect('tcp', 80, 'example.com')));
    await tick();

    const dataPacket = encodePacket(PACKET_TYPE.DATA, streamId, new Uint8Array([1]));
    for (let i = 0; i < 257; i++) port.postMessage(dataPacket);
    await tick();

    expect(server.dataPackets(1)).toHaveLength(256);
    expect(server.closes()).toEqual([{ streamId: 1, reason: 0x41 }]);
    expect(relay.streamCount()).toBe(0);
    expect(relay.clientsSnapshot()[0].streams).toEqual([]);
    expect(
      packets.some(
        ({ packet }) => packet?.type === PACKET_TYPE.CLOSE && packet.streamId === streamId,
      ),
    ).toBe(true);
    await relay.close();
  });

  it('keeps upstream UDP creditless for more than a TCP-sized window', async () => {
    const { relay, server } = await createRelayWithHandshake();
    const port = relay.attach();
    const packets = collectPortPackets(port);
    const streamId = 56;
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, streamId, encodeConnect('udp', 53, '1.1.1.1')));
    await tick();

    const dataPacket = encodePacket(PACKET_TYPE.DATA, streamId, new Uint8Array([1]));
    for (let i = 0; i < 300; i++) port.postMessage(dataPacket);
    await tick();

    expect(server.dataPackets(1)).toHaveLength(300);
    expect(relay.streamCount()).toBe(1);
    expect(
      packets.filter(
        ({ packet }) => packet?.type === PACKET_TYPE.CONTINUE && packet.streamId === streamId,
      ),
    ).toEqual([]);
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

  it('finishes local and upstream cleanup when an onClose callback throws', async () => {
    const { relay, server } = await createRelayWithHandshake();
    let laterCallbackCount = 0;
    relay.registerListener('dusk.local', 8080, (socket) => {
      socket.onClose(() => {
        throw new Error('broken close callback');
      });
      socket.onClose(() => laterCallbackCount++);
    });
    const port = relay.attach();
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, 1, encodeConnect('tcp', 8080, 'dusk.local')));
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, 2, encodeConnect('tcp', 443, 'example.com')));
    await tick();

    expect(() => relay.detach(port)).not.toThrow();

    expect(laterCallbackCount).toBe(1);
    expect(relay.clientCount()).toBe(0);
    expect(relay.streamCount()).toBe(0);
    expect(relay.listenersSnapshot()[0].activeStreams).toBe(0);
    expect(server.closes()).toHaveLength(1);
    await relay.close();
  });

  it('is reentrancy-safe and releases a detached client IP exactly once', async () => {
    const { relay } = await createRelayWithHandshake();
    let port: MessagePort;
    relay.registerListener('dusk.local', 8080, (socket) => {
      socket.onClose(() => relay.detach(port));
    });
    port = relay.attach();
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, 1, encodeConnect('tcp', 8080, 'dusk.local')));
    await tick();

    relay.detach(port);
    const second = relay.attach();
    const third = relay.attach();
    const clients = relay.clientsSnapshot();

    expect(clients.map(({ id }) => id)).toEqual([2, 3]);
    expect(new Set(clients.map(({ virtualIp }) => virtualIp)).size).toBe(2);

    relay.detach(second);
    relay.detach(third);
    await relay.close();
  });
});

describe('MoonbeamRelay observability', () => {
  it('clientCount reflects attached clients', async () => {
    const { relay } = await createRelayWithHandshake();
    expect(relay.clientCount()).toBe(0);
    const p1 = relay.attach();
    expect(relay.clientCount()).toBe(1);
    const p2 = relay.attach();
    expect(relay.clientCount()).toBe(2);
    relay.detach(p1);
    expect(relay.clientCount()).toBe(1);
    relay.detach(p2);
    expect(relay.clientCount()).toBe(0);
    await relay.close();
  });

  it('assigns attachment metadata and returns fresh immutable snapshots', async () => {
    const { relay } = await createRelayWithHandshake();
    const before = Date.now();
    const nova = relay.attach({ label: 'Nova' });
    const dusk = relay.attach();

    const first = relay.clientsSnapshot();
    const second = relay.clientsSnapshot();

    expect(first).toEqual([
      {
        id: 1,
        virtualIp: '100.64.0.1',
        label: 'Nova',
        connectedAt: expect.any(Number),
        streams: [],
      },
      {
        id: 2,
        virtualIp: '100.64.0.2',
        label: 'client-2',
        connectedAt: expect.any(Number),
        streams: [],
      },
    ]);
    expect(first[0].connectedAt).toBeGreaterThanOrEqual(before);
    expect(first).not.toBe(second);
    expect(first[0]).not.toBe(second[0]);
    expect(first[0].streams).not.toBe(second[0].streams);
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first[0])).toBe(true);
    expect(Object.isFrozen(first[0].streams)).toBe(true);

    relay.detach(nova);
    expect(relay.clientsSnapshot().map((client) => client.id)).toEqual([2]);
    relay.detach(dusk);
    expect(relay.clientsSnapshot()).toEqual([]);
    await relay.close();
  });

  it('keeps client IDs monotonic while reusing released virtual IPs', async () => {
    const { relay } = await createRelayWithHandshake();
    const firstPort = relay.attach();
    const secondPort = relay.attach();
    const firstIp = relay.clientsSnapshot()[0].virtualIp;

    relay.detach(firstPort);
    const thirdPort = relay.attach();
    const clients = relay.clientsSnapshot();

    expect(clients.map(({ id }) => id)).toEqual([2, 3]);
    expect(clients.map(({ virtualIp }) => virtualIp)).toEqual(['100.64.0.2', firstIp]);
    expect(new Set(clients.map(({ virtualIp }) => virtualIp)).size).toBe(clients.length);

    relay.detach(secondPort);
    relay.detach(thirdPort);
    await relay.close();
  });

  it('rejects attachment when all 254 virtual IPs are active', async () => {
    const { relay } = await createRelayWithHandshake();
    for (let i = 0; i < 254; i++) relay.attach();

    const clients = relay.clientsSnapshot();
    expect(clients).toHaveLength(254);
    expect(new Set(clients.map(({ virtualIp }) => virtualIp)).size).toBe(254);
    expect(() => relay.attach()).toThrow(/virtual IP.*exhausted/i);
    expect(relay.clientCount()).toBe(254);

    await relay.close();
  });

  it('includes active upstream stream records in client snapshots', async () => {
    const { relay } = await createRelayWithHandshake();
    const port = relay.attach({ label: 'browser' });

    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, 41, encodeConnect('tcp', 443, 'example.com')));
    await tick();

    expect(relay.clientsSnapshot()[0].streams).toEqual([
      {
        id: 41,
        type: 'tcp',
        hostname: 'example.com',
        port: 443,
        local: false,
      },
    ]);

    relay.detach(port);
    await relay.close();
  });

  it('streamCount tracks open upstream streams', async () => {
    const { relay, server } = await createRelayWithHandshake();
    const port = relay.attach();
    expect(relay.streamCount()).toBe(0);

    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, 1, encodeConnect('tcp', 80, 'a.example')));
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, 2, encodeConnect('tcp', 80, 'b.example')));
    await new Promise((r) => setTimeout(r, 10));

    expect(relay.streamCount()).toBe(2);

    // Server closes stream ID 1 (upstream ID).
    server.sendClose(1, /* CloseReason.Voluntary */ 0x02);
    await new Promise((r) => setTimeout(r, 10));
    expect(relay.streamCount()).toBe(1);

    await relay.close();
  });

  it('isClosed flips after close()', async () => {
    const { relay } = await createRelayWithHandshake();
    expect(relay.isClosed()).toBe(false);
    await relay.close();
    expect(relay.isClosed()).toBe(true);
  });
});

describe('MoonbeamRelay local TCP listeners', () => {
  it('rejects duplicate host and port registrations', async () => {
    const { relay } = await createRelayWithHandshake();
    const dispose = relay.registerListener('dusk.local', 8080, () => {});

    expect(relay.listenerCount()).toBe(1);
    expect(relay.listenersSnapshot()).toEqual([
      { host: 'dusk.local', port: 8080, activeStreams: 0 },
    ]);
    expect(() => relay.registerListener('dusk.local', 8080, () => {})).toThrow(/already registered/i);

    dispose();
    expect(relay.listenerCount()).toBe(0);
    await relay.close();
  });

  it('intercepts matching TCP CONNECT and grants stream credit without using upstream', async () => {
    const { relay, server } = await createRelayWithHandshake();
    const sockets: unknown[] = [];
    relay.registerListener('dusk.local', 8080, (socket) => sockets.push(socket));
    const port = relay.attach();
    const packets = collectPortPackets(port);

    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, 17, encodeConnect('tcp', 8080, 'dusk.local')));
    await tick();

    expect(sockets).toHaveLength(1);
    expect(server.connects()).toHaveLength(0);
    const streamContinue = packets.find(
      ({ packet }) => packet?.type === PACKET_TYPE.CONTINUE && packet.streamId === 17,
    );
    expect(streamContinue).toBeDefined();
    expect(streamContinue?.raw).toBeInstanceOf(ArrayBuffer);
    expect(relay.clientsSnapshot()[0].streams).toEqual([
      {
        id: 17,
        type: 'tcp',
        hostname: 'dusk.local',
        port: 8080,
        local: true,
      },
    ]);

    await relay.close();
  });

  it('cooperatively waits through zero handshake credit for local stream credit', async () => {
    const { relay } = await createRelayWithHandshake();
    let received = 0;
    relay.registerListener('dusk.local', 8080, (socket) => {
      socket.onData(() => received++);
    });
    const port = relay.attach();
    const streamId = 18;
    const sender = createStreamCreditSender(port, streamId, 300);
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, streamId, encodeConnect('tcp', 8080, 'dusk.local')));

    await sender.completed;
    await waitFor(() => received === 300);
    expect(sender.handshakeValues).toEqual([0]);
    expect(sender.values).toEqual([256, 256]);
    expect(relay.streamCount()).toBe(1);
    expect(relay.clientsSnapshot()[0].streams[0].local).toBe(true);
    await relay.close();
  });

  it('routes DATA and CLOSE bidirectionally as ArrayBuffer payloads', async () => {
    const { relay } = await createRelayWithHandshake();
    let localSocket: Parameters<Parameters<MoonbeamRelay['registerListener']>[2]>[0] | undefined;
    const received: Uint8Array[] = [];
    const closeReasons: number[] = [];
    relay.registerListener('dusk.local', 8080, (socket) => {
      localSocket = socket;
      socket.onData((data) => received.push(data));
      socket.onClose((reason) => closeReasons.push(reason));
    });
    const port = relay.attach();
    const packets = collectPortPackets(port);
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, 23, encodeConnect('tcp', 8080, 'dusk.local')));
    await tick();

    port.postMessage(encodePacket(PACKET_TYPE.DATA, 23, new TextEncoder().encode('request')));
    await tick();
    expect(received.map((data) => new TextDecoder().decode(data))).toEqual(['request']);

    localSocket!.send(new TextEncoder().encode('response'));
    await tick();
    const response = packets.find(
      ({ packet }) => packet?.type === PACKET_TYPE.DATA && packet.streamId === 23,
    );
    expect(response?.raw).toBeInstanceOf(ArrayBuffer);
    expect(new TextDecoder().decode(response?.packet?.payload)).toBe('response');

    port.postMessage(encodePacket(PACKET_TYPE.CLOSE, 23, encodeClose(0x02)));
    await tick();
    expect(closeReasons).toEqual([0x02]);
    expect(relay.clientsSnapshot()[0].streams).toEqual([]);

    await relay.close();
  });

  it('replenishes local DATA credit only after each full 256-frame window is delivered', async () => {
    const { relay } = await createRelayWithHandshake();
    let received = 0;
    relay.registerListener('dusk.local', 8080, (socket) => {
      socket.onData(() => received++);
    });
    const port = relay.attach();
    const packets = collectPortPackets(port);
    const streamId = 230;
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, streamId, encodeConnect('tcp', 8080, 'dusk.local')));
    await tick();

    const continueValues = () =>
      packets
        .filter(
          ({ packet }) => packet?.type === PACKET_TYPE.CONTINUE && packet.streamId === streamId,
        )
        .map(({ packet }) => decodeContinue(packet!.payload));
    const dataPacket = encodePacket(PACKET_TYPE.DATA, streamId, new Uint8Array([1]));
    const sendGrantedFrames = (count: number) => {
      for (let i = 0; i < count; i++) port.postMessage(dataPacket);
    };

    expect(continueValues()).toEqual([256]);
    sendGrantedFrames(255);
    await tick();
    expect(received).toBe(255);
    expect(continueValues()).toEqual([256]);

    sendGrantedFrames(1);
    await waitFor(() => continueValues().length === 2);
    expect(received).toBe(256);
    expect(continueValues()).toEqual([256, 256]);

    sendGrantedFrames(256);
    await waitFor(() => continueValues().length === 3);
    expect(received).toBe(512);
    expect(continueValues()).toEqual([256, 256, 256]);

    sendGrantedFrames(8);
    await tick();
    expect(received).toBe(520);
    expect(continueValues()).toEqual([256, 256, 256]);
    expect(
      packets
        .filter(
          ({ packet }) => packet?.type === PACKET_TYPE.CONTINUE && packet.streamId === streamId,
        )
        .every(({ raw }) => raw instanceof ArrayBuffer),
    ).toBe(true);

    await relay.close();
  });

  it('closes a local TCP stream when a malicious client exceeds its advertised window', async () => {
    const { relay } = await createRelayWithHandshake();
    let received = 0;
    const closeReasons: number[] = [];
    relay.registerListener('dusk.local', 8080, (socket) => {
      socket.onData(() => received++);
      socket.onClose((reason) => closeReasons.push(reason));
    });
    const port = relay.attach();
    const packets = collectPortPackets(port);
    const streamId = 235;
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, streamId, encodeConnect('tcp', 8080, 'dusk.local')));
    await tick();

    const dataPacket = encodePacket(PACKET_TYPE.DATA, streamId, new Uint8Array([1]));
    for (let i = 0; i < 257; i++) port.postMessage(dataPacket);
    await tick();

    expect(received).toBe(256);
    expect(closeReasons).toEqual([0x41]);
    expect(relay.streamCount()).toBe(0);
    expect(relay.listenersSnapshot()[0].activeStreams).toBe(0);
    expect(relay.clientsSnapshot()[0].streams).toEqual([]);
    expect(
      packets.some(
        ({ packet }) => packet?.type === PACKET_TYPE.CLOSE && packet.streamId === streamId,
      ),
    ).toBe(true);
    await relay.close();
  });

  it('closes an existing local stream and ignores a duplicate CONNECT stream ID', async () => {
    const { relay, server } = await createRelayWithHandshake();
    let handlerCalls = 0;
    const closeReasons: number[] = [];
    relay.registerListener('dusk.local', 8080, (socket) => {
      handlerCalls++;
      socket.onClose((reason) => closeReasons.push(reason));
    });
    const port = relay.attach();
    const packets = collectPortPackets(port);
    const connect = encodePacket(PACKET_TYPE.CONNECT, 231, encodeConnect('tcp', 8080, 'dusk.local'));
    port.postMessage(connect);
    await tick();
    port.postMessage(connect);
    await tick();

    expect(handlerCalls).toBe(1);
    expect(closeReasons).toEqual([0x41]);
    expect(server.connects()).toHaveLength(0);
    expect(relay.streamCount()).toBe(0);
    expect(relay.listenersSnapshot()[0].activeStreams).toBe(0);
    expect(relay.clientsSnapshot()[0].streams).toEqual([]);
    expect(
      packets.some(
        ({ packet }) => packet?.type === PACKET_TYPE.CLOSE && packet.streamId === 231,
      ),
    ).toBe(true);
    await relay.close();
  });

  it('closes an existing upstream stream and ignores a duplicate CONNECT stream ID', async () => {
    const { relay, server } = await createRelayWithHandshake();
    const port = relay.attach();
    const packets = collectPortPackets(port);
    const first = encodePacket(PACKET_TYPE.CONNECT, 232, encodeConnect('tcp', 80, 'one.example'));
    const duplicate = encodePacket(PACKET_TYPE.CONNECT, 232, encodeConnect('tcp', 80, 'two.example'));
    port.postMessage(first);
    await tick();
    port.postMessage(duplicate);
    await tick();

    expect(server.connects()).toHaveLength(1);
    expect(server.closes()).toEqual([{ streamId: 1, reason: 0x41 }]);
    expect(relay.streamCount()).toBe(0);
    expect(relay.clientsSnapshot()[0].streams).toEqual([]);
    expect(
      packets.some(
        ({ packet }) => packet?.type === PACKET_TYPE.CLOSE && packet.streamId === 232,
      ),
    ).toBe(true);
    await relay.close();
  });

  it('isolates onData exceptions and finishes the dispatch snapshot after synchronous close', async () => {
    const { relay } = await createRelayWithHandshake();
    let laterCallbackCount = 0;
    relay.registerListener('dusk.local', 8080, (socket) => {
      socket.onData(() => {
        throw new Error('broken data callback');
      });
      socket.onData(() => socket.close(0x02));
      socket.onData(() => laterCallbackCount++);
    });
    const port = relay.attach();
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, 233, encodeConnect('tcp', 8080, 'dusk.local')));
    await tick();

    port.postMessage(encodePacket(PACKET_TYPE.DATA, 233, new Uint8Array([1])));
    await tick();

    expect(laterCallbackCount).toBe(1);
    expect(relay.streamCount()).toBe(0);
    expect(relay.listenersSnapshot()[0].activeStreams).toBe(0);
    expect(relay.clientsSnapshot()[0].streams).toEqual([]);
    await relay.close();
  });

  it('supports callback unsubscribe and harmless registration after local socket closure', async () => {
    const { relay } = await createRelayWithHandshake();
    let socket: Parameters<Parameters<MoonbeamRelay['registerListener']>[2]>[0] | undefined;
    let dataCalls = 0;
    relay.registerListener('dusk.local', 8080, (localSocket) => {
      socket = localSocket;
    });
    const port = relay.attach();
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, 234, encodeConnect('tcp', 8080, 'dusk.local')));
    await tick();

    const unsubscribeData = socket!.onData(() => dataCalls++);
    expect(unsubscribeData).toBeTypeOf('function');
    unsubscribeData();
    port.postMessage(encodePacket(PACKET_TYPE.DATA, 234, new Uint8Array([1])));
    await tick();
    expect(dataCalls).toBe(0);

    socket!.close(0x03);
    const lateCloseReasons: number[] = [];
    const unsubscribeClose = socket!.onClose((reason) => lateCloseReasons.push(reason));
    const unsubscribeLateData = socket!.onData(() => dataCalls++);
    expect(unsubscribeClose).toBeTypeOf('function');
    expect(unsubscribeLateData).toBeTypeOf('function');
    expect(lateCloseReasons).toEqual([0x03]);
    unsubscribeClose();
    unsubscribeLateData();

    await relay.close();
  });

  it('posts CONTINUE before a synchronous handler send', async () => {
    const { relay } = await createRelayWithHandshake();
    relay.registerListener('dusk.local', 8080, (socket) => {
      socket.send(new TextEncoder().encode('immediate'));
    });
    const port = relay.attach();
    const packets = collectPortPackets(port);

    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, 24, encodeConnect('tcp', 8080, 'dusk.local')));
    await tick();

    expect(
      packets
        .filter(({ packet }) => packet?.streamId === 24)
        .map(({ packet }) => packet?.type),
    ).toEqual([PACKET_TYPE.CONTINUE, PACKET_TYPE.DATA]);
    await relay.close();
  });

  it('posts CONTINUE before a synchronous handler close without stale credit', async () => {
    const { relay } = await createRelayWithHandshake();
    relay.registerListener('dusk.local', 8080, (socket) => socket.close(0x03));
    const port = relay.attach();
    const packets = collectPortPackets(port);

    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, 25, encodeConnect('tcp', 8080, 'dusk.local')));
    await tick();

    const streamPackets = packets.filter(({ packet }) => packet?.streamId === 25);
    expect(streamPackets.map(({ packet }) => packet?.type)).toEqual([
      PACKET_TYPE.CONTINUE,
      PACKET_TYPE.CLOSE,
    ]);
    expect(streamPackets.every(({ raw }) => raw instanceof ArrayBuffer)).toBe(true);
    expect(relay.clientsSnapshot()[0].streams).toEqual([]);
    await relay.close();
  });

  it('cleans local streams when their client detaches', async () => {
    const { relay } = await createRelayWithHandshake();
    const closeReasons: number[] = [];
    relay.registerListener('dusk.local', 8080, (socket) => {
      socket.onClose((reason) => closeReasons.push(reason));
    });
    const port = relay.attach();
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, 26, encodeConnect('tcp', 8080, 'dusk.local')));
    await tick();

    expect(relay.listenersSnapshot()[0].activeStreams).toBe(1);
    relay.detach(port);

    expect(closeReasons).toEqual([0x02]);
    expect(relay.clientCount()).toBe(0);
    expect(relay.streamCount()).toBe(0);
    expect(relay.listenersSnapshot()[0].activeStreams).toBe(0);
    await relay.close();
  });

  it('cleans local streams and listeners when the relay closes', async () => {
    const { relay } = await createRelayWithHandshake();
    const closeReasons: number[] = [];
    relay.registerListener('dusk.local', 8080, (socket) => {
      socket.onClose((reason) => closeReasons.push(reason));
    });
    const port = relay.attach();
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, 27, encodeConnect('tcp', 8080, 'dusk.local')));
    await tick();

    await relay.close();

    expect(closeReasons).toEqual([0x02]);
    expect(relay.clientCount()).toBe(0);
    expect(relay.streamCount()).toBe(0);
    expect(relay.listenerCount()).toBe(0);
    expect(relay.listenersSnapshot()).toEqual([]);
  });

  it('socket close emits Wisp CLOSE and listener disposal closes active streams', async () => {
    const { relay } = await createRelayWithHandshake();
    const sockets: Parameters<Parameters<MoonbeamRelay['registerListener']>[2]>[0][] = [];
    const closeReasons: number[] = [];
    const dispose = relay.registerListener('dusk.local', 8080, (socket) => {
      sockets.push(socket);
      socket.onClose((reason) => closeReasons.push(reason));
    });
    const port = relay.attach();
    const packets = collectPortPackets(port);
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, 31, encodeConnect('tcp', 8080, 'dusk.local')));
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, 32, encodeConnect('tcp', 8080, 'dusk.local')));
    await tick();

    sockets[0].close(0x03);
    await tick();
    expect(
      packets.some(
        ({ packet }) => packet?.type === PACKET_TYPE.CLOSE && packet.streamId === 31,
      ),
    ).toBe(true);

    dispose();
    await tick();
    expect(relay.listenerCount()).toBe(0);
    expect(closeReasons).toEqual([0x03, 0x02]);
    expect(
      packets.some(
        ({ packet }) => packet?.type === PACKET_TYPE.CLOSE && packet.streamId === 32,
      ),
    ).toBe(true);
    expect(relay.clientsSnapshot()[0].streams).toEqual([]);

    await relay.close();
  });

  it('listener disposal finishes all stream cleanup when an onClose callback throws', async () => {
    const { relay } = await createRelayWithHandshake();
    let connection = 0;
    let laterCallbackCount = 0;
    const dispose = relay.registerListener('dusk.local', 8080, (socket) => {
      if (connection++ === 0) {
        socket.onClose(() => {
          throw new Error('broken close callback');
        });
      } else {
        socket.onClose(() => laterCallbackCount++);
      }
    });
    const port = relay.attach();
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, 41, encodeConnect('tcp', 8080, 'dusk.local')));
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, 42, encodeConnect('tcp', 8080, 'dusk.local')));
    await tick();

    expect(() => dispose()).not.toThrow();

    expect(laterCallbackCount).toBe(1);
    expect(relay.listenerCount()).toBe(0);
    expect(relay.streamCount()).toBe(0);
    expect(relay.clientsSnapshot()[0].streams).toEqual([]);
    await relay.close();
  });

  it('relay close reaches every callback and closes upstream when an onClose callback throws', async () => {
    const { relay, ws } = await createRelayWithHandshake();
    let laterCallbackCount = 0;
    relay.registerListener('dusk.local', 8080, (socket) => {
      socket.onClose(() => {
        throw new Error('broken close callback');
      });
      socket.onClose(() => laterCallbackCount++);
    });
    const port = relay.attach();
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, 43, encodeConnect('tcp', 8080, 'dusk.local')));
    port.postMessage(encodePacket(PACKET_TYPE.CONNECT, 44, encodeConnect('tcp', 443, 'example.com')));
    await tick();

    await expect(relay.close()).resolves.toBeUndefined();

    expect(laterCallbackCount).toBe(1);
    expect(relay.clientCount()).toBe(0);
    expect(relay.streamCount()).toBe(0);
    expect(relay.listenerCount()).toBe(0);
    expect(ws.readyState).toBe(MockWebSocket.CLOSED);
  });
});
