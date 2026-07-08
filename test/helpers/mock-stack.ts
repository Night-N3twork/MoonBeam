/**
 * Mock of the subset of `tcpip` (lwIP) NetworkStack used by Gateway.
 *
 * Only the methods Gateway calls are implemented:
 *   - createTunInterface({ ip })
 *   - createLoopbackInterface({ ip })
 *   - createTapInterface({ mac, ip })
 *   - openUdp({ port })
 *   - connectTcp({ host, port })
 *   - listenTcp({ port })
 *
 * Each returns a small object with the fields Gateway and its subsystems
 * touch (`readable`, `writable`, `ip`, `mac`, `close()` where applicable).
 * Streams are no-op pipes — bytes pushed in and never consumed; tests don't
 * exercise the data plane through this mock.
 *
 * Used by test/gateway.test.ts (and may be reused by future Gateway tests).
 */

export interface MockTunInterface {
  type: 'tun';
  ip: string;
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
}

export interface MockLoopbackInterface {
  type: 'loopback';
  ip: string;
}

export interface MockTapInterface {
  type: 'tap';
  mac: string;
  ip: string;
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
}

export interface MockUdpSocket {
  port?: number;
  readable: ReadableStream<{ host: string; port: number; data: Uint8Array }>;
  writable: WritableStream<{ host: string; port: number; data: Uint8Array }>;
  close(): Promise<void>;
}

export interface MockTcpConnection {
  host: string;
  port: number;
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  close(): Promise<void>;
}

export interface MockTcpListener {
  port: number;
  [Symbol.asyncIterator](): AsyncIterableIterator<MockTcpConnection>;
}

/**
 * Records the order in which interfaces are created so tests can verify
 * spec §2.4 LIFO ordering (Tun first, Loopback, then Tap).
 */
export class MockStack {
  readonly creationOrder: ('tun' | 'loopback' | 'tap')[] = [];
  readonly tunInterfaces: MockTunInterface[] = [];
  readonly loopbackInterfaces: MockLoopbackInterface[] = [];
  readonly tapInterfaces: MockTapInterface[] = [];
  readonly udpSockets: MockUdpSocket[] = [];
  readonly udpOpenCalls: ({ port?: number; host?: string } | undefined)[] = [];
  readonly tcpConnectCalls: { host: string; port: number }[] = [];
  readonly tcpListenCalls: { port: number; host?: string }[] = [];

  async createTunInterface(opts: { ip?: string }): Promise<MockTunInterface> {
    const iface: MockTunInterface = {
      type: 'tun',
      ip: opts.ip ?? '',
      readable: new ReadableStream<Uint8Array>(),
      writable: new WritableStream<Uint8Array>(),
    };
    this.tunInterfaces.push(iface);
    this.creationOrder.push('tun');
    return iface;
  }

  async createLoopbackInterface(opts: { ip?: string }): Promise<MockLoopbackInterface> {
    const iface: MockLoopbackInterface = { type: 'loopback', ip: opts.ip ?? '' };
    this.loopbackInterfaces.push(iface);
    this.creationOrder.push('loopback');
    return iface;
  }

  async createTapInterface(opts: { mac?: string; ip?: string }): Promise<MockTapInterface> {
    const iface: MockTapInterface = {
      type: 'tap',
      mac: opts.mac ?? '02:00:00:00:00:01',
      ip: opts.ip ?? '',
      readable: new ReadableStream<Uint8Array>(),
      writable: new WritableStream<Uint8Array>(),
    };
    this.tapInterfaces.push(iface);
    this.creationOrder.push('tap');
    return iface;
  }

  async openUdp(opts?: { port?: number; host?: string }): Promise<MockUdpSocket> {
    this.udpOpenCalls.push(opts);
    const sock: MockUdpSocket = {
      port: opts?.port,
      readable: new ReadableStream(),
      writable: new WritableStream(),
      close: async () => undefined,
    };
    this.udpSockets.push(sock);
    return sock;
  }

  async connectTcp(opts: { host: string; port: number }): Promise<MockTcpConnection> {
    this.tcpConnectCalls.push(opts);
    return {
      host: opts.host,
      port: opts.port,
      readable: new ReadableStream(),
      writable: new WritableStream(),
      close: async () => undefined,
    };
  }

  async listenTcp(opts: { port: number; host?: string }): Promise<MockTcpListener> {
    this.tcpListenCalls.push(opts);
    return {
      port: opts.port,
      async *[Symbol.asyncIterator]() {
        // Never yields in the mock; tests can override if needed.
      },
    };
  }
}
