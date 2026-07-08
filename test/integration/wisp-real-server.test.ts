/**
 * Real-server integration test for WispClient.
 *
 * Spins up an in-process @mercuryworkshop/wisp-js server, points a real
 * WispClient at it (using Node 22's built-in WebSocket), opens a TCP stream
 * to a public HTTP target, and verifies the response looks like HTTP.
 *
 * This is the only test that exercises actual wire-format interop. If
 * everything else passes but this fails, our spec interpretation is
 * probably off somewhere.
 *
 * Failure modes worth reporting (per task brief):
 *   - Handshake never completes.
 *   - CONNECT is rejected by server.
 *   - DATA is sent but no reply.
 *   - DNS / outbound network unreachable from this machine.
 */

import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import { server as wisp } from '@mercuryworkshop/wisp-js/server';
import { WispClient } from '../../src/wisp-client';

let httpServer: http.Server;
let serverUrl: string;

beforeAll(async () => {
  // Allow loopback so the server will let us reach 1.1.1.1 / public hosts.
  // We don't actually need loopback for outbound — we need the *destination*
  // permission, not the *bind* permission. Defaults already allow public IPs.
  // We do enable allow_loopback_ips because tests sometimes use 127.0.0.1.
  wisp.options.allow_loopback_ips = true;

  httpServer = http.createServer();
  httpServer.on('upgrade', (req, sock, head) => {
    wisp.routeRequest(req, sock as any, head);
  });
  await new Promise<void>((resolve) => {
    httpServer.listen(0, '127.0.0.1', () => resolve());
  });
  const addr = httpServer.address();
  if (!addr || typeof addr === 'string') {
    throw new Error('Could not bind test wisp server');
  }
  serverUrl = `ws://127.0.0.1:${addr.port}/`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => httpServer.close(() => resolve()));
});

/**
 * Read at least `min` bytes (or until close) from a Wisp stream's data
 * events. Returns the concatenation. We use the event API (not the
 * ReadableStream) here to mirror how the NAT layer will consume.
 */
function readUntil(
  stream: { on: (e: string, l: (...args: any[]) => void) => void },
  options: { minBytes: number; timeoutMs: number },
): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const chunks: Uint8Array[] = [];
    let total = 0;
    let done = false;
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      if (total >= options.minBytes) finish();
      else reject(new Error(`timeout reading: got ${total} bytes (needed ${options.minBytes})`));
    }, options.timeoutMs);

    const finish = () => {
      done = true;
      clearTimeout(timer);
      const out = new Uint8Array(total);
      let off = 0;
      for (const c of chunks) {
        out.set(c, off);
        off += c.length;
      }
      resolve(out);
    };

    stream.on('data', (chunk: Uint8Array) => {
      if (done) return;
      chunks.push(chunk);
      total += chunk.length;
      if (total >= options.minBytes) finish();
    });
    stream.on('close', () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      const out = new Uint8Array(total);
      let off = 0;
      for (const c of chunks) {
        out.set(c, off);
        off += c.length;
      }
      resolve(out);
    });
  });
}

describe('WispClient against real wisp-js server', () => {
  test('handshake completes and reports server capabilities', async () => {
    const client = new WispClient({ url: serverUrl, handshakeTimeoutMs: 5_000 });
    try {
      await client.ready();
      expect(client.connected).toBe(true);
      // wisp-js defaults advertise UDP. MOTD is null unless configured.
      expect(client.udpSupported).toBe(true);
    } finally {
      client.close();
    }
  });

  test('TCP stream to example.com:80 receives an HTTP response', async () => {
    const client = new WispClient({ url: serverUrl, handshakeTimeoutMs: 5_000 });
    try {
      await client.ready();
      const stream = client.createStream('example.com', 80, 'tcp');

      // Wait for stream to open. If confirmStreamOpen, we get a CONTINUE;
      // otherwise the optimistic 'open' fires on a microtask.
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('open timeout')), 5_000);
        stream.on('open', () => {
          clearTimeout(timeout);
          resolve();
        });
        stream.on('close', (info: { reason: number }) => {
          clearTimeout(timeout);
          reject(new Error(`stream closed before open: 0x${info.reason.toString(16)}`));
        });
      });

      // Issue a minimal HTTP/1.0 request — Connection: close so the server
      // closes after sending, and we can rely on stream close as
      // end-of-data.
      const req =
        'GET / HTTP/1.0\r\n' +
        'Host: example.com\r\n' +
        'Connection: close\r\n' +
        'User-Agent: WispClient-test/1.0\r\n' +
        '\r\n';
      stream.send(new TextEncoder().encode(req));

      const response = await readUntil(stream, { minBytes: 12, timeoutMs: 15_000 });
      const head = new TextDecoder('utf-8').decode(response.subarray(0, 64));
      expect(head).toMatch(/^HTTP\/1\.[01] /);
    } finally {
      client.close();
    }
  }, 30_000);
});
