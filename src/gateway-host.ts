/**
 * gateway-host — bridges a `FakeWebSocket` to a `TapInterface` (lwIP) and
 * optionally to a soft-router running in parallel.
 *
 * Responsibilities:
 *   - Outbound (host -> WebSocket): pump frames out of `tap.readable` AND
 *     accept frames from the optional soft-router. All such frames are
 *     wrapped with the QEMU 4-byte BE length prefix and handed to
 *     FakeWebSocket via the `send()` callback supplied to `onConnect`.
 *   - Inbound  (WebSocket -> host): receive length-prefixed wire bytes from
 *     `onSend`, reassemble using a per-host leftover buffer. Each complete
 *     Ethernet frame is delivered to BOTH `tap.writable` (so lwIP can
 *     handle ARP/ICMP/DHCP/local) AND the optional soft-router (which
 *     forwards off-subnet IP packets to the NATs).
 *
 * Pure data shuffling — no protocol logic. See spec §3.5.
 */

import { frameMessage, extractFrames, concat } from './frame-utils';
import type { FakeWebSocketHost } from './fake-websocket';

export interface TapInterface {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
}

/**
 * Optional soft-router hook. When supplied, every guest-origin Ethernet
 * frame is also delivered to `softRouter.ingress(frame)`. The router's
 * outbound side is wired by calling `softRouter.setSend(sendFn)` so the
 * router can emit reply frames on the same channel as lwIP.
 */
export interface GatewayHostOptions {
  softRouter?: {
    ingress(frame: Uint8Array): void;
    setSend(send: (frame: Uint8Array) => void): void;
  };
}

export function makeGatewayHost(
  tap: TapInterface,
  options: GatewayHostOptions = {},
): FakeWebSocketHost {
  let leftover = new Uint8Array(0);
  let writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  let closed = false;
  let pumpRunning = false;
  const softRouter = options.softRouter ?? null;

  function startPump(send: (frame: Uint8Array) => void): void {
    if (pumpRunning) return;
    pumpRunning = true;
    reader = tap.readable.getReader();
    void (async () => {
      try {
        while (!closed) {
          const r = await reader!.read();
          if (closed) break;
          if (r.done) break;
          if (r.value) {
            try {
              send(frameMessage(r.value));
            } catch (err) {
              // Don't kill the pump on a bad send — log via console and continue.
              // eslint-disable-next-line no-console
              console.warn('[gateway-host] send threw, continuing pump:', err);
            }
          }
        }
      } catch (err) {
        if (!closed) {
          // eslint-disable-next-line no-console
          console.warn('[gateway-host] readable pump error:', err);
        }
      } finally {
        try {
          reader?.releaseLock();
        } catch {
          /* noop */
        }
      }
    })();
  }

  return {
    onConnect(send: (frame: Uint8Array) => void): void {
      try {
        writer = tap.writable.getWriter();
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn('[gateway-host] could not acquire tap writer:', err);
      }
      // Wire the soft-router's reply path to the same `send` callback so
      // router-emitted Ethernet frames go out the FakeWebSocket alongside
      // lwIP's outgoing frames.
      if (softRouter) {
        softRouter.setSend((frame) => {
          if (closed) return;
          try {
            send(frameMessage(frame));
          } catch (err) {
            // eslint-disable-next-line no-console
            console.warn('[gateway-host] softRouter send threw:', err);
          }
        });
      }
      startPump(send);
    },

    onSend(data: Uint8Array): void {
      if (closed) return;
      leftover = concat(leftover, data);
      const { frames, remainder } = extractFrames(leftover);
      leftover = remainder;

      if (frames.length === 0) return;
      if (!writer && !softRouter) {
        // eslint-disable-next-line no-console
        console.warn(
          `[gateway-host] onSend got ${data.length}B but neither tap writer ` +
            `nor soft-router available; ${frames.length} frame(s) dropped`,
        );
        return;
      }
      if (!writer) {
        // eslint-disable-next-line no-console
        console.warn(`[gateway-host] no tap writer; routing ${frames.length} frame(s) to soft-router only`);
      }

      // Tee each frame: lwIP path + soft-router path. The two consumers
      // see the same byte sequence; neither mutates the buffer.
      for (const frame of frames) {
        // 1. lwIP path: write to tap.writable. Fire-and-forget for
        //    throughput; surface errors via console.
        if (writer) {
          writer.write(frame).catch((err) => {
            // eslint-disable-next-line no-console
            console.warn('[gateway-host] tap.writable.write rejected:', err);
          });
        }
        // 2. Soft-router path: synchronous; the router decides whether
        //    to enqueue the IP payload to the NATs.
        if (softRouter) {
          try {
            softRouter.ingress(frame);
          } catch (err) {
            // eslint-disable-next-line no-console
            console.warn('[gateway-host] softRouter.ingress threw:', err);
          }
        }
      }
    },

    onClose(): void {
      if (closed) return;
      closed = true;
      try {
        reader?.cancel().catch(() => {
          /* noop */
        });
      } catch {
        /* noop */
      }
      try {
        writer?.releaseLock();
      } catch {
        /* noop */
      }
      writer = null;
      reader = null;
      leftover = new Uint8Array(0);
    },
  };
}
