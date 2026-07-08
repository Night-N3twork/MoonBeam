/**
 * soft-router — a tiny IP forwarder living between the guest's L2 (Tap)
 * and Eclipse's TCP/UDP NATs.
 *
 * Why this exists
 * ===============
 * The `tcpip` library we use as our LAN-side stack is an *endpoint* host
 * stack: it terminates TCP/UDP for IPs bound to its own interfaces, but
 * it does NOT forward IP packets between interfaces. That means a guest
 * packet destined for, say, `1.1.1.1` arrives on the Tap, lwIP unwraps
 * the Ethernet frame, looks at the IP destination, finds nothing local
 * to deliver it to, and drops it on the floor.
 *
 * The soft-router runs in *parallel* with lwIP. Every Ethernet frame
 * coming from the guest is delivered to BOTH:
 *   - lwIP's `tap.writable`           (so ARP / ICMP-to-gateway / DHCP
 *                                      keep working through lwIP), and
 *   - `softRouter.ingress(frame)`     (so we can intercept off-subnet IP
 *                                      packets and forward them).
 *
 * For frames whose IP destination is OUTSIDE the LAN subnet, we strip the
 * Ethernet header and push the bare IP packet onto the `outgoing` readable
 * stream that TCP/UDP NATs consume. The NATs' write side (`incoming`)
 * accepts IP packets from the internet (Wisp side); the soft-router wraps
 * each one in an Ethernet frame (dst MAC = the guest's learned MAC, src
 * MAC = the gateway MAC) and emits it via the `send` callback shared with
 * lwIP's outgoing-frame pump.
 *
 * The router learns the guest's MAC address from any Ethernet source MAC
 * we've seen. Until learning happens, IP-to-guest replies have nowhere to
 * go and are dropped (they would be no-ops anyway since the guest has not
 * yet sent its first packet).
 */

import {
  parseEthernet,
  parseIPv4,
  buildEthernetFrame,
  isInSubnet,
} from './packet';

const ETHERTYPE_IPV4 = 0x0800;

/** Parse "aa:bb:cc:dd:ee:ff" into a 6-byte Uint8Array. */
function parseMac(s: string): Uint8Array {
  const parts = s.split(':');
  if (parts.length !== 6) throw new Error(`soft-router: invalid MAC "${s}"`);
  const out = new Uint8Array(6);
  for (let i = 0; i < 6; i++) {
    const v = parseInt(parts[i]!, 16);
    if (Number.isNaN(v) || v < 0 || v > 0xff) {
      throw new Error(`soft-router: invalid MAC byte "${parts[i]}"`);
    }
    out[i] = v;
  }
  return out;
}

export interface SoftRouterConfig {
  /** Gateway IP as a 32-bit number (network byte order). */
  gatewayIp: number;
  /** Subnet mask as a 32-bit number. */
  subnetMask: number;
  /** Gateway MAC, as the colon-separated string we already use elsewhere. */
  gatewayMac: string;
  /** Optional: emit verbose logs to console. Default: false. */
  debug?: boolean;
}

export interface SoftRouter {
  /**
   * Duplex view exposed to the NATs.
   *   - readable: bare IPv4 packets destined OUTSIDE the LAN. NATs read
   *     these and forward via Wisp.
   *   - writable: bare IPv4 packets coming back FROM the internet that
   *     should be delivered to the guest. The router wraps them in an
   *     Ethernet frame and hands them to `send`.
   */
  ipDuplex: {
    readable: ReadableStream<Uint8Array>;
    writable: WritableStream<Uint8Array>;
  };

  /**
   * Hook the router up to the host's frame transmitter. `send(frame)` is
   * called for every Ethernet frame the router wants to deliver to the
   * guest. (gateway-host re-uses the same `send` callback used to pump
   * lwIP's outgoing frames, so router-originated and lwIP-originated
   * frames are interleaved transparently.)
   */
  setSend(send: (frame: Uint8Array) => void): void;

  /**
   * Feed a raw Ethernet frame (as received from the guest) into the
   * router. The router learns the guest's MAC, then either:
   *   - forwards the IP payload to the NATs (if dst IP is off-subnet), or
   *   - ignores the frame (lwIP will handle it).
   *
   * Non-IPv4 frames are ignored.
   */
  ingress(frame: Uint8Array): void;

  /** Returns the learned guest MAC (or null if not yet learned). */
  getLearnedGuestMac(): Uint8Array | null;

  /** Stop the router; close the stream pair. Idempotent. */
  destroy(): Promise<void>;
}

export function createSoftRouter(cfg: SoftRouterConfig): SoftRouter {
  const gatewayMac = parseMac(cfg.gatewayMac);
  const subnetIp = cfg.gatewayIp;
  const subnetMask = cfg.subnetMask;
  const debug = cfg.debug === true;

  let learnedGuestMac: Uint8Array | null = null;
  let send: ((frame: Uint8Array) => void) | null = null;
  let destroyed = false;

  // --- outgoing IP stream (router -> NATs) -------------------------------
  // We expose this as a ReadableStream the NATs `getReader()` on. We
  // produce into it via `controller.enqueue(ipPacket)` from `ingress()`.
  //
  // The NATs already have backpressure-aware read loops; ReadableStream's
  // default queuing strategy (1 chunk in flight) is fine for our packet
  // rates.
  let outgoingController: ReadableStreamDefaultController<Uint8Array> | null = null;
  const outgoing = new ReadableStream<Uint8Array>({
    start(controller) {
      outgoingController = controller;
    },
    cancel() {
      outgoingController = null;
    },
  });

  // --- incoming IP stream (NATs -> router) -------------------------------
  // Replies from the internet arrive here. Each chunk is one IPv4 packet.
  // We wrap with Ethernet (dst=learnedGuestMac, src=gatewayMac) and call
  // `send`.
  const incoming = new WritableStream<Uint8Array>({
    write(ipPkt) {
      if (destroyed) return;
      if (!send) {
        if (debug) {
          // eslint-disable-next-line no-console
          console.warn('[soft-router] reply IP packet dropped: no send hook');
        }
        return;
      }
      if (!learnedGuestMac) {
        if (debug) {
          // eslint-disable-next-line no-console
          console.warn('[soft-router] reply IP packet dropped: no learned guest MAC yet');
        }
        return;
      }
      // Sanity: must be IPv4 (the NATs only write IPv4).
      const hdr = parseIPv4(ipPkt, 0);
      if (!hdr) {
        if (debug) {
          // eslint-disable-next-line no-console
          console.warn('[soft-router] reply IP packet dropped: malformed IPv4');
        }
        return;
      }
      const frame = buildEthernetFrame(
        learnedGuestMac,
        gatewayMac,
        ETHERTYPE_IPV4,
        ipPkt,
      );
      try {
        send(frame);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn('[soft-router] send threw on reply:', err);
      }
    },
  });

  function ingress(frame: Uint8Array): void {
    if (destroyed) return;

    const eth = parseEthernet(frame);
    if (!eth) return;

    // Learn the guest's MAC the first time we see a unicast frame from it.
    // Filter out the broadcast / multicast we don't want to learn from.
    const srcMac = eth.srcMac;
    const isMcast = (srcMac[0]! & 0x01) === 0x01;
    if (!isMcast) {
      if (!learnedGuestMac) {
        learnedGuestMac = srcMac;
        if (debug) {
          // eslint-disable-next-line no-console
          console.log(
            `[soft-router] learned guest MAC: ${Array.from(srcMac)
              .map((b) => b.toString(16).padStart(2, '0'))
              .join(':')}`,
          );
        }
      }
    }

    if (eth.ethertype !== ETHERTYPE_IPV4) return;

    const ipBytes = frame.subarray(eth.payloadOffset);
    const ip = parseIPv4(ipBytes, 0);
    if (!ip) return;

    // Only forward packets whose destination is OUTSIDE the LAN subnet.
    // In-subnet packets (DHCP broadcast, ARP-resolved peer chatter, gateway
    // pings) are handled by lwIP via the parallel tap.writable path.
    const onLan = isInSubnet(ip.dstIp, subnetIp, subnetMask);
    if (onLan) return;

    // Strip Ethernet header; emit the bare IPv4 packet to the NATs.
    // We slice (not subarray) to give the NATs an independently-owned
    // buffer — the caller's frame may be reused.
    const ipPkt = ipBytes.slice(0, ip.totalLength > 0 ? ip.totalLength : ipBytes.length);

    if (debug) {
      // eslint-disable-next-line no-console
      console.log(
        `[soft-router] forwarding IP packet ${ip.protocol === 6 ? 'TCP' : ip.protocol === 17 ? 'UDP' : `proto=${ip.protocol}`} -> NATs (${ipPkt.length}B)`,
      );
    }

    if (outgoingController) {
      try {
        outgoingController.enqueue(ipPkt);
      } catch {
        // Stream errored; drop.
      }
    }
  }

  return {
    ipDuplex: { readable: outgoing, writable: incoming },
    setSend(s) {
      send = s;
    },
    ingress,
    getLearnedGuestMac() {
      return learnedGuestMac;
    },
    async destroy() {
      if (destroyed) return;
      destroyed = true;
      send = null;
      try {
        outgoingController?.close();
      } catch {
        /* ignore */
      }
      outgoingController = null;
    },
  };
}
