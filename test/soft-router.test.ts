/**
 * Tests for soft-router — the IP forwarder that bridges the guest's L2
 * (Tap) with Eclipse's TCP/UDP NATs.
 */

import { describe, test, expect } from 'vitest';
import { createSoftRouter } from '../src/soft-router';
import {
  buildEthernetFrame,
  buildIPv4Packet,
  buildUdpSegment,
  parseEthernet,
  parseIPv4,
  ipToNum,
  parseCidr,
} from '../src/packet';

const ETHERTYPE_IPV4 = 0x0800;
const GUEST_MAC = new Uint8Array([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
const GW_MAC_STR = '02:00:00:00:00:01';
const GW_MAC = new Uint8Array([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

function makeRouter() {
  const { ip: gwIp, mask } = parseCidr('192.168.127.1/24');
  return createSoftRouter({
    gatewayIp: gwIp,
    subnetMask: mask,
    gatewayMac: GW_MAC_STR,
  });
}

function buildUdpEthFrame(opts: {
  srcMac: Uint8Array;
  dstMac: Uint8Array;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  payload: Uint8Array;
}): Uint8Array {
  const udp = buildUdpSegment(
    opts.srcPort,
    opts.dstPort,
    opts.payload,
    ipToNum(opts.srcIp),
    ipToNum(opts.dstIp),
  );
  const ip = buildIPv4Packet(
    ipToNum(opts.srcIp),
    ipToNum(opts.dstIp),
    17 /* IP_PROTO_UDP */,
    udp,
  );
  return buildEthernetFrame(opts.dstMac, opts.srcMac, ETHERTYPE_IPV4, ip);
}

async function readAllFromStream(
  stream: ReadableStream<Uint8Array>,
  count: number,
  timeoutMs = 100,
): Promise<Uint8Array[]> {
  const reader = stream.getReader();
  const out: Uint8Array[] = [];
  const deadline = Date.now() + timeoutMs;
  try {
    while (out.length < count) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) break;
      const r = await Promise.race([
        reader.read(),
        new Promise<{ done: true; value: undefined }>((resolve) =>
          setTimeout(() => resolve({ done: true, value: undefined }), remaining),
        ),
      ]);
      if (r.done) break;
      if (r.value) out.push(r.value);
    }
  } finally {
    reader.releaseLock();
  }
  return out;
}

describe('soft-router', () => {
  test('learns the guest MAC from the first unicast frame', () => {
    const router = makeRouter();
    expect(router.getLearnedGuestMac()).toBeNull();

    const frame = buildUdpEthFrame({
      srcMac: GUEST_MAC,
      dstMac: GW_MAC,
      srcIp: '192.168.127.2',
      dstIp: '1.1.1.1',
      srcPort: 12345,
      dstPort: 53,
      payload: new Uint8Array([0xde, 0xad]),
    });
    router.ingress(frame);

    const learned = router.getLearnedGuestMac();
    expect(learned).not.toBeNull();
    expect(Array.from(learned!)).toEqual(Array.from(GUEST_MAC));
  });

  test('does NOT learn MAC from multicast/broadcast source', () => {
    const router = makeRouter();
    const bcastMac = new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    const frame = buildUdpEthFrame({
      srcMac: bcastMac,
      dstMac: GW_MAC,
      srcIp: '192.168.127.2',
      dstIp: '1.1.1.1',
      srcPort: 1234,
      dstPort: 53,
      payload: new Uint8Array([0]),
    });
    router.ingress(frame);
    expect(router.getLearnedGuestMac()).toBeNull();
  });

  test('forwards off-subnet IPv4 packet to the NAT-facing readable', async () => {
    const router = makeRouter();
    const payload = new Uint8Array([1, 2, 3, 4, 5]);
    const frame = buildUdpEthFrame({
      srcMac: GUEST_MAC,
      dstMac: GW_MAC,
      srcIp: '192.168.127.2',
      dstIp: '1.1.1.1',
      srcPort: 5555,
      dstPort: 53,
      payload,
    });
    router.ingress(frame);

    const packets = await readAllFromStream(router.ipDuplex.readable, 1);
    expect(packets.length).toBe(1);

    // The packet on the readable side should be the bare IPv4 (no Ethernet).
    const ip = parseIPv4(packets[0]!, 0);
    expect(ip).not.toBeNull();
    expect(ip!.protocol).toBe(17);
    // Source / dest match what we put in.
    expect(ip!.srcIp).toBe(ipToNum('192.168.127.2'));
    expect(ip!.dstIp).toBe(ipToNum('1.1.1.1'));
  });

  test('does NOT forward in-subnet packets (lwIP handles them)', async () => {
    const router = makeRouter();
    const frame = buildUdpEthFrame({
      srcMac: GUEST_MAC,
      dstMac: GW_MAC,
      // 192.168.127.3 is in the gateway's /24 subnet — should NOT forward.
      srcIp: '192.168.127.2',
      dstIp: '192.168.127.3',
      srcPort: 5000,
      dstPort: 80,
      payload: new Uint8Array([0]),
    });
    router.ingress(frame);

    // Give the controller microtask a chance to enqueue (it shouldn't).
    await new Promise((r) => setTimeout(r, 10));
    const packets = await readAllFromStream(router.ipDuplex.readable, 1, 30);
    expect(packets.length).toBe(0);
  });

  test('does NOT forward non-IPv4 frames (ARP, IPv6, etc.)', async () => {
    const router = makeRouter();
    const arpPayload = new Uint8Array(28); // minimal ARP-sized payload
    const arpFrame = buildEthernetFrame(GW_MAC, GUEST_MAC, 0x0806 /* ARP */, arpPayload);
    router.ingress(arpFrame);

    await new Promise((r) => setTimeout(r, 10));
    const packets = await readAllFromStream(router.ipDuplex.readable, 1, 30);
    expect(packets.length).toBe(0);

    // …but the source MAC should still have been learned.
    expect(router.getLearnedGuestMac()).not.toBeNull();
  });

  test('egress: wraps IP reply in Ethernet and emits via send hook', async () => {
    const router = makeRouter();

    // Learn the guest MAC first.
    const learnFrame = buildUdpEthFrame({
      srcMac: GUEST_MAC,
      dstMac: GW_MAC,
      srcIp: '192.168.127.2',
      dstIp: '1.1.1.1',
      srcPort: 1234,
      dstPort: 53,
      payload: new Uint8Array([0]),
    });
    router.ingress(learnFrame);

    const sentFrames: Uint8Array[] = [];
    router.setSend((f) => sentFrames.push(f));

    // NAT writes an IP reply (1.1.1.1 -> 192.168.127.2 via UDP).
    const replyPayload = new Uint8Array([0xa, 0xb, 0xc]);
    const udp = buildUdpSegment(
      53,
      1234,
      replyPayload,
      ipToNum('1.1.1.1'),
      ipToNum('192.168.127.2'),
    );
    const ipReply = buildIPv4Packet(
      ipToNum('1.1.1.1'),
      ipToNum('192.168.127.2'),
      17,
      udp,
    );
    const writer = router.ipDuplex.writable.getWriter();
    await writer.write(ipReply);
    writer.releaseLock();

    // Yield so the WritableStream's write() callback runs.
    await new Promise((r) => setTimeout(r, 5));

    expect(sentFrames.length).toBe(1);
    const eth = parseEthernet(sentFrames[0]!);
    expect(eth).not.toBeNull();
    expect(Array.from(eth!.dstMac)).toEqual(Array.from(GUEST_MAC));
    expect(Array.from(eth!.srcMac)).toEqual(Array.from(GW_MAC));
    expect(eth!.ethertype).toBe(ETHERTYPE_IPV4);
  });

  test('egress: drops reply if guest MAC not learned yet', async () => {
    const router = makeRouter();
    const sentFrames: Uint8Array[] = [];
    router.setSend((f) => sentFrames.push(f));

    const ipReply = buildIPv4Packet(
      ipToNum('1.1.1.1'),
      ipToNum('192.168.127.2'),
      17,
      buildUdpSegment(53, 1234, new Uint8Array([0]), ipToNum('1.1.1.1'), ipToNum('192.168.127.2')),
    );
    const writer = router.ipDuplex.writable.getWriter();
    await writer.write(ipReply);
    writer.releaseLock();
    await new Promise((r) => setTimeout(r, 5));

    expect(sentFrames.length).toBe(0);
  });

  test('destroy() closes the outgoing readable and ignores further ingress', async () => {
    const router = makeRouter();
    await router.destroy();

    const frame = buildUdpEthFrame({
      srcMac: GUEST_MAC,
      dstMac: GW_MAC,
      srcIp: '192.168.127.2',
      dstIp: '1.1.1.1',
      srcPort: 1234,
      dstPort: 53,
      payload: new Uint8Array([0]),
    });
    router.ingress(frame); // should be a no-op

    const reader = router.ipDuplex.readable.getReader();
    const { done } = await reader.read();
    expect(done).toBe(true);
    reader.releaseLock();
  });
});
