import { describe, it, expect } from "vitest";
import {
  IP_PROTO_ICMP,
  IP_PROTO_TCP,
  IP_PROTO_UDP,
  TCP_SYN,
  TCP_ACK,
  TCP_FIN,
  ipToNum,
  numToIp,
  parseCidr,
  isInSubnet,
  macEquals,
  parseIPv4,
  buildIPv4Packet,
  parseTcp,
  buildTcpSegment,
  parseUdp,
  buildUdpSegment,
  buildIcmpPortUnreachable,
  parseEthernet,
  buildEthernetFrame,
} from "../src/packet";

// ---- internet checksum (RFC 1071) used by tests for verification ----
function internetChecksum(buf: Uint8Array): number {
  let sum = 0;
  let i = 0;
  for (; i + 1 < buf.length; i += 2) {
    sum += (buf[i]! << 8) | buf[i + 1]!;
  }
  if (i < buf.length) sum += buf[i]! << 8;
  while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16);
  return (~sum) & 0xffff;
}

describe("address helpers", () => {
  it("ipToNum/numToIp round-trips for standard IPs", () => {
    const cases = [
      "0.0.0.0",
      "255.255.255.255",
      "192.168.1.1",
      "10.0.0.1",
      "127.0.0.1",
      "192.168.127.2",
      "8.8.8.8",
    ];
    for (const ip of cases) {
      expect(numToIp(ipToNum(ip))).toBe(ip);
    }
  });

  it("ipToNum produces correct uint32 values", () => {
    expect(ipToNum("0.0.0.0")).toBe(0);
    expect(ipToNum("255.255.255.255")).toBe(0xffffffff);
    expect(ipToNum("192.168.127.2")).toBe(0xc0a87f02);
    expect(ipToNum("1.2.3.4")).toBe(0x01020304);
  });

  it("parseCidr handles /0, /8, /24, /32", () => {
    expect(parseCidr("0.0.0.0/0")).toEqual({
      ip: 0,
      mask: 0,
      prefix: 0,
    });
    expect(parseCidr("10.0.0.0/8")).toEqual({
      ip: 0x0a000000,
      mask: 0xff000000,
      prefix: 8,
    });
    expect(parseCidr("192.168.1.0/24")).toEqual({
      ip: 0xc0a80100,
      mask: 0xffffff00,
      prefix: 24,
    });
    expect(parseCidr("1.2.3.4/32")).toEqual({
      ip: 0x01020304,
      mask: 0xffffffff,
      prefix: 32,
    });
  });

  it("parseCidr throws on invalid input", () => {
    expect(() => parseCidr("not-a-cidr")).toThrow();
    expect(() => parseCidr("1.2.3.4")).toThrow();
    expect(() => parseCidr("1.2.3.4/33")).toThrow();
    expect(() => parseCidr("1.2.3.4/-1")).toThrow();
    expect(() => parseCidr("256.0.0.0/8")).toThrow();
    expect(() => parseCidr("1.2.3/8")).toThrow();
  });

  it("isInSubnet matches addresses inside the prefix", () => {
    const { ip, mask } = parseCidr("192.168.1.0/24");
    expect(isInSubnet(ipToNum("192.168.1.5"), ip, mask)).toBe(true);
    expect(isInSubnet(ipToNum("192.168.1.255"), ip, mask)).toBe(true);
    expect(isInSubnet(ipToNum("192.168.2.1"), ip, mask)).toBe(false);
    expect(isInSubnet(ipToNum("10.0.0.1"), ip, mask)).toBe(false);

    const all = parseCidr("0.0.0.0/0");
    expect(isInSubnet(ipToNum("8.8.8.8"), all.ip, all.mask)).toBe(true);
  });

  it("macEquals compares MAC bytes", () => {
    const a = new Uint8Array([1, 2, 3, 4, 5, 6]);
    const b = new Uint8Array([1, 2, 3, 4, 5, 6]);
    const c = new Uint8Array([1, 2, 3, 4, 5, 7]);
    expect(macEquals(a, b)).toBe(true);
    expect(macEquals(a, c)).toBe(false);
    expect(macEquals(a, new Uint8Array(5))).toBe(false);
  });
});

describe("IPv4 parse/build", () => {
  it("round-trips for several protocols and payload sizes", () => {
    const protos = [IP_PROTO_TCP, IP_PROTO_UDP, IP_PROTO_ICMP];
    const sizes = [0, 1, 20, 100, 1000];
    for (const proto of protos) {
      for (const size of sizes) {
        const payload = new Uint8Array(size);
        for (let i = 0; i < size; i++) payload[i] = i & 0xff;
        const pkt = buildIPv4Packet(
          ipToNum("192.168.1.10"),
          ipToNum("8.8.8.8"),
          proto,
          payload,
          { identification: 0x1234 },
        );
        const hdr = parseIPv4(pkt, 0);
        expect(hdr).not.toBeNull();
        expect(hdr!.version).toBe(4);
        expect(hdr!.ihl).toBe(5);
        expect(hdr!.protocol).toBe(proto);
        expect(hdr!.srcIp).toBe(ipToNum("192.168.1.10"));
        expect(hdr!.dstIp).toBe(ipToNum("8.8.8.8"));
        expect(hdr!.totalLength).toBe(20 + size);
        expect(hdr!.payloadLength).toBe(size);
        expect(hdr!.identification).toBe(0x1234);
        expect(hdr!.ttl).toBe(64);
        const sliced = pkt.slice(hdr!.payloadOffset, hdr!.payloadOffset + hdr!.payloadLength);
        expect(Array.from(sliced)).toEqual(Array.from(payload));
      }
    }
  });

  it("computes a valid IPv4 header checksum", () => {
    const pkt = buildIPv4Packet(
      ipToNum("10.0.0.1"),
      ipToNum("10.0.0.2"),
      IP_PROTO_TCP,
      new Uint8Array(8),
    );
    // Checksum over the 20-byte header should be 0 when re-summed.
    const checked = internetChecksum(pkt.subarray(0, 20));
    expect(checked).toBe(0);
  });

  it("returns null on truncated/malformed packets", () => {
    // Too short for header
    expect(parseIPv4(new Uint8Array(10), 0)).toBeNull();

    // Wrong version
    const wrongVer = buildIPv4Packet(0x01020304, 0x05060708, IP_PROTO_UDP, new Uint8Array(4));
    wrongVer[0] = (6 << 4) | 5; // version 6, ihl 5
    expect(parseIPv4(wrongVer, 0)).toBeNull();

    // ihl < 5
    const shortIhl = buildIPv4Packet(0x01020304, 0x05060708, IP_PROTO_UDP, new Uint8Array(4));
    shortIhl[0] = (4 << 4) | 4;
    expect(parseIPv4(shortIhl, 0)).toBeNull();

    // totalLength larger than buffer
    const bigLen = buildIPv4Packet(0x01020304, 0x05060708, IP_PROTO_UDP, new Uint8Array(4));
    bigLen[2] = 0xff;
    bigLen[3] = 0xff;
    expect(parseIPv4(bigLen, 0)).toBeNull();

    // ihl*4 > totalLength
    const badIhl = buildIPv4Packet(0x01020304, 0x05060708, IP_PROTO_UDP, new Uint8Array(0));
    badIhl[0] = (4 << 4) | 15; // ihl=15 → 60 bytes header, but totalLength is 20
    expect(parseIPv4(badIhl, 0)).toBeNull();
  });
});

describe("TCP parse/build", () => {
  it("round-trips with various flags and payloads", () => {
    const srcIp = ipToNum("192.168.1.10");
    const dstIp = ipToNum("8.8.8.8");
    const cases: Array<{ flags: number; payload: Uint8Array }> = [
      { flags: TCP_SYN, payload: new Uint8Array(0) },
      { flags: TCP_SYN | TCP_ACK, payload: new Uint8Array(0) },
      { flags: TCP_ACK, payload: new Uint8Array([1, 2, 3, 4, 5]) },
      { flags: TCP_ACK | TCP_FIN, payload: new Uint8Array(0) },
    ];
    for (const c of cases) {
      const seg = buildTcpSegment(
        12345,
        80,
        0xdeadbeef,
        0xcafebabe,
        c.flags,
        65535,
        c.payload,
        srcIp,
        dstIp,
      );
      const tcp = parseTcp(seg, 0);
      expect(tcp).not.toBeNull();
      expect(tcp!.srcPort).toBe(12345);
      expect(tcp!.dstPort).toBe(80);
      expect(tcp!.seqNum >>> 0).toBe(0xdeadbeef);
      expect(tcp!.ackNum >>> 0).toBe(0xcafebabe);
      expect(tcp!.flags).toBe(c.flags);
      expect(tcp!.window).toBe(65535);
      expect(tcp!.dataOffset).toBe(5);
      const slice = seg.slice(tcp!.payloadOffset);
      expect(Array.from(slice)).toEqual(Array.from(c.payload));
    }
  });

  it("returns null on truncated TCP", () => {
    expect(parseTcp(new Uint8Array(15), 0)).toBeNull();

    const seg = buildTcpSegment(
      1,
      2,
      0,
      0,
      TCP_ACK,
      0,
      new Uint8Array(0),
      0x01020304,
      0x05060708,
    );
    // dataOffset < 5
    seg[12] = (4 << 4); // dataOffset=4
    expect(parseTcp(seg, 0)).toBeNull();

    const seg2 = buildTcpSegment(
      1,
      2,
      0,
      0,
      TCP_ACK,
      0,
      new Uint8Array(0),
      0x01020304,
      0x05060708,
    );
    seg2[12] = (15 << 4); // dataOffset=15 → 60 bytes, but seg is 20
    expect(parseTcp(seg2, 0)).toBeNull();
  });

  it("computes a TCP checksum that verifies via pseudo-header", () => {
    // Hand-construct: src 192.168.0.1:1234, dst 192.168.0.2:80, payload "hi"
    const srcIp = ipToNum("192.168.0.1");
    const dstIp = ipToNum("192.168.0.2");
    const payload = new TextEncoder().encode("hi");
    const seg = buildTcpSegment(
      1234,
      80,
      0,
      0,
      TCP_ACK,
      8192,
      payload,
      srcIp,
      dstIp,
    );

    // Re-verify: checksum over pseudo-header + segment must be zero.
    const pseudo = new Uint8Array(12);
    const dv = new DataView(pseudo.buffer);
    dv.setUint32(0, srcIp, false);
    dv.setUint32(4, dstIp, false);
    pseudo[8] = 0;
    pseudo[9] = IP_PROTO_TCP;
    dv.setUint16(10, seg.length, false);
    const buf = new Uint8Array(pseudo.length + seg.length);
    buf.set(pseudo, 0);
    buf.set(seg, pseudo.length);
    expect(internetChecksum(buf)).toBe(0);

    // Also confirm checksum field is non-zero (sanity)
    const tcp = parseTcp(seg, 0)!;
    expect(tcp.checksum).not.toBe(0);
  });
});

describe("UDP parse/build", () => {
  it("round-trips with various payload sizes", () => {
    const srcIp = ipToNum("192.168.1.10");
    const dstIp = ipToNum("8.8.8.8");
    const sizes = [0, 1, 20, 1400];
    for (const size of sizes) {
      const payload = new Uint8Array(size);
      for (let i = 0; i < size; i++) payload[i] = (i * 7) & 0xff;
      const seg = buildUdpSegment(53535, 53, payload, srcIp, dstIp);
      const udp = parseUdp(seg, 0);
      expect(udp).not.toBeNull();
      expect(udp!.srcPort).toBe(53535);
      expect(udp!.dstPort).toBe(53);
      expect(udp!.length).toBe(8 + size);
      expect(udp!.payloadOffset).toBe(8);
      expect(Array.from(seg.slice(udp!.payloadOffset))).toEqual(Array.from(payload));
    }
  });

  it("computes a UDP checksum that verifies via pseudo-header", () => {
    const srcIp = ipToNum("192.168.0.1");
    const dstIp = ipToNum("192.168.0.2");
    const payload = new TextEncoder().encode("test");
    const seg = buildUdpSegment(1000, 2000, payload, srcIp, dstIp);

    const pseudo = new Uint8Array(12);
    const dv = new DataView(pseudo.buffer);
    dv.setUint32(0, srcIp, false);
    dv.setUint32(4, dstIp, false);
    pseudo[8] = 0;
    pseudo[9] = IP_PROTO_UDP;
    dv.setUint16(10, seg.length, false);
    const buf = new Uint8Array(pseudo.length + seg.length);
    buf.set(pseudo, 0);
    buf.set(seg, pseudo.length);
    expect(internetChecksum(buf)).toBe(0);
  });

  it("returns null on truncated UDP", () => {
    expect(parseUdp(new Uint8Array(7), 0)).toBeNull();
  });
});

describe("buildIcmpPortUnreachable", () => {
  it("produces a valid ICMP type 3 code 3 packet swapping src/dst", () => {
    const guestIp = ipToNum("192.168.127.2");
    const dstIp = ipToNum("8.8.8.8");
    const payload = new TextEncoder().encode("hello dns");
    const udpSeg = buildUdpSegment(54321, 53, payload, guestIp, dstIp);
    const ipPkt = buildIPv4Packet(guestIp, dstIp, IP_PROTO_UDP, udpSeg);

    const icmpPkt = buildIcmpPortUnreachable(ipPkt);

    // It's a valid IPv4 packet
    const hdr = parseIPv4(icmpPkt, 0);
    expect(hdr).not.toBeNull();
    expect(hdr!.protocol).toBe(IP_PROTO_ICMP);
    // Source = original dst, Destination = original src
    expect(hdr!.srcIp).toBe(dstIp);
    expect(hdr!.dstIp).toBe(guestIp);

    // ICMP body starts with type 3, code 3
    const off = hdr!.payloadOffset;
    expect(icmpPkt[off]).toBe(3);
    expect(icmpPkt[off + 1]).toBe(3);

    // ICMP checksum verifies (sum over ICMP header+body == 0)
    const icmp = icmpPkt.subarray(off, off + hdr!.payloadLength);
    expect(internetChecksum(icmp)).toBe(0);

    // Body after the 8-byte ICMP header should contain the original IP header
    // (20 bytes) + first 8 bytes of UDP header.
    const innerStart = off + 8;
    const innerLen = 20 + 8;
    const inner = icmpPkt.subarray(innerStart, innerStart + innerLen);
    expect(Array.from(inner.subarray(0, 20))).toEqual(Array.from(ipPkt.subarray(0, 20)));
    expect(Array.from(inner.subarray(20, 28))).toEqual(Array.from(udpSeg.subarray(0, 8)));
  });
});

describe("Ethernet", () => {
  it("round-trips a frame", () => {
    const dst = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    const src = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    const payload = new Uint8Array([1, 2, 3, 4, 5]);
    const frame = buildEthernetFrame(dst, src, 0x0800, payload);
    const eth = parseEthernet(frame);
    expect(eth).not.toBeNull();
    expect(macEquals(eth!.dstMac, dst)).toBe(true);
    expect(macEquals(eth!.srcMac, src)).toBe(true);
    expect(eth!.ethertype).toBe(0x0800);
    expect(eth!.payloadOffset).toBe(14);
    expect(Array.from(frame.slice(eth!.payloadOffset))).toEqual(Array.from(payload));
  });

  it("returns null on truncated Ethernet", () => {
    expect(parseEthernet(new Uint8Array(13))).toBeNull();
  });
});
