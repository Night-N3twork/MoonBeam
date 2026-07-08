/**
 * Packet codec for Ethernet, IPv4, ARP, ICMPv4, TCP, UDP.
 *
 * Pure functions. No DOM, no globals. Used by NAT layers to parse forwarded
 * packets and craft injection packets. See
 *   docs/specs/2026-05-27-vm-wisp-networking-design.md §4.8, §5.3, §6.4
 *
 * All multi-byte fields are big-endian on the wire (the default for DataView
 * methods invoked with `false` for littleEndian).
 */

// -- IP protocol numbers (IANA) --
export const IP_PROTO_ICMP = 1;
export const IP_PROTO_TCP = 6;
export const IP_PROTO_UDP = 17;

// -- TCP flag bits --
export const TCP_FIN = 0x01;
export const TCP_SYN = 0x02;
export const TCP_RST = 0x04;
export const TCP_PSH = 0x08;
export const TCP_ACK = 0x10;
export const TCP_URG = 0x20;

// -- Ethernet --
const ETH_HDR_LEN = 14;
// -- IPv4 --
const IPV4_MIN_HDR_LEN = 20;
const IPV4_FLAG_DF = 0x4000;
// -- TCP --
const TCP_MIN_HDR_LEN = 20;
// -- UDP --
const UDP_HDR_LEN = 8;
// -- ICMP --
const ICMP_HDR_LEN = 8;

// ---------------------------------------------------------------------------
// Internet checksum (RFC 1071)
// ---------------------------------------------------------------------------

/** Compute the one's-complement 16-bit checksum over `buf`. */
function checksum16(buf: Uint8Array): number {
  let sum = 0;
  let i = 0;
  const len = buf.length;
  for (; i + 1 < len; i += 2) {
    sum += (buf[i]! << 8) | buf[i + 1]!;
  }
  if (i < len) sum += buf[i]! << 8;
  while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16);
  return (~sum) & 0xffff;
}

/** Build a TCP/UDP pseudo-header buffer for checksum computation. */
function pseudoHeader(srcIp: number, dstIp: number, proto: number, len: number): Uint8Array {
  const buf = new Uint8Array(12);
  const dv = new DataView(buf.buffer);
  dv.setUint32(0, srcIp >>> 0, false);
  dv.setUint32(4, dstIp >>> 0, false);
  buf[8] = 0;
  buf[9] = proto & 0xff;
  dv.setUint16(10, len & 0xffff, false);
  return buf;
}

/** Compute a checksum over the concatenation of `parts`. */
function checksumMulti(parts: Uint8Array[]): number {
  let total = 0;
  for (const p of parts) total += p.length;
  const merged = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    merged.set(p, off);
    off += p.length;
  }
  return checksum16(merged);
}

// ---------------------------------------------------------------------------
// Address helpers
// ---------------------------------------------------------------------------

export function ipToNum(s: string): number {
  const parts = s.split(".");
  if (parts.length !== 4) throw new Error(`invalid IPv4: ${s}`);
  let out = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) throw new Error(`invalid IPv4: ${s}`);
    const n = Number(part);
    if (n < 0 || n > 255) throw new Error(`invalid IPv4 octet: ${part}`);
    out = (out << 8) | n;
  }
  return out >>> 0;
}

export function numToIp(n: number): string {
  const u = n >>> 0;
  return `${(u >>> 24) & 0xff}.${(u >>> 16) & 0xff}.${(u >>> 8) & 0xff}.${u & 0xff}`;
}

export function parseCidr(s: string): { ip: number; mask: number; prefix: number } {
  const idx = s.indexOf("/");
  if (idx < 0) throw new Error(`invalid CIDR: ${s}`);
  const ipStr = s.slice(0, idx);
  const prefixStr = s.slice(idx + 1);
  if (!/^\d+$/.test(prefixStr)) throw new Error(`invalid CIDR prefix: ${prefixStr}`);
  const prefix = Number(prefixStr);
  if (prefix < 0 || prefix > 32) throw new Error(`invalid CIDR prefix: ${prefix}`);
  const ip = ipToNum(ipStr);
  // mask: 0 prefix yields 0; 32 prefix yields 0xffffffff
  const mask = prefix === 0 ? 0 : ((0xffffffff << (32 - prefix)) >>> 0);
  return { ip, mask, prefix };
}

export function isInSubnet(ip: number, subnetIp: number, mask: number): boolean {
  return ((ip & mask) >>> 0) === ((subnetIp & mask) >>> 0);
}

export function macEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// ---------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------

export interface IPv4Header {
  version: number;
  ihl: number;
  tos: number;
  totalLength: number;
  identification: number;
  flags: number;
  fragmentOffset: number;
  ttl: number;
  protocol: number;
  checksum: number;
  srcIp: number;
  dstIp: number;
  payloadOffset: number;
  payloadLength: number;
}

export function parseIPv4(buf: Uint8Array, offset: number): IPv4Header | null {
  if (buf.length - offset < IPV4_MIN_HDR_LEN) return null;
  const dv = new DataView(buf.buffer, buf.byteOffset + offset, buf.length - offset);
  const verIhl = dv.getUint8(0);
  const version = (verIhl >>> 4) & 0x0f;
  const ihl = verIhl & 0x0f;
  if (version !== 4) return null;
  if (ihl < 5) return null;
  const hdrLen = ihl * 4;
  const tos = dv.getUint8(1);
  const totalLength = dv.getUint16(2, false);
  if (totalLength > buf.length - offset) return null;
  if (hdrLen > totalLength) return null;
  const identification = dv.getUint16(4, false);
  const flagsFragRaw = dv.getUint16(6, false);
  const flags = (flagsFragRaw >>> 13) & 0x07;
  const fragmentOffset = flagsFragRaw & 0x1fff;
  const ttl = dv.getUint8(8);
  const protocol = dv.getUint8(9);
  const checksum = dv.getUint16(10, false);
  const srcIp = dv.getUint32(12, false);
  const dstIp = dv.getUint32(16, false);
  return {
    version,
    ihl,
    tos,
    totalLength,
    identification,
    flags,
    fragmentOffset,
    ttl,
    protocol,
    checksum,
    srcIp,
    dstIp,
    payloadOffset: offset + hdrLen,
    payloadLength: totalLength - hdrLen,
  };
}

export function buildIPv4Packet(
  srcIp: number,
  dstIp: number,
  protocol: number,
  payload: Uint8Array,
  opts?: { ttl?: number; identification?: number },
): Uint8Array {
  const ttl = opts?.ttl ?? 64;
  const identification =
    opts?.identification ?? (Math.floor(Math.random() * 0x10000) & 0xffff);
  const totalLength = IPV4_MIN_HDR_LEN + payload.length;
  const pkt = new Uint8Array(totalLength);
  const dv = new DataView(pkt.buffer);
  dv.setUint8(0, (4 << 4) | 5);
  dv.setUint8(1, 0); // TOS
  dv.setUint16(2, totalLength, false);
  dv.setUint16(4, identification, false);
  dv.setUint16(6, IPV4_FLAG_DF, false); // flags=DF, frag offset=0
  dv.setUint8(8, ttl);
  dv.setUint8(9, protocol);
  dv.setUint16(10, 0, false); // checksum placeholder
  dv.setUint32(12, srcIp >>> 0, false);
  dv.setUint32(16, dstIp >>> 0, false);
  pkt.set(payload, IPV4_MIN_HDR_LEN);
  const csum = checksum16(pkt.subarray(0, IPV4_MIN_HDR_LEN));
  dv.setUint16(10, csum, false);
  return pkt;
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

export interface TcpHeader {
  srcPort: number;
  dstPort: number;
  seqNum: number;
  ackNum: number;
  dataOffset: number;
  flags: number;
  window: number;
  checksum: number;
  urgentPointer: number;
  payloadOffset: number;
}

export function parseTcp(buf: Uint8Array, offset: number): TcpHeader | null {
  if (buf.length - offset < TCP_MIN_HDR_LEN) return null;
  const dv = new DataView(buf.buffer, buf.byteOffset + offset, buf.length - offset);
  const srcPort = dv.getUint16(0, false);
  const dstPort = dv.getUint16(2, false);
  const seqNum = dv.getUint32(4, false);
  const ackNum = dv.getUint32(8, false);
  const off12 = dv.getUint8(12);
  const dataOffset = (off12 >>> 4) & 0x0f;
  if (dataOffset < 5) return null;
  const hdrLen = dataOffset * 4;
  if (hdrLen > buf.length - offset) return null;
  const flags = dv.getUint8(13);
  const window = dv.getUint16(14, false);
  const checksum = dv.getUint16(16, false);
  const urgentPointer = dv.getUint16(18, false);
  return {
    srcPort,
    dstPort,
    seqNum,
    ackNum,
    dataOffset,
    flags,
    window,
    checksum,
    urgentPointer,
    payloadOffset: offset + hdrLen,
  };
}

export function buildTcpSegment(
  srcPort: number,
  dstPort: number,
  seq: number,
  ack: number,
  flags: number,
  window: number,
  payload: Uint8Array,
  srcIpForChecksum: number,
  dstIpForChecksum: number,
): Uint8Array {
  const segLen = TCP_MIN_HDR_LEN + payload.length;
  const seg = new Uint8Array(segLen);
  const dv = new DataView(seg.buffer);
  dv.setUint16(0, srcPort & 0xffff, false);
  dv.setUint16(2, dstPort & 0xffff, false);
  dv.setUint32(4, seq >>> 0, false);
  dv.setUint32(8, ack >>> 0, false);
  dv.setUint8(12, 5 << 4); // dataOffset=5, reserved=0
  dv.setUint8(13, flags & 0xff);
  dv.setUint16(14, window & 0xffff, false);
  dv.setUint16(16, 0, false); // checksum placeholder
  dv.setUint16(18, 0, false); // urgent pointer
  seg.set(payload, TCP_MIN_HDR_LEN);
  const pseudo = pseudoHeader(srcIpForChecksum, dstIpForChecksum, IP_PROTO_TCP, segLen);
  const csum = checksumMulti([pseudo, seg]);
  dv.setUint16(16, csum, false);
  return seg;
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

export interface UdpHeader {
  srcPort: number;
  dstPort: number;
  length: number;
  checksum: number;
  payloadOffset: number;
}

export function parseUdp(buf: Uint8Array, offset: number): UdpHeader | null {
  if (buf.length - offset < UDP_HDR_LEN) return null;
  const dv = new DataView(buf.buffer, buf.byteOffset + offset, buf.length - offset);
  const srcPort = dv.getUint16(0, false);
  const dstPort = dv.getUint16(2, false);
  const length = dv.getUint16(4, false);
  const checksum = dv.getUint16(6, false);
  return {
    srcPort,
    dstPort,
    length,
    checksum,
    payloadOffset: offset + UDP_HDR_LEN,
  };
}

export function buildUdpSegment(
  srcPort: number,
  dstPort: number,
  payload: Uint8Array,
  srcIpForChecksum: number,
  dstIpForChecksum: number,
): Uint8Array {
  const segLen = UDP_HDR_LEN + payload.length;
  const seg = new Uint8Array(segLen);
  const dv = new DataView(seg.buffer);
  dv.setUint16(0, srcPort & 0xffff, false);
  dv.setUint16(2, dstPort & 0xffff, false);
  dv.setUint16(4, segLen & 0xffff, false);
  dv.setUint16(6, 0, false); // checksum placeholder
  seg.set(payload, UDP_HDR_LEN);
  const pseudo = pseudoHeader(srcIpForChecksum, dstIpForChecksum, IP_PROTO_UDP, segLen);
  let csum = checksumMulti([pseudo, seg]);
  // UDP convention: a transmitted zero means "no checksum"; encode actual zero as 0xffff.
  if (csum === 0) csum = 0xffff;
  dv.setUint16(6, csum, false);
  return seg;
}

// ---------------------------------------------------------------------------
// ICMP port-unreachable (RFC 792)
// ---------------------------------------------------------------------------

export function buildIcmpPortUnreachable(originalIpPkt: Uint8Array): Uint8Array {
  const origHdr = parseIPv4(originalIpPkt, 0);
  if (!origHdr) throw new Error("buildIcmpPortUnreachable: malformed original packet");
  const origHdrLen = origHdr.ihl * 4;
  // ICMP body per RFC 792: original IP header + first 8 bytes of payload.
  const innerBytes = Math.min(8, origHdr.payloadLength);
  const icmpBodyLen = ICMP_HDR_LEN + origHdrLen + innerBytes;
  const icmp = new Uint8Array(icmpBodyLen);
  const dv = new DataView(icmp.buffer);
  dv.setUint8(0, 3); // type: Destination Unreachable
  dv.setUint8(1, 3); // code: Port Unreachable
  dv.setUint16(2, 0, false); // checksum placeholder
  dv.setUint32(4, 0, false); // unused (4 bytes of zeros)
  // Copy original IP header
  icmp.set(originalIpPkt.subarray(0, origHdrLen), ICMP_HDR_LEN);
  // Copy first 8 bytes of the original payload (UDP header in spec usage)
  icmp.set(
    originalIpPkt.subarray(origHdr.payloadOffset, origHdr.payloadOffset + innerBytes),
    ICMP_HDR_LEN + origHdrLen,
  );
  const csum = checksum16(icmp);
  dv.setUint16(2, csum, false);
  // Wrap in an IPv4 packet: src = original dst, dst = original src
  return buildIPv4Packet(origHdr.dstIp, origHdr.srcIp, IP_PROTO_ICMP, icmp);
}

// ---------------------------------------------------------------------------
// Ethernet
// ---------------------------------------------------------------------------

export interface EthernetHeader {
  dstMac: Uint8Array;
  srcMac: Uint8Array;
  ethertype: number;
  payloadOffset: number;
}

export function parseEthernet(buf: Uint8Array): EthernetHeader | null {
  if (buf.length < ETH_HDR_LEN) return null;
  const dstMac = buf.slice(0, 6);
  const srcMac = buf.slice(6, 12);
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.length);
  const ethertype = dv.getUint16(12, false);
  return { dstMac, srcMac, ethertype, payloadOffset: ETH_HDR_LEN };
}

export function buildEthernetFrame(
  dstMac: Uint8Array,
  srcMac: Uint8Array,
  ethertype: number,
  payload: Uint8Array,
): Uint8Array {
  if (dstMac.length !== 6 || srcMac.length !== 6) {
    throw new Error("buildEthernetFrame: MAC must be 6 bytes");
  }
  const frame = new Uint8Array(ETH_HDR_LEN + payload.length);
  frame.set(dstMac, 0);
  frame.set(srcMac, 6);
  const dv = new DataView(frame.buffer);
  dv.setUint16(12, ethertype & 0xffff, false);
  frame.set(payload, ETH_HDR_LEN);
  return frame;
}
