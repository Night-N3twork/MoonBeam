/**
 * DHCP server bound on lwIP UDP:67. Serves the single guest VM.
 *
 * Behavior per spec §8 of `docs/specs/2026-05-27-vm-wisp-networking-design.md`.
 *
 * Flow:
 *   DISCOVER -> OFFER  (yiaddr=vmIp, options for mask/router/dns/lease/server-id)
 *   REQUEST  -> ACK if requested IP matches vmIp, else NAK
 *   RELEASE  -> log; no reply
 *   DECLINE  -> log warning; no reply
 *
 * No lease table is maintained: there is exactly one client (the VM) and we
 * always offer it the same IP. Replies are sent to broadcast 255.255.255.255:68
 * via the UDP socket; lwIP handles the L2/L3 plumbing.
 *
 * Frame layout (BOOTP/DHCP):
 *   0      op        (1=request, 2=reply)
 *   1      htype     (1=ethernet)
 *   2      hlen      (6 for ethernet MAC)
 *   3      hops      (0)
 *   4..7   xid       (transaction ID; echoed)
 *   8..9   secs      (0)
 *   10..11 flags
 *   12..15 ciaddr
 *   16..19 yiaddr    (server fills in)
 *   20..23 siaddr
 *   24..27 giaddr
 *   28..43 chaddr    (client MAC, padded with zeros to 16 bytes)
 *   44..107 sname    (empty)
 *   108..235 file    (empty)
 *   236..239 magic   (0x63 82 53 63)
 *   240..  options   (TLV; 0xff terminator)
 */

import type { NetworkStack, UdpSocket } from 'tcpip';
import { numToIp } from './packet';

// ---------------------------------------------------------------------------
// DHCP constants (RFC 2131 / 2132)
// ---------------------------------------------------------------------------

const DHCP_MAGIC_COOKIE = 0x63825363;

const DHCP_OP_REQUEST = 1;
const DHCP_OP_REPLY = 2;

// Message types (option 53 values)
const DHCP_DISCOVER = 1;
const DHCP_OFFER = 2;
const DHCP_REQUEST = 3;
const DHCP_DECLINE = 4;
const DHCP_ACK = 5;
const DHCP_NAK = 6;
const DHCP_RELEASE = 7;

// Option codes
const OPT_PAD = 0;
const OPT_SUBNET_MASK = 1;
const OPT_ROUTER = 3;
const OPT_DNS_SERVER = 6;
const OPT_HOSTNAME = 12;
const OPT_REQUESTED_IP = 50;
const OPT_LEASE_TIME = 51;
const OPT_MSG_TYPE = 53;
const OPT_SERVER_ID = 54;
const OPT_PARAM_REQUEST_LIST = 55;
const OPT_END = 255;

const DHCP_HEADER_LEN = 240; // up to and including magic cookie
const DHCP_BUF_LEN = 576;
const DHCP_MIN_PACKET_LEN = 300;
const DHCP_CLIENT_PORT = 68;
const DHCP_SERVER_PORT = 67;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface DhcpServiceConfig {
  /** tcpip.js NetworkStack. We bind on `stack.openUdp({port: 67})`. */
  stack: NetworkStack;
  /** Gateway IP (uint32). Also used as DHCP server identifier. */
  gatewayIp: number;
  /** Subnet mask (uint32). */
  subnetMask: number;
  /** IP to assign to the VM. */
  vmIp: number;
  /** DNS server to advertise. The Gateway defaults this to 1.1.1.1. */
  dnsServer: number;
  /** Lease duration in seconds. Default 86400 (1 day). */
  leaseTime?: number;
}

interface DhcpMessage {
  op: number;
  htype: number;
  hlen: number;
  xid: number;
  flags: number;
  ciaddr: number;
  yiaddr: number;
  siaddr: number;
  giaddr: number;
  /** 16 bytes — first `hlen` are the MAC, rest is zero padding. */
  chaddr: Uint8Array;
  options: Map<number, Uint8Array>;
}

// ---------------------------------------------------------------------------
// DhcpService
// ---------------------------------------------------------------------------

export class DhcpService {
  private readonly stack: NetworkStack;
  private readonly gatewayIp: number;
  private readonly subnetMask: number;
  private readonly vmIp: number;
  private readonly dnsServer: number;
  private readonly leaseTime: number;

  private socket: UdpSocket | null = null;
  private reader: ReadableStreamDefaultReader<{ host: string; port: number; data: Uint8Array }> | null = null;
  private writer: WritableStreamDefaultWriter<{ host: string; port: number; data: Uint8Array }> | null = null;
  private running = false;
  private readLoopDone: Promise<void> | null = null;

  constructor(config: DhcpServiceConfig) {
    this.stack = config.stack;
    this.gatewayIp = config.gatewayIp >>> 0;
    this.subnetMask = config.subnetMask >>> 0;
    this.vmIp = config.vmIp >>> 0;
    this.dnsServer = config.dnsServer >>> 0;
    this.leaseTime = config.leaseTime ?? 86400;
  }

  async start(): Promise<void> {
    if (this.running) return;
    this.socket = await this.stack.openUdp({ port: DHCP_SERVER_PORT });
    this.running = true;
    this.reader = this.socket.readable.getReader();
    this.writer = this.socket.writable.getWriter();
    this.readLoopDone = this._readLoop();
  }

  async destroy(): Promise<void> {
    if (!this.running && !this.socket) return;
    this.running = false;

    // Cancel reader first so the read loop exits.
    if (this.reader) {
      try { await this.reader.cancel(); } catch { /* ignore */ }
      try { this.reader.releaseLock(); } catch { /* ignore */ }
      this.reader = null;
    }
    if (this.writer) {
      try { this.writer.releaseLock(); } catch { /* ignore */ }
      this.writer = null;
    }
    if (this.socket) {
      try { await this.socket.close(); } catch { /* ignore */ }
      this.socket = null;
    }
    if (this.readLoopDone) {
      try { await this.readLoopDone; } catch { /* ignore */ }
      this.readLoopDone = null;
    }
  }

  // -------------------------------------------------------------------------
  // Read loop
  // -------------------------------------------------------------------------

  private async _readLoop(): Promise<void> {
    const reader = this.reader;
    if (!reader) return;
    try {
      while (this.running) {
        const { done, value } = await reader.read();
        if (done) break;
        try {
          await this._handleDatagram(value.data);
        } catch (err) {
          // Don't let a single bad datagram kill the loop.
          // eslint-disable-next-line no-console
          console.error('[DHCP] error handling datagram:', err);
        }
      }
    } catch (err) {
      if (this.running) {
        // eslint-disable-next-line no-console
        console.error('[DHCP] read loop error:', err);
      }
    }
  }

  // -------------------------------------------------------------------------
  // Message dispatch
  // -------------------------------------------------------------------------

  private async _handleDatagram(data: Uint8Array): Promise<void> {
    const msg = parseDhcp(data);
    if (!msg) return;

    const msgTypeOpt = msg.options.get(OPT_MSG_TYPE);
    if (!msgTypeOpt || msgTypeOpt.length < 1) return;
    const msgType = msgTypeOpt[0]!;

    switch (msgType) {
      case DHCP_DISCOVER:
        await this._sendReply(msg, DHCP_OFFER);
        return;

      case DHCP_REQUEST: {
        // If client included a server identifier and it's not us, ignore.
        const serverIdOpt = msg.options.get(OPT_SERVER_ID);
        if (serverIdOpt && serverIdOpt.length >= 4) {
          const sid = readUint32BE(serverIdOpt, 0);
          if (sid !== this.gatewayIp) return;
        }

        // Determine the IP the client wants. The client may signal it via
        // option 50 (Requested IP) when in SELECTING/INIT-REBOOT, or via
        // ciaddr when in RENEWING. Either MUST equal our vmIp.
        let requested: number | null = null;
        const reqIpOpt = msg.options.get(OPT_REQUESTED_IP);
        if (reqIpOpt && reqIpOpt.length >= 4) {
          requested = readUint32BE(reqIpOpt, 0);
        } else if (msg.ciaddr !== 0) {
          requested = msg.ciaddr;
        }

        if (requested !== null && requested !== this.vmIp) {
          await this._sendReply(msg, DHCP_NAK);
          return;
        }
        await this._sendReply(msg, DHCP_ACK);
        return;
      }

      case DHCP_RELEASE:
        // Just log; no reply per RFC 2131.
        // eslint-disable-next-line no-console
        console.log(`[DHCP] RELEASE from ${formatMac(msg.chaddr, msg.hlen)}`);
        return;

      case DHCP_DECLINE:
        // eslint-disable-next-line no-console
        console.warn(
          `[DHCP] DECLINE from ${formatMac(msg.chaddr, msg.hlen)} ` +
            `(client says ${numToIp(this.vmIp)} is in use); continuing to serve.`,
        );
        return;

      default:
        return;
    }
  }

  private async _sendReply(request: DhcpMessage, msgType: number): Promise<void> {
    const data = this._buildReply(request, msgType);
    const writer = this.writer;
    if (!writer) return;
    try {
      await writer.write({
        host: '255.255.255.255',
        port: DHCP_CLIENT_PORT,
        data,
      });
    } catch (err) {
      if (this.running) {
        // eslint-disable-next-line no-console
        console.error('[DHCP] failed to send reply:', err);
      }
    }
  }

  // -------------------------------------------------------------------------
  // Reply builder
  // -------------------------------------------------------------------------

  private _buildReply(request: DhcpMessage, msgType: number): Uint8Array {
    const buf = new Uint8Array(DHCP_BUF_LEN);
    const dv = new DataView(buf.buffer);

    // Fixed header
    buf[0] = DHCP_OP_REPLY;
    buf[1] = request.htype;
    buf[2] = request.hlen;
    buf[3] = 0; // hops
    dv.setUint32(4, request.xid >>> 0, false);
    dv.setUint16(8, 0, false); // secs
    dv.setUint16(10, request.flags & 0xffff, false);
    // ciaddr (12..15) left as 0.
    if (msgType !== DHCP_NAK) {
      dv.setUint32(16, this.vmIp, false); // yiaddr
      dv.setUint32(20, this.gatewayIp, false); // siaddr (server address)
    }
    // giaddr left as 0 (per spec §8: "giaddr = 0").
    // chaddr (28..43)
    buf.set(request.chaddr.subarray(0, 16), 28);
    // sname (44..107) and file (108..235) left as zeros.
    dv.setUint32(236, DHCP_MAGIC_COOKIE, false);

    // Options
    let off = DHCP_HEADER_LEN;

    // 53: DHCP Message Type
    off = writeOption(buf, off, OPT_MSG_TYPE, [msgType]);
    // 54: Server Identifier
    off = writeOptionUint32(buf, off, OPT_SERVER_ID, this.gatewayIp);

    if (msgType !== DHCP_NAK) {
      // 51: Lease Time
      off = writeOptionUint32(buf, off, OPT_LEASE_TIME, this.leaseTime);
      // 1: Subnet Mask
      off = writeOptionUint32(buf, off, OPT_SUBNET_MASK, this.subnetMask);
      // 3: Router (Gateway)
      off = writeOptionUint32(buf, off, OPT_ROUTER, this.gatewayIp);
      // 6: DNS Server
      off = writeOptionUint32(buf, off, OPT_DNS_SERVER, this.dnsServer);
    }

    // 255: End
    buf[off++] = OPT_END;

    // Pad to BOOTP minimum to keep finicky clients happy.
    const length = Math.max(off, DHCP_MIN_PACKET_LEN);
    return buf.slice(0, length);
  }
}

// ---------------------------------------------------------------------------
// DHCP packet parsing — exported only via the message handler; kept private.
// ---------------------------------------------------------------------------

function parseDhcp(data: Uint8Array): DhcpMessage | null {
  if (data.byteLength < DHCP_HEADER_LEN) return null;

  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);

  // Magic cookie check first — cheapest way to reject non-DHCP UDP.
  if (dv.getUint32(236, false) !== DHCP_MAGIC_COOKIE) return null;

  const op = data[0]!;
  if (op !== DHCP_OP_REQUEST) return null; // we only handle client-originated packets

  const htype = data[1]!;
  const hlen = data[2]!;
  // Sanity-check hlen fits in chaddr field.
  if (hlen > 16) return null;

  const msg: DhcpMessage = {
    op,
    htype,
    hlen,
    xid: dv.getUint32(4, false),
    flags: dv.getUint16(10, false),
    ciaddr: dv.getUint32(12, false),
    yiaddr: dv.getUint32(16, false),
    siaddr: dv.getUint32(20, false),
    giaddr: dv.getUint32(24, false),
    chaddr: data.slice(28, 44),
    options: new Map(),
  };

  // TLV options. Tolerate truncation: silently stop if we run out of bytes.
  let offset = DHCP_HEADER_LEN;
  const end = data.byteLength;
  while (offset < end) {
    const code = data[offset++]!;
    if (code === OPT_END) break;
    if (code === OPT_PAD) continue;
    if (offset >= end) break; // truncated length byte
    const len = data[offset++]!;
    if (offset + len > end) break; // truncated value
    // Last write wins on duplicate option codes (RFC permits).
    msg.options.set(code, data.slice(offset, offset + len));
    offset += len;
  }

  return msg;
}

// ---------------------------------------------------------------------------
// Option writers
// ---------------------------------------------------------------------------

function writeOption(buf: Uint8Array, offset: number, code: number, value: ArrayLike<number>): number {
  buf[offset++] = code;
  buf[offset++] = value.length;
  for (let i = 0; i < value.length; i++) buf[offset++] = value[i]! & 0xff;
  return offset;
}

function writeOptionUint32(buf: Uint8Array, offset: number, code: number, value: number): number {
  buf[offset++] = code;
  buf[offset++] = 4;
  const v = value >>> 0;
  buf[offset++] = (v >>> 24) & 0xff;
  buf[offset++] = (v >>> 16) & 0xff;
  buf[offset++] = (v >>> 8) & 0xff;
  buf[offset++] = v & 0xff;
  return offset;
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

function readUint32BE(buf: Uint8Array, offset: number): number {
  return (
    ((buf[offset]! << 24) >>> 0) |
    (buf[offset + 1]! << 16) |
    (buf[offset + 2]! << 8) |
    buf[offset + 3]!
  ) >>> 0;
}

function formatMac(chaddr: Uint8Array, hlen: number): string {
  const n = Math.min(hlen || 6, chaddr.length, 6);
  const parts: string[] = [];
  for (let i = 0; i < n; i++) parts.push(chaddr[i]!.toString(16).padStart(2, '0'));
  return parts.join(':');
}
