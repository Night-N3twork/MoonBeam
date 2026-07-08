/**
 * Egress policy: decides whether a given (ipNum, port, proto) may be forwarded
 * out through Wisp. Pure / synchronous / allocation-free in the success path.
 *
 * Per spec §7 of `docs/specs/2026-05-27-vm-wisp-networking-design.md`.
 */

import { parseCidr, numToIp } from './packet';

/** Compute the inclusive [start, end] uint32 bounds of a CIDR string. */
function cidrToRange(cidr: string): { start: number; end: number } {
  const { ip, mask } = parseCidr(cidr);
  const start = (ip & mask) >>> 0;
  const end = (start | (~mask >>> 0)) >>> 0;
  return { start, end };
}

export type CidrToken = string | 'public' | '*';

export interface EgressPolicyConfig {
  allow?: CidrToken[];
  deny?: string[];
  allowLoopback?: boolean;
  denyPorts?: number[];
  onBlocked?: (info: BlockedInfo) => void;
}

export interface BlockedInfo {
  ip: string;
  port: number;
  proto: 'tcp' | 'udp';
  reason:
    | 'this-network'
    | 'rfc1918'
    | 'cgnat'
    | 'loopback'
    | 'link-local'
    | 'multicast'
    | 'broadcast'
    | 'reserved'
    | 'deny-cidr'
    | 'deny-port'
    | 'not-in-allow';
}

type ReservedReason = Exclude<
  BlockedInfo['reason'],
  'deny-cidr' | 'deny-port' | 'not-in-allow'
>;

/** The IANA special-use IPv4 ranges that define what is NOT "public".
 *  Order here doesn't matter — we sort by start IP at compile time. */
const RESERVED_RANGES: ReadonlyArray<{
  cidr: string;
  reason: ReservedReason;
}> = [
  { cidr: '0.0.0.0/8', reason: 'this-network' },
  { cidr: '10.0.0.0/8', reason: 'rfc1918' },
  { cidr: '100.64.0.0/10', reason: 'cgnat' },
  { cidr: '127.0.0.0/8', reason: 'loopback' },
  { cidr: '169.254.0.0/16', reason: 'link-local' },
  { cidr: '172.16.0.0/12', reason: 'rfc1918' },
  { cidr: '192.0.0.0/24', reason: 'reserved' },
  { cidr: '192.0.2.0/24', reason: 'reserved' },
  { cidr: '192.88.99.0/24', reason: 'reserved' },
  { cidr: '192.168.0.0/16', reason: 'rfc1918' },
  { cidr: '198.18.0.0/15', reason: 'reserved' },
  { cidr: '198.51.100.0/24', reason: 'reserved' },
  { cidr: '203.0.113.0/24', reason: 'reserved' },
  { cidr: '224.0.0.0/4', reason: 'multicast' },
  // 240.0.0.0/4 (former Class E) — NOTE: gateway TunIP 240.0.0.1 lives here
  // intentionally; lwIP intercepts that locally before NAT/policy see it.
  { cidr: '240.0.0.0/4', reason: 'reserved' },
  // 255.255.255.255/32 is technically inside 240.0.0.0/4 (overlap), so it's
  // NOT in this table — see `_isInReserved` which special-cases it for
  // the more-specific 'broadcast' reason.
];

/** Limited-broadcast address; checked as a special case to override the
 *  surrounding 240.0.0.0/4 reserved range with the more-specific reason. */
const BROADCAST_IP = 0xffffffff;

type AllowToken =
  | { kind: 'star' }
  | { kind: 'public' }
  | { kind: 'cidr'; start: number; end: number };

interface Range {
  start: number;
  end: number;
}

export class EgressPolicy {
  private readonly _allowTokens: ReadonlyArray<AllowToken>;
  private readonly _denyList: ReadonlyArray<Range>;
  private readonly _denyPorts: Set<number>;
  private readonly _allowLoopback: boolean;
  private readonly _onBlocked: ((info: BlockedInfo) => void) | undefined;

  // Parallel arrays for the precomputed reserved-range table.
  // Sorted by `_reservedStarts[i]` ascending; ranges are disjoint by
  // construction (the IANA list contains no overlaps).
  private readonly _reservedStarts: Uint32Array;
  private readonly _reservedEnds: Uint32Array;
  private readonly _reservedReasons: ReadonlyArray<ReservedReason>;

  // Cached bounds of 127.0.0.0/8 — looked up so frequently that a dedicated
  // pair of uints is worth it.
  private readonly _loopbackStart: number;
  private readonly _loopbackEnd: number;

  constructor(config: EgressPolicyConfig = {}) {
    const allow = config.allow ?? ['public'];
    const deny = config.deny ?? [];
    this._allowLoopback = config.allowLoopback ?? false;
    this._denyPorts = new Set(config.denyPorts ?? []);
    this._onBlocked = config.onBlocked;

    this._allowTokens = allow.map<AllowToken>((tok) => {
      if (tok === '*') return { kind: 'star' };
      if (tok === 'public') return { kind: 'public' };
      const { start, end } = cidrToRange(tok);
      return { kind: 'cidr', start, end };
    });

    this._denyList = deny.map<Range>((cidr) => cidrToRange(cidr));

    // Build sorted reserved-range tables.
    const compiled = RESERVED_RANGES.map(({ cidr, reason }) => {
      const { start, end } = cidrToRange(cidr);
      return { start, end, reason };
    }).sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0));

    this._reservedStarts = new Uint32Array(compiled.length);
    this._reservedEnds = new Uint32Array(compiled.length);
    const reasons: ReservedReason[] = [];
    for (let i = 0; i < compiled.length; i++) {
      this._reservedStarts[i] = compiled[i].start;
      this._reservedEnds[i] = compiled[i].end;
      reasons.push(compiled[i].reason);
    }
    this._reservedReasons = reasons;

    // Loopback bounds: precomputed for the hot path.
    const lb = cidrToRange('127.0.0.0/8');
    this._loopbackStart = lb.start;
    this._loopbackEnd = lb.end;
  }

  permits(ipNum: number, port: number, proto: 'tcp' | 'udp'): boolean {
    // 1. Hard port deny (always wins).
    if (this._denyPorts.has(port)) {
      this._fireBlocked(ipNum, port, proto, 'deny-port');
      return false;
    }

    // 2. Hard CIDR deny (wins over allow).
    for (let i = 0; i < this._denyList.length; i++) {
      const r = this._denyList[i];
      if (ipNum >= r.start && ipNum <= r.end) {
        this._fireBlocked(ipNum, port, proto, 'deny-cidr');
        return false;
      }
    }

    // 3. Allow check.
    const inLoopback = this._inLoopback(ipNum);
    for (let i = 0; i < this._allowTokens.length; i++) {
      const tok = this._allowTokens[i];
      if (tok.kind === 'star') {
        // '*' bypasses the public/reserved distinction, but loopback is still
        // gated behind allowLoopback — routing localhost through a remote
        // Wisp server is almost always a mistake.
        if (inLoopback && !this._allowLoopback) continue;
        return true;
      }
      if (tok.kind === 'public') {
        if (inLoopback) {
          if (this._allowLoopback) return true;
          continue;
        }
        if (this._isInReserved(ipNum) !== null) continue;
        return true;
      }
      // CIDR token.
      if (ipNum >= tok.start && ipNum <= tok.end) {
        // Loopback exception: even an explicit `allow: ['127.0.0.0/8']` does
        // not enable loopback unless `allowLoopback: true`.
        if (inLoopback && !this._allowLoopback) continue;
        return true;
      }
    }

    // 4. Deny with the most-specific reason.
    const reservedReason = this._isInReserved(ipNum);
    const reason: BlockedInfo['reason'] = reservedReason ?? 'not-in-allow';
    this._fireBlocked(ipNum, port, proto, reason);
    return false;
  }

  evaluate(
    ipNum: number,
    port: number,
    proto: 'tcp' | 'udp',
  ): { allow: true } | { allow: false; reason: BlockedInfo['reason'] } {
    // Mirror permits() exactly, but return reason instead of firing onBlocked.
    // We could refactor to share code, but the success-path allocation-free
    // requirement on permits() makes the duplication preferable to a
    // branchier shared helper.
    if (this._denyPorts.has(port)) return { allow: false, reason: 'deny-port' };

    for (let i = 0; i < this._denyList.length; i++) {
      const r = this._denyList[i];
      if (ipNum >= r.start && ipNum <= r.end) {
        return { allow: false, reason: 'deny-cidr' };
      }
    }

    const inLoopback = this._inLoopback(ipNum);
    for (let i = 0; i < this._allowTokens.length; i++) {
      const tok = this._allowTokens[i];
      if (tok.kind === 'star') {
        if (inLoopback && !this._allowLoopback) continue;
        return { allow: true };
      }
      if (tok.kind === 'public') {
        if (inLoopback) {
          if (this._allowLoopback) return { allow: true };
          continue;
        }
        if (this._isInReserved(ipNum) !== null) continue;
        return { allow: true };
      }
      if (ipNum >= tok.start && ipNum <= tok.end) {
        if (inLoopback && !this._allowLoopback) continue;
        return { allow: true };
      }
    }

    const reservedReason = this._isInReserved(ipNum);
    return { allow: false, reason: reservedReason ?? 'not-in-allow' };
  }

  // ---------------------------------------------------------------------
  // Internal helpers.
  // ---------------------------------------------------------------------

  private _inLoopback(ip: number): boolean {
    return ip >= this._loopbackStart && ip <= this._loopbackEnd;
  }

  /**
   * Binary search over disjoint sorted ranges. Returns the reason string of
   * the matching range, or null if the IP is not reserved.
   * Returns a string literal (interned) — does not allocate.
   */
  private _isInReserved(ip: number): ReservedReason | null {
    // Most-specific match first: 255.255.255.255 is inside 240.0.0.0/4 but
    // deserves the dedicated 'broadcast' reason.
    if (ip === BROADCAST_IP) return 'broadcast';

    const starts = this._reservedStarts;
    const ends = this._reservedEnds;
    let lo = 0;
    let hi = starts.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      if (ip < starts[mid]) {
        hi = mid - 1;
      } else if (ip > ends[mid]) {
        lo = mid + 1;
      } else {
        return this._reservedReasons[mid];
      }
    }
    return null;
  }

  private _fireBlocked(
    ipNum: number,
    port: number,
    proto: 'tcp' | 'udp',
    reason: BlockedInfo['reason'],
  ): void {
    const cb = this._onBlocked;
    if (cb === undefined) return;
    // Allocation only happens here — i.e. only in the failure path.
    cb({ ip: numToIp(ipNum), port, proto, reason });
  }
}
