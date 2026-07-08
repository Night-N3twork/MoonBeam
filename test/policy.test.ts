/**
 * Tests for src/policy.ts. Per spec §5.9 / §7.
 */

import { describe, it, expect, vi } from 'vitest';
import { EgressPolicy, type BlockedInfo } from '../src/policy';
import { ipToNum } from '../src/packet';

// ---- helpers --------------------------------------------------------------

const TCP = 'tcp' as const;
const UDP = 'udp' as const;

function ip(addr: string): number {
  return ipToNum(addr);
}

// ---- defaults -------------------------------------------------------------

describe('EgressPolicy — defaults', () => {
  const p = new EgressPolicy();

  it('permits a public IP on TCP', () => {
    expect(p.permits(ip('8.8.8.8'), 443, TCP)).toBe(true);
    expect(p.permits(ip('1.1.1.1'), 53, UDP)).toBe(true);
  });

  it('denies RFC1918 192.168.1.1', () => {
    expect(p.permits(ip('192.168.1.1'), 80, TCP)).toBe(false);
  });

  it('denies RFC1918 10.0.0.5', () => {
    expect(p.permits(ip('10.0.0.5'), 443, TCP)).toBe(false);
  });

  it('denies RFC1918 172.16.5.5', () => {
    expect(p.permits(ip('172.16.5.5'), 443, TCP)).toBe(false);
  });

  it('denies loopback 127.0.0.1', () => {
    expect(p.permits(ip('127.0.0.1'), 80, TCP)).toBe(false);
  });

  it('denies link-local 169.254.1.1', () => {
    expect(p.permits(ip('169.254.1.1'), 80, TCP)).toBe(false);
  });

  it('denies multicast 224.0.0.1', () => {
    expect(p.permits(ip('224.0.0.1'), 0, UDP)).toBe(false);
  });

  it('denies broadcast 255.255.255.255', () => {
    expect(p.permits(ip('255.255.255.255'), 67, UDP)).toBe(false);
  });

  it('denies this-network 0.0.0.0', () => {
    expect(p.permits(ip('0.0.0.0'), 80, TCP)).toBe(false);
  });

  it('denies CGNAT 100.64.0.1', () => {
    expect(p.permits(ip('100.64.0.1'), 443, TCP)).toBe(false);
  });

  it('denies IETF benchmark 198.18.0.5', () => {
    expect(p.permits(ip('198.18.0.5'), 80, TCP)).toBe(false);
  });

  it('denies former Class E 240.0.0.1 (gateway TunIP)', () => {
    expect(p.permits(ip('240.0.0.1'), 80, TCP)).toBe(false);
  });

  it('denies docs ranges', () => {
    expect(p.permits(ip('192.0.2.1'), 80, TCP)).toBe(false);
    expect(p.permits(ip('198.51.100.5'), 80, TCP)).toBe(false);
    expect(p.permits(ip('203.0.113.7'), 80, TCP)).toBe(false);
  });
});

// ---- allowLoopback --------------------------------------------------------

describe('EgressPolicy — allowLoopback', () => {
  it('allowLoopback:true lets 127.0.0.1 through but RFC1918 still denied', () => {
    const p = new EgressPolicy({ allowLoopback: true });
    expect(p.permits(ip('127.0.0.1'), 80, TCP)).toBe(true);
    expect(p.permits(ip('192.168.1.1'), 80, TCP)).toBe(false);
  });
});

// ---- explicit CIDR allow --------------------------------------------------

describe('EgressPolicy — explicit CIDR allow', () => {
  it('allow:["10.0.0.0/8"] (no public) permits 10.0.0.42, denies 8.8.8.8', () => {
    const p = new EgressPolicy({ allow: ['10.0.0.0/8'] });
    expect(p.permits(ip('10.0.0.42'), 443, TCP)).toBe(true);
    expect(p.permits(ip('8.8.8.8'), 443, TCP)).toBe(false);
  });

  it('allow:["public","10.0.0.0/8"] permits both 8.8.8.8 and 10.0.0.42', () => {
    const p = new EgressPolicy({ allow: ['public', '10.0.0.0/8'] });
    expect(p.permits(ip('8.8.8.8'), 443, TCP)).toBe(true);
    expect(p.permits(ip('10.0.0.42'), 443, TCP)).toBe(true);
  });

  it('allow:["127.0.0.0/8"] without allowLoopback STILL denies 127.0.0.1', () => {
    const p = new EgressPolicy({ allow: ['127.0.0.0/8'] });
    expect(p.permits(ip('127.0.0.1'), 80, TCP)).toBe(false);
  });

  it('allow:["127.0.0.0/8"] with allowLoopback permits 127.0.0.1', () => {
    const p = new EgressPolicy({
      allow: ['127.0.0.0/8'],
      allowLoopback: true,
    });
    expect(p.permits(ip('127.0.0.1'), 80, TCP)).toBe(true);
  });
});

// ---- wildcard allow -------------------------------------------------------

describe('EgressPolicy — "*" allow', () => {
  it('allow:["*"] permits anything except loopback (still gated)', () => {
    const p = new EgressPolicy({ allow: ['*'] });
    expect(p.permits(ip('8.8.8.8'), 443, TCP)).toBe(true);
    expect(p.permits(ip('192.168.1.1'), 80, TCP)).toBe(true);
    expect(p.permits(ip('10.0.0.5'), 80, TCP)).toBe(true);
    expect(p.permits(ip('169.254.1.1'), 80, TCP)).toBe(true);
    expect(p.permits(ip('224.0.0.1'), 80, UDP)).toBe(true);
    // loopback still gated
    expect(p.permits(ip('127.0.0.1'), 80, TCP)).toBe(false);
  });

  it('allow:["*"] with allowLoopback permits everything including loopback', () => {
    const p = new EgressPolicy({ allow: ['*'], allowLoopback: true });
    expect(p.permits(ip('127.0.0.1'), 80, TCP)).toBe(true);
    expect(p.permits(ip('8.8.8.8'), 443, TCP)).toBe(true);
  });
});

// ---- deny wins over allow -------------------------------------------------

describe('EgressPolicy — deny CIDR overrides allow', () => {
  it('allow:["10.0.0.0/8"] deny:["10.0.0.5/32"] denies the /32', () => {
    const p = new EgressPolicy({
      allow: ['10.0.0.0/8'],
      deny: ['10.0.0.5/32'],
    });
    expect(p.permits(ip('10.0.0.4'), 80, TCP)).toBe(true);
    expect(p.permits(ip('10.0.0.5'), 80, TCP)).toBe(false);
    expect(p.permits(ip('10.0.0.6'), 80, TCP)).toBe(true);
  });

  it('deny CIDR even works against allow:["*"]', () => {
    const p = new EgressPolicy({
      allow: ['*'],
      deny: ['8.8.8.8/32'],
    });
    expect(p.permits(ip('8.8.8.8'), 53, UDP)).toBe(false);
    expect(p.permits(ip('8.8.4.4'), 53, UDP)).toBe(true);
  });
});

// ---- denyPorts ------------------------------------------------------------

describe('EgressPolicy — denyPorts', () => {
  it('denyPorts:[25] blocks port 25 even with allow:["*"]', () => {
    const p = new EgressPolicy({ allow: ['*'], denyPorts: [25] });
    expect(p.permits(ip('8.8.8.8'), 25, TCP)).toBe(false);
    expect(p.permits(ip('8.8.8.8'), 26, TCP)).toBe(true);
    // applies to both TCP and UDP
    expect(p.permits(ip('8.8.8.8'), 25, UDP)).toBe(false);
  });
});

// ---- evaluate() reasons ---------------------------------------------------

describe('EgressPolicy — evaluate() returns specific reasons', () => {
  const p = new EgressPolicy();

  it('rfc1918', () => {
    expect(p.evaluate(ip('192.168.1.1'), 80, TCP)).toEqual({
      allow: false,
      reason: 'rfc1918',
    });
    expect(p.evaluate(ip('10.0.0.5'), 80, TCP)).toEqual({
      allow: false,
      reason: 'rfc1918',
    });
    expect(p.evaluate(ip('172.16.0.1'), 80, TCP)).toEqual({
      allow: false,
      reason: 'rfc1918',
    });
  });

  it('loopback', () => {
    expect(p.evaluate(ip('127.0.0.1'), 80, TCP)).toEqual({
      allow: false,
      reason: 'loopback',
    });
  });

  it('cgnat', () => {
    expect(p.evaluate(ip('100.64.0.1'), 80, TCP)).toEqual({
      allow: false,
      reason: 'cgnat',
    });
  });

  it('link-local', () => {
    expect(p.evaluate(ip('169.254.1.1'), 80, TCP)).toEqual({
      allow: false,
      reason: 'link-local',
    });
  });

  it('multicast', () => {
    expect(p.evaluate(ip('224.0.0.1'), 80, UDP)).toEqual({
      allow: false,
      reason: 'multicast',
    });
  });

  it('broadcast', () => {
    expect(p.evaluate(ip('255.255.255.255'), 80, UDP)).toEqual({
      allow: false,
      reason: 'broadcast',
    });
  });

  it('this-network', () => {
    expect(p.evaluate(ip('0.0.0.0'), 80, TCP)).toEqual({
      allow: false,
      reason: 'this-network',
    });
  });

  it('reserved (Class E, gateway TunIP)', () => {
    expect(p.evaluate(ip('240.0.0.1'), 80, TCP)).toEqual({
      allow: false,
      reason: 'reserved',
    });
  });

  it('reserved (IETF benchmark)', () => {
    expect(p.evaluate(ip('198.18.0.5'), 80, TCP)).toEqual({
      allow: false,
      reason: 'reserved',
    });
  });

  it('public IP on default policy → allow', () => {
    expect(p.evaluate(ip('8.8.8.8'), 443, TCP)).toEqual({ allow: true });
  });

  it('not-in-allow when allow list is restricted and IP is plain public', () => {
    const restricted = new EgressPolicy({ allow: ['10.0.0.0/8'] });
    expect(restricted.evaluate(ip('8.8.8.8'), 443, TCP)).toEqual({
      allow: false,
      reason: 'not-in-allow',
    });
  });

  it('deny-port wins over reserved-range', () => {
    const p2 = new EgressPolicy({ denyPorts: [25] });
    // Even an RFC1918 IP returns deny-port when port matches.
    expect(p2.evaluate(ip('192.168.1.1'), 25, TCP)).toEqual({
      allow: false,
      reason: 'deny-port',
    });
  });

  it('deny-cidr wins over allow', () => {
    const p2 = new EgressPolicy({
      allow: ['*'],
      deny: ['8.8.8.8/32'],
    });
    expect(p2.evaluate(ip('8.8.8.8'), 53, UDP)).toEqual({
      allow: false,
      reason: 'deny-cidr',
    });
  });
});

// ---- onBlocked callback ---------------------------------------------------

describe('EgressPolicy — onBlocked callback', () => {
  it('fires exactly once per denied call with correct info', () => {
    const calls: BlockedInfo[] = [];
    const p = new EgressPolicy({
      onBlocked: (info) => {
        calls.push(info);
      },
    });

    expect(p.permits(ip('192.168.1.1'), 80, TCP)).toBe(false);
    expect(calls.length).toBe(1);
    expect(calls[0]).toEqual({
      ip: '192.168.1.1',
      port: 80,
      proto: 'tcp',
      reason: 'rfc1918',
    });

    expect(p.permits(ip('127.0.0.1'), 22, TCP)).toBe(false);
    expect(calls.length).toBe(2);
    expect(calls[1].reason).toBe('loopback');
    expect(calls[1].ip).toBe('127.0.0.1');
  });

  it('does NOT fire on allowed calls (success path is allocation-free)', () => {
    const cb = vi.fn();
    const p = new EgressPolicy({ onBlocked: cb });

    // 100 allowed calls.
    for (let i = 0; i < 100; i++) {
      expect(p.permits(ip('8.8.8.8'), 443, TCP)).toBe(true);
    }
    expect(cb).not.toHaveBeenCalled();
  });

  it('fires with deny-port reason for port denials', () => {
    const cb = vi.fn();
    const p = new EgressPolicy({ allow: ['*'], denyPorts: [25], onBlocked: cb });
    p.permits(ip('8.8.8.8'), 25, TCP);
    expect(cb).toHaveBeenCalledTimes(1);
    expect(cb.mock.calls[0][0]).toEqual({
      ip: '8.8.8.8',
      port: 25,
      proto: 'tcp',
      reason: 'deny-port',
    });
  });

  it('fires with deny-cidr reason for CIDR denials', () => {
    const cb = vi.fn();
    const p = new EgressPolicy({
      allow: ['*'],
      deny: ['8.8.8.8/32'],
      onBlocked: cb,
    });
    p.permits(ip('8.8.8.8'), 53, UDP);
    expect(cb).toHaveBeenCalledTimes(1);
    expect(cb.mock.calls[0][0].reason).toBe('deny-cidr');
  });
});

// ---- boundary cases -------------------------------------------------------

describe('EgressPolicy — RFC1918 boundary tests (10.0.0.0/8)', () => {
  const p = new EgressPolicy();

  it('9.255.255.255 just outside is permitted', () => {
    expect(p.permits(ip('9.255.255.255'), 80, TCP)).toBe(true);
  });

  it('10.0.0.0 (start of range) is denied', () => {
    expect(p.permits(ip('10.0.0.0'), 80, TCP)).toBe(false);
  });

  it('10.255.255.255 (end of range) is denied', () => {
    expect(p.permits(ip('10.255.255.255'), 80, TCP)).toBe(false);
  });

  it('11.0.0.0 just past is permitted', () => {
    expect(p.permits(ip('11.0.0.0'), 80, TCP)).toBe(true);
  });
});

describe('EgressPolicy — 172.16.0.0/12 boundary tests', () => {
  const p = new EgressPolicy();

  it('172.15.255.255 outside is permitted', () => {
    expect(p.permits(ip('172.15.255.255'), 80, TCP)).toBe(true);
  });

  it('172.16.0.0 start denied', () => {
    expect(p.permits(ip('172.16.0.0'), 80, TCP)).toBe(false);
  });

  it('172.31.255.255 end denied', () => {
    expect(p.permits(ip('172.31.255.255'), 80, TCP)).toBe(false);
  });

  it('172.32.0.0 just past permitted', () => {
    expect(p.permits(ip('172.32.0.0'), 80, TCP)).toBe(true);
  });
});

describe('EgressPolicy — 240.0.0.0/4 (Class E) boundary', () => {
  const p = new EgressPolicy();

  it('239.255.255.255 is multicast (224.0.0.0/4 covers it) → denied', () => {
    expect(p.permits(ip('239.255.255.255'), 80, UDP)).toBe(false);
  });

  it('240.0.0.0 start denied', () => {
    expect(p.permits(ip('240.0.0.0'), 80, TCP)).toBe(false);
  });

  it('255.255.255.254 in class E denied', () => {
    expect(p.permits(ip('255.255.255.254'), 80, TCP)).toBe(false);
  });
});

describe('EgressPolicy — proto field passthrough', () => {
  it('onBlocked sees correct proto', () => {
    const calls: BlockedInfo[] = [];
    const p = new EgressPolicy({ onBlocked: (i) => calls.push(i) });
    p.permits(ip('192.168.1.1'), 80, TCP);
    p.permits(ip('192.168.1.1'), 80, UDP);
    expect(calls.map((c) => c.proto)).toEqual(['tcp', 'udp']);
  });
});

describe('EgressPolicy — empty allow list', () => {
  it('allow:[] denies everything (no allow token can match)', () => {
    const p = new EgressPolicy({ allow: [] });
    expect(p.permits(ip('8.8.8.8'), 443, TCP)).toBe(false);
    expect(p.evaluate(ip('8.8.8.8'), 443, TCP)).toEqual({
      allow: false,
      reason: 'not-in-allow',
    });
  });
});
