// DHCP over shm: DORA, using the lease to ping the gateway, a second client,
// renew, NAK for a foreign address, release, and a separate DHCP server IP.
// Run with `./build.sh test`.
import fs from "node:fs";
import assert from "node:assert/strict";
import init, * as wasm from "../../pkg/moonbeam.js";
import { Moonbeam } from "../moonbeam.js";
import { ShmLink } from "../client.js";

await init({ module_or_path: fs.readFileSync(new URL("../../pkg/moonbeam_bg.wasm", import.meta.url)) });

const GW = [10, 0, 0, 1];
const ROUTER = [0x02, 0x6e, 0x69, 0x67, 0x68, 0x74];
const BCAST = [255, 255, 255, 255, 255, 255];
const mb = Moonbeam.start(wasm, { gatewayIp: GW });

const withTimeout = (p, ms, what) =>
  Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error("timeout: " + what)), ms))]);

function csum(b, s, e) {
  let x = 0;
  for (let i = s; i < e; i += 2) x += (b[i] << 8) | (b[i + 1] ?? 0);
  while (x >> 16) x = (x & 0xffff) + (x >> 16);
  return ~x & 0xffff;
}

// --- building client frames ---
function udpFrame(srcMac, dstMac, srcIp, dstIp, sport, dport, payload) {
  const f = new Uint8Array(14 + 20 + 8 + payload.length);
  f.set(dstMac, 0); f.set(srcMac, 6); f.set([8, 0], 12);
  const ipLen = 20 + 8 + payload.length;
  f.set([0x45, 0, ipLen >> 8, ipLen & 0xff, 0, 0, 0, 0, 64, 17, 0, 0], 14);
  f.set(srcIp, 26); f.set(dstIp, 30);
  const c = csum(f, 14, 34); f[24] = c >> 8; f[25] = c & 0xff;
  const udpLen = 8 + payload.length;
  f.set([sport >> 8, sport & 0xff, dport >> 8, dport & 0xff, udpLen >> 8, udpLen & 0xff, 0, 0], 34);
  f.set(payload, 42);
  return f;
}

let xidCounter = 0x1000;
function dhcpMsg(mac, type, { ciaddr = [0, 0, 0, 0], requested, server, broadcast = false } = {}) {
  const opts = [53, 1, type, 55, 3, 1, 3, 6, 12, 4, 0x74, 0x65, 0x73, 0x74]; // incl. options the old parser choked on
  if (requested) opts.push(50, 4, ...requested);
  if (server) opts.push(54, 4, ...server);
  opts.push(255);
  const m = new Uint8Array(240 + opts.length);
  m.set([1, 1, 6, 0], 0);
  const xid = xidCounter++;
  m.set([xid >>> 24, (xid >> 16) & 0xff, (xid >> 8) & 0xff, xid & 0xff], 4);
  if (broadcast) m[10] = 0x80;
  m.set(ciaddr, 12);
  m.set(mac, 28);
  m.set([0x63, 0x82, 0x53, 0x63], 236);
  m.set(opts, 240);
  return { m, xid };
}

// --- parsing replies ---
function parseDhcp(f) {
  assert.deepEqual([...f.slice(12, 14)], [8, 0], "ipv4");
  assert.equal(f[23], 17, "udp");
  assert.equal(csum(f, 14, 34), 0, "valid ip checksum");
  assert.equal((f[34] << 8) | f[35], 67, "from server port");
  assert.equal((f[36] << 8) | f[37], 68, "to client port");
  const ipLen = (f[16] << 8) | f[17];
  const udpLen = (f[38] << 8) | f[39];
  assert.equal(ipLen, f.length - 14, "ip total length");
  assert.equal(udpLen, f.length - 34, "udp length");
  const m = f.slice(42);
  assert.equal(m[0], 2, "BOOTREPLY");
  assert.deepEqual([...m.slice(236, 240)], [0x63, 0x82, 0x53, 0x63], "magic");
  const opts = {};
  for (let i = 240; i < m.length && m[i] !== 255; ) {
    if (m[i] === 0) { i++; continue; }
    assert.equal(opts[m[i]], undefined, `option ${m[i]} appears once`);
    opts[m[i]] = [...m.slice(i + 2, i + 2 + m[i + 1])];
    i += 2 + m[i + 1];
  }
  return {
    dstMac: [...f.slice(0, 6)], srcMac: [...f.slice(6, 12)],
    srcIp: [...f.slice(26, 30)], dstIp: [...f.slice(30, 34)],
    xid: (m[4] << 24 >>> 0) + (m[5] << 16) + (m[6] << 8) + m[7],
    yiaddr: [...m.slice(16, 20)], chaddr: [...m.slice(28, 34)],
    type: opts[53]?.[0], opts,
  };
}

async function client(mac, memPages = 16) {
  const memory = new WebAssembly.Memory({ initial: memPages, maximum: memPages, shared: true });
  const link = ShmLink.create(memory.buffer, 0, { slotCount: 16 });
  await mb.addShm({ memory, offset: 0, mac });
  await link.attached();
  const it = link.frames()[Symbol.asyncIterator]();
  const all = (what) => withTimeout(it.next().then((r) => r.value), 1000, what);
  return {
    mac, link,
    send: (f) => assert.ok(link.send(f), "send"),
    all,
    // next DHCP reply, skipping unrelated traffic (ARP etc.)
    async dhcp(what) {
      for (;;) {
        const f = await all(what);
        if (f[12] === 8 && f[13] === 0 && f[23] === 17 && ((f[34] << 8) | f[35]) === 67) return parseDhcp(f);
      }
    },
  };
}

function sendDhcp(c, type, opts) {
  const { m, xid } = dhcpMsg(c.mac, type, opts);
  const src = opts?.ciaddr ?? [0, 0, 0, 0];
  const dstIp = opts?.unicastTo ?? [255, 255, 255, 255];
  const dstMac = opts?.unicastMac ?? BCAST;
  c.send(udpFrame(c.mac, dstMac, src, dstIp, 68, 67, m));
  return xid;
}

async function dora(c, opts = {}) {
  const x1 = sendDhcp(c, 1, opts);
  const offer = await c.dhcp("offer");
  assert.equal(offer.type, 2, "OFFER");
  assert.equal(offer.xid, x1, "offer xid");
  assert.deepEqual(offer.chaddr, c.mac);
  const x2 = sendDhcp(c, 3, { ...opts, requested: offer.yiaddr, server: offer.opts[54] });
  const ack = await c.dhcp("ack");
  assert.equal(ack.type, 5, "ACK");
  assert.equal(ack.xid, x2, "ack xid");
  assert.deepEqual(ack.yiaddr, offer.yiaddr);
  return { offer, ack };
}

// 1. DORA, unicast replies
const a = await client([2, 0, 0, 0, 0, 0xa]);
const { offer, ack } = await dora(a);
assert.deepEqual(offer.dstMac, a.mac, "offer unicast to chaddr");
assert.deepEqual(offer.dstIp, offer.yiaddr, "offer unicast to yiaddr");
assert.deepEqual(offer.srcMac, ROUTER, "server shares the gateway's MAC");
assert.deepEqual(offer.srcIp, GW);
assert.deepEqual(ack.opts[1], [255, 255, 255, 0], "subnet");
assert.deepEqual(ack.opts[3], GW, "router");
assert.deepEqual(ack.opts[54], GW, "server id");
assert.equal(ack.opts[51].length, 4, "lease time");
const ipA = ack.yiaddr;
assert.equal(ipA[3], 100, "first lease is .100");
console.log("dora ok:", ipA.join("."));

// 2. the lease works: ping the gateway from it
{
  const f = new Uint8Array(14 + 20 + 8);
  f.set(ROUTER, 0); f.set(a.mac, 6); f.set([8, 0], 12);
  f.set([0x45, 0, 0, 28, 0, 1, 0, 0, 64, 1, 0, 0], 14); f.set(ipA, 26); f.set(GW, 30);
  const c = csum(f, 14, 34); f[24] = c >> 8; f[25] = c & 0xff;
  f.set([8, 0, 0, 0, 0, 1, 0, 1], 34);
  const c2 = csum(f, 34, 42); f[36] = c2 >> 8; f[37] = c2 & 0xff;
  a.send(f);
  // lwip ARPs for ipA first; answer it
  for (;;) {
    const r = await a.all("ping reply");
    if (r[12] === 8 && r[13] === 6 && r[21] === 1) {
      const rep = new Uint8Array(42);
      rep.set(r.slice(6, 12), 0); rep.set(a.mac, 6); rep.set([8, 6, 0, 1, 8, 0, 6, 4, 0, 2], 12);
      rep.set(a.mac, 22); rep.set(ipA, 28); rep.set(r.slice(22, 32), 32);
      a.send(rep);
      continue;
    }
    if (r[12] === 8 && r[13] === 0 && r[23] === 1) {
      assert.equal(r[34], 0, "echo reply");
      assert.deepEqual([...r.slice(30, 34)], ipA);
      break;
    }
  }
  console.log("ping from leased address ok");
}

// 3. second client gets a different address; broadcast flag honoured
const b = await client([2, 0, 0, 0, 0, 0xb]);
const lb = await dora(b, { broadcast: true });
assert.deepEqual(lb.offer.dstMac, BCAST, "broadcast flag -> broadcast reply");
assert.deepEqual(lb.offer.dstIp, [255, 255, 255, 255]);
assert.notDeepEqual(lb.ack.yiaddr, ipA, "distinct leases");
console.log("second client ok:", lb.ack.yiaddr.join("."));
// a's DHCP traffic must not have leaked to b, nor b's broadcast DISCOVER to a
await new Promise((r) => setTimeout(r, 20));
// b's broadcast-flagged OFFER/ACK correctly reach everyone, but b's own
// DISCOVER/REQUEST (to port 67) must have been consumed by the server
for (let f; (f = a.link.receive()) !== null; ) {
  const toServer = f[12] === 8 && f[13] === 0 && f[23] === 17 && ((f[36] << 8) | f[37]) === 67;
  console.log("  a saw:", toServer ? "client->server DHCP (leak!)" : `${f[23] === 17 ? "dhcp reply" : "other"} from ${[...f.slice(6, 12)].map((x) => x.toString(16)).join(":")}`);
  assert.ok(!toServer, "client DHCP requests not leaked to other clients");
}

// 4. renew from the bound address (unicast to the server, ciaddr set)
{
  sendDhcp(a, 3, { ciaddr: ipA, unicastTo: GW, unicastMac: ROUTER });
  const r = await a.dhcp("renew ack");
  assert.equal(r.type, 5, "renew ACK");
  assert.deepEqual(r.dstIp, ipA, "renew reply to ciaddr");
  console.log("renew ok");
}

// 5. requesting an address on another subnet gets a NAK, broadcast
{
  sendDhcp(a, 3, { requested: [192, 168, 9, 9], server: GW });
  const r = await a.dhcp("nak");
  assert.equal(r.type, 6, "NAK");
  assert.deepEqual(r.dstMac, BCAST, "NAK broadcast");
  assert.deepEqual(r.opts[54], GW, "NAK has server id");
  assert.equal(r.opts[51], undefined, "NAK has no lease time");
  console.log("nak ok");
}

// 6. release, then a new client can get that address back
{
  sendDhcp(a, 7, { ciaddr: ipA, unicastTo: GW, unicastMac: ROUTER });
  await new Promise((r) => setTimeout(r, 20));
  const c = await client([2, 0, 0, 0, 0, 0xc]);
  const { ack } = await dora(c);
  assert.deepEqual(ack.yiaddr, ipA, "released address reused");
  console.log("release ok");
}

// 7. junk that used to hang or crash the parser: truncated options
{
  const { m } = dhcpMsg(a.mac, 1);
  const bad = m.slice(0, 244); bad[240] = 55; bad[241] = 200; // option claims 200 bytes
  a.send(udpFrame(a.mac, BCAST, [0, 0, 0, 0], [255, 255, 255, 255], 68, 67, bad));
  const tiny = new Uint8Array(10);
  a.send(udpFrame(a.mac, BCAST, [0, 0, 0, 0], [255, 255, 255, 255], 68, 67, tiny));
  // still alive afterwards
  sendDhcp(a, 1);
  assert.equal((await a.dhcp("offer after junk")).type, 2);
  console.log("malformed input ok");
}

await mb.stop();
console.log("dhcp tests passed");
