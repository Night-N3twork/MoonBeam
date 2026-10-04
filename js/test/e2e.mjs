// End-to-end test in Node: ARP + ping through lwip over shm and MessagePort,
// routing between clients, a hostile flooding client, and close/stop.
// Run with `./build.sh test` (needs node >= 22 and wasm-bindgen).
import fs from "node:fs";
import assert from "node:assert/strict";
import init, * as wasm from "../../pkg/moonbeam.js";
import { Moonbeam } from "../moonbeam.js";
import { ShmLink } from "../client.js";

await init({ module_or_path: fs.readFileSync(new URL("../../pkg/moonbeam_bg.wasm", import.meta.url)) });
const GW = [10, 0, 0, 1];
const ROUTER = [0x02, 0x6e, 0x69, 0x67, 0x68, 0x74];
const mb = Moonbeam.start(wasm, { gatewayIp: GW });

function csum(b, s, e) { let x = 0; for (let i = s; i < e; i += 2) x += (b[i] << 8) | (b[i + 1] ?? 0); while (x >> 16) x = (x & 0xffff) + (x >> 16); return ~x & 0xffff; }
function arpRequest(mac, ip) {
  const f = new Uint8Array(42);
  f.set([255,255,255,255,255,255], 0); f.set(mac, 6); f.set([0x08, 0x06], 12);
  f.set([0,1, 8,0, 6, 4, 0,1], 14); f.set(mac, 22); f.set(ip, 28); f.set(GW, 38);
  return f;
}
function ping(mac, ip, seq) {
  const f = new Uint8Array(14 + 20 + 8 + 4);
  f.set(ROUTER, 0); f.set(mac, 6); f.set([0x08, 0x00], 12);
  f.set([0x45, 0, 0, 32, 0, 1, 0, 0, 64, 1, 0, 0], 14); f.set(ip, 26); f.set(GW, 30);
  const c = csum(f, 14, 34); f[24] = c >> 8; f[25] = c & 0xff;
  f.set([8, 0, 0, 0, 0x12, 0x34, 0, seq, 0xde, 0xad, 0xbe, 0xef], 34);
  const c2 = csum(f, 34, f.length); f[36] = c2 >> 8; f[37] = c2 & 0xff;
  return f;
}
const withTimeout = (p, ms, what) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error("timeout: " + what)), ms))]);

// --- shm client ---
const memory = new WebAssembly.Memory({ initial: 16, maximum: 16, shared: true });
const link = ShmLink.create(memory.buffer, 64, { slotCount: 16 });
const macA = [2, 0, 0, 0, 0, 0xa];
const ipA = [10, 0, 0, 100];
const idA = await mb.addShm({ memory, offset: 64, mac: macA });
await link.attached();
const frames = link.frames()[Symbol.asyncIterator]();
const next = (what) => withTimeout(frames.next().then((r) => r.value), 1000, what);

assert.ok(link.send(arpRequest(macA, ipA)));
const arp = await next("arp reply");
assert.deepEqual([...arp.slice(0, 6)], macA, "arp reply to us");
assert.deepEqual([...arp.slice(12, 14)], [8, 6]);
assert.equal(arp[21], 2, "arp opcode reply");
assert.deepEqual([...arp.slice(22, 28)], ROUTER, "router mac in reply");
console.log("shm: arp ok");

const t0 = performance.now();
for (let i = 0; i < 200; i++) {
  assert.ok(link.send(ping(macA, ipA, i & 0xff)));
  const r = await next("echo reply " + i);
  assert.equal(r[34], 0, "icmp echo reply");
  assert.equal(r[41], i & 0xff, "seq");
  assert.deepEqual([...r.slice(42, 46)], [0xde, 0xad, 0xbe, 0xef]);
}
console.log(`shm: 200 pings ok, ${((performance.now() - t0) / 200 * 1000).toFixed(0)} us/rtt`);

// --- messageport client, and routing between clients ---
const { port1, port2 } = new MessageChannel();
const macB = [2, 0, 0, 0, 0, 0xb];
mb.addPort(port2, macB);
const portFrames = [];
let portWake = () => {};
port1.onmessage = (ev) => { const f = new Uint8Array(ev.data); answerArp(f); portFrames.push(f); portWake(); };
const portRaw = () => new Promise((r) => { if (portFrames.length) return r(portFrames.shift()); portWake = () => r(portFrames.shift()); });
// skips broadcasts (ARP requests from lwip, other clients' ARPs)
const portNext = (what) => withTimeout((async () => { for (;;) { const f = await portRaw(); if (f[0] !== 0xff) return f; } })(), 1000, what);
const arpReply = (req, mac, ip) => { const f = new Uint8Array(42); f.set(req.slice(6, 12), 0); f.set(mac, 6); f.set([8, 6, 0,1, 8,0, 6,4, 0,2], 12); f.set(mac, 22); f.set(ip, 28); f.set(req.slice(22, 28), 32); f.set(req.slice(28, 32), 38); return f; };
// answer lwip's ARP requests for the port client, like a real host would
const portIp = [10, 0, 0, 101];
const answerArp = (f) => { if (f[0] === 0xff && f[12] === 8 && f[13] === 6 && f[21] === 1 && f.slice(38, 42).every((b, i) => b === portIp[i])) { const r = arpReply(f, macB, portIp); port1.postMessage(r.buffer, [r.buffer]); } };

const pb = ping(macB, portIp, 7).buffer;
port1.postMessage(pb, [pb]);
const pr = await portNext("port echo reply");
assert.equal(pr[34], 0); assert.deepEqual([...pr.slice(0, 6)], macB);
console.log("port: ping ok");

// shm -> port unicast
const hello = new Uint8Array(60); hello.set(macB, 0); hello.set(macA, 6); hello.set([0x88, 0xb5], 12); hello[20] = 42;
link.send(hello);
const got = await portNext("shm->port");
assert.equal(got[20], 42);
// port -> shm unicast
const back = new Uint8Array(60); back.set(macA, 0); back.set(macB, 6); back.set([0x88, 0xb5], 12); back[20] = 43;
port1.postMessage(back.buffer, [back.buffer]);
let f; do { f = await next("port->shm"); } while (f[0] === 0xff);
assert.equal(f[20], 43);
console.log("routing between clients ok");

// --- hostile client: ring full of bad slots, never notifies ---
const evilMem = new WebAssembly.Memory({ initial: 4, maximum: 4, shared: true });
const evil = ShmLink.create(evilMem.buffer, 0, { slotCount: 16 });
await mb.addShm({ memory: evilMem, offset: 0, mac: [2, 0, 0, 0, 0, 0xe] });
await evil.attached();
let stopEvil = false;
// default maxFrame 1514 -> 1536 byte slots; to_host ring follows to_client
const toHost = new Int32Array(evilMem.buffer, 64 + (128 + 16 * 1536), 32);
const slotsView = new DataView(evilMem.buffer, 64 + (128 + 16 * 1536) + 128);
(function flood() {
  if (stopEvil) return;
  // refill with garbage lengths as fast as possible
  const tail = Atomics.load(toHost, 16);
  for (let i = 0; i < 16; i++) slotsView.setUint32(((tail + i) & 15) * 1536, 0xffffffff, true);
  Atomics.store(toHost, 0, (tail + 16) | 0);
  setImmediate(flood);
})();
// the good client must still get served
const t1 = performance.now();
for (let i = 0; i < 20; i++) {
  link.send(ping(macA, ipA, i));
  let r; do { r = await next("ping under flood " + i); } while (r[0] === 0xff);
  assert.equal(r[34], 0);
}
stopEvil = true;
console.log(`hostile flood: good client still served, ${((performance.now() - t1) / 20 * 1000).toFixed(0)} us/rtt`);

// --- client closes ---
await withTimeout(link.close(), 1000, "close");
assert.equal(link.state, 3, "RELEASED");
console.log("shm close ok");

await mb.stop();
console.log("stopped");
