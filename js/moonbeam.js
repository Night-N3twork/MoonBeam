// High level wrapper around the moonbeam wasm module. Owns lwip's lifecycle
// and the event loop, so callers only deal with clients:
//
//   import init, * as wasm from "./pkg/moonbeam.js";
//   await init();
//   const mb = Moonbeam.start(wasm, { gatewayIp: [10, 0, 0, 1] });
//   mb.addPort(port, mac);
//   await mb.addShm({ memory, offset, memory64, mac });
//   ...
//   await mb.stop();
//
// Everything here must run on one thread (lwip is NO_SYS). Only one Moonbeam
// can exist per wasm instance; to restart, load a fresh instance.

// slots each client may consume per tick; bounds how long one client can
// hold the thread before others (and MessagePort traffic) get a turn
const SLOTS_PER_TICK = 64;
// arm() result meaning "frames are already waiting"; a real seq of -1 only
// costs one extra pass
const ARM_PENDING = -1;

const yieldTask = globalThis.scheduler?.yield
  ? () => globalThis.scheduler.yield()
  : () => new Promise((resolve) => {
      const ch = new MessageChannel();
      ch.port1.onmessage = () => { ch.port1.close(); resolve(); };
      ch.port2.postMessage(null);
    });

function bytes(v, n, what) {
  const b = v instanceof Uint8Array ? v : Uint8Array.from(v);
  if (b.length !== n) throw new TypeError(`${what} must be ${n} bytes`);
  return b;
}

export class Moonbeam {
  #wasm;
  #shims = new Map(); // memory64 -> compiled bridge module
  #shm = new Map(); // id -> { e, futex, word, mac }
  #ports = new Map(); // mac string -> port
  #pending = new Map(); // shm id -> armed waitAsync promise
  #kick = () => {};
  #running = true;
  #done;

  /**
   * `dhcpIp` is the DHCP server's address; it defaults to the gateway's.
   * Clients are leased .100 - .163 of the gateway's /24.
   */
  static start(wasm, { gatewayIp = [10, 0, 0, 1], dhcpIp = gatewayIp, netmask = [255, 255, 255, 0] } = {}) {
    wasm.start(bytes(gatewayIp, 4, "gatewayIp"), bytes(dhcpIp, 4, "dhcpIp"), bytes(netmask, 4, "netmask"));
    return new Moonbeam(wasm);
  }

  constructor(wasm) {
    this.#wasm = wasm;
    this.#done = this.#loop();
  }

  /** Attaches a client that talks over a MessagePort (ArrayBuffer frames). */
  addPort(port, mac) {
    mac = bytes(mac, 6, "mac");
    this.#wasm.port_attach(port, mac);
    this.#ports.set(mac.join(":"), port);
  }

  removePort(mac) {
    mac = bytes(mac, 6, "mac");
    this.#ports.delete(mac.join(":"));
    return this.#wasm.port_detach(mac);
  }

  /**
   * Attaches a client whose rings live in its own shared memory (see
   * client.js). Rejects if the block is malformed or moonbeam refuses it.
   * Resolves to an id for removeShm.
   */
  async addShm({ memory, offset, memory64 = false, mac }) {
    mac = bytes(mac, 6, "mac");
    if (!(memory instanceof WebAssembly.Memory)) throw new TypeError("memory must be a WebAssembly.Memory");
    if (!(memory.buffer instanceof SharedArrayBuffer)) throw new TypeError("client memory must be shared");

    let mod = this.#shims.get(memory64);
    if (!mod) {
      mod = await WebAssembly.compile(this.#wasm.shm_shim_wasm(memory64));
      this.#shims.set(memory64, mod);
    }
    const { exports: e } = await WebAssembly.instantiate(mod, {
      host: { memory: this.#wasm.shm_host_memory() },
      client: { memory },
    });

    const off = BigInt(offset);
    const rc = e.init(Number(off & 0xffffffffn) | 0, Number(off >> 32n) | 0);
    if (rc !== 0) throw new Error(`shm block rejected by bridge (code ${rc})`);

    const table = this.#wasm.shm_function_table();
    const slots = [e.push, e.drain, e.state, e.close].map((f) => table.grow(1, f));
    const id = this.#wasm.shm_attach(mac, ...slots);
    if (id === undefined) {
      e.close();
      throw new Error("moonbeam refused the shm client");
    }

    // memory64 clients get a BigInt address from futex()
    const word = Number(e.futex()) / 4;
    this.#shm.set(id, { e, futex: new Int32Array(memory.buffer), word, mac });
    this.#kick();
    return id;
  }

  removeShm(id) {
    this.#shm.delete(id);
    this.#pending.delete(id);
    this.#wasm.shm_detach(id);
  }

  /** Closes every client and stops lwip. The instance cannot be restarted. */
  async stop() {
    this.#running = false;
    this.#kick();
    await this.#done;
    this.#wasm.stop();
    this.#shm.clear();
    this.#ports.clear();
  }

  async #loop() {
    while (this.#running) {
      const sleepMs = this.#wasm.tick(SLOTS_PER_TICK);

      let busy = false;
      for (const [id, c] of this.#shm) {
        if (c.e.state() !== 2 /* ATTACHED */) {
          // tick() released it: the client closed or clobbered its state
          this.#shm.delete(id);
          this.#pending.delete(id);
          continue;
        }
        if (this.#pending.has(id)) continue; // already armed, don't stack waiters
        const seq = c.e.arm();
        if (seq === ARM_PENDING) { busy = true; continue; }
        const r = Atomics.waitAsync(c.futex, c.word, seq);
        if (!r.async) { busy = true; continue; } // pushed since arm
        this.#pending.set(id, r.value.then(() => { this.#pending.delete(id); }));
      }

      if (busy) {
        // more frames queued: go again, but let MessagePort traffic and
        // other tasks run first
        await yieldTask();
        continue;
      }

      let timer;
      const kicked = new Promise((resolve) => { this.#kick = resolve; });
      const ticked = new Promise((resolve) => { timer = setTimeout(resolve, sleepMs); });
      await Promise.race([...this.#pending.values(), kicked, ticked]);
      clearTimeout(timer);
    }
  }
}
