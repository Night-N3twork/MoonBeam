// Client side of the shm ring transport (spec in src/ringbuf.rs).
//
// This file has no dependency on moonbeam and runs on the client's own thread.
// It is a reference for JS clients; wasm clients implement the same protocol
// with plain loads, stores and atomics on their own memory.
//
//   const memory = new WebAssembly.Memory({ initial: 64, maximum: 64, shared: true });
//   const link = ShmLink.create(memory.buffer, 0);
//   moonbeamPort.postMessage({ memory, offset: 0, memory64: false, mac });
//   link.send(frame);
//   for await (const frame of link.frames()) { ... }

export const MAGIC = 0x4252424d; // "MBRB"
export const VERSION = 2;
export const STATE = { FREE: 0, READY: 1, ATTACHED: 2, RELEASED: 3, CLOSING: 4 };

const BLOCK_HEADER = 64;
const RING_HEADER = 128;
// u32 word indices within a block / ring header
const B = { MAGIC: 0, VERSION: 1, SIZE: 2, SLOT_COUNT: 3, SLOT_SIZE: 4, MAX_FRAME: 5, TO_CLIENT: 6, TO_HOST: 7, STATE: 8 };
const R = { HEAD: 0, SEQ: 1, WAITING: 2, DROPPED: 3, TAIL: 16 };

export function geometry({ slotCount = 256, maxFrame = 1514 } = {}) {
  if (slotCount < 2 || (slotCount & (slotCount - 1)) !== 0) throw new RangeError("slotCount must be a power of two >= 2");
  if (maxFrame < 60 || maxFrame > 65535) throw new RangeError("maxFrame must be 60..65535");
  const slotSize = (maxFrame + 4 + 63) & ~63;
  const ringSize = RING_HEADER + slotCount * slotSize;
  return { slotCount, maxFrame, slotSize, ringSize, size: BLOCK_HEADER + 2 * ringSize };
}

export function blockSize(opts) {
  return geometry(opts).size;
}

class Ring {
  constructor(buffer, offset, geo) {
    this.h = new Int32Array(buffer, offset, RING_HEADER / 4);
    this.bytes = new Uint8Array(buffer, offset + RING_HEADER, geo.slotCount * geo.slotSize);
    this.view = new DataView(buffer, offset + RING_HEADER, geo.slotCount * geo.slotSize);
    this.mask = geo.slotCount - 1;
    this.slotCount = geo.slotCount;
    this.slotSize = geo.slotSize;
    this.maxFrame = geo.maxFrame;
  }

  // producer
  push(frame) {
    const head = Atomics.load(this.h, R.HEAD);
    const tail = Atomics.load(this.h, R.TAIL);
    if (frame.byteLength > this.maxFrame || ((head - tail) >>> 0) >= this.slotCount) {
      Atomics.add(this.h, R.DROPPED, 1);
      return false;
    }
    const at = (head & this.mask) * this.slotSize;
    this.view.setUint32(at, frame.byteLength, true);
    this.bytes.set(frame instanceof Uint8Array ? frame : new Uint8Array(frame), at + 4);
    Atomics.store(this.h, R.HEAD, (head + 1) | 0);
    Atomics.add(this.h, R.SEQ, 1);
    if (Atomics.exchange(this.h, R.WAITING, 0) !== 0) Atomics.notify(this.h, R.SEQ);
    return true;
  }

  // consumer: returns a copy of the next frame, or null if empty
  pop() {
    const tail = Atomics.load(this.h, R.TAIL);
    const head = Atomics.load(this.h, R.HEAD);
    if (head === tail) return null;
    const at = (tail & this.mask) * this.slotSize;
    const len = this.view.getUint32(at, true);
    // moonbeam is trusted, but don't let a bug read past the slot
    const frame = len <= this.maxFrame ? this.bytes.slice(at + 4, at + 4 + len) : new Uint8Array(0);
    Atomics.store(this.h, R.TAIL, (tail + 1) | 0);
    return frame;
  }

  // same order as the bridge's arm(): load seq, set waiting, recheck
  arm() {
    const seq = Atomics.load(this.h, R.SEQ);
    Atomics.store(this.h, R.WAITING, 1);
    return Atomics.load(this.h, R.HEAD) !== Atomics.load(this.h, R.TAIL) ? null : seq;
  }
}

export class ShmLink {
  /** Lays out a new block at `offset` (64-byte aligned) in `buffer` and offers it. */
  static create(buffer, offset, opts) {
    if (offset % 64 !== 0) throw new RangeError("offset must be 64-byte aligned");
    const geo = geometry(opts);
    new Uint8Array(buffer, offset, geo.size).fill(0);
    const h = new Int32Array(buffer, offset, BLOCK_HEADER / 4);
    h[B.VERSION] = VERSION;
    h[B.SIZE] = geo.size;
    h[B.SLOT_COUNT] = geo.slotCount;
    h[B.SLOT_SIZE] = geo.slotSize;
    h[B.MAX_FRAME] = geo.maxFrame;
    h[B.TO_CLIENT] = BLOCK_HEADER;
    h[B.TO_HOST] = BLOCK_HEADER + geo.ringSize;
    h[B.MAGIC] = MAGIC;
    Atomics.store(h, B.STATE, STATE.READY);
    return new ShmLink(buffer, offset, geo);
  }

  constructor(buffer, offset, geo) {
    this.h = new Int32Array(buffer, offset, BLOCK_HEADER / 4);
    this.rx = new Ring(buffer, offset + BLOCK_HEADER, geo);
    this.tx = new Ring(buffer, offset + BLOCK_HEADER + geo.ringSize, geo);
  }

  get state() {
    return Atomics.load(this.h, B.STATE);
  }

  /** Resolves once moonbeam has attached (or rejects if it released the block). */
  async attached() {
    for (;;) {
      const s = this.state;
      if (s === STATE.ATTACHED) return;
      if (s !== STATE.READY) throw new Error(`block is ${s}, not attaching`);
      // the bridge notifies seq on close, not on attach, so poll
      await new Promise((r) => setTimeout(r, 5));
    }
  }

  /** Queues a frame for moonbeam. false if the ring is full or it is too big. */
  send(frame) {
    return this.state === STATE.ATTACHED && this.tx.push(frame);
  }

  /** Next frame from moonbeam, or null if none is queued. */
  receive() {
    return this.rx.pop();
  }

  /** Waits until a frame is queued or the link closes. */
  async wait() {
    const seq = this.rx.arm();
    if (seq === null || this.state !== STATE.ATTACHED) return;
    const r = Atomics.waitAsync(this.rx.h, R.SEQ, seq);
    if (r.async) await r.value;
  }

  /** Yields frames until the link closes. */
  async *frames() {
    while (this.state === STATE.ATTACHED) {
      let frame;
      while ((frame = this.receive()) !== null) yield frame;
      await this.wait();
    }
  }

  /** Asks moonbeam to let go. Resolves once the memory may be reused. */
  async close() {
    Atomics.compareExchange(this.h, B.STATE, STATE.ATTACHED, STATE.CLOSING);
    Atomics.compareExchange(this.h, B.STATE, STATE.READY, STATE.FREE);
    // wake moonbeam so it notices promptly
    Atomics.add(this.tx.h, R.SEQ, 1);
    Atomics.notify(this.tx.h, R.SEQ);
    while (this.state === STATE.CLOSING) await new Promise((r) => setTimeout(r, 5));
  }
}
