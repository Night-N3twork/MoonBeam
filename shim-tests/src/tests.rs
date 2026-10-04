use super::shim::render;
use wasmtime::*;

const SC: u32 = 4;
const SS: u32 = 128;
const MF: u32 = 100;
const RING: u32 = 128 + SC * SS;

struct Env {
    store: Store<()>,
    host: Memory,
    client: ClientMem,
    inst: Instance,
    base: u64,
}

impl Env {
    fn new(m64: bool, base: u64, client_pages: u64) -> Self {
        Self::with(m64, true, base, client_pages)
    }
    fn with(m64: bool, shared: bool, base: u64, client_pages: u64) -> Self {
        let mut cfg = Config::new();
        cfg.wasm_multi_memory(true).wasm_memory64(true).wasm_threads(true).shared_memory(true);
        let engine = Engine::new(&cfg).unwrap();
        let mut text = render(m64, false);
        if !shared {
            text = text.replace("281474976710656 shared", "281474976710656");
        }
        let module = Module::new(&engine, wat::parse_str(text).unwrap()).unwrap();
        let mut store = Store::new(&engine, ());
        let host = Memory::new(&mut store, MemoryType::new(2, None)).unwrap();
        let cty = if m64 {
            MemoryTypeBuilder::new().memory64(true).shared(shared).min(client_pages).max(Some(1 << 48)).build().unwrap()
        } else {
            MemoryType::shared(client_pages as u32, 65536)
        };
        let (client, ext): (ClientMem, Extern) = if shared {
            let m = SharedMemory::new(&engine, cty).unwrap();
            (ClientMem::Shared(m.clone()), m.into())
        } else {
            let m = Memory::new(&mut store, cty).unwrap();
            (ClientMem::Plain(m), m.into())
        };
        let inst = Instance::new(&mut store, &module, &[host.into(), ext]).unwrap();
        let e = Env { store, host, client, inst, base };
        e.layout();
        e
    }
    fn ptr(&self) -> *mut u8 {
        match &self.client {
            ClientMem::Shared(m) => m.data().as_ptr() as *mut u8,
            ClientMem::Plain(m) => m.data_ptr(&self.store),
        }
    }
    fn write(&self, off: u64, bytes: &[u8]) {
        unsafe { std::ptr::copy(bytes.as_ptr(), self.ptr().add((self.base + off) as usize), bytes.len()) }
    }
    fn cw(&self, off: u64, v: u32) {
        self.write(off, &v.to_le_bytes());
    }
    fn cr(&self, off: u64) -> u32 {
        let mut b = [0u8; 4];
        unsafe { std::ptr::copy(self.ptr().add((self.base + off) as usize), b.as_mut_ptr(), 4) };
        u32::from_le_bytes(b)
    }
    fn layout(&self) {
        self.cw(0, 0x4252424d);
        self.cw(4, 2);
        self.cw(8, 64 + 2 * RING);
        self.cw(12, SC);
        self.cw(16, SS);
        self.cw(20, MF);
        self.cw(24, 64);
        self.cw(28, 64 + RING);
        self.cw(32, 1);
    }
    fn call<P: WasmParams, R: WasmResults>(&mut self, name: &str, p: P) -> R {
        let f = self.inst.get_typed_func::<P, R>(&mut self.store, name).unwrap();
        f.call(&mut self.store, p).unwrap()
    }
    /// (bytes written, slots consumed)
    fn drain(&mut self, dst: u32, cap: u32, max: u32) -> (u32, u32) {
        let r: i64 = self.call("drain", (dst, cap, max));
        (r as u32, (r as u64 >> 32) as u32)
    }
    fn init(&mut self) -> i32 {
        let (lo, hi) = (self.base as u32, (self.base >> 32) as u32);
        self.call("init", (lo, hi))
    }
    // client side producer for the to_host ring
    fn client_push(&self, frame: &[u8]) {
        let th = 64 + RING as u64;
        let head = self.cr(th);
        let slot = th + 128 + ((head & (SC - 1)) * SS) as u64;
        self.cw(slot, frame.len() as u32);
        self.write(slot + 4, frame);
        self.cw(th, head.wrapping_add(1));
    }
}

enum ClientMem {
    Shared(SharedMemory),
    Plain(Memory),
}

fn round_trip(mut e: Env) {
    assert_eq!(e.init(), 0);
    assert_eq!(e.cr(32), 2, "state ATTACHED");
    assert_eq!(e.init(), -9);

    // host -> client
    e.host.write(&mut e.store, 1000, b"hello").unwrap();
    for i in 0..SC {
        assert_eq!(e.call::<(u32, u32), i32>("push", (1000, 5)), 1, "push {i}");
    }
    assert_eq!(e.call::<(u32, u32), i32>("push", (1000, 5)), 0, "full");
    assert_eq!(e.call::<(u32, u32), i32>("push", (1000, MF + 1)), 0, "too big");
    assert_eq!(e.cr(64), SC, "to_client head");
    assert_eq!(e.cr(64 + 12), 2, "dropped");
    assert_eq!(e.cr(64 + 4), SC, "seq bumped per push");
    assert_eq!(e.cr(64 + 128), 5);

    // client -> host, including a bad length that must be skipped
    e.client_push(b"abc");
    e.client_push(b"defgh");
    e.cw(64 + RING as u64 + 128 + SS as u64, 9999);
    e.client_push(&[7; 100]);
    let (n, slots) = e.drain(4000, 4096, 64);
    assert_eq!(n, (4 + 4) + (4 + 100));
    assert_eq!(slots, 3, "bad slot still counts");
    let mut out = vec![0u8; n as usize];
    e.host.read(&e.store, 4000, &mut out).unwrap();
    assert_eq!(&out[..8], &[3, 0, 0, 0, b'a', b'b', b'c', 0]);
    assert_eq!(u32::from_le_bytes(out[8..12].try_into().unwrap()), 100);
    assert_eq!(e.cr(64 + RING as u64 + 64), 3, "tail advanced past all 3");

    // wraps many times
    for i in 0..50u32 {
        e.client_push(&i.to_le_bytes());
        assert_eq!(e.drain(4000, 4096, 64), (8, 1));
    }

    // drain respects cap: record that does not fit stays queued
    e.client_push(&[1; 100]);
    assert_eq!(e.drain(4000, 50, 64), (0, 0));
    assert_eq!(e.drain(4000, 104, 64), (104, 1));

    // ring full of bad slots: nothing copied, but every slot is charged
    for _ in 0..SC {
        e.client_push(b"x");
        let th = 64 + RING as u64;
        let head = e.cr(th).wrapping_sub(1);
        e.cw(th + 128 + ((head & (SC - 1)) * SS) as u64, 0xffff_ffff);
    }
    assert_eq!(e.drain(4000, 4096, 2), (0, 2), "budget bounded by slots");
    assert_eq!(e.drain(4000, 4096, 64), (0, SC - 2));
    assert_eq!(e.drain(4000, 4096, 64), (0, 0));

    // corrupt head: discarded, no trap
    e.cw(64 + RING as u64, 0xdead_beef);
    assert_eq!(e.drain(4000, 4096, 64), (0, 64), "corrupt head uses the whole budget");
    assert_eq!(e.cr(64 + RING as u64 + 64), 0xdead_beef);

    // corrupt to_client tail: push still bounded by mask
    e.cw(64 + 64, 0x1234_5678);
    let _: i32 = e.call("push", (1000u32, 5u32));

    // arm on an empty ring: sets waiting, returns current seq
    let th = 64 + RING as u64;
    e.cw(th + 4, 41);
    e.cw(th + 8, 0);
    assert_eq!(e.call::<(), i32>("arm", ()), 41);
    assert_eq!(e.cr(th + 8), 1, "waiting set");

    // arm with a frame queued: still sets waiting, but says don't sleep
    e.cw(th + 8, 0);
    e.client_push(b"late");
    assert_eq!(e.call::<(), i32>("arm", ()), -1);
    assert_eq!(e.cr(th + 8), 1, "waiting set even when not sleeping");
    assert_eq!(e.drain(4000, 4096, 64), (8, 1));
    assert_eq!(e.call::<(), i32>("arm", ()), 41);

    // close: release and stop touching memory
    e.call::<(), ()>("close", ());
    assert_eq!(e.cr(32), 3);
    assert_eq!(e.call::<(u32, u32), i32>("push", (1000, 5)), -1);
    assert_eq!(e.call::<(), i32>("state", ()), 3);
}

#[test]
fn memory32_round_trip() {
    round_trip(Env::new(false, 0x10000, 4));
}

#[test]
fn memory64_round_trip() {
    round_trip(Env::new(true, 0x20040, 4));
}

// wasmtime traps on shared memory64 accesses past 4 GiB, so the high-address
// check uses an unshared client memory; the shim code is otherwise identical
#[test]
fn memory64_round_trip_above_4gib() {
    round_trip(Env::with(true, false, (1u64 << 32) + 0x40, 65536 + 2));
}

#[test]
fn rejects_bad_blocks() {
    type Patch = (u64, u32);
    let cases: &[(&[Patch], i32)] = &[
        (&[(0, 0)], -3),
        (&[(4, 1)], -4),
        (&[(8, 0xffff_0000)], -2),
        (&[(12, 3)], -5),
        (&[(12, 0)], -5),
        (&[(16, MF)], -5),
        (&[(20, 70000)], -5),
        (&[(16, 1 << 20)], -5),
        (&[(24, 0)], -6),
        (&[(24, 65)], -6),
        (&[(28, 64)], -6),
        (&[(28, 64 + RING + 64)], -6),
        (&[(32, 2)], -7),
    ];
    for (patch, want) in cases {
        let mut e = Env::new(false, 0x10000, 4);
        for (o, v) in *patch { e.cw(*o, *v); }
        assert_eq!(e.init(), *want, "{patch:?}");
        assert_eq!(e.call::<(u32, u32), i32>("push", (0, 1)), -1);
    }
    let mut e = Env::new(false, 0x10000, 4);
    e.base = 0x10001;
    assert_eq!(e.init(), -1);
    e.base = 4 * 65536;
    assert_eq!(e.init(), -2);
    e.base = 1 << 40;
    assert_eq!(e.init(), -2);
}
