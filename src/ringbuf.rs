// this is giga vibed obviously but this was pissing me off

use std::cell::RefCell;

use wasm_bindgen::prelude::*;

pub const STATE_FREE: u32 = 0;
pub const STATE_READY: u32 = 1;
pub const STATE_ATTACHED: u32 = 2;
pub const STATE_RELEASED: u32 = 3;
pub const STATE_CLOSING: u32 = 4;

/// Bridge modules, built from `shm_shim.wat` by build.rs. Moonbeam's memory
/// is the "host" import; the client's memory is the "client" import.
static SHIM32: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/shm_shim32.wasm"));
static SHIM64: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/shm_shim64.wasm"));

#[wasm_bindgen]
pub fn shm_shim_wasm(memory64: bool) -> Vec<u8> {
    if memory64 { SHIM64 } else { SHIM32 }.to_vec()
}

/// Moonbeam's own memory, for the bridge's "host" import. Never give this
/// to a client.
#[wasm_bindgen]
pub fn shm_host_memory() -> JsValue {
    wasm_bindgen::memory()
}

/// Moonbeam's function table; bridge exports are appended to it so Rust can
/// call them. (wasm-bindgen renames the table export, so go through this.)
#[wasm_bindgen]
pub fn shm_function_table() -> JsValue {
    wasm_bindgen::function_table()
}

/// Function table indices of one bridge instance's exports.
#[derive(Clone, Copy)]
struct Bridge {
    push: usize,
    drain: usize,
    state: usize,
    close: usize,
}

impl Bridge {
    fn new(push: u32, drain: u32, state: u32, close: u32) -> Option<Self> {
        if [push, drain, state, close].contains(&0) {
            return None;
        }
        Some(Bridge { push: push as usize, drain: drain as usize, state: state as usize, close: close as usize })
    }

    // On wasm32 a function pointer is an index into the function table, and
    // call_indirect checks the signature, so a wrong index traps rather than
    // calling something with the wrong type.
    #[cfg(target_family = "wasm")]
    fn push(&self, frame: &[u8]) -> i32 {
        let f: extern "C" fn(u32, u32) -> i32 = unsafe { std::mem::transmute(self.push) };
        f(frame.as_ptr() as u32, frame.len() as u32)
    }

    /// Returns (bytes written into `dst`, slots consumed).
    #[cfg(target_family = "wasm")]
    fn drain(&self, dst: &mut [u8], max_slots: u32) -> (usize, u32) {
        let f: extern "C" fn(u32, u32, u32) -> i64 = unsafe { std::mem::transmute(self.drain) };
        let r = f(dst.as_mut_ptr() as u32, dst.len() as u32, max_slots) as u64;
        ((r as u32 as usize).min(dst.len()), ((r >> 32) as u32).min(max_slots))
    }

    #[cfg(target_family = "wasm")]
    fn state(&self) -> u32 {
        let f: extern "C" fn() -> i32 = unsafe { std::mem::transmute(self.state) };
        f() as u32
    }

    #[cfg(target_family = "wasm")]
    fn close(&self) {
        let f: extern "C" fn() = unsafe { std::mem::transmute(self.close) };
        f()
    }

    #[cfg(not(target_family = "wasm"))]
    fn push(&self, _: &[u8]) -> i32 { -1 }
    #[cfg(not(target_family = "wasm"))]
    fn drain(&self, _: &mut [u8], _: u32) -> (usize, u32) { (0, 0) }
    #[cfg(not(target_family = "wasm"))]
    fn state(&self) -> u32 { STATE_RELEASED }
    #[cfg(not(target_family = "wasm"))]
    fn close(&self) {}
}

pub struct ShmClient {
    pub id: u32,
    pub mac: [u8; 6],
    bridge: Bridge,
}

#[derive(Default)]
struct Registry {
    next_id: u32,
    clients: Vec<ShmClient>,
}

thread_local! {
    static REGISTRY: RefCell<Registry> = RefCell::new(Registry::default());
    // heap allocated: building a 256 KiB array on the wasm stack overflows it
    static SCRATCH: RefCell<Box<[u8]>> = RefCell::new(vec![0u8; SCRATCH_LEN].into_boxed_slice());
}

/// Large enough for a whole ring of max-size frames per drain call.
const SCRATCH_LEN: usize = 256 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PushResult {
    Queued,
    Dropped,
    Gone,
}

/// Registers a bridge that JS has instantiated, `init`-ed and placed in the
/// function table. Returns the id used for every later call.
pub fn attach(mac: [u8; 6], push: u32, drain: u32, state: u32, close: u32) -> Option<u32> {
    let bridge = Bridge::new(push, drain, state, close)?;
    if bridge.state() != STATE_ATTACHED {
        return None;
    }
    REGISTRY.with_borrow_mut(|r| {
        r.next_id = r.next_id.wrapping_add(1).max(1);
        let id = r.next_id;
        r.clients.push(ShmClient { id, mac, bridge });
        Some(id)
    })
}

fn bridge(id: u32) -> Option<Bridge> {
    REGISTRY.with_borrow(|r| r.clients.iter().find(|c| c.id == id).map(|c| c.bridge))
}

pub fn push(id: u32, frame: &[u8]) -> PushResult {
    match bridge(id).map(|b| b.push(frame)) {
        Some(1) => PushResult::Queued,
        Some(0) => PushResult::Dropped,
        _ => PushResult::Gone,
    }
}

/// Releases the client's block. Returns its MAC if it was attached.
pub fn detach(id: u32) -> Option<[u8; 6]> {
    let client = REGISTRY.with_borrow_mut(|r| {
        let i = r.clients.iter().position(|c| c.id == id)?;
        Some(r.clients.swap_remove(i))
    })?;
    client.bridge.close();
    Some(client.mac)
}

/// Drains every client's to_host ring, calling `on_frame(frame, sender_mac)`.
/// Each client may consume at most `max_slots_per_client` slots per call,
/// valid or not, so one client cannot hold the thread. Clients that asked to
/// close are released and reported via `on_closed`. Returns frames handled.
pub fn poll(
    max_slots_per_client: u32,
    mut on_frame: impl FnMut(&[u8], [u8; 6]),
    mut on_closed: impl FnMut([u8; 6]),
) -> usize {
    let snapshot: Vec<(u32, [u8; 6], Bridge)> =
        REGISTRY.with_borrow(|r| r.clients.iter().map(|c| (c.id, c.mac, c.bridge)).collect());
    let mut total = 0;

    SCRATCH.with_borrow_mut(|scratch| {
        for (id, mac, bridge) in snapshot {
            match bridge.state() {
                STATE_ATTACHED => {}
                // CLOSING, or the client clobbered the state word: let go either way
                _ => {
                    if detach(id).is_some() {
                        on_closed(mac);
                    }
                    continue;
                }
            }

            let mut left = max_slots_per_client;
            while left > 0 {
                let (bytes, slots) = bridge.drain(&mut scratch[..], left);
                if slots == 0 {
                    break;
                }
                left -= slots;
                for frame in Records(&scratch[..bytes]) {
                    on_frame(frame, mac);
                    total += 1;
                }
            }
        }
    });
    total
}

/// Iterates the `u32 len + payload, padded to 4` records written by `drain`.
struct Records<'a>(&'a [u8]);

impl<'a> Iterator for Records<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let len = u32::from_le_bytes(self.0.get(..4)?.try_into().ok()?) as usize;
        let frame = self.0.get(4..4 + len)?;
        let next = (4 + len + 3) & !3;
        self.0 = self.0.get(next..).unwrap_or(&[]);
        Some(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::Records;

    #[test]
    fn records() {
        let buf = [3, 0, 0, 0, 1, 2, 3, 0, 0, 0, 0, 0, 5, 0, 0, 0, 9, 9, 9, 9, 9, 0, 0, 0];
        let got: Vec<&[u8]> = Records(&buf).collect();
        assert_eq!(got, vec![&[1, 2, 3][..], &[][..], &[9; 5][..]]);
        assert_eq!(Records(&[200, 0, 0, 0, 1]).count(), 0);
    }
}
