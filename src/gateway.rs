use std::cell::RefCell;
use std::sync::{OnceLock, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};

use wasm_bindgen::prelude::*;
use web_sys::{MessageEvent, MessagePort, js_sys::{self, Array, Uint8Array}};
use anyhow::Result;

use crate::dhcp::{self, DhcpService, DHCP_MAC};
use crate::{lwip::{netif, pbuf_layer_PBUF_RAW, pbuf_type_PBUF_POOL}, netif_input, pbuf_alloc, pbuf_free, pbuf_take, ringbuf::{self, PushResult}};

static Gateway: OnceLock<Gateway> = OnceLock::new();
pub const ROUTER_MAC: [u8; 6] = [0x02, 0x6e, 0x69, 0x67, 0x68, 0x74];
const BROADCAST_MAC: [u8; 6] = [0xff; 6];
pub const MAX_FRAME: usize = 1514;

pub fn get() -> Option<&'static Gateway> {
    Gateway.get().filter(|gw| !gw.stopped.load(Ordering::Relaxed))
}

pub fn init(netif_ptr: *mut netif, dhcp: DhcpService) -> Option<&'static Gateway> {
    // make sure if we're sharing ips we're sharing macs
    let dhcp_mac = if dhcp.server_ip == dhcp.gateway_ip { ROUTER_MAC } else { DHCP_MAC };
    let gw = Gateway {
        router_mac: ROUTER_MAC,
        clients: RwLock::new(Vec::new()),
        dhcp_mac,
        dhcp: RefCell::new(dhcp),
        netif_ptr,
        stopped: AtomicBool::new(false),
    };
    Gateway.set(gw).ok()?;
    Gateway.get()
}

struct LanClient  {
    mac: [u8; 6],
    channel: Channel
}

enum Channel {
    /// id from ringbuf::attach; the rings live in the client's own memory
    ShmBuffer(u32),
    MessagePort(MessagePort),
}

unsafe impl Send for Gateway {}
unsafe impl Sync for Gateway {}

unsafe impl Send for Channel {}
unsafe impl Sync for Channel {}

unsafe impl Send for LanClient {}
unsafe impl Sync for LanClient {}

impl Channel {
    pub fn send(&self, frame: &[u8]) -> Result<()> {
        match self {
            Channel::MessagePort(port) => {
                forward_messageport(port, frame)
            }
            Channel::ShmBuffer(id) => match ringbuf::push(*id, frame) {
                PushResult::Queued => Ok(()),
                PushResult::Dropped => anyhow::bail!("shm ring for client {id} is full or frame too large"),
                PushResult::Gone => anyhow::bail!("shm client {id} is detached"),
            },
        }
    }

    /// Releases whatever the channel holds on the client's side.
    fn close(self) {
        match self {
            Channel::ShmBuffer(id) => { ringbuf::detach(id); }
            Channel::MessagePort(port) => {
                port.set_onmessage(None);
                port.close();
            }
        }
    }
}

pub struct Gateway {
    pub router_mac: [u8; 6],
    clients: RwLock<Vec<LanClient>>,
    dhcp_mac: [u8; 6],
    /// only borrowed inside dhcp(), never across routing (lwip thread only)
    dhcp: RefCell<DhcpService>,
    pub netif_ptr: *mut netif,
    stopped: AtomicBool,
}

impl Gateway {
    fn send_to(&self, mac: [u8; 6], frame: &[u8]) -> bool {
        match self.clients.read().unwrap().iter().find(|c| c.mac == mac) {
            Some(client) => { let _ = client.channel.send(frame); true }
            None => false,
        }
    }

    fn register_client(&self, mac: [u8; 6], channel: Channel) {
        let replaced: Vec<LanClient> = {
            let mut clients = self.clients.write().unwrap();
            // remove anyone else with the same mac just in case
            let (old, keep) = std::mem::take(&mut *clients).into_iter().partition(|c| c.mac == mac);
            *clients = keep;
            clients.push(LanClient { mac, channel });
            old
        };
        for client in replaced {
            client.channel.close();
        }
    }

    fn take_clients(&self, pred: impl Fn(&LanClient) -> bool) -> Vec<LanClient> {
        let mut clients = self.clients.write().unwrap();
        let (taken, keep) = std::mem::take(&mut *clients).into_iter().partition(|c| pred(c));
        *clients = keep;
        taken
    }

    // give messageport a closure to react to stuff
    pub fn bind_messageport(self: &'static Self, port: MessagePort, client_mac: [u8; 6]) {
        let closure = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let data = event.data();

            if let Ok(buf) = data.dyn_into::<js_sys::ArrayBuffer>() { // i guess bro
                if buf.byte_length() as usize > MAX_FRAME { return; }
                let view = Uint8Array::new(&buf);
                let mut frame = [0u8; MAX_FRAME];
                let frame = &mut frame[..view.length() as usize];
                view.copy_to(frame);

                self.route_frame(frame, client_mac);
            }
        });

        port.set_onmessage(Some(closure.as_ref().unchecked_ref()));
        closure.forget();
        self.register_client(client_mac, Channel::MessagePort(port));
    }

    pub fn detach_messageport(&self, client_mac: [u8; 6]) -> bool {
        let taken = self.take_clients(|c| c.mac == client_mac && matches!(c.channel, Channel::MessagePort(_)));
        let found = !taken.is_empty();
        taken.into_iter().for_each(|c| c.channel.close());
        found
    }

    pub fn attach_shm(&self, client_mac: [u8; 6], push: u32, drain: u32, state: u32, close: u32) -> Option<u32> {
        let id = ringbuf::attach(client_mac, push, drain, state, close)?;
        self.register_client(client_mac, Channel::ShmBuffer(id));
        Some(id)
    }

    pub fn detach_shm(&self, id: u32) {
        let is_this = |c: &LanClient| matches!(c.channel, Channel::ShmBuffer(i) if i == id);
        self.take_clients(is_this).into_iter().for_each(|c| c.channel.close());
    }

    // routes everything in queue and returns frames
    pub fn poll_shm(self: &'static Self, max_slots_per_client: u32) -> usize {
        ringbuf::poll(
            max_slots_per_client,
            |frame, mac| self.route_frame(frame, mac),
            // ringbuf already released the block, just forget the route
            |mac| { self.take_clients(|c| c.mac == mac && matches!(c.channel, Channel::ShmBuffer(_))); },
        )
    }

    pub fn shutdown(&self) {
        self.stopped.store(true, Ordering::Relaxed);
        self.take_clients(|_| true).into_iter().for_each(|c| c.channel.close());
    }

    pub fn route_frame(self: &'static Self, frame: &[u8], src_mac: [u8; 6]) {
        let pkt_len = frame.len();
        if pkt_len < 14 || pkt_len > MAX_FRAME { return; }

        let dst_mac: [u8; 6] = frame[0..6].try_into().unwrap();
        let from_router = src_mac == self.router_mac || src_mac == self.dhcp_mac;

        if !from_router && (dst_mac == BROADCAST_MAC || dst_mac == self.dhcp_mac) && self.dhcp(frame) {
            return;
        }

        if dst_mac == BROADCAST_MAC {
            for client in self.clients.read().unwrap().iter().filter(|c| c.mac != src_mac) {
                let _ = client.channel.send(frame);
            }

            if !from_router { self.to_lwip(frame); }
            return;
        }

        if dst_mac == self.router_mac {
            if !from_router { self.to_lwip(frame); }
            return;
        }

        self.send_to(dst_mac, frame);
    }

    fn dhcp(self: &'static Self, frame: &[u8]) -> bool {
        let (consumed, reply) = {
            let mut dhcp = self.dhcp.borrow_mut();
            if let Some(reply) = dhcp.handle_frame(frame, self.dhcp_mac) {
                (true, reply)
            } else if self.dhcp_mac != self.router_mac {
                let reply = dhcp::arp_reply_for(frame, self.dhcp_mac, dhcp.server_ip);
                (reply.is_some(), reply)
            } else {
                (false, None)
            }
        };
        if let Some(reply) = reply {
            self.route_frame(&reply, self.dhcp_mac);
        }
        consumed || (self.dhcp_mac != self.router_mac && frame[0..6] == self.dhcp_mac)
    }

    fn to_lwip(&self, frame: &[u8]) {
        unsafe {
            let pbuf = pbuf_alloc(pbuf_layer_PBUF_RAW, frame.len() as u16, pbuf_type_PBUF_POOL);
            if pbuf.is_null() { return; }
            if pbuf_take(pbuf, frame.as_ptr().cast(), frame.len() as u16) != 0
                || netif_input(pbuf, self.netif_ptr) != 0
            {
                pbuf_free(pbuf);
            }
        }
    }
}

fn parse_mac(mac: &[u8]) -> Result<[u8; 6], JsError> {
    mac.try_into().map_err(|_| JsError::new("mac must be 6 bytes"))
}

#[wasm_bindgen]
pub fn port_attach(port: MessagePort, mac: &[u8]) -> Result<(), JsError> {
    let mac = parse_mac(mac)?;
    let gw = get().ok_or_else(|| JsError::new("moonbeam is not started"))?;
    gw.bind_messageport(port, mac);
    Ok(())
}

#[wasm_bindgen]
pub fn port_detach(mac: &[u8]) -> bool {
    match (parse_mac(mac), get()) {
        (Ok(mac), Some(gw)) => gw.detach_messageport(mac),
        _ => false,
    }
}

#[wasm_bindgen]
pub fn shm_attach(mac: &[u8], push: u32, drain: u32, state: u32, close: u32) -> Option<u32> {
    get()?.attach_shm(mac.try_into().ok()?, push, drain, state, close)
}

#[wasm_bindgen]
pub fn shm_detach(id: u32) {
    if let Some(gw) = get() {
        gw.detach_shm(id);
    }
}

pub fn forward_messageport(port: &MessagePort, data: &[u8]) -> anyhow::Result<()> {
    let js_arr = Uint8Array::new_with_length(data.len() as u32);
    js_arr.copy_from(data);

    // js is stupid
    let buf = js_arr.buffer();
    let transfer = Array::new();
    transfer.push(&buf);

    port.post_message_with_transferable(&buf, &transfer).map_err(|e| anyhow::anyhow!("error when sending on messageport: {:?}", e))?;

    Ok(())
}
