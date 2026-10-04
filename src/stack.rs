//actual attempt to make ts usable
use std::cell::Cell;
use std::ptr;

use wasm_bindgen::prelude::*;

use crate::dhcp::DhcpService;
use crate::gateway::{self, MAX_FRAME, ROUTER_MAC};
use crate::lwip::{
    err_enum_t_ERR_IF, err_enum_t_ERR_OK, err_t, ip4_addr, netif, pbuf, NETIF_FLAG_BROADCAST,
    NETIF_FLAG_ETHARP, NETIF_FLAG_ETHERNET, NETIF_FLAG_LINK_UP, SYS_TIMEOUTS_SLEEPTIME_INFINITE,
};
use crate::{
    etharp_output, lwip_init, netif_add, netif_input, netif_remove, netif_set_default,
    netif_set_down, netif_set_link_up, netif_set_up, pbuf_copy_partial, sys_check_timeouts,
};

const MTU: u16 = 1500;
const MAX_SLEEP_MS: u32 = 100; // protect against mean clients (we could do this better maybe? idk)
static mut NETIF: netif = unsafe { std::mem::zeroed() };

thread_local! {
    static STATE: Cell<State> = const { Cell::new(State::Fresh) };
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Fresh,
    Running,
    Stopped,
}

fn ip(bytes: &[u8]) -> Result<ip4_addr, JsError> {
    let b: [u8; 4] = bytes.try_into().map_err(|_| JsError::new("addresses must be 4 bytes"))?;
    Ok(ip4_addr { addr: u32::from_ne_bytes(b) })
}

unsafe extern "C" fn netif_init(nif: *mut netif) -> err_t {
    unsafe {
        (*nif).name = [b'm' as _, b'b' as _];
        (*nif).mtu = MTU;
        (*nif).hwaddr = ROUTER_MAC;
        (*nif).hwaddr_len = 6;
        (*nif).flags = (NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET | NETIF_FLAG_LINK_UP) as u8;
        (*nif).output = Some(etharp_output);
        (*nif).linkoutput = Some(linkoutput);
    }
    err_enum_t_ERR_OK as err_t
}

// where lwip sends output
unsafe extern "C" fn linkoutput(_nif: *mut netif, p: *mut pbuf) -> err_t {
    let Some(gw) = gateway::get() else { return err_enum_t_ERR_IF as err_t };
    let mut frame = [0u8; MAX_FRAME];
    let len = unsafe { (*p).tot_len } as usize;
    if len > MAX_FRAME {
        return err_enum_t_ERR_IF as err_t;
    }
    let copied = unsafe { pbuf_copy_partial(p, frame.as_mut_ptr().cast(), len as u16, 0) } as usize;
    gw.route_frame(&frame[..copied], ROUTER_MAC);
    err_enum_t_ERR_OK as err_t
}

#[wasm_bindgen]
pub fn start(gateway_ip: &[u8], dhcp_ip: &[u8], netmask: &[u8]) -> Result<(), JsError> {
    if STATE.get() != State::Fresh {
        return Err(JsError::new("moonbeam was already started"));
    }
    let addr = ip(gateway_ip)?;
    let mask = ip(netmask)?;
    let no_gw = ip4_addr { addr: 0 };

    unsafe {
        lwip_init();
        let nif = &raw mut NETIF;
        if netif_add(nif, &addr, &mask, &no_gw, ptr::null_mut(), Some(netif_init), Some(netif_input)).is_null() {
            return Err(JsError::new("netif_add failed"));
        }
        netif_set_default(nif);
        netif_set_link_up(nif);
        netif_set_up(nif);

        let dhcp = DhcpService::new(gateway_ip, dhcp_ip, netmask, 86400, 11000).map_err(|_| JsError::new("failed to create dhcp service"))?;
        gateway::init(nif, dhcp).ok_or_else(|| JsError::new("gateway already initialised"))?;
    }
    STATE.set(State::Running);
    Ok(())
}

// do work
#[wasm_bindgen]
pub fn tick(max_slots_per_client: u32) -> u32 {
    if STATE.get() != State::Running {
        return MAX_SLEEP_MS;
    }
    if let Some(gw) = gateway::get() {
        gw.poll_shm(max_slots_per_client);
    }
    match unsafe { sys_check_timeouts() } {
        SYS_TIMEOUTS_SLEEPTIME_INFINITE => MAX_SLEEP_MS,
        ms => ms.min(MAX_SLEEP_MS),
    }
}

#[wasm_bindgen]
pub fn stop() {
    if STATE.get() != State::Running {
        return;
    }
    STATE.set(State::Stopped);
    if let Some(gw) = gateway::get() {
        gw.shutdown();
    }
    unsafe {
        let nif = &raw mut NETIF;
        netif_set_down(nif);
        netif_remove(nif);
    }
}
