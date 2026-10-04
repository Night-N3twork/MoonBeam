#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use wasm_bindgen::prelude::wasm_bindgen;

use crate::lwip::{err_t, ip4_addr_t, netif, netif_init_fn, netif_input_fn, pbuf, pbuf_layer, pbuf_type};

mod lwip {
    include!(concat!(env!("OUT_DIR"), "/lwip.rs"));
}

//stuff bindgen isnt doing for some reason

unsafe extern "C" {
    pub fn pbuf_alloc(layer: pbuf_layer, length: u16, type_: pbuf_type) -> *mut pbuf;
    pub fn pbuf_free(pbuf: *mut pbuf) -> u8;
    pub fn pbuf_take(pbuf: *mut pbuf, data: *const std::ffi::c_void, len: u16) -> err_t;
    pub fn pbuf_copy_partial(pbuf: *const pbuf, data: *mut std::ffi::c_void, len: u16, offset: u16) -> u16;
    pub fn netif_input(pbuf: *mut pbuf, netif: *mut netif) -> err_t;

    pub fn lwip_init();
    pub fn netif_add(
        netif: *mut netif,
        ipaddr: *const ip4_addr_t,
        netmask: *const ip4_addr_t,
        gw: *const ip4_addr_t,
        state: *mut std::ffi::c_void,
        init: netif_init_fn,
        input: netif_input_fn,
    ) -> *mut netif;
    pub fn netif_set_default(netif: *mut netif);
    pub fn netif_set_up(netif: *mut netif);
    pub fn netif_set_down(netif: *mut netif);
    pub fn netif_set_link_up(netif: *mut netif);
    pub fn netif_remove(netif: *mut netif);
    pub fn etharp_output(netif: *mut netif, pbuf: *mut pbuf, ipaddr: *const ip4_addr_t) -> err_t;

    pub fn sys_check_timeouts() -> u32;
}

// web bindings

#[wasm_bindgen]
unsafe extern "C" {
    #[wasm_bindgen(js_namespace = performance, js_name = now)]
    pub(crate) unsafe fn performance_now() -> f64;
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sys_now() -> u32 {
    (unsafe { performance_now() }) as u32
}

mod gateway;
mod dhcp;
mod stack;

macro_rules! log {
    ($($t:tt)*) => {
        web_sys::console::log_1(&format!($($t)*).into());
    }
}
pub(crate) use log;
pub mod ringbuf;
