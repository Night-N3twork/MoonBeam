use std::{env, path::PathBuf};

#[path = "build_support/shm_shim.rs"]
mod shm_shim;

fn build_shm_shims(out_dir: &PathBuf) {
    println!("cargo:rerun-if-changed=src/shm_shim.wat");
    println!("cargo:rerun-if-changed=build_support/shm_shim.rs");
    // moonbeam's memory is only shared when built with +atomics
    let host_shared = env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default().split(',').any(|f| f == "atomics");
    for (memory64, name) in [(false, "shm_shim32.wasm"), (true, "shm_shim64.wasm")] {
        let wasm = wat::parse_str(shm_shim::render(memory64, host_shared)).expect("shm_shim.wat failed to assemble");
        std::fs::write(out_dir.join(name), wasm).expect("couldnt write shm shim");
    }
}

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    build_shm_shims(&out_dir);

    let lwip_root = "deps/lwip/src";

    // Mirrors COREFILES + CORE4FILES from deps/lwip/src/Filelists.mk, plus the
    // ethernet netif. Partial lists link-fail: the core modules reference each
    // other (def.c provides lwip_htons, ethernet.c provides ethbroadcast, ...).
    let core_files = [
        "core/init.c",
        "core/def.c",
        "core/dns.c",
        "core/inet_chksum.c",
        "core/ip.c",
        "core/mem.c",
        "core/memp.c",
        "core/netif.c",
        "core/pbuf.c",
        "core/raw.c",
        "core/stats.c",
        "core/sys.c",
        "core/altcp.c",
        "core/altcp_alloc.c",
        "core/altcp_tcp.c",
        "core/tcp.c",
        "core/tcp_in.c",
        "core/tcp_out.c",
        "core/timeouts.c",
        "core/udp.c",
        "core/ipv4/acd.c",
        "core/ipv4/autoip.c",
        "core/ipv4/dhcp.c",
        "core/ipv4/etharp.c",
        "core/ipv4/icmp.c",
        "core/ipv4/igmp.c",
        "core/ipv4/ip4_frag.c",
        "core/ipv4/ip4.c",
        "core/ipv4/ip4_addr.c",
        "netif/ethernet.c",
    ];

    let mut build = cc::Build::new();
    build
        .include("include")
        .include(format!("{}/include", lwip_root))
        .include("deps")
        .flag("-ffreestanding")
        .flag("-fno-builtin");

    for file in core_files {
        build.file(format!("{}/{}", lwip_root, file));
    }

    build.compile("lwip");

    println!("cargo:rerun-if-changed=deps/wrapper.h");
    println!("cargo:rerun-if-changed=deps/lwipopts.h");
    println!("cargo:rerun-if-changed=include");

    let lwip_bindings = bindgen::Builder::default()
        .header("deps/wrapper.h")
        .size_t_is_usize(true)
        .clang_arg("-DNO_SYS=1")
        .clang_arg("--target=wasm32-unknown-unknown")
        .clang_arg("-nostdinc")
        .clang_arg("-Iinclude")
        .clang_arg("-Ideps")
        .clang_arg("-Ideps/lwip/src/include")
        .generate()
        .expect("failed to generate lwip bindings");
    // non needed bindings will be compiled out idgaf

    lwip_bindings
        .write_to_file(out_dir.join("lwip.rs"))
        .expect("couldnt output bindings");
}
