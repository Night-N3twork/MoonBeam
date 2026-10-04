// Renders src/shm_shim.wat for one combination of memory types. Shared by
// build.rs and the shim tests so both use exactly the same module.

pub const SHIM_WAT: &str = include_str!("../src/shm_shim.wat");

/// `memory64`: the client memory is a 64-bit memory.
/// `host_shared`: moonbeam's own memory is a shared memory (built with +atomics).
pub fn render(memory64: bool, host_shared: bool) -> String {
    let host = if host_shared { "1 65536 shared" } else { "1" };
    let (client, a, ca, to_a, mem_bytes) = if memory64 {
        (
            "i64 1 281474976710656 shared",
            "i64",
            "(i64.extend_i32_u (local.get $x))",
            "(local.get $x)",
            "(i64.shl (memory.size $client) (i64.const 16))",
        )
    } else {
        (
            "1 65536 shared",
            "i32",
            "(local.get $x)",
            "(i32.wrap_i64 (local.get $x))",
            "(i64.shl (i64.extend_i32_u (memory.size $client)) (i64.const 16))",
        )
    };

    SHIM_WAT
        .replace("@HOST_LIMITS", host)
        .replace("@CLIENT_LIMITS", client)
        .replace("@CA_BODY", ca)
        .replace("@TOA_BODY", to_a)
        .replace("@MEMBYTES_BODY", mem_bytes)
        .replace("@A.", &format!("{a}."))
        .replace("@A", a)
}
