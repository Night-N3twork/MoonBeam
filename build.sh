#!/usr/bin/env bash
# Builds moonbeam for the web into pkg/ (wasm + wasm-bindgen JS glue).
#   ./build.sh           debug build
#   ./build.sh release   optimised build
#   ./build.sh test      debug build, then shim tests and the node e2e + dhcp tests
set -euo pipefail
cd "$(dirname "$0")"

profile=debug
cargo_flags=()
if [[ "${1:-}" == release ]]; then
  profile=release
  cargo_flags=(--release)
fi

cargo build --target wasm32-unknown-unknown "${cargo_flags[@]}"
wasm-bindgen --target web --out-dir pkg "target/wasm32-unknown-unknown/$profile/moonbeam.wasm"

if [[ "${1:-}" == test ]]; then
  (cd shim-tests && cargo test)
  node js/test/e2e.mjs
  node js/test/dhcp.mjs
fi
