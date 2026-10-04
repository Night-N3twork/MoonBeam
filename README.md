## moonbeam but way different and in rust

- supports clients communicating over messageport or shm ring buffer that works with wasm32 or wasm64 clients (or js ofc)
- good documentation is being worked on
- has dhcp server that can lend 64 addresses (dont ask why)
- will support internet access over wisp

### building:

make sure to include the lwip submodule

you will need:
- rust target wasm32-unknown-unknown
- wasm-bindgen-cli version 0.2.126 exactly
- nodejs 24 or later
