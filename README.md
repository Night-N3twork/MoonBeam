# @nightnetwork/moonbeam

Browser network stack — Wisp v2.1 client, virtual LAN gateway, TCP/UDP NAT, DHCP, egress policy, and QEMU-wasm FakeWebSocket shim.

## Status

Faithful extraction of Eclipse's `src/net/`. Same code, same behavior, same tests.

- 289/289 tests passing (identical to Eclipse's net-scoped baseline).
- Two deviations from strict verbatim, both documented in the design spec: (a) one-line `?? undefined` fix on `src/udp-nat.ts:293` (real latent Eclipse type bug), (b) TypeScript pinned at `~5.4.0` (matches Eclipse's stated intent).
- Additional build tooling MoonBeam owns (Eclipse doesn't have because Eclipse doesn't publish): `tsconfig.build.json` and `scripts/fix-esm-extensions.mjs`.

Pre-1.0. No stability promise until 1.0.0.

## Install

```bash
npm install @nightnetwork/moonbeam
```

## Prerequisites

- Modern JS runtime (browser or Node ≥ 20) with `EventTarget`, `Uint8Array`, `WebSocket`.
- **Cross-origin isolation** (COOP `same-origin` + COEP `require-corp`) if callers use `SharedArrayBuffer`.
- A reachable Wisp v2.1 server (e.g. [`@mercuryworkshop/wisp-js`](https://www.npmjs.com/package/@mercuryworkshop/wisp-js) or a compatible v1 server — `allowV1: true` is the default).

## Quickstart

```ts
import { Gateway } from '@nightnetwork/moonbeam';

// 1. Configure the gateway. Only `wispUrl` is required; everything else
//    has sensible defaults (see GatewayConfig).
const gateway = new Gateway({
  wispUrl: 'wss://your-wisp-server/',
  // Optional:
  //   egress: { allow: ['public'] },      // egress policy
  //   gatewayIp: '192.168.127.1/24',      // LAN CIDR
  //   vmIp: '192.168.127.2',              // VM address served via DHCP
  //   dnsServer: '1.1.1.1',
});

// 2. Bring it up. init() connects the WispClient, wires the NATs, and
//    starts the DHCP service.
await gateway.init();

// 3. Attach a guest. The exact wiring depends on your host — QEMU-wasm,
//    a Web Worker, another VM shim — but at the L2 layer you just shuttle
//    Ethernet frames in and out of the gateway.
//
//    Example for QEMU-wasm: intercept its socket via FakeWebSocket.
//    Example for a custom guest: feed frames directly to the tun/tap
//    interface exposed on `gateway`.
```

For richer wiring examples (FakeWebSocket for QEMU-wasm, direct tun/tap injection, egress policy composition), see Eclipse's `src/core/eclipse.ts` — that file demonstrates every consumption pattern MoonBeam supports.

## Components

Everything is re-exported from the package root; there are no subpath entries.

- **`WispClient`** — Wisp v2.1 protocol client. Manages the WebSocket, multiplexes streams, handles the CONTINUE credit protocol, supports v1 fallback.
- **`Gateway`** — Composes `WispClient` + `TcpNat` + `UdpNat` + `DhcpService` + policy into a virtual LAN.
- **`TcpNat`, `UdpNat`** — Stateful NATs that translate guest packets into Wisp streams.
- **`DhcpService`** — Serves DHCP inside the virtual LAN.
- **`EgressPolicy`** — Configurable allow/deny for outbound connections.
- **`FakeWebSocket`, `installFakeWebSocket`** — Intercepts QEMU-wasm's WebSocket instantiation without touching globals.
- **`createSoftRouter`, `SoftRouter`** — Packet routing between LAN and gateway.
- **Packet helpers** — `parseIPv4`, `parseTcp`, `parseUdp`, `parseEthernet`, `buildIPv4Packet`, `buildTcpSegment`, `buildUdpSegment`, `buildEthernetFrame`, `ipToNum`, `numToIp`, `parseCidr`, etc.

## Relay endpoint (v0.2)

MoonBeam v0.2 adds `MoonbeamRelay` — an in-page wisp relay that accepts wisp
frames from local WASM clients over `MessagePort` and forwards them through a
shared upstream `WispClient`. Designed for consumers like Nova that run in a
browser worker and need wisp egress without opening their own WebSocket.

```ts
import { MoonbeamRelay } from '@nightnetwork/moonbeam';

const relay = await MoonbeamRelay.create({
  wispUrl: 'wss://your-wisp-server/',
});

const port = relay.attach();     // returns MessagePort to hand to a client
// ... client speaks wisp over `port` ...
relay.detach(port);              // reclaim resources for that client
await relay.close();             // tear down all clients + upstream WebSocket
```

The relay does stream-level pass-through: each attached client's stream IDs
are rewritten to relay-unique IDs before forwarding upstream, and rewritten
back on the return path. Multiple clients can share one relay, sharing the
single upstream WebSocket.

## Scripts

```bash
npm install                 # install deps
npm test                    # unit tests (12 files, 289 tests)
npm run test:integration    # integration tests (opt-in, network-dependent)
npm run build               # emit dist/ (tsc + ESM extension fixer)
```

`npm run typecheck` is currently broken due to a `rootDir`/`include` contradiction inherited from Eclipse's tsconfig. This is a known follow-up; runtime and build are unaffected. Vitest uses esbuild and doesn't hit this path.

## License

Apache-2.0. Extracted from [Eclipse](https://github.com/) (Apache-2.0). See `LICENSE`.
