# @nightnetwork/moonbeam

**Browser network stack. Wisp relay, virtual LAN, TCP/UDP NAT.**

Complete browser-side networking library providing a Wisp v2.1 client, in-page relay with local TCP listener registration, virtual LAN gateway with DHCP, TCP/UDP NAT, configurable egress policy, and QEMU-wasm integration.

**Version 1.0.0** · Apache-2.0

---

## Features

### MoonbeamRelay

In-page Wisp relay endpoint. Accepts Wisp frames from local consumers (Nova, other WASM clients) over `MessagePort` transports and forwards them through a shared upstream `WispClient`.

- **MessagePort transport** — each attached client gets its own `MessagePort`; no WebSocket per client
- **Stream-level pass-through** — stream IDs are rewritten to relay-unique IDs before forwarding upstream, rewritten back on the return path
- **Local TCP listener registration** — `registerListener(host, port, handler)` intercepts CONNECT requests matching a host:port and routes them to an in-process handler instead of upstream
- **Virtual IP pool** — each attached client receives a unique `100.64.0.x` address from a 254-address CGNAT pool
- **Flow control** — CONTINUE credit protocol for TCP streams; bounded receive windows for local streams with automatic replenishment
- **Client snapshots** — `clientsSnapshot()` and `listenersSnapshot()` return frozen observability views of all attached clients, their streams, and registered listeners

### WispClient

From-scratch Wisp v2.1 protocol client.

- **Wisp v2.1 and v1 support** — full v2 INFO handshake with extension negotiation; v1 fallback enabled by default (`allowV1: true`)
- **WebSocket transport** — single multiplexed WebSocket connection; works in browsers, Web Workers, and Node 22+
- **Stream multiplexing** — create TCP and UDP streams over one connection with automatic stream ID management
- **CONTINUE credit protocol** — per-stream TCP backpressure with credit tracking and send queuing
- **Dual API** — both Streams API (`readable`/`writable`) and event API (`on('data')`, `on('close')`, etc.) per stream
- **Extension negotiation** — UDP, Stream Open Confirmation, MOTD, password/pubkey auth detection
- **Error codes** — `E_WISP_HANDSHAKE`, `E_WISP_V1_UNSUPPORTED`, `E_WISP_AUTH_REQUIRED`, `E_WISP_STREAM_ID_EXHAUSTED`, `E_WISP_UDP_UNSUPPORTED`

### Gateway

Top-level orchestrator composing a virtual LAN from all subsystems.

- **Full virtual LAN** — lwIP `NetworkStack` with Tun, Loopback, and Tap interfaces wired in LIFO order per spec §2.4
- **Automatic DHCP** — single-client DHCP lease for the VM (configurable or disabled with `vmIp: null`)
- **Soft-router** — parallel IP forwarder that intercepts off-subnet guest packets and routes them to the NATs, bypassing lwIP's endpoint-only limitation
- **Host-side service bindings** — `connectTcp()`, `listenTcp()`, `openUdp()` for host code
- **Hot-swap support** — `setWispClient()` atomically swaps the upstream Wisp connection; NATs read the current client via callback
- **Lifecycle events** — `connect`, `disconnect`, `error`, `wisp-changed`

### TcpNat

Stateful TCP NAT translating guest IPv4/TCP packets into multiplexed Wisp TCP streams.

- **NAT transparency** — guest sees responses as if from the remote server (src=remote, dst=guest)
- **Sequence-number tracking** — u32 modular arithmetic per RFC 793; out-of-order packets dropped (guest retransmits)
- **MSS chunking** — upstream Wisp chunks are segmented to 1460B MSS before delivery to guest (avoids virtio-net oversized frame crashes)
- **Swap-in-progress queue** — SYNs during Wisp hot-swap are buffered (bounded, default 256) and drained when the new client is live
- **Stream Open Confirmation** — defers SYN-ACK until upstream confirms (when negotiated), giving the guest ECONNREFUSED semantics
- **`resetAll()`** — RST every active flow for hot-swap orchestration

### UdpNat

Stateful UDP NAT with per-5-tuple flow tracking.

- **LRU eviction** — capped at `maxFlows` (default 1024) with least-recently-used eviction
- **Idle sweeper** — closes flows idle longer than `idleTimeoutMs` (default 60s)
- **ICMP port-unreachable** — synthesized for policy-denied or swap-in-progress datagrams
- **Stats** — `getStats()` returns active flows, total created, forwarded, and dropped counts

### EgressPolicy

Configurable allow/deny policy for outbound connections.

- **Allow tokens** — `'public'` (excludes all IANA reserved ranges), `'*'` (everything except loopback unless opted in), or explicit CIDR strings
- **Deny list** — CIDR-based hard deny (wins over allow)
- **Port deny** — block specific ports globally
- **Loopback guard** — `allowLoopback: false` (default) prevents routing localhost through remote Wisp
- **`onBlocked` callback** — receives structured `BlockedInfo` with IP, port, proto, and reason (`rfc1918`, `cgnat`, `loopback`, `multicast`, `deny-cidr`, `deny-port`, etc.)
- **Allocation-free success path** — `permits()` allocates nothing on allow; only the blocked path creates objects

### FakeWebSocket

QEMU-wasm WebSocket interception.

- **`WebSocket`-shaped API** — extends `EventTarget`; supports `addEventListener`, `on*` setters, `send()`, `close()`, `readyState`, `binaryType`
- **`FakeWebSocketHost` interface** — `onConnect`, `onSend`, `onClose` callbacks route bytes into the in-page lwIP stack
- **`installFakeWebSocket(Module, host)`** — patches Emscripten's `Module.websocket.WebSocketConstructor` and optionally `globalThis.WebSocket` with sentinel-URL detection; returns an `uninstall` function
- **No globals in workers** — auto-detects `WorkerGlobalScope` and skips the global patch unless `forceGlobalPatch: true`

### Packet helpers

Pure-function codec for Ethernet, IPv4, TCP, UDP, ICMP, and ARP.

- `parseIPv4` / `buildIPv4Packet`
- `parseTcp` / `buildTcpSegment`
- `parseUdp` / `buildUdpSegment`
- `parseEthernet` / `buildEthernetFrame`
- `buildIcmpPortUnreachable`
- `ipToNum` / `numToIp` / `parseCidr` / `isInSubnet` / `macEquals`

---

## Installation

```bash
npm install @nightnetwork/moonbeam
```

Requires a modern JS runtime (browser or Node ≥ 20) with `EventTarget`, `Uint8Array`, `ReadableStream`/`WritableStream`, and `WebSocket`. Cross-origin isolation (COOP `same-origin` + COEP `require-corp`) is needed if callers use `SharedArrayBuffer`.

---

## Quick start

### MoonbeamRelay with Nova

```ts
import { MoonbeamRelay } from '@nightnetwork/moonbeam';

// Create a relay backed by a Wisp server
const relay = await MoonbeamRelay.create({
  wispUrl: 'wss://your-wisp-server/',
});

// Attach a client — returns a MessagePort to hand to Nova
const port = relay.attach({ label: 'nova-worker' });

// Register a local TCP listener (e.g., for localhost:8080)
const unregister = relay.registerListener('localhost', 8080, (socket) => {
  socket.onData((data) => {
    // Handle incoming data from the client
    socket.send(new TextEncoder().encode('HTTP/1.1 200 OK\r\n\r\nHello'));
    socket.close();
  });
});

// Observability
console.log(relay.clientCount());        // 1
console.log(relay.clientsSnapshot());    // frozen snapshot of all clients + streams
console.log(relay.listenersSnapshot());  // frozen snapshot of registered listeners

// Cleanup
unregister();          // remove the listener
relay.detach(port);    // detach the client
await relay.close();   // tear down relay + upstream WebSocket
```

### Gateway with QEMU-wasm

```ts
import {
  Gateway,
  FakeWebSocket,
  installFakeWebSocket,
  type FakeWebSocketHost,
} from '@nightnetwork/moonbeam';

// 1. Create and initialize the gateway
const gateway = new Gateway({
  wispUrl: 'wss://your-wisp-server/',
  egress: { allow: ['public'] },
  gatewayIp: '192.168.127.1/24',
});
await gateway.init();

// 2. Wire QEMU-wasm's networking through the gateway
const tap = gateway.getTap();
const softRouter = gateway.getSoftRouter();

const host: FakeWebSocketHost = {
  onConnect(send) {
    // Pump frames from tap + soft-router to QEMU
    const reader = tap.readable.getReader();
    (async () => {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        send(value);
      }
    })();
    softRouter.setSend(send);
  },
  onSend(data) {
    // Guest frame → lwIP + soft-router
    const writer = tap.writable.getWriter();
    writer.write(data).then(() => writer.releaseLock());
    softRouter.ingress(data);
  },
  onClose() {
    gateway.destroy();
  },
};

// 3. Install the FakeWebSocket before QEMU boots
const uninstall = installFakeWebSocket(Module, host);

// QEMU's `-netdev socket,connect=ws://wisp-gateway.local/` will be
// intercepted and routed through the in-page gateway.
```

---

## API reference

### MoonbeamRelay

```ts
class MoonbeamRelay {
  static create(opts: MoonbeamRelayOptions): Promise<MoonbeamRelay>
  attach(metadata?: MoonbeamAttachmentMetadata): MessagePort
  detach(port: MessagePort): void
  registerListener(host: string, port: number, handler: MoonbeamLocalConnectionHandler): () => void
  close(): Promise<void>
  clientCount(): number
  streamCount(): number
  clientsSnapshot(): readonly MoonbeamClientSnapshot[]
  listenerCount(): number
  listenersSnapshot(): readonly MoonbeamListenerSnapshot[]
  isClosed(): boolean
}
```

| Method | Description |
|---|---|
| `create(opts)` | Async factory. Connects to the upstream Wisp server and resolves when the handshake completes. |
| `attach(metadata?)` | Attach a new client. Returns a `MessagePort` the client uses to speak Wisp frames. Assigns a virtual IP from the `100.64.0.0/24` pool. |
| `detach(port)` | Detach a client by its `MessagePort`. Closes all streams and reclaims the virtual IP. |
| `registerListener(host, port, handler)` | Register a local TCP listener. CONNECT requests matching `host:port` are routed to `handler` instead of upstream. Returns an unregister function. |
| `close()` | Gracefully shut down: detach all clients, close listeners, close the upstream `WispClient`. |
| `clientCount()` | Number of currently attached clients. |
| `streamCount()` | Total open upstream + local streams across all clients. |
| `clientsSnapshot()` | Frozen snapshot of all clients and their streams (id, virtualIp, label, connectedAt, streams). |
| `listenerCount()` | Number of registered listeners. |
| `listenersSnapshot()` | Frozen snapshot of all listeners (host, port, activeStreams). |
| `isClosed()` | Whether the relay has been closed. |

### Gateway

```ts
class Gateway {
  constructor(config: GatewayConfig)
  init(): Promise<void>
  destroy(): Promise<void>
  getStack(): NetworkStack
  getTap(): TapInterface
  getTun(): TunInterface
  getSoftRouter(): SoftRouter
  getVmIp(): string
  get wisp(): WispClient
  get swapInProgress(): boolean
  connectTcp(host: string, port: number): Promise<TcpSocket>
  listenTcp(port: number): Promise<TcpListener>
  openUdp(port?: number): Promise<UdpSocket>
  setWispClient(newClient: WispClient): void
  on(event: string, listener: Function): () => void
}
```

| Option | Default | Description |
|---|---|---|
| `wispUrl` | *(required)* | Wisp v2.1 endpoint URL |
| `egress` | `{ allow: ['public'] }` | Egress policy configuration |
| `gatewayIp` | `'192.168.127.1/24'` | LAN-side gateway IP in CIDR |
| `gatewayMac` | `'02:00:00:00:00:01'` | Gateway MAC address |
| `vmIp` | gateway + 1 | VM IP for DHCP; `null` disables DHCP |
| `dnsServer` | `'1.1.1.1'` | DNS advertised via DHCP |
| `dhcpLeaseTime` | `86400` | DHCP lease duration in seconds |
| `tunIp` | `'240.0.0.1/0'` | Tun interface IP (Class E, never-routable) |
| `allowV1` | `true` | Accept Wisp v1 servers |
| `udpAssumedInV1` | `true` | Assume UDP support for v1 servers |

---

## Architecture overview

```
┌─────────────────────────────────────────────────────────┐
│  Browser page                                           │
│                                                         │
│  ┌──────────┐     MessagePort      ┌────────────────┐   │
│  │  Nova /  │◄────────────────────►│ MoonbeamRelay  │   │
│  │  WASM    │  Wisp frames         │  (in-page)     │   │
│  └──────────┘                      └───────┬────────┘   │
│                                            │            │
│  ┌──────────┐   FakeWebSocket    ┌─────────▼────────┐   │
│  │  QEMU-   │◄──────────────────►│    Gateway       │   │
│  │  wasm    │  Ethernet frames   │  ┌─────────────┐ │   │
│  └──────────┘                    │  │  lwIP Stack  │ │   │
│                                  │  │  Tap/Tun/Lo  │ │   │
│                                  │  └──────┬──────┘ │   │
│                                  │         │        │   │
│                                  │  ┌──────▼──────┐ │   │
│                                  │  │ SoftRouter   │ │   │
│                                  │  └──┬───────┬──┘ │   │
│                                  │     │       │    │   │
│                                  │  ┌──▼──┐ ┌──▼──┐│   │
│                                  │  │TcpNat│ │UdpNat││   │
│                                  │  └──┬──┘ └──┬──┘│   │
│                                  │     │       │    │   │
│                                  │  ┌──▼───────▼──┐│   │
│                                  │  │ EgressPolicy ││   │
│                                  │  └──────┬──────┘│   │
│                                  └─────────┼───────┘   │
│                                            │            │
│                                     ┌──────▼──────┐     │
│                                     │ WispClient  │     │
│                                     │ (WebSocket) │     │
│                                     └──────┬──────┘     │
└────────────────────────────────────────────┼─────────────┘
                                             │
                                    ┌────────▼────────┐
                                    │  Wisp Server    │
                                    │  (remote)       │
                                    └─────────────────┘
```

The **Gateway** path handles full virtual-machine networking: guest Ethernet frames flow through the lwIP stack and soft-router. Off-subnet IP packets are extracted, passed through the TCP/UDP NATs, checked against the egress policy, and forwarded as Wisp streams.

The **MoonbeamRelay** path is lighter-weight: WASM clients speak Wisp directly over `MessagePort`. The relay rewrites stream IDs and multiplexes all clients onto a single upstream `WispClient`. Local TCP listeners allow in-process request interception without hitting the network.

---

## Testing

```bash
npm test              # 330+ unit tests via Vitest
npm run test:watch    # watch mode
npm run typecheck     # tsc --noEmit (see known issue below)
npm run build         # emit dist/ (tsc + ESM extension fixer)
```

The test suite covers all components: WispClient handshake (v1 and v2), stream multiplexing, credit protocol, MoonbeamRelay attach/detach/listener lifecycle, TCP NAT connection/data/FIN/RST/swap-queue flows, UDP NAT flow tracking/eviction/ICMP, DHCP DISCOVER/REQUEST/NAK/RELEASE, egress policy allow/deny/CIDR/port/loopback, FakeWebSocket state machine, soft-router MAC learning and IP forwarding, and packet codec round-trips.

**Known issue:** `npm run typecheck` currently reports errors due to a `rootDir`/`include` contradiction inherited from the original tsconfig. Runtime, build, and tests are unaffected — Vitest uses esbuild and does not hit this path.

---

## Browser requirements

- Modern browser or Node ≥ 20
- `EventTarget`, `MessageChannel`, `MessagePort`
- `ReadableStream`, `WritableStream` (WHATWG Streams)
- `WebSocket` (for `WispClient`; not needed if using `_injectWebSocket`)
- `Uint8Array`, `DataView`, `ArrayBuffer`
- Cross-origin isolation headers if using `SharedArrayBuffer`

---

## Migration from 0.x

### 0.x → 1.0.0

- **Stable API** — all public interfaces are now considered stable. The `MoonbeamRelay`, `WispClient`, `Gateway`, and all NAT/policy/packet APIs have settled.
- **MoonbeamRelay** — introduced in 0.2, now fully stable with local TCP listener support, virtual IP assignment, and observability snapshots.
- **No breaking changes** from 0.3 — the 1.0 release is a stability milestone. All existing imports and usage patterns continue to work.
- **Package access** — published as `public` on npm (was `restricted` in 0.x).

---

## Contributing

1. Fork & clone
2. `npm install`
3. `npm test` — all tests must pass
4. `npm run typecheck` — note the known tsconfig issue; focus on new code being type-clean
5. Open a PR against `main`

---

## License

Apache-2.0
