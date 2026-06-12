# PLANNED.md — Flint

## What is it?

Flint is a zero-config censorship bypass tool for Linux, Windows, and macOS. It automatically detects blocked or throttled traffic and routes it through the best available method — no VPS required, no manual configuration. Users who have their own VPS get a faster, dedicated tunnel.

Flint also implements **Pheron**, a custom 2-hop onion routing protocol built on a peer-to-peer node pool. Every Flint user is simultaneously a node and a client — the network grows with the user base.

---

## Problem

Existing tools fail in one of two ways:

- **Powerful but complex** (sing-box, Clash) — require a VPS, JSON config, technical knowledge. Normal users can't use them.
- **Simple but weak** (Psiphon, Lantern) — no VPS needed, but slow, unstable, privacy-questionable.

**No tool is both simple and strong. Flint is.**

---

## How it works

### Fallback Chain — No VPS

```
1. DPI Bypass      → fast, no server, defeats throttling (Discord, Steam, Spotify)
2. Pheron Relay    → 2-hop P2P, user pool, cryptographic privacy guarantee
3. Tor             → slow but always available, maximum anonymity
```

### Fallback Chain — With VPS

```
1. DPI Bypass      → fast, no server
2. Own VPS (VLESS) → fastest tunnel, full privacy, user controls the server
3. Pheron Relay    → P2P fallback
4. Tor             → last resort
```

Flint tests each method automatically and picks the best working one. The user does nothing.

---

## Pheron Protocol

Pheron is a 2-hop onion routing protocol designed for speed and privacy without requiring dedicated relay infrastructure.

### Core properties
- Every Flint user is a node. Opening Flint = joining the pool.
- Every connection uses exactly 2 hops, chosen randomly from the pool.
- If fewer than 2 other nodes are available, Pheron is skipped — Tor is used instead.
- 2-hop is mandatory. 1-hop is never used (privacy guarantee broken).

### How a connection works

```
Client
  │
  │  Outer layer: encrypted with Node1's public key
  │  Contains: Node2 address + inner payload
  ▼
Node 1
  │  Decrypts outer layer → sees only: "forward this to Node2"
  │  Cannot see: destination, content
  ▼
Node 2
  │  Decrypts inner layer → sees only: destination + content
  │  Cannot see: who the original client is
  ▼
Destination
```

### Security model
- Node1 knows who you are, not where you're going
- Node2 knows where you're going, not who you are
- Even if Node1 and Node2 collude, they cannot cryptographically link identity to destination (forward secrecy per session)
- Nodes are selected randomly; same node is never used for both hops

### Node pool
- Pool is dynamic — nodes join when Flint opens, leave when it closes
- Pool state is distributed (no central server)
- Node selection avoids same ASN / geographic region for both hops when possible

---

## Architecture

```
flint/
├── core/                   # Go — main daemon, fallback orchestration
│   ├── detector/           # Automatic block/throttle detection
│   ├── fallback/           # Fallback chain manager
│   ├── config/             # User config loader
│   └── main.go
├── dpi/                    # Rust — DPI bypass engine
│   ├── packet/             # Packet capture and manipulation
│   └── strategies/         # Split hello, TTL manipulation, desync
├── pheron/                 # Go — Pheron protocol implementation
│   ├── node/               # Node server (relay mode)
│   ├── client/             # Client (routing mode)
│   ├── crypto/             # Key exchange, onion encryption
│   └── pool/               # Peer discovery, pool management
├── tunnel/                 # Go — VPS tunnel (VLESS)
├── tor/                    # Go — Tor integration (bine/pt)
├── cli/                    # Go — CLI interface
├── spec/                   # Pheron protocol specification
│   └── PHERON.md
├── PLANNED.md
└── README.md
```

---

## Language Decisions

| Component | Language | Reason |
|-----------|----------|--------|
| Core daemon | Go | Goroutines ideal for concurrent connections, rich networking ecosystem |
| DPI bypass | Rust | Zero-cost abstractions, memory safety, low-level packet access |
| Pheron protocol | Go | Consistent with core, easy crypto library access |
| VLESS tunnel | Go | sing-box/Xray reference implementations in Go |
| Tor integration | Go | bine/pt library |

---

## Detection Engine

Flint tests connectivity before routing:

1. **DNS check** — is the domain resolving?
2. **TCP connect** — does the connection complete?
3. **RST/timeout detection** — is traffic being reset or throttled mid-stream?
4. **Latency baseline** — is throughput abnormally low vs expected?

Results are cached per domain/IP. Cache refreshes every 24 hours or on user request.

A bundled blocklist ships with Flint — known blocked domains/IPs for Turkey, Russia, Iran, China. This eliminates cold-start detection delay for common cases.

---

## Core Features

### v0.1.0 — DPI Bypass MVP
- [x] Rust packet capture layer (Linux: netfilter/nfqueue, Windows: WinDivert, macOS: libpcap/BPF)
- [x] IP and TCP header parsers
- [x] TLS ClientHello detector with SNI extraction
- [x] TCP split hello strategy
- [x] TTL manipulation strategy
- [x] Basic Go CLI (cobra with start/stop/status/add-vps/blocklist/node commands)
- [x] Project structure (Go modules, Rust crate, config loader, fallback manager)
- [x] Unix socket permissions set to 0666 so non-root users can connect without sudo
- [x] Auto-detect platform (Linux/Windows/macOS) — `core/platform` (Detect + capture-backend mapping), tested
- [x] Bundled blocklist (Turkey + Russia baseline) — `core/blocklist` (embedded baseline + loader), tested
- [x] End-to-end DPI bypass integration — iptables rule management in `dpi/src/ffi.rs` (dpi_start adds NFQUEUE rule, dpi_stop removes it, with signal/panic cleanup), integration test in `core/dpi/dpi_integration_test.go`

### v0.2.0 — Tor Integration
- [x] Tor integration via bine/pt (`tor/handler.go` — managed Tor process, bootstrap wait, SOCKS health check)
- [x] Automatic fallback from DPI bypass to Tor (Tor handler in the fallback chain after the Pheron stub)
- [x] Detection engine (DNS + TCP + RST/timeout detection) — `core/detector/engine.go`
- [x] Detection cache (24h TTL, per-domain, invalidate-on-request) — `core/detector/cache.go`

### v0.3.0 — VPS Tunnel
- [x] VLESS protocol implementation — `tunnel/vless` (request/response header codec + UUID parsing in `vless.go`, VLESS-over-TLS dialer + local SOCKS5 proxy in `handler.go`, implements `fallback.Handler`), tested
- [x] VPS config (add server: address, port, UUID, TLS) — `flint add-vps <addr:port> <uuid>` with `--name/--sni/--no-tls/--disabled`, persists to `~/.config/flint/config.toml` (`ServerConfig` gained `TLS`/`SNI`; `TunnelConfig.ListenSOCKS`)
- [x] Fallback chain: DPI → VPS (if configured) → Pheron stub → Tor — wired in `core/main.go` via `det.VLESSHandler`, inserted only when an enabled server exists
- [x] Connection health monitoring — `Handler.Health` pings 1.1.1.1:80 through the tunnel; background `monitor` goroutine re-pings every 30s and logs health transitions

### v0.4.0 — Pheron v0.1 (Beta)
- [x] Pheron node server (relay mode) — `pheron/node` (accepts one onion layer per connection, decrypts with static key, forwards inner blob to next hop or connects to destination), relays via layered `SecureConn`
- [x] Pheron client (routing mode) — `pheron/client` (seals inner layer to hop2, wraps in hop1 layer, dials hop1, streams through nested `SecureConn`), exposes 2-hop `Circuit`; SOCKS5 front-end in `pheron/handler.go`
- [x] Onion encryption (X25519 key exchange + ChaCha20-Poly1305) — `pheron/crypto` (`Seal`/`Open` sealed box with ephemeral sender key + HKDF-SHA256; `SecureConn` length-framed AEAD stream with per-direction counter nonces), tested incl. multi-frame + reverse direction
- [x] Basic peer discovery (static bootstrap nodes) — `pheron/pool` seeded from `config.Pheron.BootstrapNodes` (`host:port@base64url-pubkey`), parsed by `detector.ParseBootstrapNodes`
- [x] 2-hop enforcement — fallback to Tor if pool < 2 nodes — `Handler.Start` fails when `pool.Count() < 2`; `pool.SelectTwo` returns `ErrInsufficientNodes` and two distinct hops, tested
- [x] Node pool join/leave on Flint open/close — `pool.Join` on `Handler.Start` (runs local relay too), `pool.Leave` on `Handler.Stop`
- [x] Labeled "Beta" in CLI — `Handler.Label()` returns "beta" via the optional `fallback.Labeled` interface; surfaced in the status JSON payload

### v0.5.0 — Pheron v0.2 (Stable)
- [ ] Distributed peer discovery (no central bootstrap dependency)
- [ ] ASN/geo-aware node selection (avoid same region for both hops)
- [ ] Forward secrecy per session
- [ ] Node reputation scoring (latency, reliability)
- [ ] Pool health metrics

### v1.0.0 — Stable Release
- [ ] Full fallback chain working on all 3 platforms
- [ ] Pheron stable
- [ ] Auto-update mechanism
- [ ] Full documentation
- [ ] Pheron protocol spec published (spec/PHERON.md)

### v2.0.0 — Dashboard
- [ ] TypeScript web dashboard
- [ ] Real-time connection stats
- [ ] Node pool visualization
- [ ] Blocklist editor

---

## CLI Interface

```
flint [OPTIONS]

Commands:
  start              Start Flint daemon
  stop               Stop Flint daemon
  status             Show current connection method and stats
  add-vps            Add a VPS server (VLESS)
  blocklist update   Update bundled blocklist
  node               Show node pool status

Options:
  --no-node          Run as client only, don't join node pool
  --method METHOD    Force a specific method (dpi, pheron, vless, tor)
  --verbose          Verbose logging
  --config PATH      Config file path
```

---

## Pheron Protocol Spec

The full Pheron protocol specification will live in `spec/PHERON.md` and will be published as a standalone document. Goal: allow third-party implementations.

Key spec sections:
- Packet format
- Key exchange (X25519)
- Encryption (ChaCha20-Poly1305)
- Peer discovery protocol
- Node pool state synchronization
- 2-hop selection algorithm
- Forward secrecy mechanism

---

## Out of Scope (v1.0.0)

- Mobile (Android/iOS)
- Browser extension
- GUI desktop app (dashboard is v2.0)
- Paid/subscription model
- Central authority of any kind

---

## Roadmap

| Version | Goal | Key milestone |
|---------|------|---------------|
| v0.1.0 | DPI bypass working | Defeats throttling on Linux/Windows/macOS |
| v0.2.0 | Tor fallback | Full fallback chain without VPS |
| v0.3.0 | VPS tunnel | Power users have dedicated tunnel |
| v0.4.0 | Pheron beta | P2P relay live, needs user growth |
| v0.5.0 | Pheron stable | Distributed, no bootstrap dependency |
| v1.0.0 | Stable release | All platforms, full docs, Pheron spec published |
| v2.0.0 | Dashboard | Visual interface, node pool stats |
