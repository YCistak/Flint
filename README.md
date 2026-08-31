# Flint

**Zero-config censorship bypass for Linux, Windows and macOS.**

Flint detects blocked or throttled traffic on its own and routes it through the best
method that actually works — no VPS, no JSON config, no manual tuning. If you *do* own
a VPS, Flint uses it as a faster dedicated tunnel.

It also implements **Pheron**, a 2-hop onion routing protocol built on a peer-to-peer
node pool: every Flint user is a relay and a client at the same time, so the network
grows with its users instead of with donated infrastructure.

> **Status: v0.5.0, pre-release.** The fallback chain, the DPI engine, the VLESS tunnel
> and Pheron are implemented and unit-tested. v1.0.0 is gated on cross-platform
> verification and the published protocol spec — see [PLANNED.md](PLANNED.md).

---

## Why

Existing tools fail in one of two directions:

| | Problem |
|---|---|
| **Powerful but complex** — sing-box, Clash | Need a VPS, a JSON config and networking knowledge |
| **Simple but weak** — Psiphon, Lantern | No VPS needed, but slow, unstable, privacy-questionable |

Flint aims to be both simple and strong.

## How it works

Flint probes each method and keeps the fastest one that survives. The user does nothing.

```
1. DPI Bypass      → fast, serverless, defeats throttling (Discord, Steam, Spotify)
2. Own VPS (VLESS) → fastest tunnel, you control the server        [if configured]
3. Pheron Relay    → 2-hop P2P onion routing over the user pool
4. Tor             → slow but always there, maximum anonymity
```

Detection runs before routing — DNS resolution, TCP connect, RST/timeout detection and a
latency baseline — cached per domain for 24 hours. A bundled blocklist (Turkey, Russia,
Iran, China) removes the cold-start delay for domains that are known to be blocked.

## Pheron

```
Client
  │  Outer layer: sealed to Node1's public key — contains Node2's address
  ▼
Node 1 ── decrypts outer layer → sees only "forward this to Node2"
  │        cannot see destination or content
  ▼
Node 2 ── decrypts inner layer → sees only destination and content
  │        cannot see who the client is
  ▼
Destination
```

- **Node 1 knows who you are, not where you are going. Node 2 knows the reverse.**
- Even if both hops collude they cannot cryptographically link identity to destination —
  each layer is sealed with a fresh ephemeral X25519 key that is discarded immediately.
- 2 hops are mandatory. 1-hop is never used, because the privacy guarantee breaks.
  Below 2 available peers Pheron steps aside and Tor takes over.
- Peer discovery is a gossip protocol over the relay listener — the pool grows past the
  bootstrap set, so there is no central directory to seize.
- Hop selection weights peers by reputation (Laplace-smoothed reliability × EWMA latency)
  and prefers hops in different regions.

Crypto: X25519 key exchange · ChaCha20-Poly1305 AEAD · HKDF-SHA256.
Protocol notes, including the honest caveat about relay static keys, live in
[`spec/PHERON.md`](spec/PHERON.md).

## Install

Requires Go 1.23 and Rust 1.75 — the DPI engine is a Rust static library the Go binary
links against, so **Rust builds first**. Full matrix in [BUILD.md](BUILD.md).

```sh
git clone https://github.com/YCistak/Flint.git
cd Flint
make            # cargo build --release, then go build -o flint
```

Linux also needs `libnfnetlink-dev` and `libmnl-dev`; Windows needs the WinDivert 2.x
driver; macOS needs the Xcode CLI tools.

## Usage

```sh
flint start                       # start the daemon, pick a method automatically
flint status                      # which method is live, plus pool metrics
flint add-vps 1.2.3.4:443 <uuid>  # register your own VLESS server
flint node                        # node pool status
flint stop
```

| Flag | Effect |
|---|---|
| `--no-node` | Client only — use the pool, don't relay for others |
| `--method dpi\|vless\|pheron\|tor` | Force one method instead of the chain |
| `--verbose` | Verbose logging |
| `--config PATH` | Alternate config file |

Config lives at `~/.config/flint/config.toml`. The IPC socket is mode 0666, so `status`
and friends work without `sudo`.

## Layout

| Path | Language | Contents |
|---|---|---|
| `core/` | Go | Daemon, detection engine, fallback chain, blocklist, IPC |
| `dpi/` | Rust | Packet capture (nfqueue / WinDivert / BPF) and bypass strategies |
| `pheron/` | Go | Node server, client, onion crypto, peer pool and gossip |
| `tunnel/vless/` | Go | VLESS-over-TLS dialer and local SOCKS5 front-end |
| `tor/` | Go | Managed Tor process via `cretz/bine` |
| `cli/` | Go | Cobra CLI |
| `spec/` | — | Pheron protocol specification |

```sh
go test ./...          # Go units
cd dpi && cargo test   # Rust units
```

## Legal

Flint is a privacy and anti-censorship tool, published for people who need to reach the
open internet from networks that filter it. Check your local law before using it, and
don't use it to attack other people's infrastructure.

## License

[GPL-3.0](LICENSE).
