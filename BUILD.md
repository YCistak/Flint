# Build Guide

## Prerequisites

| Tool | Minimum version | Install |
|------|-----------------|---------|
| Go | 1.23 | https://go.dev/dl |
| Rust + Cargo | 1.75 | https://rustup.rs |
| CGo (gcc/clang) | any | `apt install build-essential` / `xcode-select --install` |
| **Linux only** | | |
| libnfnetlink-dev | any | `apt install libnfnetlink-dev libmnl-dev` |
| **macOS only** | | |
| libpcap-dev | any | included with Xcode CLI tools |
| **Windows only** | | |
| WinDivert driver | 2.x | https://reqrypt.org/windivert.html |

## Build order

The Rust static library **must exist** before the Go toolchain links against it.
Always build Rust first.

### 1 — Compile the Rust DPI crate

```sh
cd dpi
cargo build --release
# Produces: dpi/target/release/libflint_dpi.a (Linux/macOS)
#           dpi/target/release/flint_dpi.lib   (Windows)
cd ..
```

### 2 — Build the Go CLI

```sh
go build -o flint ./cli/...
```

### One-liner (Linux/macOS)

```sh
(cd dpi && cargo build --release) && go build -o flint ./cli/...
```

## Using the Makefile

A `Makefile` at the project root wraps the two steps:

```sh
make          # build everything (dpi lib + flint CLI)
make dpi      # rebuild only the Rust library
make cli      # rebuild only the Go CLI (requires dpi already built)
make clean    # remove all build artefacts
```

## Cross-compilation

Cross-compilation requires a matching Rust target and a compatible C cross-linker.

```sh
# Example: build for aarch64-linux from x86_64-linux
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
GOARCH=arm64 GOOS=linux CGO_ENABLED=1 \
  CC=aarch64-linux-gnu-gcc \
  CGO_LDFLAGS="$(pwd)/dpi/target/aarch64-unknown-linux-gnu/release/libflint_dpi.a" \
  go build -o flint-arm64 ./cli/...
```

## How the FFI bridge works

```
cli/main.go
  └── imports core  (package core)
        └── imports core/detector  (package detector)
              └── imports core/dpi  (package dpi — CGo)
                    │
                    │  CGo LDFLAGS: …/libflint_dpi.a (full path, not -l flag)
                    │  CGo CFLAGS:  -I…/dpi/include
                    │
                    └── dpi/target/release/libflint_dpi.a
                          │
                          └── dpi/src/ffi.rs
                                dpi_start()   #[no_mangle] extern "C"
                                dpi_stop()    #[no_mangle] extern "C"
                                dpi_status()  #[no_mangle] extern "C"
```

`dpi_start` spawns a Rust background thread that opens the platform packet
queue (Linux: nfqueue 0, macOS/Windows: idle stub until wired in v0.2).
The thread applies `SplitHelloStrategy` to every intercepted TCP packet
before reinjection.

### Linux iptables rule (required at runtime)

```sh
# Intercept outbound TLS before it leaves the host
sudo iptables -I OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 0
# Remove when done
sudo iptables -D OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 0
```

## Development tips

* `cargo check` in `dpi/` for fast Rust feedback without linking.
* `go vet ./...` for Go static analysis.
* `CGO_ENABLED=0 go build ./...` to build stubs-only (skips `core/dpi` which requires CGo).
* The `dpi/Cargo.toml` `[lib]` section produces three artefact types:
  `staticlib` (for CGo), `cdylib` (for future Python/Node bindings),
  `rlib` (for tests and `cargo check`).
