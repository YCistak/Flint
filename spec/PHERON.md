# Pheron Protocol Specification

> Full specification to be populated

## Overview

Pheron is a 2-hop onion routing protocol designed for speed and privacy without requiring dedicated relay infrastructure.

## Sections (TBD)

- Packet format
- Key exchange (X25519)
- Encryption (ChaCha20-Poly1305)
- Peer discovery protocol
- Node pool state synchronization
- 2-hop selection algorithm
- Forward secrecy mechanism

## Forward secrecy (current state, v0.2)

Every onion layer is sealed with a **fresh ephemeral X25519 key** on the client
side: the layer key is `ECDH(ephemeral_client, static_relay)`, and the ephemeral
private key is discarded immediately after the layer is sealed.

This delivers:

- **Per-session key independence** — each circuit derives its keys from new
  ephemerals, so compromising one session reveals nothing about another.
- **Sender-side forward secrecy** — the client holds no long-term secret, so
  compromising a client yields nothing that decrypts recorded circuits.

It does **not** yet protect against later compromise of a relay's *static*
private key: because the ephemeral public key travels in the clear, an adversary
holding recorded traffic plus a relay's static key can recompute that relay's
layer key. The 2-hop design still prevents client↔destination correlation unless
**both** hops' static keys are compromised for the same circuit.

**Planned (future revision):** an interactive ephemeral–ephemeral handshake
(both client and relay contributing fresh keys for the streaming session key) to
extend forward secrecy to relay static-key compromise. Tracked against the
streaming key derived in `pheron/crypto` (`SecureConn`).
