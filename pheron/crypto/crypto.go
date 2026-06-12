// Package crypto provides the cryptographic primitives for Pheron's onion
// routing: X25519 key agreement and ChaCha20-Poly1305 authenticated
// encryption.
//
// Two primitives are exposed:
//
//   - Seal/Open implement a one-shot sealed box. The sender generates an
//     ephemeral X25519 key pair, performs ECDH against the recipient's static
//     public key, derives a key with HKDF-SHA256, and encrypts with
//     ChaCha20-Poly1305. The ephemeral public key is prepended so the
//     recipient can recover the shared secret. This is used to wrap each onion
//     layer during circuit setup.
//
//   - SecureConn turns the ECDH shared secret returned by Seal/Open into a
//     bidirectional, length-framed AEAD stream. Nesting two SecureConns lets a
//     client encrypt a payload in layers so each relay can strip exactly one.
//
// # Forward secrecy (per session)
//
// The client holds no long-term key material: it generates a fresh ephemeral
// X25519 key pair for every layer of every circuit (see Seal). Two consequences
// follow, verified by the tests in this package:
//
//   - Session-key independence. Each circuit derives its layer keys from fresh
//     ephemerals, so compromising one session's keys reveals nothing about any
//     other session — past or future. There is no client-side long-term secret
//     whose compromise could unravel recorded traffic.
//
//   - Sender-side forward secrecy. The ephemeral private key is discarded as
//     soon as Seal returns; it is never stored or transmitted (only its public
//     half goes on the wire). An adversary who later compromises the *client*
//     learns nothing that decrypts recorded circuits.
//
// Caveat — relay static keys are long-term. The shared secret for a layer is
// ECDH(ephemeral_client, static_relay). Because the ephemeral public key
// travels in the clear, an adversary who records a circuit and *later* obtains
// a relay node's static private key can recompute that layer's secret and
// decrypt the bytes that passed through that relay. Pheron's 2-hop design still
// prevents such an adversary from linking client to destination unless it
// compromises *both* hops' static keys for the same circuit. Achieving forward
// secrecy against relay static-key compromise as well would require an
// interactive ephemeral-ephemeral handshake (both ends contributing fresh
// keys); that is left to a future protocol revision and noted in spec/PHERON.md.
package crypto

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// PublicKeySize is the length in bytes of an X25519 public key.
const PublicKeySize = 32

const nonceSize = chacha20poly1305.NonceSize // 12

// HKDF info labels keep the setup-seal key and the streaming key independent
// even though both derive from the same ECDH shared secret.
const (
	infoSetup  = "pheron-setup-v1"
	infoStream = "pheron-stream-v1"
)

// PublicKey is an X25519 public key.
type PublicKey [PublicKeySize]byte

// String renders the key as unpadded base64url, the form used in bootstrap
// node descriptors.
func (p PublicKey) String() string {
	return base64.RawURLEncoding.EncodeToString(p[:])
}

// ParsePublicKey decodes an unpadded base64url X25519 public key.
func ParsePublicKey(s string) (PublicKey, error) {
	var pk PublicKey
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return pk, fmt.Errorf("pheron/crypto: decode public key: %w", err)
	}
	if len(b) != PublicKeySize {
		return pk, fmt.Errorf("pheron/crypto: public key must be %d bytes, got %d", PublicKeySize, len(b))
	}
	copy(pk[:], b)
	return pk, nil
}

// KeyPair is a static X25519 key pair identifying a Pheron node.
type KeyPair struct {
	priv *ecdh.PrivateKey
}

// GenerateKeyPair creates a fresh X25519 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pheron/crypto: generate key: %w", err)
	}
	return &KeyPair{priv: priv}, nil
}

// Public returns the key pair's public key.
func (k *KeyPair) Public() PublicKey {
	var pk PublicKey
	copy(pk[:], k.priv.PublicKey().Bytes())
	return pk
}

// Seal encrypts plaintext to recipient. The returned blob is
// ephemeralPublicKey(32) || nonce(12) || ciphertext+tag. It also returns the
// ECDH shared secret so the caller can open a streaming SecureConn keyed to the
// same hop.
func Seal(recipient PublicKey, plaintext []byte) (blob, secret []byte, err error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("pheron/crypto: ephemeral key: %w", err)
	}
	recipPub, err := ecdh.X25519().NewPublicKey(recipient[:])
	if err != nil {
		return nil, nil, fmt.Errorf("pheron/crypto: invalid recipient key: %w", err)
	}
	secret, err = eph.ECDH(recipPub)
	if err != nil {
		return nil, nil, fmt.Errorf("pheron/crypto: ECDH: %w", err)
	}

	aead, err := newAEAD(secret, infoSetup)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("pheron/crypto: nonce: %w", err)
	}

	ephPub := eph.PublicKey().Bytes()
	out := make([]byte, 0, len(ephPub)+nonceSize+len(plaintext)+aead.Overhead())
	out = append(out, ephPub...)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plaintext, nil)
	return out, secret, nil
}

// Open reverses Seal using the recipient's private key, returning the plaintext
// and the ECDH shared secret.
func Open(kp *KeyPair, blob []byte) (plaintext, secret []byte, err error) {
	if len(blob) < PublicKeySize+nonceSize {
		return nil, nil, fmt.Errorf("pheron/crypto: sealed blob too short (%d bytes)", len(blob))
	}
	ephPub, err := ecdh.X25519().NewPublicKey(blob[:PublicKeySize])
	if err != nil {
		return nil, nil, fmt.Errorf("pheron/crypto: invalid ephemeral key: %w", err)
	}
	secret, err = kp.priv.ECDH(ephPub)
	if err != nil {
		return nil, nil, fmt.Errorf("pheron/crypto: ECDH: %w", err)
	}

	aead, err := newAEAD(secret, infoSetup)
	if err != nil {
		return nil, nil, err
	}
	nonce := blob[PublicKeySize : PublicKeySize+nonceSize]
	ct := blob[PublicKeySize+nonceSize:]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("pheron/crypto: decrypt layer: %w", err)
	}
	return pt, secret, nil
}

// newAEAD derives a ChaCha20-Poly1305 instance from a shared secret and an HKDF
// info label.
func newAEAD(secret []byte, info string) (cipher.AEAD, error) {
	r := hkdf.New(sha256.New, secret, nil, []byte(info))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("pheron/crypto: derive key: %w", err)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("pheron/crypto: init AEAD: %w", err)
	}
	return aead, nil
}

// ── Streaming layer ──────────────────────────────────────────────────────────

const (
	// maxFramePlaintext bounds the plaintext carried in a single stream frame.
	maxFramePlaintext = 16 * 1024
	// maxFrameCiphertext is the largest ciphertext we will read, guarding
	// against a peer announcing an absurd frame length.
	maxFrameCiphertext = maxFramePlaintext + 16 // + Poly1305 tag
)

// SecureConn wraps an io.ReadWriter in a length-framed ChaCha20-Poly1305
// stream. Each frame is [uint32 ciphertextLen][ciphertext]; the nonce is a
// per-direction counter so the same key can encrypt both directions without
// reuse. A SecureConn may wrap another SecureConn to layer encryption.
//
// SecureConn serialises reads against reads and writes against writes; it is
// safe for one reader and one writer to operate concurrently, matching how the
// relay loops use it.
type SecureConn struct {
	raw  io.ReadWriter
	aead cipher.AEAD

	writePrefix byte
	readPrefix  byte

	wmu      sync.Mutex
	writeCtr uint64

	rmu      sync.Mutex
	readCtr  uint64
	leftover []byte
}

// NewSecureConn keys a stream from an ECDH shared secret. The initiator (the
// circuit's client side) and the responder (the relay side) must pass opposite
// values of initiator so their send/receive nonce spaces line up.
func NewSecureConn(raw io.ReadWriter, secret []byte, initiator bool) (*SecureConn, error) {
	aead, err := newAEAD(secret, infoStream)
	if err != nil {
		return nil, err
	}
	sc := &SecureConn{raw: raw, aead: aead}
	if initiator {
		sc.writePrefix, sc.readPrefix = 0x00, 0x01
	} else {
		sc.writePrefix, sc.readPrefix = 0x01, 0x00
	}
	return sc, nil
}

// nonce builds a 12-byte nonce from a direction prefix and a counter.
func nonce(prefix byte, ctr uint64) []byte {
	n := make([]byte, nonceSize)
	n[0] = prefix
	binary.BigEndian.PutUint64(n[nonceSize-8:], ctr)
	return n
}

// Write encrypts p, splitting into frames no larger than maxFramePlaintext.
func (c *SecureConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxFramePlaintext {
			chunk = p[:maxFramePlaintext]
		}
		n := nonce(c.writePrefix, c.writeCtr)
		c.writeCtr++

		frame := make([]byte, 4, 4+len(chunk)+c.aead.Overhead())
		frame = c.aead.Seal(frame, n, chunk, nil)
		binary.BigEndian.PutUint32(frame[:4], uint32(len(frame)-4))
		if _, err := c.raw.Write(frame); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

// Read returns decrypted plaintext, buffering any frame remainder that does not
// fit in p for the next call.
func (c *SecureConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()

	if len(c.leftover) == 0 {
		var hdr [4]byte
		if _, err := io.ReadFull(c.raw, hdr[:]); err != nil {
			return 0, err
		}
		clen := binary.BigEndian.Uint32(hdr[:])
		if clen == 0 || clen > maxFrameCiphertext {
			return 0, fmt.Errorf("pheron/crypto: invalid frame length %d", clen)
		}
		ct := make([]byte, clen)
		if _, err := io.ReadFull(c.raw, ct); err != nil {
			return 0, err
		}
		n := nonce(c.readPrefix, c.readCtr)
		c.readCtr++
		pt, err := c.aead.Open(nil, n, ct, nil)
		if err != nil {
			return 0, fmt.Errorf("pheron/crypto: stream decrypt: %w", err)
		}
		c.leftover = pt
	}

	n := copy(p, c.leftover)
	c.leftover = c.leftover[n:]
	return n, nil
}
