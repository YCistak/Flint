package crypto

import (
	"bytes"
	"testing"
)

// TestForwardSecrecyFreshEphemeralPerSession verifies the property the package
// doc claims: every Seal to the same recipient uses a fresh ephemeral key, so
// the derived session secrets are independent across sessions. This is what
// gives Pheron per-session key independence and sender-side forward secrecy.
func TestForwardSecrecyFreshEphemeralPerSession(t *testing.T) {
	recipient, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	msg := []byte("same plaintext, two sessions")
	blob1, secret1, err := Seal(recipient.Public(), msg)
	if err != nil {
		t.Fatalf("Seal #1: %v", err)
	}
	blob2, secret2, err := Seal(recipient.Public(), msg)
	if err != nil {
		t.Fatalf("Seal #2: %v", err)
	}

	// Fresh ephemeral key each time → different ephemeral public keys (first 32
	// bytes of the blob).
	if bytes.Equal(blob1[:PublicKeySize], blob2[:PublicKeySize]) {
		t.Fatalf("ephemeral public key reused across sessions — not forward secret")
	}
	// Independent session secrets.
	if bytes.Equal(secret1, secret2) {
		t.Fatalf("session secrets identical across sessions — keys not independent")
	}
	// Identical plaintext must not produce identical ciphertext.
	if bytes.Equal(blob1, blob2) {
		t.Fatalf("identical ciphertext for identical plaintext — nonce/ephemeral reuse")
	}

	// Each session still opens correctly to its own secret.
	for i, b := range [][]byte{blob1, blob2} {
		pt, _, err := Open(recipient, b)
		if err != nil {
			t.Fatalf("Open session %d: %v", i+1, err)
		}
		if !bytes.Equal(pt, msg) {
			t.Fatalf("session %d plaintext mismatch", i+1)
		}
	}
}
