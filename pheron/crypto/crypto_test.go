package crypto

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	recipient, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	msg := []byte("forward to node2")
	blob, sealSecret, err := Seal(recipient.Public(), msg)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	pt, openSecret, err := Open(recipient, blob)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatalf("plaintext = %q, want %q", pt, msg)
	}
	if !bytes.Equal(sealSecret, openSecret) {
		t.Fatalf("shared secrets differ between Seal and Open")
	}
}

func TestOpenWrongKeyFails(t *testing.T) {
	recipient, _ := GenerateKeyPair()
	wrong, _ := GenerateKeyPair()

	blob, _, err := Seal(recipient.Public(), []byte("secret"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, _, err := Open(wrong, blob); err == nil {
		t.Fatalf("Open with wrong key should fail")
	}
}

func TestParsePublicKeyRoundTrip(t *testing.T) {
	kp, _ := GenerateKeyPair()
	pk := kp.Public()
	parsed, err := ParsePublicKey(pk.String())
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if parsed != pk {
		t.Fatalf("round-trip mismatch")
	}
	if _, err := ParsePublicKey("not-base64!!"); err == nil {
		t.Fatalf("expected error on bad key")
	}
}

// TestSecureConnRoundTrip exercises the streaming layer over an in-memory pipe,
// in both directions, including a payload large enough to span multiple frames.
func TestSecureConnRoundTrip(t *testing.T) {
	kp, _ := GenerateKeyPair()
	blob, secret, _ := Seal(kp.Public(), nil)
	_, secret2, _ := Open(kp, blob)
	if !bytes.Equal(secret, secret2) {
		t.Fatalf("secret mismatch in setup")
	}

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	initiator, err := NewSecureConn(c1, secret, true)
	if err != nil {
		t.Fatalf("NewSecureConn initiator: %v", err)
	}
	responder, err := NewSecureConn(c2, secret, false)
	if err != nil {
		t.Fatalf("NewSecureConn responder: %v", err)
	}

	big := bytes.Repeat([]byte("pheron-stream-"), 5000) // > one frame

	var wg sync.WaitGroup
	wg.Add(2)
	// initiator -> responder
	go func() {
		defer wg.Done()
		if _, err := initiator.Write(big); err != nil {
			t.Errorf("initiator write: %v", err)
		}
	}()
	got := make([]byte, len(big))
	go func() {
		defer wg.Done()
		if _, err := io.ReadFull(responder, got); err != nil {
			t.Errorf("responder read: %v", err)
		}
	}()
	wg.Wait()
	if !bytes.Equal(got, big) {
		t.Fatalf("initiator->responder payload mismatch")
	}

	// responder -> initiator (reverse direction, same key)
	reply := []byte("ack from responder")
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err := responder.Write(reply); err != nil {
			t.Errorf("responder write: %v", err)
		}
	}()
	rbuf := make([]byte, len(reply))
	go func() {
		defer wg.Done()
		if _, err := io.ReadFull(initiator, rbuf); err != nil {
			t.Errorf("initiator read: %v", err)
		}
	}()
	wg.Wait()
	if !bytes.Equal(rbuf, reply) {
		t.Fatalf("responder->initiator payload mismatch")
	}
}
