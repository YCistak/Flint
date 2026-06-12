package pheron

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/YCistak/flint/pheron/client"
	"github.com/YCistak/flint/pheron/crypto"
	"github.com/YCistak/flint/pheron/node"
	"github.com/YCistak/flint/pheron/pool"
)

// echoServer accepts connections and echoes everything back. It models the
// circuit destination.
func echoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	return ln
}

// startNode spins up a relay node on a random port and returns its server and
// pool descriptor.
func startNode(t *testing.T) (*node.Server, pool.Node) {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	srv := node.New(kp)
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("node start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })
	return srv, pool.Node{Address: srv.Addr(), PublicKey: kp.Public()}
}

func TestTwoHopCircuitEcho(t *testing.T) {
	dest := echoServer(t)
	defer dest.Close()

	_, n1 := startNode(t)
	_, n2 := startNode(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	circuit, err := client.Dial(ctx, n1, n2, dest.Addr().String())
	if err != nil {
		t.Fatalf("Dial circuit: %v", err)
	}
	defer circuit.Close()

	msg := bytes.Repeat([]byte("through two hops! "), 2000) // spans many frames
	go func() { _, _ = circuit.Write(msg) }()

	got := make([]byte, len(msg))
	if _, err := io.ReadFull(circuit, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch through circuit")
	}
}

func TestPoolEnforcementSkipsWithFewerThanTwoNodes(t *testing.T) {
	_, n1 := startNode(t)

	// Only one bootstrap node — a 2-hop circuit is impossible, so Start must
	// fail (letting the fallback chain proceed to Tor).
	h, err := New(Config{
		ListenSOCKS: "127.0.0.1:0",
		NodeListen:  "127.0.0.1:0",
		Bootstrap:   []pool.Node{n1},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := h.Start(context.Background()); err == nil {
		_ = h.Stop(context.Background())
		t.Fatalf("Start should fail with fewer than 2 nodes")
	}
}

func TestHandlerHealthAndSOCKS(t *testing.T) {
	dest := echoServer(t)
	defer dest.Close()

	_, n1 := startNode(t)
	_, n2 := startNode(t)

	h, err := New(Config{
		ListenSOCKS:  "127.0.0.1:0",
		NodeListen:   "127.0.0.1:0",
		Bootstrap:    []pool.Node{n1, n2},
		HealthTarget: dest.Addr().String(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := h.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer h.Stop(context.Background())

	if h.Label() != "beta" {
		t.Fatalf("Label = %q, want beta", h.Label())
	}

	// Health builds a circuit to the echo destination; the echoed HTTP request
	// bytes satisfy the 1-byte read.
	if err := h.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}

	// Exercise the SOCKS5 front-end end to end.
	socksAddr := h.listener.Addr().String()
	client, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	defer client.Close()

	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}

	// CONNECT to the echo destination by IP.
	host, portStr, _ := net.SplitHostPort(dest.Addr().String())
	var port int
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	req := []byte{0x05, 0x01, 0x00, socksAtypIPv4}
	req = append(req, net.ParseIP(host).To4()...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := client.Write(req); err != nil {
		t.Fatalf("connect req: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("connect reply: %v", err)
	}
	if reply[1] != socksSucceeded {
		t.Fatalf("connect status = %d, want %d", reply[1], socksSucceeded)
	}

	payload := []byte("socks over pheron")
	go func() { _, _ = client.Write(payload) }()
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(client, echoed); err != nil {
		t.Fatalf("read echo via socks: %v", err)
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatalf("socks echo mismatch")
	}
}
