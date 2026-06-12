package vless

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// fakeVLESSServer accepts one connection, parses the VLESS request header,
// writes the response header, then echoes everything that follows. It models a
// minimal VLESS endpoint for testing the client without TLS.
func fakeVLESSServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakeVLESS(conn)
		}
	}()
	return ln
}

func serveFakeVLESS(conn net.Conn) {
	defer conn.Close()
	if err := readRequestHeader(conn); err != nil {
		return
	}
	// Response header: version 0, no addons.
	if _, err := conn.Write([]byte{0x00, 0x00}); err != nil {
		return
	}
	_, _ = io.Copy(conn, conn) // echo destination payload
}

// readRequestHeader consumes a VLESS request header from r, leaving it
// positioned at the start of the payload.
func readRequestHeader(r io.Reader) error {
	head := make([]byte, 19) // version+uuid+addonLen+cmd
	if _, err := io.ReadFull(r, head); err != nil {
		return err
	}
	addonLen := int(head[17])
	if addonLen > 0 {
		if _, err := io.ReadFull(r, make([]byte, addonLen)); err != nil {
			return err
		}
	}
	addr := make([]byte, 3) // port(2) + atyp(1)
	if _, err := io.ReadFull(r, addr); err != nil {
		return err
	}
	var n int
	switch addr[2] {
	case atypIPv4:
		n = 4
	case atypIPv6:
		n = 16
	case atypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return err
		}
		n = int(l[0])
	default:
		return fmt.Errorf("bad atyp %d", addr[2])
	}
	_, err := io.ReadFull(r, make([]byte, n))
	return err
}

func newTestHandler(t *testing.T, serverAddr, listenSOCKS string) *Handler {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(serverAddr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	h, err := New(Config{
		Address:     host,
		Port:        port,
		UUID:        testUUID,
		TLS:         false,
		ListenSOCKS: listenSOCKS,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

func TestDialTunnelEchoes(t *testing.T) {
	ln := fakeVLESSServer(t)
	defer ln.Close()

	h := newTestHandler(t, ln.Addr().String(), "127.0.0.1:0")
	conn, err := h.dialTunnel(context.Background(), "example.com", 443)
	if err != nil {
		t.Fatalf("dialTunnel: %v", err)
	}
	defer conn.Close()

	want := []byte("hello through vless")
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("echo = %q, want %q", got, want)
	}
}

func TestHealthThroughTunnel(t *testing.T) {
	ln := fakeVLESSServer(t)
	defer ln.Close()

	h := newTestHandler(t, ln.Addr().String(), "127.0.0.1:0")
	// The echo server returns the first byte of the HTTP request, satisfying
	// the 1-byte read in Health.
	if err := h.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}
}

func TestSOCKS5ProxyEndToEnd(t *testing.T) {
	ln := fakeVLESSServer(t)
	defer ln.Close()

	// Pick a free local port for the SOCKS proxy.
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve socks port: %v", err)
	}
	socksAddr := socksLn.Addr().String()
	socksLn.Close()

	h := newTestHandler(t, ln.Addr().String(), socksAddr)
	if err := h.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer h.Stop(context.Background())

	// Give the listener a moment to come up.
	var client net.Conn
	for i := 0; i < 50; i++ {
		client, err = net.Dial("tcp", socksAddr)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	defer client.Close()

	// SOCKS5 greeting: version 5, 1 method, no-auth.
	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("greeting reply = %v, want [5 0]", resp)
	}

	// CONNECT to example.com:443 (domain atyp).
	req := []byte{0x05, 0x01, 0x00, socksAtypDomain, byte(len("example.com"))}
	req = append(req, []byte("example.com")...)
	req = append(req, 0x01, 0xbb) // port 443
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

	// Now the pipe is open to the echo server.
	want := []byte("payload via socks")
	if _, err := client.Write(want); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("socks echo = %q, want %q", got, want)
	}
}
