package redirect

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// upstreamFunc adapts a plain dial function to the Upstream interface.
type upstreamFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func (f upstreamFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}

// directUpstream forwards straight to the real destination — it stands in for a
// SOCKS proxy whose far side simply reaches the origin.
var directUpstream = upstreamFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
})

// startEchoServer returns a listener that echoes each line back, uppercased,
// so the test can prove bytes traversed the full client→upstream→origin path.
func startEchoServer(t *testing.T) net.Listener {
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
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if len(line) > 0 {
						fmt.Fprintf(c, "ECHO:%s", line)
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln
}

func TestForwardSplicesThroughUpstream(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()

	// The "client" side is one end of a loopback TCP pair; forward() is given
	// the other end and told to reach the echo server via the upstream.
	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer clientLn.Close()

	clientConn, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer clientConn.Close()

	serverSide, err := clientLn.Accept()
	if err != nil {
		t.Fatalf("accept client: %v", err)
	}

	go func() {
		if err := forward(serverSide, echo.Addr().String(), directUpstream); err != nil {
			t.Errorf("forward: %v", err)
		}
	}()

	clientConn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(clientConn, "hello\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := bufio.NewReader(clientConn).ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != "ECHO:hello\n" {
		t.Fatalf("got %q, want %q", got, "ECHO:hello\n")
	}
}

func TestRedirectorEndToEnd(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()

	r := New("127.0.0.1:0", func() Upstream { return directUpstream })
	// Inject the original destination since there is no real REDIRECT rule in a
	// unit test: pretend every redirected connection was bound for the echo server.
	r.origDst = func(net.Conn) (string, error) { return echo.Addr().String(), nil }

	if err := r.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer r.Stop()

	conn, err := net.Dial("tcp", r.Addr())
	if err != nil {
		t.Fatalf("dial redirector: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(conn, "ping\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != "ECHO:ping\n" {
		t.Fatalf("got %q, want %q", got, "ECHO:ping\n")
	}
}

func TestRedirectorDropsWhenNoUpstream(t *testing.T) {
	r := New("127.0.0.1:0", func() Upstream { return nil }) // no working proxy
	r.origDst = func(net.Conn) (string, error) { return "192.0.2.1:443", nil }

	if err := r.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer r.Stop()

	conn, err := net.Dial("tcp", r.Addr())
	if err != nil {
		t.Fatalf("dial redirector: %v", err)
	}
	defer conn.Close()

	// With no upstream the redirector closes the connection without forwarding;
	// the read must return EOF rather than hang or panic.
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != io.EOF {
		t.Fatalf("expected EOF on dropped connection, got %v", err)
	}
}
