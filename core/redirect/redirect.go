// Package redirect implements the transparent-proxy layer that escalates
// blocked destinations from the always-on DPI bypass to a SOCKS upstream
// (Tor / VLESS / Pheron).
//
// Architecture: a kernel REDIRECT/NAT rule diverts outbound TCP for
// destinations the detector flagged as blocked to a local listener owned by a
// Redirector. For each diverted connection the Redirector recovers the real
// destination (via SO_ORIGINAL_DST on Linux), dials it through the currently
// active Upstream, and splices the two connections. Because the upstream is
// resolved per-connection through a provider func, failover between proxy
// methods is just a matter of swapping which Upstream the provider returns.
package redirect

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// dialTimeout bounds how long a single upstream CONNECT may take before the
// diverted client connection is abandoned.
const dialTimeout = 30 * time.Second

// Upstream is the minimal dialer abstraction shared by every proxy method.
// VLESS and Pheron expose a local SOCKS5 endpoint (wrap it with SOCKSUpstream);
// Tor already hands out a proxy.Dialer, which satisfies this interface directly.
type Upstream interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// UpstreamProvider returns the Upstream to use for the next connection, or nil
// when no working proxy is currently available. It is consulted per-connection
// so that failover takes effect immediately without restarting the Redirector.
type UpstreamProvider func() Upstream

// origDstFunc recovers the pre-NAT destination of a redirected connection. It is
// a field so tests can inject a known destination without a real REDIRECT rule.
type origDstFunc func(net.Conn) (string, error)

// Redirector accepts kernel-redirected connections and forwards them through
// the active Upstream to their original destination.
type Redirector struct {
	listenAddr string
	provider   UpstreamProvider
	origDst    origDstFunc

	mu sync.Mutex
	ln net.Listener
}

// New creates a Redirector that will listen on listenAddr and resolve its
// upstream per-connection via provider.
func New(listenAddr string, provider UpstreamProvider) *Redirector {
	return &Redirector{
		listenAddr: listenAddr,
		provider:   provider,
		origDst:    originalDestination,
	}
}

// Start binds the listener and serves in a background goroutine. It returns once
// the socket is bound so callers can install the kernel REDIRECT rule knowing
// the listener is ready.
func (r *Redirector) Start() error {
	ln, err := net.Listen("tcp", r.listenAddr)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.ln = ln
	r.mu.Unlock()

	go r.serve(ln)
	log.Printf("redirect: transparent proxy listening on %s", ln.Addr())
	return nil
}

// Addr returns the bound listener address, or the empty string before Start.
func (r *Redirector) Addr() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ln == nil {
		return ""
	}
	return r.ln.Addr().String()
}

// Stop closes the listener; in-flight connections finish on their own.
func (r *Redirector) Stop() error {
	r.mu.Lock()
	ln := r.ln
	r.ln = nil
	r.mu.Unlock()
	if ln == nil {
		return nil
	}
	return ln.Close()
}

func (r *Redirector) serve(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			// A closed listener (Stop) surfaces as ErrClosed — exit quietly.
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("redirect: accept error: %v", err)
			return
		}
		go r.handle(conn)
	}
}

func (r *Redirector) handle(client net.Conn) {
	defer client.Close()

	dst, err := r.origDst(client)
	if err != nil {
		log.Printf("redirect: cannot recover original destination from %s: %v",
			client.RemoteAddr(), err)
		return
	}

	up := r.provider()
	if up == nil {
		log.Printf("redirect: no upstream available for %s — dropping", dst)
		return
	}

	if err := forward(client, dst, up); err != nil {
		log.Printf("redirect: forward to %s failed: %v", dst, err)
	}
}

// forward dials dst through up and splices the two connections, propagating
// half-closes so neither side hangs after the other finishes writing.
func forward(client net.Conn, dst string, up Upstream) error {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	remote, err := up.DialContext(ctx, "tcp", dst)
	if err != nil {
		return err
	}
	defer remote.Close()

	done := make(chan struct{}, 2)
	go func() { copyAndCloseWrite(remote, client); done <- struct{}{} }()
	go func() { copyAndCloseWrite(client, remote); done <- struct{}{} }()
	<-done
	<-done
	return nil
}

// copyAndCloseWrite copies src→dst and then half-closes dst's write side (when
// supported) so the peer sees EOF, mirroring how a normal TCP relay drains.
func copyAndCloseWrite(dst, src net.Conn) {
	_, _ = io.Copy(dst, src)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
