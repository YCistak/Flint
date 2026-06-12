// Package node implements the Pheron relay server. A node accepts a single
// onion layer per connection, decrypts it with its static key, and either
// forwards the inner layer to the next hop (relay role) or connects to the
// final destination (exit role). It never learns more than one link of the
// path: a relay sees the next hop but not the destination or the original
// client; an exit sees the destination but not the client.
package node

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/YCistak/flint/pheron/crypto"
	"github.com/YCistak/flint/pheron/wire"
)

// dialTimeout bounds how long a node waits when opening the onward connection
// (to the next hop or the destination).
const dialTimeout = 15 * time.Second

// Server is a Pheron relay listening for circuit connections.
type Server struct {
	kp *crypto.KeyPair

	mu       sync.Mutex
	ln       net.Listener
	wg       sync.WaitGroup
	run      bool
	onGossip func([]byte) []byte
}

// New returns a relay server identified by kp.
func New(kp *crypto.KeyPair) *Server {
	return &Server{kp: kp}
}

// SetGossipHandler installs the callback invoked for inbound gossip requests.
// The handler receives the peer's advertised list and returns the local list to
// send back. It must be set before Start. If unset, gossip connections are
// dropped.
func (s *Server) SetGossipHandler(fn func([]byte) []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onGossip = fn
}

// PublicKey returns the node's static public key, used to build its pool
// descriptor.
func (s *Server) PublicKey() crypto.PublicKey { return s.kp.Public() }

// Start binds the listener on listenAddr (e.g. ":9999" or "127.0.0.1:0") and
// begins accepting circuits in the background. It is a no-op if already running.
func (s *Server) Start(listenAddr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.run {
		return nil
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("pheron/node: listen on %s: %w", listenAddr, err)
	}
	s.ln = ln
	s.run = true

	s.wg.Add(1)
	go s.acceptLoop(ln)
	log.Printf("pheron/node: relay listening on %s", ln.Addr())
	return nil
}

// Addr returns the bound listener address, or "" if not started. Useful when
// Start was called with port 0.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Stop closes the listener and waits for in-flight handlers to finish.
func (s *Server) Stop() error {
	s.mu.Lock()
	if !s.run {
		s.mu.Unlock()
		return nil
	}
	s.run = false
	ln := s.ln
	s.ln = nil
	s.mu.Unlock()

	err := ln.Close()
	s.wg.Wait()
	if err != nil {
		return fmt.Errorf("pheron/node: close listener: %w", err)
	}
	return nil
}

func (s *Server) acceptLoop(ln net.Listener) {
	defer s.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(conn)
		}()
	}
}

// handle reads the one-byte message type and dispatches to the circuit or
// gossip handler.
func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	var typ [1]byte
	if _, err := io.ReadFull(conn, typ[:]); err != nil {
		return
	}
	switch typ[0] {
	case wire.MsgCircuit:
		s.handleCircuit(conn)
	case wire.MsgGossip:
		s.handleGossip(conn)
	default:
		log.Printf("pheron/node: unknown message type %d", typ[0])
	}
}

// handleGossip merges the peer's advertised list and replies with our own.
func (s *Server) handleGossip(conn net.Conn) {
	s.mu.Lock()
	fn := s.onGossip
	s.mu.Unlock()
	if fn == nil {
		return
	}
	req, err := wire.ReadFrame(conn)
	if err != nil {
		return
	}
	if err := wire.WriteFrame(conn, fn(req)); err != nil {
		log.Printf("pheron/node: gossip reply: %v", err)
	}
}

// handleCircuit processes one circuit connection: read the layer, decrypt it,
// then act on the embedded command.
func (s *Server) handleCircuit(conn net.Conn) {
	blob, err := wire.ReadFrame(conn)
	if err != nil {
		return // client disconnected before sending the layer
	}
	payload, secret, err := crypto.Open(s.kp, blob)
	if err != nil {
		log.Printf("pheron/node: rejecting layer: %v", err)
		return
	}
	cmd, addr, inner, err := wire.DecodeSetup(payload)
	if err != nil {
		log.Printf("pheron/node: bad setup payload: %v", err)
		return
	}

	switch cmd {
	case wire.CmdForward:
		s.relayForward(conn, secret, addr, inner)
	case wire.CmdConnect:
		s.relayConnect(conn, secret, addr)
	}
}

// relayForward strips this layer (decrypting client traffic with secret) and
// forwards the inner blob plus the remaining stream to the next hop.
func (s *Server) relayForward(client net.Conn, secret []byte, nextAddr string, inner []byte) {
	next, err := net.DialTimeout("tcp", nextAddr, dialTimeout)
	if err != nil {
		log.Printf("pheron/node: dial next hop %s: %v", nextAddr, err)
		return
	}
	defer next.Close()

	// The next hop expects a message-type byte before the layer, just like a
	// client opening a circuit.
	if _, err := next.Write([]byte{wire.MsgCircuit}); err != nil {
		log.Printf("pheron/node: forward message type: %v", err)
		return
	}
	if err := wire.WriteFrame(next, inner); err != nil {
		log.Printf("pheron/node: forward inner layer: %v", err)
		return
	}

	sc, err := crypto.NewSecureConn(client, secret, false)
	if err != nil {
		log.Printf("pheron/node: secure conn: %v", err)
		return
	}
	// sc carries this hop's plaintext, which is the next hop's ciphertext —
	// forwarded verbatim, so the relay never sees the destination's data.
	pipe(sc, next)
}

// relayConnect is the exit role: open the destination and relay decrypted
// client traffic to and from it.
func (s *Server) relayConnect(client net.Conn, secret []byte, dstAddr string) {
	dst, err := net.DialTimeout("tcp", dstAddr, dialTimeout)
	if err != nil {
		log.Printf("pheron/node: dial destination %s: %v", dstAddr, err)
		return
	}
	defer dst.Close()

	sc, err := crypto.NewSecureConn(client, secret, false)
	if err != nil {
		log.Printf("pheron/node: secure conn: %v", err)
		return
	}
	pipe(sc, dst)
}

// pipe copies bytes both ways until either side closes, then returns. Closing
// the underlying connections (by the caller's defers) unblocks the surviving
// copy goroutine.
func pipe(a, b io.ReadWriter) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	<-done
}
