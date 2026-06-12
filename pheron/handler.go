// Package pheron wires the Pheron components — relay node, node pool, and
// circuit client — into a fallback.Handler. Every Flint instance is both a
// node (it runs a relay) and a client (it builds circuits through the pool).
//
// Pheron is a v0.1 beta: peer discovery is limited to a static bootstrap list,
// and the handler enforces the protocol's hard 2-hop requirement — if the pool
// holds fewer than two other nodes, Start fails so the fallback manager skips
// Pheron and falls through to Tor.
package pheron

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/YCistak/flint/pheron/client"
	"github.com/YCistak/flint/pheron/crypto"
	"github.com/YCistak/flint/pheron/node"
	"github.com/YCistak/flint/pheron/pool"
)

const (
	dialTimeout   = 15 * time.Second
	healthTimeout = 25 * time.Second
)

// Default endpoint dialed through a circuit during Health checks.
const defaultHealthTarget = "1.1.1.1:80"

// Config configures the Pheron handler.
type Config struct {
	// ListenSOCKS is the local SOCKS5 address applications use to route through
	// Pheron. Defaults to 127.0.0.1:1081.
	ListenSOCKS string
	// NodeListen is the address the local relay binds (e.g. ":9999"). Defaults
	// to ":9999".
	NodeListen string
	// Advertise is the "host:port" other nodes use to reach this relay. When
	// empty, the bound NodeListen address is used.
	Advertise string
	// Bootstrap is the static seed set of peer nodes.
	Bootstrap []pool.Node
	// HealthTarget overrides the endpoint dialed through a circuit during
	// Health checks. Defaults to defaultHealthTarget.
	HealthTarget string
}

// Handler implements fallback.Handler for the Pheron P2P relay.
type Handler struct {
	cfg  Config
	kp   *crypto.KeyPair
	node *node.Server
	pool *pool.Pool

	mu       sync.Mutex
	listener net.Listener
	running  bool
}

// New constructs a Pheron handler, generating a fresh node identity.
func New(cfg Config) (*Handler, error) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	if cfg.ListenSOCKS == "" {
		cfg.ListenSOCKS = "127.0.0.1:1081"
	}
	if cfg.NodeListen == "" {
		cfg.NodeListen = ":9999"
	}
	if cfg.HealthTarget == "" {
		cfg.HealthTarget = defaultHealthTarget
	}
	return &Handler{
		cfg:  cfg,
		kp:   kp,
		node: node.New(kp),
	}, nil
}

// Name satisfies fallback.Handler.
func (h *Handler) Name() string { return "pheron" }

// Label marks Pheron as beta in status output (fallback.Labeled).
func (h *Handler) Label() string { return "beta" }

// Start brings up the relay, joins the pool, and — only if at least two other
// nodes are available — opens the local SOCKS5 proxy. With fewer than two nodes
// it returns an error so the manager falls through to Tor.
func (h *Handler) Start(_ context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.running {
		return nil
	}

	// Run the local relay so this instance contributes to the pool.
	if err := h.node.Start(h.cfg.NodeListen); err != nil {
		return err
	}

	advertise := h.cfg.Advertise
	if advertise == "" {
		advertise = h.node.Addr()
	}
	self := pool.Node{Address: advertise, PublicKey: h.kp.Public()}

	h.pool = pool.New(self, h.cfg.Bootstrap)
	if err := h.pool.Join(); err != nil {
		_ = h.node.Stop()
		return err
	}

	// 2-hop enforcement: Pheron is unusable without at least two other nodes.
	if h.pool.Count() < 2 {
		h.pool.Leave()
		_ = h.node.Stop()
		return fmt.Errorf("pheron: need at least 2 nodes for a 2-hop circuit, have %d", h.pool.Count())
	}

	ln, err := net.Listen("tcp", h.cfg.ListenSOCKS)
	if err != nil {
		h.pool.Leave()
		_ = h.node.Stop()
		return fmt.Errorf("pheron: listen on %s: %w", h.cfg.ListenSOCKS, err)
	}
	h.listener = ln
	h.running = true

	go h.acceptLoop(ln)
	log.Printf("pheron[beta]: SOCKS5 proxy on %s, pool has %d node(s)", h.cfg.ListenSOCKS, h.pool.Count())
	return nil
}

// Stop closes the SOCKS proxy, leaves the pool, and stops the relay.
func (h *Handler) Stop(_ context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.running {
		return nil
	}
	h.running = false

	var firstErr error
	if h.listener != nil {
		if err := h.listener.Close(); err != nil {
			firstErr = err
		}
		h.listener = nil
	}
	if h.pool != nil {
		h.pool.Leave()
	}
	if err := h.node.Stop(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// Health builds a 2-hop circuit to the health target and confirms a byte flows
// through it.
func (h *Handler) Health(ctx context.Context) error {
	h.mu.Lock()
	p := h.pool
	running := h.running
	h.mu.Unlock()
	if !running || p == nil {
		return fmt.Errorf("pheron: handler not running")
	}

	ctx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()

	circuit, err := h.dialCircuit(ctx, p, h.cfg.HealthTarget)
	if err != nil {
		return err
	}
	defer circuit.Close()

	if dl, ok := ctx.Deadline(); ok {
		_ = circuit.SetDeadline(dl)
	}

	req := "GET / HTTP/1.0\r\nHost: " + hostOnly(h.cfg.HealthTarget) + "\r\n\r\n"
	if _, err := io.WriteString(circuit, req); err != nil {
		return fmt.Errorf("pheron: health write: %w", err)
	}
	var buf [1]byte
	if _, err := io.ReadFull(circuit, buf[:]); err != nil {
		return fmt.Errorf("pheron: health read (circuit carried no data): %w", err)
	}
	return nil
}

// dialCircuit selects two nodes and builds a circuit to destination.
func (h *Handler) dialCircuit(ctx context.Context, p *pool.Pool, destination string) (*client.Circuit, error) {
	hop1, hop2, err := p.SelectTwo()
	if err != nil {
		return nil, err // ErrInsufficientNodes when pool < 2
	}
	return client.Dial(ctx, hop1, hop2, destination)
}

// acceptLoop serves the local SOCKS5 proxy until the listener closes.
func (h *Handler) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go h.handleSOCKS(conn)
	}
}

// handleSOCKS performs a minimal SOCKS5 CONNECT handshake, builds a circuit to
// the requested destination, and pipes the two together.
func (h *Handler) handleSOCKS(conn net.Conn) {
	defer conn.Close()

	host, port, err := socks5Connect(conn)
	if err != nil {
		log.Printf("pheron: SOCKS5 handshake failed: %v", err)
		return
	}
	destination := net.JoinHostPort(host, strconv.Itoa(int(port)))

	h.mu.Lock()
	p := h.pool
	h.mu.Unlock()
	if p == nil {
		_ = socks5Reply(conn, socksGeneralFailure)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	circuit, err := h.dialCircuit(ctx, p, destination)
	cancel()
	if err != nil {
		log.Printf("pheron: circuit to %s failed: %v", destination, err)
		_ = socks5Reply(conn, socksGeneralFailure)
		return
	}
	defer circuit.Close()

	if err := socks5Reply(conn, socksSucceeded); err != nil {
		return
	}

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(circuit, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, circuit); done <- struct{}{} }()
	<-done
}

func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
