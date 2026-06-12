package pool

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/YCistak/flint/pheron/crypto"
	"github.com/YCistak/flint/pheron/wire"
)

// Gossip implements distributed peer discovery. On a fixed interval each node
// contacts a random subset of its known peers, sends them its current view of
// the pool, and merges the view they send back. After the first successful
// round a node's pool no longer depends on the static bootstrap list — peers
// learned through gossip keep the pool populated as bootstrap nodes churn.
//
// The exchange rides the node's existing listener, distinguished from circuit
// traffic by a one-byte message type (wire.MsgGossip). The payload is a plain
// list of peer descriptors; it carries no secrets, so it is sent in the clear.
// Each receiver independently derives region and reputation locally, so a peer
// cannot forge those attributes by lying in a gossip message.
type Gossip struct {
	pool *Pool

	interval time.Duration
	fanout   int
	timeout  time.Duration

	// dial is overridable in tests; defaults to a plain TCP dialer.
	dial func(ctx context.Context, addr string) (net.Conn, error)

	mu        sync.Mutex
	rounds    int
	lastRound time.Time
}

const (
	defaultGossipInterval = 30 * time.Second
	defaultGossipFanout   = 3
	defaultGossipTimeout  = 10 * time.Second
	// maxGossipPeers bounds how many peers a single gossip message may carry,
	// guarding against a malicious peer announcing an enormous list.
	maxGossipPeers = 1024
)

// NewGossip creates a gossip engine for the given pool using default timing.
func NewGossip(p *Pool) *Gossip {
	return &Gossip{
		pool:     p,
		interval: defaultGossipInterval,
		fanout:   defaultGossipFanout,
		timeout:  defaultGossipTimeout,
		dial: func(ctx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		},
	}
}

// Run gossips on a fixed interval until ctx is cancelled.
func (g *Gossip) Run(ctx context.Context) {
	t := time.NewTicker(g.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.round(ctx)
		}
	}
}

// round performs a single gossip cycle: push our view to a random subset of
// peers and merge whatever each returns.
func (g *Gossip) round(ctx context.Context) {
	peers := g.pool.List()
	if len(peers) == 0 {
		return
	}
	targets, err := pickRandom(peers, g.fanout)
	if err != nil {
		log.Printf("pheron/gossip: target selection: %v", err)
		return
	}
	payload := encodePeers(g.pool.snapshotWithSelf())
	for _, target := range targets {
		g.exchange(ctx, target, payload)
	}

	g.mu.Lock()
	g.rounds++
	g.lastRound = time.Now()
	g.mu.Unlock()
}

// exchange sends our view to one peer and merges its reply.
func (g *Gossip) exchange(ctx context.Context, target Node, payload []byte) {
	conn, err := g.dial(ctx, target.Address)
	if err != nil {
		g.pool.Reputation().RecordFailure(target.ID())
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(g.timeout))

	if _, err := conn.Write([]byte{wire.MsgGossip}); err != nil {
		return
	}
	if err := wire.WriteFrame(conn, payload); err != nil {
		return
	}
	resp, err := wire.ReadFrame(conn)
	if err != nil {
		return
	}
	learned, err := decodePeers(resp)
	if err != nil {
		log.Printf("pheron/gossip: decode reply from %s: %v", target.Address, err)
		return
	}
	g.pool.Merge(learned)
}

// HandleInbound processes a gossip request received by the local node: it merges
// the sender's advertised peers and returns our own view to send back. It is
// installed as the node server's gossip handler.
func (g *Gossip) HandleInbound(req []byte) []byte {
	if learned, err := decodePeers(req); err == nil {
		g.pool.Merge(learned)
	}
	return encodePeers(g.pool.snapshotWithSelf())
}

// Stats reports gossip activity for status output.
func (g *Gossip) Stats() map[string]interface{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	m := map[string]interface{}{
		"rounds": g.rounds,
		"fanout": g.fanout,
	}
	if !g.lastRound.IsZero() {
		m["last_round_age_sec"] = int(time.Since(g.lastRound).Seconds())
	}
	return m
}

// pickRandom returns up to k distinct nodes chosen uniformly at random.
func pickRandom(nodes []Node, k int) ([]Node, error) {
	if k >= len(nodes) {
		out := make([]Node, len(nodes))
		copy(out, nodes)
		return out, nil
	}
	// Partial Fisher-Yates over a copy.
	pool := make([]Node, len(nodes))
	copy(pool, nodes)
	for i := 0; i < k; i++ {
		j, err := randIndexRange(i, len(pool))
		if err != nil {
			return nil, err
		}
		pool[i], pool[j] = pool[j], pool[i]
	}
	return pool[:k], nil
}

// randIndexRange returns a random index in [lo, hi).
func randIndexRange(lo, hi int) (int, error) {
	r, err := randFloat()
	if err != nil {
		return 0, err
	}
	return lo + int(r*float64(hi-lo)), nil
}

// ── Peer-list wire encoding ──────────────────────────────────────────────────
//
// count(uint16) followed by, per node: addrLen(uint16) | addr | publicKey(32).

func encodePeers(nodes []Node) []byte {
	if len(nodes) > maxGossipPeers {
		nodes = nodes[:maxGossipPeers]
	}
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, uint16(len(nodes)))
	for _, n := range nodes {
		_ = binary.Write(buf, binary.BigEndian, uint16(len(n.Address)))
		buf.WriteString(n.Address)
		buf.Write(n.PublicKey[:])
	}
	return buf.Bytes()
}

func decodePeers(b []byte) ([]Node, error) {
	r := bytes.NewReader(b)
	var count uint16
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return nil, fmt.Errorf("pheron/gossip: read count: %w", err)
	}
	if int(count) > maxGossipPeers {
		return nil, fmt.Errorf("pheron/gossip: peer count %d exceeds limit", count)
	}
	nodes := make([]Node, 0, count)
	for i := 0; i < int(count); i++ {
		var addrLen uint16
		if err := binary.Read(r, binary.BigEndian, &addrLen); err != nil {
			return nil, fmt.Errorf("pheron/gossip: read address length: %w", err)
		}
		addr := make([]byte, addrLen)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, fmt.Errorf("pheron/gossip: read address: %w", err)
		}
		var pk crypto.PublicKey
		if _, err := io.ReadFull(r, pk[:]); err != nil {
			return nil, fmt.Errorf("pheron/gossip: read public key: %w", err)
		}
		nodes = append(nodes, Node{Address: string(addr), PublicKey: pk})
	}
	return nodes, nil
}
