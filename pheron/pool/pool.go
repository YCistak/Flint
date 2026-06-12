// Package pool manages Pheron's node pool: the set of relay nodes a client can
// route through. In v0.1 the pool is seeded from a static list of bootstrap
// nodes; later versions add distributed discovery.
//
// The pool tracks the local node ("self") separately and never offers it for
// routing — a client routing through itself would defeat the privacy model.
// SelectTwo enforces the protocol's 2-hop rule by returning two distinct nodes
// and an error when fewer than two are available.
package pool

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"

	"github.com/YCistak/flint/pheron/crypto"
)

// ErrInsufficientNodes is returned by SelectTwo when the pool holds fewer than
// two routable nodes. Callers treat this as the signal to fall through to Tor.
var ErrInsufficientNodes = errors.New("pheron/pool: fewer than 2 nodes available")

// Node describes a reachable Pheron relay.
type Node struct {
	// Address is the node's "host:port" Pheron listener.
	Address string
	// PublicKey is the node's static X25519 key.
	PublicKey crypto.PublicKey
}

// ID is a stable identifier derived from the node's public key.
func (n Node) ID() string { return n.PublicKey.String() }

// Pool is a thread-safe set of known nodes plus the local node identity.
type Pool struct {
	mu     sync.RWMutex
	self   Node
	nodes  map[string]Node // keyed by ID, never contains self
	joined bool

	// bootstrap is the static seed set loaded on Join.
	bootstrap []Node
}

// New creates a pool for the local node self, seeded (on Join) with the given
// bootstrap nodes. self and any bootstrap entry matching self are excluded from
// routing.
func New(self Node, bootstrap []Node) *Pool {
	return &Pool{
		self:      self,
		nodes:     make(map[string]Node),
		bootstrap: bootstrap,
	}
}

// Join brings the local node into the pool and loads the bootstrap nodes. In
// v0.1 this is a local operation; distributed announcement arrives in v0.5.
func (p *Pool) Join() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.joined = true
	for _, n := range p.bootstrap {
		if n.ID() == p.self.ID() {
			continue // don't route through ourselves
		}
		if n.Address == "" {
			return fmt.Errorf("pheron/pool: bootstrap node %s has no address", n.ID())
		}
		p.nodes[n.ID()] = n
	}
	return nil
}

// Leave removes the local node from the pool and clears known peers.
func (p *Pool) Leave() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.joined = false
	p.nodes = make(map[string]Node)
}

// Add records a node as available (ignored if it is the local node).
func (p *Pool) Add(n Node) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n.ID() == p.self.ID() {
		return
	}
	p.nodes[n.ID()] = n
}

// Remove drops a node by ID.
func (p *Pool) Remove(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.nodes, id)
}

// List returns the routable nodes in deterministic (ID-sorted) order.
func (p *Pool) List() []Node {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.listLocked()
}

func (p *Pool) listLocked() []Node {
	out := make([]Node, 0, len(p.nodes))
	for _, n := range p.nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// Count returns the number of routable nodes.
func (p *Pool) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.nodes)
}

// SelectTwo picks two distinct nodes at random for a 2-hop circuit. The same
// node is never returned for both hops. It returns ErrInsufficientNodes when
// fewer than two nodes are available.
func (p *Pool) SelectTwo() (Node, Node, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	list := p.listLocked()
	if len(list) < 2 {
		return Node{}, Node{}, ErrInsufficientNodes
	}

	i, err := randIndex(len(list))
	if err != nil {
		return Node{}, Node{}, err
	}
	j, err := randIndex(len(list) - 1)
	if err != nil {
		return Node{}, Node{}, err
	}
	if j >= i {
		j++ // map into the range excluding i, keeping the two hops distinct
	}
	return list[i], list[j], nil
}

// randIndex returns a uniformly random integer in [0, n) using crypto/rand.
func randIndex(n int) (int, error) {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, fmt.Errorf("pheron/pool: random selection: %w", err)
	}
	return int(v.Int64()), nil
}
