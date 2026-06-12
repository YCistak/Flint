// Package pool manages Pheron's node pool: the set of relay nodes a client can
// route through.
//
// In v0.1 the pool was seeded from a static bootstrap list. v0.2 adds
// distributed peer discovery via gossip (discovery.go) so the pool grows beyond
// the bootstrap set, reputation scoring (reputation.go) so reliable, fast nodes
// are preferred, and ASN/geo-aware selection so the two hops of a circuit tend
// to sit in different regions.
//
// The pool tracks the local node ("self") separately and never offers it for
// routing — a client routing through itself would defeat the privacy model.
// SelectTwo enforces the protocol's 2-hop rule by returning two distinct nodes
// and an error when fewer than two are available.
package pool

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"

	"github.com/YCistak/flint/pheron/crypto"
)

// ErrInsufficientNodes is returned by SelectTwo when the pool holds fewer than
// two routable nodes. Callers treat this as the signal to fall through to Tor.
var ErrInsufficientNodes = errors.New("pheron/pool: fewer than 2 nodes available")

// regionDiversityBonus multiplies a candidate's selection weight for the second
// hop when it sits in a different region than the first hop, biasing circuits
// toward crossing regions/ASNs without ever making it a hard requirement (a
// hard requirement would break in a pool concentrated in one region).
const regionDiversityBonus = 4.0

// Node describes a reachable Pheron relay.
type Node struct {
	// Address is the node's "host:port" Pheron listener.
	Address string
	// PublicKey is the node's static X25519 key.
	PublicKey crypto.PublicKey
}

// ID is a stable identifier derived from the node's public key.
func (n Node) ID() string { return n.PublicKey.String() }

// Geolocator maps a host (IP or hostname) to a coarse region/ASN label used for
// hop diversity. Implementations should be cheap and must not block.
type Geolocator interface {
	Region(host string) string
}

// GeolocatorFunc adapts a function to the Geolocator interface.
type GeolocatorFunc func(host string) string

// Region implements Geolocator.
func (f GeolocatorFunc) Region(host string) string { return f(host) }

// Pool is a thread-safe set of known nodes plus the local node identity.
type Pool struct {
	mu     sync.RWMutex
	self   Node
	nodes  map[string]Node // keyed by ID, never contains self
	joined bool

	// bootstrap is the static seed set loaded on Join.
	bootstrap []Node

	geo Geolocator
	rep *Reputation
}

// New creates a pool for the local node self, seeded (on Join) with the given
// bootstrap nodes. self and any bootstrap entry matching self are excluded from
// routing. A default heuristic geolocator and an empty reputation tracker are
// installed; override the geolocator with SetGeolocator.
func New(self Node, bootstrap []Node) *Pool {
	return &Pool{
		self:      self,
		nodes:     make(map[string]Node),
		bootstrap: bootstrap,
		geo:       DefaultGeolocator(),
		rep:       NewReputation(),
	}
}

// SetGeolocator overrides the region lookup used for hop diversity.
func (p *Pool) SetGeolocator(g Geolocator) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if g != nil {
		p.geo = g
	}
}

// Reputation returns the pool's reputation tracker so callers can record
// circuit outcomes.
func (p *Pool) Reputation() *Reputation { return p.rep }

// Join brings the local node into the pool and loads the bootstrap nodes. Once
// gossip is running the pool no longer depends on the bootstrap set.
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

// Add records a node as available (ignored if it is the local node or has no
// address).
func (p *Pool) Add(n Node) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n.ID() == p.self.ID() || n.Address == "" {
		return
	}
	p.nodes[n.ID()] = n
}

// Merge adds a batch of nodes learned from a peer (e.g. via gossip).
func (p *Pool) Merge(nodes []Node) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, n := range nodes {
		if n.ID() == p.self.ID() || n.Address == "" {
			continue
		}
		p.nodes[n.ID()] = n
	}
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

// snapshotWithSelf returns the local node followed by all known peers — the
// view advertised during gossip so peers learn about us.
func (p *Pool) snapshotWithSelf() []Node {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Node, 0, len(p.nodes)+1)
	if p.self.Address != "" {
		out = append(out, p.self)
	}
	out = append(out, p.listLocked()...)
	return out
}

// Count returns the number of routable nodes.
func (p *Pool) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.nodes)
}

// SelectTwo picks two distinct nodes for a 2-hop circuit, weighting each pick by
// reputation and biasing the second hop toward a different region than the
// first. It returns ErrInsufficientNodes when fewer than two nodes are
// available.
func (p *Pool) SelectTwo() (Node, Node, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	list := p.listLocked()
	if len(list) < 2 {
		return Node{}, Node{}, ErrInsufficientNodes
	}

	hop1, i, err := p.weightedPick(list, nil)
	if err != nil {
		return Node{}, Node{}, err
	}
	region1 := p.regionLocked(hop1)

	rest := make([]Node, 0, len(list)-1)
	rest = append(rest, list[:i]...)
	rest = append(rest, list[i+1:]...)

	hop2, _, err := p.weightedPick(rest, func(n Node) float64 {
		if p.regionLocked(n) != region1 {
			return regionDiversityBonus
		}
		return 1.0
	})
	if err != nil {
		return Node{}, Node{}, err
	}
	return hop1, hop2, nil
}

// weightedPick selects a node from list with probability proportional to its
// reputation score times an optional per-node bonus, returning the node and its
// index in list.
func (p *Pool) weightedPick(list []Node, bonus func(Node) float64) (Node, int, error) {
	weights := make([]float64, len(list))
	var total float64
	for i, n := range list {
		w := p.rep.Score(n.ID())
		if bonus != nil {
			w *= bonus(n)
		}
		if w <= 0 {
			w = 1e-6
		}
		weights[i] = w
		total += w
	}

	r, err := randFloat()
	if err != nil {
		return Node{}, 0, err
	}
	target := r * total
	for i, w := range weights {
		target -= w
		if target < 0 {
			return list[i], i, nil
		}
	}
	last := len(list) - 1
	return list[last], last, nil // floating-point fallthrough
}

// regionLocked returns the region label for a node based on its address host.
func (p *Pool) regionLocked(n Node) string {
	host := n.Address
	if h, _, err := net.SplitHostPort(n.Address); err == nil {
		host = h
	}
	return p.geo.Region(host)
}

// Health returns pool metrics for status reporting: node count, the regional
// distribution of nodes, and aggregate reputation statistics.
func (p *Pool) Health() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	list := p.listLocked()
	regions := make(map[string]int)
	for _, n := range list {
		regions[p.regionLocked(n)]++
	}
	return map[string]interface{}{
		"node_count": len(list),
		"regions":    regions,
		"reputation": p.rep.Summary(),
	}
}

// randFloat returns a uniform float64 in [0, 1) using crypto/rand.
func randFloat() (float64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("pheron/pool: random: %w", err)
	}
	// 53 high bits give an evenly spaced double in [0, 1).
	return float64(binary.BigEndian.Uint64(b[:])>>11) / (1 << 53), nil
}

// ── Default geolocator ───────────────────────────────────────────────────────

// DefaultGeolocator returns a heuristic geolocator. It is a placeholder for a
// real GeoIP/ASN database (e.g. MaxMind): public IPv4 addresses are bucketed by
// their first octet, which approximates allocation blocks well enough to add
// hop diversity, while private/loopback addresses collapse to "local".
func DefaultGeolocator() Geolocator { return defaultGeolocator{} }

type defaultGeolocator struct{}

func (defaultGeolocator) Region(host string) string {
	ip := net.ParseIP(host)
	if ip == nil {
		return "zone-" + bucket(host)
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() {
		return "local"
	}
	if v4 := ip.To4(); v4 != nil {
		return "as-" + strconv.Itoa(int(v4[0]))
	}
	return "v6-" + bucket(host)
}

// bucket returns a small stable label derived from s, used when no IP-based
// region is available.
func bucket(s string) string {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return strconv.Itoa(int(h % 16))
}
