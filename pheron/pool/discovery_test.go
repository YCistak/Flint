package pool

import (
	"context"
	"testing"

	"github.com/YCistak/flint/pheron/crypto"
	"github.com/YCistak/flint/pheron/node"
)

func nodeFromKey(t *testing.T, addr string) (*crypto.KeyPair, Node) {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return kp, Node{Address: addr, PublicKey: kp.Public()}
}

// TestGossipLearnsTransitivePeers verifies that after one gossip round a node
// learns a peer it had never been told about directly, proving the pool no
// longer depends solely on the bootstrap set.
func TestGossipLearnsTransitivePeers(t *testing.T) {
	// Node B runs a real server and answers gossip.
	kpB, _ := crypto.GenerateKeyPair()
	srvB := node.New(kpB)
	if err := srvB.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start B: %v", err)
	}
	defer srvB.Stop()
	nodeB := Node{Address: srvB.Addr(), PublicKey: kpB.Public()}

	// C is a peer that only B knows about.
	_, nodeC := nodeFromKey(t, "203.0.113.7:9999")

	// B's pool (self = B) knows about C.
	selfB := nodeB
	poolB := New(selfB, nil)
	if err := poolB.Join(); err != nil {
		t.Fatalf("join B: %v", err)
	}
	poolB.Add(nodeC)
	srvB.SetGossipHandler(NewGossip(poolB).HandleInbound)

	// A's pool (self = A) is bootstrapped only with B.
	_, selfA := nodeFromKey(t, "198.51.100.4:9999")
	poolA := New(selfA, []Node{nodeB})
	if err := poolA.Join(); err != nil {
		t.Fatalf("join A: %v", err)
	}
	if poolA.Count() != 1 {
		t.Fatalf("A should start knowing only B, has %d", poolA.Count())
	}

	// One gossip round: A contacts B, B merges A and returns its view (B + C).
	gossipA := NewGossip(poolA)
	gossipA.round(context.Background())

	found := false
	for _, n := range poolA.List() {
		if n.ID() == nodeC.ID() {
			found = true
		}
	}
	if !found {
		t.Fatalf("A did not learn about C via gossip; pool = %d nodes", poolA.Count())
	}

	// B should also have learned about A from the inbound gossip.
	foundA := false
	for _, n := range poolB.List() {
		if n.ID() == selfA.ID() {
			foundA = true
		}
	}
	if !foundA {
		t.Fatalf("B did not learn about A from inbound gossip")
	}
}

func TestEncodeDecodePeersRoundTrip(t *testing.T) {
	_, a := nodeFromKey(t, "1.2.3.4:9999")
	_, b := nodeFromKey(t, "example.com:1234")
	got, err := decodePeers(encodePeers([]Node{a, b}))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 2 || got[0].ID() != a.ID() || got[1].ID() != b.ID() {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got[0].Address != a.Address || got[1].Address != b.Address {
		t.Fatalf("address mismatch after round-trip")
	}
}
