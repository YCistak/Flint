package pool

import (
	"errors"
	"testing"

	"github.com/YCistak/flint/pheron/crypto"
)

func mkNode(t *testing.T, addr string) Node {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return Node{Address: addr, PublicKey: kp.Public()}
}

func TestJoinExcludesSelfAndCounts(t *testing.T) {
	self := mkNode(t, "127.0.0.1:9999")
	a := mkNode(t, "127.0.0.1:1")
	b := mkNode(t, "127.0.0.1:2")

	// Include self in the bootstrap list to confirm it is filtered out.
	p := New(self, []Node{a, b, self})
	if err := p.Join(); err != nil {
		t.Fatalf("Join: %v", err)
	}
	if got := p.Count(); got != 2 {
		t.Fatalf("Count = %d, want 2 (self excluded)", got)
	}
}

func TestSelectTwoDistinct(t *testing.T) {
	self := mkNode(t, "self")
	p := New(self, []Node{mkNode(t, "a"), mkNode(t, "b"), mkNode(t, "c")})
	if err := p.Join(); err != nil {
		t.Fatalf("Join: %v", err)
	}
	for i := 0; i < 100; i++ {
		n1, n2, err := p.SelectTwo()
		if err != nil {
			t.Fatalf("SelectTwo: %v", err)
		}
		if n1.ID() == n2.ID() {
			t.Fatalf("SelectTwo returned the same node for both hops")
		}
	}
}

func TestSelectTwoInsufficient(t *testing.T) {
	self := mkNode(t, "self")
	p := New(self, []Node{mkNode(t, "a")})
	if err := p.Join(); err != nil {
		t.Fatalf("Join: %v", err)
	}
	if _, _, err := p.SelectTwo(); !errors.Is(err, ErrInsufficientNodes) {
		t.Fatalf("SelectTwo error = %v, want ErrInsufficientNodes", err)
	}
}

func TestLeaveClearsPool(t *testing.T) {
	self := mkNode(t, "self")
	p := New(self, []Node{mkNode(t, "a"), mkNode(t, "b")})
	if err := p.Join(); err != nil {
		t.Fatalf("Join: %v", err)
	}
	p.Leave()
	if got := p.Count(); got != 0 {
		t.Fatalf("Count after Leave = %d, want 0", got)
	}
}
