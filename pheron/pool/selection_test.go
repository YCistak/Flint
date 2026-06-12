package pool

import (
	"testing"
	"time"
)

// twoRegionGeo assigns nodes to regions by a prefix of their address.
func twoRegionGeo() Geolocator {
	return GeolocatorFunc(func(host string) string {
		if len(host) > 0 && host[0] == 'u' {
			return "us"
		}
		return "eu"
	})
}

func TestSelectTwoPrefersDifferentRegions(t *testing.T) {
	self := mkNode(t, "self")
	p := New(self, []Node{
		mkNode(t, "us-1"), mkNode(t, "us-2"),
		mkNode(t, "eu-1"), mkNode(t, "eu-2"),
	})
	p.SetGeolocator(twoRegionGeo())
	if err := p.Join(); err != nil {
		t.Fatalf("Join: %v", err)
	}

	diff := 0
	const trials = 400
	for i := 0; i < trials; i++ {
		n1, n2, err := p.SelectTwo()
		if err != nil {
			t.Fatalf("SelectTwo: %v", err)
		}
		r1 := p.geo.Region(n1.Address)
		r2 := p.geo.Region(n2.Address)
		if r1 != r2 {
			diff++
		}
	}
	// With a 4x diversity bonus and balanced regions, cross-region circuits
	// should dominate. Uniform random would give ~50%.
	if frac := float64(diff) / trials; frac < 0.6 {
		t.Fatalf("cross-region fraction = %.2f, want > 0.6", frac)
	}
}

func TestSelectTwoFavorsHighReputation(t *testing.T) {
	self := mkNode(t, "self")
	star := mkNode(t, "star")
	bad := []Node{mkNode(t, "b1"), mkNode(t, "b2"), mkNode(t, "b3"), mkNode(t, "b4")}
	p := New(self, append([]Node{star}, bad...))
	if err := p.Join(); err != nil {
		t.Fatalf("Join: %v", err)
	}

	rep := p.Reputation()
	for i := 0; i < 10; i++ {
		rep.RecordSuccess(star.ID(), 5*time.Millisecond)
		for _, b := range bad {
			rep.RecordFailure(b.ID())
		}
	}

	hits := 0
	const trials = 400
	for i := 0; i < trials; i++ {
		n1, n2, err := p.SelectTwo()
		if err != nil {
			t.Fatalf("SelectTwo: %v", err)
		}
		if n1.ID() == star.ID() || n2.ID() == star.ID() {
			hits++
		}
	}
	// The high-reputation node should appear in well over half of circuits;
	// uniform selection of 2 from 5 would give ~40%.
	if frac := float64(hits) / trials; frac < 0.6 {
		t.Fatalf("high-reputation node selection fraction = %.2f, want > 0.6", frac)
	}
}

func TestDefaultGeolocator(t *testing.T) {
	g := DefaultGeolocator()
	if r := g.Region("127.0.0.1"); r != "local" {
		t.Errorf("loopback region = %q, want local", r)
	}
	if r := g.Region("10.0.0.5"); r != "local" {
		t.Errorf("private region = %q, want local", r)
	}
	// Two public IPs in different /8 blocks should differ.
	if g.Region("8.8.8.8") == g.Region("1.1.1.1") {
		t.Errorf("distinct /8 blocks should map to distinct regions")
	}
}
