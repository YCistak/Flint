package pool

import (
	"testing"
	"time"
)

func TestReputationNeutralForUnknown(t *testing.T) {
	r := NewReputation()
	if got := r.Score("unknown"); got != neutralScore {
		t.Fatalf("unknown score = %v, want %v", got, neutralScore)
	}
}

func TestReputationSuccessBeatsFailure(t *testing.T) {
	r := NewReputation()
	for i := 0; i < 10; i++ {
		r.RecordSuccess("good", 10*time.Millisecond)
		r.RecordFailure("bad")
	}
	good, bad := r.Score("good"), r.Score("bad")
	if good <= bad {
		t.Fatalf("reliable node score %v should exceed unreliable %v", good, bad)
	}
	if good <= neutralScore {
		t.Fatalf("consistently good node score %v should exceed neutral %v", good, neutralScore)
	}
}

func TestReputationLatencyPenalty(t *testing.T) {
	r := NewReputation()
	// Same perfect reliability, different latency.
	for i := 0; i < 5; i++ {
		r.RecordSuccess("fast", 5*time.Millisecond)
		r.RecordSuccess("slow", 2*time.Second)
	}
	if r.Score("fast") <= r.Score("slow") {
		t.Fatalf("fast node should outscore slow node (%v vs %v)", r.Score("fast"), r.Score("slow"))
	}
}

func TestReputationSummary(t *testing.T) {
	r := NewReputation()
	if got := r.Summary()["tracked"]; got != 0 {
		t.Fatalf("empty summary tracked = %v, want 0", got)
	}
	r.RecordSuccess("a", 10*time.Millisecond)
	r.RecordFailure("b")
	s := r.Summary()
	if s["tracked"] != 2 {
		t.Fatalf("tracked = %v, want 2", s["tracked"])
	}
	if _, ok := s["avg_score"]; !ok {
		t.Fatalf("summary missing avg_score")
	}
}
