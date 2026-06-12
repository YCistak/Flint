package pool

import (
	"math"
	"sync"
	"time"
)

// Reputation tracks per-node reliability and latency so SelectTwo can prefer
// nodes that have proven fast and dependable. Scores are bounded in (0, 1]:
// a brand-new, untracked node starts at neutralScore so it still receives some
// traffic and can earn a reputation, while a node that keeps failing decays
// toward zero.
//
// Reputation is safe for concurrent use and is keyed by node ID (public key).
type Reputation struct {
	mu    sync.RWMutex
	stats map[string]*nodeStats
}

type nodeStats struct {
	successes int
	failures  int
	latency   time.Duration // EWMA of observed circuit latency; 0 = no sample
	lastSeen  time.Time
}

const (
	// repAlpha is the Laplace smoothing constant for the reliability ratio.
	repAlpha = 1.0
	// neutralScore is the score of an untracked node (successes == failures == 0
	// gives exactly this via the smoothing formula, but we special-case nil).
	neutralScore = 0.5
	// latencyBaseline is the latency at or below which a node earns the full
	// latency factor of 1.0. Slower nodes are scaled down proportionally.
	latencyBaseline = 50 * time.Millisecond
	// latencyEWMA weights each new latency sample against the running average.
	latencyEWMA = 0.3
	// minLatencyFactor floors the latency penalty so a slow-but-reliable node is
	// never scored to zero.
	minLatencyFactor = 0.05
)

// NewReputation returns an empty reputation tracker.
func NewReputation() *Reputation {
	return &Reputation{stats: make(map[string]*nodeStats)}
}

// RecordSuccess records a successful circuit through the node and folds the
// observed latency into its running average.
func (r *Reputation) RecordSuccess(id string, latency time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.statForUpdate(id)
	s.successes++
	s.lastSeen = time.Now()
	if latency > 0 {
		if s.latency == 0 {
			s.latency = latency
		} else {
			s.latency = time.Duration((1-latencyEWMA)*float64(s.latency) + latencyEWMA*float64(latency))
		}
	}
}

// RecordFailure records a failed attempt to use the node.
func (r *Reputation) RecordFailure(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.statForUpdate(id)
	s.failures++
	s.lastSeen = time.Now()
}

func (r *Reputation) statForUpdate(id string) *nodeStats {
	s := r.stats[id]
	if s == nil {
		s = &nodeStats{}
		r.stats[id] = s
	}
	return s
}

// Score returns the node's reputation in (0, 1]. Higher is better.
func (r *Reputation) Score(id string) float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.scoreLocked(id)
}

func (r *Reputation) scoreLocked(id string) float64 {
	s := r.stats[id]
	if s == nil {
		return neutralScore
	}
	reliability := (float64(s.successes) + repAlpha) /
		(float64(s.successes+s.failures) + 2*repAlpha)

	latencyFactor := 1.0
	if s.latency > 0 {
		latencyFactor = float64(latencyBaseline) / float64(s.latency)
		if latencyFactor > 1 {
			latencyFactor = 1
		}
		if latencyFactor < minLatencyFactor {
			latencyFactor = minLatencyFactor
		}
	}
	return reliability * latencyFactor
}

// Summary returns aggregate reputation statistics for status reporting.
func (r *Reputation) Summary() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.stats) == 0 {
		return map[string]interface{}{"tracked": 0}
	}
	var sum float64
	min, max := math.Inf(1), math.Inf(-1)
	for id := range r.stats {
		sc := r.scoreLocked(id)
		sum += sc
		min = math.Min(min, sc)
		max = math.Max(max, sc)
	}
	n := float64(len(r.stats))
	return map[string]interface{}{
		"tracked":   len(r.stats),
		"avg_score": round2(sum / n),
		"min_score": round2(min),
		"max_score": round2(max),
	}
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }
