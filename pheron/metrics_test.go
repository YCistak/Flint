package pheron

import (
	"context"
	"testing"

	"github.com/YCistak/flint/pheron/pool"
)

// TestHandlerMetrics verifies the handler exposes pool health metrics suitable
// for the IPC status command once it is running.
func TestHandlerMetrics(t *testing.T) {
	_, n1 := startNode(t)
	_, n2 := startNode(t)

	h, err := New(Config{
		ListenSOCKS: "127.0.0.1:0",
		NodeListen:  "127.0.0.1:0",
		Bootstrap:   []pool.Node{n1, n2},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Before Start, metrics report not running.
	if running := h.Metrics()["running"]; running != false {
		t.Fatalf("pre-start running = %v, want false", running)
	}

	if err := h.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer h.Stop(context.Background())

	m := h.Metrics()
	if m["running"] != true {
		t.Fatalf("running = %v, want true", m["running"])
	}
	if nc, ok := m["node_count"].(int); !ok || nc != 2 {
		t.Fatalf("node_count = %v, want 2", m["node_count"])
	}
	if _, ok := m["regions"]; !ok {
		t.Fatalf("metrics missing regions distribution")
	}
	if _, ok := m["reputation"]; !ok {
		t.Fatalf("metrics missing reputation summary")
	}
	if _, ok := m["gossip"]; !ok {
		t.Fatalf("metrics missing gossip stats")
	}
}
