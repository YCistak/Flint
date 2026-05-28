package detector

import (
	"context"
	"fmt"
	"log"

	"github.com/YCistak/flint/core/dpi"
	"github.com/YCistak/flint/core/fallback"
)

// Detector is a stub for v0.1.0. In later versions it will perform DNS/TCP/RST
// detection and cache results per domain/IP.
type Detector struct{}

// NewDetector creates a new Detector.
func NewDetector() *Detector { return &Detector{} }

// DPIHandler returns a Handler that delegates to the compiled Rust dpi library.
func (d *Detector) DPIHandler() fallback.Handler {
	return dpi.New()
}

// PheronHandler returns a stub handler for the Pheron P2P relay (v0.4.0).
func (d *Detector) PheronHandler() fallback.Handler {
	return &StubHandler{name: "pheron"}
}

// TorHandler returns a stub handler for Tor fallback (v0.2.0).
func (d *Detector) TorHandler() fallback.Handler {
	return &StubHandler{name: "tor"}
}

// ── StubHandler — placeholder for methods not yet implemented ────────────────

// StubHandler satisfies fallback.Handler with no-op behaviour.
type StubHandler struct {
	name    string
	running bool
}

func (h *StubHandler) Start(_ context.Context) error {
	log.Printf("StubHandler[%s].Start()", h.name)
	h.running = true
	return nil
}

func (h *StubHandler) Stop(_ context.Context) error {
	log.Printf("StubHandler[%s].Stop()", h.name)
	h.running = false
	return nil
}

func (h *StubHandler) Health(_ context.Context) error {
	if !h.running {
		return fmt.Errorf("%s: handler not running", h.name)
	}
	return nil
}

func (h *StubHandler) Name() string { return h.name }
