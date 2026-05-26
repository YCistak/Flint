package detector

import (
	"context"
	"fmt"
	"log"

	"github.com/YCistak/flint/core/fallback"
)

// Detector is a stub for v0.1.0. In later versions, it will perform
// DNS/TCP/RST detection and cache results.
type Detector struct{}

// NewDetector creates a new detector instance.
func NewDetector() *Detector {
	return &Detector{}
}

// DPIHandler returns a stub handler for the DPI bypass method.
func (d *Detector) DPIHandler() fallback.Handler {
	return &StubHandler{name: "dpi"}
}

// PheronHandler returns a stub handler for the Pheron P2P relay method.
func (d *Detector) PheronHandler() fallback.Handler {
	return &StubHandler{name: "pheron"}
}

// TorHandler returns a stub handler for Tor fallback.
func (d *Detector) TorHandler() fallback.Handler {
	return &StubHandler{name: "tor"}
}

// StubHandler is a placeholder implementation of fallback.Handler for v0.1.0.
type StubHandler struct {
	name    string
	running bool
}

// Start initializes the handler.
func (h *StubHandler) Start(ctx context.Context) error {
	log.Printf("StubHandler[%s].Start() called", h.name)
	h.running = true
	return nil
}

// Stop cleanly shuts down the handler.
func (h *StubHandler) Stop(ctx context.Context) error {
	log.Printf("StubHandler[%s].Stop() called", h.name)
	h.running = false
	return nil
}

// Health checks if the handler is working.
func (h *StubHandler) Health(ctx context.Context) error {
	if !h.running {
		return fmt.Errorf("handler not running")
	}
	log.Printf("StubHandler[%s].Health() OK", h.name)
	return nil
}

// Name returns the handler's name.
func (h *StubHandler) Name() string {
	return h.name
}
