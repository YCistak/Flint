package detector

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/YCistak/flint/core/config"
	"github.com/YCistak/flint/core/dpi"
	"github.com/YCistak/flint/core/fallback"
	"github.com/YCistak/flint/tor"
	"github.com/YCistak/flint/tunnel/vless"
)

// Detector performs DNS/TCP/RST censorship detection, caches results per
// domain, and supplies the fallback handlers for the daemon's method chain.
type Detector struct {
	engine *Engine
	cache  *Cache
}

// NewDetector creates a Detector with the default 24h detection cache TTL.
func NewDetector() *Detector {
	return NewDetectorWithTTL(DefaultCacheTTL)
}

// NewDetectorWithTTL creates a Detector with a custom detection cache TTL.
// A non-positive ttl falls back to DefaultCacheTTL.
func NewDetectorWithTTL(ttl time.Duration) *Detector {
	return &Detector{
		engine: NewEngine(),
		cache:  NewCache(ttl),
	}
}

// Check probes a domain for censorship, returning a cached result when one is
// still valid. Pass force=true to bypass the cache and re-probe.
func (d *Detector) Check(ctx context.Context, domain string, force bool) Result {
	if !force {
		if res, ok := d.cache.Get(domain); ok {
			return res
		}
	}
	res := d.engine.Probe(ctx, domain)
	d.cache.Set(domain, res)
	return res
}

// Invalidate drops the cached detection result for domain.
func (d *Detector) Invalidate(domain string) { d.cache.Invalidate(domain) }

// DPIHandler returns a Handler that delegates to the compiled Rust dpi library.
func (d *Detector) DPIHandler() fallback.Handler {
	return dpi.New()
}

// VLESSHandler returns a Handler that tunnels traffic through the given VPS
// server, exposing a local SOCKS5 proxy at listenSOCKS. It returns an error if
// the server config is invalid (e.g. a malformed UUID).
func (d *Detector) VLESSHandler(server config.ServerConfig, listenSOCKS string) (fallback.Handler, error) {
	return vless.New(vless.Config{
		Address:     server.Address,
		Port:        server.Port,
		UUID:        server.UUID,
		TLS:         server.TLS,
		SNI:         server.SNI,
		ListenSOCKS: listenSOCKS,
	})
}

// PheronHandler returns a stub handler for the Pheron P2P relay (v0.4.0).
func (d *Detector) PheronHandler() fallback.Handler {
	return &StubHandler{name: "pheron"}
}

// TorHandler returns the Tor fallback handler backed by a managed Tor process.
func (d *Detector) TorHandler() fallback.Handler {
	return tor.New("", "")
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
