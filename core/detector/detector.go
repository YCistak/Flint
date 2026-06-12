package detector

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/YCistak/flint/core/config"
	"github.com/YCistak/flint/core/dpi"
	"github.com/YCistak/flint/core/fallback"
	"github.com/YCistak/flint/pheron"
	"github.com/YCistak/flint/pheron/crypto"
	"github.com/YCistak/flint/pheron/pool"
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

// PheronHandler returns the Pheron P2P relay handler (v0.1 beta), built from the
// daemon's Pheron config. The handler runs a local relay node, joins the pool
// from the configured static bootstrap nodes, and exposes a SOCKS5 proxy that
// routes through 2-hop circuits. At Start it enforces the 2-hop rule: if fewer
// than two other nodes are available it fails so the chain falls through to Tor.
//
// listenSOCKS is the local SOCKS5 address for Pheron (distinct from the VLESS
// proxy address).
func (d *Detector) PheronHandler(cfg config.PheronConfig, listenSOCKS string) (fallback.Handler, error) {
	bootstrap, err := ParseBootstrapNodes(cfg.BootstrapNodes)
	if err != nil {
		return nil, err
	}
	return pheron.New(pheron.Config{
		ListenSOCKS: listenSOCKS,
		NodeListen:  fmt.Sprintf(":%d", cfg.LocalPort),
		Bootstrap:   bootstrap,
	})
}

// ParseBootstrapNodes parses static bootstrap node descriptors of the form
// "host:port@base64url-publickey" into pool nodes.
func ParseBootstrapNodes(entries []string) ([]pool.Node, error) {
	nodes := make([]pool.Node, 0, len(entries))
	for _, e := range entries {
		at := strings.LastIndex(e, "@")
		if at < 0 {
			return nil, fmt.Errorf("bootstrap node %q: want host:port@publickey", e)
		}
		addr, keyStr := e[:at], e[at+1:]
		pk, err := crypto.ParsePublicKey(keyStr)
		if err != nil {
			return nil, fmt.Errorf("bootstrap node %q: %w", e, err)
		}
		nodes = append(nodes, pool.Node{Address: addr, PublicKey: pk})
	}
	return nodes, nil
}

// TorHandler returns the Tor fallback handler backed by a managed Tor process.
func (d *Detector) TorHandler() fallback.Handler {
	return tor.New("", "")
}
