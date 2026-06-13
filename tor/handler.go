// Package tor integrates the Tor network as a fallback method using the
// bine library (github.com/cretz/bine). It starts and manages a local Tor
// process and exposes a fallback.Handler so the fallback manager can treat
// Tor like any other bypass method.
//
// Tor is the last resort in the fallback chain: slow but almost always
// available, providing maximum anonymity when DPI bypass and Pheron fail.
package tor

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cretz/bine/tor"
)

// Default timeouts for Tor lifecycle operations. Bootstrapping over the live
// Tor network can be slow, so these are generous.
const (
	startTimeout     = 3 * time.Minute
	bootstrapTimeout = 3 * time.Minute
	healthTimeout    = 30 * time.Second
)

// healthCheckAddr is dialed through the Tor SOCKS proxy during Health checks
// to confirm the circuit can actually carry traffic. check.torproject.org is
// operated by the Tor Project specifically for connectivity verification.
const healthCheckAddr = "check.torproject.org:443"

// Handler implements fallback.Handler by starting a local Tor process and
// routing health checks through it. It is safe for concurrent use.
type Handler struct {
	// ExePath optionally overrides the path to the tor executable. If empty,
	// bine looks for "tor" on the PATH.
	ExePath string
	// DataDir optionally sets a persistent Tor data directory. If empty, bine
	// creates (and cleans up) a temporary directory on each start.
	DataDir string

	mu      sync.Mutex
	process *tor.Tor
	// dialer is created lazily on first DialContext and reused across
	// connections; bine's Dialer manages circuit state internally.
	dialer *tor.Dialer
}

// New returns a Tor Handler. exePath and dataDir may be empty to use bine's
// defaults ("tor" on PATH and a temporary data directory).
func New(exePath, dataDir string) *Handler {
	return &Handler{ExePath: exePath, DataDir: dataDir}
}

// Start launches the Tor process and waits for it to bootstrap onto the
// network. It is a no-op if Tor is already running.
func (h *Handler) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.process != nil {
		return nil
	}

	startCtx, cancel := context.WithTimeout(ctx, startTimeout)
	defer cancel()

	t, err := tor.Start(startCtx, &tor.StartConf{
		ExePath:       h.ExePath,
		DataDir:       h.DataDir,
		EnableNetwork: false, // bring the network up explicitly below so we can wait for bootstrap
	})
	if err != nil {
		return fmt.Errorf("tor: failed to start process: %w", err)
	}

	// Connect to the wider Tor network and block until bootstrap reaches 100%.
	bootCtx, bootCancel := context.WithTimeout(ctx, bootstrapTimeout)
	defer bootCancel()
	if err := t.EnableNetwork(bootCtx, true); err != nil {
		_ = t.Close()
		return fmt.Errorf("tor: failed to bootstrap network: %w", err)
	}

	h.process = t
	return nil
}

// Stop shuts down the Tor process. It is a no-op if Tor is not running.
func (h *Handler) Stop(_ context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.process == nil {
		return nil
	}

	err := h.process.Close()
	h.process = nil
	h.dialer = nil
	if err != nil {
		return fmt.Errorf("tor: failed to stop process: %w", err)
	}
	return nil
}

// Health confirms Tor is running and can carry traffic by opening a circuit
// to a known endpoint through the Tor SOCKS proxy.
func (h *Handler) Health(ctx context.Context) error {
	h.mu.Lock()
	t := h.process
	h.mu.Unlock()

	if t == nil {
		return fmt.Errorf("tor: handler not running")
	}

	dialCtx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()

	dialer, err := t.Dialer(dialCtx, nil)
	if err != nil {
		return fmt.Errorf("tor: failed to create dialer: %w", err)
	}

	conn, err := dialer.DialContext(dialCtx, "tcp", healthCheckAddr)
	if err != nil {
		return fmt.Errorf("tor: health dial to %s failed: %w", healthCheckAddr, err)
	}
	_ = conn.Close()
	return nil
}

// Name satisfies fallback.Handler.
func (h *Handler) Name() string { return "tor" }

// DialContext routes a connection through Tor, satisfying the transparent-proxy
// upstream contract (redirect.Upstream). The bine dialer is created once and
// reused; it is reset when the handler stops.
func (h *Handler) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	h.mu.Lock()
	t := h.process
	d := h.dialer
	h.mu.Unlock()

	if t == nil {
		return nil, fmt.Errorf("tor: handler not running")
	}
	if d == nil {
		nd, err := t.Dialer(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("tor: failed to create dialer: %w", err)
		}
		h.mu.Lock()
		// Another goroutine may have set it first; keep whichever is present.
		if h.dialer == nil {
			h.dialer = nd
		}
		d = h.dialer
		h.mu.Unlock()
	}
	return d.DialContext(ctx, network, addr)
}
