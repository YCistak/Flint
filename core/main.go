// Package core provides the daemon library for Flint.
package core

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/YCistak/flint/core/blocklist"
	"github.com/YCistak/flint/core/config"
	"github.com/YCistak/flint/core/detector"
	"github.com/YCistak/flint/core/fallback"
	"github.com/YCistak/flint/core/ipc"
	"github.com/YCistak/flint/core/redirect"
)

// pheronListenSOCKS is the local SOCKS5 address for the Pheron proxy. It is
// kept distinct from the VLESS proxy (default 127.0.0.1:1080) so both can run.
const pheronListenSOCKS = "127.0.0.1:1081"

// redirectPort is where the transparent proxy listens and where the nft
// REDIRECT rule sends diverted traffic.
const redirectPort = 1090

// seedConcurrency bounds how many blocklist domains are probed in parallel.
const seedConcurrency = 8

// Daemon represents the Flint daemon instance.
//
// Model: DPI bypass runs system-wide and always-on (first line against
// throttling). Destinations the detector flags as blocked are diverted by an
// nft REDIRECT rule into a local transparent proxy, which forwards them through
// the first working method of the proxy chain (VLESS → Pheron → Tor).
type Daemon struct {
	config    *config.Config
	dpi       fallback.Handler
	proxies   *fallback.Manager
	detector  *detector.Detector
	blocklist *blocklist.Blocklist
	redir     *redirect.Redirector
	nft       *redirect.NFTRedirector

	mu     sync.Mutex
	dpiUp  bool
	dpiErr string
	// nftUp reports whether the transparent-redirect rule is installed.
	nftUp bool
}

// NewDaemon creates a new Daemon from cfg.
func NewDaemon(cfg *config.Config) (*Daemon, error) {
	det := detector.NewDetectorWithTTL(time.Duration(cfg.Daemon.DetectionCacheTTL) * time.Second)

	// Proxy chain (escalation upstreams), in priority order: VPS → Pheron → Tor.
	var proxies []fallback.Handler
	if server, ok := cfg.Tunnel.FirstEnabledServer(); ok {
		vh, err := det.VLESSHandler(server, cfg.Tunnel.ListenSOCKS)
		if err != nil {
			return nil, fmt.Errorf("invalid VPS config %q: %w", server.Name, err)
		}
		proxies = append(proxies, vh)
		log.Printf("VPS tunnel configured: %s (%s:%d)", server.Name, server.Address, server.Port)
	}
	if cfg.Pheron.Enabled {
		ph, err := det.PheronHandler(cfg.Pheron, pheronListenSOCKS)
		if err != nil {
			return nil, fmt.Errorf("invalid Pheron config: %w", err)
		}
		proxies = append(proxies, ph)
	}
	proxies = append(proxies, det.TorHandler())

	bl, err := blocklist.LoadBaseline()
	if err != nil {
		log.Printf("WARNING: bundled blocklist failed to load: %v", err)
		bl = nil
	}

	d := &Daemon{
		config:    cfg,
		dpi:       det.DPIHandler(),
		proxies:   fallback.New(proxies),
		detector:  det,
		blocklist: bl,
		nft:       redirect.NewNFTRedirector(redirectPort),
	}
	d.redir = redirect.New(fmt.Sprintf("127.0.0.1:%d", redirectPort), d.upstream)
	return d, nil
}

// upstream resolves the redirect.Upstream for the currently active proxy, or nil
// when no proxy is up yet. It is consulted per-connection, so switching the
// active method takes effect immediately.
func (d *Daemon) upstream() redirect.Upstream {
	h := d.proxies.CurrentHandler()
	if h == nil {
		return nil
	}
	// SOCKS-based methods (VLESS, Pheron) expose a local SOCKS5 endpoint.
	if sa, ok := h.(interface{ SOCKSAddr() string }); ok {
		return redirect.SOCKSUpstream(sa.SOCKSAddr())
	}
	// Tor already provides a DialContext that satisfies redirect.Upstream.
	if up, ok := h.(redirect.Upstream); ok {
		return up
	}
	return nil
}

// Run starts the daemon and blocks until shutdown (signal or IPC stop command).
func (d *Daemon) Run(ctx context.Context) error {
	if err := ipc.WritePID(ipc.PIDPath); err != nil {
		return fmt.Errorf("could not write PID file %s: %w", ipc.PIDPath, err)
	}
	defer ipc.RemovePID(ipc.PIDPath)

	// 1) DPI bypass: always-on, system-wide. Best effort — without it (e.g. no
	//    root) the proxy-routing path still works for blocked destinations.
	if err := d.dpi.Start(ctx); err != nil {
		d.setDPI(false, err.Error())
		log.Printf("WARNING: DPI bypass unavailable: %v (continuing — proxy routing still works)", err)
	} else {
		d.setDPI(true, "")
		defer d.dpi.Stop(context.Background()) //nolint:errcheck
		log.Printf("DPI bypass active (system-wide, tcp/443)")
	}

	// 2) Transparent redirect: listener + nft rule. Start with an empty divert
	//    set; the proxy chain and blocklist seeding fill it in asynchronously.
	if err := d.redir.Start(); err != nil {
		log.Printf("WARNING: transparent proxy listener failed: %v", err)
	} else {
		defer d.redir.Stop() //nolint:errcheck
		if err := d.nft.Install(); err != nil {
			log.Printf("WARNING: transparent routing disabled: %v", err)
		} else {
			d.setNFT(true)
			defer d.nft.Cleanup()
		}
	}

	// 3) Proxy chain + blocklist seeding run in the background so the daemon is
	//    immediately responsive even while Tor bootstraps (which can take
	//    minutes). The goroutine owns proxy shutdown, tied to runCtx.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	proxyDone := make(chan struct{})
	go d.runProxies(runCtx, proxyDone)

	// 4) IPC server.
	stopFromIPC := make(chan struct{}, 1)
	srv, err := ipc.NewServer(ipc.SocketPath, d, stopFromIPC)
	if err != nil {
		cancel()
		<-proxyDone
		return fmt.Errorf("failed to start IPC server: %w", err)
	}
	go srv.Serve()
	defer srv.Close(ipc.SocketPath)

	log.Printf("Flint daemon running (pid=%d, socket=%s)", os.Getpid(), ipc.SocketPath)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	select {
	case sig := <-sigChan:
		log.Printf("received signal %v — shutting down", sig)
	case <-stopFromIPC:
		log.Printf("stop requested via IPC — shutting down")
	case <-ctx.Done():
		log.Printf("context cancelled — shutting down")
	}

	// Stop the proxy goroutine (and its handlers) before the deferred teardown
	// of the redirect/DPI layers runs.
	cancel()
	select {
	case <-proxyDone:
	case <-time.After(10 * time.Second):
		log.Printf("proxy shutdown timed out")
	}

	log.Printf("Flint daemon stopped")
	return nil
}

// runProxies brings up the first working proxy method, seeds the divert set from
// the blocklist, then waits for shutdown to tear the chain down. It always
// closes done so Run can synchronise on it.
func (d *Daemon) runProxies(ctx context.Context, done chan<- struct{}) {
	defer close(done)

	if err := d.proxies.Start(ctx); err != nil {
		log.Printf("WARNING: no proxy upstream available: %v (blocked destinations cannot be routed)", err)
		<-ctx.Done()
		return
	}
	log.Printf("Proxy upstream active: %s", d.proxies.Current())

	if d.nftIsUp() {
		d.seedBlocklist(ctx)
	}

	<-ctx.Done()
	d.proxies.Stop(context.Background()) //nolint:errcheck
}

// seedBlocklist probes the bundled blocklist and diverts the IPs of domains that
// are confirmed blocked into the transparent proxy, eliminating cold-start
// detection latency for known cases.
func (d *Daemon) seedBlocklist(ctx context.Context) {
	if d.blocklist == nil {
		return
	}
	domains := d.blocklist.Domains()
	log.Printf("redirect: probing %d known domain(s) to seed the divert set...", len(domains))

	sem := make(chan struct{}, seedConcurrency)
	var wg sync.WaitGroup
	for _, dom := range domains {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(dom string) {
			defer wg.Done()
			defer func() { <-sem }()

			res := d.detector.Check(ctx, dom, false)
			if !res.Blocked {
				return
			}
			for _, ip := range res.Addrs {
				if net.ParseIP(ip).To4() == nil {
					continue // nft set holds IPv4 only
				}
				if err := d.nft.Block(ip); err != nil {
					log.Printf("redirect: failed to divert %s (%s): %v", ip, dom, err)
				}
			}
		}(dom)
	}
	wg.Wait()
	log.Printf("redirect: seeding complete — %d IP(s) diverted to proxy", d.nft.Count())
}

func (d *Daemon) setDPI(up bool, errMsg string) {
	d.mu.Lock()
	d.dpiUp, d.dpiErr = up, errMsg
	d.mu.Unlock()
}

func (d *Daemon) setNFT(up bool) {
	d.mu.Lock()
	d.nftUp = up
	d.mu.Unlock()
}

func (d *Daemon) nftIsUp() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.nftUp
}

// Status returns the status of the daemon (used by the IPC server).
func (d *Daemon) Status() map[string]interface{} {
	d.mu.Lock()
	dpiUp, dpiErr, nftUp := d.dpiUp, d.dpiErr, d.nftUp
	d.mu.Unlock()

	dpi := map[string]interface{}{"active": dpiUp}
	if dpiErr != "" {
		dpi["error"] = dpiErr
	}

	upstream := "none"
	if h := d.proxies.CurrentHandler(); h != nil {
		upstream = h.Name()
	}

	return map[string]interface{}{
		"dpi": dpi,
		"redirect": map[string]interface{}{
			"enabled":      nftUp,
			"upstream":     upstream,
			"diverted_ips": d.nft.Count(),
		},
		"proxies": d.proxies.Status()["methods"],
	}
}

// CurrentMethod returns the name of the currently active proxy upstream.
func (d *Daemon) CurrentMethod() string {
	return d.proxies.Current()
}
