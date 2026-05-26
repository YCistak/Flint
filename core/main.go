// Package core provides the daemon library for Flint.
//
// The Daemon type orchestrates the fallback chain and is used by both
// the CLI and the standalone daemon entry point.
package core

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/YCistak/flint/core/config"
	"github.com/YCistak/flint/core/fallback"
	"github.com/YCistak/flint/core/detector"
)

// Daemon represents the Flint daemon instance.
type Daemon struct {
	config  *config.Config
	manager *fallback.Manager
	done    chan struct{}
}

// NewDaemon creates a new daemon instance.
func NewDaemon(cfg *config.Config) (*Daemon, error) {
	// Stub out detector for v0.1.0
	det := detector.NewDetector()

	// Build fallback handlers (stubs for now).
	// In later versions, these will be actual DPI, VLESS, Pheron, Tor handlers.
	handlers := []fallback.Handler{
		det.DPIHandler(),
		det.PheronHandler(),
		det.TorHandler(),
	}

	mgr := fallback.New(handlers)
	return &Daemon{
		config:  cfg,
		manager: mgr,
		done:    make(chan struct{}),
	}, nil
}

// Run starts the daemon and blocks until shutdown.
func (d *Daemon) Run(ctx context.Context) error {
	log.Printf("Flint daemon starting...")

	// Start the fallback manager.
	if err := d.manager.Start(ctx); err != nil {
		return fmt.Errorf("failed to start fallback manager: %w", err)
	}

	// Set up signal handling for graceful shutdown.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		log.Printf("Received signal: %v", sig)
		if err := d.manager.Stop(ctx); err != nil {
			log.Printf("Error stopping manager: %v", err)
		}
	case <-ctx.Done():
		log.Printf("Context cancelled")
		if err := d.manager.Stop(ctx); err != nil {
			log.Printf("Error stopping manager: %v", err)
		}
	}

	log.Printf("Flint daemon stopped")
	return nil
}

// CurrentMethod returns the currently active method name.
func (d *Daemon) CurrentMethod() string {
	return d.manager.Current()
}

// Status returns the status of all fallback methods.
func (d *Daemon) Status() map[string]interface{} {
	return d.manager.Status()
}
