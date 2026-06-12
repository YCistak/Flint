// Package core provides the daemon library for Flint.
package core

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/YCistak/flint/core/config"
	"github.com/YCistak/flint/core/detector"
	"github.com/YCistak/flint/core/fallback"
	"github.com/YCistak/flint/core/ipc"
)

// Daemon represents the Flint daemon instance.
type Daemon struct {
	config  *config.Config
	manager *fallback.Manager
}

// NewDaemon creates a new Daemon from cfg.
func NewDaemon(cfg *config.Config) (*Daemon, error) {
	det := detector.NewDetectorWithTTL(time.Duration(cfg.Daemon.DetectionCacheTTL) * time.Second)
	handlers := []fallback.Handler{
		det.DPIHandler(),
		det.PheronHandler(),
		det.TorHandler(),
	}
	return &Daemon{
		config:  cfg,
		manager: fallback.New(handlers),
	}, nil
}

// Run starts the daemon and blocks until shutdown (signal or IPC stop command).
func (d *Daemon) Run(ctx context.Context) error {
	// Write PID file so the CLI can report which process is running.
	// This must succeed before the IPC socket is opened; fail hard so the
	// caller knows the daemon did not start cleanly.
	if err := ipc.WritePID(ipc.PIDPath); err != nil {
		return fmt.Errorf("could not write PID file %s: %w", ipc.PIDPath, err)
	}
	defer ipc.RemovePID(ipc.PIDPath)

	// Start fallback chain.
	if err := d.manager.Start(ctx); err != nil {
		return fmt.Errorf("failed to start fallback manager: %w", err)
	}
	defer d.manager.Stop(ctx) //nolint:errcheck

	// Start IPC server.
	stopFromIPC := make(chan struct{}, 1)
	srv, err := ipc.NewServer(ipc.SocketPath, d, stopFromIPC)
	if err != nil {
		return fmt.Errorf("failed to start IPC server: %w", err)
	}
	go srv.Serve()
	defer srv.Close(ipc.SocketPath)

	log.Printf("Flint daemon running (pid=%d, socket=%s)", os.Getpid(), ipc.SocketPath)

	// Block until signal, IPC stop, or context cancellation.
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

	log.Printf("Flint daemon stopped")
	return nil
}

// Status returns the status of all fallback methods (used by the IPC server).
func (d *Daemon) Status() map[string]interface{} {
	return d.manager.Status()
}

// CurrentMethod returns the name of the currently active fallback method.
func (d *Daemon) CurrentMethod() string {
	return d.manager.Current()
}
