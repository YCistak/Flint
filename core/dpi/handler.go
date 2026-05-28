// Package dpi wraps the Rust flint-dpi static library via CGo.
//
// Build prerequisites: run `cargo build --release` inside the dpi/ directory
// before building any Go package that imports this one.  See BUILD.md.
package dpi

/*
#cgo CFLAGS:  -I${SRCDIR}/../../dpi/include

// Link the static archive directly so the dynamic .so produced by cdylib is
// not preferred by the linker.
#cgo linux   LDFLAGS: ${SRCDIR}/../../dpi/target/release/libflint_dpi.a -lpthread -ldl -lnfnetlink -lmnl
#cgo darwin  LDFLAGS: ${SRCDIR}/../../dpi/target/release/libflint_dpi.a -lpthread
#cgo windows LDFLAGS: ${SRCDIR}/../../dpi/target/release/flint_dpi.lib  -lws2_32

#include "flint_dpi.h"
*/
import "C"

import (
	"context"
	"fmt"
)

// ── Status constants (mirror flint_dpi.h) ────────────────────────────────────

const (
	StatusStopped = int(C.DPI_STATUS_STOPPED)
	StatusRunning = int(C.DPI_STATUS_RUNNING)
	StatusError   = int(C.DPI_STATUS_ERROR)
)

// ── Handler ───────────────────────────────────────────────────────────────────

// Handler implements fallback.Handler by delegating lifecycle calls to the
// Rust dpi library via the three C entry points: dpi_start, dpi_stop,
// dpi_status.
type Handler struct{}

// New returns a Handler that wraps the compiled Rust dpi crate.
func New() *Handler { return &Handler{} }

// Start calls dpi_start() in the Rust library.
func (h *Handler) Start(_ context.Context) error {
	fmt.Println("[CGo] calling dpi_start")
	rc := int(C.dpi_start())
	fmt.Printf("[CGo] dpi_start returned %d\n", rc)
	if rc != 0 {
		return fmt.Errorf("dpi_start: error code %d", rc)
	}
	return nil
}

// Stop calls dpi_stop() in the Rust library.
func (h *Handler) Stop(_ context.Context) error {
	rc := int(C.dpi_stop())
	// DPI_ERR_NOT_RUNNING (-2) is acceptable at shutdown — treat as success.
	if rc != 0 && rc != -2 {
		return fmt.Errorf("dpi_stop: error code %d", rc)
	}
	return nil
}

// Health returns nil only when dpi_status() reports DPI_STATUS_RUNNING.
func (h *Handler) Health(_ context.Context) error {
	switch int(C.dpi_status()) {
	case StatusRunning:
		return nil
	case StatusError:
		return fmt.Errorf("DPI engine is in error state")
	default:
		return fmt.Errorf("DPI engine is not running")
	}
}

// Name satisfies fallback.Handler.
func (h *Handler) Name() string { return "dpi" }
