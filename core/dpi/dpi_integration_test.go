package dpi

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"testing"
)

// ruleArgs are the iptables match args for the NFQUEUE redirect rule the Rust
// engine installs on dpi_start (see dpi/src/ffi.rs).
var ruleArgs = []string{
	"-C", "OUTPUT",
	"-p", "tcp", "--dport", "443",
	"-j", "NFQUEUE", "--queue-num", "0",
}

// iptablesRuleExists reports whether the NFQUEUE redirect rule is present.
func iptablesRuleExists(t *testing.T) bool {
	t.Helper()
	err := exec.Command("iptables", ruleArgs...).Run()
	return err == nil
}

// TestDPIStartInstallsIptablesRule is an end-to-end check that starting the
// DPI handler actually installs the NFQUEUE iptables rule and that stopping it
// removes the rule.
//
// It requires Linux and root (iptables needs CAP_NET_ADMIN). When those are
// not available the test skips rather than passing, because the rule genuinely
// cannot be installed without privileges.
func TestDPIStartInstallsIptablesRule(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("iptables NFQUEUE wiring is Linux-only (GOOS=%s)", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root: iptables needs CAP_NET_ADMIN to add/check rules")
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("iptables binary not found on PATH")
	}

	// Don't clobber a rule a real daemon may already have installed.
	if iptablesRuleExists(t) {
		t.Skip("NFQUEUE rule already present before test; refusing to manage external state")
	}

	h := New()
	ctx := context.Background()

	if err := h.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	// Ensure cleanup even if assertions fail.
	t.Cleanup(func() { _ = h.Stop(ctx) })

	if !iptablesRuleExists(t) {
		t.Fatal("after Start(), expected NFQUEUE iptables rule to be present, but it is not")
	}

	if err := h.Stop(ctx); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
	if iptablesRuleExists(t) {
		t.Fatal("after Stop(), expected NFQUEUE iptables rule to be removed, but it is still present")
	}
}
