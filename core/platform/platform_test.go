package platform

import (
	"runtime"
	"testing"
)

// TestDetectMatchesCurrentOS verifies that Detect resolves to the platform
// matching the OS the test is running on.
func TestDetectMatchesCurrentOS(t *testing.T) {
	want := map[string]Platform{
		"linux":   Linux,
		"windows": Windows,
		"darwin":  MacOS,
	}[runtime.GOOS]

	if want == "" {
		t.Skipf("test OS %q is not one of the supported platforms", runtime.GOOS)
	}

	got := Detect()
	if got != want {
		t.Fatalf("Detect() = %q on GOOS=%q, want %q", got, runtime.GOOS, want)
	}
	if !got.Supported() {
		t.Fatalf("detected platform %q reports Supported() = false", got)
	}
}

// TestCaptureBackend verifies each platform maps to its expected capture
// backend, matching the architecture in PLANNED.md.
func TestCaptureBackend(t *testing.T) {
	cases := []struct {
		p    Platform
		want CaptureBackend
	}{
		{Linux, BackendNFQueue},
		{Windows, BackendWinDivert},
		{MacOS, BackendBPF},
		{Unknown, BackendNone},
	}
	for _, c := range cases {
		if got := c.p.CaptureBackend(); got != c.want {
			t.Errorf("%s.CaptureBackend() = %q, want %q", c.p, got, c.want)
		}
	}
}
