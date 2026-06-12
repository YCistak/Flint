// Package platform provides auto-detection of the host operating system so the
// daemon can select the correct packet-capture backend (nfqueue on Linux,
// WinDivert on Windows, libpcap/BPF on macOS).
package platform

import "runtime"

// Platform identifies a supported host operating system.
type Platform string

const (
	Linux   Platform = "linux"
	Windows Platform = "windows"
	MacOS   Platform = "macos"
	Unknown Platform = "unknown"
)

// CaptureBackend names the packet-capture mechanism used on a platform.
type CaptureBackend string

const (
	BackendNFQueue   CaptureBackend = "nfqueue"
	BackendWinDivert CaptureBackend = "windivert"
	BackendBPF       CaptureBackend = "bpf"
	BackendNone      CaptureBackend = "none"
)

// Detect returns the Platform for the OS the binary is running on, derived
// from runtime.GOOS. Unrecognised systems return Unknown.
func Detect() Platform {
	switch runtime.GOOS {
	case "linux":
		return Linux
	case "windows":
		return Windows
	case "darwin":
		return MacOS
	default:
		return Unknown
	}
}

// Supported reports whether Flint supports this platform.
func (p Platform) Supported() bool {
	switch p {
	case Linux, Windows, MacOS:
		return true
	default:
		return false
	}
}

// CaptureBackend returns the packet-capture backend used on this platform.
func (p Platform) CaptureBackend() CaptureBackend {
	switch p {
	case Linux:
		return BackendNFQueue
	case Windows:
		return BackendWinDivert
	case MacOS:
		return BackendBPF
	default:
		return BackendNone
	}
}

// String returns the platform identifier.
func (p Platform) String() string { return string(p) }
