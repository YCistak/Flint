//go:build !linux

package redirect

import "fmt"

// runNftErr is a stub on non-Linux platforms, where the transparent-redirect
// path is not available (nftables is Linux-only).
func runNftErr([]string) error {
	return fmt.Errorf("nftables transparent redirect is only supported on Linux")
}
