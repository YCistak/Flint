//go:build !linux

package redirect

import (
	"fmt"
	"net"
)

// originalDestination is Linux-only (SO_ORIGINAL_DST). On other platforms the
// transparent-redirect path is not wired up yet, so report that clearly rather
// than silently misrouting.
func originalDestination(net.Conn) (string, error) {
	return "", fmt.Errorf("transparent redirect (SO_ORIGINAL_DST) is only implemented on Linux")
}
