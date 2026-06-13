//go:build linux

package redirect

import (
	"fmt"
	"net"
	"strconv"

	"golang.org/x/sys/unix"
)

// soOriginalDst is the SO_ORIGINAL_DST getsockopt option (netfilter), used to
// recover the pre-NAT destination of a connection redirected by an iptables
// REDIRECT / nft `redirect` rule.
const soOriginalDst = 80

// originalDestination reads SO_ORIGINAL_DST from a redirected IPv4 TCP
// connection and returns the original "ip:port" the client meant to reach.
func originalDestination(c net.Conn) (string, error) {
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("connection is %T, not *net.TCPConn", c)
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return "", err
	}

	var (
		host    string
		port    uint16
		sockErr error
	)
	ctrlErr := raw.Control(func(fd uintptr) {
		// SO_ORIGINAL_DST yields a sockaddr_in; GetsockoptIPv6Mreq is the
		// conventional way to pull the raw 16-byte blob out of Go's syscall
		// layer. Multiaddr layout: [0:2]=family, [2:4]=port (big-endian),
		// [4:8]=IPv4 address.
		mreq, e := unix.GetsockoptIPv6Mreq(int(fd), unix.IPPROTO_IP, soOriginalDst)
		if e != nil {
			sockErr = e
			return
		}
		m := mreq.Multiaddr
		host = net.IPv4(m[4], m[5], m[6], m[7]).String()
		port = uint16(m[2])<<8 | uint16(m[3])
	})
	if ctrlErr != nil {
		return "", ctrlErr
	}
	if sockErr != nil {
		return "", fmt.Errorf("getsockopt SO_ORIGINAL_DST: %w", sockErr)
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}
