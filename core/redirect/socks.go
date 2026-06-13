package redirect

import (
	"context"
	"net"

	"golang.org/x/net/proxy"
)

// socksUpstream dials through a local SOCKS5 proxy (as exposed by the VLESS and
// Pheron handlers). Tor is not wrapped here: bine already hands out a
// proxy.Dialer that satisfies Upstream directly.
type socksUpstream struct {
	addr string
}

// SOCKSUpstream returns an Upstream that routes connections through the SOCKS5
// proxy listening at addr (host:port).
func SOCKSUpstream(addr string) Upstream {
	return socksUpstream{addr: addr}
}

func (s socksUpstream) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d, err := proxy.SOCKS5("tcp", s.addr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	if cd, ok := d.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, network, addr)
	}
	return d.Dial(network, addr)
}
