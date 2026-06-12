package pheron

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// Minimal SOCKS5 (RFC 1928) server: no authentication, CONNECT command only.
// Applications point at the local proxy and their connections are carried over
// Pheron circuits.

const (
	socksVersion        byte = 0x05
	socksCmdConnect     byte = 0x01
	socksSucceeded      byte = 0x00
	socksGeneralFailure byte = 0x01

	socksAtypIPv4   byte = 0x01
	socksAtypDomain byte = 0x03
	socksAtypIPv6   byte = 0x04
)

// socks5Connect reads the greeting and CONNECT request, returning the requested
// destination host and port.
func socks5Connect(c net.Conn) (string, uint16, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(c, header); err != nil {
		return "", 0, fmt.Errorf("read greeting: %w", err)
	}
	if header[0] != socksVersion {
		return "", 0, fmt.Errorf("unsupported SOCKS version %d", header[0])
	}
	if _, err := io.ReadFull(c, make([]byte, int(header[1]))); err != nil {
		return "", 0, fmt.Errorf("read methods: %w", err)
	}
	if _, err := c.Write([]byte{socksVersion, 0x00}); err != nil {
		return "", 0, fmt.Errorf("write method selection: %w", err)
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return "", 0, fmt.Errorf("read request: %w", err)
	}
	if req[0] != socksVersion {
		return "", 0, fmt.Errorf("unsupported SOCKS version %d", req[0])
	}
	if req[1] != socksCmdConnect {
		_ = socks5Reply(c, socksGeneralFailure)
		return "", 0, fmt.Errorf("unsupported SOCKS command %d (only CONNECT)", req[1])
	}

	var host string
	switch req[3] {
	case socksAtypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, fmt.Errorf("read IPv4: %w", err)
		}
		host = net.IP(b).String()
	case socksAtypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, fmt.Errorf("read IPv6: %w", err)
		}
		host = net.IP(b).String()
	case socksAtypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return "", 0, fmt.Errorf("read domain length: %w", err)
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, fmt.Errorf("read domain: %w", err)
		}
		host = string(b)
	default:
		_ = socks5Reply(c, socksGeneralFailure)
		return "", 0, fmt.Errorf("unsupported address type %d", req[3])
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(c, portBytes); err != nil {
		return "", 0, fmt.Errorf("read port: %w", err)
	}
	return host, binary.BigEndian.Uint16(portBytes), nil
}

// socks5Reply sends a SOCKS5 reply with the given status and a zero
// BND.ADDR/BND.PORT, sufficient for CONNECT clients.
func socks5Reply(c net.Conn, status byte) error {
	_, err := c.Write([]byte{socksVersion, status, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
