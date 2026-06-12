// Package vless implements the client side of the VLESS protocol so a Flint
// user's own VPS can serve as a dedicated tunnel in the fallback chain.
//
// VLESS is a stateless, lightweight transport (the protocol used by Xray and
// V2Ray). A client opens a TCP connection to the server — almost always
// wrapped in TLS — writes a single request header identifying itself by UUID
// and naming the final destination, then streams the proxied payload. The
// server replies with a short response header followed by the destination's
// data. There is no per-packet framing: after the headers the connection is a
// transparent byte pipe to the destination.
//
// Reference: https://xtls.github.io/development/protocols/vless.html
package vless

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
)

// VLESS protocol version. Only version 0 exists.
const protocolVersion byte = 0x00

// VLESS commands (request header).
const (
	cmdTCP byte = 0x01
	cmdUDP byte = 0x02
)

// VLESS address types (request header).
const (
	atypIPv4   byte = 0x01
	atypDomain byte = 0x02
	atypIPv6   byte = 0x03
)

// parseUUID converts the canonical 8-4-4-4-12 hyphenated UUID string into its
// 16-byte form as required by the VLESS request header.
func parseUUID(s string) ([16]byte, error) {
	var out [16]byte
	clean := strings.ReplaceAll(s, "-", "")
	if len(clean) != 32 {
		return out, fmt.Errorf("vless: invalid UUID %q: want 36 chars (8-4-4-4-12)", s)
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return out, fmt.Errorf("vless: invalid UUID %q: %w", s, err)
	}
	copy(out[:], b)
	return out, nil
}

// encodeRequestHeader builds the VLESS request header addressed to host:port.
//
// Layout:
//
//	1 byte   protocol version (0)
//	16 bytes UUID
//	1 byte   addon length M
//	M bytes  addons (none here, so M = 0)
//	1 byte   command (TCP)
//	2 bytes  port (big endian)
//	1 byte   address type
//	N bytes  address (IPv4=4, IPv6=16, domain=1 length byte + name)
func encodeRequestHeader(uuid [16]byte, host string, port uint16) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.WriteByte(protocolVersion)
	buf.Write(uuid[:])
	buf.WriteByte(0x00) // addon length: no addons
	buf.WriteByte(cmdTCP)
	_ = binary.Write(buf, binary.BigEndian, port)

	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf.WriteByte(atypIPv4)
			buf.Write(v4)
		} else {
			buf.WriteByte(atypIPv6)
			buf.Write(ip.To16())
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("vless: domain %q length out of range", host)
		}
		buf.WriteByte(atypDomain)
		buf.WriteByte(byte(len(host)))
		buf.WriteString(host)
	}

	return buf.Bytes(), nil
}

// consumeResponseHeader reads and discards the server's VLESS response header
// from r, leaving r positioned at the start of the destination's payload.
//
// Layout:
//
//	1 byte   protocol version
//	1 byte   addon length N
//	N bytes  addons
func consumeResponseHeader(r io.Reader) error {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return fmt.Errorf("vless: reading response header: %w", err)
	}
	if head[0] != protocolVersion {
		return fmt.Errorf("vless: unexpected response version %d", head[0])
	}
	if n := int(head[1]); n > 0 {
		if _, err := io.ReadFull(r, make([]byte, n)); err != nil {
			return fmt.Errorf("vless: discarding response addons: %w", err)
		}
	}
	return nil
}
