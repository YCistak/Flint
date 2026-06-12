// Package wire defines Pheron's on-the-wire framing and the circuit-setup
// payload that each onion layer carries.
//
// During setup a node receives one length-prefixed frame, decrypts it (see
// package crypto), and parses a setup payload telling it what to do:
//
//	CmdForward  — strip this layer and forward the embedded inner blob to the
//	              named next hop, then relay the stream.
//	CmdConnect  — this is the exit hop: open a TCP connection to the named
//	              destination and relay the stream.
package wire

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Protocol version carried at the head of every setup payload.
const protocolVersion byte = 0x01

// Setup commands.
const (
	CmdConnect byte = 0x01 // exit hop: connect to destination
	CmdForward byte = 0x02 // relay hop: forward inner blob to next hop
)

// maxFrameLen caps a single length-prefixed frame (setup blobs are small; this
// guards against a peer announcing an absurd length).
const maxFrameLen = 1 << 20 // 1 MiB

// WriteFrame writes b prefixed with a uint32 big-endian length.
func WriteFrame(w io.Writer, b []byte) error {
	if len(b) > maxFrameLen {
		return fmt.Errorf("pheron/wire: frame too large (%d bytes)", len(b))
	}
	buf := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(b)))
	copy(buf[4:], b)
	_, err := w.Write(buf)
	return err
}

// ReadFrame reads a single length-prefixed frame.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrameLen {
		return nil, fmt.Errorf("pheron/wire: frame length %d exceeds limit", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// EncodeSetup builds a setup payload:
//
//	version(1) | cmd(1) | addrLen(uint16) | addr | inner...
//
// For CmdForward, inner is the next layer's sealed blob. For CmdConnect, inner
// is empty.
func EncodeSetup(cmd byte, addr string, inner []byte) []byte {
	out := make([]byte, 0, 4+len(addr)+len(inner))
	out = append(out, protocolVersion, cmd)
	var al [2]byte
	binary.BigEndian.PutUint16(al[:], uint16(len(addr)))
	out = append(out, al[:]...)
	out = append(out, addr...)
	out = append(out, inner...)
	return out
}

// DecodeSetup parses a setup payload produced by EncodeSetup.
func DecodeSetup(b []byte) (cmd byte, addr string, inner []byte, err error) {
	if len(b) < 4 {
		return 0, "", nil, fmt.Errorf("pheron/wire: setup payload too short")
	}
	if b[0] != protocolVersion {
		return 0, "", nil, fmt.Errorf("pheron/wire: unsupported version %d", b[0])
	}
	cmd = b[1]
	if cmd != CmdConnect && cmd != CmdForward {
		return 0, "", nil, fmt.Errorf("pheron/wire: unknown command %d", cmd)
	}
	addrLen := int(binary.BigEndian.Uint16(b[2:4]))
	if len(b) < 4+addrLen {
		return 0, "", nil, fmt.Errorf("pheron/wire: truncated address")
	}
	addr = string(b[4 : 4+addrLen])
	inner = b[4+addrLen:]
	return cmd, addr, inner, nil
}
