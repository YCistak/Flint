// Package client builds Pheron circuits. A circuit is a 2-hop onion path:
// the client seals the destination request to the exit node (hop 2), wraps that
// in a layer sealed to the relay node (hop 1), and opens a TCP connection to
// hop 1. Application data is then sent through a doubly-encrypted stream so each
// hop can strip exactly one layer.
package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/YCistak/flint/pheron/crypto"
	"github.com/YCistak/flint/pheron/pool"
	"github.com/YCistak/flint/pheron/wire"
)

// Circuit is an established 2-hop path to a destination. Read and Write carry
// application plaintext; the layering is handled internally.
type Circuit struct {
	conn   net.Conn            // raw TCP to hop 1
	stream io.ReadWriteCloser // nested SecureConn: inner (hop 2) over outer (hop 1)
}

// streamConn adapts the two stacked SecureConns into a single ReadWriteCloser,
// closing the underlying TCP connection on Close.
type streamConn struct {
	io.Reader
	io.Writer
	conn net.Conn
}

func (s *streamConn) Close() error { return s.conn.Close() }

// Dial builds a circuit hop1 → hop2 → destination. destination is the final
// "host:port". The two hops must be distinct (the pool guarantees this).
func Dial(ctx context.Context, hop1, hop2 pool.Node, destination string) (*Circuit, error) {
	if hop1.ID() == hop2.ID() {
		return nil, fmt.Errorf("pheron/client: both hops are the same node")
	}

	// Inner layer: tell hop2 to connect to the destination. Sealed to hop2 so
	// hop1 cannot read it.
	innerPayload := wire.EncodeSetup(wire.CmdConnect, destination, nil)
	innerBlob, secret2, err := crypto.Seal(hop2.PublicKey, innerPayload)
	if err != nil {
		return nil, fmt.Errorf("pheron/client: seal inner layer: %w", err)
	}

	// Outer layer: tell hop1 to forward the inner blob to hop2.
	outerPayload := wire.EncodeSetup(wire.CmdForward, hop2.Address, innerBlob)
	outerBlob, secret1, err := crypto.Seal(hop1.PublicKey, outerPayload)
	if err != nil {
		return nil, fmt.Errorf("pheron/client: seal outer layer: %w", err)
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", hop1.Address)
	if err != nil {
		return nil, fmt.Errorf("pheron/client: dial hop1 %s: %w", hop1.Address, err)
	}
	if err := wire.WriteFrame(conn, outerBlob); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("pheron/client: send setup: %w", err)
	}

	// Stream layering, outermost (wire) first: hop1's key wraps hop2's key.
	outer, err := crypto.NewSecureConn(conn, secret1, true)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	inner, err := crypto.NewSecureConn(outer, secret2, true)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	return &Circuit{
		conn:   conn,
		stream: &streamConn{Reader: inner, Writer: inner, conn: conn},
	}, nil
}

// SetDeadline sets read/write deadlines on the underlying connection, bounding
// blocking circuit operations.
func (c *Circuit) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

// Read returns application data from the destination.
func (c *Circuit) Read(p []byte) (int, error) { return c.stream.Read(p) }

// Write sends application data to the destination.
func (c *Circuit) Write(p []byte) (int, error) { return c.stream.Write(p) }

// Close tears down the circuit.
func (c *Circuit) Close() error { return c.stream.Close() }
