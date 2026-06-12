package vless

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

// Tunable timeouts for the VLESS tunnel.
const (
	dialTimeout    = 15 * time.Second
	healthTimeout  = 20 * time.Second
	healthInterval = 30 * time.Second
)

// healthTarget is dialed through the tunnel during health checks. Cloudflare's
// 1.1.1.1 resolver answers a bare HTTP request on port 80, which is enough to
// confirm the VPS is forwarding traffic end to end.
const (
	healthTargetHost = "1.1.1.1"
	healthTargetPort = 80
)

// Config describes a single VLESS server to tunnel through.
type Config struct {
	// Address is the VPS hostname or IP.
	Address string
	// Port is the VLESS listening port on the VPS.
	Port int
	// UUID authenticates the client to the server (canonical hyphenated form).
	UUID string
	// TLS wraps the stream in TLS (the standard VLESS-over-TLS deployment).
	TLS bool
	// SNI is the TLS server name to present; defaults to Address when empty.
	SNI string
	// ListenSOCKS is the local address to expose a SOCKS5 proxy on. Defaults
	// to 127.0.0.1:1080 when empty.
	ListenSOCKS string
}

// Handler tunnels TCP traffic through a user-owned VPS using VLESS, and
// implements fallback.Handler so the fallback manager can treat it like any
// other bypass method. It exposes a local SOCKS5 proxy: connections accepted
// there are forwarded to their destination through the VPS.
//
// Handler is safe for concurrent use.
type Handler struct {
	cfg  Config
	uuid [16]byte

	mu       sync.Mutex
	listener net.Listener
	// cancelMonitor stops the background health-monitor goroutine.
	cancelMonitor context.CancelFunc
}

// New builds a Handler from cfg, validating the UUID up front.
func New(cfg Config) (*Handler, error) {
	uuid, err := parseUUID(cfg.UUID)
	if err != nil {
		return nil, err
	}
	if cfg.Address == "" || cfg.Port <= 0 {
		return nil, fmt.Errorf("vless: server address and port are required")
	}
	if cfg.ListenSOCKS == "" {
		cfg.ListenSOCKS = "127.0.0.1:1080"
	}
	return &Handler{cfg: cfg, uuid: uuid}, nil
}

// serverAddr is the VPS dial target.
func (h *Handler) serverAddr() string {
	return net.JoinHostPort(h.cfg.Address, strconv.Itoa(h.cfg.Port))
}

// dialTunnel opens a connection to the VPS, completes the VLESS handshake for
// the destination host:port, and returns a net.Conn that streams transparently
// to that destination. The server's response header is consumed lazily on the
// first Read.
func (h *Handler) dialTunnel(ctx context.Context, host string, port uint16) (net.Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	raw, err := d.DialContext(ctx, "tcp", h.serverAddr())
	if err != nil {
		return nil, fmt.Errorf("vless: dial VPS %s: %w", h.serverAddr(), err)
	}

	conn := raw
	if h.cfg.TLS {
		sni := h.cfg.SNI
		if sni == "" {
			sni = h.cfg.Address
		}
		tlsConn := tls.Client(raw, &tls.Config{ServerName: sni})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("vless: TLS handshake with %s: %w", h.serverAddr(), err)
		}
		conn = tlsConn
	}

	header, err := encodeRequestHeader(h.uuid, host, port)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if _, err := conn.Write(header); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("vless: writing request header: %w", err)
	}

	return &tunnelConn{Conn: conn}, nil
}

// tunnelConn wraps an established VLESS stream. The server prefixes the proxied
// payload with a response header, which is consumed on the first Read so the
// caller only ever sees destination bytes.
type tunnelConn struct {
	net.Conn
	once    sync.Once
	headErr error
}

func (c *tunnelConn) Read(p []byte) (int, error) {
	c.once.Do(func() { c.headErr = consumeResponseHeader(c.Conn) })
	if c.headErr != nil {
		return 0, c.headErr
	}
	return c.Conn.Read(p)
}

// Start brings up the local SOCKS5 proxy and launches the health monitor. It is
// a no-op if the tunnel is already running.
func (h *Handler) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.listener != nil {
		return nil
	}

	ln, err := net.Listen("tcp", h.cfg.ListenSOCKS)
	if err != nil {
		return fmt.Errorf("vless: listen on %s: %w", h.cfg.ListenSOCKS, err)
	}
	h.listener = ln

	go h.acceptLoop(ln)

	monitorCtx, cancel := context.WithCancel(context.Background())
	h.cancelMonitor = cancel
	go h.monitor(monitorCtx)

	log.Printf("vless: tunnel to %s active, SOCKS5 proxy on %s", h.serverAddr(), h.cfg.ListenSOCKS)
	return nil
}

// Stop closes the SOCKS5 listener and stops the health monitor. It is a no-op
// if the tunnel is not running.
func (h *Handler) Stop(_ context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.listener == nil {
		return nil
	}
	if h.cancelMonitor != nil {
		h.cancelMonitor()
		h.cancelMonitor = nil
	}
	err := h.listener.Close()
	h.listener = nil
	if err != nil {
		return fmt.Errorf("vless: closing listener: %w", err)
	}
	return nil
}

// Health confirms the tunnel can carry traffic by opening a connection through
// the VPS to a known endpoint and exchanging a byte.
func (h *Handler) Health(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()

	conn, err := h.dialTunnel(ctx, healthTargetHost, healthTargetPort)
	if err != nil {
		return err
	}
	defer conn.Close()

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	// A minimal HTTP/1.0 request elicits a response from 1.1.1.1:80.
	req := "GET / HTTP/1.0\r\nHost: " + healthTargetHost + "\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return fmt.Errorf("vless: health write: %w", err)
	}
	var buf [1]byte
	if _, err := io.ReadFull(conn, buf[:]); err != nil {
		return fmt.Errorf("vless: health read (no response through tunnel): %w", err)
	}
	return nil
}

// Name satisfies fallback.Handler.
func (h *Handler) Name() string { return "vless" }

// monitor pings the tunnel on a fixed interval and logs transitions. The
// fallback manager owns failover decisions; this loop provides visibility into
// tunnel health between manager-driven checks.
func (h *Handler) monitor(ctx context.Context) {
	ticker := time.NewTicker(healthInterval)
	defer ticker.Stop()

	healthy := true
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := h.Health(ctx)
			switch {
			case err != nil && healthy:
				healthy = false
				log.Printf("vless: tunnel to %s is unhealthy: %v", h.serverAddr(), err)
			case err == nil && !healthy:
				healthy = true
				log.Printf("vless: tunnel to %s recovered", h.serverAddr())
			}
		}
	}
}

// acceptLoop serves the local SOCKS5 proxy until the listener is closed.
func (h *Handler) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		go h.handleSOCKS(conn)
	}
}

// handleSOCKS performs a minimal SOCKS5 CONNECT handshake with a local client,
// dials the requested destination through the VPS, and pipes the two together.
func (h *Handler) handleSOCKS(client net.Conn) {
	defer client.Close()

	host, port, err := socks5Connect(client)
	if err != nil {
		log.Printf("vless: SOCKS5 handshake failed: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	upstream, err := h.dialTunnel(ctx, host, port)
	cancel()
	if err != nil {
		log.Printf("vless: tunnel dial to %s:%d failed: %v", host, port, err)
		_ = socks5Reply(client, socksGeneralFailure)
		return
	}
	defer upstream.Close()

	if err := socks5Reply(client, socksSucceeded); err != nil {
		return
	}

	// Pipe both directions until either side closes.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}

// ── Minimal SOCKS5 (RFC 1928), CONNECT + no-auth only ────────────────────────

const (
	socksVersion        byte = 0x05
	socksCmdConnect     byte = 0x01
	socksSucceeded      byte = 0x00
	socksGeneralFailure byte = 0x01

	socksAtypIPv4   byte = 0x01
	socksAtypDomain byte = 0x03
	socksAtypIPv6   byte = 0x04
)

// socks5Connect reads the greeting and a CONNECT request, returning the
// requested destination host and port. Only the no-authentication method and
// the CONNECT command are supported.
func socks5Connect(c net.Conn) (string, uint16, error) {
	// Greeting: version, nMethods, methods...
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
	// Reply: no authentication required.
	if _, err := c.Write([]byte{socksVersion, 0x00}); err != nil {
		return "", 0, fmt.Errorf("write method selection: %w", err)
	}

	// Request: version, command, reserved, atyp, addr, port.
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
// BND.ADDR/BND.PORT, which is sufficient for CONNECT clients.
func socks5Reply(c net.Conn, status byte) error {
	_, err := c.Write([]byte{socksVersion, status, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
