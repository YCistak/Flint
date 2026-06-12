package detector

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"syscall"
	"time"
)

// Reason classifies why a domain was judged blocked (or not).
type Reason string

const (
	// ReasonOK means the domain resolved, connected, and completed a TLS
	// handshake without interference.
	ReasonOK Reason = "ok"
	// ReasonDNSBlocked means DNS resolution failed or returned no addresses,
	// which often indicates DNS-based censorship.
	ReasonDNSBlocked Reason = "dns_blocked"
	// ReasonTCPTimeout means the TCP connection or handshake timed out, which
	// often indicates IP-level blocking or throttling.
	ReasonTCPTimeout Reason = "tcp_timeout"
	// ReasonRST means the connection was reset, typically by a DPI middlebox
	// injecting RST packets after seeing the TLS ClientHello/SNI.
	ReasonRST Reason = "rst"
	// ReasonConnRefused means the peer actively refused the connection.
	ReasonConnRefused Reason = "conn_refused"
)

// Result is the outcome of probing a single domain.
type Result struct {
	Domain string
	// Blocked is true when interference was detected at any stage.
	Blocked bool
	// Reason classifies the outcome.
	Reason Reason
	// DNSResolved is true if the domain resolved to at least one address.
	DNSResolved bool
	// Addrs holds the resolved IP addresses (empty if DNS failed).
	Addrs []string
	// TCPConnected is true if the TCP handshake completed.
	TCPConnected bool
	// HandshakeOK is true if the TLS handshake completed without a reset.
	HandshakeOK bool
	// Latency is the time to establish the TCP connection (meaningful only
	// when TCPConnected is true).
	Latency time.Duration
	// CheckedAt is when the probe ran.
	CheckedAt time.Time
}

// Engine probes domains for censorship using DNS, TCP, and RST/timeout
// signals. The zero value is not usable; construct with NewEngine.
type Engine struct {
	resolver       *net.Resolver
	dnsTimeout     time.Duration
	connectTimeout time.Duration
	handshakeTO    time.Duration
}

// NewEngine returns a detection Engine with default timeouts.
func NewEngine() *Engine {
	return &Engine{
		resolver:       net.DefaultResolver,
		dnsTimeout:     5 * time.Second,
		connectTimeout: 8 * time.Second,
		handshakeTO:    8 * time.Second,
	}
}

// Probe runs the full detection sequence against domain (host without port)
// over port 443: DNS resolution, TCP connect, then a TLS handshake used to
// surface DPI RST injection. It never returns an error; the verdict is
// carried in the Result.
func (e *Engine) Probe(ctx context.Context, domain string) Result {
	res := Result{Domain: domain, CheckedAt: time.Now(), Reason: ReasonOK}

	// 1. DNS check.
	dnsCtx, cancel := context.WithTimeout(ctx, e.dnsTimeout)
	addrs, err := e.resolver.LookupHost(dnsCtx, domain)
	cancel()
	if err != nil || len(addrs) == 0 {
		res.Blocked = true
		res.Reason = ReasonDNSBlocked
		return res
	}
	res.DNSResolved = true
	res.Addrs = addrs

	// 2. TCP connect to :443, measuring latency.
	dialer := net.Dialer{Timeout: e.connectTimeout}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(domain, "443"))
	if err != nil {
		res.Blocked = true
		res.Reason = classifyNetErr(err)
		return res
	}
	res.Latency = time.Since(start)
	res.TCPConnected = true
	defer conn.Close()

	// 3. RST / timeout detection: drive a TLS handshake. DPI middleboxes that
	// key on the SNI commonly inject an RST once the ClientHello is seen, so a
	// handshake reset is a strong block signal even when TCP connected fine.
	_ = conn.SetDeadline(time.Now().Add(e.handshakeTO))
	tlsConn := tls.Client(conn, &tls.Config{ServerName: domain})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		res.Blocked = true
		res.Reason = classifyNetErr(err)
		return res
	}
	res.HandshakeOK = true
	return res
}

// classifyNetErr maps a network error to a detection Reason.
func classifyNetErr(err error) Reason {
	if err == nil {
		return ReasonOK
	}

	// Timeout (deadline exceeded or i/o timeout).
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ReasonTCPTimeout
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ReasonTCPTimeout
	}

	// Connection reset (RST injection) vs actively refused.
	if errors.Is(err, syscall.ECONNRESET) {
		return ReasonRST
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return ReasonConnRefused
	}

	// A TLS handshake aborted by a mid-stream RST often surfaces as an
	// unexpected EOF rather than a typed syscall error.
	if errors.Is(err, net.ErrClosed) {
		return ReasonRST
	}

	// Fall back to RST as the generic "interfered with" verdict.
	return ReasonRST
}
