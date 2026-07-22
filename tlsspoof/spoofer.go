package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

type Spoofer struct {
	pool        *Pool
	dialTimeout time.Duration
	fpConfig    FingerprintConfig
}

func NewSpoofer(pool *Pool, dialTimeout time.Duration,
	fpConfig FingerprintConfig) *Spoofer {
	return &Spoofer{
		pool:        pool,
		dialTimeout: dialTimeout,
		fpConfig:    fpConfig,
	}
}

// dialUTLS creates TCP conn, wraps in utls with browser fingerprint
func (s *Spoofer) dialUTLS(ctx context.Context, host, port, ua string) (
	*utls.UConn, string, error) {

	addr := net.JoinHostPort(host, port)

	rawConn, err := (&net.Dialer{Timeout: s.dialTimeout}).
		DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, "", fmt.Errorf("tcp dial %s: %w", addr, err)
	}

	fp := pickFingerprint(ua, s.fpConfig)

	config := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	}

	uConn := utls.UClient(rawConn, config, fp)

	if err := uConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, "", fmt.Errorf("utls handshake %s: %w", addr, err)
	}

	proto := uConn.ConnectionState().NegotiatedProtocol
	if proto == "" {
		proto = "http/1.1"
	}

	return uConn, proto, nil
}

// RoundTrip executes HTTP request through spoofed TLS
func (s *Spoofer) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		if req.URL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	if req.URL.Scheme == "http" {
		return s.roundTripPlain(req, host, port)
	}

	// 1. Try H2 pool
	if cc := s.pool.H2Get(host); cc != nil {
		resp, err := cc.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
	}

	// 2. Try H1 pool
	if pc := s.pool.H1Get(host); pc != nil {
		resp, err := s.sendH1(req, pc.conn, pc.br)
		if err == nil {
			s.wrapBody(resp, pc, host)
			return resp, nil
		}
		pc.conn.Close()
	}

	// 3. Dial fresh with spoofed TLS
	ua := req.Header.Get("User-Agent")
	uConn, proto, err := s.dialUTLS(req.Context(), host, port, ua)
	if err != nil {
		return nil, err
	}

	if proto == "h2" {
		h2t := &http2.Transport{}
		h2cc, err := h2t.NewClientConn(uConn)
		if err != nil {
			uConn.Close()
			return nil, fmt.Errorf("h2 client conn: %w", err)
		}
		s.pool.H2Put(host, h2cc)
		resp, err := h2cc.RoundTrip(req)
		if err != nil {
			return nil, fmt.Errorf("h2 roundtrip: %w", err)
		}
		return resp, nil
	}

	// H1.1 over fresh spoofed TLS
	br := bufio.NewReader(uConn)
	resp, err := s.sendH1(req, uConn, br)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("h1 roundtrip: %w", err)
	}

	pc := &h1Conn{
		conn:     uConn,
		br:       br,
		host:     host,
		created:  time.Now(),
		lastUsed: time.Now(),
	}
	s.wrapBody(resp, pc, host)
	return resp, nil
}

func (s *Spoofer) roundTripPlain(req *http.Request, host, port string) (
	*http.Response, error) {

	if pc := s.pool.H1Get(host); pc != nil {
		resp, err := s.sendH1(req, pc.conn, pc.br)
		if err == nil {
			s.wrapBody(resp, pc, host)
			return resp, nil
		}
		pc.conn.Close()
	}

	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, s.dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("tcp dial %s: %w", addr, err)
	}

	br := bufio.NewReader(conn)
	resp, err := s.sendH1(req, conn, br)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("h1 plain roundtrip: %w", err)
	}

	pc := &h1Conn{
		conn: conn, br: br, host: host,
		created: time.Now(), lastUsed: time.Now(),
	}
	s.wrapBody(resp, pc, host)
	return resp, nil
}

func (s *Spoofer) sendH1(req *http.Request, conn net.Conn,
	br *bufio.Reader) (*http.Response, error) {

	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return resp, nil
}

// ─── Body Wrapper ───────────────────────────────────────────────
// [BUGFIX #5] Removed broken connClosed() method entirely
// [BUGFIX #6] forceClose flag for Connection: close responses
// [BUGFIX #7] readError flag tracks non-EOF read failures
//
// Pooling decision on Close():
//   forceClose || readError || !eof  →  close conn (don't pool)
//   otherwise                        →  return conn to pool

type pooledBody struct {
	inner      io.ReadCloser
	pc         *h1Conn
	pool       *Pool
	host       string
	closed     bool
	eof        bool
	readError  bool
	forceClose bool
}

func (b *pooledBody) Read(p []byte) (int, error) {
	n, err := b.inner.Read(p)
	if err == io.EOF {
		b.eof = true
	} else if err != nil {
		b.readError = true
	}
	return n, err
}

func (b *pooledBody) Close() error {
	if b.closed {
		return nil
	}
	b.closed = true
	err := b.inner.Close()

	if !b.forceClose && !b.readError && b.eof {
		b.pool.H1Put(b.pc)
	} else {
		b.pc.conn.Close()
	}
	return err
}

func (s *Spoofer) wrapBody(resp *http.Response, pc *h1Conn, host string) {
	pb := &pooledBody{
		inner: resp.Body,
		pc:    pc,
		pool:  s.pool,
		host:  host,
	}
	// [BUGFIX #6] If server says Connection: close, don't pool
	if resp.Close {
		pb.forceClose = true
	}
	resp.Body = pb
}
