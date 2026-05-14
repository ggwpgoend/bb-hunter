// Package proxy implements a scope-enforcing HTTP/CONNECT proxy.
// All subprocess tools (nuclei, katana, gau, naabu) are configured to
// route traffic through this proxy, ensuring they cannot reach out-of-scope
// targets even though they don't use the Go http.RoundTripper.
//
// Usage:
//
//	nuclei --proxy http://127.0.0.1:18080
//	katana --proxy http://127.0.0.1:18080
//	gau --proxy http://127.0.0.1:18080
package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/scope"
)

// EgressProxy is an HTTP proxy that enforces scope on all connections.
// It supports both regular HTTP proxying and CONNECT tunneling (for HTTPS).
type EgressProxy struct {
	enforcer *scope.Enforcer
	addr     string
	server   *http.Server
	logger   *slog.Logger
}

// NewEgressProxy creates a new scope-enforcing proxy.
func NewEgressProxy(enforcer *scope.Enforcer, addr string, logger *slog.Logger) *EgressProxy {
	if logger == nil {
		logger = slog.Default()
	}
	p := &EgressProxy{
		enforcer: enforcer,
		addr:     addr,
		logger:   logger,
	}
	p.server = &http.Server{
		Addr:         addr,
		Handler:      p,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}
	return p
}

// ListenAndServe starts the proxy. Blocks until the server is shut down.
func (p *EgressProxy) ListenAndServe() error {
	p.logger.Info("egress proxy starting", "addr", p.addr)
	return p.server.ListenAndServe()
}

// Shutdown gracefully stops the proxy.
func (p *EgressProxy) Shutdown(ctx context.Context) error {
	return p.server.Shutdown(ctx)
}

// ServeHTTP handles both regular HTTP proxy requests and CONNECT tunnels.
func (p *EgressProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

// handleConnect handles HTTPS CONNECT tunneling.
func (p *EgressProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
		port = "443"
	}

	// Validate scope
	targetURL := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(host, port),
	}
	if err := p.enforcer.CheckURL(targetURL); err != nil {
		p.logger.Warn("CONNECT blocked",
			"host", r.Host,
			"reason", err.Error(),
		)
		http.Error(w, "scope: blocked", http.StatusForbidden)
		return
	}

	// Dial the target through the enforcer's pinned-IP dialer
	transport := p.enforcer.Transport()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	targetConn, err := transport.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		p.logger.Warn("CONNECT dial failed",
			"host", r.Host,
			"error", err.Error(),
		)
		http.Error(w, "scope: dial failed", http.StatusBadGateway)
		return
	}

	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		targetConn.Close()
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		targetConn.Close()
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}

	// Send 200 OK to the client
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	p.logger.Debug("CONNECT tunnel established", "host", r.Host)

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(targetConn, clientConn)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(clientConn, targetConn)
		if tc, ok := clientConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	wg.Wait()

	clientConn.Close()
	targetConn.Close()
}

// handleHTTP handles regular HTTP proxy requests (non-CONNECT).
func (p *EgressProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Host == "" {
		http.Error(w, "not a proxy request", http.StatusBadRequest)
		return
	}

	// Validate scope
	if err := p.enforcer.CheckURL(r.URL); err != nil {
		p.logger.Warn("HTTP blocked",
			"url", r.URL.String(),
			"reason", err.Error(),
		)
		http.Error(w, "scope: blocked", http.StatusForbidden)
		return
	}

	// Use the enforcer's transport (with pinned-IP dialer)
	transport := p.enforcer.Transport()

	// Create the outgoing request
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""

	// Remove hop-by-hop headers
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Proxy-Authenticate")
	outReq.Header.Del("Proxy-Authorization")

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		p.logger.Warn("HTTP roundtrip failed",
			"url", r.URL.String(),
			"error", err.Error(),
		)
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
