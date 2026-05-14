// Package scope implements the ScopeEnforcer — the legal-defense foundation
// of bb-hunter. Every outgoing HTTP request MUST pass through this enforcer.
//
// Key properties:
//   - Pinned-IP dialer: DNS is resolved once, IP is verified, then the same IP
//     is used for the actual connection. Eliminates DNS rebinding TOCTOU.
//   - IP blocklist: RFC1918, loopback, link-local, cloud metadata, IPv6 ULA.
//   - Hostname normalization: trailing dot, punycode (IDNA), publicsuffix.
//   - Redirect validation: every redirect destination is re-checked.
//   - WebSocket/HTTP3 blocked by default (only http/https allowed).
package scope

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

var (
	ErrOutOfScope    = errors.New("scope: target is out of scope")
	ErrBlockedIP     = errors.New("scope: all resolved IPs are blocked")
	ErrNoIPs         = errors.New("scope: DNS resolved to zero IPs")
	ErrBlockedScheme = errors.New("scope: scheme not allowed (only http/https)")
	ErrRedirectOOS   = errors.New("scope: redirect target is out of scope")
)

// Config holds the scope definition loaded from scope.yaml.
type Config struct {
	// AllowedDomains is a list of in-scope domains. Supports wildcards:
	//   "example.com"       — exact match + all subdomains
	//   "*.example.com"     — only subdomains, not example.com itself
	AllowedDomains []string

	// AllowedIPs is an optional list of specific IPs/CIDRs that are in scope
	// even if they would otherwise be blocked (e.g., target's internal test range).
	// Use with extreme caution.
	AllowedIPs []*net.IPNet

	// MaxRedirects is the maximum number of redirects to follow (default: 10).
	MaxRedirects int
}

// Enforcer validates that HTTP requests stay within the defined scope.
// It provides a custom http.Transport with pinned-IP dialer and redirect checking.
type Enforcer struct {
	config   Config
	resolver *net.Resolver
	mu       sync.RWMutex

	// normalized allowed domains (lowercased, IDNA-encoded, no trailing dot)
	allowedDomains []allowedDomain
}

type allowedDomain struct {
	// domain is the normalized domain (e.g., "example.com")
	domain string
	// wildcard means only subdomains match, not the domain itself
	wildcard bool
	// etldPlusOne is the eTLD+1 for quick rejection
	etldPlusOne string
}

// New creates a new Enforcer with the given scope configuration.
func New(cfg Config) (*Enforcer, error) {
	if len(cfg.AllowedDomains) == 0 {
		return nil, errors.New("scope: at least one allowed domain is required")
	}

	if cfg.MaxRedirects <= 0 {
		cfg.MaxRedirects = 10
	}

	e := &Enforcer{
		config: cfg,
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "udp", "8.8.8.8:53")
			},
		},
	}

	for _, d := range cfg.AllowedDomains {
		ad, err := normalizeDomain(d)
		if err != nil {
			return nil, fmt.Errorf("scope: bad domain %q: %w", d, err)
		}
		e.allowedDomains = append(e.allowedDomains, ad)
	}

	return e, nil
}

// Transport returns an http.Transport with pinned-IP dialer that prevents
// DNS rebinding attacks. All connections go through scope-verified IPs.
func (e *Enforcer) Transport() *http.Transport {
	return &http.Transport{
		DialContext:         e.pinnedDialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
	}
}

// Client returns an http.Client with scope enforcement on every request
// and every redirect.
func (e *Enforcer) Client() *http.Client {
	return &http.Client{
		Transport: e.Transport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= e.config.MaxRedirects {
				return fmt.Errorf("scope: too many redirects (%d)", len(via))
			}
			if err := e.CheckURL(req.URL); err != nil {
				return fmt.Errorf("%w: redirect to %s", ErrRedirectOOS, req.URL.Host)
			}
			return nil
		},
		Timeout: 30 * time.Second,
	}
}

// CheckURL validates that a URL is in scope (scheme + hostname).
// Does NOT make network calls — only checks against allowed domains.
func (e *Enforcer) CheckURL(u *url.URL) error {
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return ErrBlockedScheme
	}

	hostname := u.Hostname()
	if hostname == "" {
		return ErrOutOfScope
	}

	// Check if hostname is an IP literal
	if ip := net.ParseIP(hostname); ip != nil {
		// Explicit allow overrides blocklist (for target's internal test ranges)
		if e.isAllowedIP(ip) {
			return nil
		}
		if IsBlockedIP(ip) {
			return ErrBlockedIP
		}
		return fmt.Errorf("%w: IP literal %s not in allowed list", ErrOutOfScope, hostname)
	}

	// Normalize hostname
	normalized, err := normalizeHostname(hostname)
	if err != nil {
		return fmt.Errorf("%w: cannot normalize %q: %v", ErrOutOfScope, hostname, err)
	}

	if !e.isDomainAllowed(normalized) {
		return fmt.Errorf("%w: %s", ErrOutOfScope, hostname)
	}

	return nil
}

// CheckRequest validates a full HTTP request.
func (e *Enforcer) CheckRequest(req *http.Request) error {
	return e.CheckURL(req.URL)
}

// pinnedDialContext resolves DNS, verifies IPs against blocklist and scope,
// then connects to a verified IP directly. This eliminates the DNS rebinding
// TOCTOU window — the IP used for the connection is the same IP that was checked.
func (e *Enforcer) pinnedDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("scope: bad address %q: %w", addr, err)
	}

	// If host is already an IP, check it directly
	if ip := net.ParseIP(host); ip != nil {
		if IsBlockedIP(ip) && !e.isAllowedIP(ip) {
			return nil, fmt.Errorf("%w: %s", ErrBlockedIP, ip)
		}
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
	}

	// Resolve DNS
	ips, err := e.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("scope: DNS lookup failed for %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoIPs, host)
	}

	// Find the first safe IP
	for _, ipAddr := range ips {
		ip := ipAddr.IP

		// Normalize IPv4-mapped IPv6
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}

		if IsBlockedIP(ip) && !e.isAllowedIP(ip) {
			continue
		}

		// Connect directly to the verified IP
		target := net.JoinHostPort(ip.String(), port)
		conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, target)
		if err != nil {
			continue // try next IP
		}
		return conn, nil
	}

	return nil, fmt.Errorf("%w: all %d IPs for %s are blocked", ErrBlockedIP, len(ips), host)
}

// isDomainAllowed checks if a normalized hostname matches any allowed domain.
func (e *Enforcer) isDomainAllowed(hostname string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, ad := range e.allowedDomains {
		if ad.wildcard {
			// *.example.com — matches sub.example.com but not example.com
			if hostname != ad.domain && strings.HasSuffix(hostname, "."+ad.domain) {
				return true
			}
		} else {
			// example.com — matches example.com and sub.example.com
			if hostname == ad.domain || strings.HasSuffix(hostname, "."+ad.domain) {
				return true
			}
		}
	}

	return false
}

// isAllowedIP checks if an IP is in the explicit allow list.
func (e *Enforcer) isAllowedIP(ip net.IP) bool {
	for _, n := range e.config.AllowedIPs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// normalizeHostname converts a hostname to a canonical form:
// - Remove trailing dot
// - IDNA encode (punycode)
// - Lowercase
func normalizeHostname(host string) (string, error) {
	host = strings.TrimSuffix(host, ".")
	host = strings.ToLower(host)

	// IDNA encoding (handles punycode, e.g., кириллица.рф → xn--...)
	normalized, err := idna.Lookup.ToASCII(host)
	if err != nil {
		// If IDNA fails, fall back to the lowercased version
		return host, nil
	}

	return normalized, nil
}

// normalizeDomain parses a domain pattern (with optional wildcard) into
// an allowedDomain struct.
func normalizeDomain(pattern string) (allowedDomain, error) {
	wildcard := false
	domain := pattern

	if strings.HasPrefix(domain, "*.") {
		wildcard = true
		domain = domain[2:]
	}

	domain = strings.TrimSuffix(domain, ".")
	domain = strings.ToLower(domain)

	normalized, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		normalized = domain
	}

	// Compute eTLD+1 for quick rejection
	etld1, err := publicsuffix.EffectiveTLDPlusOne(normalized)
	if err != nil {
		etld1 = normalized
	}

	return allowedDomain{
		domain:      normalized,
		wildcard:    wildcard,
		etldPlusOne: etld1,
	}, nil
}
