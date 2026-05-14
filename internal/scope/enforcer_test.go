package scope

import (
	"net"
	"net/url"
	"testing"
)

func TestIsBlockedIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		blocked bool
	}{
		// IPv4 blocked
		{"loopback", "127.0.0.1", true},
		{"loopback-alt", "127.0.0.2", true},
		{"rfc1918-10", "10.0.0.1", true},
		{"rfc1918-172", "172.16.0.1", true},
		{"rfc1918-192", "192.168.1.1", true},
		{"link-local", "169.254.1.1", true},
		{"aws-metadata", "169.254.169.254", true},
		{"alibaba-metadata", "100.100.100.200", true},
		{"cgn", "100.64.0.1", true},
		{"multicast", "224.0.0.1", true},

		// IPv4 allowed
		{"public-1", "8.8.8.8", false},
		{"public-2", "1.1.1.1", false},
		{"public-3", "93.184.216.34", false},

		// IPv6 blocked
		{"ipv6-loopback", "::1", true},
		{"ipv6-ula", "fd00::1", true},
		{"ipv6-link-local", "fe80::1", true},
		{"ipv6-mapped-loopback", "::ffff:127.0.0.1", true},
		{"ipv6-mapped-rfc1918", "::ffff:10.0.0.1", true},
		{"ipv6-mapped-metadata", "::ffff:169.254.169.254", true},
		{"aws-ipv6-metadata", "fd00:ec2::254", true},

		// IPv6 allowed
		{"ipv6-public", "2607:f8b0:4004:800::200e", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("cannot parse IP %q", tt.ip)
			}
			got := IsBlockedIP(ip)
			if got != tt.blocked {
				t.Errorf("IsBlockedIP(%s) = %v, want %v", tt.ip, got, tt.blocked)
			}
		})
	}
}

func TestNormalizeHostname(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"Example.COM", "example.com"},
		{"example.com.", "example.com"},
		{"EXAMPLE.COM.", "example.com"},
		{"sub.example.com.", "sub.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := normalizeHostname(tt.input)
			if err != nil {
				t.Fatalf("normalizeHostname(%q) error: %v", tt.input, err)
			}
			if got != tt.expected {
				t.Errorf("normalizeHostname(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestCheckURL(t *testing.T) {
	e, err := New(Config{
		AllowedDomains: []string{"example.com", "*.target.ru"},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		rawURL  string
		wantErr bool
	}{
		// In scope
		{"exact-match", "https://example.com/path", false},
		{"subdomain", "https://sub.example.com/path", false},
		{"deep-subdomain", "https://a.b.c.example.com/", false},
		{"wildcard-subdomain", "https://app.target.ru/admin", false},
		{"wildcard-deep", "https://dev.app.target.ru/", false},
		{"http-ok", "http://example.com/", false},

		// Out of scope
		{"different-domain", "https://evil.com/", true},
		{"suffix-attack", "https://example.com.evil.com/", true},
		{"prefix-attack", "https://notexample.com/", true},
		{"wildcard-base", "https://target.ru/", true}, // *.target.ru excludes target.ru itself

		// Blocked schemes
		{"ftp", "ftp://example.com/", true},
		{"ws", "ws://example.com/", true},
		{"wss", "wss://example.com/", true},

		// IP literals (blocked)
		{"localhost-ip", "http://127.0.0.1/", true},
		{"rfc1918-ip", "http://10.0.0.1/", true},
		{"metadata-ip", "http://169.254.169.254/latest/meta-data/", true},
		{"ipv6-loopback", "http://[::1]/", true},

		// Trailing dot normalization
		{"trailing-dot", "https://example.com./path", false},

		// Case insensitive host
		{"uppercase-host", "https://EXAMPLE.COM/path", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("cannot parse URL %q: %v", tt.rawURL, err)
			}
			err = e.CheckURL(u)
			if tt.wantErr && err == nil {
				t.Errorf("CheckURL(%q) = nil, want error", tt.rawURL)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("CheckURL(%q) = %v, want nil", tt.rawURL, err)
			}
		})
	}
}

func TestCheckURL_AllowedIP(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("10.20.30.0/24")
	e, err := New(Config{
		AllowedDomains: []string{"example.com"},
		AllowedIPs:     []*net.IPNet{ipNet},
	})
	if err != nil {
		t.Fatal(err)
	}

	// This IP is in RFC1918 but explicitly allowed
	u, _ := url.Parse("http://10.20.30.5/api")
	if err := e.CheckURL(u); err != nil {
		t.Errorf("allowed IP 10.20.30.5 should pass: %v", err)
	}

	// This IP is in RFC1918 but NOT allowed
	u, _ = url.Parse("http://10.99.99.99/api")
	if err := e.CheckURL(u); err == nil {
		t.Error("non-allowed private IP 10.99.99.99 should fail")
	}
}

func TestDomainMatching_PublicSuffixSafety(t *testing.T) {
	e, err := New(Config{
		AllowedDomains: []string{"example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Attacker-controlled domain that ends with "example.com" in the string
	// but is NOT a subdomain of example.com
	attacks := []string{
		"https://example.com.attacker.com/",
		"https://fakeexample.com/",
		"https://evil-example.com/",
	}

	for _, rawURL := range attacks {
		u, _ := url.Parse(rawURL)
		if err := e.CheckURL(u); err == nil {
			t.Errorf("suffix attack %q should be blocked", rawURL)
		}
	}
}
