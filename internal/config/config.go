// Package config handles loading and validating bb-hunter configuration.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/ggwpgoend/bb-hunter/internal/scope"
	"gopkg.in/yaml.v3"
)

// ScopeFile represents the scope.yaml configuration file.
type ScopeFile struct {
	// Program is the bug bounty program name (for audit trail).
	Program string `yaml:"program"`

	// Platform is the BB platform (standoff, bizone, bugbountyru).
	Platform string `yaml:"platform"`

	// Domains is the list of in-scope domain patterns.
	// Supports "example.com" (exact + subdomains) and "*.example.com" (subdomains only).
	Domains []string `yaml:"domains"`

	// AllowedIPs is an optional list of specific IPs/CIDRs that are in scope.
	AllowedIPs []string `yaml:"allowed_ips,omitempty"`

	// ExcludedPaths is a list of URL path patterns to skip (regex).
	ExcludedPaths []string `yaml:"excluded_paths,omitempty"`

	// MaxRedirects is the maximum number of redirects to follow.
	MaxRedirects int `yaml:"max_redirects,omitempty"`

	// RateLimit is the per-host rate limit in requests per second.
	RateLimit float64 `yaml:"rate_limit,omitempty"`

	// NucleiSeverity is the minimum nuclei template severity to use.
	// One of: info, low, medium, high, critical.
	NucleiSeverity string `yaml:"nuclei_severity,omitempty"`
}

// LoadScopeFile reads and validates a scope.yaml file.
func LoadScopeFile(path string) (*ScopeFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: cannot read scope file %q: %w", path, err)
	}

	var sf ScopeFile
	if err := yaml.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("config: cannot parse scope file %q: %w", path, err)
	}

	if err := sf.Validate(); err != nil {
		return nil, fmt.Errorf("config: scope file %q invalid: %w", path, err)
	}

	return &sf, nil
}

// Validate checks the scope file for logical errors.
func (sf *ScopeFile) Validate() error {
	if sf.Program == "" {
		return errors.New("program name is required")
	}

	if len(sf.Domains) == 0 {
		return errors.New("at least one domain is required")
	}

	validPlatforms := map[string]bool{
		"standoff":   true,
		"bizone":     true,
		"bugbountyru": true,
	}
	if sf.Platform != "" && !validPlatforms[sf.Platform] {
		return fmt.Errorf("unknown platform %q (expected: standoff, bizone, bugbountyru)", sf.Platform)
	}

	for _, cidr := range sf.AllowedIPs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			if ip := net.ParseIP(cidr); ip == nil {
				return fmt.Errorf("invalid IP/CIDR in allowed_ips: %q", cidr)
			}
		}
	}

	validSeverities := map[string]bool{
		"":         true,
		"info":     true,
		"low":      true,
		"medium":   true,
		"high":     true,
		"critical": true,
	}
	if !validSeverities[sf.NucleiSeverity] {
		return fmt.Errorf("invalid nuclei_severity %q", sf.NucleiSeverity)
	}

	return nil
}

// ToScopeConfig converts the scope file into an enforcer Config.
func (sf *ScopeFile) ToScopeConfig() (scope.Config, error) {
	cfg := scope.Config{
		AllowedDomains: sf.Domains,
		MaxRedirects:   sf.MaxRedirects,
	}

	for _, cidr := range sf.AllowedIPs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try as a single IP
			ip := net.ParseIP(cidr)
			if ip == nil {
				return cfg, fmt.Errorf("invalid IP %q", cidr)
			}
			mask := net.CIDRMask(32, 32)
			if ip.To4() == nil {
				mask = net.CIDRMask(128, 128)
			}
			ipNet = &net.IPNet{IP: ip, Mask: mask}
		}
		cfg.AllowedIPs = append(cfg.AllowedIPs, ipNet)
	}

	return cfg, nil
}
