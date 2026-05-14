package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadScopeFile_Valid(t *testing.T) {
	content := `
program: "Test Bug Bounty"
platform: "standoff"
domains:
  - "example.com"
  - "*.target.ru"
allowed_ips:
  - "10.20.30.0/24"
max_redirects: 5
rate_limit: 10.0
nuclei_severity: "medium"
`

	dir := t.TempDir()
	path := filepath.Join(dir, "scope.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	sf, err := LoadScopeFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if sf.Program != "Test Bug Bounty" {
		t.Errorf("program = %q, want %q", sf.Program, "Test Bug Bounty")
	}
	if len(sf.Domains) != 2 {
		t.Errorf("domains count = %d, want 2", len(sf.Domains))
	}
	if sf.MaxRedirects != 5 {
		t.Errorf("max_redirects = %d, want 5", sf.MaxRedirects)
	}
}

func TestLoadScopeFile_NoDomains(t *testing.T) {
	content := `
program: "Test"
platform: "standoff"
domains: []
`

	dir := t.TempDir()
	path := filepath.Join(dir, "scope.yaml")
	os.WriteFile(path, []byte(content), 0o644)

	_, err := LoadScopeFile(path)
	if err == nil {
		t.Error("expected error for empty domains")
	}
}

func TestLoadScopeFile_NoProgram(t *testing.T) {
	content := `
domains:
  - "example.com"
`

	dir := t.TempDir()
	path := filepath.Join(dir, "scope.yaml")
	os.WriteFile(path, []byte(content), 0o644)

	_, err := LoadScopeFile(path)
	if err == nil {
		t.Error("expected error for missing program name")
	}
}

func TestLoadScopeFile_BadPlatform(t *testing.T) {
	content := `
program: "Test"
platform: "hackerone"
domains:
  - "example.com"
`

	dir := t.TempDir()
	path := filepath.Join(dir, "scope.yaml")
	os.WriteFile(path, []byte(content), 0o644)

	_, err := LoadScopeFile(path)
	if err == nil {
		t.Error("expected error for unknown platform")
	}
}

func TestToScopeConfig(t *testing.T) {
	sf := &ScopeFile{
		Program:    "Test",
		Domains:    []string{"example.com"},
		AllowedIPs: []string{"10.20.30.0/24"},
	}

	cfg, err := sf.ToScopeConfig()
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.AllowedDomains) != 1 {
		t.Errorf("AllowedDomains count = %d, want 1", len(cfg.AllowedDomains))
	}
	if len(cfg.AllowedIPs) != 1 {
		t.Errorf("AllowedIPs count = %d, want 1", len(cfg.AllowedIPs))
	}
}
