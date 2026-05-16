package scanner

import (
	"testing"
)

func TestDefaultHints(t *testing.T) {
	tests := []struct {
		vulnClass string
		url       string
		wantNil   bool
		wantSub   string // expected substring in prompt
	}{
		{"xss", "https://example.com/search?q=test", false, "XSS"},
		{"sqli", "https://example.com/api?id=1", false, "SQL injection"},
		{"ssrf", "https://example.com/fetch?url=x", false, "SSRF"},
		{"idor", "https://example.com/api/user/123", false, "object references"},
		{"auth_bypass", "https://example.com/admin", false, "authentication bypass"},
		{"info_disclosure", "https://example.com/debug", false, "information disclosure"},
		{"rce", "https://example.com/exec?cmd=ls", false, "command injection"},
		{"lfi", "https://example.com/read?file=x", false, "file inclusion"},
		{"open_redirect", "https://example.com/login?next=x", false, "open redirect"},
		{"csrf", "https://example.com/api/transfer", false, "CSRF"},
		{"misconfig", "https://example.com/", false, "misconfigurations"},
		{"unknown_class", "https://example.com/", true, ""},
	}

	for _, tt := range tests {
		hint := DefaultHints(tt.vulnClass, tt.url)
		if tt.wantNil {
			if hint != nil {
				t.Errorf("DefaultHints(%q) = %v, want nil", tt.vulnClass, hint)
			}
			continue
		}
		if hint == nil {
			t.Errorf("DefaultHints(%q) = nil, want non-nil", tt.vulnClass)
			continue
		}
		if hint.VulnClass != tt.vulnClass {
			t.Errorf("hint.VulnClass = %q, want %q", hint.VulnClass, tt.vulnClass)
		}
		if len(hint.URLs) != 1 || hint.URLs[0] != tt.url {
			t.Errorf("hint.URLs = %v, want [%s]", hint.URLs, tt.url)
		}
		if tt.wantSub != "" && !contains(hint.Prompt, tt.wantSub) {
			t.Errorf("hint.Prompt = %q, want substring %q", hint.Prompt, tt.wantSub)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && containsStr(s, sub)
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestGeneratePrompts(t *testing.T) {
	hints := []AnalystHint{
		{VulnClass: "xss", Prompt: "check for XSS", URLs: []string{"https://a.com"}},
		{VulnClass: "sqli", Prompt: "", URLs: []string{"https://b.com"}},       // empty prompt
		{VulnClass: "ssrf", Prompt: "check SSRF", URLs: nil},                    // no URLs
		{VulnClass: "idor", Prompt: "check IDOR", URLs: []string{"https://c.com"}},
	}

	prompts := GeneratePrompts(hints)

	if len(prompts) != 2 {
		t.Errorf("expected 2 prompts (skip empty prompt and no URLs), got %d", len(prompts))
	}

	if prompts[0].Description != "check for XSS" {
		t.Errorf("first prompt = %q, want 'check for XSS'", prompts[0].Description)
	}
	if prompts[1].Description != "check IDOR" {
		t.Errorf("second prompt = %q, want 'check IDOR'", prompts[1].Description)
	}
}

func TestNewNucleiAIRunner_Defaults(t *testing.T) {
	r := NewNucleiAIRunner(NucleiAIConfig{})
	if r.cfg.NucleiPath != "nuclei" {
		t.Errorf("default nuclei path = %q, want 'nuclei'", r.cfg.NucleiPath)
	}
	if r.cfg.RateLimit != 5 {
		t.Errorf("default rate limit = %f, want 5", r.cfg.RateLimit)
	}
}
