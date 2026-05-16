package browser

import (
	"context"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.AgentBrowserBin != "agent-browser" {
		t.Errorf("AgentBrowserBin = %q, want 'agent-browser'", cfg.AgentBrowserBin)
	}
	if cfg.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", cfg.Timeout)
	}
	if !cfg.Headless {
		t.Error("Headless should be true by default")
	}
	if cfg.ScreenshotDir != "/tmp/bb-hunter-screenshots" {
		t.Errorf("ScreenshotDir = %q", cfg.ScreenshotDir)
	}
}

func TestNewEngine_Defaults(t *testing.T) {
	e := NewEngine(Config{})
	if e.cfg.AgentBrowserBin != "agent-browser" {
		t.Errorf("AgentBrowserBin = %q", e.cfg.AgentBrowserBin)
	}
	if e.cfg.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v", e.cfg.Timeout)
	}
	if e.cfg.ScreenshotDir == "" {
		t.Error("ScreenshotDir should not be empty")
	}
}

func TestScreenshotPath(t *testing.T) {
	e := NewEngine(Config{ScreenshotDir: "/tmp/test-screenshots"})
	path := e.screenshotPath("finding-123", "before")
	if path == "" {
		t.Fatal("path should not be empty")
	}
	if !contains(path, "finding-123") {
		t.Errorf("path should contain finding ID: %s", path)
	}
	if !contains(path, "before") {
		t.Errorf("path should contain suffix: %s", path)
	}
	if !contains(path, ".png") {
		t.Errorf("path should end with .png: %s", path)
	}
}

func TestScreenshotPath_SlashInID(t *testing.T) {
	e := NewEngine(Config{ScreenshotDir: "/tmp/test"})
	path := e.screenshotPath("finding/with/slashes", "test")
	if contains(path, "finding/with/slashes") {
		t.Errorf("slashes should be replaced: %s", path)
	}
}

func TestBatchEvidence_Empty(t *testing.T) {
	e := NewEngine(Config{})
	results := e.BatchEvidence(context.Background(), nil)
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestBatchEvidence_AgentBrowserNotAvailable(t *testing.T) {
	e := NewEngine(Config{AgentBrowserBin: "/nonexistent/agent-browser"})
	input := []FindingInput{
		{FindingID: "f1", VulnClass: "xss", URL: "https://example.com/search?q=test"},
	}
	ctx := context.Background()
	results := e.BatchEvidence(ctx, input)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Error == "" {
		t.Error("expected error when agent-browser not available")
	}
	if results[0].FindingID != "f1" {
		t.Errorf("FindingID = %q", results[0].FindingID)
	}
}

func TestEvidence_JSONFields(t *testing.T) {
	ev := Evidence{
		FindingID:   "f1",
		VulnClass:   "xss",
		URL:         "https://example.com",
		Verified:    true,
		Description: "XSS found",
		Screenshots: []string{"/tmp/s1.png"},
		Duration:    5 * time.Second,
		Steps: []Step{
			{Order: 1, Action: "open", Description: "Navigate", Success: true},
		},
	}

	if ev.FindingID != "f1" {
		t.Errorf("FindingID = %q", ev.FindingID)
	}
	if !ev.Verified {
		t.Error("expected Verified = true")
	}
	if len(ev.Steps) != 1 {
		t.Errorf("expected 1 step, got %d", len(ev.Steps))
	}
	if ev.Steps[0].Order != 1 {
		t.Errorf("step order = %d, want 1", ev.Steps[0].Order)
	}
}

func TestFindingInput_Fields(t *testing.T) {
	f := FindingInput{
		FindingID: "f1",
		VulnClass: "csrf",
		URL:       "https://example.com/transfer",
		Params:    []string{"amount", "to"},
	}
	if f.FindingID != "f1" {
		t.Errorf("FindingID = %q", f.FindingID)
	}
	if len(f.Params) != 2 {
		t.Errorf("expected 2 params, got %d", len(f.Params))
	}
}

func TestAvailable_NotInstalled(t *testing.T) {
	e := NewEngine(Config{AgentBrowserBin: "/nonexistent/agent-browser"})
	if e.Available() {
		t.Error("Available() should return false when agent-browser not installed")
	}
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
