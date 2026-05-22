package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestAgent builds a bare Agent with the supplied Config. It bypasses
// New() because we don't need the LLM client / executor wired for direct
// processFinding tests.
func newTestAgent(cfg Config) *Agent {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Agent{cfg: cfg, log: cfg.Logger}
}

func TestProcessFinding_FullPipeline(t *testing.T) {
	dir := t.TempDir()

	gateCalled := false
	pocCalled := false
	runCalled := false
	reportCalled := false

	a := newTestAgent(Config{
		FindingsDir: dir,
		GateFinding: func(ctx context.Context, f Finding) (GateDecision, error) {
			gateCalled = true
			if f.ID == "" {
				t.Errorf("expected finding ID assigned before gate, got empty")
			}
			return GateDecision{Verdict: "PASS", Score: 7, Reason: "good"}, nil
		},
		GeneratePoC: func(ctx context.Context, f Finding) (PoC, error) {
			pocCalled = true
			return PoC{
				Script:      "import json;print(json.dumps({\"vulnerable\":True,\"evidence\":\"hit\"}))",
				Interpreter: "python3",
				Description: "test poc",
			}, nil
		},
		RunPoC: func(ctx context.Context, f Finding, p PoC) (PoCResult, error) {
			runCalled = true
			if p.Script == "" {
				t.Error("PoC script empty in RunPoC")
			}
			return PoCResult{
				Verified: true,
				Evidence: "canary observed",
				ExitCode: 0,
				Stdout:   `{"vulnerable":true,"evidence":"canary"}`,
			}, nil
		},
		GenerateReport: func(ctx context.Context, f Finding) (string, error) {
			reportCalled = true
			if !f.SandboxVerified {
				t.Error("expected SandboxVerified=true in finding passed to reporter")
			}
			return "# Тест отчёт\n\n## Описание\nуязвимость", nil
		},
	})

	f := Finding{
		VulnClass:   "xxe",
		Severity:    "high",
		URL:         "https://example.test/api",
		Description: "XML entity expansion",
		Evidence:    "&xxe; expanded",
		Confidence:  0.6,
		ProofLevel:  "behavioral",
	}

	mutated, accepted, status := a.processFinding(context.Background(), f)
	if !accepted {
		t.Fatalf("expected accepted=true, status=%q", status)
	}
	if !gateCalled || !pocCalled || !runCalled || !reportCalled {
		t.Errorf("missing callback: gate=%v poc=%v run=%v report=%v", gateCalled, pocCalled, runCalled, reportCalled)
	}
	if mutated.GateVerdict != "PASS" {
		t.Errorf("GateVerdict = %q, want PASS", mutated.GateVerdict)
	}
	if mutated.GateScore != 7 {
		t.Errorf("GateScore = %d, want 7", mutated.GateScore)
	}
	if !mutated.SandboxVerified {
		t.Errorf("SandboxVerified = false, want true")
	}
	if mutated.ProofLevel != "direct" {
		t.Errorf("ProofLevel = %q, want direct after sandbox verification", mutated.ProofLevel)
	}
	if mutated.Confidence < 0.85 {
		t.Errorf("Confidence = %f, want >= 0.85 after sandbox verification", mutated.Confidence)
	}
	if !strings.Contains(mutated.ReportMarkdown, "Тест отчёт") {
		t.Errorf("ReportMarkdown does not contain expected content: %q", mutated.ReportMarkdown)
	}

	// Verify on-disk persistence
	if mutated.FindingDir == "" {
		t.Fatal("FindingDir not set")
	}
	for _, name := range []string{"finding.json", "report.ru.md", "poc.py", "sandbox.json"} {
		p := filepath.Join(mutated.FindingDir, name)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected %s on disk, got %v", p, err)
		}
	}

	// Verify finding.json round-trips
	data, err := os.ReadFile(filepath.Join(mutated.FindingDir, "finding.json"))
	if err != nil {
		t.Fatalf("read finding.json: %v", err)
	}
	var loaded Finding
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal finding.json: %v", err)
	}
	if loaded.ID != mutated.ID {
		t.Errorf("finding.json ID = %q, want %q", loaded.ID, mutated.ID)
	}
	if !loaded.SandboxVerified {
		t.Errorf("finding.json SandboxVerified = false, want true")
	}
}

func TestProcessFinding_GateKills(t *testing.T) {
	dir := t.TempDir()
	a := newTestAgent(Config{
		FindingsDir: dir,
		GateFinding: func(ctx context.Context, f Finding) (GateDecision, error) {
			return GateDecision{Verdict: "KILL", Score: 1, Reason: "no impact"}, nil
		},
		GeneratePoC: func(ctx context.Context, f Finding) (PoC, error) {
			t.Error("PoC must not be generated after KILL verdict")
			return PoC{}, nil
		},
		GenerateReport: func(ctx context.Context, f Finding) (string, error) {
			t.Error("Reporter must not run after KILL verdict")
			return "", nil
		},
	})

	_, accepted, status := a.processFinding(context.Background(), Finding{
		VulnClass: "info_disclosure",
		Severity:  "low",
		URL:       "https://x.test",
	})
	if accepted {
		t.Errorf("expected rejected, got accepted (status=%q)", status)
	}
	if !strings.Contains(status, "gate killed") {
		t.Errorf("status = %q, want gate killed", status)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("expected no persisted directory after KILL, got %d entries", len(entries))
	}
}

func TestProcessFinding_GateDowngrades(t *testing.T) {
	a := newTestAgent(Config{
		GateFinding: func(ctx context.Context, f Finding) (GateDecision, error) {
			return GateDecision{Verdict: "DOWNGRADE", Score: 4, Reason: "thin evidence"}, nil
		},
	})

	mutated, accepted, _ := a.processFinding(context.Background(), Finding{
		VulnClass: "xss",
		Severity:  "high",
		URL:       "https://x.test",
	})
	if !accepted {
		t.Fatal("DOWNGRADE must still accept the finding")
	}
	if mutated.Severity != "medium" {
		t.Errorf("severity after DOWNGRADE from high = %q, want medium", mutated.Severity)
	}
	if mutated.GateVerdict != "DOWNGRADE" {
		t.Errorf("GateVerdict = %q, want DOWNGRADE", mutated.GateVerdict)
	}
}

func TestProcessFinding_BrowserVerifierRejectsXSS(t *testing.T) {
	a := newTestAgent(Config{
		VerifyFinding: func(ctx context.Context, f Finding) (VerificationResult, error) {
			return VerificationResult{Verified: false, Reason: "no script execution"}, nil
		},
		GateFinding: func(ctx context.Context, f Finding) (GateDecision, error) {
			t.Error("Gate must not run after verifier reject")
			return GateDecision{}, nil
		},
	})

	_, accepted, status := a.processFinding(context.Background(), Finding{
		VulnClass: "xss",
		Severity:  "medium",
		URL:       "https://x.test/?q=<script>alert(1)</script>",
		Evidence:  "<script>alert(1)</script>",
	})
	if accepted {
		t.Errorf("expected rejected, status=%q", status)
	}
	if !strings.Contains(status, "browser verification rejected") {
		t.Errorf("status = %q, want browser verification rejected", status)
	}
}

func TestProcessFinding_PoCFails_DegradesGracefully(t *testing.T) {
	a := newTestAgent(Config{
		GateFinding: func(ctx context.Context, f Finding) (GateDecision, error) {
			return GateDecision{Verdict: "PASS", Score: 6}, nil
		},
		GeneratePoC: func(ctx context.Context, f Finding) (PoC, error) {
			return PoC{}, errors.New("LLM rate-limited")
		},
		GenerateReport: func(ctx context.Context, f Finding) (string, error) {
			return "report ok", nil
		},
	})

	mutated, accepted, status := a.processFinding(context.Background(), Finding{
		VulnClass: "sqli",
		Severity:  "high",
		URL:       "https://x.test/q?id=1",
	})
	if !accepted {
		t.Fatalf("finding must remain accepted on PoC failure (status=%q)", status)
	}
	if mutated.ReportMarkdown != "report ok" {
		t.Errorf("Reporter should still run after PoC failure; got %q", mutated.ReportMarkdown)
	}
	if !strings.Contains(status, "PoC generation failed") {
		t.Errorf("status = %q, want PoC generation failed", status)
	}
}

func TestProcessFinding_SandboxUnverified_DowngradesProof(t *testing.T) {
	a := newTestAgent(Config{
		GateFinding: func(ctx context.Context, f Finding) (GateDecision, error) {
			return GateDecision{Verdict: "PASS", Score: 6}, nil
		},
		GeneratePoC: func(ctx context.Context, f Finding) (PoC, error) {
			return PoC{Script: "echo {}", Interpreter: "bash"}, nil
		},
		RunPoC: func(ctx context.Context, f Finding, p PoC) (PoCResult, error) {
			return PoCResult{Verified: false, Stdout: "{}", ExitCode: 0}, nil
		},
	})

	mutated, accepted, _ := a.processFinding(context.Background(), Finding{
		VulnClass:  "lfi",
		Severity:   "high",
		URL:        "https://x.test/?f=/etc/passwd",
		Confidence: 0.95,
		ProofLevel: "direct",
	})
	if !accepted {
		t.Fatal("unverified sandbox must not drop the finding")
	}
	if mutated.ProofLevel != "behavioral" {
		t.Errorf("ProofLevel after unverified sandbox = %q, want behavioral", mutated.ProofLevel)
	}
	if mutated.Confidence > 0.7 {
		t.Errorf("Confidence after unverified sandbox = %f, want <= 0.7", mutated.Confidence)
	}
}

func TestAssessEvidence(t *testing.T) {
	cases := []struct {
		class, evidence string
		want            bool
	}{
		{"lfi", "root:x:0:0:root:/root:/bin/bash", true},
		{"lfi", "404 not found", false},
		{"sqli", "You have an error in your SQL syntax near", true},
		{"sqli", "200 OK", false},
		{"info_disclosure", "AKIAIOSFODNN7EXAMPLE", true},
		{"info_disclosure", "nothing", false},
		{"xss", "alert(1)", false}, // xss not in passive table; needs browser verifier
	}
	for _, c := range cases {
		got := AssessEvidence(c.class, c.evidence, "")
		if got != c.want {
			t.Errorf("AssessEvidence(%q, %q) = %v, want %v", c.class, c.evidence, got, c.want)
		}
	}
}

func TestDowngradeSeverity(t *testing.T) {
	cases := map[string]string{
		"critical": "high",
		"high":     "medium",
		"medium":   "low",
		"low":      "info",
		"info":     "info",
		"":         "low",
		"unknown":  "low",
	}
	for in, want := range cases {
		if got := downgradeSeverity(in); got != want {
			t.Errorf("downgradeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPocExtension(t *testing.T) {
	cases := map[string]string{
		"python3":    "py",
		"python":     "py",
		"bash":       "sh",
		"sh":         "sh",
		"curl":       "sh",
		"node":       "js",
		"javascript": "js",
		"":           "txt",
		"weird":      "txt",
	}
	for in, want := range cases {
		if got := pocExtension(in); got != want {
			t.Errorf("pocExtension(%q) = %q, want %q", in, got, want)
		}
	}
}
