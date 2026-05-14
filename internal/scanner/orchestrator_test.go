package scanner

import (
	"testing"

	"github.com/ggwpgoend/bb-hunter/internal/models"
)

func TestMapSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  models.Severity
	}{
		{"info", models.SeverityInfo},
		{"low", models.SeverityLow},
		{"medium", models.SeverityMedium},
		{"high", models.SeverityHigh},
		{"critical", models.SeverityCritical},
		{"INFO", models.SeverityInfo},
		{"High", models.SeverityHigh},
		{"unknown", models.SeverityInfo},
		{"", models.SeverityInfo},
	}

	for _, tc := range tests {
		got := mapSeverity(tc.input)
		if got != tc.want {
			t.Errorf("mapSeverity(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestGenerateID(t *testing.T) {
	id1 := generateID("f")
	id2 := generateID("f")

	if id1 == id2 {
		t.Error("generated IDs should be unique")
	}
	if len(id1) < 5 {
		t.Errorf("ID too short: %q", id1)
	}
	if id1[:2] != "f-" {
		t.Errorf("ID should start with prefix: %q", id1)
	}
}

func TestNucleiToFindings(t *testing.T) {
	o := &Orchestrator{programID: "test-program"}

	results := []NucleiResult{
		{
			TemplateID: "xss-reflected",
			Name:       "Reflected XSS",
			Severity:   "high",
			URL:        "https://example.com/search?q=test&lang=en",
			Matched:    "body",
			Evidence:   "reflected input in body",
		},
		{
			TemplateID: "sqli-blind",
			Name:       "Blind SQLi",
			Severity:   "critical",
			URL:        "https://example.com/api/users?id=1",
			Matched:    "time-based",
			Evidence:   "5s delay on payload",
		},
	}

	findings := o.nucleiToFindings(results, "run-001")

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	f1 := findings[0]
	if f1.ProgramID != "test-program" {
		t.Errorf("ProgramID = %q", f1.ProgramID)
	}
	if f1.ScanRunID != "run-001" {
		t.Errorf("ScanRunID = %q", f1.ScanRunID)
	}
	if f1.Severity != models.SeverityHigh {
		t.Errorf("Severity = %q, want high", f1.Severity)
	}
	if f1.Status != models.StatusNew {
		t.Errorf("Status = %q, want new", f1.Status)
	}
	if f1.NucleiTemplateID != "xss-reflected" {
		t.Errorf("TemplateID = %q", f1.NucleiTemplateID)
	}
	if f1.Host != "example.com" {
		t.Errorf("Host = %q", f1.Host)
	}
	if len(f1.ParamNames) != 2 {
		t.Errorf("ParamNames = %v, want 2 params", f1.ParamNames)
	}
	if f1.FindingKey == "" {
		t.Error("FindingKey should not be empty")
	}

	f2 := findings[1]
	if f2.Severity != models.SeverityCritical {
		t.Errorf("f2 Severity = %q, want critical", f2.Severity)
	}

	// Keys should be different
	if f1.FindingKey == f2.FindingKey {
		t.Error("different findings should have different keys")
	}
}

func TestNucleiToFindings_Empty(t *testing.T) {
	o := &Orchestrator{programID: "test"}
	findings := o.nucleiToFindings(nil, "run-001")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil input, got %d", len(findings))
	}
}
