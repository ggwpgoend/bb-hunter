package historian

import (
	"context"
	"testing"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/differ"
	"github.com/ggwpgoend/bb-hunter/internal/llm"
	"github.com/ggwpgoend/bb-hunter/internal/models"
)

func makeFinding(severity models.Severity, vulnClass models.VulnClass, url string) *models.Finding {
	return &models.Finding{
		ID:        "f-test",
		URL:       url,
		Severity:  severity,
		VulnClass: vulnClass,
		Status:    models.StatusNew,
		Confidence: 0.85,
	}
}

func TestAnalyzeWithoutLLMNoChanges(t *testing.T) {
	h := NewHistorian(nil, nil)

	diff := &differ.DiffResult{
		PreviousRunID:  "run1",
		CurrentRunID:   "run2",
		ComputedAt:     time.Now(),
		UnchangedCount: 5,
		Entries: []differ.DiffEntry{
			{ChangeType: differ.ChangeUnchanged},
			{ChangeType: differ.ChangeUnchanged},
			{ChangeType: differ.ChangeUnchanged},
			{ChangeType: differ.ChangeUnchanged},
			{ChangeType: differ.ChangeUnchanged},
		},
	}

	analysis := h.AnalyzeWithoutLLM(diff)

	if analysis.RiskLevel != "low" {
		t.Errorf("expected low risk for no changes, got %s", analysis.RiskLevel)
	}
	if analysis.Summary == "" {
		t.Error("summary should not be empty")
	}
}

func TestAnalyzeWithoutLLMNewCritical(t *testing.T) {
	h := NewHistorian(nil, nil)

	diff := &differ.DiffResult{
		PreviousRunID: "run1",
		CurrentRunID:  "run2",
		NewCount:      1,
		Entries: []differ.DiffEntry{
			{
				ChangeType: differ.ChangeNew,
				Current:    makeFinding(models.SeverityCritical, models.VulnRCE, "https://example.com/rce"),
			},
		},
	}

	analysis := h.AnalyzeWithoutLLM(diff)

	if analysis.RiskLevel != "critical" {
		t.Errorf("expected critical risk for new RCE, got %s", analysis.RiskLevel)
	}
	if len(analysis.Priorities) != 1 {
		t.Errorf("expected 1 priority, got %d", len(analysis.Priorities))
	}
}

func TestAnalyzeWithoutLLMGoneFindings(t *testing.T) {
	h := NewHistorian(nil, nil)

	diff := &differ.DiffResult{
		PreviousRunID: "run1",
		CurrentRunID:  "run2",
		GoneCount:     3,
		Entries: []differ.DiffEntry{
			{ChangeType: differ.ChangeGone, Previous: makeFinding(models.SeverityHigh, models.VulnXSS, "https://example.com/xss")},
			{ChangeType: differ.ChangeGone, Previous: makeFinding(models.SeverityMedium, models.VulnSQLi, "https://example.com/sqli")},
			{ChangeType: differ.ChangeGone, Previous: makeFinding(models.SeverityLow, models.VulnMisconfig, "https://example.com/misc")},
		},
	}

	analysis := h.AnalyzeWithoutLLM(diff)

	if analysis.RiskLevel != "low" {
		t.Errorf("expected low risk when only findings disappeared, got %s", analysis.RiskLevel)
	}

	hasPatchTrend := false
	for _, trend := range analysis.Trends {
		if containsStr(trend, "исчезло") || containsStr(trend, "пропатчены") {
			hasPatchTrend = true
		}
	}
	if !hasPatchTrend {
		t.Error("expected trend about patched vulns")
	}
}

func TestAnalyzeWithoutLLMGrowingAttackSurface(t *testing.T) {
	h := NewHistorian(nil, nil)

	diff := &differ.DiffResult{
		PreviousRunID: "run1",
		CurrentRunID:  "run2",
		NewCount:      5,
		GoneCount:     1,
		Entries: []differ.DiffEntry{
			{ChangeType: differ.ChangeNew, Current: makeFinding(models.SeverityMedium, models.VulnXSS, "https://example.com/1")},
			{ChangeType: differ.ChangeNew, Current: makeFinding(models.SeverityMedium, models.VulnXSS, "https://example.com/2")},
			{ChangeType: differ.ChangeNew, Current: makeFinding(models.SeverityLow, models.VulnMisconfig, "https://example.com/3")},
			{ChangeType: differ.ChangeNew, Current: makeFinding(models.SeverityLow, models.VulnMisconfig, "https://example.com/4")},
			{ChangeType: differ.ChangeNew, Current: makeFinding(models.SeverityInfo, models.VulnInfoDisclosure, "https://example.com/5")},
			{ChangeType: differ.ChangeGone, Previous: makeFinding(models.SeverityLow, models.VulnMisconfig, "https://example.com/old")},
		},
	}

	analysis := h.AnalyzeWithoutLLM(diff)

	hasGrowthTrend := false
	for _, trend := range analysis.Trends {
		if containsStr(trend, "увеличивается") {
			hasGrowthTrend = true
		}
	}
	if !hasGrowthTrend {
		t.Error("expected trend about growing attack surface")
	}
}

func TestAnalyzeWithoutLLMEmpty(t *testing.T) {
	h := NewHistorian(nil, nil)

	diff := &differ.DiffResult{
		PreviousRunID: "run1",
		CurrentRunID:  "run2",
	}

	analysis := h.AnalyzeWithoutLLM(diff)

	if analysis.RiskLevel != "low" {
		t.Errorf("expected low risk for empty diff, got %s", analysis.RiskLevel)
	}
	if !containsStr(analysis.Summary, "нет данных") {
		t.Errorf("expected 'нет данных' in summary, got: %s", analysis.Summary)
	}
}

func TestInferRiskLevel(t *testing.T) {
	tests := []struct {
		name     string
		diff     *differ.DiffResult
		expected string
	}{
		{
			name:     "no new findings",
			diff:     &differ.DiffResult{},
			expected: "low",
		},
		{
			name: "new medium findings",
			diff: &differ.DiffResult{
				NewCount: 2,
				Entries: []differ.DiffEntry{
					{ChangeType: differ.ChangeNew, Current: makeFinding(models.SeverityMedium, models.VulnXSS, "")},
					{ChangeType: differ.ChangeNew, Current: makeFinding(models.SeverityMedium, models.VulnSQLi, "")},
				},
			},
			expected: "low",
		},
		{
			name: "one new high",
			diff: &differ.DiffResult{
				NewCount: 1,
				Entries: []differ.DiffEntry{
					{ChangeType: differ.ChangeNew, Current: makeFinding(models.SeverityHigh, models.VulnXSS, "")},
				},
			},
			expected: "medium",
		},
		{
			name: "three new high",
			diff: &differ.DiffResult{
				NewCount: 3,
				Entries: []differ.DiffEntry{
					{ChangeType: differ.ChangeNew, Current: makeFinding(models.SeverityHigh, models.VulnXSS, "")},
					{ChangeType: differ.ChangeNew, Current: makeFinding(models.SeverityHigh, models.VulnSQLi, "")},
					{ChangeType: differ.ChangeNew, Current: makeFinding(models.SeverityHigh, models.VulnSSRF, "")},
				},
			},
			expected: "high",
		},
		{
			name: "new critical",
			diff: &differ.DiffResult{
				NewCount: 1,
				Entries: []differ.DiffEntry{
					{ChangeType: differ.ChangeNew, Current: makeFinding(models.SeverityCritical, models.VulnRCE, "")},
				},
			},
			expected: "critical",
		},
		{
			name: "many new low",
			diff: &differ.DiffResult{
				NewCount: 15,
				Entries: func() []differ.DiffEntry {
					entries := make([]differ.DiffEntry, 15)
					for i := range entries {
						entries[i] = differ.DiffEntry{
							ChangeType: differ.ChangeNew,
							Current:    makeFinding(models.SeverityLow, models.VulnMisconfig, ""),
						}
					}
					return entries
				}(),
			},
			expected: "medium",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferRiskLevel(tt.diff)
			if got != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, got)
			}
		})
	}
}

func TestBuildDiffPrompt(t *testing.T) {
	diff := &differ.DiffResult{
		PreviousRunID:  "run-prev",
		CurrentRunID:   "run-curr",
		NewCount:       1,
		GoneCount:      1,
		ChangedCount:   1,
		UnchangedCount: 1,
		Entries: []differ.DiffEntry{
			{
				ChangeType: differ.ChangeNew,
				Current:    makeFinding(models.SeverityHigh, models.VulnXSS, "https://example.com/new"),
			},
			{
				ChangeType: differ.ChangeGone,
				Previous:   makeFinding(models.SeverityMedium, models.VulnSQLi, "https://example.com/gone"),
			},
			{
				ChangeType: differ.ChangeChanged,
				FindingKey: "changed-key",
				Previous:   makeFinding(models.SeverityMedium, models.VulnXSS, ""),
				Current:    makeFinding(models.SeverityHigh, models.VulnXSS, ""),
			},
			{
				ChangeType: differ.ChangeUnchanged,
			},
		},
	}

	prompt := buildDiffPrompt(diff)

	checks := []string{
		"run-prev", "run-curr",
		"НОВЫЕ НАХОДКИ",
		"ИСЧЕЗНУВШИЕ",
		"ИЗМЕНЁННЫЕ",
		"example.com/new",
		"example.com/gone",
		"changed-key",
	}

	for _, check := range checks {
		if !containsStr(prompt, check) {
			t.Errorf("prompt should contain %q", check)
		}
	}
}

// TestAnalyzeWithMockLLM tests the LLM-based analysis path.
func TestAnalyzeWithMockLLM(t *testing.T) {
	mockProvider := &mockLLMProvider{
		response: &llm.Response{
			Content:      "Обнаружена новая critical уязвимость RCE. Рекомендуется немедленная проверка.",
			Provider:     "mock",
			Model:        "test",
			InputTokens:  100,
			OutputTokens: 50,
		},
	}

	client, err := llm.NewClient(mockProvider)
	if err != nil {
		t.Fatal(err)
	}

	h := NewHistorian(client, nil)

	diff := &differ.DiffResult{
		PreviousRunID: "run1",
		CurrentRunID:  "run2",
		NewCount:      1,
		Entries: []differ.DiffEntry{
			{
				ChangeType: differ.ChangeNew,
				Current:    makeFinding(models.SeverityCritical, models.VulnRCE, "https://example.com/rce"),
			},
		},
	}

	analysis, err := h.Analyze(context.Background(), diff)
	if err != nil {
		t.Fatal(err)
	}

	if analysis.Summary == "" {
		t.Error("analysis summary should not be empty")
	}
	if analysis.Provider != "mock" {
		t.Errorf("expected mock provider, got %s", analysis.Provider)
	}
	if analysis.RiskLevel != "critical" {
		t.Errorf("expected critical risk, got %s", analysis.RiskLevel)
	}
}

// mockLLMProvider implements llm.Provider for testing.
type mockLLMProvider struct {
	response *llm.Response
}

func (m *mockLLMProvider) Name() string      { return "mock" }
func (m *mockLLMProvider) Model() string      { return "test" }
func (m *mockLLMProvider) Available() bool    { return true }
func (m *mockLLMProvider) Complete(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	return m.response, nil
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
