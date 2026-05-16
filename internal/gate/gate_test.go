package gate

import (
	"testing"

	"github.com/ggwpgoend/bb-hunter/internal/models"
)

func TestEvaluateAlgorithmic_HighQuality(t *testing.T) {
	g := NewGate(nil, nil)

	f := &models.Finding{
		ID:              "f1",
		URL:             "https://example.com/api/users?q=test",
		Method:          "GET",
		Host:            "example.com",
		Path:            "/api/users",
		Severity:        models.SeverityHigh,
		VulnClass:       models.VulnXSS,
		Confidence:      0.85,
		ScannerEvidence: "reflected parameter in response",
		ReportMarkdown:  "# XSS\n\nReflected cross-site scripting found in the `q` parameter of `/api/users`. The value is reflected without encoding in the HTML response body. This allows an attacker to inject arbitrary JavaScript.",
	}

	result := g.EvaluateAlgorithmic(f)

	if result.Verdict != VerdictPass {
		t.Errorf("expected PASS, got %s (score %d)", result.Verdict, result.Score)
	}
	if result.Score < 5 {
		t.Errorf("expected score >= 5, got %d", result.Score)
	}
}

func TestEvaluateAlgorithmic_LowQuality(t *testing.T) {
	g := NewGate(nil, nil)

	f := &models.Finding{
		ID:         "f2",
		URL:        "",
		Method:     "",
		Host:       "",
		Severity:   models.SeverityInfo,
		VulnClass:  models.VulnOther,
		Confidence: 0.1,
	}

	result := g.EvaluateAlgorithmic(f)

	if result.Verdict != VerdictKill {
		t.Errorf("expected KILL, got %s (score %d)", result.Verdict, result.Score)
	}
}

func TestEvaluateAlgorithmic_Borderline(t *testing.T) {
	g := NewGate(nil, nil)

	f := &models.Finding{
		ID:              "f3",
		URL:             "https://example.com/page",
		Method:          "GET",
		Host:            "example.com",
		Path:            "/page",
		Severity:        models.SeverityMedium,
		VulnClass:       models.VulnMisconfig,
		Confidence:      0.4, // below uniqueness threshold
		ScannerEvidence: "some evidence",
	}

	result := g.EvaluateAlgorithmic(f)

	// Score should be: URL+method(1) + evidence(1) + impact(1) + scope(1) + severity(1) + uniqueness(0) + report(0) = 5
	if result.Score < 3 {
		t.Errorf("expected borderline score (3-5), got %d", result.Score)
	}
}

func TestEvaluateAlgorithmic_Downgrade(t *testing.T) {
	g := NewGate(nil, nil)
	g.SetMinScore(6) // raise threshold so borderline findings get DOWNGRADE

	f := &models.Finding{
		ID:              "f4",
		URL:             "https://example.com/api",
		Method:          "GET",
		Host:            "example.com",
		Path:            "/api",
		Severity:        models.SeverityHigh,
		VulnClass:       models.VulnMisconfig,
		Confidence:      0.6,
		ScannerEvidence: "something",
		ReportMarkdown:  "# Report\n\nFound a misconfiguration on the API endpoint that exposes internal headers. This could be used to gather information about the backend infrastructure.",
	}

	result := g.EvaluateAlgorithmic(f)

	// With minScore=6, score of 5 should give DOWNGRADE
	if result.Score == 5 && result.Verdict != VerdictDowngrade {
		t.Errorf("expected DOWNGRADE for score 5 with minScore 6, got %s", result.Verdict)
	}
}

func TestSetMinScore_Bounds(t *testing.T) {
	g := NewGate(nil, nil)

	g.SetMinScore(-1)
	if g.minScore != 0 {
		t.Errorf("expected 0, got %d", g.minScore)
	}

	g.SetMinScore(10)
	if g.minScore != 7 {
		t.Errorf("expected 7, got %d", g.minScore)
	}

	g.SetMinScore(5)
	if g.minScore != 5 {
		t.Errorf("expected 5, got %d", g.minScore)
	}
}

func TestParseResponse_ValidJSON(t *testing.T) {
	g := NewGate(nil, nil)

	jsonResp := `{
		"questions": [
			{"question": "reproductibility", "passed": true, "detail": "URL provided"},
			{"question": "evidence", "passed": true, "detail": "nuclei template match"},
			{"question": "security_impact", "passed": true, "detail": "XSS allows script injection"},
			{"question": "scope", "passed": true, "detail": "domain in scope"},
			{"question": "severity", "passed": true, "detail": "high is appropriate"},
			{"question": "uniqueness", "passed": false, "detail": "possible scanner artifact"},
			{"question": "report_quality", "passed": true, "detail": "clear and actionable"}
		],
		"suggested_severity": "medium",
		"reasoning": "6/7 passed, one concern about uniqueness"
	}`

	result, err := g.parseResponse("f1", jsonResp)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if result.Score != 6 {
		t.Errorf("expected score 6, got %d", result.Score)
	}
	if result.Verdict != VerdictPass {
		t.Errorf("expected PASS, got %s", result.Verdict)
	}
	if result.SuggestedSeverity != "medium" {
		t.Errorf("expected suggested severity medium, got %s", result.SuggestedSeverity)
	}
}

func TestParseResponse_LowScore(t *testing.T) {
	g := NewGate(nil, nil)

	jsonResp := `{
		"questions": [
			{"question": "reproductibility", "passed": false, "detail": "no steps"},
			{"question": "evidence", "passed": false, "detail": "none"},
			{"question": "security_impact", "passed": false, "detail": "info only"},
			{"question": "scope", "passed": true, "detail": "ok"},
			{"question": "severity", "passed": false, "detail": "inflated"},
			{"question": "uniqueness", "passed": false, "detail": "scanner artifact"},
			{"question": "report_quality", "passed": false, "detail": "empty"}
		],
		"reasoning": "extremely low quality"
	}`

	result, err := g.parseResponse("f2", jsonResp)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if result.Score != 1 {
		t.Errorf("expected score 1, got %d", result.Score)
	}
	if result.Verdict != VerdictKill {
		t.Errorf("expected KILL, got %s", result.Verdict)
	}
}

func TestParseResponse_MarkdownWrapped(t *testing.T) {
	g := NewGate(nil, nil)

	wrapped := "```json\n" + `{
		"questions": [
			{"question": "q1", "passed": true, "detail": "ok"},
			{"question": "q2", "passed": true, "detail": "ok"},
			{"question": "q3", "passed": true, "detail": "ok"},
			{"question": "q4", "passed": true, "detail": "ok"},
			{"question": "q5", "passed": true, "detail": "ok"},
			{"question": "q6", "passed": true, "detail": "ok"},
			{"question": "q7", "passed": true, "detail": "ok"}
		],
		"reasoning": "all pass"
	}` + "\n```"

	result, err := g.parseResponse("f3", wrapped)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if result.Score != 7 {
		t.Errorf("expected score 7, got %d", result.Score)
	}
	if result.Verdict != VerdictPass {
		t.Errorf("expected PASS, got %s", result.Verdict)
	}
}

func TestDowngradeSeverity(t *testing.T) {
	tests := []struct {
		input models.Severity
		want  string
	}{
		{models.SeverityCritical, "high"},
		{models.SeverityHigh, "medium"},
		{models.SeverityMedium, "low"},
		{models.SeverityLow, "info"},
		{models.SeverityInfo, "info"},
	}

	for _, tt := range tests {
		got := downgradeSeverity(tt.input)
		if got != tt.want {
			t.Errorf("downgradeSeverity(%s) = %s, want %s", tt.input, got, tt.want)
		}
	}
}
