package analyst

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/llm"
	"github.com/ggwpgoend/bb-hunter/internal/models"
)

type mockProvider struct {
	response string
	sentinel bool // if true, include sentinel in response
}

func (m *mockProvider) Name() string    { return "mock" }
func (m *mockProvider) Model() string   { return "mock-1" }
func (m *mockProvider) Available() bool { return true }
func (m *mockProvider) Complete(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	content := m.response
	if m.sentinel && req.SentinelUUID != "" {
		content = "leaked: " + req.SentinelUUID + " " + content
	}
	return &llm.Response{
		Content:      content,
		Provider:     "mock",
		Model:        "mock-1",
		InputTokens:  100,
		OutputTokens: 50,
		Latency:      time.Millisecond,
	}, nil
}

func TestAnalyst_Analyze_XSS(t *testing.T) {
	classification := Classification{
		VulnClass:     "xss",
		Confidence:    0.85,
		Hypothesis:    "Reflected input in search parameter without encoding",
		Severity:      "high",
		FalsePositive: false,
		Reasoning:     "Input reflected in HTML body without sanitization",
	}
	respJSON, _ := json.Marshal(classification)

	client, _ := llm.NewClient(&mockProvider{response: string(respJSON)})
	analyst := NewAnalyst(client, nil, nil)

	finding := &models.Finding{
		ID:               "f-001",
		URL:              "https://example.com/search?q=test",
		Method:           "GET",
		Host:             "example.com",
		Path:             "/search",
		NucleiTemplateID: "xss-reflected",
		ScannerEvidence:  "reflected <script> in body",
		Severity:         models.SeverityMedium,
		Status:           models.StatusNew,
		ParamNames:       []string{"q"},
	}

	result, err := analyst.Analyze(context.Background(), finding)
	if err != nil {
		t.Fatal(err)
	}

	if result.VulnClass != models.VulnXSS {
		t.Errorf("VulnClass = %q, want xss", result.VulnClass)
	}
	if result.Confidence != 0.85 {
		t.Errorf("Confidence = %f, want 0.85", result.Confidence)
	}
	if result.Severity != models.SeverityHigh {
		t.Errorf("Severity = %q, want high", result.Severity)
	}
	if result.Status != models.StatusAnalyzed {
		t.Errorf("Status = %q, want analyzed", result.Status)
	}
	if result.Hypothesis == "" {
		t.Error("Hypothesis should not be empty")
	}
}

func TestAnalyst_Analyze_FalsePositive(t *testing.T) {
	classification := Classification{
		VulnClass:     "misconfig",
		Confidence:    0.1,
		Hypothesis:    "Generic header check, not exploitable",
		Severity:      "info",
		FalsePositive: true,
		Reasoning:     "Missing X-Frame-Options on static page",
	}
	respJSON, _ := json.Marshal(classification)

	client, _ := llm.NewClient(&mockProvider{response: string(respJSON)})
	analyst := NewAnalyst(client, nil, nil)

	finding := &models.Finding{
		ID:               "f-002",
		URL:              "https://example.com/",
		Method:           "GET",
		Host:             "example.com",
		Path:             "/",
		NucleiTemplateID: "http-missing-security-headers",
		Severity:         models.SeverityInfo,
		Status:           models.StatusNew,
	}

	result, err := analyst.Analyze(context.Background(), finding)
	if err != nil {
		t.Fatal(err)
	}

	if result.Status != models.StatusRejected {
		t.Errorf("Status = %q, want rejected (false positive)", result.Status)
	}
	if result.Confidence != 0.1 {
		t.Errorf("Confidence = %f, want 0.1", result.Confidence)
	}
}

func TestAnalyst_Analyze_SentinelLeak(t *testing.T) {
	client, _ := llm.NewClient(&mockProvider{
		response: `{"vuln_class":"xss","confidence":0.9}`,
		sentinel: true,
	})
	analyst := NewAnalyst(client, nil, nil)

	finding := &models.Finding{
		ID:     "f-003",
		URL:    "https://example.com/",
		Method: "GET",
		Host:   "example.com",
		Path:   "/",
		Status: models.StatusNew,
	}

	result, err := analyst.Analyze(context.Background(), finding)
	if err != nil {
		t.Fatal(err)
	}

	// Should NOT be classified — sentinel leaked = possible prompt injection
	if result.Status != models.StatusNew {
		t.Errorf("Status = %q, want new (sentinel leaked)", result.Status)
	}
	if result.Hypothesis != "[SENTINEL LEAKED — manual review required]" {
		t.Errorf("Hypothesis = %q, expected sentinel warning", result.Hypothesis)
	}
}

func TestAnalyst_AnalyzeBatch(t *testing.T) {
	classification := Classification{
		VulnClass:  "sqli",
		Confidence: 0.7,
		Hypothesis: "Possible blind SQL injection",
		Severity:   "high",
	}
	respJSON, _ := json.Marshal(classification)

	client, _ := llm.NewClient(&mockProvider{response: string(respJSON)})
	analyst := NewAnalyst(client, nil, nil)

	findings := []*models.Finding{
		{ID: "f-010", URL: "https://example.com/1", Method: "GET", Host: "example.com", Status: models.StatusNew},
		{ID: "f-011", URL: "https://example.com/2", Method: "GET", Host: "example.com", Status: models.StatusNew},
		{ID: "f-012", URL: "https://example.com/3", Method: "GET", Host: "example.com", Status: models.StatusNew},
	}

	results, err := analyst.AnalyzeBatch(context.Background(), findings)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Errorf("batch returned %d results, want 3", len(results))
	}
}

func TestMapVulnClass(t *testing.T) {
	tests := []struct {
		input string
		want  models.VulnClass
	}{
		{"xss", models.VulnXSS},
		{"sqli", models.VulnSQLi},
		{"ssrf", models.VulnSSRF},
		{"rce", models.VulnRCE},
		{"XSS", models.VulnXSS},
		{"unknown", models.VulnOther},
	}
	for _, tc := range tests {
		if got := mapVulnClass(tc.input); got != tc.want {
			t.Errorf("mapVulnClass(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestClampConfidence(t *testing.T) {
	if clampConfidence(-0.5) != 0 {
		t.Error("negative should clamp to 0")
	}
	if clampConfidence(1.5) != 1 {
		t.Error(">1 should clamp to 1")
	}
	if clampConfidence(0.75) != 0.75 {
		t.Error("valid value should pass through")
	}
}

func TestBuildAnalysisPrompt(t *testing.T) {
	f := &models.Finding{
		URL:              "https://example.com/api?q=test",
		Method:           "POST",
		Host:             "example.com",
		Path:             "/api",
		NucleiTemplateID: "xss-reflected",
		ScannerEvidence:  "reflected in body",
		Severity:         models.SeverityMedium,
		ParamNames:       []string{"q"},
	}

	prompt := buildAnalysisPrompt(f)

	if !containsStr(prompt, "https://example.com/api?q=test") {
		t.Error("prompt should contain URL")
	}
	if !containsStr(prompt, "POST") {
		t.Error("prompt should contain method")
	}
	if !containsStr(prompt, "xss-reflected") {
		t.Error("prompt should contain template")
	}
	if !containsStr(prompt, "reflected in body") {
		t.Error("prompt should contain evidence")
	}
}

func TestRepairJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"complete", `{"a":"b"}`, true},
		{"truncated string", `{"a":"trunc`, true},
		{"truncated brace", `{"a":"b"`, true},
		{"truncated nested", `{"a":{"b":"c"`, true},
		{"empty", "", true},
		{"truncated array", `{"a":[1,2`, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repaired := repairJSON(tc.input)
			if tc.valid {
				var v any
				if err := json.Unmarshal([]byte(repaired), &v); err != nil {
					t.Errorf("repairJSON(%q) = %q, not valid JSON: %v", tc.input, repaired, err)
				}
			}
		})
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && searchStr(s, substr)
}

func searchStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
