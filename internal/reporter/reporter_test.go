package reporter

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/llm"
	"github.com/ggwpgoend/bb-hunter/internal/models"
)

type mockProvider struct {
	response string
}

func (m *mockProvider) Name() string    { return "mock" }
func (m *mockProvider) Model() string   { return "mock-1" }
func (m *mockProvider) Available() bool { return true }
func (m *mockProvider) Complete(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	return &llm.Response{
		Content:      m.response,
		Provider:     "mock",
		Model:        "mock-1",
		InputTokens:  200,
		OutputTokens: 500,
		Latency:      time.Millisecond,
	}, nil
}

const sampleReport = `# Reflected XSS в параметре поиска

Обнаружена уязвимость отражённого межсайтового скриптинга.

## Описание
Параметр ` + "`q`" + ` на странице /search не проходит санитизацию.

## Шаги воспроизведения
1. Перейти на https://example.com/search?q=<script>alert(1)</script>
2. Наблюдать выполнение скрипта

## Влияние
- Кража сессионных cookie
- Фишинг от имени сайта

## Severity
High — возможна кража учётных данных.
`

func TestReporter_GenerateReport(t *testing.T) {
	client, _ := llm.NewClient(&mockProvider{response: sampleReport})
	reporter := NewReporter(client, "standoff", nil)

	finding := &models.Finding{
		ID:               "f-001",
		URL:              "https://example.com/search?q=test",
		Method:           "GET",
		Host:             "example.com",
		Path:             "/search",
		VulnClass:        models.VulnXSS,
		Severity:         models.SeverityHigh,
		Confidence:       0.85,
		Hypothesis:       "Reflected input without encoding",
		NucleiTemplateID: "xss-reflected",
		ScannerEvidence:  "reflected <script> in body",
		Status:           models.StatusAnalyzed,
		ParamNames:       []string{"q"},
	}

	result, err := reporter.GenerateReport(context.Background(), finding)
	if err != nil {
		t.Fatal(err)
	}

	if result.Status != models.StatusReported {
		t.Errorf("Status = %q, want reported", result.Status)
	}
	if result.ReportMarkdown == "" {
		t.Error("ReportMarkdown should not be empty")
	}
	if !strings.Contains(result.ReportMarkdown, "XSS") {
		t.Error("report should mention XSS")
	}
}

func TestReporter_GenerateReportBatch_SkipRejected(t *testing.T) {
	client, _ := llm.NewClient(&mockProvider{response: sampleReport})
	reporter := NewReporter(client, "standoff", nil)

	findings := []*models.Finding{
		{ID: "f-001", Status: models.StatusAnalyzed, Confidence: 0.8, URL: "https://example.com/1", Method: "GET", Host: "example.com"},
		{ID: "f-002", Status: models.StatusRejected, Confidence: 0.1, URL: "https://example.com/2", Method: "GET", Host: "example.com"},
		{ID: "f-003", Status: models.StatusAnalyzed, Confidence: 0.9, URL: "https://example.com/3", Method: "GET", Host: "example.com"},
	}

	results, err := reporter.GenerateReportBatch(context.Background(), findings)
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 2 {
		t.Errorf("expected 2 results (skip rejected), got %d", len(results))
	}
}

func TestReporter_GenerateReportBatch_SkipLowConfidence(t *testing.T) {
	client, _ := llm.NewClient(&mockProvider{response: sampleReport})
	reporter := NewReporter(client, "standoff", nil)

	findings := []*models.Finding{
		{ID: "f-001", Status: models.StatusAnalyzed, Confidence: 0.8, URL: "https://example.com/1", Method: "GET", Host: "example.com"},
		{ID: "f-002", Status: models.StatusAnalyzed, Confidence: 0.2, URL: "https://example.com/2", Method: "GET", Host: "example.com"},
	}

	results, err := reporter.GenerateReportBatch(context.Background(), findings)
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 1 {
		t.Errorf("expected 1 result (skip low confidence), got %d", len(results))
	}
}

func TestBuildReportPrompt(t *testing.T) {
	f := &models.Finding{
		URL:              "https://example.com/api",
		Method:           "POST",
		Host:             "example.com",
		Path:             "/api",
		VulnClass:        models.VulnSQLi,
		Severity:         models.SeverityCritical,
		Confidence:       0.95,
		Hypothesis:       "Time-based blind SQLi",
		NucleiTemplateID: "sqli-blind",
		ScannerEvidence:  "5s delay",
		ParamNames:       []string{"id", "name"},
	}

	prompt := buildReportPrompt(f)

	if !strings.Contains(prompt, "POST") {
		t.Error("prompt should contain method")
	}
	if !strings.Contains(prompt, "sqli") {
		t.Error("prompt should contain vuln class")
	}
	if !strings.Contains(prompt, "95%") {
		t.Error("prompt should contain confidence")
	}
	if !strings.Contains(prompt, "id, name") {
		t.Error("prompt should contain params")
	}
}
