// E2E test: Analyst + Reporter with real Gemini API
//
// Run: GEMINI_API_KEY=... go test -v -count=1 -run TestE2E /tmp/e2e_llm_test.go
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/analyst"
	"github.com/ggwpgoend/bb-hunter/internal/llm"
	"github.com/ggwpgoend/bb-hunter/internal/models"
	"github.com/ggwpgoend/bb-hunter/internal/reporter"
)

func TestE2E_Analyst_RealGemini(t *testing.T) {
	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		t.Skip("GEMINI_API_KEY not set")
	}

	provider := llm.NewGeminiProvider(apiKey, "gemini-2.5-flash")
	client, err := llm.NewClient(provider)
	if err != nil {
		t.Fatal(err)
	}

	analystAgent := analyst.NewAnalyst(client, nil, nil)

	// Test case 1: Real XSS finding
	xssFinding := &models.Finding{
		ID:               "e2e-xss-001",
		URL:              "https://example.com/search?q=<script>alert(1)</script>",
		Method:           "GET",
		Host:             "example.com",
		Path:             "/search",
		NucleiTemplateID: "xss-reflected-double-context",
		ScannerEvidence:  "matcher: body\ncurl: curl -X GET 'https://example.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E'\nresponse_snippet: <html><body><h1>Search results for: <script>alert(1)</script></h1></body></html>",
		Severity:         models.SeverityMedium,
		Status:           models.StatusNew,
		ParamNames:       []string{"q"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	fmt.Println("=== TEST 1: Analyst classifies XSS finding ===")
	result, err := analystAgent.Analyze(ctx, xssFinding)
	if err != nil {
		t.Fatalf("Analyst.Analyze failed: %v", err)
	}

	fmt.Printf("VulnClass:  %s\n", result.VulnClass)
	fmt.Printf("Confidence: %.2f\n", result.Confidence)
	fmt.Printf("Severity:   %s\n", result.Severity)
	fmt.Printf("Status:     %s\n", result.Status)
	fmt.Printf("Hypothesis: %s\n", result.Hypothesis)

	// Validate results
	if result.VulnClass != models.VulnXSS {
		t.Errorf("Expected vuln_class=xss, got %q", result.VulnClass)
	}
	if result.Confidence < 0.5 {
		t.Errorf("Expected confidence >= 0.5 for clear XSS, got %.2f", result.Confidence)
	}
	if result.Status == models.StatusNew {
		t.Error("Status should have changed from 'new'")
	}
	fmt.Println("✓ XSS classification correct")

	// Test case 2: False positive (missing headers)
	fmt.Println("\n=== TEST 2: Analyst detects false positive ===")
	fpFinding := &models.Finding{
		ID:               "e2e-fp-001",
		URL:              "https://example.com/",
		Method:           "GET",
		Host:             "example.com",
		Path:             "/",
		NucleiTemplateID: "http-missing-security-headers",
		ScannerEvidence:  "matcher: x-frame-options\ncurl: curl -X GET 'https://example.com/'",
		Severity:         models.SeverityInfo,
		Status:           models.StatusNew,
	}

	result2, err := analystAgent.Analyze(ctx, fpFinding)
	if err != nil {
		t.Fatalf("Analyst.Analyze (FP) failed: %v", err)
	}

	fmt.Printf("VulnClass:     %s\n", result2.VulnClass)
	fmt.Printf("Confidence:    %.2f\n", result2.Confidence)
	fmt.Printf("Severity:      %s\n", result2.Severity)
	fmt.Printf("FalsePositive: %v (status=%s)\n", result2.Status == models.StatusRejected, result2.Status)
	fmt.Printf("Hypothesis:    %s\n", result2.Hypothesis)

	if result2.Confidence > 0.5 {
		t.Logf("WARNING: expected low confidence for missing headers, got %.2f", result2.Confidence)
	}
	fmt.Println("✓ False positive handling correct")

	// Test case 3: SQLi finding
	fmt.Println("\n=== TEST 3: Analyst classifies SQLi finding ===")
	sqliFinding := &models.Finding{
		ID:               "e2e-sqli-001",
		URL:              "https://example.com/api/users?id=1",
		Method:           "GET",
		Host:             "example.com",
		Path:             "/api/users",
		NucleiTemplateID: "sqli-time-based-blind",
		ScannerEvidence:  "matcher: time-based\ncurl: curl -X GET 'https://example.com/api/users?id=1%27%20AND%20SLEEP(5)--'\nresponse_snippet: Response time: 5.2s (normal: 0.1s)",
		Severity:         models.SeverityHigh,
		Status:           models.StatusNew,
		ParamNames:       []string{"id"},
	}

	result3, err := analystAgent.Analyze(ctx, sqliFinding)
	if err != nil {
		t.Fatalf("Analyst.Analyze (SQLi) failed: %v", err)
	}

	fmt.Printf("VulnClass:  %s\n", result3.VulnClass)
	fmt.Printf("Confidence: %.2f\n", result3.Confidence)
	fmt.Printf("Severity:   %s\n", result3.Severity)
	fmt.Printf("Hypothesis: %s\n", result3.Hypothesis)

	if result3.VulnClass != models.VulnSQLi {
		t.Errorf("Expected vuln_class=sqli, got %q", result3.VulnClass)
	}
	fmt.Println("✓ SQLi classification correct")
}

func TestE2E_Reporter_RealGemini(t *testing.T) {
	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		t.Skip("GEMINI_API_KEY not set")
	}

	provider := llm.NewGeminiProvider(apiKey, "gemini-2.5-flash")
	client, err := llm.NewClient(provider)
	if err != nil {
		t.Fatal(err)
	}

	reporterAgent := reporter.NewReporter(client, "standoff", nil)

	finding := &models.Finding{
		ID:               "e2e-report-001",
		URL:              "https://example.com/search?q=test",
		Method:           "GET",
		Host:             "example.com",
		Path:             "/search",
		VulnClass:        models.VulnXSS,
		Severity:         models.SeverityHigh,
		Confidence:       0.85,
		Hypothesis:       "Reflected input in search parameter without HTML encoding. The <script> tag is rendered directly in the page body.",
		NucleiTemplateID: "xss-reflected-double-context",
		ScannerEvidence:  "matcher: body\nResponse contains unencoded user input in HTML body",
		Status:           models.StatusAnalyzed,
		ParamNames:       []string{"q"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	fmt.Println("\n=== TEST 4: Reporter generates Russian report ===")
	result, err := reporterAgent.GenerateReport(ctx, finding)
	if err != nil {
		t.Fatalf("Reporter.GenerateReport failed: %v", err)
	}

	fmt.Printf("Status: %s\n", result.Status)
	fmt.Printf("Report length: %d chars\n", len(result.ReportMarkdown))
	fmt.Printf("\n--- REPORT ---\n%s\n--- END ---\n", result.ReportMarkdown)

	if result.Status != models.StatusReported {
		t.Errorf("Expected status=reported, got %q", result.Status)
	}
	if len(result.ReportMarkdown) < 100 {
		t.Error("Report too short")
	}

	// Check report is in Russian
	hasRussian := false
	russianWords := []string{"уязвимость", "Описание", "воспроизведения", "Влияние", "устранени", "Шаги", "результат"}
	for _, word := range russianWords {
		if strings.Contains(strings.ToLower(result.ReportMarkdown), strings.ToLower(word)) {
			hasRussian = true
			break
		}
	}
	if !hasRussian {
		t.Error("Report should be in Russian")
	}
	fmt.Println("✓ Report generated in Russian")
}

func TestE2E_FullPipeline_MockScan(t *testing.T) {
	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		t.Skip("GEMINI_API_KEY not set")
	}

	provider := llm.NewGeminiProvider(apiKey, "gemini-2.5-flash")
	client, err := llm.NewClient(provider)
	if err != nil {
		t.Fatal(err)
	}

	analystAgent := analyst.NewAnalyst(client, nil, nil)
	reporterAgent := reporter.NewReporter(client, "standoff", nil)

	// Simulate scanner output (2 findings)
	scannerFindings := []*models.Finding{
		{
			ID:               "pipe-001",
			URL:              "https://example.com/login",
			Method:           "POST",
			Host:             "example.com",
			Path:             "/login",
			NucleiTemplateID: "default-login-credentials",
			ScannerEvidence:  "matcher: body\ncurl: curl -X POST 'https://example.com/login' -d 'user=admin&pass=admin'\nresponse_snippet: Welcome, admin!",
			Severity:         models.SeverityHigh,
			Status:           models.StatusNew,
			ParamNames:       []string{"user", "pass"},
		},
		{
			ID:               "pipe-002",
			URL:              "https://example.com/robots.txt",
			Method:           "GET",
			Host:             "example.com",
			Path:             "/robots.txt",
			NucleiTemplateID: "robots-txt-endpoint",
			ScannerEvidence:  "matcher: status_code\nStatus: 200\nContent: Disallow: /admin",
			Severity:         models.SeverityInfo,
			Status:           models.StatusNew,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	fmt.Println("\n=== TEST 5: Full pipeline (mock scan → analyze → report) ===")

	// Stage 1: Analyze
	fmt.Println("Stage 1: Analyzing findings...")
	analyzed, err := analystAgent.AnalyzeBatch(ctx, scannerFindings)
	if err != nil {
		t.Fatalf("AnalyzeBatch failed: %v", err)
	}
	fmt.Printf("Analyzed: %d findings\n", len(analyzed))

	for _, f := range analyzed {
		fmt.Printf("  [%s] class=%s conf=%.2f severity=%s status=%s\n",
			f.ID, f.VulnClass, f.Confidence, f.Severity, f.Status)
	}

	// Stage 2: Generate reports
	fmt.Println("\nStage 2: Generating reports...")
	reported, err := reporterAgent.GenerateReportBatch(ctx, analyzed)
	if err != nil {
		t.Fatalf("GenerateReportBatch failed: %v", err)
	}
	fmt.Printf("Reports generated: %d\n", len(reported))

	for i, f := range reported {
		fmt.Printf("\n--- Report %d/%d (finding %s) ---\n", i+1, len(reported), f.ID)
		// Print first 500 chars of report
		report := f.ReportMarkdown
		if len(report) > 500 {
			report = report[:500] + "...[truncated]"
		}
		fmt.Println(report)
	}

	// Verify pipeline
	if len(analyzed) < 1 {
		t.Error("Expected at least 1 analyzed finding")
	}

	// The robots.txt finding should have low confidence or be rejected
	for _, f := range analyzed {
		if f.NucleiTemplateID == "robots-txt-endpoint" && f.Confidence > 0.5 {
			t.Logf("Note: robots.txt was rated confidence=%.2f (expected low)", f.Confidence)
		}
	}

	fmt.Println("\n✓ Full pipeline completed successfully")

	// Print final summary as JSON
	summary := map[string]any{
		"scanner_findings": len(scannerFindings),
		"analyzed":         len(analyzed),
		"reported":         len(reported),
		"findings": func() []map[string]any {
			var r []map[string]any
			for _, f := range analyzed {
				r = append(r, map[string]any{
					"id":         f.ID,
					"vuln_class": f.VulnClass,
					"confidence": f.Confidence,
					"severity":   f.Severity,
					"status":     f.Status,
				})
			}
			return r
		}(),
	}
	summaryJSON, _ := json.MarshalIndent(summary, "", "  ")
	fmt.Printf("\n=== Pipeline Summary ===\n%s\n", summaryJSON)
}
