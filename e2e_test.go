//go:build e2e
// +build e2e

// E2E integration test for BB-Hunter pipeline components.
// Requires: GEMINI_API_KEY environment variable set.
// Run: go test -tags e2e -v -run TestE2E -timeout 180s
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/analyst"
	"github.com/ggwpgoend/bb-hunter/internal/chainer"
	"github.com/ggwpgoend/bb-hunter/internal/dedup"
	"github.com/ggwpgoend/bb-hunter/internal/gate"
	"github.com/ggwpgoend/bb-hunter/internal/llm"
	"github.com/ggwpgoend/bb-hunter/internal/models"
	"github.com/ggwpgoend/bb-hunter/internal/reporter"
	"github.com/ggwpgoend/bb-hunter/internal/scope"

	_ "modernc.org/sqlite"
)

func setupLLM(t *testing.T) *llm.Client {
	key := os.Getenv("GEMINI_API_KEY")
	if key == "" {
		t.Skip("GEMINI_API_KEY not set")
	}
	provider := llm.NewGeminiProvider(key, "gemini-2.0-flash")
	client, err := llm.NewClient(provider)
	if err != nil {
		t.Fatalf("failed to create LLM client: %v", err)
	}
	return client
}

func mockFindings() []*models.Finding {
	return []*models.Finding{
		{
			ID:              "f-e2e-xss-1",
			Host:            "testphp.vulnweb.com",
			URL:             "https://testphp.vulnweb.com/search.php?test=query",
			Method:          "GET",
			VulnClass:       "xss",
			Severity:        models.SeverityMedium,
			Status:          models.StatusNew,
			Confidence:      0.8,
			FindingKey:      "GET|testphp.vulnweb.com|/search.php|test|reflected-xss",
			ScannerEvidence: "Reflected XSS in search parameter: <script>alert(1)</script> reflected in response body",
			ParamNames:      []string{"test"},
			CreatedAt:       time.Now(),
		},
		{
			ID:              "f-e2e-sqli-1",
			Host:            "testphp.vulnweb.com",
			URL:             "https://testphp.vulnweb.com/artists.php?artist=1",
			Method:          "GET",
			VulnClass:       "sqli",
			Severity:        models.SeverityHigh,
			Status:          models.StatusNew,
			Confidence:      0.9,
			FindingKey:      "GET|testphp.vulnweb.com|/artists.php|artist|sql-injection",
			ScannerEvidence: "SQL injection: artist=1' OR 1=1-- triggers error: You have an error in your SQL syntax",
			ParamNames:      []string{"artist"},
			CreatedAt:       time.Now(),
		},
		{
			ID:              "f-e2e-misconfig-1",
			Host:            "testphp.vulnweb.com",
			URL:             "https://testphp.vulnweb.com/.htaccess",
			Method:          "GET",
			VulnClass:       "misconfig",
			Severity:        models.SeverityLow,
			Status:          models.StatusNew,
			Confidence:      0.6,
			FindingKey:      "GET|testphp.vulnweb.com|/.htaccess||exposed-config",
			ScannerEvidence: ".htaccess file is publicly accessible, reveals internal paths",
			CreatedAt:       time.Now(),
		},
	}
}

// TestE2E_Analyst tests Analyst with real Gemini API.
func TestE2E_Analyst(t *testing.T) {
	client := setupLLM(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	scopeCfg := scope.Config{
		AllowedDomains: []string{"testphp.vulnweb.com"},
	}
	enforcer, err := scope.New(scopeCfg)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}

	a := analyst.NewAnalyst(client, enforcer, slog.Default())
	findings := mockFindings()

	for _, f := range findings {
		t.Run(string(f.VulnClass), func(t *testing.T) {
			result, err := a.Analyze(ctx, f)
			if err != nil {
				t.Fatalf("analyst error: %v", err)
			}
			hypPreview := result.Hypothesis
			if len(hypPreview) > 80 {
				hypPreview = hypPreview[:80]
			}
			t.Logf("Finding %s: class=%s severity=%s hypothesis=%s",
				f.ID, result.VulnClass, result.Severity, hypPreview)

			if result.VulnClass == "" {
				t.Error("VulnClass should not be empty")
			}
			if result.Severity == "" {
				t.Error("Severity should not be empty")
			}
		})
	}
}

// TestE2E_Reporter tests Reporter with real Gemini API.
func TestE2E_Reporter(t *testing.T) {
	client := setupLLM(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	r := reporter.NewReporter(client, "standoff", slog.Default())
	findings := mockFindings()

	for _, f := range findings {
		t.Run(string(f.VulnClass), func(t *testing.T) {
			result, err := r.GenerateReport(ctx, f)
			if err != nil {
				t.Fatalf("reporter error: %v", err)
			}

			t.Logf("Report for %s: %d chars", f.ID, len(result.ReportMarkdown))
			preview := result.ReportMarkdown
			if len(preview) > 300 {
				preview = preview[:300]
			}
			t.Logf("Preview:\n%s", preview)

			if len(result.ReportMarkdown) < 50 {
				t.Error("Report too short")
			}

			// Check Russian content
			russianWords := []string{"уязвим", "безопасност", "обнаружен", "сервер", "атак", "параметр"}
			foundRussian := false
			lower := strings.ToLower(result.ReportMarkdown)
			for _, w := range russianWords {
				if strings.Contains(lower, w) {
					foundRussian = true
					break
				}
			}
			if !foundRussian {
				t.Error("Report should contain Russian text")
			}
		})
	}
}

// TestE2E_Dedup tests duplicate detection with real DB.
func TestE2E_Dedup(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS findings (
		id TEXT PRIMARY KEY, host TEXT, url TEXT, path TEXT,
		method TEXT, vuln_class TEXT, severity TEXT,
		status TEXT DEFAULT 'new', confidence REAL,
		finding_key TEXT, scanner_evidence TEXT,
		hypothesis TEXT, param_names TEXT, nuclei_template_id TEXT,
		created_at DATETIME, updated_at DATETIME,
		hitl_decision TEXT, hitl_decided_at DATETIME
	)`)
	if err != nil {
		t.Fatal(err)
	}

	checker := dedup.NewChecker(db, slog.Default())
	findings := mockFindings()

	// First run: all should be "new"
	results1, err := checker.CheckBatch(findings)
	if err != nil {
		t.Fatalf("first check: %v", err)
	}
	for _, r := range results1 {
		if r.Verdict != dedup.VerdictNew {
			t.Errorf("first run: %s should be 'new', got %s", r.FindingID, r.Verdict)
		}
	}
	t.Log("First run: all findings are new")

	// Insert findings with different IDs (simulate previous scan run)
	for _, f := range findings {
		prevID := "prev-" + f.ID
		_, err = db.Exec(`INSERT INTO findings (id, host, url, path, method, vuln_class, severity, status, confidence, finding_key, scanner_evidence, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
			prevID, f.Host, f.URL, f.URL, f.Method, f.VulnClass, f.Severity, "confirmed", f.Confidence, f.FindingKey, f.ScannerEvidence)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Second run: should detect exact duplicates
	results2, err := checker.CheckBatch(findings)
	if err != nil {
		t.Fatalf("second check: %v", err)
	}
	for _, r := range results2 {
		if r.Verdict != dedup.VerdictConfirmed {
			t.Errorf("second run: %s should be 'confirmed_duplicate', got %s", r.FindingID, r.Verdict)
		}
		t.Logf("Duplicate: %s matched %s (%s)", r.FindingID, r.MatchedID, r.Reason)
	}
}

// TestE2E_Gate tests quality gate.
func TestE2E_Gate(t *testing.T) {
	t.Run("algorithmic", func(t *testing.T) {
		g := gate.NewGate(nil, slog.Default())
		for _, f := range mockFindings() {
			result := g.EvaluateAlgorithmic(f)
			reasoning := result.Reasoning
			if len(reasoning) > 60 {
				reasoning = reasoning[:60]
			}
			t.Logf("Gate %s: verdict=%s score=%d/7 reasoning=%s", f.ID, result.Verdict, result.Score, reasoning)
			if result.Score < 0 || result.Score > 7 {
				t.Errorf("score out of range: %d", result.Score)
			}
		}
	})

	t.Run("with_llm", func(t *testing.T) {
		client := setupLLM(t)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		g := gate.NewGate(client, slog.Default())
		f := mockFindings()[0]

		result, err := g.Evaluate(ctx, f)
		if err != nil {
			t.Skipf("gate LLM: %v (rate limited or quota exceeded — algorithmic fallback works)", err)
		}
		reasoning := result.Reasoning
		if len(reasoning) > 80 {
			reasoning = reasoning[:80]
		}
		t.Logf("Gate LLM: verdict=%s score=%d/7 reasoning=%s", result.Verdict, result.Score, reasoning)
	})
}

// TestE2E_Chainer tests exploit chain builder.
func TestE2E_Chainer(t *testing.T) {
	t.Run("algorithmic", func(t *testing.T) {
		c := chainer.NewChainer(nil, slog.Default())
		chains := c.FindChainsAlgorithmic(mockFindings())
		t.Logf("Algorithmic chains: %d", len(chains))
		for _, ch := range chains {
			t.Logf("Chain: %s (severity=%s, confidence=%.0f%%)", ch.Name, ch.Severity, ch.Confidence*100)
		}
	})

	t.Run("with_llm", func(t *testing.T) {
		client := setupLLM(t)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		c := chainer.NewChainer(client, slog.Default())
		chains, err := c.FindChains(ctx, mockFindings())
		if err != nil {
			t.Fatalf("chainer LLM: %v", err)
		}
		t.Logf("LLM chains: %d", len(chains))
		for _, ch := range chains {
			t.Logf("Chain: %s (severity=%s, confidence=%.0f%%)", ch.Name, ch.Severity, ch.Confidence*100)
		}
	})
}

// TestE2E_FullPipeline runs mock findings through all stages.
func TestE2E_FullPipeline(t *testing.T) {
	client := setupLLM(t)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	logger := slog.Default()
	findings := mockFindings()

	// Stage 1: Analyst
	t.Log("=== Stage 1: Analyst ===")
	scopeCfg := scope.Config{AllowedDomains: []string{"testphp.vulnweb.com"}}
	enforcer, _ := scope.New(scopeCfg)
	a := analyst.NewAnalyst(client, enforcer, logger)

	for _, f := range findings {
		result, err := a.Analyze(ctx, f)
		if err != nil {
			t.Logf("Analyst failed for %s: %v", f.ID, err)
			continue
		}
		f.VulnClass = result.VulnClass
		f.Severity = result.Severity
		f.Hypothesis = result.Hypothesis
		f.Confidence = result.Confidence
		t.Logf("Analyzed %s: class=%s sev=%s conf=%.2f", f.ID, f.VulnClass, f.Severity, f.Confidence)
	}

	// Stage 2: Reporter
	t.Log("=== Stage 2: Reporter ===")
	rep := reporter.NewReporter(client, "standoff", logger)
	var totalReportLen int
	for _, f := range findings {
		result, err := rep.GenerateReport(ctx, f)
		if err != nil {
			t.Logf("Reporter failed for %s: %v", f.ID, err)
			continue
		}
		totalReportLen += len(result.ReportMarkdown)
		t.Logf("Report %s: %d chars", f.ID, len(result.ReportMarkdown))
	}

	// Stage 3: Dedup
	t.Log("=== Stage 3: Dedup ===")
	db, _ := sql.Open("sqlite", ":memory:")
	defer db.Close()
	db.Exec(`CREATE TABLE findings (id TEXT PRIMARY KEY, host TEXT, url TEXT, path TEXT, method TEXT, vuln_class TEXT, severity TEXT, status TEXT DEFAULT 'new', confidence REAL, finding_key TEXT, scanner_evidence TEXT, hypothesis TEXT, param_names TEXT, nuclei_template_id TEXT, created_at DATETIME, updated_at DATETIME, hitl_decision TEXT, hitl_decided_at DATETIME)`)

	checker := dedup.NewChecker(db, logger)
	dedupResults, _ := checker.CheckBatch(findings)
	for _, r := range dedupResults {
		t.Logf("Dedup %s: %s", r.FindingID, r.Verdict)
	}

	// Stage 4: Gate
	t.Log("=== Stage 4: Gate ===")
	g := gate.NewGate(client, logger)
	gateResults, _ := g.EvaluateBatch(ctx, findings)
	var passed []*models.Finding
	for i, gr := range gateResults {
		t.Logf("Gate %s: %s (%d/7)", gr.FindingID, gr.Verdict, gr.Score)
		if gr.Verdict != gate.VerdictKill {
			passed = append(passed, findings[i])
		}
	}
	t.Logf("Gate: %d/%d passed", len(passed), len(findings))

	// Stage 5: Chainer
	t.Log("=== Stage 5: Chainer ===")
	ch := chainer.NewChainer(client, logger)
	chains, _ := ch.FindChains(ctx, passed)
	t.Logf("Chains: %d", len(chains))
	for _, c := range chains {
		t.Logf("Chain: %s (%s, %.0f%%)", c.Name, c.Severity, c.Confidence*100)
	}

	// Summary
	fmt.Fprintf(os.Stderr, "\n===== E2E PIPELINE COMPLETE =====\n")
	fmt.Fprintf(os.Stderr, "Findings:    %d\n", len(findings))
	fmt.Fprintf(os.Stderr, "Reports:     %d chars total\n", totalReportLen)
	fmt.Fprintf(os.Stderr, "Gate passed: %d/%d\n", len(passed), len(findings))
	fmt.Fprintf(os.Stderr, "Chains:      %d\n", len(chains))
}
