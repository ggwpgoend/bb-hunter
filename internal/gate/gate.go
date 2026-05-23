// Package gate implements the 7-Question Gate — a formal quality validation
// for findings before they reach HITL.
//
// Borrowed concept: pentest-agents' /validate command and 7-Question Gate.
// Each finding is evaluated on 7 criteria. The verdict is PASS, KILL, or DOWNGRADE.
// This prevents low-quality findings from wasting reviewer time and protects
// platform reputation.
package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ggwpgoend/bb-hunter/internal/llm"
	"github.com/ggwpgoend/bb-hunter/internal/models"
)

// Verdict is the gate decision.
type Verdict string

const (
	VerdictPass      Verdict = "PASS"
	VerdictKill      Verdict = "KILL"
	VerdictDowngrade Verdict = "DOWNGRADE"
)

// Result is the gate evaluation for a single finding.
type Result struct {
	FindingID string  `json:"finding_id"`
	Verdict   Verdict `json:"verdict"`
	Score     int     `json:"score"`     // 0–7 (number of passed questions)
	MinScore  int     `json:"min_score"` // threshold for PASS (default 5)

	// Individual question results
	Questions [7]QuestionResult `json:"questions"`

	// Suggested severity (for DOWNGRADE verdict)
	SuggestedSeverity string `json:"suggested_severity,omitempty"`

	// Gate reasoning
	Reasoning string `json:"reasoning"`
}

// QuestionResult is the result of a single gate question.
type QuestionResult struct {
	Question string `json:"question"`
	Passed   bool   `json:"passed"`
	Detail   string `json:"detail"`
}

// Gate evaluates findings against 7 quality criteria.
type Gate struct {
	client   *llm.Client
	log      *slog.Logger
	minScore int // minimum score for PASS (default 5)
}

// NewGate creates a new 7-Question Gate.
func NewGate(client *llm.Client, logger *slog.Logger) *Gate {
	if logger == nil {
		logger = slog.Default()
	}
	return &Gate{client: client, log: logger, minScore: 5}
}

// SetMinScore sets the minimum score for PASS verdict (0–7).
func (g *Gate) SetMinScore(n int) {
	if n < 0 {
		n = 0
	}
	if n > 7 {
		n = 7
	}
	g.minScore = n
}

const gateSystemPrompt = `Ты — валидатор качества bug bounty находок. Оцени находку по 7 критериям.

Для каждого вопроса ответь true (проходит) или false (не проходит) и дай краткое объяснение.

7 ВОПРОСОВ:
1. ВОСПРОИЗВОДИМОСТЬ: Можно ли воспроизвести уязвимость по предоставленным данным?
2. EVIDENCE: Есть ли конкретные доказательства (response, screenshot, output)?
3. SECURITY IMPACT: Есть ли реальное влияние на безопасность (не просто informational)?
4. SCOPE: Находка в пределах скоупа программы?
5. SEVERITY: Severity корректно определена (не завышена/занижена)?
6. УНИКАЛЬНОСТЬ: Это не типичная false positive (scanner artifact, WAF block, default page)?
7. REPORT QUALITY: Описание достаточно для понимания и воспроизведения?

Формат ответа: ТОЛЬКО RAW JSON, без markdown-обёртки, без префиксов/постфиксов. Никаких тройных бэктиков, никаких fenced code-blockов.
{
  "questions": [
    {"question": "reproducibility", "passed": true, "detail": "..."},
    {"question": "evidence", "passed": true, "detail": "..."},
    {"question": "security_impact", "passed": true, "detail": "..."},
    {"question": "scope", "passed": true, "detail": "..."},
    {"question": "severity", "passed": true, "detail": "..."},
    {"question": "uniqueness", "passed": true, "detail": "..."},
    {"question": "report_quality", "passed": true, "detail": "..."}
  ],
  "overall_verdict": "PASS",
  "suggested_severity": "medium",
  "reasoning": "краткое обоснование общего вердикта"
}

Дополнительные правила:
- Если скоуп или программа неизвестны — ставь scope.passed: true (не блокируй из-за отсутствия информации о скоупе).
- detail — одно короткое предложение (≤120 символов).
- reasoning — 1-2 предложения максимум.`

// Evaluate runs the 7-Question Gate on a finding.
func (g *Gate) Evaluate(ctx context.Context, f *models.Finding) (*Result, error) {
	prompt := buildGatePrompt(f)

	req := &llm.Request{
		Messages: []llm.Message{
			{Role: llm.RoleSystem, Content: gateSystemPrompt},
			{Role: llm.RoleUser, Content: prompt},
		},
		MaxTokens:   2000,
		Temperature: 0.1,
		JSONMode:    true,
	}

	resp, err := g.client.Complete(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("gate: LLM call failed: %w", err)
	}

	return g.parseResponse(f.ID, resp.Content)
}

// EvaluateAlgorithmic runs the gate without LLM — uses heuristic checks.
// Useful as fallback when LLM is unavailable.
func (g *Gate) EvaluateAlgorithmic(f *models.Finding) *Result {
	result := &Result{
		FindingID: f.ID,
		MinScore:  g.minScore,
	}

	questions := [7]struct {
		name   string
		passed bool
		detail string
	}{
		{
			name:   "reproducibility",
			passed: f.URL != "" && f.Method != "",
			detail: boolDetail(f.URL != "" && f.Method != "", "URL and method present", "missing URL or method"),
		},
		{
			name:   "evidence",
			passed: f.ScannerEvidence != "" || f.NucleiTemplateID != "",
			detail: boolDetail(f.ScannerEvidence != "" || f.NucleiTemplateID != "", "scanner evidence or template ID present", "no evidence"),
		},
		{
			name:   "security_impact",
			passed: f.Severity != models.SeverityInfo,
			detail: boolDetail(f.Severity != models.SeverityInfo, "severity > info", "informational only"),
		},
		{
			name:   "scope",
			passed: f.Host != "" || true, // unknown scope → pass (don't block on missing scope info)
			detail: boolDetail(f.Host != "", "host is specified", "scope unknown — passing by default"),
		},
		{
			name:   "severity",
			passed: f.Severity != "" && f.Confidence > 0.3,
			detail: boolDetail(f.Confidence > 0.3, fmt.Sprintf("confidence %.0f%%", f.Confidence*100), "low confidence"),
		},
		{
			name:   "uniqueness",
			passed: f.Confidence > 0.5,
			detail: boolDetail(f.Confidence > 0.5, "analyst confidence > 50%", "likely false positive"),
		},
		{
			name:   "report_quality",
			passed: len(f.ReportMarkdown) > 100,
			detail: boolDetail(len(f.ReportMarkdown) > 100, fmt.Sprintf("report %d chars", len(f.ReportMarkdown)), "report too short or missing"),
		},
	}

	score := 0
	for i, q := range questions {
		result.Questions[i] = QuestionResult{
			Question: q.name,
			Passed:   q.passed,
			Detail:   q.detail,
		}
		if q.passed {
			score++
		}
	}
	result.Score = score

	switch {
	case score >= g.minScore:
		result.Verdict = VerdictPass
		result.Reasoning = fmt.Sprintf("passed %d/7 checks (threshold %d)", score, g.minScore)
	case score >= g.minScore-2:
		result.Verdict = VerdictDowngrade
		result.Reasoning = fmt.Sprintf("passed %d/7 checks — below threshold, consider downgrading severity", score)
		result.SuggestedSeverity = downgradeSeverity(f.Severity)
	default:
		result.Verdict = VerdictKill
		result.Reasoning = fmt.Sprintf("passed only %d/7 checks — not worth submitting", score)
	}

	g.log.Info("gate: algorithmic evaluation",
		"finding_id", f.ID,
		"verdict", result.Verdict,
		"score", result.Score,
	)

	return result
}

// EvaluateBatch runs the gate on multiple findings.
// Uses LLM when available, falls back to algorithmic.
func (g *Gate) EvaluateBatch(ctx context.Context, findings []*models.Finding) ([]*Result, error) {
	results := make([]*Result, 0, len(findings))
	for _, f := range findings {
		r, err := g.Evaluate(ctx, f)
		if err != nil {
			g.log.Warn("gate: LLM evaluation failed, using algorithmic fallback",
				"finding_id", f.ID, "error", err)
			r = g.EvaluateAlgorithmic(f)
		}
		results = append(results, r)
	}
	return results, nil
}

func (g *Gate) parseResponse(findingID, content string) (*Result, error) {
	result := &Result{
		FindingID: findingID,
		MinScore:  g.minScore,
	}

	var parsed struct {
		Questions []struct {
			Question string `json:"question"`
			Passed   bool   `json:"passed"`
			Detail   string `json:"detail"`
		} `json:"questions"`
		SuggestedSeverity string `json:"suggested_severity"`
		Reasoning         string `json:"reasoning"`
	}

	cleaned := extractJSON(content)
	if err := json.Unmarshal([]byte(cleaned), &parsed); err != nil {
		// Try truncation recovery: response may have been cut off by max_tokens.
		recovered := recoverTruncatedJSON(cleaned)
		if rerr := json.Unmarshal([]byte(recovered), &parsed); rerr != nil {
			return nil, fmt.Errorf("gate: failed to parse response: %w (recovery also failed: %v)", err, rerr)
		}
		g.log.Warn("gate: response was truncated, recovered partial JSON",
			"finding_id", findingID,
			"raw_len", len(content),
			"recovered_questions", len(parsed.Questions),
		)
	}

	score := 0
	for i := 0; i < 7 && i < len(parsed.Questions); i++ {
		result.Questions[i] = QuestionResult{
			Question: parsed.Questions[i].Question,
			Passed:   parsed.Questions[i].Passed,
			Detail:   parsed.Questions[i].Detail,
		}
		if parsed.Questions[i].Passed {
			score++
		}
	}

	result.Score = score
	result.SuggestedSeverity = parsed.SuggestedSeverity
	result.Reasoning = parsed.Reasoning

	switch {
	case score >= g.minScore:
		result.Verdict = VerdictPass
	case score >= g.minScore-2:
		result.Verdict = VerdictDowngrade
	default:
		result.Verdict = VerdictKill
	}

	g.log.Info("gate: LLM evaluation",
		"finding_id", findingID,
		"verdict", result.Verdict,
		"score", score,
	)

	return result, nil
}

func buildGatePrompt(f *models.Finding) string {
	var sb strings.Builder
	sb.WriteString("Оцени следующую находку по 7 вопросам:\n\n")
	sb.WriteString(fmt.Sprintf("URL: %s\n", f.URL))
	sb.WriteString(fmt.Sprintf("Method: %s\n", f.Method))
	sb.WriteString(fmt.Sprintf("Vuln Class: %s\n", f.VulnClass))
	sb.WriteString(fmt.Sprintf("Severity: %s\n", f.Severity))
	sb.WriteString(fmt.Sprintf("Confidence: %.0f%%\n", f.Confidence*100))

	if f.Hypothesis != "" {
		sb.WriteString(fmt.Sprintf("\nГипотеза аналитика:\n%s\n", f.Hypothesis))
	}
	if f.ReportMarkdown != "" {
		// Truncate report for context window
		report := f.ReportMarkdown
		if len(report) > 500 {
			report = report[:500] + "..."
		}
		sb.WriteString(fmt.Sprintf("\nОтчёт (фрагмент):\n%s\n", report))
	}

	return sb.String()
}

func boolDetail(b bool, trueMsg, falseMsg string) string {
	if b {
		return trueMsg
	}
	return falseMsg
}

func downgradeSeverity(s models.Severity) string {
	switch s {
	case models.SeverityCritical:
		return string(models.SeverityHigh)
	case models.SeverityHigh:
		return string(models.SeverityMedium)
	case models.SeverityMedium:
		return string(models.SeverityLow)
	default:
		return string(models.SeverityInfo)
	}
}

// recoverTruncatedJSON attempts to repair a JSON string that was cut off mid-
// generation (typically because the LLM hit max_tokens). It finds the last
// position where the brace/bracket stack is balanced and truncates the input
// to that point. This lets partial-but-structurally-valid responses still
// parse (e.g. a gate response with 5/7 questions captured before truncation).
func recoverTruncatedJSON(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{") && !strings.HasPrefix(s, "[") {
		return s
	}
	var stack []byte
	lastBalanced := -1
	inString := false
	escape := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escape {
			escape = false
			continue
		}
		if c == '\\' && inString {
			escape = true
			continue
		}
		if c == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		switch c {
		case '{', '[':
			stack = append(stack, c)
		case '}':
			if len(stack) > 0 && stack[len(stack)-1] == '{' {
				stack = stack[:len(stack)-1]
			}
			if len(stack) == 0 {
				lastBalanced = i
			}
		case ']':
			if len(stack) > 0 && stack[len(stack)-1] == '[' {
				stack = stack[:len(stack)-1]
			}
			if len(stack) == 0 {
				lastBalanced = i
			}
		}
	}
	if lastBalanced > 0 {
		return s[:lastBalanced+1]
	}
	// Truncated in the middle of an array — close open scopes pessimistically.
	if len(stack) > 0 {
		var closer []byte
		for i := len(stack) - 1; i >= 0; i-- {
			if stack[i] == '{' {
				closer = append(closer, '}')
			} else {
				closer = append(closer, ']')
			}
		}
		// Trim trailing dangling key/comma before closing.
		trimmed := strings.TrimRight(s, " \t\n\r,:")
		// If trimmed ends with a string-key (\"foo\"), drop it to avoid \"key\":}.
		if idx := strings.LastIndex(trimmed, ","); idx >= 0 {
			trimmed = trimmed[:idx]
		}
		return strings.TrimRight(trimmed, " \t\n\r,:") + string(closer)
	}
	return s
}

func extractJSON(s string) string {
	if idx := strings.Index(s, "```json"); idx >= 0 {
		s = s[idx+7:]
		if end := strings.Index(s, "```"); end >= 0 {
			return strings.TrimSpace(s[:end])
		}
	}
	if idx := strings.Index(s, "```"); idx >= 0 {
		s = s[idx+3:]
		if end := strings.Index(s, "```"); end >= 0 {
			return strings.TrimSpace(s[:end])
		}
	}
	if idx := strings.Index(s, "{"); idx >= 0 {
		if end := strings.LastIndex(s, "}"); end >= 0 {
			return s[idx : end+1]
		}
	}
	return s
}
