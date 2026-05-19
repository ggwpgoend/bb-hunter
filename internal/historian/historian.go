// Package historian implements the Historian LLM agent.
// It analyzes diff results between scan runs to provide
// strategic insights: trends, regressions, patched vulns,
// and priority recommendations.
package historian

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/differ"
	"github.com/ggwpgoend/bb-hunter/internal/llm"
)

// Historian analyzes scan diffs using an LLM.
type Historian struct {
	client *llm.Client
	log    *slog.Logger
}

// NewHistorian creates a new Historian agent.
func NewHistorian(client *llm.Client, logger *slog.Logger) *Historian {
	if logger == nil {
		logger = slog.Default()
	}
	return &Historian{
		client: client,
		log:    logger,
	}
}

// Analysis is the Historian's output for a diff.
type Analysis struct {
	Summary      string    `json:"summary"`       // high-level summary in Russian
	Trends       []string  `json:"trends"`         // observed trends
	Priorities   []string  `json:"priorities"`     // recommended priorities
	RiskLevel    string    `json:"risk_level"`     // overall risk: low/medium/high/critical
	AnalyzedAt   time.Time `json:"analyzed_at"`
	Provider     string    `json:"provider"`
	InputTokens  int       `json:"input_tokens"`
	OutputTokens int       `json:"output_tokens"`
}

const historianSystemPrompt = `Ты — аналитик безопасности, отслеживающий изменения между сканами bug bounty программы.

Тебе предоставляется diff между двумя сканами. Проанализируй изменения и дай:

1. **Краткий обзор** (2-3 предложения) — что изменилось между сканами
2. **Тренды** — паттерны: растёт ли количество уязвимостей, какие классы появляются/исчезают
3. **Приоритеты** — на что стоит обратить внимание в первую очередь
4. **Уровень риска** — общая оценка: low, medium, high, critical

Правила:
1. Пиши на русском
2. Будь конкретным: указывай URL, классы уязвимостей, severity
3. Если уязвимость исчезла — возможно, её пропатчили (отметь как позитивный тренд)
4. Новые critical/high уязвимости = повышение уровня риска
5. Регрессии: если уязвимость исчезла в предыдущем diff'е, а теперь снова появилась — это РЕГРЕССИЯ. Отмечай такие случаи отдельно с пометкой "[РЕГРЕССИЯ]" и повышай priority. Примеры: auth bypass вернулся после CSRF-token fix, XSS снова доступен после санитизации
6. Если нет значимых изменений — так и пиши, не выдумывай
`

// Analyze processes a diff result and produces strategic analysis.
func (h *Historian) Analyze(ctx context.Context, diff *differ.DiffResult) (*Analysis, error) {
	prompt := buildDiffPrompt(diff)

	req := &llm.Request{
		Messages: []llm.Message{
			{Role: llm.RoleSystem, Content: historianSystemPrompt},
			{Role: llm.RoleUser, Content: prompt},
		},
		MaxTokens:   1024,
		Temperature: 0.3,
	}

	resp, err := h.client.Complete(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("historian: LLM call failed: %w", err)
	}

	analysis := &Analysis{
		Summary:      resp.Content,
		AnalyzedAt:   time.Now(),
		Provider:     resp.Provider,
		InputTokens:  resp.InputTokens,
		OutputTokens: resp.OutputTokens,
		RiskLevel:    inferRiskLevel(diff),
	}

	h.log.Info("historian: analysis complete",
		"previous_run", diff.PreviousRunID,
		"current_run", diff.CurrentRunID,
		"new", diff.NewCount,
		"gone", diff.GoneCount,
		"changed", diff.ChangedCount,
		"risk_level", analysis.RiskLevel,
		"provider", resp.Provider,
	)

	return analysis, nil
}

// AnalyzeWithoutLLM produces a purely algorithmic analysis
// when LLM is unavailable or unnecessary (e.g., no changes).
func (h *Historian) AnalyzeWithoutLLM(diff *differ.DiffResult) *Analysis {
	var summary strings.Builder

	summary.WriteString(fmt.Sprintf("Сравнение сканов %s → %s: ", diff.PreviousRunID, diff.CurrentRunID))

	total := diff.NewCount + diff.GoneCount + diff.ChangedCount + diff.UnchangedCount
	if total == 0 {
		summary.WriteString("нет данных для анализа.")
		return &Analysis{
			Summary:    summary.String(),
			RiskLevel:  "low",
			AnalyzedAt: time.Now(),
		}
	}

	parts := []string{}
	if diff.NewCount > 0 {
		parts = append(parts, fmt.Sprintf("%d новых", diff.NewCount))
	}
	if diff.GoneCount > 0 {
		parts = append(parts, fmt.Sprintf("%d исчезнувших", diff.GoneCount))
	}
	if diff.ChangedCount > 0 {
		parts = append(parts, fmt.Sprintf("%d изменённых", diff.ChangedCount))
	}
	if diff.UnchangedCount > 0 {
		parts = append(parts, fmt.Sprintf("%d без изменений", diff.UnchangedCount))
	}
	summary.WriteString(strings.Join(parts, ", ") + ".")

	var trends []string
	var priorities []string

	// Analyze new findings by severity
	newHighCrit := 0
	for _, e := range diff.Entries {
		if e.ChangeType == differ.ChangeNew && e.Current != nil {
			switch e.Current.Severity {
			case "high", "critical":
				newHighCrit++
				priorities = append(priorities, fmt.Sprintf("[%s] %s — %s (%s)",
					e.Current.Severity, e.Current.URL, e.Current.VulnClass, e.Current.NucleiTemplateID))
			}
		}
	}

	if newHighCrit > 0 {
		trends = append(trends, fmt.Sprintf("%d новых high/critical находок", newHighCrit))
	}
	if diff.GoneCount > 0 {
		trends = append(trends, fmt.Sprintf("%d уязвимостей исчезло (возможно, пропатчены)", diff.GoneCount))
	}
	if diff.NewCount > diff.GoneCount {
		trends = append(trends, "поверхность атаки увеличивается")
	} else if diff.GoneCount > diff.NewCount {
		trends = append(trends, "поверхность атаки сокращается (позитивный тренд)")
	}

	return &Analysis{
		Summary:    summary.String(),
		Trends:     trends,
		Priorities: priorities,
		RiskLevel:  inferRiskLevel(diff),
		AnalyzedAt: time.Now(),
	}
}

// inferRiskLevel derives risk level from diff statistics.
func inferRiskLevel(diff *differ.DiffResult) string {
	critCount := 0
	highCount := 0

	for _, e := range diff.Entries {
		if e.ChangeType == differ.ChangeNew && e.Current != nil {
			switch e.Current.Severity {
			case "critical":
				critCount++
			case "high":
				highCount++
			}
		}
	}

	switch {
	case critCount > 0:
		return "critical"
	case highCount >= 3:
		return "high"
	case highCount > 0 || diff.NewCount > 10:
		return "medium"
	default:
		return "low"
	}
}

func buildDiffPrompt(diff *differ.DiffResult) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Diff между сканами: %s → %s\n\n", diff.PreviousRunID, diff.CurrentRunID))
	sb.WriteString(fmt.Sprintf("Итого: %d новых, %d исчезнувших, %d изменённых, %d без изменений\n\n",
		diff.NewCount, diff.GoneCount, diff.ChangedCount, diff.UnchangedCount))

	if diff.NewCount > 0 {
		sb.WriteString("=== НОВЫЕ НАХОДКИ ===\n")
		for _, e := range diff.Entries {
			if e.ChangeType == differ.ChangeNew && e.Current != nil {
				sb.WriteString(fmt.Sprintf("- [%s] %s — %s (confidence: %.0f%%)\n",
					e.Current.Severity, e.Current.URL, e.Current.VulnClass, e.Current.Confidence*100))
			}
		}
		sb.WriteString("\n")
	}

	if diff.GoneCount > 0 {
		sb.WriteString("=== ИСЧЕЗНУВШИЕ ===\n")
		for _, e := range diff.Entries {
			if e.ChangeType == differ.ChangeGone && e.Previous != nil {
				sb.WriteString(fmt.Sprintf("- [%s] %s — %s\n",
					e.Previous.Severity, e.Previous.URL, e.Previous.VulnClass))
			}
		}
		sb.WriteString("\n")
	}

	if diff.ChangedCount > 0 {
		sb.WriteString("=== ИЗМЕНЁННЫЕ ===\n")
		for _, e := range diff.Entries {
			if e.ChangeType == differ.ChangeChanged && e.Previous != nil && e.Current != nil {
				sb.WriteString(fmt.Sprintf("- %s: %s/%s → %s/%s\n",
					e.FindingKey,
					e.Previous.Severity, e.Previous.VulnClass,
					e.Current.Severity, e.Current.VulnClass))
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
