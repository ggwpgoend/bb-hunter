// Package reporter implements the Reporter LLM agent.
// It generates markdown vulnerability reports in Russian
// for submission to BB platforms (Standoff, BI.ZONE).
package reporter

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/llm"
	"github.com/ggwpgoend/bb-hunter/internal/models"
)

// Reporter generates vulnerability reports using an LLM.
type Reporter struct {
	client   *llm.Client
	platform string // "standoff", "bizone", "bugbountyru"
	log      *slog.Logger
}

// NewReporter creates a new Reporter agent.
func NewReporter(client *llm.Client, platform string, logger *slog.Logger) *Reporter {
	if logger == nil {
		logger = slog.Default()
	}
	return &Reporter{
		client:   client,
		platform: platform,
		log:      logger,
	}
}

const reportSystemPrompt = `Ты — профессиональный исследователь безопасности.
Твоя задача: написать отчёт об уязвимости для программы bug bounty на русском языке.

Платформа: %s

Отчёт должен быть в формате Markdown и содержать:

# Название уязвимости
Краткое описание (1 предложение)

## Описание
Подробное описание уязвимости: что она позволяет атакующему, в каком компоненте находится.

## Шаги воспроизведения
1. Шаг 1
2. Шаг 2
3. ...

## Ожидаемый результат
Что должно происходить в безопасной системе.

## Фактический результат
Что происходит сейчас (и почему это уязвимость).

## Влияние
Какой ущерб может нанести эксплуатация:
- Конфиденциальность
- Целостность
- Доступность

## Рекомендации по устранению
Конкретные технические рекомендации.

## Severity
Обоснование уровня критичности + CVSS вектор в формате:
CVSS:3.1/<vector_string> (X.X)

Правила:
- Пиши на русском языке
- Будь техничным и конкретным
- Не приукрашивай — объективно оценивай severity
- Включай конкретные URL, параметры, endpoints
- Безопасные canary payload'ы разрешены в отчёте (alert(1), sleep-based SQLi, canary-строки) — они показывают proof
- Не включай деструктивные или опасные payload'ы (eval, exec, cookie theft)
- Missing headers без контекста = info, не пиши длинный отчёт
- Всегда указывай CVSS:3.1 вектор в секции Severity
`

// GenerateReport creates a markdown report for a finding.
func (r *Reporter) GenerateReport(ctx context.Context, finding *models.Finding) (*models.Finding, error) {
	userMsg := buildReportPrompt(finding)

	req := &llm.Request{
		Messages: []llm.Message{
			{Role: llm.RoleSystem, Content: fmt.Sprintf(reportSystemPrompt, r.platform)},
			{Role: llm.RoleUser, Content: userMsg},
		},
		MaxTokens:   2048,
		Temperature: 0.3,
	}

	resp, err := r.client.Complete(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("reporter: LLM call failed: %w", err)
	}

	result := *finding
	result.ReportMarkdown = resp.Content
	result.Status = models.StatusReported
	result.UpdatedAt = time.Now()

	r.log.Info("reporter: generated report",
		"finding_id", result.ID,
		"vuln_class", result.VulnClass,
		"report_len", len(result.ReportMarkdown),
		"provider", resp.Provider,
		"tokens", resp.InputTokens+resp.OutputTokens,
	)

	return &result, nil
}

// GenerateReportBatch generates reports for multiple findings.
func (r *Reporter) GenerateReportBatch(ctx context.Context, findings []*models.Finding) ([]*models.Finding, error) {
	var results []*models.Finding
	for _, f := range findings {
		// Skip low-confidence or false positives
		if f.Status == models.StatusRejected {
			r.log.Debug("reporter: skipping rejected finding", "finding_id", f.ID)
			continue
		}
		if f.Confidence < 0.3 {
			r.log.Debug("reporter: skipping low-confidence finding",
				"finding_id", f.ID,
				"confidence", f.Confidence,
			)
			continue
		}

		result, err := r.GenerateReport(ctx, f)
		if err != nil {
			r.log.Error("reporter: batch item failed", "finding_id", f.ID, "error", err)
			continue
		}
		results = append(results, result)
	}
	return results, nil
}

func buildReportPrompt(f *models.Finding) string {
	var sb strings.Builder
	sb.WriteString("Напиши отчёт об уязвимости на основе следующих данных:\n\n")
	sb.WriteString(fmt.Sprintf("URL: %s\n", f.URL))
	sb.WriteString(fmt.Sprintf("Метод: %s\n", f.Method))
	sb.WriteString(fmt.Sprintf("Хост: %s\n", f.Host))
	sb.WriteString(fmt.Sprintf("Путь: %s\n", f.Path))

	if f.NucleiTemplateID != "" {
		sb.WriteString(fmt.Sprintf("Nuclei шаблон: %s\n", f.NucleiTemplateID))
	}
	if f.VulnClass != "" {
		sb.WriteString(fmt.Sprintf("Класс уязвимости: %s\n", f.VulnClass))
	}
	if f.Severity != "" {
		sb.WriteString(fmt.Sprintf("Severity: %s\n", f.Severity))
	}
	if f.Confidence > 0 {
		sb.WriteString(fmt.Sprintf("Уверенность: %.0f%%\n", f.Confidence*100))
	}
	if f.Hypothesis != "" {
		sb.WriteString(fmt.Sprintf("\nГипотеза аналитика:\n%s\n", f.Hypothesis))
	}
	if f.ScannerEvidence != "" {
		sb.WriteString(fmt.Sprintf("\nЕвиденс сканера:\n%s\n", f.ScannerEvidence))
	}
	if len(f.ParamNames) > 0 {
		sb.WriteString(fmt.Sprintf("Параметры: %s\n", strings.Join(f.ParamNames, ", ")))
	}

	return sb.String()
}
