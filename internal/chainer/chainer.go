// Package chainer implements the Exploit Chain Builder.
//
// Borrowed concept: pentest-agents' exploit chain builder with 12 patterns.
// Given a set of findings, identifies possible multi-step exploit chains
// where individual low/medium findings combine into high/critical impact.
//
// Example chains:
//   - SSRF → Internal API Access → RCE
//   - XSS → CSRF → Account Takeover
//   - Open Redirect → OAuth Token Theft
//   - IDOR → PII Leak → Account Enumeration
package chainer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ggwpgoend/bb-hunter/internal/llm"
	"github.com/ggwpgoend/bb-hunter/internal/models"
)

// Chain represents a multi-step exploit chain.
type Chain struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Steps       []ChainStep  `json:"steps"`
	Impact      string       `json:"impact"`       // overall impact description
	Severity    string       `json:"severity"`      // combined severity (usually higher than individual)
	Confidence  float64      `json:"confidence"`    // 0.0–1.0
	Priority    int          `json:"priority"`      // 1=critical, 2=interesting, 3=informational
	PatternUsed string       `json:"pattern_used"`  // which known pattern matched
}

// ChainStep is one step in an exploit chain.
type ChainStep struct {
	Order     int    `json:"order"`
	FindingID string `json:"finding_id"`
	VulnClass string `json:"vuln_class"`
	URL       string `json:"url"`
	Action    string `json:"action"` // what the attacker does at this step
}

// Pattern defines a known exploit chain pattern.
type Pattern struct {
	Name     string   // human-readable name
	Steps    []string // ordered vuln classes (e.g., ["ssrf", "rce"])
	Severity string   // resulting severity when chain completes
	Impact   string   // impact description
}

// KnownPatterns is the built-in library of exploit chain patterns.
// Borrowed from pentest-agents' 12 chain patterns + additions.
var KnownPatterns = []Pattern{
	{
		Name:     "SSRF → Internal API → RCE",
		Steps:    []string{"ssrf", "rce"},
		Severity: "critical",
		Impact:   "SSRF allows access to internal services, leading to remote code execution",
	},
	{
		Name:     "SSRF → Cloud Metadata → Credential Theft",
		Steps:    []string{"ssrf", "info_disclosure"},
		Severity: "critical",
		Impact:   "SSRF to cloud metadata endpoint exposes IAM credentials",
	},
	{
		Name:     "XSS → CSRF → Account Takeover",
		Steps:    []string{"xss", "csrf"},
		Severity: "high",
		Impact:   "Stored/Reflected XSS bypasses CSRF protection for account takeover",
	},
	{
		Name:     "XSS → Session Hijacking",
		Steps:    []string{"xss", "auth_bypass"},
		Severity: "high",
		Impact:   "XSS steals session tokens, allowing authentication bypass",
	},
	{
		Name:     "IDOR → PII Leak → Account Enumeration",
		Steps:    []string{"idor", "info_disclosure"},
		Severity: "high",
		Impact:   "IDOR exposes personal data enabling mass enumeration",
	},
	{
		Name:     "Open Redirect → OAuth Token Theft",
		Steps:    []string{"open_redirect", "auth_bypass"},
		Severity: "high",
		Impact:   "Open redirect in OAuth callback steals authorization tokens",
	},
	{
		Name:     "LFI → Source Code Disclosure → Auth Bypass",
		Steps:    []string{"lfi", "auth_bypass"},
		Severity: "critical",
		Impact:   "Local file inclusion reveals source code with hardcoded secrets",
	},
	{
		Name:     "LFI → RCE via Log Poisoning",
		Steps:    []string{"lfi", "rce"},
		Severity: "critical",
		Impact:   "LFI combined with log poisoning achieves remote code execution",
	},
	{
		Name:     "SQLi → Auth Bypass → Admin Access",
		Steps:    []string{"sqli", "auth_bypass"},
		Severity: "critical",
		Impact:   "SQL injection bypasses authentication for admin-level access",
	},
	{
		Name:     "SQLi → Data Exfiltration",
		Steps:    []string{"sqli", "info_disclosure"},
		Severity: "critical",
		Impact:   "SQL injection enables bulk extraction of sensitive data",
	},
	{
		Name:     "Misconfig → Info Disclosure → Further Exploitation",
		Steps:    []string{"misconfig", "info_disclosure"},
		Severity: "medium",
		Impact:   "Misconfiguration exposes debug info enabling deeper attacks",
	},
	{
		Name:     "Open Redirect → XSS via JavaScript URI",
		Steps:    []string{"open_redirect", "xss"},
		Severity: "high",
		Impact:   "Open redirect accepting javascript: URIs enables XSS",
	},
}

// Chainer analyzes findings for possible exploit chains.
type Chainer struct {
	client *llm.Client
	log    *slog.Logger
}

// NewChainer creates a new Exploit Chain Builder.
func NewChainer(client *llm.Client, logger *slog.Logger) *Chainer {
	if logger == nil {
		logger = slog.Default()
	}
	return &Chainer{client: client, log: logger}
}

// FindChains identifies exploit chains from a set of findings.
// First uses algorithmic pattern matching, then optionally uses LLM
// for more creative chain discovery.
func (c *Chainer) FindChains(ctx context.Context, findings []*models.Finding) ([]Chain, error) {
	// Step 1: Algorithmic pattern matching
	chains := c.findAlgorithmic(findings)

	// Step 2: LLM-based creative chain discovery (if client available and findings exist)
	if c.client != nil && len(findings) >= 2 {
		llmChains, err := c.findWithLLM(ctx, findings)
		if err != nil {
			c.log.Warn("chainer: LLM chain discovery failed, using algorithmic only", "error", err)
		} else {
			chains = append(chains, llmChains...)
		}
	}

	// Deduplicate chains
	chains = deduplicateChains(chains)

	c.log.Info("chainer: chain analysis complete", "chains_found", len(chains))
	return chains, nil
}

// FindChainsAlgorithmic identifies chains using only pattern matching (no LLM).
func (c *Chainer) FindChainsAlgorithmic(findings []*models.Finding) []Chain {
	chains := c.findAlgorithmic(findings)
	c.log.Info("chainer: algorithmic analysis complete", "chains_found", len(chains))
	return chains
}

// findAlgorithmic matches findings against known patterns.
func (c *Chainer) findAlgorithmic(findings []*models.Finding) []Chain {
	if len(findings) < 2 {
		return nil
	}

	// Index findings by vuln class
	byClass := make(map[string][]*models.Finding)
	for _, f := range findings {
		cls := strings.ToLower(string(f.VulnClass))
		if cls != "" {
			byClass[cls] = append(byClass[cls], f)
		}
	}

	// Index findings by host for same-target chain validation
	byHost := make(map[string][]*models.Finding)
	for _, f := range findings {
		if f.Host != "" {
			byHost[f.Host] = append(byHost[f.Host], f)
		}
	}

	var chains []Chain
	chainID := 0

	for _, pattern := range KnownPatterns {
		// Check if all steps of the pattern are present
		var stepFindings [][]*models.Finding
		allPresent := true
		for _, stepClass := range pattern.Steps {
			fs, ok := byClass[stepClass]
			if !ok || len(fs) == 0 {
				allPresent = false
				break
			}
			stepFindings = append(stepFindings, fs)
		}

		if !allPresent {
			continue
		}

		// Try to build chains with findings on the same host (stronger signal)
		for _, f1 := range stepFindings[0] {
			for _, f2 := range stepFindings[len(stepFindings)-1] {
				if f1.ID == f2.ID {
					continue
				}

				sameOrg := sameOrganization(f1.Host, f2.Host)
				confidence := 0.4
				if f1.Host == f2.Host {
					confidence = 0.75
				} else if sameOrg {
					confidence = 0.6
				}

				chainID++
				priority := inferPriority(pattern.Severity)
				chain := Chain{
					ID:          fmt.Sprintf("chain-%d", chainID),
					Name:        pattern.Name,
					Severity:    pattern.Severity,
					Impact:      pattern.Impact,
					Confidence:  confidence,
					Priority:    priority,
					PatternUsed: pattern.Name,
				}

				for i, stepClass := range pattern.Steps {
					f := stepFindings[i][0]
					if i == 0 {
						f = f1
					} else if i == len(pattern.Steps)-1 {
						f = f2
					}
					chain.Steps = append(chain.Steps, ChainStep{
						Order:     i + 1,
						FindingID: f.ID,
						VulnClass: stepClass,
						URL:       f.URL,
						Action:    fmt.Sprintf("Step %d: exploit %s at %s", i+1, stepClass, f.URL),
					})
				}

				chains = append(chains, chain)

				// Only generate one chain per pattern per host pair
				break
			}
			break
		}
	}

	return chains
}

const chainerSystemPrompt = `Ты — эксперт по exploit chain building для bug bounty.
Твоя задача: найти возможные цепочки эксплуатации (exploit chains) из набора отдельных уязвимостей.

Правила:
1. Цепочка должна состоять из 2+ шагов
2. Каждый шаг использует реальную найденную уязвимость
3. Цепочка должна увеличивать общий impact относительно каждой уязвимости по отдельности
4. Уязвимости в рамках одной организации (same organization) допустимы — кросс-субдоменные цепочки валидны (например, admin.example.com → api.example.com)
5. Будь реалистичен — не выдумывай цепочки которые нельзя выполнить

Формат ответа (JSON массив):
[
  {
    "name": "SSRF → Internal API → RCE",
    "steps": [
      {"order": 1, "finding_id": "f-xxx", "vuln_class": "ssrf", "action": "Use SSRF to reach internal API"},
      {"order": 2, "finding_id": "f-yyy", "vuln_class": "rce", "action": "Execute code via internal API"}
    ],
    "impact": "Full remote code execution via SSRF chain",
    "severity": "critical",
    "confidence": 0.5,
    "priority": 1
  }
]

Поле priority:
- 1 = critical chain (непосредственная угроза, high/critical impact)
- 2 = interesting (стоит проверить, medium impact)
- 3 = informational (теоретически возможно, low impact)

confidence — оценивай реалистично на основе доказательств. Не привязывайся к какому-то одному значению.

Если цепочек нет — верни пустой массив [].`

func (c *Chainer) findWithLLM(ctx context.Context, findings []*models.Finding) ([]Chain, error) {
	prompt := buildChainerPrompt(findings)

	req := &llm.Request{
		Messages: []llm.Message{
			{Role: llm.RoleSystem, Content: chainerSystemPrompt},
			{Role: llm.RoleUser, Content: prompt},
		},
		MaxTokens:   1024,
		Temperature: 0.3,
		JSONMode:    true,
	}

	resp, err := c.client.Complete(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("chainer: LLM call failed: %w", err)
	}

	return parseChainerResponse(resp.Content)
}

func buildChainerPrompt(findings []*models.Finding) string {
	var sb strings.Builder
	sb.WriteString("Проанализируй следующие уязвимости и найди возможные exploit chains:\n\n")

	for _, f := range findings {
		sb.WriteString(fmt.Sprintf("- ID: %s | Host: %s | URL: %s | Class: %s | Severity: %s",
			f.ID, f.Host, f.URL, f.VulnClass, f.Severity))
		if f.Hypothesis != "" {
			sb.WriteString(fmt.Sprintf(" | Hypothesis: %s", f.Hypothesis))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func parseChainerResponse(content string) ([]Chain, error) {
	cleaned := extractJSON(content)

	var parsed []struct {
		Name   string `json:"name"`
		Steps  []struct {
			Order     int    `json:"order"`
			FindingID string `json:"finding_id"`
			VulnClass string `json:"vuln_class"`
			Action    string `json:"action"`
		} `json:"steps"`
		Impact     string  `json:"impact"`
		Severity   string  `json:"severity"`
		Confidence float64 `json:"confidence"`
	}

	if err := json.Unmarshal([]byte(cleaned), &parsed); err != nil {
		return nil, fmt.Errorf("chainer: failed to parse response: %w", err)
	}

	var chains []Chain
	for i, p := range parsed {
		chain := Chain{
			ID:         fmt.Sprintf("llm-chain-%d", i+1),
			Name:       p.Name,
			Impact:     p.Impact,
			Severity:   p.Severity,
			Confidence: p.Confidence,
		}
		for _, s := range p.Steps {
			chain.Steps = append(chain.Steps, ChainStep{
				Order:     s.Order,
				FindingID: s.FindingID,
				VulnClass: s.VulnClass,
				Action:    s.Action,
			})
		}
		chains = append(chains, chain)
	}

	return chains, nil
}

func deduplicateChains(chains []Chain) []Chain {
	seen := make(map[string]struct{})
	var result []Chain

	for _, c := range chains {
		key := c.Name
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, c)
		}
	}

	return result
}

// sameOrganization returns true if two hosts belong to the same organization
// (i.e. share the same registered domain, allowing cross-subdomain chains).
func sameOrganization(h1, h2 string) bool {
	if h1 == "" || h2 == "" {
		return false
	}
	return baseDomain(h1) == baseDomain(h2)
}

// baseDomain extracts the registered domain from a host (e.g. "api.example.com" → "example.com").
func baseDomain(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// inferPriority maps a severity string to a priority level.
func inferPriority(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 1
	case "high":
		return 1
	case "medium":
		return 2
	default:
		return 3
	}
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
	if idx := strings.Index(s, "["); idx >= 0 {
		if end := strings.LastIndex(s, "]"); end >= 0 {
			return s[idx : end+1]
		}
	}
	return s
}
