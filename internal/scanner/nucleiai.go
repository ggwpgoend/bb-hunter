// nucleiai.go adds nuclei -ai support for dynamic template generation.
//
// Borrowed concept: ProjectDiscovery's nuclei -ai flag.
// Instead of relying only on pre-built templates, this generates
// context-specific nuclei templates using AI, then runs them against targets.
// Useful for non-standard findings where standard templates miss the vuln.
package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// NucleiAIConfig configures nuclei -ai scanning.
type NucleiAIConfig struct {
	NucleiPath string
	ProxyAddr  string
	RateLimit  float64
	Logger     *slog.Logger
}

// NucleiAIRunner runs nuclei with -ai flag for dynamic template generation.
type NucleiAIRunner struct {
	cfg NucleiAIConfig
	log *slog.Logger
}

// NewNucleiAIRunner creates a new nuclei -ai runner.
func NewNucleiAIRunner(cfg NucleiAIConfig) *NucleiAIRunner {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.NucleiPath == "" {
		cfg.NucleiPath = "nuclei"
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 5
	}
	return &NucleiAIRunner{cfg: cfg, log: cfg.Logger}
}

// AIPrompt describes what to check for with nuclei -ai.
type AIPrompt struct {
	Description string // e.g., "check for SSRF via redirect parameter"
	TargetURLs  []string
}

// AIResult contains the output of a nuclei -ai scan.
type AIResult struct {
	Prompt   string        `json:"prompt"`
	Findings []NucleiResult `json:"findings"`
	Duration time.Duration  `json:"duration"`
	Error    string        `json:"error,omitempty"`
}

// Run executes nuclei -ai with the given prompt against target URLs.
func (r *NucleiAIRunner) Run(ctx context.Context, prompt AIPrompt) (*AIResult, error) {
	if len(prompt.TargetURLs) == 0 {
		return &AIResult{Prompt: prompt.Description}, nil
	}

	start := time.Now()
	r.log.Info("nuclei-ai: starting",
		"prompt", prompt.Description,
		"targets", len(prompt.TargetURLs),
	)

	args := []string{
		"-ai", prompt.Description,
		"-silent",
		"-rate-limit", fmt.Sprintf("%d", int(r.cfg.RateLimit)),
		"-no-color",
		"-jsonl",
	}

	if r.cfg.ProxyAddr != "" {
		args = append(args, "-proxy", r.cfg.ProxyAddr)
	}

	p := &Pipeline{
		cfg: PipelineConfig{
			ProxyAddr: r.cfg.ProxyAddr,
			Tools:     ToolPaths{Nuclei: r.cfg.NucleiPath},
		},
		log: r.log,
	}

	lines, err := p.runToolWithStdin(ctx, r.cfg.NucleiPath, args, prompt.TargetURLs)

	result := &AIResult{
		Prompt:   prompt.Description,
		Duration: time.Since(start),
	}

	if err != nil {
		result.Error = err.Error()
		r.log.Warn("nuclei-ai: execution error", "error", err)
		// Don't fail — return partial results
	}

	for _, line := range lines {
		nr, parseErr := parseNucleiJSON(line)
		if parseErr != nil {
			r.log.Debug("nuclei-ai: failed to parse line", "line", line)
			continue
		}
		result.Findings = append(result.Findings, nr)
	}

	r.log.Info("nuclei-ai: complete",
		"prompt", prompt.Description,
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

// GeneratePrompts creates nuclei -ai prompts based on analyst findings.
// This is the bridge between Analyst output and nuclei -ai input.
func GeneratePrompts(findings []AnalystHint) []AIPrompt {
	var prompts []AIPrompt

	for _, hint := range findings {
		if hint.Prompt == "" || len(hint.URLs) == 0 {
			continue
		}
		prompts = append(prompts, AIPrompt{
			Description: hint.Prompt,
			TargetURLs:  hint.URLs,
		})
	}

	return prompts
}

// AnalystHint is a suggestion from the Analyst for deeper nuclei -ai scanning.
type AnalystHint struct {
	VulnClass string
	Prompt    string   // nuclei -ai prompt text
	URLs      []string // target URLs
}

// DefaultHints generates standard nuclei -ai prompts based on vuln class.
func DefaultHints(vulnClass, url string) *AnalystHint {
	promptMap := map[string]string{
		"xss":             "check for reflected and stored XSS via user input parameters",
		"sqli":            "check for SQL injection via query parameters and form fields",
		"ssrf":            "check for SSRF via redirect, url, and callback parameters",
		"idor":            "check for insecure direct object references in API endpoints",
		"auth_bypass":     "check for authentication bypass via header manipulation and path traversal",
		"info_disclosure": "check for sensitive information disclosure in response headers and error pages",
		"rce":             "check for remote code execution via command injection in parameters",
		"lfi":             "check for local file inclusion via path parameters",
		"open_redirect":   "check for open redirect via url and redirect parameters",
		"csrf":            "check for missing CSRF tokens on state-changing endpoints",
		"misconfig":       "check for security misconfigurations in headers, CORS, and server settings",
	}

	prompt, ok := promptMap[strings.ToLower(vulnClass)]
	if !ok {
		return nil
	}

	return &AnalystHint{
		VulnClass: vulnClass,
		Prompt:    prompt,
		URLs:      []string{url},
	}
}
