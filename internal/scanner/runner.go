// Package scanner implements the recon pipeline:
// subfinder → httpx → katana → gau → nuclei
//
// All subprocess tools are routed through the egress proxy
// to enforce scope (P0 blocker #2).
package scanner

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// ToolPaths configures the paths to external recon tools.
type ToolPaths struct {
	Subfinder string
	Httpx     string
	Katana    string
	Gau       string
	Nuclei    string
	Naabu     string
}

// DefaultToolPaths returns tool paths assuming tools are in $PATH.
func DefaultToolPaths() ToolPaths {
	return ToolPaths{
		Subfinder: "subfinder",
		Httpx:     "httpx",
		Katana:    "katana",
		Gau:       "gau",
		Nuclei:    "nuclei",
		Naabu:     "naabu",
	}
}

// PipelineConfig configures the scanner pipeline.
type PipelineConfig struct {
	// Domains to scan (from scope.yaml)
	Domains []string

	// Proxy address for subprocess egress enforcement
	ProxyAddr string // e.g., "http://127.0.0.1:18080"

	// Rate limit (requests per second)
	RateLimit float64

	// Nuclei severity filter
	NucleiSeverity string // e.g., "medium,high,critical"

	// Katana depth (default 3 for MVP)
	KatanaDepth int

	// Tool paths
	Tools ToolPaths

	// Logger
	Logger *slog.Logger
}

// Pipeline executes the recon pipeline stages.
type Pipeline struct {
	cfg PipelineConfig
	log *slog.Logger
}

// NewPipeline creates a new scanner pipeline.
func NewPipeline(cfg PipelineConfig) *Pipeline {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.KatanaDepth <= 0 {
		cfg.KatanaDepth = 3
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 10
	}
	if cfg.NucleiSeverity == "" {
		cfg.NucleiSeverity = "medium,high,critical"
	}
	return &Pipeline{cfg: cfg, log: cfg.Logger}
}

// SubdomainResult contains the output of subdomain enumeration.
type SubdomainResult struct {
	Subdomains []string
	Duration   time.Duration
}

// HostResult contains a live host with metadata.
type HostResult struct {
	URL        string
	StatusCode int
	Title      string
	Tech       []string
}

// CrawlResult contains crawled URLs.
type CrawlResult struct {
	URLs     []string
	Duration time.Duration
}

// NucleiResult contains a single nuclei finding.
type NucleiResult struct {
	TemplateID string
	Name       string
	Severity   string
	URL        string
	Matched    string
	Evidence   string
	Timestamp  time.Time
}

// RunSubfinder enumerates subdomains for the configured domains.
func (p *Pipeline) RunSubfinder(ctx context.Context) (*SubdomainResult, error) {
	start := time.Now()
	p.log.Info("scanner: starting subfinder", "domains", p.cfg.Domains)

	args := []string{
		"-silent",
		"-all",
	}
	for _, d := range p.cfg.Domains {
		// Strip wildcard prefix for subfinder
		d = strings.TrimPrefix(d, "*.")
		args = append(args, "-d", d)
	}

	lines, err := p.runTool(ctx, p.cfg.Tools.Subfinder, args, false)
	if err != nil {
		return nil, fmt.Errorf("subfinder: %w", err)
	}

	result := &SubdomainResult{
		Subdomains: lines,
		Duration:   time.Since(start),
	}

	p.log.Info("scanner: subfinder complete",
		"subdomains", len(result.Subdomains),
		"duration", result.Duration,
	)
	return result, nil
}

// RunHttpx probes hosts for liveness and fingerprints them.
func (p *Pipeline) RunHttpx(ctx context.Context, hosts []string) ([]HostResult, error) {
	if len(hosts) == 0 {
		return nil, nil
	}

	p.log.Info("scanner: starting httpx", "hosts", len(hosts))

	args := []string{
		"-silent",
		"-status-code",
		"-title",
		"-tech-detect",
		"-rate-limit", fmt.Sprintf("%d", int(p.cfg.RateLimit)),
		"-no-color",
	}

	if p.cfg.ProxyAddr != "" {
		args = append(args, "-http-proxy", p.cfg.ProxyAddr)
	}

	lines, err := p.runToolWithStdin(ctx, p.cfg.Tools.Httpx, args, hosts)
	if err != nil {
		return nil, fmt.Errorf("httpx: %w", err)
	}

	var results []HostResult
	for _, line := range lines {
		hr := parseHttpxLine(line)
		if hr.URL != "" {
			results = append(results, hr)
		}
	}

	p.log.Info("scanner: httpx complete", "live_hosts", len(results))
	return results, nil
}

// RunKatana crawls live hosts to discover URLs and endpoints.
func (p *Pipeline) RunKatana(ctx context.Context, urls []string) (*CrawlResult, error) {
	if len(urls) == 0 {
		return &CrawlResult{}, nil
	}

	start := time.Now()
	p.log.Info("scanner: starting katana", "urls", len(urls))

	args := []string{
		"-silent",
		"-depth", fmt.Sprintf("%d", p.cfg.KatanaDepth),
		"-rate-limit", fmt.Sprintf("%d", int(p.cfg.RateLimit)),
		"-no-color",
	}

	if p.cfg.ProxyAddr != "" {
		args = append(args, "-proxy", p.cfg.ProxyAddr)
	}

	lines, err := p.runToolWithStdin(ctx, p.cfg.Tools.Katana, args, urls)
	if err != nil {
		return nil, fmt.Errorf("katana: %w", err)
	}

	result := &CrawlResult{
		URLs:     dedup(lines),
		Duration: time.Since(start),
	}

	p.log.Info("scanner: katana complete",
		"urls_found", len(result.URLs),
		"duration", result.Duration,
	)
	return result, nil
}

// RunGau fetches historical URLs from Wayback Machine and other sources.
func (p *Pipeline) RunGau(ctx context.Context, domains []string) (*CrawlResult, error) {
	if len(domains) == 0 {
		return &CrawlResult{}, nil
	}

	start := time.Now()
	p.log.Info("scanner: starting gau", "domains", len(domains))

	lines, err := p.runToolWithStdin(ctx, p.cfg.Tools.Gau, []string{"--subs"}, domains)
	if err != nil {
		return nil, fmt.Errorf("gau: %w", err)
	}

	result := &CrawlResult{
		URLs:     dedup(lines),
		Duration: time.Since(start),
	}

	p.log.Info("scanner: gau complete",
		"urls_found", len(result.URLs),
		"duration", result.Duration,
	)
	return result, nil
}

// RunNuclei scans URLs with nuclei templates.
func (p *Pipeline) RunNuclei(ctx context.Context, urls []string) ([]NucleiResult, error) {
	if len(urls) == 0 {
		return nil, nil
	}

	p.log.Info("scanner: starting nuclei", "urls", len(urls))

	args := []string{
		"-silent",
		"-severity", p.cfg.NucleiSeverity,
		"-rate-limit", fmt.Sprintf("%d", int(p.cfg.RateLimit)),
		"-no-color",
		"-jsonl",
	}

	if p.cfg.ProxyAddr != "" {
		args = append(args, "-proxy", p.cfg.ProxyAddr)
	}

	lines, err := p.runToolWithStdin(ctx, p.cfg.Tools.Nuclei, args, urls)
	if err != nil {
		return nil, fmt.Errorf("nuclei: %w", err)
	}

	var results []NucleiResult
	for _, line := range lines {
		nr, err := parseNucleiJSON(line)
		if err != nil {
			p.log.Warn("scanner: failed to parse nuclei output", "line", line, "error", err)
			continue
		}
		results = append(results, nr)
	}

	p.log.Info("scanner: nuclei complete", "findings", len(results))
	return results, nil
}

// runTool executes a tool and returns stdout lines.
func (p *Pipeline) runTool(ctx context.Context, tool string, args []string, useProxy bool) ([]string, error) {
	cmd := exec.CommandContext(ctx, tool, args...)

	if useProxy && p.cfg.ProxyAddr != "" {
		cmd.Env = append(cmd.Environ(),
			"HTTP_PROXY="+p.cfg.ProxyAddr,
			"HTTPS_PROXY="+p.cfg.ProxyAddr,
			"http_proxy="+p.cfg.ProxyAddr,
			"https_proxy="+p.cfg.ProxyAddr,
		)
	}

	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("exit %d: %s", exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return nil, err
	}

	return splitLines(string(out)), nil
}

// runToolWithStdin executes a tool, feeds stdin, and returns stdout lines.
func (p *Pipeline) runToolWithStdin(ctx context.Context, tool string, args []string, stdinLines []string) ([]string, error) {
	cmd := exec.CommandContext(ctx, tool, args...)

	if p.cfg.ProxyAddr != "" {
		cmd.Env = append(cmd.Environ(),
			"HTTP_PROXY="+p.cfg.ProxyAddr,
			"HTTPS_PROXY="+p.cfg.ProxyAddr,
			"http_proxy="+p.cfg.ProxyAddr,
			"https_proxy="+p.cfg.ProxyAddr,
		)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start: %w", err)
	}

	// Write stdin
	go func() {
		defer stdin.Close()
		for _, line := range stdinLines {
			fmt.Fprintln(stdin, line)
		}
	}()

	// Read stdout
	var lines []string
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB lines
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Some tools return non-zero on "no results" — not an error
			if exitErr.ExitCode() == 1 && len(lines) == 0 {
				return nil, nil
			}
			return lines, fmt.Errorf("exit %d: %s", exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return lines, err
	}

	return lines, nil
}

// splitLines splits output into non-empty lines.
func splitLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// dedup removes duplicate strings preserving order.
func dedup(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	var result []string
	for _, item := range items {
		if _, ok := seen[item]; !ok {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}
