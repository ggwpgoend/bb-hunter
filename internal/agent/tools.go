package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ToolDef describes a tool available to the agent.
type ToolDef struct {
	Name        string
	Description string
	Args        string // human-readable argument description
}

// AllTools returns the full list of tools available to the agent.
func AllTools() []ToolDef {
	return []ToolDef{
		{Name: "browser_open", Description: "Open a URL in headless browser", Args: "<url>"},
		{Name: "browser_screenshot", Description: "Take a screenshot of current page", Args: "<filename>"},
		{Name: "browser_eval", Description: "Execute JavaScript in browser and return result", Args: "<javascript_code>"},
		{Name: "browser_snapshot", Description: "Get DOM accessibility tree / page text content", Args: ""},
		{Name: "browser_click", Description: "Click an element by CSS selector", Args: "<css_selector>"},
		{Name: "browser_type", Description: "Type text into an input field", Args: "<css_selector> <text>"},
		{Name: "http_get", Description: "Send HTTP GET request and return response headers + body (truncated)", Args: "<url>"},
		{Name: "http_raw", Description: "Send raw HTTP request with custom method/headers/body", Args: "<method> <url> [header:value ...] [body:data]"},
		{Name: "run_nuclei", Description: "Run nuclei scanner on a URL with optional template filter", Args: "<url> [template_filter]"},
		{Name: "run_subfinder", Description: "Enumerate subdomains for a domain", Args: "<domain>"},
		{Name: "run_httpx", Description: "Probe hosts for live HTTP services", Args: "<host1,host2,...>"},
		{Name: "run_katana", Description: "Crawl a URL and discover endpoints", Args: "<url> [depth]"},
		{Name: "run_cmd", Description: "Run an arbitrary shell command (recon only, no destructive ops)", Args: "<command>"},
		{Name: "report_finding", Description: "Report a discovered vulnerability", Args: "<json: {vuln_class, severity, url, description, evidence}>"},
		{Name: "done", Description: "Finish the agent session and summarize results", Args: "[summary]"},
	}
}

// ToolsPrompt returns a formatted string listing all tools for the system prompt.
func ToolsPrompt() string {
	var sb strings.Builder
	sb.WriteString("Available tools:\n\n")
	for _, t := range AllTools() {
		sb.WriteString(fmt.Sprintf("  %s %s\n    %s\n\n", t.Name, t.Args, t.Description))
	}
	return sb.String()
}

// ToolExecutor runs tools and returns observations.
type ToolExecutor struct {
	agentBrowserBin string
	screenshotDir   string
	proxyAddr       string
	httpClient      *http.Client
	findings        []Finding
}

// Finding is a vulnerability discovered by the agent.
type Finding struct {
	VulnClass   string `json:"vuln_class"`
	Severity    string `json:"severity"`
	URL         string `json:"url"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
}

// NewToolExecutor creates a tool executor.
func NewToolExecutor(agentBrowserBin, screenshotDir, proxyAddr string) *ToolExecutor {
	if agentBrowserBin == "" {
		agentBrowserBin = "agent-browser"
	}
	if screenshotDir == "" {
		screenshotDir = "screenshots"
	}
	return &ToolExecutor{
		agentBrowserBin: agentBrowserBin,
		screenshotDir:   screenshotDir,
		proxyAddr:       proxyAddr,
		httpClient:      &http.Client{Timeout: 30 * time.Second},
	}
}

// Findings returns all reported findings.
func (te *ToolExecutor) Findings() []Finding {
	return te.findings
}

// Execute runs a tool and returns the observation string.
func (te *ToolExecutor) Execute(ctx context.Context, tool, args string) string {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	switch tool {
	case "browser_open":
		return te.browserOpen(ctx, args)
	case "browser_screenshot":
		return te.browserScreenshot(ctx, args)
	case "browser_eval":
		return te.browserEval(ctx, args)
	case "browser_snapshot":
		return te.browserSnapshot(ctx)
	case "browser_click":
		return te.browserClick(ctx, args)
	case "browser_type":
		return te.browserType(ctx, args)
	case "http_get":
		return te.httpGet(ctx, args)
	case "http_raw":
		return te.httpRaw(ctx, args)
	case "run_nuclei":
		return te.runNuclei(ctx, args)
	case "run_subfinder":
		return te.runSubfinder(ctx, args)
	case "run_httpx":
		return te.runHttpx(ctx, args)
	case "run_katana":
		return te.runKatana(ctx, args)
	case "run_cmd":
		return te.runCmd(ctx, args)
	case "report_finding":
		return te.reportFinding(args)
	case "done":
		return "DONE"
	default:
		return fmt.Sprintf("ERROR: unknown tool '%s'. Use one of the available tools.", tool)
	}
}

// Browser tools — delegate to agent-browser CLI.

func (te *ToolExecutor) browserOpen(ctx context.Context, url string) string {
	url = strings.TrimSpace(url)
	if url == "" {
		return "ERROR: url is required"
	}
	out, err := te.runBrowserCmd(ctx, "open", url)
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	if out == "" {
		return fmt.Sprintf("OK: opened %s", url)
	}
	return truncate(out, 2000)
}

func (te *ToolExecutor) browserScreenshot(ctx context.Context, filename string) string {
	filename = strings.TrimSpace(filename)
	if filename == "" {
		filename = fmt.Sprintf("screenshot_%d.png", time.Now().UnixMilli())
	}
	path := filepath.Join(te.screenshotDir, filename)
	_ = os.MkdirAll(te.screenshotDir, 0o755)

	_, err := te.runBrowserCmd(ctx, "screenshot", path)
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	return fmt.Sprintf("OK: screenshot saved to %s", path)
}

func (te *ToolExecutor) browserEval(ctx context.Context, js string) string {
	js = strings.TrimSpace(js)
	if js == "" {
		return "ERROR: javascript code is required"
	}
	out, err := te.runBrowserCmd(ctx, "eval", js)
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	return truncate(out, 3000)
}

func (te *ToolExecutor) browserSnapshot(ctx context.Context) string {
	out, err := te.runBrowserCmd(ctx, "snapshot")
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	return truncate(out, 4000)
}

func (te *ToolExecutor) browserClick(ctx context.Context, selector string) string {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return "ERROR: CSS selector is required"
	}
	out, err := te.runBrowserCmd(ctx, "click", selector)
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	if out == "" {
		return fmt.Sprintf("OK: clicked %s", selector)
	}
	return truncate(out, 1000)
}

func (te *ToolExecutor) browserType(ctx context.Context, args string) string {
	parts := strings.SplitN(strings.TrimSpace(args), " ", 2)
	if len(parts) < 2 {
		return "ERROR: usage: browser_type <selector> <text>"
	}
	out, err := te.runBrowserCmd(ctx, "type", parts[0], parts[1])
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	if out == "" {
		return fmt.Sprintf("OK: typed into %s", parts[0])
	}
	return truncate(out, 1000)
}

func (te *ToolExecutor) runBrowserCmd(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, te.agentBrowserBin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		errMsg := stderr.String()
		if errMsg == "" {
			errMsg = err.Error()
		}
		return "", fmt.Errorf("agent-browser %s: %s", args[0], strings.TrimSpace(errMsg))
	}
	return stdout.String(), nil
}

// HTTP tools.

func (te *ToolExecutor) httpGet(ctx context.Context, url string) string {
	url = strings.TrimSpace(url)
	if url == "" {
		return "ERROR: url is required"
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) BB-Hunter-Agent/1.0")

	resp, err := te.httpClient.Do(req)
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("HTTP %d %s\n", resp.StatusCode, resp.Status))
	for k, v := range resp.Header {
		sb.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
	}
	sb.WriteString("\n")
	sb.WriteString(string(body))

	return truncate(sb.String(), 4000)
}

func (te *ToolExecutor) httpRaw(ctx context.Context, args string) string {
	parts := strings.Fields(args)
	if len(parts) < 2 {
		return "ERROR: usage: http_raw <method> <url> [header:value ...] [body:data]"
	}

	method := strings.ToUpper(parts[0])
	url := parts[1]
	var bodyStr string
	headers := make(map[string]string)

	for _, p := range parts[2:] {
		if strings.HasPrefix(p, "body:") {
			bodyStr = strings.TrimPrefix(p, "body:")
		} else if idx := strings.Index(p, ":"); idx > 0 {
			headers[p[:idx]] = p[idx+1:]
		}
	}

	var bodyReader io.Reader
	if bodyStr != "" {
		bodyReader = strings.NewReader(bodyStr)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) BB-Hunter-Agent/1.0")

	resp, err := te.httpClient.Do(req)
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("HTTP %d %s\n", resp.StatusCode, resp.Status))
	for k, v := range resp.Header {
		sb.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
	}
	sb.WriteString("\n")
	sb.WriteString(string(body))

	return truncate(sb.String(), 4000)
}

// Recon tools — delegate to installed CLI tools.

func (te *ToolExecutor) runNuclei(ctx context.Context, args string) string {
	parts := strings.Fields(strings.TrimSpace(args))
	if len(parts) == 0 {
		return "ERROR: url is required"
	}

	cmdArgs := []string{"-u", parts[0], "-silent", "-jsonl", "-no-color", "-rate-limit", "10"}
	if len(parts) > 1 {
		cmdArgs = append(cmdArgs, "-t", parts[1])
	}
	return te.runReconTool(ctx, "nuclei", cmdArgs, 120*time.Second)
}

func (te *ToolExecutor) runSubfinder(ctx context.Context, domain string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return "ERROR: domain is required"
	}
	return te.runReconTool(ctx, "subfinder", []string{"-d", domain, "-silent"}, 60*time.Second)
}

func (te *ToolExecutor) runHttpx(ctx context.Context, hosts string) string {
	hosts = strings.TrimSpace(hosts)
	if hosts == "" {
		return "ERROR: hosts are required"
	}
	hostList := strings.Split(hosts, ",")
	input := strings.Join(hostList, "\n")

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "httpx", "-silent", "-status-code", "-title", "-tech-detect")
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Sprintf("ERROR: httpx: %v (%s)", err, strings.TrimSpace(stderr.String()))
	}
	return truncate(stdout.String(), 3000)
}

func (te *ToolExecutor) runKatana(ctx context.Context, args string) string {
	parts := strings.Fields(strings.TrimSpace(args))
	if len(parts) == 0 {
		return "ERROR: url is required"
	}
	cmdArgs := []string{"-u", parts[0], "-silent", "-no-color", "-d", "2"}
	if len(parts) > 1 {
		cmdArgs = []string{"-u", parts[0], "-silent", "-no-color", "-d", parts[1]}
	}
	return te.runReconTool(ctx, "katana", cmdArgs, 60*time.Second)
}

func (te *ToolExecutor) runReconTool(ctx context.Context, tool string, args []string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, tool, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Sprintf("TIMEOUT: %s timed out after %s. Partial output:\n%s", tool, timeout, truncate(stdout.String(), 2000))
		}
		// Some tools return non-zero with valid output
		if stdout.Len() > 0 {
			return truncate(stdout.String(), 3000)
		}
		return fmt.Sprintf("ERROR: %s: %v (%s)", tool, err, strings.TrimSpace(stderr.String()))
	}
	out := stdout.String()
	if out == "" {
		return fmt.Sprintf("OK: %s returned no output (no results)", tool)
	}
	return truncate(out, 3000)
}

func (te *ToolExecutor) runCmd(ctx context.Context, cmdStr string) string {
	cmdStr = strings.TrimSpace(cmdStr)
	if cmdStr == "" {
		return "ERROR: command is required"
	}

	// Block destructive commands
	lower := strings.ToLower(cmdStr)
	blocked := []string{"rm ", "rm\t", "mkfs", "dd ", "shutdown", "reboot", "> /dev/", "chmod 777"}
	for _, b := range blocked {
		if strings.Contains(lower, b) {
			return "ERROR: destructive commands are not allowed"
		}
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", cmdStr)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		combined := stdout.String() + stderr.String()
		if combined != "" {
			return truncate(combined, 3000)
		}
		return fmt.Sprintf("ERROR: %v", err)
	}
	out := stdout.String()
	if out == "" {
		return "OK: command completed with no output"
	}
	return truncate(out, 3000)
}

func (te *ToolExecutor) reportFinding(args string) string {
	args = strings.TrimSpace(args)
	if args == "" {
		return "ERROR: JSON finding data is required"
	}

	var f Finding
	if err := json.Unmarshal([]byte(args), &f); err != nil {
		return fmt.Sprintf("ERROR: invalid JSON: %v", err)
	}
	if f.VulnClass == "" || f.URL == "" {
		return "ERROR: vuln_class and url are required fields"
	}
	if f.Severity == "" {
		f.Severity = "medium"
	}

	te.findings = append(te.findings, f)
	return fmt.Sprintf("OK: finding #%d reported — %s %s at %s", len(te.findings), f.Severity, f.VulnClass, f.URL)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "\n... [truncated]"
}
