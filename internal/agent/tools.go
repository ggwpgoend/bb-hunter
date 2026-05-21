package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
		{Name: "http_raw", Description: "Send raw HTTP request with custom method/headers/body. Wrap header values and bodies that contain spaces in matching \" or ' quotes. Inside a \"...\" group, escape inner double quotes as \\\", or use '...' as the outer pair.", Args: "<method> <url> [\"Header-Name: value\" ...] [\"body: payload\"]"},
		{Name: "run_nuclei", Description: "Run nuclei scanner on a URL with optional template filter", Args: "<url> [template_filter]"},
		{Name: "run_subfinder", Description: "Enumerate subdomains for a domain", Args: "<domain>"},
		{Name: "run_httpx", Description: "Probe hosts for live HTTP services", Args: "<host1,host2,...>"},
		{Name: "run_katana", Description: "Crawl a URL and discover endpoints", Args: "<url> [depth]"},
		{Name: "run_ffuf", Description: "Fuzz a URL with a wordlist (path discovery). URL must contain FUZZ.", Args: "<url> <wordlist_path> [filter_status_codes]"},
		{Name: "build_wordlist", Description: "Write a wordlist file from inline newline-separated paths.", Args: "<output_path>\\n<path1>\\n<path2>..."},
		{Name: "run_cmd", Description: "Run an arbitrary shell command (recon only, no destructive ops)", Args: "<command>"},
		{Name: "recall", Description: "Retrieve stored data from session memory", Args: "endpoints | http <url> | js <url> | search <keyword>"},
		{Name: "report_finding", Description: "Report a discovered vulnerability", Args: "<json: {vuln_class, severity, url, description, evidence}>"},
		{Name: "done", Description: "Finish the agent session and summarize results", Args: "[summary]"},
	}
}

// ToolsPrompt returns a compact string listing all tools for the system prompt.
func ToolsPrompt() string {
	var sb strings.Builder
	sb.WriteString("Tools:\n")
	for _, t := range AllTools() {
		if t.Args != "" {
			sb.WriteString(fmt.Sprintf("%s %s\n", t.Name, t.Args))
		} else {
			sb.WriteString(fmt.Sprintf("%s\n", t.Name))
		}
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
	store           *SessionStore // session store for recall tool
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

func (te *ToolExecutor) DropLastFinding() (Finding, bool) {
	if len(te.findings) == 0 {
		return Finding{}, false
	}
	f := te.findings[len(te.findings)-1]
	te.findings = te.findings[:len(te.findings)-1]
	return f, true
}

func (te *ToolExecutor) dropFinding(f Finding) {
	for i := len(te.findings) - 1; i >= 0; i-- {
		if te.findings[i] == f {
			te.findings = append(te.findings[:i], te.findings[i+1:]...)
			return
		}
	}
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
	case "run_ffuf":
		return te.runFfuf(ctx, args)
	case "build_wordlist":
		return te.buildWordlistTool(args)
	case "run_cmd":
		return te.runCmd(ctx, args)
	case "recall":
		if te.store != nil {
			return te.store.Recall(args)
		}
		return "ERROR: session store not available"
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
	url = stripOuterQuotes(url)
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
	return truncate(out, 80000)
}

func (te *ToolExecutor) browserScreenshot(ctx context.Context, filename string) string {
	filename = stripOuterQuotes(filename)
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
	js = stripOuterQuotes(js)
	if js == "" {
		return "ERROR: javascript code is required"
	}
	out, err := te.runBrowserCmd(ctx, "eval", js)
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	return truncate(out, 80000)
}

func (te *ToolExecutor) browserSnapshot(ctx context.Context) string {
	out, err := te.runBrowserCmd(ctx, "snapshot")
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	return truncate(out, 80000)
}

func (te *ToolExecutor) VerifyXSSExecution(ctx context.Context, f Finding) VerificationResult {
	payloads := xssEvidencePayloads(f)
	if len(payloads) == 0 {
		return VerificationResult{Verified: false, Reason: "no XSS payload found in evidence"}
	}

	openOut := te.browserOpen(ctx, f.URL)
	if strings.HasPrefix(openOut, "ERROR:") {
		return VerificationResult{Verified: false, Reason: openOut}
	}
	time.Sleep(1 * time.Second)

	snapshot := te.browserSnapshot(ctx)
	evalOut := te.browserEval(ctx, `JSON.stringify({href:window.location.href,title:document.title,text:document.body?document.body.innerText:"",html:document.documentElement?document.documentElement.outerHTML:""})`)
	combined := strings.ToLower(snapshot + "\n" + evalOut)
	if containsAlertMarker(combined) {
		return VerificationResult{Verified: true, Reason: "browser alert/dialog marker observed"}
	}
	if strings.HasPrefix(snapshot, "ERROR:") && strings.HasPrefix(evalOut, "ERROR:") {
		return VerificationResult{Verified: false, Reason: "browser opened URL but snapshot/eval failed"}
	}
	for _, payload := range payloads {
		if payload != "" && strings.Contains(combined, strings.ToLower(payload)) {
			return VerificationResult{Verified: true, Reason: "payload reflected in DOM snapshot (weak evidence)"}
		}
	}
	if containsScriptMarker(combined) {
		return VerificationResult{Verified: true, Reason: "script execution marker reflected in DOM (weak evidence)"}
	}
	return VerificationResult{Verified: false, Reason: "no alert/dialog marker or DOM reflection observed"}
}

func (te *ToolExecutor) browserClick(ctx context.Context, selector string) string {
	selector = stripOuterQuotes(selector)
	if selector == "" {
		return "ERROR: CSS selector or @ref is required"
	}
	if strings.HasPrefix(selector, "e") && len(selector) > 1 && selector[1] >= '0' && selector[1] <= '9' {
		selector = "@" + selector
	}

	urlBefore := te.captureCurrentURL(ctx)

	out, err := te.runBrowserCmd(ctx, "click", selector)
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}

	urlAfter := te.captureCurrentURL(ctx)

	clickOut := out
	if clickOut == "" {
		clickOut = fmt.Sprintf("OK: clicked %s", selector)
	}
	navSuffix := describeNavigation(classifyNavigation(urlBefore, urlAfter), urlBefore, urlAfter)
	return truncate(composeClickObservation(clickOut, navSuffix), 80000)
}

// captureCurrentURL returns window.location.href via the browser_eval
// machinery, or "" when the underlying tool errored (no browser open,
// page not loaded, eval rejected, etc.). The empty-string case is handled
// by classifyNavigation as navUnknown so the click observation is not
// polluted with a misleading WARNING.
func (te *ToolExecutor) captureCurrentURL(ctx context.Context) string {
	out, err := te.runBrowserCmd(ctx, "eval", "window.location.href")
	if err != nil {
		return ""
	}
	return normaliseEvalURL(out)
}

func (te *ToolExecutor) browserType(ctx context.Context, args string) string {
	selector, text, ok := splitFirstField(args)
	if !ok {
		return "ERROR: usage: browser_type <selector_or_@ref> <text>"
	}
	if strings.HasPrefix(selector, "e") && len(selector) > 1 && selector[1] >= '0' && selector[1] <= '9' {
		selector = "@" + selector
	}
	out, err := te.runBrowserCmd(ctx, "fill", selector, text)
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	if out == "" {
		return fmt.Sprintf("OK: typed into %s", selector)
	}
	return truncate(out, 80000)
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
	url = stripOuterQuotes(url)
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

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 100000))

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("HTTP %d %s\n", resp.StatusCode, resp.Status))
	for k, v := range resp.Header {
		sb.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
	}
	sb.WriteString("\n")
	sb.WriteString(string(body))

	return truncate(filterHTTPObservation(sb.String()), 80000)
}

func (te *ToolExecutor) httpRaw(ctx context.Context, args string) string {
	parts := splitArgsQuoteAware(args)
	if len(parts) < 2 {
		return "ERROR: usage: http_raw <method> <url> [\"Header-Name: value\" ...] [\"body: payload\"]"
	}

	method := strings.ToUpper(parts[0])
	url := parts[1]
	var bodyStr string
	headers := make(map[string]string)

	for _, p := range parts[2:] {
		switch {
		case strings.HasPrefix(p, "body:"):
			bodyStr = strings.TrimPrefix(p, "body:")
		case strings.HasPrefix(p, "body="):
			bodyStr = strings.TrimPrefix(p, "body=")
		default:
			if idx := strings.Index(p, ":"); idx > 0 {
				name := strings.TrimSpace(p[:idx])
				value := strings.TrimSpace(p[idx+1:])
				if name != "" {
					headers[name] = value
				}
			}
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

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 100000))

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("HTTP %d %s\n", resp.StatusCode, resp.Status))
	for k, v := range resp.Header {
		sb.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
	}
	sb.WriteString("\n")
	sb.WriteString(string(body))

	return truncate(filterHTTPObservation(sb.String()), 80000)
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
	return truncate(out, 80000)
}

func (te *ToolExecutor) runCmd(ctx context.Context, cmdStr string) string {
	cmdStr = stripOuterQuotes(cmdStr)
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
	return truncate(out, 80000)
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

var xssPayloadRe = regexp.MustCompile(`(?i)(<script[^>]*>.*?</script>|<svg[^>]*onload[^>]*>|<img[^>]*onerror[^>]*>|javascript:[^\s"'<>]+|alert\s*\([^)]*\))`)

func xssEvidencePayloads(f Finding) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if decoded, err := url.QueryUnescape(s); err == nil {
			s = decoded
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}

	if u, err := url.Parse(f.URL); err == nil {
		for _, vals := range u.Query() {
			for _, v := range vals {
				if strings.Contains(strings.ToLower(v), "alert") || strings.Contains(v, "<") || strings.Contains(strings.ToLower(v), "javascript:") {
					add(v)
				}
			}
		}
	}
	for _, src := range []string{f.Evidence, f.Description, f.URL} {
		for _, match := range xssPayloadRe.FindAllString(src, -1) {
			add(match)
		}
	}
	return out
}

func containsAlertMarker(s string) bool {
	markers := []string{"alert(", "dialog", "javascript dialog", "page.on('dialog", "window.alert", "__bbhunter_alert"}
	for _, marker := range markers {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

func containsScriptMarker(s string) bool {
	return strings.Contains(s, "<script") || strings.Contains(s, "onerror=") || strings.Contains(s, "onload=") || strings.Contains(s, "javascript:")
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "\n... [truncated]"
}

// stripOuterQuotes removes a single pair of matching outer "..." or '...'
// quotes from s, after trimming surrounding whitespace. LLM agents frequently
// produce actions like `ACTION: http_get "https://..."` or
// `ACTION: run_cmd 'curl ...'`, and the response parser hands the tool the
// quote characters as literal bytes — without this helper Go's URL / header
// / shell parsers reject them.
func stripOuterQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// splitArgsQuoteAware splits s on unquoted whitespace, but treats "..."
// and '...' groupings as a single field. The opening quote must be the
// first byte of a field; the matching closing quote is the next byte
// of the same kind that is followed by whitespace or end-of-string,
// which makes the function robust to bodies that contain inner same-type
// quotes (XML attributes, JSON values, etc.):
//
//	http_raw POST <url> "Content-Type: application/xml" "body:<?xml version=\"1.0\"?>..."
//	http_raw POST <url> "Content-Type: application/xml" "body:<?xml version="1.0"?>..."
//
// both yield identical fields. Backslash-escaped quotes (\" / \') and
// backslash-escaped backslashes (\\) inside a quoted run are unescaped.
func splitArgsQuoteAware(s string) []string {
	var fields []string
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		if s[i] == '"' || s[i] == '\'' {
			quote := s[i]
			i++
			var buf strings.Builder
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) && (s[i+1] == quote || s[i+1] == '\\') {
					buf.WriteByte(s[i+1])
					i += 2
					continue
				}
				if s[i] == quote && (i+1 == len(s) || s[i+1] == ' ' || s[i+1] == '\t') {
					i++
					break
				}
				buf.WriteByte(s[i])
				i++
			}
			fields = append(fields, buf.String())
			continue
		}
		start := i
		for i < len(s) && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		fields = append(fields, s[start:i])
	}
	return fields
}

// splitFirstField pulls the first whitespace-delimited (quote-aware) field
// off s and returns it together with the remainder. The remainder is also
// passed through stripOuterQuotes so callers can hand the text straight
// to a downstream binary. Returns ok=false if s has no fields.
func splitFirstField(s string) (first, rest string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", false
	}
	parts := splitArgsQuoteAware(s)
	if len(parts) == 0 {
		return "", "", false
	}
	if len(parts) == 1 {
		return parts[0], "", true
	}
	idx := indexAfterFirstField(s)
	if idx < 0 {
		return parts[0], stripOuterQuotes(strings.Join(parts[1:], " ")), true
	}
	return parts[0], stripOuterQuotes(s[idx:]), true
}

// indexAfterFirstField returns the byte offset in s where the second field
// begins, using the same quote semantics as splitArgsQuoteAware so that
// inner quotes don't terminate the first field prematurely. -1 if there
// is no second field.
func indexAfterFirstField(s string) int {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	if i >= len(s) {
		return -1
	}
	if s[i] == '"' || s[i] == '\'' {
		quote := s[i]
		i++
		for i < len(s) {
			if s[i] == '\\' && i+1 < len(s) && (s[i+1] == quote || s[i+1] == '\\') {
				i += 2
				continue
			}
			if s[i] == quote && (i+1 == len(s) || s[i+1] == ' ' || s[i+1] == '\t') {
				i++
				break
			}
			i++
		}
	} else {
		for i < len(s) && s[i] != ' ' && s[i] != '\t' {
			i++
		}
	}
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	if i >= len(s) {
		return -1
	}
	return i
}
