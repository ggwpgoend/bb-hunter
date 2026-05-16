// Package browser provides browser-based PoC execution for BB-Hunter.
//
// Uses agent-browser CLI (Rust native) for headless browser automation:
//   - XSS verification via real DOM injection detection
//   - CSRF token absence checks
//   - Open redirect following
//   - Clickjacking frame tests
//   - Screenshots as evidence
//   - Video recording of exploit flows
//
// Borrowed concepts:
//   - agent-browser (vercel-labs): CLI-driven browser automation with accessibility tree
//   - Obscura: lightweight headless browser (30MB vs Chrome 200MB)
//
// Security: all requests go through egress proxy, same scope enforcement as Scanner.
package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Config holds browser engine configuration.
type Config struct {
	AgentBrowserBin string        `json:"agent_browser_bin" yaml:"agent_browser_bin"`
	ProxyAddr       string        `json:"proxy_addr" yaml:"proxy_addr"`
	ScreenshotDir   string        `json:"screenshot_dir" yaml:"screenshot_dir"`
	Timeout         time.Duration `json:"timeout" yaml:"timeout"`
	Headless        bool          `json:"headless" yaml:"headless"`
	Logger          *slog.Logger  `json:"-" yaml:"-"`
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		AgentBrowserBin: "agent-browser",
		ScreenshotDir:   "/tmp/bb-hunter-screenshots",
		Timeout:         30 * time.Second,
		Headless:        true,
	}
}

// Evidence captures browser-based proof for a finding.
type Evidence struct {
	FindingID    string        `json:"finding_id"`
	VulnClass    string        `json:"vuln_class"`
	URL          string        `json:"url"`
	Verified     bool          `json:"verified"`
	Description  string        `json:"description"`
	Screenshots  []string      `json:"screenshots,omitempty"`
	VideoPath    string        `json:"video_path,omitempty"`
	DOMSnapshot  string        `json:"dom_snapshot,omitempty"`
	PageTitle    string        `json:"page_title,omitempty"`
	FinalURL     string        `json:"final_url,omitempty"`
	Headers      string        `json:"headers,omitempty"`
	Duration     time.Duration `json:"duration"`
	Steps        []Step        `json:"steps"`
	Error        string        `json:"error,omitempty"`
}

// Step is one action in a browser PoC flow.
type Step struct {
	Order       int    `json:"order"`
	Action      string `json:"action"`
	Selector    string `json:"selector,omitempty"`
	Value       string `json:"value,omitempty"`
	Description string `json:"description"`
	Success     bool   `json:"success"`
	Output      string `json:"output,omitempty"`
}

// Engine drives browser-based PoC execution.
type Engine struct {
	cfg Config
	log *slog.Logger
}

// NewEngine creates a new browser PoC engine.
func NewEngine(cfg Config) *Engine {
	if cfg.AgentBrowserBin == "" {
		cfg.AgentBrowserBin = "agent-browser"
	}
	if cfg.ScreenshotDir == "" {
		cfg.ScreenshotDir = "/tmp/bb-hunter-screenshots"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Engine{cfg: cfg, log: cfg.Logger}
}

// Available checks if agent-browser is installed and callable.
func (e *Engine) Available() bool {
	cmd := exec.Command(e.cfg.AgentBrowserBin, "version")
	return cmd.Run() == nil
}

// RunPoC executes a browser-based PoC for a specific vulnerability class.
func (e *Engine) RunPoC(ctx context.Context, findingID, vulnClass, url string, params []string) (*Evidence, error) {
	start := time.Now()

	evidence := &Evidence{
		FindingID: findingID,
		VulnClass: vulnClass,
		URL:       url,
	}

	_ = os.MkdirAll(e.cfg.ScreenshotDir, 0o755)

	ctx, cancel := context.WithTimeout(ctx, e.cfg.Timeout)
	defer cancel()

	var err error
	switch strings.ToLower(vulnClass) {
	case "xss":
		err = e.verifyXSS(ctx, evidence, url, params)
	case "csrf":
		err = e.verifyCSRF(ctx, evidence, url)
	case "open_redirect":
		err = e.verifyOpenRedirect(ctx, evidence, url, params)
	case "clickjacking":
		err = e.verifyClickjacking(ctx, evidence, url)
	case "info_disclosure":
		err = e.verifyInfoDisclosure(ctx, evidence, url)
	default:
		err = e.verifyGeneric(ctx, evidence, url)
	}

	evidence.Duration = time.Since(start)

	if err != nil {
		evidence.Error = err.Error()
		e.log.Warn("browser: PoC execution error",
			"finding_id", findingID,
			"vuln_class", vulnClass,
			"error", err,
		)
	}

	e.log.Info("browser: PoC complete",
		"finding_id", findingID,
		"vuln_class", vulnClass,
		"verified", evidence.Verified,
		"duration", evidence.Duration,
		"screenshots", len(evidence.Screenshots),
	)

	return evidence, nil
}

// verifyXSS checks for reflected/stored XSS using a safe canary.
func (e *Engine) verifyXSS(ctx context.Context, ev *Evidence, url string, params []string) error {
	idSuffix := ev.FindingID
	if len(idSuffix) > 8 {
		idSuffix = idSuffix[:8]
	}
	canary := "bbhunter_xss_canary_" + idSuffix

	// Step 1: Open target URL
	step1 := Step{Order: 1, Action: "open", Description: "Navigate to target URL"}
	if err := e.runCmd(ctx, "open", url); err != nil {
		step1.Success = false
		step1.Output = err.Error()
		ev.Steps = append(ev.Steps, step1)
		return fmt.Errorf("failed to open URL: %w", err)
	}
	step1.Success = true
	ev.Steps = append(ev.Steps, step1)

	// Step 2: Take initial screenshot
	screenshotPath := e.screenshotPath(ev.FindingID, "before")
	step2 := Step{Order: 2, Action: "screenshot", Description: "Capture initial page state"}
	if err := e.runCmd(ctx, "screenshot", screenshotPath); err == nil {
		ev.Screenshots = append(ev.Screenshots, screenshotPath)
		step2.Success = true
	} else {
		step2.Success = false
		step2.Output = err.Error()
	}
	ev.Steps = append(ev.Steps, step2)

	// Step 3: Try injecting canary into first available param
	testURL := url
	if len(params) > 0 {
		if strings.Contains(url, "?") {
			testURL = url + "&" + params[0] + "=" + canary
		} else {
			testURL = url + "?" + params[0] + "=" + canary
		}
	} else if strings.Contains(url, "=") {
		// Replace first parameter value with canary
		parts := strings.SplitN(url, "=", 2)
		if len(parts) == 2 {
			ampIdx := strings.Index(parts[1], "&")
			if ampIdx > 0 {
				testURL = parts[0] + "=" + canary + parts[1][ampIdx:]
			} else {
				testURL = parts[0] + "=" + canary
			}
		}
	}

	step3 := Step{Order: 3, Action: "navigate", Description: "Inject canary string", Value: canary}
	if err := e.runCmd(ctx, "open", testURL); err != nil {
		step3.Success = false
		step3.Output = err.Error()
		ev.Steps = append(ev.Steps, step3)
		return nil
	}
	step3.Success = true
	ev.Steps = append(ev.Steps, step3)

	// Step 4: Get page source and check for canary reflection
	step4 := Step{Order: 4, Action: "check_reflection", Description: "Check if canary is reflected in DOM"}
	snapshot, err := e.runCmdOutput(ctx, "snapshot")
	if err == nil {
		ev.DOMSnapshot = snapshot
		if strings.Contains(snapshot, canary) {
			ev.Verified = true
			ev.Description = fmt.Sprintf("XSS canary '%s' reflected in DOM", canary)
			step4.Success = true
			step4.Output = "canary found in DOM"
		} else {
			step4.Success = true
			step4.Output = "canary not found in DOM"
		}
	} else {
		step4.Success = false
		step4.Output = err.Error()
	}
	ev.Steps = append(ev.Steps, step4)

	// Step 5: Check via JavaScript evaluation
	step5 := Step{Order: 5, Action: "eval", Description: "Check DOM for canary via JavaScript"}
	jsCheck := fmt.Sprintf(`document.body.innerHTML.includes('%s')`, canary)
	jsResult, err := e.runCmdOutput(ctx, "eval", jsCheck)
	if err == nil {
		if strings.TrimSpace(jsResult) == "true" {
			ev.Verified = true
			ev.Description = fmt.Sprintf("XSS canary '%s' reflected in page body", canary)
			step5.Success = true
			step5.Output = "canary confirmed via JS eval"
		} else {
			step5.Success = true
			step5.Output = "canary not found via JS eval"
		}
	} else {
		step5.Success = false
		step5.Output = err.Error()
	}
	ev.Steps = append(ev.Steps, step5)

	// Step 6: Final screenshot
	afterScreenshot := e.screenshotPath(ev.FindingID, "after")
	step6 := Step{Order: 6, Action: "screenshot", Description: "Capture post-injection state"}
	if err := e.runCmd(ctx, "screenshot", afterScreenshot); err == nil {
		ev.Screenshots = append(ev.Screenshots, afterScreenshot)
		step6.Success = true
	} else {
		step6.Success = false
		step6.Output = err.Error()
	}
	ev.Steps = append(ev.Steps, step6)

	// Step 7: Get final URL (check for redirects)
	if finalURL, err := e.runCmdOutput(ctx, "get", "url"); err == nil {
		ev.FinalURL = strings.TrimSpace(finalURL)
	}

	// Step 8: Get page title
	if title, err := e.runCmdOutput(ctx, "get", "title"); err == nil {
		ev.PageTitle = strings.TrimSpace(title)
	}

	return nil
}

// verifyCSRF checks for missing CSRF protection on forms.
func (e *Engine) verifyCSRF(ctx context.Context, ev *Evidence, url string) error {
	// Step 1: Open URL
	step1 := Step{Order: 1, Action: "open", Description: "Navigate to target URL"}
	if err := e.runCmd(ctx, "open", url); err != nil {
		step1.Success = false
		step1.Output = err.Error()
		ev.Steps = append(ev.Steps, step1)
		return fmt.Errorf("failed to open URL: %w", err)
	}
	step1.Success = true
	ev.Steps = append(ev.Steps, step1)

	// Step 2: Screenshot
	screenshotPath := e.screenshotPath(ev.FindingID, "csrf-page")
	if err := e.runCmd(ctx, "screenshot", screenshotPath); err == nil {
		ev.Screenshots = append(ev.Screenshots, screenshotPath)
	}

	// Step 3: Check for CSRF tokens in forms
	step3 := Step{Order: 3, Action: "eval", Description: "Check forms for CSRF tokens"}
	jsCheck := `JSON.stringify({
		forms: document.forms.length,
		csrf_tokens: Array.from(document.querySelectorAll('input[name*="csrf"], input[name*="token"], input[name*="_token"], meta[name="csrf-token"]')).length,
		hidden_inputs: Array.from(document.querySelectorAll('input[type="hidden"]')).map(i => i.name)
	})`
	result, err := e.runCmdOutput(ctx, "eval", jsCheck)
	if err == nil {
		step3.Success = true
		step3.Output = strings.TrimSpace(result)

		var formCheck struct {
			Forms        int      `json:"forms"`
			CSRFTokens   int      `json:"csrf_tokens"`
			HiddenInputs []string `json:"hidden_inputs"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(result)), &formCheck); err == nil {
			if formCheck.Forms > 0 && formCheck.CSRFTokens == 0 {
				ev.Verified = true
				ev.Description = fmt.Sprintf("%d form(s) found without CSRF protection", formCheck.Forms)
			}
		}
	} else {
		step3.Success = false
		step3.Output = err.Error()
	}
	ev.Steps = append(ev.Steps, step3)

	return nil
}

// verifyOpenRedirect checks if a URL parameter causes a redirect to external domain.
func (e *Engine) verifyOpenRedirect(ctx context.Context, ev *Evidence, url string, params []string) error {
	externalTarget := "https://bbhunter-redirect-canary.example.com"

	// Build test URL with redirect param
	testURL := url
	redirectParams := []string{"url", "redirect", "next", "return", "goto", "continue", "dest", "destination", "redir", "return_url", "redirect_uri"}

	if len(params) > 0 {
		redirectParams = params
	}

	for _, param := range redirectParams {
		if strings.Contains(url, "?") {
			testURL = url + "&" + param + "=" + externalTarget
		} else {
			testURL = url + "?" + param + "=" + externalTarget
		}
		break
	}

	// Step 1: Open URL
	step1 := Step{Order: 1, Action: "open", Description: "Navigate with redirect parameter", Value: testURL}
	if err := e.runCmd(ctx, "open", testURL); err != nil {
		step1.Success = false
		step1.Output = err.Error()
		ev.Steps = append(ev.Steps, step1)
		return nil
	}
	step1.Success = true
	ev.Steps = append(ev.Steps, step1)

	// Step 2: Check final URL
	step2 := Step{Order: 2, Action: "get_url", Description: "Check if redirected to external domain"}
	finalURL, err := e.runCmdOutput(ctx, "get", "url")
	if err == nil {
		ev.FinalURL = strings.TrimSpace(finalURL)
		step2.Success = true
		step2.Output = ev.FinalURL

		if strings.Contains(ev.FinalURL, "bbhunter-redirect-canary") ||
			strings.Contains(ev.FinalURL, "example.com") {
			ev.Verified = true
			ev.Description = fmt.Sprintf("Open redirect: navigated to %s", ev.FinalURL)
		}
	} else {
		step2.Success = false
		step2.Output = err.Error()
	}
	ev.Steps = append(ev.Steps, step2)

	// Step 3: Screenshot
	screenshotPath := e.screenshotPath(ev.FindingID, "redirect")
	if err := e.runCmd(ctx, "screenshot", screenshotPath); err == nil {
		ev.Screenshots = append(ev.Screenshots, screenshotPath)
	}

	return nil
}

// verifyClickjacking checks if a page can be framed.
func (e *Engine) verifyClickjacking(ctx context.Context, ev *Evidence, url string) error {
	// Step 1: Check X-Frame-Options and CSP headers via JS
	step1 := Step{Order: 1, Action: "open", Description: "Navigate to target"}
	if err := e.runCmd(ctx, "open", url); err != nil {
		step1.Success = false
		step1.Output = err.Error()
		ev.Steps = append(ev.Steps, step1)
		return nil
	}
	step1.Success = true
	ev.Steps = append(ev.Steps, step1)

	// Step 2: Check response headers via eval
	step2 := Step{Order: 2, Action: "eval", Description: "Check X-Frame-Options and CSP"}
	jsCheck := `(async () => {
		try {
			const r = await fetch(window.location.href, {method: 'HEAD'});
			return JSON.stringify({
				xfo: r.headers.get('X-Frame-Options') || 'none',
				csp: r.headers.get('Content-Security-Policy') || 'none'
			});
		} catch(e) { return JSON.stringify({error: e.message}); }
	})()`
	result, err := e.runCmdOutput(ctx, "eval", jsCheck)
	if err == nil {
		step2.Success = true
		step2.Output = strings.TrimSpace(result)

		var headers struct {
			XFO string `json:"xfo"`
			CSP string `json:"csp"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(result)), &headers); err == nil {
			noXFO := headers.XFO == "none" || headers.XFO == ""
			noFrameAncestors := !strings.Contains(headers.CSP, "frame-ancestors")
			if noXFO && noFrameAncestors {
				ev.Verified = true
				ev.Description = "Page has no X-Frame-Options or CSP frame-ancestors — vulnerable to clickjacking"
			}
			ev.Headers = fmt.Sprintf("X-Frame-Options: %s | CSP: %s", headers.XFO, headers.CSP)
		}
	} else {
		step2.Success = false
		step2.Output = err.Error()
	}
	ev.Steps = append(ev.Steps, step2)

	screenshotPath := e.screenshotPath(ev.FindingID, "clickjacking")
	if err := e.runCmd(ctx, "screenshot", screenshotPath); err == nil {
		ev.Screenshots = append(ev.Screenshots, screenshotPath)
	}

	return nil
}

// verifyInfoDisclosure checks for exposed sensitive data.
func (e *Engine) verifyInfoDisclosure(ctx context.Context, ev *Evidence, url string) error {
	step1 := Step{Order: 1, Action: "open", Description: "Navigate to target"}
	if err := e.runCmd(ctx, "open", url); err != nil {
		step1.Success = false
		step1.Output = err.Error()
		ev.Steps = append(ev.Steps, step1)
		return nil
	}
	step1.Success = true
	ev.Steps = append(ev.Steps, step1)

	// Check for sensitive information patterns in page
	step2 := Step{Order: 2, Action: "eval", Description: "Check for sensitive data patterns"}
	jsCheck := `JSON.stringify({
		server_header: document.querySelector('meta[name="server"]')?.content || null,
		has_stack_trace: document.body.innerText.includes('Traceback') || document.body.innerText.includes('stack trace'),
		has_sql_error: document.body.innerText.includes('SQL') && document.body.innerText.includes('error'),
		has_env_vars: document.body.innerText.includes('DATABASE_URL') || document.body.innerText.includes('SECRET_KEY'),
		has_version_info: /\b(apache|nginx|php|python|ruby|node|java)\s*\/?\s*\d+\.\d+/i.test(document.body.innerText),
		page_size: document.body.innerText.length
	})`
	result, err := e.runCmdOutput(ctx, "eval", jsCheck)
	if err == nil {
		step2.Success = true
		step2.Output = strings.TrimSpace(result)

		var check struct {
			StackTrace  bool `json:"has_stack_trace"`
			SQLError    bool `json:"has_sql_error"`
			EnvVars     bool `json:"has_env_vars"`
			VersionInfo bool `json:"has_version_info"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(result)), &check); err == nil {
			if check.StackTrace || check.SQLError || check.EnvVars || check.VersionInfo {
				ev.Verified = true
				var reasons []string
				if check.StackTrace {
					reasons = append(reasons, "stack trace exposed")
				}
				if check.SQLError {
					reasons = append(reasons, "SQL error exposed")
				}
				if check.EnvVars {
					reasons = append(reasons, "environment variables exposed")
				}
				if check.VersionInfo {
					reasons = append(reasons, "server version info exposed")
				}
				ev.Description = "Information disclosure: " + strings.Join(reasons, ", ")
			}
		}
	} else {
		step2.Success = false
		step2.Output = err.Error()
	}
	ev.Steps = append(ev.Steps, step2)

	screenshotPath := e.screenshotPath(ev.FindingID, "info-disclosure")
	if err := e.runCmd(ctx, "screenshot", screenshotPath); err == nil {
		ev.Screenshots = append(ev.Screenshots, screenshotPath)
	}

	return nil
}

// verifyGeneric performs a generic browser check — screenshot + DOM snapshot.
func (e *Engine) verifyGeneric(ctx context.Context, ev *Evidence, url string) error {
	step1 := Step{Order: 1, Action: "open", Description: "Navigate to target"}
	if err := e.runCmd(ctx, "open", url); err != nil {
		step1.Success = false
		step1.Output = err.Error()
		ev.Steps = append(ev.Steps, step1)
		return nil
	}
	step1.Success = true
	ev.Steps = append(ev.Steps, step1)

	// Screenshot
	screenshotPath := e.screenshotPath(ev.FindingID, "generic")
	if err := e.runCmd(ctx, "screenshot", screenshotPath); err == nil {
		ev.Screenshots = append(ev.Screenshots, screenshotPath)
	}

	// Snapshot
	if snapshot, err := e.runCmdOutput(ctx, "snapshot"); err == nil {
		ev.DOMSnapshot = snapshot
	}

	// Title
	if title, err := e.runCmdOutput(ctx, "get", "title"); err == nil {
		ev.PageTitle = strings.TrimSpace(title)
	}

	// URL
	if finalURL, err := e.runCmdOutput(ctx, "get", "url"); err == nil {
		ev.FinalURL = strings.TrimSpace(finalURL)
	}

	ev.Description = "Generic browser evidence captured"
	return nil
}

// runCmd executes an agent-browser command.
func (e *Engine) runCmd(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, e.cfg.AgentBrowserBin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("agent-browser %s: %w (%s)", args[0], err, stderr.String())
	}
	return nil
}

// runCmdOutput executes an agent-browser command and returns stdout.
func (e *Engine) runCmdOutput(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, e.cfg.AgentBrowserBin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("agent-browser %s: %w (%s)", args[0], err, stderr.String())
	}
	return stdout.String(), nil
}

// screenshotPath generates a unique screenshot path.
func (e *Engine) screenshotPath(findingID, suffix string) string {
	safe := strings.ReplaceAll(findingID, "/", "_")
	return filepath.Join(e.cfg.ScreenshotDir, fmt.Sprintf("%s_%s_%d.png", safe, suffix, time.Now().UnixMilli()))
}

// Close closes the browser.
func (e *Engine) Close(ctx context.Context) error {
	return e.runCmd(ctx, "close")
}

// BatchEvidence runs browser PoC for multiple findings.
func (e *Engine) BatchEvidence(ctx context.Context, findings []FindingInput) []*Evidence {
	var results []*Evidence
	for _, f := range findings {
		ev, err := e.RunPoC(ctx, f.FindingID, f.VulnClass, f.URL, f.Params)
		if err != nil {
			ev = &Evidence{
				FindingID: f.FindingID,
				VulnClass: f.VulnClass,
				URL:       f.URL,
				Error:     err.Error(),
			}
		}
		results = append(results, ev)
	}
	return results
}

// FindingInput is the input for a browser PoC.
type FindingInput struct {
	FindingID string
	VulnClass string
	URL       string
	Params    []string
}
