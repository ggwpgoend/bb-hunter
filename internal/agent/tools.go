package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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
		{Name: "browser_open", Description: "Open a URL in headless browser. Default action timeout is 60s (CDP). Pair with browser_wait when the page needs network-idle (SPA, slow assets) before the next browser_* call.", Args: "<url>"},
		{Name: "browser_screenshot", Description: "Take a screenshot of current page", Args: "<filename>"},
		{Name: "evidence_screenshot", Description: "Take a screenshot intended as evidence and auto-attach it to the next report_finding. Call this AFTER triggering a payload (e.g. alert dialog rendered, reflected XSS visible, sensitive data exposed in DOM). The screenshot becomes part of the finding's Attachments and is copied to findings/<id>/ on persist.", Args: "[label]"},
		{Name: "browser_eval", Description: "Execute JavaScript in browser and return result", Args: "<javascript_code>"},
		{Name: "browser_snapshot", Description: "Get DOM accessibility tree (interactive elements only, compact, with URLs). Pair with browser_wait before snapshotting SPA pages that lazy-load content.", Args: ""},
		{Name: "browser_click", Description: "Click an element by CSS selector or @eN ref from browser_snapshot. Refs go stale after any page-changing action — re-snapshot first.", Args: "<css_selector_or_@ref>"},
		{Name: "browser_type", Description: "Type text into an input field by CSS selector or @eN ref.", Args: "<css_selector_or_@ref> <text>"},
		{Name: "browser_wait", Description: "Wait for a page condition before the next browser_* call. Arg forms: '<ms_number>' dumb sleep; '@eN' / '<css>' until element appears; '--load networkidle' wait until network idle (best for SPA); '--load domcontentloaded' until DOMContentLoaded; '--text <s>' until text appears; '--url <glob>' until URL matches.", Args: "<selector|ms|--load networkidle|--load domcontentloaded|--text <s>|--url <glob>>"},
		{Name: "browser_doctor", Description: "Diagnose agent-browser health (Chrome installed, daemon alive, last error, etc.). Use after a series of browser_* ERRORs to decide whether to keep retrying or fall back to http_get / run_cmd curl.", Args: ""},
		{Name: "http_get", Description: "Send HTTP GET request and return response headers + body (truncated). Default timeout 10s. For slow endpoints use http_request with \"timeout\":N, or run_cmd \"curl -m N -sS <url>\".", Args: "<url>"},
		{Name: "http_request", Description: "Send structured HTTP request. Prefer this over http_raw for POST/PUT/custom headers to avoid quoting mistakes. Default timeout 10s; pass \"timeout\":N (seconds, max 60) for slower endpoints.", Args: `{"method":"POST","url":"https://...","headers":{"Content-Type":"application/json"},"body":"...","timeout":10}`},
		{Name: "http_raw", Description: "Send raw HTTP request with custom method/headers/body. Default timeout 10s. Wrap header values and bodies that contain spaces in matching \" or ' quotes. Inside a \"...\" group, escape inner double quotes as \\\", or use '...' as the outer pair.", Args: "<method> <url> [\"Header-Name: value\" ...] [\"body: payload\"]"},
		{Name: "run_nuclei", Description: "Run nuclei scanner on a URL with optional template filter", Args: "<url> [template_filter]"},
		{Name: "run_subfinder", Description: "Enumerate subdomains for a domain", Args: "<domain>"},
		{Name: "run_httpx", Description: "Probe hosts for live HTTP services", Args: "<host1,host2,...>"},
		{Name: "run_katana", Description: "Crawl a URL and discover endpoints", Args: "<url> [depth]"},
		{Name: "run_ffuf", Description: "Fuzz a URL with a wordlist (path discovery). URL must contain FUZZ.", Args: "<url> <wordlist_path> [filter_status_codes]"},
		{Name: "build_wordlist", Description: "Write a wordlist file from inline newline-separated paths.", Args: "<output_path>\\n<path1>\\n<path2>..."},
		{Name: "run_cmd", Description: "Run an arbitrary shell command (recon only, no destructive ops)", Args: "<command>"},
		{Name: "recall", Description: "Retrieve stored data from session memory", Args: "endpoints | endpoint <filter> | http <url> | last_response | tests [filter] | negative | js <url> | search <keyword>"},
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

	// pendingEvidence is a list of file paths captured via evidence_*
	// tools since the last report_finding. They become Attachments on the
	// next finding and are then drained.
	pendingEvidence []string

	browserKills int // consecutive browser process kills

	// logger is used for structured browser/HTTP diagnostics. Defaults to
	// slog.Default() when not explicitly set via WithLogger.
	logger *slog.Logger

	// Browser daemon tuning (agent-browser CLI runs as a persistent daemon
	// between subprocess invocations; these knobs harden it against slow
	// targets and stale state).
	browserDefaultTimeoutMS int    // AGENT_BROWSER_DEFAULT_TIMEOUT (ms)
	browserSessionName      string // --session <name>
	browserCloseOnTimeout   bool   // run "close --all" before retrying a CDP-timed-out command

	// browserDoctorOK is set by browserHealthCheck (run once at agent
	// startup). When false, browser_* commands fast-fail with a hint to
	// use http_get/http_raw/run_cmd curl instead. Empty string == not yet
	// checked → optimistic: assume available.
	browserDoctorReason string
	browserDisabled     bool

	// lastCDPTimeout tracks when the last "CDP command timed out" error
	// was observed so we don't spam close --all on every consecutive
	// failure.
	lastCDPTimeout time.Time
}

// Finding is a vulnerability discovered by the agent.
//
// Fields prefixed with ★ are filled by the post-finding pipeline (Gate /
// Exploiter / Sandbox / Reporter) after the LLM calls report_finding. The
// LLM only needs to provide the first 5 fields plus optional Confidence /
// ProofLevel; everything else is overwritten by the pipeline.
type Finding struct {
	// Filled by the LLM via report_finding JSON
	VulnClass   string  `json:"vuln_class"`
	Severity    string  `json:"severity"`
	URL         string  `json:"url"`
	Description string  `json:"description"`
	Evidence    string  `json:"evidence"`
	Confidence  float64 `json:"confidence,omitempty"`  // 0.0-1.0; LLM self-assessment
	ProofLevel  string  `json:"proof_level,omitempty"` // direct | behavioral | inferred

	// ★ Filled by the post-finding pipeline. Not part of the LLM contract.
	ID              string `json:"id,omitempty"`
	GateVerdict     string `json:"gate_verdict,omitempty"`     // PASS | KILL | DOWNGRADE
	GateScore       int    `json:"gate_score,omitempty"`       // 0-7
	GateReasoning   string `json:"gate_reasoning,omitempty"`
	PoCScript       string `json:"poc_script,omitempty"`
	PoCInterpreter  string `json:"poc_interpreter,omitempty"`
	PoCDescription  string `json:"poc_description,omitempty"`
	SandboxVerified bool   `json:"sandbox_verified,omitempty"`
	SandboxEvidence string `json:"sandbox_evidence,omitempty"`
	SandboxStdout   string `json:"sandbox_stdout,omitempty"`
	SandboxStderr   string `json:"sandbox_stderr,omitempty"`
	SandboxExitCode int    `json:"sandbox_exit_code,omitempty"`
	ReportMarkdown  string `json:"report_markdown,omitempty"`
	FindingDir      string `json:"finding_dir,omitempty"` // persistence directory

	// Attachments are absolute paths to evidence files captured via
	// evidence_screenshot (and similar tools) prior to report_finding.
	// persistFinding copies them into the finding directory and rewrites
	// these paths to the relative names inside that directory.
	Attachments []string `json:"attachments,omitempty"`
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
		// httpClient timeout is a hard ceiling; per-request context
		// timeouts (default 10s, agent-configurable up to 60s) govern
		// the actual HTTP cancellation. Leave room above the per-
		// request max so we never trip the client-wide timeout in
		// normal use.
		httpClient: &http.Client{Timeout: 65 * time.Second},

		logger:                  slog.Default(),
		browserDefaultTimeoutMS: 60_000, // agent-browser default is 25s — too low for slow lab pages
		browserSessionName:      "bb-hunter",
		browserCloseOnTimeout:   true,
	}
}

// WithLogger attaches a structured logger. Returns the same executor so it
// can be used in a builder chain.
func (te *ToolExecutor) WithLogger(l *slog.Logger) *ToolExecutor {
	if l != nil {
		te.logger = l
	}
	return te
}

// WithBrowserSession overrides the agent-browser --session name. Empty
// string disables session isolation (CLI default "default" will be used).
func (te *ToolExecutor) WithBrowserSession(name string) *ToolExecutor {
	te.browserSessionName = name
	return te
}

// WithBrowserDefaultTimeoutMS overrides the AGENT_BROWSER_DEFAULT_TIMEOUT
// env var injected when spawning agent-browser. Zero -> leave unset, the
// CLI default (25 000 ms) applies.
func (te *ToolExecutor) WithBrowserDefaultTimeoutMS(ms int) *ToolExecutor {
	te.browserDefaultTimeoutMS = ms
	return te
}

// HTTP per-request timeout policy: default 10s, agent-overridable via the
// "timeout" JSON field on http_request, hard ceiling at 60s.
const (
	httpDefaultTimeout = 10 * time.Second
	httpMaxTimeout     = 60 * time.Second
)

// resolveHTTPTimeout maps a user-supplied seconds value to a duration. Zero
// or negative -> default; over the ceiling -> ceiling.
func resolveHTTPTimeout(seconds int) time.Duration {
	if seconds <= 0 {
		return httpDefaultTimeout
	}
	d := time.Duration(seconds) * time.Second
	if d > httpMaxTimeout {
		return httpMaxTimeout
	}
	return d
}

// httpTimeoutHint is the observation returned to the agent when an HTTP
// request was killed by the per-request timeout. It tells the agent both
// what happened and the two ways out — explicit "timeout":N or run_cmd curl.
func httpTimeoutHint(d time.Duration, url string) string {
	return fmt.Sprintf(
		"TIMEOUT after %s on %s. Hints: (a) retry with http_request {\"timeout\":30,...} for slow endpoints; (b) for >60s use run_cmd \"curl -m 120 -sS '%s'\"; (c) time-based attacks (sleep/WAITFOR) are reportable EVEN IF the request times out — note the timing and call report_finding.",
		d, url, url,
	)
}

// Findings returns all reported findings.
func (te *ToolExecutor) Findings() []Finding {
	return te.findings
}

// UpdateLastFinding replaces the most recently appended finding with the
// mutated copy. Used by the post-finding pipeline to write back enrichment
// (gate verdict, PoC, sandbox result, report markdown) without going through
// equality-based lookup (which breaks once any field has been set).
func (te *ToolExecutor) UpdateLastFinding(f Finding) {
	if len(te.findings) == 0 {
		return
	}
	te.findings[len(te.findings)-1] = f
}

func (te *ToolExecutor) DropLastFinding() (Finding, bool) {
	if len(te.findings) == 0 {
		return Finding{}, false
	}
	f := te.findings[len(te.findings)-1]
	te.findings = te.findings[:len(te.findings)-1]
	return f, true
}

// dropFinding removes the most recently appended finding. The post-finding
// pipeline always operates on the last-appended finding (see Run), so an
// identity-based search is unnecessary — and now impossible since Finding
// contains slice fields and is no longer comparable with ==.
func (te *ToolExecutor) dropFinding(_ Finding) {
	te.DropLastFinding()
}

// Execute runs a tool and returns the observation string.
func (te *ToolExecutor) Execute(ctx context.Context, tool, args string) string {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	switch tool {
	case "browser_open":
		return te.browserOpen(ctx, args)
	case "browser_screenshot":
		return te.browserScreenshot(ctx, args)
	case "evidence_screenshot":
		return te.evidenceScreenshot(ctx, args)
	case "browser_eval":
		return te.browserEval(ctx, args)
	case "browser_snapshot":
		return te.browserSnapshot(ctx)
	case "browser_click":
		return te.browserClick(ctx, args)
	case "browser_type":
		return te.browserType(ctx, args)
	case "browser_wait":
		return te.browserWait(ctx, args)
	case "browser_doctor":
		return te.browserDoctorTool(ctx)
	case "http_get":
		return te.httpGet(ctx, args)
	case "http_raw":
		return te.httpRaw(ctx, args)
	case "http_request":
		return te.httpRequest(ctx, args)
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

// evidenceScreenshot captures the current browser page as evidence for the
// next report_finding call. Optional positional argument is a short label
// (kebab-case recommended) that's woven into the filename; otherwise a
// timestamp is used. The path is staged in pendingEvidence and consumed by
// reportFinding (drained into Finding.Attachments).
func (te *ToolExecutor) evidenceScreenshot(ctx context.Context, label string) string {
	label = sanitizeEvidenceLabel(stripOuterQuotes(label))
	if label == "" {
		label = "evidence"
	}
	name := fmt.Sprintf("%s_%d.png", label, time.Now().UnixMilli())
	path := filepath.Join(te.screenshotDir, name)
	_ = os.MkdirAll(te.screenshotDir, 0o755)

	_, err := te.runBrowserCmd(ctx, "screenshot", path)
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	te.pendingEvidence = append(te.pendingEvidence, path)
	return fmt.Sprintf("OK: evidence captured (%s) — will attach to next report_finding (pending=%d)", path, len(te.pendingEvidence))
}

// sanitizeEvidenceLabel restricts an evidence label to a safe filename slug:
// lowercase ASCII letters/digits, dash, underscore. Anything else collapses
// to '_'. Trailing/leading separators are trimmed. Empty input -> "".
func sanitizeEvidenceLabel(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
		default:
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), "_-")
	if len(out) > 40 {
		out = out[:40]
	}
	return out
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

// browserSnapshot returns an interactive-only, compact accessibility tree
// with URLs on links. Per the agent-browser core skill, `-i` is the
// preferred mode for AI agents — it cuts payload size by ~80% versus the
// full tree (no empty structural nodes, no static text). Refs (@e1, @e2,
// ...) are still emitted and can be passed to browser_click / browser_type.
func (te *ToolExecutor) browserSnapshot(ctx context.Context) string {
	out, err := te.runBrowserCmd(ctx, "snapshot", "-i", "-c", "-u")
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	return truncate(out, 80000)
}

// browserWait exposes agent-browser's `wait` command to the agent. It
// accepts the full surface: numeric ms (`2000`), selector / @ref, and the
// flag forms (`--load networkidle`, `--load domcontentloaded`,
// `--text "..."`, `--url "**/dashboard"`, `--fn "<js>"`). Empty arg →
// defaults to `--load networkidle` which is the catch-all for SPA navs.
func (te *ToolExecutor) browserWait(ctx context.Context, args string) string {
	args = strings.TrimSpace(args)
	var cmdArgs []string
	if args == "" {
		cmdArgs = []string{"wait", "--load", "networkidle"}
	} else {
		// Allow shorthand "networkidle" / "domcontentloaded" / "load" by
		// auto-prefixing --load when the arg is a known wait state.
		switch strings.ToLower(args) {
		case "networkidle", "domcontentloaded", "load":
			cmdArgs = []string{"wait", "--load", strings.ToLower(args)}
		default:
			parts := splitArgsQuoteAware(args)
			cmdArgs = append([]string{"wait"}, parts...)
		}
	}
	out, err := te.runBrowserCmd(ctx, cmdArgs...)
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	if strings.TrimSpace(out) == "" {
		return "OK: wait completed"
	}
	return truncate(out, 4000)
}

// browserDoctorTool exposes `agent-browser doctor --offline --quick` to
// the agent so it can decide whether browser_* is healthy or whether it
// should fall back to http_get / run_cmd curl. The CLI doctor checks for
// Chrome installation, daemon state, version skew, and obvious env
// problems without making any network calls.
func (te *ToolExecutor) browserDoctorTool(ctx context.Context) string {
	out, err := te.runBrowserCmd(ctx, "doctor", "--offline", "--quick")
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	return truncate(out, 8000)
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

// runBrowserCmd spawns the `agent-browser` CLI with the given args and
// returns its stdout. The CLI runs as a persistent daemon between calls
// (state is preserved across subprocess invocations); this wrapper layers
// on the bb-hunter-specific harderning:
//
//  1. Default action timeout bumped from the CLI default (25 s) to 60 s
//     via AGENT_BROWSER_DEFAULT_TIMEOUT — slow lab pages (PortSwigger,
//     LFI labs with heavy JS) often need >25 s to fire DOMContentLoaded.
//  2. --session bb-hunter isolates our state from any other agent-browser
//     daemon running on the same host.
//  3. If the call fails with "CDP command timed out" we treat the daemon
//     as stale: call `agent-browser close --all` to kill Chrome + daemon
//     and retry the original command exactly once (with a fresh daemon).
//  4. Stderr is captured separately and logged at Warn level with full
//     structured fields — no more "ERROR: agent-browser open: …" with no
//     visibility into what actually went wrong.
//  5. If the binary is missing or the doctor disabled us at startup, we
//     fast-fail with a hint instead of spinning up Chrome every call.
func (te *ToolExecutor) runBrowserCmd(ctx context.Context, args ...string) (string, error) {
	if te.browserDisabled {
		return "", fmt.Errorf("agent-browser disabled by startup doctor: %s — use http_get/http_raw/run_cmd curl instead",
			strings.TrimSpace(te.browserDoctorReason))
	}
	// Outer Go-side timeout: must be > AGENT_BROWSER_DEFAULT_TIMEOUT so the
	// CLI's own CDP timeout fires first (giving us a parseable stderr) rather
	// than us SIGKILL-ing the daemon mid-command.
	outerTimeout := 90 * time.Second
	if te.browserDefaultTimeoutMS > 0 {
		// 30s headroom for CLI startup, Chrome cold-start, IPC, etc.
		if d := time.Duration(te.browserDefaultTimeoutMS)*time.Millisecond + 30*time.Second; d > outerTimeout {
			outerTimeout = d
		}
	}
	stdout, stderr, runErr := te.spawnBrowser(ctx, outerTimeout, args)

	// CDP timeout / stale daemon recovery: agent-browser returns a
	// structured error "✗ CDP command timed out: <op>" when Chrome stops
	// responding on the running daemon. The fix is to kill the daemon
	// (close --all) and retry from a fresh state.
	stderrStr := stderr.String()
	if runErr != nil && te.browserCloseOnTimeout && isCDPTimeoutErr(stderrStr) &&
		// Don't recurse: the close --all itself must not trigger another retry.
		!(len(args) > 0 && args[0] == "close") &&
		// Throttle to one recovery per 60s — if a target page is just
		// inherently slow, we don't want to ping-pong daemons.
		time.Since(te.lastCDPTimeout) > 60*time.Second {

		te.lastCDPTimeout = time.Now()
		te.logger.Warn("agent-browser: CDP timeout — resetting daemon",
			"cmd", args[0],
			"stderr", strings.TrimSpace(stderrStr),
		)
		// Kill all daemons + Chrome. We deliberately ignore the result;
		// failure here just means there was nothing to close.
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 15*time.Second)
		_, _, _ = te.spawnBrowser(closeCtx, 15*time.Second, []string{"close", "--all"})
		closeCancel()

		// Retry the original command once with a fresh daemon.
		stdout, stderr, runErr = te.spawnBrowser(ctx, outerTimeout, args)
		stderrStr = stderr.String()
		if runErr == nil {
			te.logger.Info("agent-browser: recovered after daemon reset", "cmd", args[0])
		}
	}

	if runErr != nil {
		errMsg := strings.TrimSpace(stderrStr)
		if errMsg == "" {
			errMsg = runErr.Error()
		}
		te.logger.Warn("agent-browser: command failed",
			"cmd", args[0],
			"args", argsPreview(args),
			"stderr", errMsg,
			"go_err", runErr.Error(),
		)
		// Track consecutive kills/crashes (only for crashes, not for
		// well-formed CLI errors like "selector not found").
		if isFatalProcessErr(stderrStr, runErr, ctx) {
			te.browserKills++
		}
		if te.browserKills >= 3 {
			return "", fmt.Errorf("agent-browser %s: %s (browser crashed %d times consecutively — consider using http_get/http_raw/run_cmd curl instead)",
				args[0], errMsg, te.browserKills)
		}
		return "", fmt.Errorf("agent-browser %s: %s", args[0], errMsg)
	}
	te.browserKills = 0
	te.logger.Debug("agent-browser: ok",
		"cmd", args[0],
		"args", argsPreview(args),
		"bytes", stdout.Len(),
	)
	return stdout.String(), nil
}

// spawnBrowser is the raw exec wrapper used by runBrowserCmd. It applies the
// outer Go-side timeout, builds the final argv (with --session prefix), and
// captures stdout/stderr into the provided buffers. Kept separate from
// runBrowserCmd so the CDP-timeout recovery path can reuse it without
// re-entering the recovery loop.
func (te *ToolExecutor) spawnBrowser(ctx context.Context, outerTimeout time.Duration, args []string) (bytes.Buffer, bytes.Buffer, error) {
	ctx, cancel := context.WithTimeout(ctx, outerTimeout)
	defer cancel()

	finalArgs := make([]string, 0, len(args)+2)
	if te.browserSessionName != "" {
		// --session is a global flag; must precede the command.
		finalArgs = append(finalArgs, "--session", te.browserSessionName)
	}
	finalArgs = append(finalArgs, args...)

	cmd := exec.CommandContext(ctx, te.agentBrowserBin, finalArgs...)
	// Inherit the parent env then layer on AGENT_BROWSER_DEFAULT_TIMEOUT.
	// We do NOT propagate proxyAddr here — agent-browser picks proxy up
	// from --proxy or HTTP_PROXY/HTTPS_PROXY, both of which the caller
	// can pre-set if needed. Keeping this simple avoids surprises when
	// the user runs the binary inside Burp / mitmproxy.
	env := os.Environ()
	if te.browserDefaultTimeoutMS > 0 {
		env = append(env, fmt.Sprintf("AGENT_BROWSER_DEFAULT_TIMEOUT=%d", te.browserDefaultTimeoutMS))
	}
	cmd.Env = env

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout, stderr, err
}

// isCDPTimeoutErr matches the CLI's "✗ CDP command timed out: <op>"
// stderr pattern. This is the canary that the daemon's Chrome instance
// has gone unresponsive and a close --all is warranted.
func isCDPTimeoutErr(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "cdp command timed out") ||
		strings.Contains(s, "failed to connect to chrome") ||
		strings.Contains(s, "no such session")
}

// isFatalProcessErr returns true when the agent-browser invocation
// crashed (SIGKILL, SIGSEGV, exec failure) as opposed to returning a
// well-formed CLI error message (selector not found, ref expired, etc).
// Only fatal errors count toward the browserKills throttle.
func isFatalProcessErr(stderr string, runErr error, ctx context.Context) bool {
	if ctx.Err() != nil {
		// Outer context cancelled / deadline exceeded: the parent step
		// killed us, not Chrome.
		return true
	}
	if runErr == nil {
		return false
	}
	lower := strings.ToLower(stderr + " " + runErr.Error())
	for _, m := range []string{"killed", "signal", "panic", "segmentation", "exit status 137"} {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// argsPreview returns a single-line, length-capped representation of an
// argv list, safe for slog output. Eval / fill payloads are truncated to
// keep log lines readable.
func argsPreview(args []string) string {
	const maxLen = 160
	var sb strings.Builder
	for i, a := range args {
		if i > 0 {
			sb.WriteByte(' ')
		}
		if len(a) > 80 {
			sb.WriteString(a[:77])
			sb.WriteString("...")
		} else {
			sb.WriteString(a)
		}
		if sb.Len() > maxLen {
			sb.WriteString(" ...")
			break
		}
	}
	return sb.String()
}

// BrowserHealthCheck runs `agent-browser doctor --offline --quick` once
// at startup and disables browser_* tools if the doctor reports a
// non-recoverable problem (missing binary, missing Chrome, Wayland-only
// env, etc.). Called from main.go after the executor is constructed.
//
// Failure modes:
//   - Binary not found on PATH    → log Error, browserDisabled=true
//   - Binary found but doctor fails → log Warn, mark reason but stay
//     optimistic (some doctor checks fail spuriously on first run); the
//     first real browser_* will surface the actual error to the agent.
//   - All good                    → log Info with version, leave enabled.
func (te *ToolExecutor) BrowserHealthCheck(ctx context.Context) {
	// First — is the binary even on PATH?
	if _, err := exec.LookPath(te.agentBrowserBin); err != nil {
		te.browserDisabled = true
		te.browserDoctorReason = fmt.Sprintf("binary '%s' not found on PATH", te.agentBrowserBin)
		te.logger.Error("agent-browser: binary missing",
			"bin", te.agentBrowserBin,
			"hint", "install with `npm install -g agent-browser && agent-browser install --with-deps`",
		)
		return
	}

	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	stdout, stderr, err := te.spawnBrowser(cctx, 30*time.Second, []string{"doctor", "--offline", "--quick"})
	combined := strings.TrimSpace(stdout.String() + "\n" + stderr.String())
	if err != nil {
		te.browserDoctorReason = combined
		// Don't disable on a non-zero doctor exit — the CLI sometimes
		// returns 1 for "minor issue, can still run". Just log loud and
		// let the first real call confirm or refute.
		te.logger.Warn("agent-browser: doctor reported issues",
			"err", err.Error(),
			"output", truncate(combined, 1200),
		)
		return
	}
	te.logger.Info("agent-browser: doctor OK",
		"output", truncate(combined, 600),
	)
}

// HTTP tools.

func (te *ToolExecutor) httpGet(ctx context.Context, url string) string {
	url = stripOuterQuotes(url)
	if url == "" {
		return "ERROR: url is required"
	}
	return te.doHTTPRequest(ctx, "GET", url, nil, "", 0)
}

func (te *ToolExecutor) httpRaw(ctx context.Context, args string) string {
	parts := splitArgsQuoteAware(args)
	if len(parts) < 2 {
		return `ERROR: usage: http_raw <method> <url> ["Header-Name: value" ...] ["body: payload"]`
	}
	method := strings.ToUpper(parts[0])
	url := parts[1]
	headers, bodyStr := parseHTTPRawParts(parts[2:])
	return te.doHTTPRequest(ctx, method, url, headers, bodyStr, 0)
}

func (te *ToolExecutor) httpRequest(ctx context.Context, args string) string {
	spec, err := parseHTTPRequestSpec(args)
	if err != nil {
		return fmt.Sprintf(`ERROR: invalid http_request JSON: %v. Expected {"method":"POST","url":"https://...","headers":{"Content-Type":"application/json"},"body":"...","timeout":10}`, err)
	}
	headers := spec.Headers
	if headers == nil {
		headers = map[string]string{}
	}
	return te.doHTTPRequest(ctx, spec.Method, spec.URL, headers, spec.Body, spec.Timeout)
}

// doHTTPRequest is the shared transport for http_get / http_raw / http_request.
// timeoutSec=0 -> httpDefaultTimeout. Any timeoutSec > httpMaxTimeout is
// clamped. On per-request timeout it returns the structured TIMEOUT hint so
// the agent can switch tactics (longer explicit timeout or run_cmd curl).
func (te *ToolExecutor) doHTTPRequest(ctx context.Context, method, rawURL string, headers map[string]string, body string, timeoutSec int) string {
	if strings.TrimSpace(rawURL) == "" {
		return "ERROR: url is required"
	}
	if method == "" {
		method = "GET"
	}
	timeout := resolveHTTPTimeout(timeoutSec)
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(reqCtx, method, rawURL, bodyReader)
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	for k, v := range headers {
		if isValidHeaderName(k) {
			req.Header.Set(k, v)
		}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) BB-Hunter-Agent/1.0")

	resp, err := te.httpClient.Do(req)
	if err != nil {
		// Distinguish per-request timeout from other transport errors so the
		// agent knows it can extend the timeout or fall back to curl.
		if reqCtx.Err() == context.DeadlineExceeded {
			return httpTimeoutHint(timeout, rawURL)
		}
		return fmt.Sprintf("ERROR: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 100000))

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("HTTP %d %s\n", resp.StatusCode, resp.Status))
	for k, v := range resp.Header {
		sb.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
	}
	sb.WriteString("\n")
	sb.Write(bodyBytes)

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

	// Drain pending evidence files (collected by evidence_screenshot etc.)
	// into Finding.Attachments. The persist stage will copy them into the
	// finding directory and rewrite Attachments to relative names.
	if len(te.pendingEvidence) > 0 {
		f.Attachments = append(f.Attachments, te.pendingEvidence...)
		te.pendingEvidence = nil
	}

	te.findings = append(te.findings, f)
	attachNote := ""
	if n := len(f.Attachments); n > 0 {
		attachNote = fmt.Sprintf(" (%d attachment(s) staged)", n)
	}
	return fmt.Sprintf("OK: finding #%d reported — %s %s at %s%s", len(te.findings), f.Severity, f.VulnClass, f.URL, attachNote)
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
// stripBrackets removes surrounding [] from a string. LLMs frequently wrap
// http_raw arguments in array-like brackets: ["Content-Type: ..."].
func stripBrackets(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '[' && s[len(s)-1] == ']' {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

// looksLikeJSONBody returns true if s looks like a JSON object or array
// that the LLM passed as body without the "body:" prefix.
func looksLikeJSONBody(s string) bool {
	s = strings.TrimSpace(s)
	return (strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}")) ||
		(strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"))
}

// isValidHeaderName checks that s is a plausible HTTP header name
// (alphanumeric + hyphens, no brackets/braces/quotes).
func isValidHeaderName(s string) bool {
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return len(s) > 0
}

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
