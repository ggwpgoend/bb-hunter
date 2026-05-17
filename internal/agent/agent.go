package agent

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/llm"
)

// StopGraceSteps is the number of extra steps the agent is allowed to take
// after the user requests a graceful stop. This gives the model time to
// commit any pending evidence via report_finding before exiting.
const StopGraceSteps = 5

// FindingCallback is called when the agent reports a finding (e.g. for HITL integration).
type FindingCallback func(ctx context.Context, finding Finding) error

// Config holds agent configuration.
type Config struct {
	Target          string
	Domains         []string
	LLMClient       *llm.Client
	AgentBrowserBin string
	ScreenshotDir   string
	ProxyAddr       string
	MaxSteps        int // 0 = unlimited; agent runs until user requests stop or LLM emits 'done'
	Logger          *slog.Logger
	OnFinding       FindingCallback // called on each report_finding (HITL integration)
	LLMDelayMs      int             // delay between LLM calls in milliseconds (0 = default 3000ms)
}

// Agent is an autonomous LLM-driven bug bounty hunter.
type Agent struct {
	cfg      Config
	executor *ToolExecutor
	display  *Display
	log      *slog.Logger
	history  []llm.Message

	// stopRequested is set to 1 by RequestStop() to signal the run loop to
	// wind down gracefully. The loop runs at most StopGraceSteps more turns
	// after the flag flips, then exits regardless.
	stopRequested atomic.Bool
}

// New creates a new agent.
func New(cfg Config) *Agent {
	// MaxSteps == 0 means unlimited. Anything < 0 is treated as 0.
	if cfg.MaxSteps < 0 {
		cfg.MaxSteps = 0
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.LLMDelayMs <= 0 {
		cfg.LLMDelayMs = 3000
	}
	return &Agent{
		cfg:      cfg,
		executor: NewToolExecutor(cfg.AgentBrowserBin, cfg.ScreenshotDir, cfg.ProxyAddr),
		display:  NewDisplay(),
		log:      cfg.Logger,
	}
}

// RequestStop signals a graceful shutdown: the agent will receive a
// synthetic SYSTEM NOTE on the next turn telling it to report any
// remaining evidence and call `done`. After StopGraceSteps turns the loop
// exits unconditionally, returning whatever findings have been recorded.
// Calling RequestStop more than once is a no-op.
func (a *Agent) RequestStop() {
	a.stopRequested.Store(true)
}

// StopRequested reports whether RequestStop has been called.
func (a *Agent) StopRequested() bool {
	return a.stopRequested.Load()
}

const agentSystemPrompt = `You are an elite autonomous bug bounty hunter. You find REAL, EXPLOITABLE, VERIFIED vulnerabilities — never false positives.

## Response Format
Every turn you MUST output exactly:
THINK: <detailed reasoning: what you learned, what you suspect, what to try next, WHY>
ACTION: <tool_name> <arguments>

Only ONE action per turn. Wait for OBSERVATION before your next turn.

## GOLDEN RULE: VERIFY BEFORE REPORTING
A vulnerability is ONLY real if you can demonstrate attacker impact:
- XSS: your payload EXECUTES (reflected unencoded in HTML context, not inside a string/attribute that neutralizes it)
- SQLi: you get a DIFFERENT response for true vs false condition (boolean-based), or you extract data (UNION-based), or you see a raw SQL error with your injected syntax
- SSTI: your arithmetic (e.g. {{7*7}}) is EVALUATED and you see 49 in the response
- Path Traversal: you read a file you shouldn't (e.g. /etc/passwd content appears)
- Open Redirect: the server sends a 3xx with Location pointing to your attacker URL
- SSRF: you can reach an internal resource or get a callback
- IDOR: you access another user's data by changing an ID

If you inject a payload and the server returns 500 / error / empty — that is NOT a vulnerability. That is the server rejecting bad input. Move on.

## Strategy

### Phase 1: Reconnaissance (2-4 steps)
1. run_katana on the target to discover all endpoints, forms, parameters, JS files
2. http_get the main page — read headers (Server, X-Powered-By, Set-Cookie flags), note the tech stack
3. http_get /robots.txt and /sitemap.xml if they exist — they often reveal hidden paths
4. If the target has a /vulnerabilities or similar listing page, READ IT — it tells you exactly what vuln classes exist and where to look

### Phase 2: Attack Surface Mapping (3-6 steps)
For EACH interesting endpoint found in Phase 1:
1. browser_open the page, then browser_eval to extract forms, inputs, links, and JS sources:
   - browser_eval document.querySelectorAll('form').length
   - browser_eval JSON.stringify([...document.querySelectorAll('input,textarea,select')].map(e=>({tag:e.tagName,name:e.name,id:e.id,type:e.type})))
   - browser_eval JSON.stringify([...document.querySelectorAll('a')].map(a=>a.href).filter(h=>h.includes(location.host)))
2. For each form: note the action URL, method, and parameter names
3. For each JS file: http_get it, search for fetch()/XMLHttpRequest/axios calls, API endpoints, hardcoded tokens
4. Build a mental map: "endpoint X accepts params [a, b, c] via POST" — then test each param

### Phase 3: Vulnerability Testing (spend 60-80%% of your steps here)
For EACH input point (URL param, form field, cookie, header), test vuln classes methodically.
The key: inject payload → read response → check if payload was PROCESSED (not just rejected).

**XSS — Reflected/Stored:**
1. Inject a UNIQUE canary (e.g. bb1337xss) in the parameter
2. Check if the canary appears in the response HTML. If yes — note the context (HTML body, attribute, JS string)
3. Craft a context-appropriate payload:
   - HTML body: <img src=x onerror=alert(1)>
   - Inside attribute value="...": " onmouseover=alert(1) x="
   - Inside JS string: ';alert(1)//
   - Inside URL/href: javascript:alert(1)
4. Verify: does the payload appear UNENCODED in the response? If < becomes &lt; — it's filtered, move on
5. ONLY report if the payload would execute in a real browser

**SQL Injection:**
1. Send normal value (id=1) → note the response
2. Send id=1' → if you get a SQL error message mentioning syntax/SQL/query, that's a strong signal
3. Boolean test: id=1 AND 1=1 (should return normal) vs id=1 AND 1=2 (should return different/empty)
4. If boolean works: try UNION SELECT to extract data: id=1 UNION SELECT null,null,null--
5. A 500 error alone is NOT SQLi. You need either: SQL error message, boolean difference, or UNION data extraction

**Server-Side Template Injection (SSTI):**
1. Inject {{7*7}} in a parameter → check if response contains 49
2. Inject ${7*7} → check for 49
3. Inject #{7*7} → check for 49
4. If 49 appears, escalate: try {{config}} or {{self.__class__.__mro__}}

**Path Traversal / LFI:**
1. Look for params like: file=, path=, page=, template=, include=, doc=
2. Test: ....//....//....//etc/passwd (or ..%%2f..%%2f..%%2fetc/passwd for URL encoding bypass)
3. Verify: does the response contain "root:x:0:0" or actual file contents?

**Open Redirect:**
1. Find redirect params: url=, next=, redirect=, return_to=, goto=, continue=
2. Test: url=https://evil.com or url=//evil.com
3. Verify: does the response have 3xx status with Location: https://evil.com?

**SSRF:**
1. Find URL-fetching params: url=, api=, fetch=, proxy=, callback=
2. Test: url=http://127.0.0.1:80 or url=http://169.254.169.254/latest/meta-data/
3. Verify: does the response contain internal data or a different response than normal?

**CORS Misconfiguration:**
1. http_raw GET <target_url> Origin:https://evil.com
2. Check: does Access-Control-Allow-Origin echo https://evil.com AND Access-Control-Allow-Credentials: true?
3. If origin is reflected without credentials — it's informational, not exploitable

**Prototype Pollution (JS):**
1. Look for JS code that does deep merge, Object.assign, or param parsing (deparam, query-string)
2. Test: add __proto__[polluted]=true to URL params or POST body
3. Verify via browser_eval: check if Object.prototype.polluted === true

**CSRF:**
1. Check if state-changing forms (POST/PUT/DELETE) have anti-CSRF tokens
2. Check SameSite cookie attribute — if SameSite=Lax or Strict, CSRF is mitigated
3. CSRF is only reportable if: no token AND SameSite=None (or missing) AND the action has security impact

### Phase 4: Verification & Reporting
- Before calling report_finding, you MUST have concrete evidence in the HTTP response
- Include the EXACT request (method, URL, headers, body) and the EXACT response snippet proving exploitation
- Each report_finding call is independent — report each vuln separately as you find it

## FALSE POSITIVE CHECKLIST (review EVERY time before report_finding)
- [ ] Is this a real vuln or just a server error / WAF block / input validation? → 500/403/400 alone = NOT a vuln
- [ ] Did my payload actually execute/process, or was it sanitized/encoded? → Check response carefully
- [ ] Am I reporting infrastructure noise (timeout, DNS, TLS error)? → NOT a vuln
- [ ] Am I reporting a "vulnerability" page that lists vulns for educational purposes? → That's documentation, NOT a finding
- [ ] Did I verify with a SECOND request to confirm it's reproducible? → Always double-check

## CRITICAL: Browser CSS selector syntax
browser_click and browser_type require CSS selectors, NOT [ref=eXX] tokens.
The [ref=eXX] labels in browser_snapshot output are for display only and WILL NOT WORK.
Use real CSS selectors:
- #searchBar
- input[name="searchTerm"]
- form[action="/search"] input[type=text]
- button.submit-btn
If you don't know the selector, run: browser_eval document.querySelector('form').outerHTML

## CRITICAL: Report findings IMMEDIATELY
The MOMENT you have VERIFIED evidence, call report_finding. Do not accumulate findings.

ACTION: report_finding {"vuln_class":"XSS","severity":"high","url":"https://target/search?q=<svg/onload=alert(1)>","description":"Reflected XSS in q parameter — payload reflected unencoded in HTML body","evidence":"Request: GET /search?q=<svg/onload=alert(1)>\nResponse: HTTP 200\n...<svg/onload=alert(1)>... (no encoding applied)"}

## Anti-Patterns (DO NOT DO THESE)
- Do NOT spend 6+ steps on browser_snapshot of the same page — extract what you need with browser_eval
- Do NOT run nuclei with no template filter on the entire site — it wastes time
- Do NOT report a 500 Internal Server Error as SQLi
- Do NOT ignore a /vulnerabilities or hints page — it is your roadmap
- Do NOT keep exploring new surface area when you have unverified suspicions — verify first, then move on
- Do NOT call done until you have tested at least XSS, SQLi, and SSTI on the main input points

%s`

// Run starts the autonomous agent loop.
func (a *Agent) Run(ctx context.Context) ([]Finding, error) {
	startTime := time.Now()

	// Show banner with provider names
	var providerNames []string
	for _, p := range a.cfg.LLMClient.Providers() {
		providerNames = append(providerNames, p.Name())
	}
	a.display.Banner(a.cfg.Target, providerNames)

	// Initialize conversation with system prompt and first user message
	a.history = []llm.Message{
		{Role: llm.RoleSystem, Content: fmt.Sprintf(agentSystemPrompt, ToolsPrompt())},
		{Role: llm.RoleUser, Content: a.buildInitialPrompt()},
	}

	a.display.Info(fmt.Sprintf("Starting autonomous investigation of %s", a.cfg.Target))
	if a.cfg.MaxSteps == 0 {
		a.display.Info("Unlimited step budget — press Ctrl+C once to request a graceful stop (agent will commit findings and exit), twice to hard-kill.")
	}

	// stopInjectedAtStep is the step at which the graceful-stop SYSTEM NOTE
	// was added to history; used to bound the post-stop window.
	stopInjectedAtStep := 0

	// loopActive returns true while the agent should keep iterating.
	loopActive := func(step int) bool {
		// Hard cap (only when MaxSteps > 0).
		if a.cfg.MaxSteps > 0 && step > a.cfg.MaxSteps {
			return false
		}
		// Graceful-stop window: once requested, allow up to StopGraceSteps
		// more turns, then exit.
		if stopInjectedAtStep > 0 && step > stopInjectedAtStep+StopGraceSteps {
			return false
		}
		return true
	}

	for step := 1; loopActive(step); step++ {
		select {
		case <-ctx.Done():
			a.display.Info("Agent interrupted by user (hard kill)")
			goto endLoop
		default:
		}

		a.log.Info("agent: step", "step", step, "max", a.cfg.MaxSteps, "stop_requested", a.stopRequested.Load())
		a.display.Waiting(step, a.cfg.MaxSteps)

		// Rate limit: pause between LLM calls (configurable via --agent-delay)
		if step > 1 {
			time.Sleep(time.Duration(a.cfg.LLMDelayMs) * time.Millisecond)
		}

		// Graceful stop: inject a SYSTEM NOTE once, then let the loopActive
		// helper count down StopGraceSteps more turns before exiting.
		if a.stopRequested.Load() && stopInjectedAtStep == 0 {
			stopInjectedAtStep = step
			a.display.Info(fmt.Sprintf("Stop requested — granting %d more steps to commit findings and exit gracefully.", StopGraceSteps))
			a.history = append(a.history, llm.Message{
				Role: llm.RoleUser,
				Content: fmt.Sprintf("SYSTEM NOTE: the user requested a graceful stop. You have AT MOST %d more turns. If you have ANY evidence of a vulnerability (reflected payload, SQL error, open redirect, CSRF, prototype pollution, etc.), call report_finding IMMEDIATELY on the next action — one report per turn. When you have committed every finding you have evidence for, output `ACTION: done` to exit cleanly. Do NOT keep exploring new attack surface.", StopGraceSteps),
			})
		}

		// Call LLM
		llmStart := time.Now()
		resp, err := a.cfg.LLMClient.Complete(ctx, &llm.Request{
			Messages:    a.history,
			MaxTokens:   1024,
			Temperature: 0.2,
		})
		if err != nil {
			a.display.Error(fmt.Sprintf("LLM call failed: %v — retrying in 10s...", err))
			a.log.Error("agent: LLM failed", "step", step, "error", err)
			// Rate-limit aware retry: wait longer
			time.Sleep(10 * time.Second)
			resp, err = a.cfg.LLMClient.Complete(ctx, &llm.Request{
				Messages:    a.history,
				MaxTokens:   1024,
				Temperature: 0.2,
			})
			if err != nil {
				// Second retry with even longer wait
				a.display.Error(fmt.Sprintf("LLM retry failed: %v — retrying in 30s...", err))
				time.Sleep(30 * time.Second)
				resp, err = a.cfg.LLMClient.Complete(ctx, &llm.Request{
					Messages:    a.history,
					MaxTokens:   1024,
					Temperature: 0.2,
				})
				if err != nil {
					return a.executor.Findings(), fmt.Errorf("agent: LLM failed after 3 retries: %w", err)
				}
			}
		}

		// Parse the response
		content := strings.TrimSpace(resp.Content)
		a.history = append(a.history, llm.Message{Role: llm.RoleAssistant, Content: content})

		a.display.Info(fmt.Sprintf("LLM responded in %s via %s (%d tokens)",
			time.Since(llmStart).Round(time.Millisecond), resp.Provider, resp.InputTokens+resp.OutputTokens))

		a.log.Debug("agent: LLM response",
			"step", step,
			"provider", resp.Provider,
			"tokens", resp.InputTokens+resp.OutputTokens,
			"content_len", len(content),
		)

		// Extract THINK and ACTION
		think, tool, args := parseResponse(content)

		if think != "" {
			a.display.Think(think, resp.Provider)
		}

		if tool == "" {
			a.display.Error("LLM did not output a valid ACTION. Nudging...")
			a.history = append(a.history, llm.Message{
				Role:    llm.RoleUser,
				Content: "You must output THINK: followed by ACTION: on the next line. Please try again with a valid action.",
			})
			continue
		}

		// Handle done
		if tool == "done" {
			a.display.Info(fmt.Sprintf("Agent finished: %s", args))
			break
		}

		// Display action
		a.display.Action(tool, args)

		// Execute tool
		toolStart := time.Now()
		observation := a.executor.Execute(ctx, tool, args)
		a.display.ActionDone(tool, time.Since(toolStart))

		// Display observation
		a.display.Observation(observation)

		// If it's a finding, display it prominently and call HITL callback
		if tool == "report_finding" && strings.HasPrefix(observation, "OK:") {
			findings := a.executor.Findings()
			if len(findings) > 0 {
				f := findings[len(findings)-1]
				a.display.Finding(f.VulnClass, f.Severity, f.URL, f.Description)
				if a.cfg.OnFinding != nil {
					if err := a.cfg.OnFinding(ctx, f); err != nil {
						a.log.Error("agent: OnFinding callback failed", "error", err)
					}
				}
			}
		}

		// Add observation to history
		a.history = append(a.history, llm.Message{
			Role:    llm.RoleUser,
			Content: fmt.Sprintf("OBSERVATION: %s", observation),
		})

		// Trim history if too long (keep system + last N messages)
		a.trimHistory()
	}

endLoop:
	findings := a.executor.Findings()
	a.display.Summary(len(findings), a.display.step, time.Since(startTime))

	return findings, nil
}

func (a *Agent) buildInitialPrompt() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Target: %s\n", a.cfg.Target))
	if len(a.cfg.Domains) > 0 {
		sb.WriteString(fmt.Sprintf("Scope domains: %s\n", strings.Join(a.cfg.Domains, ", ")))
	}
	sb.WriteString("\nBegin your investigation. Start with reconnaissance to understand the target.")
	return sb.String()
}

// parseResponse extracts THINK and ACTION from LLM output.
func parseResponse(content string) (think, tool, args string) {
	lines := strings.Split(content, "\n")

	var thinkLines []string
	inThink := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Check for THINK:
		if strings.HasPrefix(trimmed, "THINK:") {
			inThink = true
			thought := strings.TrimSpace(strings.TrimPrefix(trimmed, "THINK:"))
			if thought != "" {
				thinkLines = append(thinkLines, thought)
			}
			continue
		}

		// Check for ACTION:
		if strings.HasPrefix(trimmed, "ACTION:") {
			inThink = false
			action := strings.TrimSpace(strings.TrimPrefix(trimmed, "ACTION:"))
			parts := strings.SplitN(action, " ", 2)
			tool = strings.TrimSpace(parts[0])
			if len(parts) > 1 {
				args = strings.TrimSpace(parts[1])
			}
			break
		}

		// Continuation of THINK
		if inThink && trimmed != "" {
			thinkLines = append(thinkLines, trimmed)
		}
	}

	think = strings.Join(thinkLines, " ")
	return
}

// trimHistory keeps conversation manageable by removing old messages.
func (a *Agent) trimHistory() {
	maxMessages := 30
	if len(a.history) <= maxMessages {
		return
	}
	// Keep system prompt (index 0) + initial user prompt (index 1) + last N messages
	keepFromEnd := maxMessages - 2
	newHistory := make([]llm.Message, 0, maxMessages)
	newHistory = append(newHistory, a.history[0]) // system
	newHistory = append(newHistory, a.history[1]) // initial
	newHistory = append(newHistory, llm.Message{
		Role:    llm.RoleUser,
		Content: "[Earlier conversation trimmed for context. Continue your investigation based on what you've learned so far.]",
	})
	newHistory = append(newHistory, a.history[len(a.history)-keepFromEnd:]...)
	a.history = newHistory
}
