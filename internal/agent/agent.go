package agent

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/llm"
)

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
	MaxSteps        int
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
}

// New creates a new agent.
func New(cfg Config) *Agent {
	if cfg.MaxSteps <= 0 {
		cfg.MaxSteps = 30
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

const agentSystemPrompt = `You are an expert autonomous bug bounty hunter. Your goal is to find REAL, EXPLOITABLE vulnerabilities on the target — not infrastructure noise.

## Response Format
Every turn you MUST output exactly:
THINK: <your detailed reasoning — what you learned, what you suspect, what to try next>
ACTION: <tool_name> <arguments>

## Strategy (follow this order)

### Phase 1: Reconnaissance & Discovery
1. Use run_katana to crawl the target and discover endpoints, forms, parameters, API paths
2. Use http_get on the main page to understand the technology stack (headers, cookies, frameworks)
3. Use browser_open + browser_snapshot to see rendered pages and find JavaScript-heavy features
4. Use browser_eval to extract: all <form> elements, all <a> links, all <script> sources, hidden inputs, API endpoints in JS code
5. Look for: admin panels, login forms, search fields, file upload, user input fields, API endpoints, WebSocket connections

### Phase 2: Deep Analysis (CRITICAL — spend most time here)
Before testing vulnerabilities, you MUST deeply analyze what you found:
- Read the HTML source carefully via browser_eval: document.documentElement.outerHTML
- Look for JavaScript files and analyze them for API endpoints, tokens, interesting functions
- Identify ALL user input points: URL parameters, form fields, cookies, headers, JSON bodies
- Map the application: what pages exist, what parameters they accept, what backend technology is used
- Look for comments in HTML/JS that reveal internal paths, developer notes, or debug info
- Check for common interesting paths: /api/, /admin/, /debug/, /swagger/, /.env, /robots.txt, /sitemap.xml
- Analyze cookies: are they HttpOnly? Secure? SameSite? Look for session management issues
- Check response headers: missing security headers (CSP, X-Frame-Options, HSTS, etc.)

### Phase 3: Vulnerability Testing (test each class methodically)
For each input point you found, test these vulnerability classes IN ORDER:

**XSS (Cross-Site Scripting):**
- Reflected: inject <script>alert(1)</script> and variations in URL params and form fields
- Check if input is reflected in response without encoding
- Try different contexts: HTML body, attribute values, JavaScript strings, URLs
- Test bypasses: <img onerror=alert(1) src=x>, <svg onload=alert(1)>, javascript: URLs

**SQL Injection:**
- Add ' (single quote) to parameters and check for SQL error messages
- Try: ' OR '1'='1, ' UNION SELECT null--, 1 AND 1=1, 1 AND 1=2
- Look for: MySQL errors, PostgreSQL errors, ORA- errors, Microsoft SQL errors
- Test both GET parameters and POST form fields

**Server-Side Template Injection (SSTI):**
- Inject {{7*7}} or ${7*7} or #{7*7} in inputs
- If you see 49 in the response, it's vulnerable
- Try: {{config}}, {{self.__class__}}, <%%= 7*7 %%>

**Path Traversal / LFI:**
- Test: ../../../../etc/passwd, ..%%2f..%%2f..%%2fetc/passwd
- Look for file inclusion parameters: file=, path=, page=, include=, template=

**IDOR (Insecure Direct Object Reference):**
- Find endpoints with IDs (e.g., /user/123, /order/456)
- Try changing IDs to access other users' data

**Open Redirect:**
- Look for redirect parameters: url=, redirect=, next=, return=, goto=
- Test: redirect=https://evil.com

**SSRF (Server-Side Request Forgery):**
- Look for URL parameters that fetch remote content
- Test: url=http://127.0.0.1, url=http://169.254.169.254/

**CORS Misconfiguration:**
- Send requests with Origin: https://evil.com header
- Check if Access-Control-Allow-Origin reflects the evil origin

**Security Headers:**
- Check for missing: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security

### Phase 4: Verification & Reporting
- ONLY report findings you can PROVE with evidence
- Include the exact request/response that demonstrates the vulnerability
- Use http_raw to craft precise proof-of-concept requests
- DO NOT report: server errors (500), timeouts, infrastructure issues, missing DNS records
- DO NOT report: generic "server returned error" as a finding
- Severity guide: Critical=RCE/auth bypass, High=SQLi/XSS with impact, Medium=CSRF/info disclosure, Low=missing headers

## Important Rules
- One action per turn
- Stay within scope domains
- Be methodical: test ONE thing at a time, observe the result, then decide next step
- If a tool times out or fails, try a different approach instead of repeating
- Prefer browser_eval for extracting specific data (faster than browser_snapshot for large pages)
- Use http_raw for precise vulnerability testing with custom headers/body
- NEVER report infrastructure errors (500, timeout, DNS failure) as vulnerabilities
- When done investigating all attack surfaces, use the done tool

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

	for step := 1; step <= a.cfg.MaxSteps; step++ {
		select {
		case <-ctx.Done():
			a.display.Info("Agent interrupted by user (Ctrl+C)")
			break
		default:
		}

		a.log.Info("agent: step", "step", step, "max", a.cfg.MaxSteps)
		a.display.Waiting(step, a.cfg.MaxSteps)

		// Rate limit: pause between LLM calls (configurable via --agent-delay)
		if step > 1 {
			time.Sleep(time.Duration(a.cfg.LLMDelayMs) * time.Millisecond)
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
