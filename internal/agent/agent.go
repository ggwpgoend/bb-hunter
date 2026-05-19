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
	reflect  *reflectState

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
		reflect:  newReflectState(),
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

const agentSystemPrompt = `You are an expert autonomous bug bounty hunter. Your goal is to find REAL, EXPLOITABLE vulnerabilities on the target.

## Available Tools
%s

## Response Format
Every turn you MUST output EXACTLY this structure, with ACTION: on its own line:

THINK: <reasoning>
ACTION: <tool_name> <arguments>

Do not wrap the block in code fences. Do not put "ACTION:" inside the THINK content; always start a new line for ACTION:.

## THINK Discipline
1. At the start of every THINK, scan back through the conversation history and re-read any prior "HYPOTHESIS:" lines you emitted. Carry them forward in your reasoning — they are your working memory and survive context trimming.
2. Do NOT repeat what you already said in earlier THINKs. Push the reasoning forward.
3. Keep THINK focused: what changed in the last observation, what you now believe, what concrete next action follows from that belief.

## HYPOTHESIS Contract
Whenever you suspect (even weakly) a specific vulnerability, emit a separate line in your THINK block in this exact format:

HYPOTHESIS: <vuln_class> @ <url> :: <one-sentence reasoning>

Examples:
HYPOTHESIS: idor @ https://t.example.com/api/v1/users/42 :: numeric id, no auth header sent on request, response body changed when id varied
HYPOTHESIS: reflected_xss @ https://t.example.com/search?q= :: payload "<svg/onload=alert(1)>" reflected unencoded in response

These lines are your durable memory. You MUST emit them when you have a working theory — even before you have proof.

## Tools Policy & Freedom
You have HTTP, Browser, Katana, Nuclei, Cmd tools. Use them to GATHER data; do the reasoning yourself.
1. Use run_katana / run_subfinder to discover endpoints. Read their output carefully — it usually contains the real attack surface.
2. When testing endpoints, prefer the MOST PROMISING one first based on recon evidence (parameters in URL, suspicious paths like /admin /api/v1/users/<id>, error messages, redirected responses). Do not parallel-test guessed-at endpoints — confirm they exist first.
3. Prefer http_get / http_raw for endpoint probing. Use browser_* tools ONLY when you need JavaScript execution, client-side routing, or DOM-based behaviour. Browser tools are slow and lossy.
4. 4xx/5xx responses are signal, not noise. Read the headers (Location, WWW-Authenticate, Set-Cookie, X-CSRF-Token, Content-Type) and the first chunk of the body — they tell you what the server expects.
5. If you need custom exploit logic or data processing, use run_cmd to execute python/node/bash. You have full freedom to write and run code.

## Browser Usage (agent-browser)
browser_snapshot returns an accessibility tree. Elements are marked like [@e30]. Pass refs directly:
- browser_click @e30
- browser_type @e4 my text
- browser_eval document.querySelector('form').submit()

After ANY browser_click, ALWAYS verify that navigation actually happened. Run:
  ACTION: browser_eval window.location.href
If the URL is unchanged AND the element had an href attribute, the click was swallowed by the SPA router. Recover with:
  ACTION: browser_open <the href value>
Do NOT repeat the same browser_click — it will fail again.

Always call browser_snapshot -i after a page load to refresh the [@e] references.

## Reporting Cadence
The MOMENT you have evidence (reflected payload, SQL error, leaked data, auth bypass, open redirect, prototype pollution, etc.) call report_finding IMMEDIATELY on the next turn. Do not batch findings.

Format:
ACTION: report_finding {"vuln_class": "xss", "severity": "high", "url": "...", "description": "...", "evidence": "..."}

If your JSON is malformed, the system will extract your description anyway — but try to keep it valid.

## Anti-Loop Discipline
If you see a "SYSTEM NOTE:" message in the conversation, the run loop has detected that you are stuck (repeating an action, oscillating between two tools, or producing repeated errors). When you see one, you MUST change at least one of: (a) the tool, (b) the target URL/endpoint, (c) the vuln class you are probing. Do NOT retry the same action with cosmetic changes (different casing, trailing slash, etc.) — that does not break the loop.`

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
		// Graceful-stop window: once requested, allow exactly StopGraceSteps
		// total turns starting with the injection turn, then exit.
		if stopInjectedAtStep > 0 && step >= stopInjectedAtStep+StopGraceSteps {
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
			note, ok := a.reflect.Observe(step, "", "", resultNoAction)
			nudge := "You must output THINK: followed by ACTION: on the next line. Please try again with a valid action."
			if ok {
				a.log.Info("agent: reflection injected", "step", step, "trigger", "no_action")
				a.display.Info(note)
				nudge = note
			}
			a.history = append(a.history, llm.Message{
				Role:    llm.RoleUser,
				Content: nudge,
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

		// Reflection: record this turn, inject a SYSTEM NOTE if a loop/error
		// pattern was detected.
		result := resultOK
		if strings.HasPrefix(observation, "ERROR:") {
			result = resultErr
		}
		if note, ok := a.reflect.Observe(step, tool, args, result); ok {
			a.log.Info("agent: reflection injected", "step", step, "tool", tool, "result", result)
			a.display.Info(note)
			a.history = append(a.history, llm.Message{
				Role:    llm.RoleUser,
				Content: note,
			})
		}

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
//
// Handles both multi-line and single-line formats:
//
//	THINK: reasoning        (multi-line, standard)
//	ACTION: tool args
//
//	THINK: reasoning ACTION: tool args   (single-line, some models)
func parseResponse(content string) (think, tool, args string) {
	lines := strings.Split(content, "\n")

	var thinkLines []string
	inThink := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Check for an embedded ACTION: marker anywhere in the line.
		// This catches the single-line "THINK: ... ACTION: ..." pattern
		// and standalone "ACTION: ..." lines alike.
		if actionIdx := findActionMarker(trimmed); actionIdx >= 0 {
			before := strings.TrimSpace(trimmed[:actionIdx])
			actionContent := strings.TrimSpace(trimmed[actionIdx+len("ACTION:"):])

			// Carry over any text before ACTION: as THINK content.
			if strings.HasPrefix(before, "THINK:") {
				thought := strings.TrimSpace(strings.TrimPrefix(before, "THINK:"))
				if thought != "" {
					thinkLines = append(thinkLines, thought)
				}
			} else if inThink && before != "" {
				thinkLines = append(thinkLines, before)
			}

			tool, args = splitToolArgs(actionContent)
			break
		}

		// No ACTION: on this line — check for THINK: start.
		if strings.HasPrefix(trimmed, "THINK:") {
			inThink = true
			thought := strings.TrimSpace(strings.TrimPrefix(trimmed, "THINK:"))
			if thought != "" {
				thinkLines = append(thinkLines, thought)
			}
			continue
		}

		// Continuation of THINK block.
		if inThink && trimmed != "" {
			thinkLines = append(thinkLines, trimmed)
		}
	}

	think = strings.Join(thinkLines, " ")
	return
}

// findActionMarker returns the byte index of an "ACTION:" token in s that
// acts as a real marker: preceded by whitespace (or at position 0) AND
// followed by whitespace (or at end of string). This avoids false positives
// like "ACTION:Forbidden" inside THINK text.
// Returns -1 if no valid marker is found.
func findActionMarker(s string) int {
	const marker = "ACTION:"
	mLen := len(marker)
	n := len(s)
	for i := 0; i+mLen <= n; i++ {
		if s[i:i+mLen] != marker {
			continue
		}
		if i > 0 && s[i-1] != ' ' && s[i-1] != '\t' {
			continue
		}
		afterIdx := i + mLen
		if afterIdx < n && s[afterIdx] != ' ' && s[afterIdx] != '\t' {
			continue
		}
		return i
	}
	return -1
}

// splitToolArgs splits "tool_name args..." into tool and args.
func splitToolArgs(action string) (string, string) {
	parts := strings.SplitN(action, " ", 2)
	t := strings.TrimSpace(parts[0])
	a := ""
	if len(parts) > 1 {
		a = strings.TrimSpace(parts[1])
	}
	return t, a
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
