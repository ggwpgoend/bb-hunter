package agent

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/llm"
)

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
	return &Agent{
		cfg:      cfg,
		executor: NewToolExecutor(cfg.AgentBrowserBin, cfg.ScreenshotDir, cfg.ProxyAddr),
		display:  NewDisplay(),
		log:      cfg.Logger,
	}
}

const agentSystemPrompt = `You are an autonomous bug bounty hunter. Find real vulnerabilities on the target.

ReAct loop: THINK then ACTION each turn. Format:
THINK: <reasoning>
ACTION: <tool> <args>

%s

Rules: one action/turn. Stay in scope. Only report verified findings with evidence. Be methodical: recon → hypothesize → test → verify → report. Use done when finished.
`

// Run starts the autonomous agent loop.
func (a *Agent) Run(ctx context.Context) ([]Finding, error) {
	startTime := time.Now()

	// Show banner
	providerCount := len(a.cfg.LLMClient.Providers())
	a.display.Banner(a.cfg.Target, providerCount)

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

		// Rate limit: pause between LLM calls to avoid free-tier throttling
		if step > 1 {
			time.Sleep(3 * time.Second)
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
			a.display.Think(think)
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

		// If it's a finding, display it prominently
		if tool == "report_finding" && strings.HasPrefix(observation, "OK:") {
			findings := a.executor.Findings()
			if len(findings) > 0 {
				f := findings[len(findings)-1]
				a.display.Finding(f.VulnClass, f.Severity, f.URL, f.Description)
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
