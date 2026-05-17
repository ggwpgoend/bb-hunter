// Package agent implements an autonomous LLM-driven bug bounty agent.
// The agent uses a ReAct (Reason+Act) loop where the LLM decides what
// tools to invoke, observes results, and reasons about next steps.
package agent

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// ANSI color codes for terminal output.
const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"

	bgBlue   = "\033[44m"
	bgGreen  = "\033[42m"
	bgYellow = "\033[43m"
	bgRed    = "\033[41m"
	bgPurple = "\033[45m"
)

// Display handles colorful terminal output for the agent.
type Display struct {
	step    int
	startAt time.Time
}

// NewDisplay creates a new terminal display.
func NewDisplay() *Display {
	return &Display{startAt: time.Now()}
}

// Banner prints the agent mode startup banner.
func (d *Display) Banner(target string, providerNames []string) {
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "%s%s ========================================== %s\n", colorBold, bgPurple, colorReset)
	fmt.Fprintf(os.Stderr, "%s%s   BB-Hunter Agent Mode                    %s\n", colorBold, bgPurple, colorReset)
	fmt.Fprintf(os.Stderr, "%s%s   LLM-driven autonomous bug hunting       %s\n", colorBold, bgPurple, colorReset)
	fmt.Fprintf(os.Stderr, "%s%s ========================================== %s\n", colorBold, bgPurple, colorReset)
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  %sTarget:%s     %s\n", colorDim, colorReset, target)
	fmt.Fprintf(os.Stderr, "  %sProviders:%s  %d LLM(s): %s\n", colorDim, colorReset, len(providerNames), strings.Join(providerNames, ", "))
	fmt.Fprintf(os.Stderr, "  %sStarted:%s    %s\n", colorDim, colorReset, time.Now().Format("15:04:05"))
	fmt.Fprintf(os.Stderr, "\n")
}

// Think prints an AI reasoning block with provider name.
func (d *Display) Think(thought, provider string) {
	d.step++
	elapsed := time.Since(d.startAt).Round(time.Second)
	if provider != "" {
		fmt.Fprintf(os.Stderr, "%s%s[%s | Step %d | %s]%s\n", colorBold, colorPurple, elapsed, d.step, provider, colorReset)
	} else {
		fmt.Fprintf(os.Stderr, "%s%s[%s | Step %d]%s\n", colorBold, colorPurple, elapsed, d.step, colorReset)
	}
	fmt.Fprintf(os.Stderr, "%s%s  THINK:%s %s\n", colorBold, colorCyan, colorReset, thought)
	fmt.Fprintf(os.Stderr, "\n")
}

// Waiting prints a progress message while waiting for LLM.
func (d *Display) Waiting(step, maxSteps int) {
	elapsed := time.Since(d.startAt).Round(time.Second)
	fmt.Fprintf(os.Stderr, "%s%s  ... AI is thinking [step %d/%d, %s elapsed] ...%s\n", colorBold, colorDim, step, maxSteps, elapsed, colorReset)
}

// Action prints a tool invocation.
func (d *Display) Action(tool, args string) {
	fmt.Fprintf(os.Stderr, "%s%s  ACTION:%s %s%s%s %s\n", colorBold, colorYellow, colorReset, colorBold, tool, colorReset, args)
}

// ActionDone prints tool execution time.
func (d *Display) ActionDone(tool string, dur time.Duration) {
	fmt.Fprintf(os.Stderr, "  %s%s  (%s took %s)%s\n", colorDim, colorGreen, tool, dur.Round(time.Millisecond), colorReset)
}

// Observation prints a tool result (truncated if long).
func (d *Display) Observation(result string) {
	lines := strings.Split(result, "\n")
	maxLines := 15
	truncated := false
	if len(lines) > maxLines {
		lines = lines[:maxLines]
		truncated = true
	}

	fmt.Fprintf(os.Stderr, "%s%s  OBSERVE:%s\n", colorBold, colorGreen, colorReset)
	for _, line := range lines {
		if len(line) > 200 {
			line = line[:200] + "..."
		}
		fmt.Fprintf(os.Stderr, "    %s%s%s\n", colorDim, line, colorReset)
	}
	if truncated {
		fmt.Fprintf(os.Stderr, "    %s... (%d more lines)%s\n", colorDim, len(strings.Split(result, "\n"))-maxLines, colorReset)
	}
	fmt.Fprintf(os.Stderr, "\n")
}

// Finding prints a discovered vulnerability.
func (d *Display) Finding(vulnClass, severity, url, description string) {
	severityColor := colorWhite
	switch strings.ToLower(severity) {
	case "critical":
		severityColor = colorRed
	case "high":
		severityColor = colorRed
	case "medium":
		severityColor = colorYellow
	case "low":
		severityColor = colorBlue
	case "info":
		severityColor = colorDim
	}

	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "%s%s !! FINDING !! %s\n", colorBold, bgRed, colorReset)
	fmt.Fprintf(os.Stderr, "  %sType:%s       %s\n", colorDim, colorReset, vulnClass)
	fmt.Fprintf(os.Stderr, "  %sSeverity:%s   %s%s%s%s\n", colorDim, colorReset, colorBold, severityColor, severity, colorReset)
	fmt.Fprintf(os.Stderr, "  %sURL:%s        %s\n", colorDim, colorReset, url)
	fmt.Fprintf(os.Stderr, "  %sDetails:%s    %s\n", colorDim, colorReset, description)
	fmt.Fprintf(os.Stderr, "\n")
}

// Error prints an error message.
func (d *Display) Error(msg string) {
	fmt.Fprintf(os.Stderr, "  %s%sERROR:%s %s\n", colorBold, colorRed, colorReset, msg)
}

// Info prints an informational message.
func (d *Display) Info(msg string) {
	fmt.Fprintf(os.Stderr, "  %s%sINFO:%s %s\n", colorBold, colorBlue, colorReset, msg)
}

// Summary prints the final agent summary.
func (d *Display) Summary(findings int, steps int, duration time.Duration) {
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "%s%s ========================================== %s\n", colorBold, bgGreen, colorReset)
	fmt.Fprintf(os.Stderr, "%s%s   Agent Complete                          %s\n", colorBold, bgGreen, colorReset)
	fmt.Fprintf(os.Stderr, "%s%s ========================================== %s\n", colorBold, bgGreen, colorReset)
	fmt.Fprintf(os.Stderr, "  %sSteps:%s      %d\n", colorDim, colorReset, steps)
	fmt.Fprintf(os.Stderr, "  %sFindings:%s   %d\n", colorDim, colorReset, findings)
	fmt.Fprintf(os.Stderr, "  %sDuration:%s   %s\n", colorDim, colorReset, duration.Round(time.Second))
	fmt.Fprintf(os.Stderr, "\n")
}
