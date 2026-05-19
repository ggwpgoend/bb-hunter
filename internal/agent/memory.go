package agent

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// hypothesis is a single durable working-memory entry.
//
// HYPOTHESIS lines are emitted by the LLM in THINK blocks per the contract
// in agentSystemPrompt. The parser stores them keyed by (vuln_class, url)
// so cosmetic re-emits do not flood the working-memory block.
type hypothesis struct {
	Class    string
	URL      string
	Why      string
	Created  time.Time
	Updated  time.Time
	Mentions int // number of times the LLM re-emitted this (class, url)
}

// workingMemory keeps the agent's durable hypotheses for the current session.
//
// The block produced by Block() is injected into every LLM call as a leading
// user message (see Agent.Run); it therefore survives history trimming and
// keeps a compact summary of "what we already suspect" at the top of the
// model's attention window. session_id is generated once per Agent and is
// stable across the whole run so future 24/7 / cross-session recall can
// key off it.
type workingMemory struct {
	mu        sync.Mutex
	sessionID string
	maxChars  int // approx 4 chars / token; default = 2000 chars (~500 tokens)
	entries   []hypothesis
	seen      map[string]int // key = vuln_class|url (lower-cased) -> index in entries
	clock     func() time.Time
}

// newWorkingMemory constructs an empty working memory bound to a fresh UUID
// session identifier. maxChars <= 0 falls back to 2000 (≈500 tokens).
func newWorkingMemory(maxChars int) *workingMemory {
	if maxChars <= 0 {
		maxChars = 2000
	}
	return &workingMemory{
		sessionID: uuid.NewString(),
		maxChars:  maxChars,
		seen:      make(map[string]int),
		clock:     time.Now,
	}
}

// SessionID returns the immutable UUID assigned at construction time.
func (m *workingMemory) SessionID() string {
	if m == nil {
		return ""
	}
	return m.sessionID
}

// Len returns the number of unique hypotheses stored.
func (m *workingMemory) Len() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

// Observe scans a THINK block for HYPOTHESIS: lines and stores any it finds.
// Returns the number of newly-added (not duplicate) hypotheses so the caller
// can log a meaningful "+N hypotheses" line.
//
// The contract enforced by the parser (see hypothesisLineRE) is exactly:
//
//	HYPOTHESIS: <vuln_class> @ <url> :: <one-line reasoning>
//
// Lines that do not match are silently ignored — the parser is the only
// hypothesis extractor (no regex fallback over THINK content, per user
// direction in handoff).
func (m *workingMemory) Observe(think string) int {
	if m == nil || think == "" {
		return 0
	}
	parsed := parseHypotheses(think, m.clock())
	if len(parsed) == 0 {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	added := 0
	for _, h := range parsed {
		key := strings.ToLower(h.Class) + "|" + strings.ToLower(h.URL)
		if idx, ok := m.seen[key]; ok {
			m.entries[idx].Why = h.Why
			m.entries[idx].Updated = h.Updated
			m.entries[idx].Mentions++
			continue
		}
		m.entries = append(m.entries, h)
		m.seen[key] = len(m.entries) - 1
		added++
	}
	return added
}

// Block renders the working-memory block injected at the top of every LLM
// call. Empty when no hypotheses have been recorded.
//
// The block is capped at maxChars; entries are emitted most-recent first
// and older entries are dropped (not summarised) when the budget is hit.
func (m *workingMemory) Block() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.entries) == 0 {
		return ""
	}

	header := "[WORKING MEMORY]\nHYPOTHESES so far (most recent first; this block survives history trimming):\n"
	footer := "\n[/WORKING MEMORY]"

	budget := m.maxChars - len(header) - len(footer)
	if budget <= 0 {
		return ""
	}

	var lines []string
	used := 0
	dropped := 0
	for i := len(m.entries) - 1; i >= 0; i-- {
		h := m.entries[i]
		line := fmt.Sprintf("- %s @ %s :: %s", h.Class, h.URL, h.Why)
		// +1 for the newline separator between lines.
		if used+len(line)+1 > budget {
			dropped = i + 1 // remaining (older) entries dropped
			break
		}
		lines = append(lines, line)
		used += len(line) + 1
	}
	if dropped > 0 {
		marker := fmt.Sprintf("- (... %d older hypotheses dropped to fit budget ...)", dropped)
		if used+len(marker)+1 <= budget {
			lines = append(lines, marker)
		}
	}
	return header + strings.Join(lines, "\n") + footer
}

// All returns a defensive copy of the stored hypotheses in chronological
// (oldest-first) order. Used by tests and by future persistence layers.
func (m *workingMemory) All() []hypothesis {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]hypothesis, len(m.entries))
	copy(out, m.entries)
	return out
}

// hypothesisLineRE matches the exact HYPOTHESIS contract emitted by the
// agent in THINK blocks. The regex requires the @ and :: delimiters with
// whitespace around them so something like "HYPOTHESIS: foo@bar::baz"
// (which the LLM should not produce) is rejected.
var hypothesisLineRE = regexp.MustCompile(`(?m)^\s*HYPOTHESIS:\s+([^@\n]+?)\s+@\s+(\S+)\s+::\s+(.+?)\s*$`)

// parseHypotheses extracts every HYPOTHESIS: line from a THINK block.
// The function is the single source of truth for the contract format —
// any future change to the contract must update this regex AND the prompt
// in agentSystemPrompt at the same time.
func parseHypotheses(think string, now time.Time) []hypothesis {
	matches := hypothesisLineRE.FindAllStringSubmatch(think, -1)
	out := make([]hypothesis, 0, len(matches))
	for _, m := range matches {
		class := strings.TrimSpace(m[1])
		url := strings.TrimSpace(m[2])
		why := strings.TrimSpace(m[3])
		if class == "" || url == "" || why == "" {
			continue
		}
		out = append(out, hypothesis{
			Class:    class,
			URL:      url,
			Why:      why,
			Created:  now,
			Updated:  now,
			Mentions: 1,
		})
	}
	return out
}
