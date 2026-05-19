package agent

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/llm"
)

// newTestAgentForBuild returns an Agent with an empty mem and a 2-message
// history (system + initial user) so buildLLMMessages can be exercised
// without spinning up an LLM client.
func newTestAgentForBuild(t *testing.T) *Agent {
	t.Helper()
	a := &Agent{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		mem: newWorkingMemory(0),
	}
	a.history = []llm.Message{
		{Role: llm.RoleSystem, Content: "system"},
		{Role: llm.RoleUser, Content: "initial"},
	}
	return a
}

func fixedTime() time.Time {
	return time.Date(2025, 11, 18, 20, 0, 0, 0, time.UTC)
}

func TestMemory_SessionIDIsUUID(t *testing.T) {
	m := newWorkingMemory(0)
	id := m.SessionID()
	if len(id) != 36 || strings.Count(id, "-") != 4 {
		t.Errorf("session id should be a UUID; got %q", id)
	}
}

func TestMemory_SessionIDStable(t *testing.T) {
	m := newWorkingMemory(0)
	if m.SessionID() != m.SessionID() {
		t.Errorf("session id must be stable across calls")
	}
}

func TestMemory_DistinctSessionsHaveDistinctIDs(t *testing.T) {
	a := newWorkingMemory(0).SessionID()
	b := newWorkingMemory(0).SessionID()
	if a == b {
		t.Errorf("UUIDs collided: %q", a)
	}
}

func TestMemory_Observe_ParsesSingleHypothesis(t *testing.T) {
	m := newWorkingMemory(0)
	m.clock = fixedTime

	think := `Looking at the request, the id parameter seems to be unauthenticated.
HYPOTHESIS: idor @ https://t.example.com/api/v1/users/42 :: numeric id, no auth header sent, response body changed when id varied
Let me probe a neighbouring id.`

	added := m.Observe(think)
	if added != 1 {
		t.Fatalf("expected 1 hypothesis added, got %d", added)
	}
	all := m.All()
	if len(all) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(all))
	}
	h := all[0]
	if h.Class != "idor" {
		t.Errorf("class: got %q", h.Class)
	}
	if h.URL != "https://t.example.com/api/v1/users/42" {
		t.Errorf("url: got %q", h.URL)
	}
	if !strings.Contains(h.Why, "numeric id") {
		t.Errorf("why: got %q", h.Why)
	}
	if h.Mentions != 1 {
		t.Errorf("mentions: got %d, want 1", h.Mentions)
	}
}

func TestMemory_Observe_ParsesMultipleHypothesesPerThink(t *testing.T) {
	m := newWorkingMemory(0)
	think := `HYPOTHESIS: reflected_xss @ https://x.io/search?q= :: <svg/onload=alert(1)> reflected unencoded
HYPOTHESIS: open_redirect @ https://x.io/go?u= :: Location header echoes the u= value verbatim`
	added := m.Observe(think)
	if added != 2 {
		t.Fatalf("expected 2 hypotheses added, got %d", added)
	}
	if got := m.Len(); got != 2 {
		t.Errorf("Len: got %d, want 2", got)
	}
}

func TestMemory_Observe_DedupBy_ClassAndURL_CaseInsensitive(t *testing.T) {
	m := newWorkingMemory(0)
	m.Observe("HYPOTHESIS: idor @ https://t.example.com/api/users/42 :: first guess")
	m.Observe("HYPOTHESIS: IDOR @ HTTPS://T.example.com/api/users/42 :: confirmed via id swap")

	if got := m.Len(); got != 1 {
		t.Fatalf("expected dedup to keep 1 entry, got %d", got)
	}
	all := m.All()
	if !strings.Contains(all[0].Why, "confirmed") {
		t.Errorf("why should be updated to latest: got %q", all[0].Why)
	}
	if all[0].Mentions != 2 {
		t.Errorf("mentions: got %d, want 2", all[0].Mentions)
	}
}

func TestMemory_Observe_IgnoresMalformedLines(t *testing.T) {
	m := newWorkingMemory(0)
	cases := []string{
		"HYPOTHESIS: nodelimiter",
		"HYPOTHESIS: foo@bar::baz",           // missing whitespace around delimiters
		"HYPOTHESIS:  @ url :: why",          // empty class
		"HYPOTHESIS: class @  :: why",        // empty url
		"HYPOTHESIS: class @ url :: ",        // empty why
		"hypothesis: idor @ https://x/ :: lowercase keyword",
		"PROBABLY-A-HYPOTHESIS: idor @ url :: prefix",
	}
	for _, c := range cases {
		if added := m.Observe(c); added != 0 {
			t.Errorf("expected 0 from %q, got %d (stored=%+v)", c, added, m.All())
		}
	}
}

func TestMemory_Observe_NoHYPOTHESISInThinkIsNoOp(t *testing.T) {
	m := newWorkingMemory(0)
	added := m.Observe("Just thinking out loud, no contract line emitted yet.")
	if added != 0 {
		t.Errorf("expected 0 added, got %d", added)
	}
}

func TestMemory_Block_EmptyWhenNoHypotheses(t *testing.T) {
	m := newWorkingMemory(0)
	if got := m.Block(); got != "" {
		t.Errorf("expected empty block; got %q", got)
	}
}

func TestMemory_Block_ContainsAllHypotheses_MostRecentFirst(t *testing.T) {
	m := newWorkingMemory(0)
	m.Observe("HYPOTHESIS: a @ url1 :: one")
	m.Observe("HYPOTHESIS: b @ url2 :: two")
	m.Observe("HYPOTHESIS: c @ url3 :: three")

	block := m.Block()
	if !strings.HasPrefix(block, "[WORKING MEMORY]") {
		t.Errorf("missing leading marker: %q", block)
	}
	if !strings.HasSuffix(block, "[/WORKING MEMORY]") {
		t.Errorf("missing trailing marker: %q", block)
	}
	idxC := strings.Index(block, "c @ url3")
	idxB := strings.Index(block, "b @ url2")
	idxA := strings.Index(block, "a @ url1")
	if !(idxC >= 0 && idxB > idxC && idxA > idxB) {
		t.Errorf("expected most-recent-first ordering (c, b, a). block:\n%s", block)
	}
}

func TestMemory_Block_RespectsCharBudgetAndAddsDropMarker(t *testing.T) {
	m := newWorkingMemory(300) // very tight; only a couple entries fit
	for i := 0; i < 10; i++ {
		m.Observe("HYPOTHESIS: classX @ https://example.com/very/long/path/" + repeat(string(rune('A'+i)), 20) + " :: reason number " + repeat("z", 20))
	}
	block := m.Block()
	if !strings.Contains(block, "[WORKING MEMORY]") {
		t.Fatalf("malformed block: %q", block)
	}
	if len(block) > 320 { // 300 budget + small markup overhead
		t.Errorf("block exceeded budget; len=%d", len(block))
	}
	if !strings.Contains(block, "older hypotheses dropped") {
		t.Errorf("expected drop marker; block:\n%s", block)
	}
}

func TestMemory_Block_RemainsSafeWithVeryTinyBudget(t *testing.T) {
	m := newWorkingMemory(50) // smaller than the header
	m.Observe("HYPOTHESIS: idor @ https://x/ :: w")
	if got := m.Block(); got != "" {
		t.Errorf("expected empty when budget cannot fit header; got %q", got)
	}
}

func TestMemory_NilSafe(t *testing.T) {
	var m *workingMemory
	if m.Len() != 0 {
		t.Errorf("nil Len should be 0")
	}
	if m.SessionID() != "" {
		t.Errorf("nil SessionID should be empty")
	}
	if m.Block() != "" {
		t.Errorf("nil Block should be empty")
	}
	if got := m.Observe("HYPOTHESIS: idor @ https://x/ :: w"); got != 0 {
		t.Errorf("nil Observe should be 0; got %d", got)
	}
}

func TestBuildLLMMessages_NoMemoryReturnsHistoryAsIs(t *testing.T) {
	a := newTestAgentForBuild(t)
	got := a.buildLLMMessages()
	if len(got) != 2 {
		t.Errorf("expected 2 messages (system + initial), got %d", len(got))
	}
}

func TestBuildLLMMessages_InjectsBlockAfterSystem(t *testing.T) {
	a := newTestAgentForBuild(t)
	a.mem.Observe("HYPOTHESIS: idor @ https://x/ :: why")

	msgs := a.buildLLMMessages()
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages (system + memory + initial), got %d", len(msgs))
	}
	if !strings.Contains(msgs[1].Content, "[WORKING MEMORY]") {
		t.Errorf("memory block not in slot 1: %q", msgs[1].Content)
	}
}

func TestBuildLLMMessages_DoesNotMutateHistory(t *testing.T) {
	a := newTestAgentForBuild(t)
	a.mem.Observe("HYPOTHESIS: idor @ https://x/ :: why")
	before := len(a.history)

	_ = a.buildLLMMessages()

	if len(a.history) != before {
		t.Errorf("history mutated: was %d, now %d", before, len(a.history))
	}
}

// repeat is a tiny strings.Repeat helper to keep test imports flat.
func repeat(s string, n int) string {
	return strings.Repeat(s, n)
}
