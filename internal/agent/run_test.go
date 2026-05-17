package agent

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/llm"
)

// scriptedProvider is a test-only llm.Provider that returns a sequence of
// canned responses based on the call number. Once the script is exhausted it
// keeps returning the last entry so the loop doesn't crash if it iterates
// further than expected.
type scriptedProvider struct {
	mu        sync.Mutex
	calls     int32
	responses []string
	onCall    func(call int)
}

func (s *scriptedProvider) Name() string    { return "scripted" }
func (s *scriptedProvider) Model() string   { return "test" }
func (s *scriptedProvider) Available() bool { return true }
func (s *scriptedProvider) Complete(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	n := int(atomic.AddInt32(&s.calls, 1))
	if s.onCall != nil {
		s.onCall(n)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := n - 1
	if idx >= len(s.responses) {
		idx = len(s.responses) - 1
	}
	return &llm.Response{
		Content:  s.responses[idx],
		Provider: "scripted",
		Model:    "test",
	}, nil
}

func (s *scriptedProvider) Calls() int { return int(atomic.LoadInt32(&s.calls)) }

const fastLoopAction = "THINK: probing\nACTION: no_such_tool"

func TestAgent_New_MaxStepsNormalization(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want int
	}{
		{"zero stays unlimited", 0, 0},
		{"negative clamps to zero", -5, 0},
		{"positive preserved", 7, 7},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client, _ := llm.NewClient(&scriptedProvider{responses: []string{"THINK: x\nACTION: done"}})
			a := New(Config{MaxSteps: c.in, LLMClient: client, LLMDelayMs: 1})
			if a.cfg.MaxSteps != c.want {
				t.Errorf("MaxSteps = %d, want %d", a.cfg.MaxSteps, c.want)
			}
		})
	}
}

func TestAgent_StopRequested_FlipsAtomicFlag(t *testing.T) {
	client, _ := llm.NewClient(&scriptedProvider{responses: []string{"THINK: x\nACTION: done"}})
	a := New(Config{LLMClient: client, LLMDelayMs: 1})
	if a.StopRequested() {
		t.Fatal("StopRequested should be false initially")
	}
	a.RequestStop()
	if !a.StopRequested() {
		t.Fatal("StopRequested should be true after RequestStop")
	}
	// Idempotent
	a.RequestStop()
	if !a.StopRequested() {
		t.Fatal("RequestStop should be idempotent")
	}
}

// TestAgent_Run_RespectsMaxSteps verifies the legacy fixed-budget path still
// honours MaxSteps when MaxSteps > 0.
func TestAgent_Run_RespectsMaxSteps(t *testing.T) {
	// Use an unknown tool so the loop stays fully in-process; this keeps the
	// test focused on MaxSteps instead of the speed of external binaries like
	// agent-browser.
	sp := &scriptedProvider{responses: []string{fastLoopAction}}
	client, _ := llm.NewClient(sp)

	a := New(Config{
		Target:     "example.com",
		LLMClient:  client,
		MaxSteps:   3,
		LLMDelayMs: 1,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.Run(ctx); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if got := sp.Calls(); got != 3 {
		t.Errorf("expected 3 LLM calls (MaxSteps=3), got %d", got)
	}
}

// TestAgent_Run_UnlimitedAndStopSignal verifies that MaxSteps=0 keeps the
// loop running past the legacy 30-step cap and that RequestStop triggers a
// graceful shutdown within StopGraceSteps.
func TestAgent_Run_UnlimitedAndStopSignal(t *testing.T) {
	const stopAt = 35 // well past the old default of 30

	sp := &scriptedProvider{
		responses: []string{fastLoopAction},
	}

	// Capture the agent so onCall can request stop on it.
	var aRef atomic.Pointer[Agent]
	sp.onCall = func(call int) {
		if call == stopAt {
			if a := aRef.Load(); a != nil {
				a.RequestStop()
			}
		}
	}

	client, _ := llm.NewClient(sp)
	a := New(Config{
		Target:     "example.com",
		LLMClient:  client,
		MaxSteps:   0, // unlimited
		LLMDelayMs: 1,
	})
	aRef.Store(a)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.Run(ctx); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// We must have run strictly more than the legacy 30-step cap.
	if got := sp.Calls(); got <= 30 {
		t.Errorf("expected >30 LLM calls in unlimited mode, got %d", got)
	}
	// And we must have stopped within StopGraceSteps after the request was
	// observed. RequestStop fires during LLM call `stopAt`, so the flag is
	// first observed at the *top* of step stopAt+1 — that's where the SYSTEM
	// NOTE gets injected. loopActive then allows up to StopGraceSteps more
	// iterations beyond the injection step.
	maxAllowed := stopAt + StopGraceSteps
	if got := sp.Calls(); got > maxAllowed {
		t.Errorf("agent kept running past grace window: got %d calls, max allowed %d", got, maxAllowed)
	}
}

// TestAgent_Run_StopSignalInjectsSystemNote checks that the synthetic SYSTEM
// NOTE is appended to history exactly once after RequestStop is observed.
func TestAgent_Run_StopSignalInjectsSystemNote(t *testing.T) {
	const stopAt = 2

	sp := &scriptedProvider{
		responses: []string{fastLoopAction},
	}

	var aRef atomic.Pointer[Agent]
	sp.onCall = func(call int) {
		if call == stopAt {
			if a := aRef.Load(); a != nil {
				a.RequestStop()
			}
		}
	}

	client, _ := llm.NewClient(sp)
	a := New(Config{
		Target:     "example.com",
		LLMClient:  client,
		MaxSteps:   0,
		LLMDelayMs: 1,
	})
	aRef.Store(a)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.Run(ctx); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// Count SYSTEM NOTE injections in history.
	count := 0
	for _, m := range a.history {
		if m.Role == llm.RoleUser && strings.Contains(m.Content, "SYSTEM NOTE: the user requested a graceful stop") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 SYSTEM NOTE injection, got %d", count)
	}
}
