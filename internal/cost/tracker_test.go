package cost

import (
	"log/slog"
	"testing"
	"time"
)

func newTestTracker() *Tracker {
	return NewTracker([]ProviderQuota{
		{Name: "gemini", DailyRequests: 100, DailyTokens: 1000000},
		{Name: "cerebras", DailyRequests: 50, DailyTokens: 500000},
	}, slog.Default())
}

func TestTracker_Record(t *testing.T) {
	tr := newTestTracker()

	err := tr.Record("gemini", 100, 50)
	if err != nil {
		t.Fatal(err)
	}

	usage, ok := tr.GetUsage("gemini")
	if !ok {
		t.Fatal("gemini usage not found")
	}
	if usage.RequestsToday != 1 {
		t.Errorf("requests = %d, want 1", usage.RequestsToday)
	}
	if usage.TokensToday != 150 {
		t.Errorf("tokens = %d, want 150", usage.TokensToday)
	}
}

func TestTracker_UnknownProvider(t *testing.T) {
	tr := newTestTracker()
	err := tr.Record("unknown", 100, 50)
	if err == nil {
		t.Error("expected error for unknown provider")
	}
}

func TestTracker_IsAvailable(t *testing.T) {
	tr := newTestTracker()

	if !tr.IsAvailable("gemini") {
		t.Error("gemini should be available initially")
	}

	// Exhaust daily requests
	for i := 0; i < 100; i++ {
		tr.Record("gemini", 10, 5)
	}

	if tr.IsAvailable("gemini") {
		t.Error("gemini should be unavailable after exhausting requests")
	}

	// Cerebras should still be available
	if !tr.IsAvailable("cerebras") {
		t.Error("cerebras should still be available")
	}
}

func TestTracker_KillSwitch(t *testing.T) {
	tr := NewTracker([]ProviderQuota{
		{Name: "p1", DailyTokens: 1000},
		{Name: "p2", DailyTokens: 1000},
	}, slog.Default())
	tr.KillThreshold = 0.9

	tr.OnKillSwitch = func() {}

	// Use 90% of total quota (900 + 900 = 1800 of 2000)
	tr.Record("p1", 450, 450) // 900 tokens
	tr.Record("p2", 450, 450) // 900 tokens

	if !tr.IsKilled() {
		t.Error("kill switch should be active at 90% usage")
	}

	// All providers should be unavailable
	if tr.IsAvailable("p1") || tr.IsAvailable("p2") {
		t.Error("all providers should be unavailable when killed")
	}

	err := tr.Record("p1", 10, 10)
	if err == nil {
		t.Error("recording should fail when kill switch is active")
	}
}

func TestTracker_KillSwitchCallback(t *testing.T) {
	tr := NewTracker([]ProviderQuota{
		{Name: "p1", DailyTokens: 100},
	}, slog.Default())
	tr.KillThreshold = 0.5

	called := make(chan bool, 1)
	tr.OnKillSwitch = func() { called <- true }

	tr.Record("p1", 25, 25) // 50% = threshold

	// Callback runs in goroutine, wait briefly
	select {
	case <-called:
		// ok
	case <-time.After(100 * time.Millisecond):
		t.Error("kill switch callback should have been called")
	}
}
