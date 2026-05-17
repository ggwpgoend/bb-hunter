package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockCloseRouterServer returns an httptest server that always returns the
// given token usage and a trivial response.
func mockCloseRouterServer(t *testing.T, promptToks, completionToks int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		resp := oaiResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{{Message: struct {
				Content string `json:"content"`
			}{Content: "ok"}}},
			Usage: struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
			}{PromptTokens: promptToks, CompletionTokens: completionToks},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

// newCloseRouterWithBaseURL is a test helper that constructs a CloseRouter
// provider pointing at an arbitrary base URL (overrides the production one).
func newCloseRouterWithBaseURL(baseURL, model string, dailyLimitUSD float64) *CloseRouterProvider {
	p := NewCloseRouterProvider("test-key", model, dailyLimitUSD)
	p.inner = NewOpenAICompatProvider("closerouter", baseURL, "test-key", model)
	return p
}

func TestCloseRouter_AccrualUnderBudget(t *testing.T) {
	srv := mockCloseRouterServer(t, 1_000_000, 0) // 1M input tokens per call
	defer srv.Close()

	p := newCloseRouterWithBaseURL(srv.URL, "anthropic/claude-opus-4.7", 1.0)

	// At $0.20/M, 1M input tokens = $0.20 per call. We can afford ~5 calls.
	for i := 0; i < 4; i++ {
		if _, err := p.Complete(context.Background(), &Request{Messages: []Message{{Role: RoleUser, Content: "hi"}}}); err != nil {
			t.Fatalf("call %d failed: %v", i, err)
		}
	}
	if !p.Available() {
		t.Errorf("provider should still be available after 4 calls (~$0.80 of $1.00 budget)")
	}
	if got := p.SpentUSD(); got < 0.79 || got > 0.81 {
		t.Errorf("spent=%v, want ~0.80", got)
	}
}

func TestCloseRouter_BudgetExhaustion(t *testing.T) {
	srv := mockCloseRouterServer(t, 1_000_000, 0)
	defer srv.Close()

	p := newCloseRouterWithBaseURL(srv.URL, "anthropic/claude-opus-4.7", 0.50)
	// One call accrues $0.20 — should still be available.
	if _, err := p.Complete(context.Background(), &Request{Messages: []Message{{Role: RoleUser, Content: "x"}}}); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if !p.Available() {
		t.Errorf("after $0.20 spent of $0.50 limit, should still be available")
	}

	// Two more calls push past $0.50.
	for i := 0; i < 2; i++ {
		_, _ = p.Complete(context.Background(), &Request{Messages: []Message{{Role: RoleUser, Content: "x"}}})
	}
	if p.Available() {
		t.Errorf("after $0.60 spent of $0.50 limit, should be unavailable")
	}

	// Subsequent Complete calls must fail fast without hitting the network.
	_, err := p.Complete(context.Background(), &Request{Messages: []Message{{Role: RoleUser, Content: "x"}}})
	if err == nil {
		t.Error("expected error when over budget")
	}
	if !strings.Contains(err.Error(), "daily budget") {
		t.Errorf("error should mention daily budget, got: %v", err)
	}
}

func TestCloseRouter_BudgetDisabled(t *testing.T) {
	srv := mockCloseRouterServer(t, 100_000_000, 0) // 100M tokens => $20 per call
	defer srv.Close()

	p := newCloseRouterWithBaseURL(srv.URL, "anthropic/claude-opus-4.7", 0)

	if _, err := p.Complete(context.Background(), &Request{Messages: []Message{{Role: RoleUser, Content: "x"}}}); err != nil {
		t.Fatalf("call: %v", err)
	}
	if !p.Available() {
		t.Errorf("with dailyLimitUSD=0, provider must stay available regardless of spend (got spent=%v)", p.SpentUSD())
	}
}

func TestCloseRouter_PricingHeuristic(t *testing.T) {
	cases := []struct {
		model         string
		wantIn, wantOut float64
	}{
		{"anthropic/claude-opus-4.7", 0.20, 0.20},
		{"anthropic/claude-haiku-4.5", 0.05, 0.05},
		{"anthropic/claude-sonnet-4.5", 0.15, 0.15},
		{"openai/gpt-5-mini", 0.05, 0.05},
		{"openai/gpt-5.5", 0.30, 0.30},
		{"google/gemini-3-flash", 0.05, 0.05},
		{"unknown/model-x", 0.20, 0.20}, // default
	}
	for _, c := range cases {
		p := NewCloseRouterProvider("k", c.model, 1.0)
		if p.pricePer1MIn != c.wantIn || p.pricePer1MOut != c.wantOut {
			t.Errorf("model %q: pricing=%v/%v, want %v/%v",
				c.model, p.pricePer1MIn, p.pricePer1MOut, c.wantIn, c.wantOut)
		}
	}
}

func TestCloseRouter_Name(t *testing.T) {
	p := NewCloseRouterProvider("k", "anthropic/claude-opus-4.7", 1.0)
	if p.Name() != "closerouter" {
		t.Errorf("Name() = %q, want closerouter", p.Name())
	}
	if p.Model() != "anthropic/claude-opus-4.7" {
		t.Errorf("Model() = %q", p.Model())
	}
}
