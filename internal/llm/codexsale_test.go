package llm

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCodexSaleModelMultiplier(t *testing.T) {
	cases := []struct {
		model string
		want  float64
	}{
		{"gpt-5.4", 1.0},
		{"openai/gpt-5.4", 1.0},
		{"gpt-5.4-mini", 0.9},
		{"openai/gpt-5.4-mini", 0.9},
		{"gpt-5.3-codex", 0.9},
		{"codex-5.3", 0.9},
		{"gpt-5.5", 4.5},
		{"unknown-model", 1.0},
	}
	for _, tc := range cases {
		got := codexSaleModelMultiplier(tc.model)
		if got != tc.want {
			t.Errorf("codexSaleModelMultiplier(%q) = %v, want %v", tc.model, got, tc.want)
		}
	}
}

func TestCodexSalePricePer1MUSD(t *testing.T) {
	// 5.45 RUB / 1M × 0.9 (gpt-5.4-mini) / 85 RUB-per-USD ≈ $0.0577 per 1M.
	p := NewCodexSaleProvider("test-key", "gpt-5.4-mini", 5.45, 85.0, 0)
	got := p.PricePer1MUSD()
	want := 5.45 * 0.9 / 85.0
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("PricePer1MUSD = %v, want %v", got, want)
	}

	// gpt-5.5 is x4.5 — most expensive Codex.Sale model.
	p2 := NewCodexSaleProvider("test-key", "gpt-5.5", 5.45, 85.0, 0)
	got2 := p2.PricePer1MUSD()
	want2 := 5.45 * 4.5 / 85.0
	if math.Abs(got2-want2) > 1e-9 {
		t.Errorf("PricePer1MUSD (gpt-5.5) = %v, want %v", got2, want2)
	}
}

func TestCodexSaleStripsJSONMode(t *testing.T) {
	// Codex.Sale's edge rejects response_format=json_object for GPT-5.x
	// reasoning models. CodexSaleProvider must strip JSONMode before
	// forwarding, and must NOT mutate the caller's Request (round-robin
	// hands the same Request to the next provider on fallback).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// If response_format is present, the edge would reject. Verify the
		// provider does not forward it.
		var got map[string]any
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("unmarshal forwarded body: %v", err)
		}
		if _, ok := got["response_format"]; ok {
			t.Errorf("CodexSale forwarded response_format despite JSONMode strip; body=%s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"ok\":true}"}}],"usage":{"prompt_tokens":5,"completion_tokens":3}}`))
	}))
	defer server.Close()

	p := NewCodexSaleProvider("test-key", "gpt-5.4-mini", 5.45, 85, 0)
	p.inner.baseURL = server.URL
	req := &Request{
		Messages: []Message{{Role: RoleUser, Content: "give json"}},
		JSONMode: true, // caller wants JSON
	}
	if _, err := p.Complete(context.Background(), req); err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
	// Caller's request must remain unchanged so the next provider in the
	// round-robin (e.g. CloseRouter) still sees JSONMode=true.
	if !req.JSONMode {
		t.Errorf("CodexSaleProvider mutated caller's JSONMode")
	}
}

func TestCodexSaleDefaults(t *testing.T) {
	// Passing 0 for base/rate should fall back to the documented defaults.
	p := NewCodexSaleProvider("key", "gpt-5.4", 0, 0, 0)
	if p.rubPer1MBase != 5.45 {
		t.Errorf("default base = %v, want 5.45", p.rubPer1MBase)
	}
	if p.rubPerUSD != 85.0 {
		t.Errorf("default rate = %v, want 85.0", p.rubPerUSD)
	}
}
