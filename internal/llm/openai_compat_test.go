package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestOpenAICompatProvider_Complete(t *testing.T) {
	// Mock OpenAI-compatible API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("missing auth header")
		}

		// Verify request format
		var req oaiRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Model != "test-model" {
			t.Errorf("model = %q, want test-model", req.Model)
		}
		if len(req.Messages) != 2 {
			t.Errorf("messages = %d, want 2", len(req.Messages))
		}

		resp := oaiResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{{Message: struct {
				Content string `json:"content"`
			}{Content: "test response"}}},
			Usage: struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
			}{PromptTokens: 10, CompletionTokens: 5},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := NewOpenAICompatProvider("test-provider", server.URL, "test-key", "test-model")

	resp, err := p.Complete(context.Background(), &Request{
		Messages: []Message{
			{Role: RoleSystem, Content: "You are helpful"},
			{Role: RoleUser, Content: "Hello"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Content != "test response" {
		t.Errorf("content = %q", resp.Content)
	}
	if resp.Provider != "test-provider" {
		t.Errorf("provider = %q", resp.Provider)
	}
	if resp.InputTokens != 10 || resp.OutputTokens != 5 {
		t.Errorf("tokens = %d/%d", resp.InputTokens, resp.OutputTokens)
	}
}

func TestOpenAICompatProvider_RateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		w.Write([]byte(`{"error":{"message":"rate limited"}}`))
	}))
	defer server.Close()

	p := NewOpenAICompatProvider("test", server.URL, "key", "model")

	_, err := p.Complete(context.Background(), &Request{
		Messages: []Message{{Role: RoleUser, Content: "test"}},
	})
	if err == nil {
		t.Error("expected rate limit error")
	}

	if p.Available() {
		t.Error("provider should be unavailable after rate limit")
	}
}

func TestOpenAICompatProvider_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := oaiResponse{
			Error: &struct {
				Message string `json:"message"`
				Type    string `json:"type"`
			}{Message: "invalid model", Type: "invalid_request_error"},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := NewOpenAICompatProvider("test", server.URL, "key", "bad-model")

	_, err := p.Complete(context.Background(), &Request{
		Messages: []Message{{Role: RoleUser, Content: "test"}},
	})
	if err == nil {
		t.Error("expected API error")
	}
}

func TestOpenAICompatProvider_JSONMode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req oaiRequest
		json.NewDecoder(r.Body).Decode(&req)

		if req.ResponseFormat == nil || req.ResponseFormat.Type != "json_object" {
			t.Error("expected json_object response format")
		}

		resp := oaiResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{{Message: struct {
				Content string `json:"content"`
			}{Content: `{"result": "ok"}`}}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := NewOpenAICompatProvider("test", server.URL, "key", "model")

	resp, err := p.Complete(context.Background(), &Request{
		Messages: []Message{{Role: RoleUser, Content: "test"}},
		JSONMode: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Content != `{"result": "ok"}` {
		t.Errorf("content = %q", resp.Content)
	}
}

// TestBackoffPersistsAcrossAvailable verifies that cooldownSec is NOT reset
// when Available() returns true. The backoff should only reset on a successful
// Complete() call.
func TestBackoffPersistsAcrossAvailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		w.Write([]byte(`{"error":{"message":"rate limited"}}`))
	}))
	defer server.Close()

	p := NewOpenAICompatProvider("test", server.URL, "key", "model")

	// First 429: cooldownSec should be 30
	p.Complete(context.Background(), &Request{
		Messages: []Message{{Role: RoleUser, Content: "test"}},
	})

	p.mu.Lock()
	cd1 := p.cooldownSec
	// Manually set retryAfter to the past so Available() returns true
	p.retryAfter = time.Now().Add(-1 * time.Second)
	p.mu.Unlock()

	if cd1 != 30 {
		t.Fatalf("after first 429: cooldownSec = %d, want 30", cd1)
	}

	// Available() should return true but NOT reset cooldownSec
	if !p.Available() {
		t.Fatal("expected Available() = true after cooldown expires")
	}

	p.mu.Lock()
	cd2 := p.cooldownSec
	p.mu.Unlock()

	if cd2 != 30 {
		t.Fatalf("after Available(): cooldownSec = %d, want 30 (should not reset)", cd2)
	}

	// Second 429: cooldownSec should double to 60
	p.Complete(context.Background(), &Request{
		Messages: []Message{{Role: RoleUser, Content: "test"}},
	})

	p.mu.Lock()
	cd3 := p.cooldownSec
	p.mu.Unlock()

	if cd3 != 60 {
		t.Fatalf("after second 429: cooldownSec = %d, want 60", cd3)
	}
}

// TestCooldownResetOnSuccess verifies that a successful Complete() resets
// cooldownSec to 0.
func TestCooldownResetOnSuccess(t *testing.T) {
	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		if n == 1 {
			// First call: 429
			w.WriteHeader(429)
			w.Write([]byte(`{"error":{"message":"rate limited"}}`))
			return
		}
		// Second call: success
		resp := oaiResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{{Message: struct {
				Content string `json:"content"`
			}{Content: "ok"}}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := NewOpenAICompatProvider("test", server.URL, "key", "model")

	// First call: 429
	p.Complete(context.Background(), &Request{
		Messages: []Message{{Role: RoleUser, Content: "test"}},
	})

	p.mu.Lock()
	if p.cooldownSec != 30 {
		t.Fatalf("after 429: cooldownSec = %d, want 30", p.cooldownSec)
	}
	p.retryAfter = time.Now().Add(-1 * time.Second) // expire cooldown
	p.mu.Unlock()

	// Second call: success → should reset cooldownSec
	_, err := p.Complete(context.Background(), &Request{
		Messages: []Message{{Role: RoleUser, Content: "test"}},
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	p.mu.Lock()
	cd := p.cooldownSec
	p.mu.Unlock()

	if cd != 0 {
		t.Fatalf("after success: cooldownSec = %d, want 0", cd)
	}
}

// TestMaxCooldownCap verifies that the backoff never exceeds maxCooldownSec.
func TestMaxCooldownCap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		w.Write([]byte(`{"error":{"message":"rate limited"}}`))
	}))
	defer server.Close()

	p := NewOpenAICompatProvider("test", server.URL, "key", "model").
		WithMaxCooldown(65)

	req := &Request{Messages: []Message{{Role: RoleUser, Content: "test"}}}

	// Simulate several consecutive 429s, manually expiring cooldown each time
	for i := 0; i < 6; i++ {
		p.Complete(context.Background(), req)
		p.mu.Lock()
		p.retryAfter = time.Now().Add(-1 * time.Second)
		p.rateLimited = false
		p.mu.Unlock()
	}

	p.mu.Lock()
	cd := p.cooldownSec
	p.mu.Unlock()

	// Backoff: 30 → 60 → 65 → 65 → 65 → 65 (capped at 65)
	if cd > 65 {
		t.Fatalf("cooldownSec = %d, want <= 65 (maxCooldownSec cap)", cd)
	}
	if cd != 65 {
		t.Fatalf("cooldownSec = %d, want 65 (should have reached the cap)", cd)
	}
}

// TestSoftTimeout verifies that a provider with softTimeout cancels slow requests.
func TestSoftTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a slow provider: sleep longer than the soft timeout
		time.Sleep(500 * time.Millisecond)
		resp := oaiResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{{Message: struct {
				Content string `json:"content"`
			}{Content: "too slow"}}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := NewOpenAICompatProvider("test", server.URL, "key", "model").
		WithSoftTimeout(100 * time.Millisecond)

	start := time.Now()
	_, err := p.Complete(context.Background(), &Request{
		Messages: []Message{{Role: RoleUser, Content: "test"}},
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}

	// Should have timed out well before 500ms
	if elapsed > 400*time.Millisecond {
		t.Fatalf("softTimeout did not work: elapsed %s, want < 400ms", elapsed)
	}
}
