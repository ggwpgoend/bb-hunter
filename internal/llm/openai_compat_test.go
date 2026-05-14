package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
