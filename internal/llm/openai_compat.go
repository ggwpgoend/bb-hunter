package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// OpenAICompatProvider implements the Provider interface for any OpenAI-compatible API.
// Works with: Cerebras, Groq, SambaNova, Together, OpenRouter, NVIDIA NIM, etc.
type OpenAICompatProvider struct {
	baseURL    string
	apiKey     string
	model      string
	name       string
	httpClient *http.Client

	mu          sync.Mutex
	rateLimited bool
	retryAfter  time.Time
}

// NewOpenAICompatProvider creates a provider for any OpenAI-compatible endpoint.
func NewOpenAICompatProvider(name, baseURL, apiKey, model string) *OpenAICompatProvider {
	return &OpenAICompatProvider{
		name:       name,
		baseURL:    baseURL,
		apiKey:     apiKey,
		model:      model,
		httpClient: &http.Client{Timeout: 120 * time.Second},
	}
}

func (o *OpenAICompatProvider) Name() string  { return o.name }
func (o *OpenAICompatProvider) Model() string { return o.model }

func (o *OpenAICompatProvider) Available() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.rateLimited && time.Now().Before(o.retryAfter) {
		return false
	}
	o.rateLimited = false
	return true
}

// OpenAI API request/response types.

type oaiRequest struct {
	Model       string       `json:"model"`
	Messages    []oaiMessage `json:"messages"`
	MaxTokens   int          `json:"max_tokens,omitempty"`
	Temperature float64      `json:"temperature,omitempty"`
	ResponseFormat *oaiResponseFormat `json:"response_format,omitempty"`
}

type oaiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type oaiResponseFormat struct {
	Type string `json:"type"` // "json_object" or "text"
}

type oaiResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

func (o *OpenAICompatProvider) Complete(ctx context.Context, req *Request) (*Response, error) {
	start := time.Now()

	// Convert to OpenAI format
	oaiReq := oaiRequest{
		Model: o.model,
	}

	for _, msg := range req.Messages {
		oaiReq.Messages = append(oaiReq.Messages, oaiMessage{
			Role:    string(msg.Role),
			Content: msg.Content,
		})
	}

	if req.MaxTokens > 0 {
		oaiReq.MaxTokens = req.MaxTokens
	}
	if req.Temperature > 0 {
		oaiReq.Temperature = req.Temperature
	}
	if req.JSONMode {
		oaiReq.ResponseFormat = &oaiResponseFormat{Type: "json_object"}
	}

	body, err := json.Marshal(oaiReq)
	if err != nil {
		return nil, fmt.Errorf("%s: marshal failed: %w", o.name, err)
	}

	url := o.baseURL + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%s: request creation failed: %w", o.name, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+o.apiKey)

	httpResp, err := o.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%s: request failed: %w", o.name, err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: read response failed: %w", o.name, err)
	}

	if httpResp.StatusCode == 429 {
		o.mu.Lock()
		o.rateLimited = true
		o.retryAfter = time.Now().Add(60 * time.Second)
		o.mu.Unlock()
		return nil, fmt.Errorf("%w: %s: %s", ErrRateLimited, o.name, string(respBody))
	}

	if httpResp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: HTTP %d: %s", o.name, httpResp.StatusCode, string(respBody))
	}

	var oaiResp oaiResponse
	if err := json.Unmarshal(respBody, &oaiResp); err != nil {
		return nil, fmt.Errorf("%s: unmarshal failed: %w", o.name, err)
	}

	if oaiResp.Error != nil {
		return nil, fmt.Errorf("%s: API error: %s", o.name, oaiResp.Error.Message)
	}

	if len(oaiResp.Choices) == 0 {
		return nil, fmt.Errorf("%s: empty response", o.name)
	}

	return &Response{
		Content:      oaiResp.Choices[0].Message.Content,
		Provider:     o.name,
		Model:        o.model,
		InputTokens:  oaiResp.Usage.PromptTokens,
		OutputTokens: oaiResp.Usage.CompletionTokens,
		Latency:      time.Since(start),
	}, nil
}
