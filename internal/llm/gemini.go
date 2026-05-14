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

// GeminiProvider implements the Provider interface for Google Gemini API.
type GeminiProvider struct {
	apiKey     string
	model      string
	baseURL    string
	httpClient *http.Client

	mu          sync.Mutex
	rateLimited bool
	retryAfter  time.Time
}

// NewGeminiProvider creates a Gemini provider.
// Model examples: "gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.5-flash-lite"
func NewGeminiProvider(apiKey, model string) *GeminiProvider {
	return &GeminiProvider{
		apiKey:     apiKey,
		model:      model,
		baseURL:    "https://generativelanguage.googleapis.com/v1beta",
		httpClient: &http.Client{Timeout: 120 * time.Second},
	}
}

func (g *GeminiProvider) Name() string  { return "gemini" }
func (g *GeminiProvider) Model() string { return g.model }

func (g *GeminiProvider) Available() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.rateLimited && time.Now().Before(g.retryAfter) {
		return false
	}
	g.rateLimited = false
	return true
}

// geminiRequest is the Gemini API request format.
type geminiRequest struct {
	Contents         []geminiContent        `json:"contents"`
	SystemInstruction *geminiContent        `json:"systemInstruction,omitempty"`
	GenerationConfig  *geminiGenerationConfig `json:"generationConfig,omitempty"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiGenerationConfig struct {
	MaxOutputTokens int     `json:"maxOutputTokens,omitempty"`
	Temperature     float64 `json:"temperature,omitempty"`
	ResponseMimeType string `json:"responseMimeType,omitempty"`
}

// geminiResponse is the Gemini API response format.
type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	UsageMetadata struct {
		PromptTokenCount     int `json:"promptTokenCount"`
		CandidatesTokenCount int `json:"candidatesTokenCount"`
	} `json:"usageMetadata"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (g *GeminiProvider) Complete(ctx context.Context, req *Request) (*Response, error) {
	start := time.Now()

	// Build Gemini request
	gemReq := geminiRequest{}

	// Extract system message if present
	var contents []geminiContent
	for _, msg := range req.Messages {
		switch msg.Role {
		case RoleSystem:
			gemReq.SystemInstruction = &geminiContent{
				Parts: []geminiPart{{Text: msg.Content}},
			}
		case RoleUser:
			contents = append(contents, geminiContent{
				Role:  "user",
				Parts: []geminiPart{{Text: msg.Content}},
			})
		case RoleAssistant:
			contents = append(contents, geminiContent{
				Role:  "model",
				Parts: []geminiPart{{Text: msg.Content}},
			})
		}
	}
	gemReq.Contents = contents

	// Generation config
	cfg := &geminiGenerationConfig{}
	if req.MaxTokens > 0 {
		cfg.MaxOutputTokens = req.MaxTokens
	}
	if req.Temperature > 0 {
		cfg.Temperature = req.Temperature
	}
	if req.JSONMode {
		cfg.ResponseMimeType = "application/json"
	}
	gemReq.GenerationConfig = cfg

	body, err := json.Marshal(gemReq)
	if err != nil {
		return nil, fmt.Errorf("gemini: marshal failed: %w", err)
	}

	url := fmt.Sprintf("%s/models/%s:generateContent?key=%s", g.baseURL, g.model, g.apiKey)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("gemini: request creation failed: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := g.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("gemini: request failed: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("gemini: read response failed: %w", err)
	}

	if httpResp.StatusCode == 429 {
		g.mu.Lock()
		g.rateLimited = true
		g.retryAfter = time.Now().Add(60 * time.Second)
		g.mu.Unlock()
		return nil, fmt.Errorf("%w: %s", ErrRateLimited, string(respBody))
	}

	if httpResp.StatusCode != 200 {
		return nil, fmt.Errorf("gemini: HTTP %d: %s", httpResp.StatusCode, string(respBody))
	}

	var gemResp geminiResponse
	if err := json.Unmarshal(respBody, &gemResp); err != nil {
		return nil, fmt.Errorf("gemini: unmarshal failed: %w", err)
	}

	if gemResp.Error != nil {
		return nil, fmt.Errorf("gemini: API error %d: %s", gemResp.Error.Code, gemResp.Error.Message)
	}

	if len(gemResp.Candidates) == 0 || len(gemResp.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("gemini: empty response")
	}

	content := gemResp.Candidates[0].Content.Parts[0].Text

	return &Response{
		Content:      content,
		Provider:     g.Name(),
		Model:        g.model,
		InputTokens:  gemResp.UsageMetadata.PromptTokenCount,
		OutputTokens: gemResp.UsageMetadata.CandidatesTokenCount,
		Latency:      time.Since(start),
	}, nil
}
