// Package llm provides a multi-provider LLM client abstraction.
// All providers use their free tiers; the client handles failover,
// rate limiting, and cost tracking.
package llm

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrNoProviders   = errors.New("llm: no providers configured")
	ErrAllFailed     = errors.New("llm: all providers failed")
	ErrRateLimited   = errors.New("llm: rate limited")
	ErrContextLength = errors.New("llm: context length exceeded")
	ErrKillSwitch    = errors.New("llm: kill switch activated")
)

// Role is the message role in a conversation.
type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// Message is a single message in a conversation.
type Message struct {
	Role    Role   `json:"role"`
	Content string `json:"content"`
}

// Request is the input to a completion call.
type Request struct {
	Messages    []Message `json:"messages"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	Temperature float64   `json:"temperature,omitempty"`
	JSONMode    bool      `json:"json_mode,omitempty"` // request structured JSON output

	// Sentinel UUID embedded in system prompt for prompt injection detection
	SentinelUUID string `json:"-"`

	// DisableThinking suppresses chain-of-thought / "thinking" tokens for
	// providers that emit them (e.g. Gemini 2.5+). Without this flag, a small
	// MaxTokens budget can be entirely consumed by thinking tokens, leaving
	// no room for the visible answer. Used by health checks where MaxTokens
	// is intentionally tiny. Providers that don't support thinking ignore it.
	DisableThinking bool `json:"-"`
}

// Response is the output from a completion call.
type Response struct {
	Content      string `json:"content"`
	Provider     string `json:"provider"`
	Model        string `json:"model"`
	InputTokens  int    `json:"input_tokens"`
	OutputTokens int    `json:"output_tokens"`
	Latency      time.Duration `json:"latency"`

	// Whether the sentinel UUID was found in the output (prompt injection indicator)
	SentinelLeaked bool `json:"sentinel_leaked,omitempty"`
}

// Provider is the interface each LLM backend implements.
type Provider interface {
	// Name returns the provider identifier (e.g., "gemini", "cerebras").
	Name() string

	// Model returns the model name (e.g., "gemini-2.5-flash").
	Model() string

	// Complete sends a completion request and returns the response.
	Complete(ctx context.Context, req *Request) (*Response, error)

	// Available returns true if the provider is currently available
	// (not rate-limited, not over quota).
	Available() bool
}

// Client manages multiple LLM providers with round-robin failover.
type Client struct {
	providers  []Provider
	killSwitch bool
	nextIdx    int // round-robin index for provider rotation
	mu         sync.Mutex
}

// NewClient creates a new multi-provider LLM client with round-robin rotation.
func NewClient(providers ...Provider) (*Client, error) {
	if len(providers) == 0 {
		return nil, ErrNoProviders
	}
	return &Client{providers: providers}, nil
}

// Complete uses round-robin to distribute calls across providers.
// On failure, tries the remaining providers before giving up.
func (c *Client) Complete(ctx context.Context, req *Request) (*Response, error) {
	if c.killSwitch {
		return nil, ErrKillSwitch
	}

	c.mu.Lock()
	startIdx := c.nextIdx
	c.nextIdx = (c.nextIdx + 1) % len(c.providers)
	c.mu.Unlock()

	var lastErr error
	n := len(c.providers)
	for i := 0; i < n; i++ {
		idx := (startIdx + i) % n
		p := c.providers[idx]

		if !p.Available() {
			continue
		}

		resp, err := p.Complete(ctx, req)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", p.Name(), err)
			continue
		}

		if req.SentinelUUID != "" {
			resp.SentinelLeaked = containsSentinel(resp.Content, req.SentinelUUID)
		}

		return resp, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("%w: last error: %v", ErrAllFailed, lastErr)
	}
	return nil, ErrAllFailed
}

// HealthResult contains the result of a provider health check.
type HealthResult struct {
	Provider  string        `json:"provider"`
	Model     string        `json:"model"`
	OK        bool          `json:"ok"`
	Latency   time.Duration `json:"latency"`
	Error     string        `json:"error,omitempty"`
}

// CheckHealth sends a minimal request to each configured provider
// and returns the results. Useful for verifying connectivity and quotas.
func (c *Client) CheckHealth(ctx context.Context) []HealthResult {
	var results []HealthResult
	for _, p := range c.providers {
		hr := HealthResult{
			Provider: p.Name(),
			Model:    p.Model(),
		}

		if !p.Available() {
			hr.Error = "rate limited"
			results = append(results, hr)
			continue
		}

		checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		req := &Request{
			Messages:    []Message{{Role: RoleUser, Content: "Reply with exactly: ok"}},
			// 16 tokens is enough for "ok" on every provider while still
			// keeping the probe cheap. DisableThinking covers Gemini 2.5+,
			// where thinking tokens would otherwise consume the budget.
			MaxTokens:       16,
			Temperature:     0,
			DisableThinking: true,
		}

		resp, err := p.Complete(checkCtx, req)
		cancel()

		if err != nil {
			hr.Error = err.Error()
		} else {
			hr.OK = true
			hr.Latency = resp.Latency
		}
		results = append(results, hr)
	}
	return results
}

// Providers returns the list of configured providers (read-only info).
func (c *Client) Providers() []Provider {
	return c.providers
}

// ActivateKillSwitch stops all LLM calls immediately.
func (c *Client) ActivateKillSwitch() {
	c.killSwitch = true
}

// containsSentinel checks if the LLM output contains the sentinel UUID.
// If it does, this indicates the model is echoing internal instructions
// (potential prompt injection).
func containsSentinel(content, uuid string) bool {
	return len(uuid) > 0 && len(content) > 0 &&
		contains(content, uuid)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
