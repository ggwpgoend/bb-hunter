package llm

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// CloseRouterProvider is a Provider for CloseRouter (https://closerouter.dev),
// an OpenAI-compatible pay-per-use gateway that exposes 20+ models from
// multiple labs (Anthropic, OpenAI, Google, etc.) behind one API key.
//
// Unlike free providers, CloseRouter is paid, so this provider tracks
// cumulative token usage and stops calling once a configurable daily USD
// budget is exhausted. The budget is reset every UTC midnight to match
// CloseRouter's server-side daily-spending caps.
type CloseRouterProvider struct {
	inner *OpenAICompatProvider

	dailyLimitUSD float64

	mu          sync.Mutex
	day         string  // UTC YYYY-MM-DD of the current budget window
	spentUSD    float64 // cumulative USD spent today
	overBudget  bool
	pricePer1MIn  float64 // price per 1M input tokens (USD)
	pricePer1MOut float64 // price per 1M output tokens (USD)
}

// CloseRouterBaseURL is the canonical OpenAI-compatible endpoint.
const CloseRouterBaseURL = "https://api.closerouter.dev/v1"

// NewCloseRouterProvider creates a CloseRouter provider with a daily USD
// spending cap. dailyLimitUSD <= 0 disables the client-side cap (CloseRouter
// will still enforce any per-key cap configured server-side).
//
// Model pricing defaults to a conservative anthropic/claude-opus-4.7 estimate
// (~$0.20 per 1M input and ~$0.20 per 1M output, per user) — override with
// SetPricing for other models.
func NewCloseRouterProvider(apiKey, model string, dailyLimitUSD float64) *CloseRouterProvider {
	inner := NewOpenAICompatProvider("closerouter", CloseRouterBaseURL, apiKey, model)
	p := &CloseRouterProvider{
		inner:         inner,
		dailyLimitUSD: dailyLimitUSD,
		pricePer1MIn:  0.20,
		pricePer1MOut: 0.20,
	}
	p.applyKnownPricing(model)
	return p
}

// applyKnownPricing sets in/out price overrides based on the model name.
// Unknown models fall back to the conservative default.
func (p *CloseRouterProvider) applyKnownPricing(model string) {
	m := strings.ToLower(model)
	switch {
	case strings.Contains(m, "opus-4"):
		p.pricePer1MIn = 0.20
		p.pricePer1MOut = 0.20
	case strings.Contains(m, "haiku"):
		p.pricePer1MIn = 0.05
		p.pricePer1MOut = 0.05
	case strings.Contains(m, "sonnet"):
		p.pricePer1MIn = 0.15
		p.pricePer1MOut = 0.15
	case strings.Contains(m, "gpt-5") && strings.Contains(m, "mini"):
		p.pricePer1MIn = 0.05
		p.pricePer1MOut = 0.05
	case strings.Contains(m, "gpt-5"):
		p.pricePer1MIn = 0.30
		p.pricePer1MOut = 0.30
	case strings.Contains(m, "gemini") && strings.Contains(m, "flash"):
		p.pricePer1MIn = 0.05
		p.pricePer1MOut = 0.05
	}
}

// SetPricing overrides the per-1M-token prices (USD) used for budget tracking.
func (p *CloseRouterProvider) SetPricing(inPer1M, outPer1M float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pricePer1MIn = inPer1M
	p.pricePer1MOut = outPer1M
}

// Name returns "closerouter".
func (p *CloseRouterProvider) Name() string { return p.inner.Name() }

// Model returns the configured model id (e.g. "anthropic/claude-opus-4.7").
func (p *CloseRouterProvider) Model() string { return p.inner.Model() }

// Available returns false if the daily budget has been exhausted OR if the
// underlying provider is rate-limited. Resets the budget at UTC midnight.
func (p *CloseRouterProvider) Available() bool {
	if !p.inner.Available() {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resetIfNewDayLocked()
	if p.dailyLimitUSD > 0 && p.overBudget {
		return false
	}
	return true
}

// SpentUSD returns how much (USD) the provider has spent today.
func (p *CloseRouterProvider) SpentUSD() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resetIfNewDayLocked()
	return p.spentUSD
}

// DailyLimitUSD returns the configured daily limit (0 = unlimited client-side).
func (p *CloseRouterProvider) DailyLimitUSD() float64 {
	return p.dailyLimitUSD
}

// Complete dispatches to the underlying OpenAI-compatible client and accrues
// the token cost. If the daily cap is exceeded, it marks the provider as
// over-budget until the next UTC midnight.
func (p *CloseRouterProvider) Complete(ctx context.Context, req *Request) (*Response, error) {
	if !p.Available() {
		return nil, fmt.Errorf("%w: %s: daily budget $%.4f exhausted", ErrRateLimited, p.Name(), p.dailyLimitUSD)
	}

	resp, err := p.inner.Complete(ctx, req)
	if err != nil {
		return nil, err
	}

	costUSD := (float64(resp.InputTokens)/1_000_000.0)*p.pricePer1MIn +
		(float64(resp.OutputTokens)/1_000_000.0)*p.pricePer1MOut

	p.mu.Lock()
	p.resetIfNewDayLocked()
	p.spentUSD += costUSD
	if p.dailyLimitUSD > 0 && p.spentUSD >= p.dailyLimitUSD {
		p.overBudget = true
	}
	p.mu.Unlock()

	return resp, nil
}

// resetIfNewDayLocked clears the spend counter when a new UTC day starts.
// Caller must hold p.mu.
func (p *CloseRouterProvider) resetIfNewDayLocked() {
	today := time.Now().UTC().Format("2006-01-02")
	if today != p.day {
		p.day = today
		p.spentUSD = 0
		p.overBudget = false
	}
}
