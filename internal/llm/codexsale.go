package llm

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// CodexSaleProvider is a Provider for Codex.Sale (https://codex.sale/v1),
// an OpenAI-compatible gateway with RUB-priced access to OpenAI's GPT-5.x
// family (including the codex-tuned variant) at a flat base rate per 1M
// tokens multiplied by a per-model coefficient.
//
// Pricing model (per the Codex.Sale rate card, May 2026):
//
//   - Base price: 5.45 RUB per 1M tokens (configurable via SetPricing).
//   - Per-model multiplier:
//     gpt-5.3-codex / gpt-5.4-mini → 0.9
//     gpt-5.4                       → 1.0
//     gpt-5.5                       → 4.5
//     Fast Speed / Priority         → ×2 (not currently surfaced by us)
//   - Cache hits are billed 100% (we don't model that here — they're a
//     small fraction of normal traffic).
//
// The provider tracks a daily USD-equivalent spend and disables itself
// when the cap is reached (mirroring CloseRouterProvider's behaviour).
type CodexSaleProvider struct {
	inner *OpenAICompatProvider

	rubPer1MBase  float64 // base price (RUB / 1M tokens) before model multiplier
	modelMul      float64 // model-specific coefficient (e.g. 0.9 for codex)
	rubPerUSD     float64 // exchange rate; USD = RUB / rubPerUSD
	dailyLimitUSD float64

	mu         sync.Mutex
	day        string  // UTC YYYY-MM-DD of the current budget window
	spentUSD   float64 // cumulative USD spent today
	overBudget bool
}

// CodexSaleBaseURL is the canonical OpenAI-compatible chat endpoint base.
const CodexSaleBaseURL = "https://codex.sale/v1"

// codexSaleModelMultiplier maps a Codex.Sale model id to its billing
// multiplier. The keys are matched case-insensitively as substrings to
// accommodate both "openai/gpt-5.4-mini" and "gpt-5.4-mini" forms.
func codexSaleModelMultiplier(model string) float64 {
	m := strings.ToLower(model)
	switch {
	case strings.Contains(m, "gpt-5.5"):
		return 4.5
	case strings.Contains(m, "gpt-5.4-mini"):
		return 0.9
	case strings.Contains(m, "gpt-5.3-codex"), strings.Contains(m, "codex-5.3"):
		return 0.9
	case strings.Contains(m, "gpt-5.4"):
		return 1.0
	default:
		return 1.0
	}
}

// NewCodexSaleProvider creates a Codex.Sale provider.
//
//   - rubPer1MBase is the base RUB price per 1M tokens (Codex.Sale advertises
//     ~5.45₽/1M as of May 2026). Pass 0 to use that default.
//   - rubPerUSD is the RUB↔USD conversion rate used to surface the spend in
//     USD for budgeting / cost tracking. Pass 0 to default to 85.
//   - dailyLimitUSD ≤ 0 disables the client-side cap.
func NewCodexSaleProvider(apiKey, model string, rubPer1MBase, rubPerUSD, dailyLimitUSD float64) *CodexSaleProvider {
	if rubPer1MBase <= 0 {
		rubPer1MBase = 5.45
	}
	if rubPerUSD <= 0 {
		rubPerUSD = 85.0
	}
	inner := NewOpenAICompatProvider("codexsale", CodexSaleBaseURL, apiKey, model)
	return &CodexSaleProvider{
		inner:         inner,
		rubPer1MBase:  rubPer1MBase,
		modelMul:      codexSaleModelMultiplier(model),
		rubPerUSD:     rubPerUSD,
		dailyLimitUSD: dailyLimitUSD,
	}
}

// SetPricing overrides the RUB base price and / or RUB-per-USD rate at
// runtime. Pass 0 for either field to leave it unchanged.
func (p *CodexSaleProvider) SetPricing(rubPer1MBase, rubPerUSD float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if rubPer1MBase > 0 {
		p.rubPer1MBase = rubPer1MBase
	}
	if rubPerUSD > 0 {
		p.rubPerUSD = rubPerUSD
	}
}

// Name returns "codexsale".
func (p *CodexSaleProvider) Name() string { return p.inner.Name() }

// Model returns the configured model id (e.g. "openai/gpt-5.4-mini").
func (p *CodexSaleProvider) Model() string { return p.inner.Model() }

// Available returns false if the daily budget has been exhausted OR if the
// underlying provider is rate-limited. Resets the budget at UTC midnight.
func (p *CodexSaleProvider) Available() bool {
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

// SpentUSD returns how much (USD-equivalent) the provider has spent today.
func (p *CodexSaleProvider) SpentUSD() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resetIfNewDayLocked()
	return p.spentUSD
}

// DailyLimitUSD returns the configured daily limit (0 = unlimited client-side).
func (p *CodexSaleProvider) DailyLimitUSD() float64 {
	return p.dailyLimitUSD
}

// PricePer1MUSD reports the current USD-equivalent per 1M tokens (used for
// startup logging / introspection). It applies the model multiplier and the
// configured RUB→USD rate to the base RUB price.
func (p *CodexSaleProvider) PricePer1MUSD() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.usdPer1MLocked()
}

func (p *CodexSaleProvider) usdPer1MLocked() float64 {
	if p.rubPerUSD <= 0 {
		return 0
	}
	return p.rubPer1MBase * p.modelMul / p.rubPerUSD
}

// Complete dispatches to the underlying OpenAI-compatible client and accrues
// the token cost. Codex.Sale bills input+output tokens at the same rate so
// they're summed when computing the per-call charge.
//
// Compatibility quirk: Codex.Sale's edge rejects requests that include
// `response_format: {"type":"json_object"}` for the GPT-5.x reasoning family
// with HTTP 400 "Апстрим отклонил формат запроса". Stage prompts already
// instruct the model to emit raw JSON (Gate / Exploiter forbid markdown
// wrappers explicitly), so we strip JSONMode for Codex.Sale and rely on
// the prompt for structure. Same goes for temperature=0 without an
// accompanying max_tokens — we forward only when both are set.
func (p *CodexSaleProvider) Complete(ctx context.Context, req *Request) (*Response, error) {
	if !p.Available() {
		return nil, fmt.Errorf("%w: %s: daily budget $%.4f exhausted", ErrRateLimited, p.Name(), p.dailyLimitUSD)
	}

	// Clone so we don't mutate the caller's request (other providers in the
	// round-robin still need the original JSONMode flag).
	cloned := *req
	cloned.JSONMode = false

	resp, err := p.inner.Complete(ctx, &cloned)
	if err != nil {
		return nil, err
	}

	totalTokens := float64(resp.InputTokens + resp.OutputTokens)

	p.mu.Lock()
	usdPer1M := p.usdPer1MLocked()
	costUSD := (totalTokens / 1_000_000.0) * usdPer1M
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
func (p *CodexSaleProvider) resetIfNewDayLocked() {
	today := time.Now().UTC().Format("2006-01-02")
	if today != p.day {
		p.day = today
		p.spentUSD = 0
		p.overBudget = false
	}
}
