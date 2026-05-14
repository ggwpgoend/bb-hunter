// Package cost implements per-provider cost/quota tracking with kill switch.
// Since all providers use free tiers, "cost" means token/request consumption
// relative to daily/monthly quotas.
package cost

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ProviderQuota defines the limits for a single LLM provider.
type ProviderQuota struct {
	Name            string
	DailyRequests   int   // max requests per day (0 = unlimited)
	DailyTokens     int64 // max tokens per day (0 = unlimited)
	MonthlyTokens   int64 // max tokens per month (0 = unlimited)
}

// ProviderUsage tracks current usage for a provider.
type ProviderUsage struct {
	RequestsToday  int
	TokensToday    int64
	TokensMonth    int64
	LastReset      time.Time
	MonthlyReset   time.Time
}

// Tracker monitors provider usage against quotas.
type Tracker struct {
	mu       sync.RWMutex
	quotas   map[string]ProviderQuota
	usage    map[string]*ProviderUsage
	killed   bool
	logger   *slog.Logger

	// KillThreshold: if total daily usage across all providers exceeds
	// this fraction (0.0-1.0) of total daily quota, activate kill switch.
	KillThreshold float64

	// OnKillSwitch is called when the kill switch activates.
	OnKillSwitch func()
}

// NewTracker creates a tracker with the given quotas.
func NewTracker(quotas []ProviderQuota, logger *slog.Logger) *Tracker {
	if logger == nil {
		logger = slog.Default()
	}
	t := &Tracker{
		quotas:        make(map[string]ProviderQuota),
		usage:         make(map[string]*ProviderUsage),
		logger:        logger,
		KillThreshold: 0.9, // 90% default
	}

	now := time.Now()
	for _, q := range quotas {
		t.quotas[q.Name] = q
		t.usage[q.Name] = &ProviderUsage{
			LastReset:    now,
			MonthlyReset: time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()),
		}
	}

	return t
}

// Record records token usage for a provider.
func (t *Tracker) Record(provider string, inputTokens, outputTokens int) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.killed {
		return fmt.Errorf("cost: kill switch active")
	}

	usage, ok := t.usage[provider]
	if !ok {
		return fmt.Errorf("cost: unknown provider %q", provider)
	}

	// Reset daily counters if day changed
	now := time.Now()
	if now.Day() != usage.LastReset.Day() || now.Month() != usage.LastReset.Month() {
		usage.RequestsToday = 0
		usage.TokensToday = 0
		usage.LastReset = now
	}
	if now.Month() != usage.MonthlyReset.Month() {
		usage.TokensMonth = 0
		usage.MonthlyReset = now
	}

	total := int64(inputTokens + outputTokens)
	usage.RequestsToday++
	usage.TokensToday += total
	usage.TokensMonth += total

	// Check quota
	quota := t.quotas[provider]
	if quota.DailyRequests > 0 && usage.RequestsToday >= quota.DailyRequests {
		t.logger.Warn("cost: daily request quota reached",
			"provider", provider,
			"used", usage.RequestsToday,
			"limit", quota.DailyRequests,
		)
	}
	if quota.DailyTokens > 0 && usage.TokensToday >= quota.DailyTokens {
		t.logger.Warn("cost: daily token quota reached",
			"provider", provider,
			"used", usage.TokensToday,
			"limit", quota.DailyTokens,
		)
	}

	// Check kill threshold
	t.checkKillThreshold()

	return nil
}

// IsAvailable returns whether a provider still has quota remaining.
func (t *Tracker) IsAvailable(provider string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.killed {
		return false
	}

	usage, ok := t.usage[provider]
	if !ok {
		return false
	}
	quota, ok := t.quotas[provider]
	if !ok {
		return false
	}

	if quota.DailyRequests > 0 && usage.RequestsToday >= quota.DailyRequests {
		return false
	}
	if quota.DailyTokens > 0 && usage.TokensToday >= quota.DailyTokens {
		return false
	}
	if quota.MonthlyTokens > 0 && usage.TokensMonth >= quota.MonthlyTokens {
		return false
	}

	return true
}

// GetUsage returns current usage for a provider.
func (t *Tracker) GetUsage(provider string) (ProviderUsage, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	u, ok := t.usage[provider]
	if !ok {
		return ProviderUsage{}, false
	}
	return *u, true
}

// IsKilled returns whether the kill switch has been activated.
func (t *Tracker) IsKilled() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.killed
}

func (t *Tracker) checkKillThreshold() {
	if t.KillThreshold <= 0 {
		return
	}

	var totalUsed, totalQuota float64
	for name, usage := range t.usage {
		quota := t.quotas[name]
		if quota.DailyTokens > 0 {
			totalUsed += float64(usage.TokensToday)
			totalQuota += float64(quota.DailyTokens)
		}
	}

	if totalQuota > 0 && totalUsed/totalQuota >= t.KillThreshold {
		t.killed = true
		t.logger.Error("cost: KILL SWITCH ACTIVATED",
			"used_fraction", totalUsed/totalQuota,
			"threshold", t.KillThreshold,
		)
		if t.OnKillSwitch != nil {
			go t.OnKillSwitch()
		}
	}
}
