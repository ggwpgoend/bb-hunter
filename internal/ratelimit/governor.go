// Package ratelimit implements a per-host token bucket rate limiter.
// Prevents bb-hunter from overwhelming targets and getting banned.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Governor manages per-host rate limits using token buckets.
type Governor struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second (default for new hosts)
	burst   int     // max burst size
}

type bucket struct {
	tokens    float64
	maxTokens float64
	rate      float64 // tokens per second
	lastFill  time.Time
}

// NewGovernor creates a rate limiter with the given default rate and burst.
func NewGovernor(requestsPerSecond float64, burst int) *Governor {
	if burst <= 0 {
		burst = 1
	}
	return &Governor{
		buckets: make(map[string]*bucket),
		rate:    requestsPerSecond,
		burst:   burst,
	}
}

// Wait blocks until a token is available for the given host.
// Returns an error if the context is cancelled.
func (g *Governor) Wait(ctx context.Context, host string) error {
	for {
		if g.tryAcquire(host) {
			return nil
		}

		// Calculate wait time
		g.mu.Lock()
		b := g.buckets[host]
		waitTime := time.Duration(float64(time.Second) / b.rate)
		g.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitTime):
		}
	}
}

// TryAcquire attempts to acquire a token without blocking.
// Returns true if a token was available.
func (g *Governor) TryAcquire(host string) bool {
	return g.tryAcquire(host)
}

func (g *Governor) tryAcquire(host string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	b, ok := g.buckets[host]
	if !ok {
		b = &bucket{
			tokens:    float64(g.burst),
			maxTokens: float64(g.burst),
			rate:      g.rate,
			lastFill:  time.Now(),
		}
		g.buckets[host] = b
	}

	// Refill tokens based on elapsed time
	now := time.Now()
	elapsed := now.Sub(b.lastFill).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.maxTokens {
		b.tokens = b.maxTokens
	}
	b.lastFill = now

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true
	}

	return false
}

// SetHostRate overrides the rate for a specific host.
func (g *Governor) SetHostRate(host string, rate float64, burst int) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.buckets[host] = &bucket{
		tokens:    float64(burst),
		maxTokens: float64(burst),
		rate:      rate,
		lastFill:  time.Now(),
	}
}
