package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestGovernor_TryAcquire(t *testing.T) {
	g := NewGovernor(10.0, 3) // 10 req/s, burst of 3

	// First 3 should succeed (burst)
	for i := 0; i < 3; i++ {
		if !g.TryAcquire("example.com") {
			t.Errorf("request %d should succeed (within burst)", i)
		}
	}

	// 4th should fail (burst exhausted)
	if g.TryAcquire("example.com") {
		t.Error("request 4 should fail (burst exhausted)")
	}
}

func TestGovernor_Refill(t *testing.T) {
	g := NewGovernor(10.0, 1) // 10 req/s, burst of 1

	// Use the token
	g.TryAcquire("example.com")

	// Should fail immediately
	if g.TryAcquire("example.com") {
		t.Error("should fail immediately after using single token")
	}

	// Wait for refill (100ms for 10 req/s)
	time.Sleep(150 * time.Millisecond)

	// Should succeed now
	if !g.TryAcquire("example.com") {
		t.Error("should succeed after refill period")
	}
}

func TestGovernor_PerHost(t *testing.T) {
	g := NewGovernor(10.0, 1)

	// Exhaust host A
	g.TryAcquire("host-a.com")
	if g.TryAcquire("host-a.com") {
		t.Error("host-a should be exhausted")
	}

	// Host B should still work
	if !g.TryAcquire("host-b.com") {
		t.Error("host-b should have its own bucket")
	}
}

func TestGovernor_Wait(t *testing.T) {
	g := NewGovernor(10.0, 1)

	// Use the token
	g.TryAcquire("example.com")

	// Wait should complete within ~200ms (refill at 10/s = 100ms per token)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := g.Wait(ctx, "example.com")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Wait should succeed: %v", err)
	}
	if elapsed < 50*time.Millisecond {
		t.Errorf("Wait should have blocked briefly, elapsed: %v", elapsed)
	}
}

func TestGovernor_WaitCancel(t *testing.T) {
	g := NewGovernor(0.1, 1) // Very slow: 1 req per 10 seconds

	// Exhaust
	g.TryAcquire("example.com")

	// Cancel quickly
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := g.Wait(ctx, "example.com")
	if err == nil {
		t.Error("Wait should fail on cancelled context")
	}
}

func TestGovernor_SetHostRate(t *testing.T) {
	g := NewGovernor(10.0, 1)

	// Override rate for specific host
	g.SetHostRate("slow.com", 1.0, 2)

	// Should get 2 burst tokens
	if !g.TryAcquire("slow.com") {
		t.Error("first request should succeed")
	}
	if !g.TryAcquire("slow.com") {
		t.Error("second request should succeed (burst=2)")
	}
	if g.TryAcquire("slow.com") {
		t.Error("third request should fail")
	}
}
