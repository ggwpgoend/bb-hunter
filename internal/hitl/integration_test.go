//go:build integration

package hitl

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/models"
)

// Run with: go test -tags integration -run TestIntegrationTelegram ./internal/hitl/ -v
// Requires env vars: TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
func TestIntegrationTelegram(t *testing.T) {
	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	chatIDStr := os.Getenv("TELEGRAM_CHAT_ID")

	if token == "" || chatIDStr == "" {
		t.Skip("TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not set")
	}

	chatID, err := strconv.ParseInt(chatIDStr, 10, 64)
	if err != nil {
		t.Fatalf("invalid TELEGRAM_CHAT_ID: %v", err)
	}

	var decisions []Decision
	var mu sync.Mutex

	bot := NewBot(Config{
		Token:   token,
		ChatID:  chatID,
		Timeout: 5 * time.Minute,
		OnDecision: func(ctx context.Context, d Decision) error {
			mu.Lock()
			decisions = append(decisions, d)
			mu.Unlock()
			t.Logf("Decision received: finding=%s state=%s reason=%s", d.FindingID, d.State, d.Reason)
			return nil
		},
	})

	finding := &models.Finding{
		ID:               "integration-test-001",
		FindingKey:       "test-key-integration",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
		ProgramID:        "test-program",
		ScanRunID:        "test-run",
		URL:              "https://example.com/search?q=<script>alert(1)</script>",
		Method:           "GET",
		Host:             "example.com",
		Path:             "/search",
		NucleiTemplateID: "xss-reflected",
		ScannerEvidence:  "Input reflected in response without encoding",
		Severity:         models.SeverityHigh,
		VulnClass:        models.VulnXSS,
		Hypothesis:       "The q parameter is reflected without HTML encoding, allowing XSS",
		Confidence:       0.92,
		Status:           models.StatusReported,
		ReportMarkdown:   "# Reflected XSS\n\nTest finding for integration test.\nURL: https://example.com/search?q=test\nSeverity: High",
	}

	ctx := context.Background()

	// Send finding to Telegram
	msgID, err := bot.SendFinding(ctx, finding)
	if err != nil {
		t.Fatalf("SendFinding failed: %v", err)
	}
	t.Logf("Finding sent to Telegram, message_id=%d", msgID)

	fmt.Println("\n=== INTEGRATION TEST ===")
	fmt.Println("Finding sent to Telegram bot.")
	fmt.Println("Please open Telegram and press Approve or Reject.")
	fmt.Println("Waiting for callback (timeout: 2 min)...")
	fmt.Println("========================")

	// Start polling
	pollCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	go bot.StartPolling(pollCtx)

	// Wait for decision
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-pollCtx.Done():
			t.Log("Timeout waiting for callback — checking if any decision was received")
			mu.Lock()
			n := len(decisions)
			mu.Unlock()
			if n == 0 {
				t.Log("No callback received within timeout (this is expected if no one pressed a button)")
			}
			bot.Stop()
			return
		case <-ticker.C:
			mu.Lock()
			n := len(decisions)
			mu.Unlock()
			if n > 0 {
				mu.Lock()
				d := decisions[0]
				mu.Unlock()
				t.Logf("SUCCESS: Decision=%s for finding=%s", d.State, d.FindingID)
				if d.FindingID != "integration-test-001" {
					t.Errorf("unexpected finding_id: %s", d.FindingID)
				}
				bot.Stop()
				return
			}
		}
	}
}
