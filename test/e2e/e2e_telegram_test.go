package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/hitl"
	"github.com/ggwpgoend/bb-hunter/internal/models"
)

// TestE2E_Telegram_BotInfo verifies the bot token is valid.
func TestE2E_Telegram_BotInfo(t *testing.T) {
	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	if token == "" {
		t.Skip("TELEGRAM_BOT_TOKEN not set")
	}

	resp, err := http.Get(fmt.Sprintf("https://api.telegram.org/bot%s/getMe", token))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		OK     bool `json:"ok"`
		Result struct {
			Username string `json:"username"`
			ID       int64  `json:"id"`
		} `json:"result"`
	}
	json.Unmarshal(body, &result)

	if !result.OK {
		t.Fatal("bot token invalid")
	}
	fmt.Printf("Bot: @%s (ID: %d)\n", result.Result.Username, result.Result.ID)
}

// TestE2E_Telegram_SendFinding sends a test finding to Telegram.
// Requires TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID.
func TestE2E_Telegram_SendFinding(t *testing.T) {
	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	chatIDStr := os.Getenv("TELEGRAM_CHAT_ID")
	if token == "" || chatIDStr == "" {
		t.Skip("TELEGRAM_BOT_TOKEN and/or TELEGRAM_CHAT_ID not set")
	}

	chatID, err := strconv.ParseInt(chatIDStr, 10, 64)
	if err != nil {
		t.Fatalf("invalid TELEGRAM_CHAT_ID: %v", err)
	}

	bot := hitl.NewBot(token, nil)
	bot.SetChatID(chatID)

	finding := &models.Finding{
		ID:               "e2e-tg-001",
		URL:              "https://example.com/search?q=test",
		Method:           "GET",
		Host:             "example.com",
		Path:             "/search",
		VulnClass:        models.VulnXSS,
		Severity:         models.SeverityHigh,
		Confidence:       0.90,
		Hypothesis:       "Reflected XSS in search parameter — user input rendered without encoding.",
		NucleiTemplateID: "xss-reflected-double-context",
		ReportMarkdown:   "# Reflected XSS\n\n## Описание\nПараметр q в поисковой строке отражается в HTML без экранирования.\n\n## Шаги воспроизведения\n1. Откройте URL\n2. Наблюдайте выполнение JavaScript.\n\n## Влияние\nКража сессии, фишинг.\n\n## Severity: High",
		Status:           models.StatusReported,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Println("=== Sending finding to Telegram ===")
	if err := bot.SendFinding(ctx, finding); err != nil {
		t.Fatalf("SendFinding failed: %v", err)
	}
	fmt.Println("Finding sent. Check Telegram for approve/reject buttons.")
}

// TestE2E_Telegram_PollAndDecide starts polling and waits for a decision.
// Requires TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID.
func TestE2E_Telegram_PollAndDecide(t *testing.T) {
	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	chatIDStr := os.Getenv("TELEGRAM_CHAT_ID")
	if token == "" || chatIDStr == "" {
		t.Skip("TELEGRAM_BOT_TOKEN and/or TELEGRAM_CHAT_ID not set")
	}

	chatID, err := strconv.ParseInt(chatIDStr, 10, 64)
	if err != nil {
		t.Fatalf("invalid TELEGRAM_CHAT_ID: %v", err)
	}

	bot := hitl.NewBot(token, nil)
	bot.SetChatID(chatID)

	// Send a finding first
	finding := &models.Finding{
		ID:               "e2e-tg-decide-001",
		URL:              "https://example.com/admin",
		Method:           "POST",
		Host:             "example.com",
		Path:             "/admin",
		VulnClass:        models.VulnAuthBypass,
		Severity:         models.SeverityHigh,
		Confidence:       0.95,
		Hypothesis:       "Default credentials admin:admin allow full access.",
		NucleiTemplateID: "default-login",
		ReportMarkdown:   "# Auth Bypass\n\n## Описание\nДоступ к админ-панели с дефолтными кредами.\n\n## Severity: High",
		Status:           models.StatusReported,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := bot.SendFinding(ctx, finding); err != nil {
		t.Fatalf("SendFinding failed: %v", err)
	}
	fmt.Println("Finding sent. Click Approve or Reject in Telegram...")

	// Start polling
	go bot.PollUpdates(ctx)

	// Wait for decision
	select {
	case d := <-bot.Decisions():
		fmt.Printf("Decision received: finding=%s action=%s\n", d.FindingID, d.Action)
		if d.FindingID != "e2e-tg-decide-001" {
			t.Errorf("wrong finding ID: %s", d.FindingID)
		}
		if d.Action != "approve" && d.Action != "reject" {
			t.Errorf("invalid action: %s", d.Action)
		}
	case <-ctx.Done():
		t.Log("Timeout — no decision received within 60s (this is OK for automated test)")
	}
}
