package hitl

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/models"
)

func testFinding(id string) *models.Finding {
	return &models.Finding{
		ID:               id,
		FindingKey:       "test-key-" + id,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
		ProgramID:        "test-program",
		ScanRunID:        "test-run",
		URL:              "https://example.com/vuln?param=test",
		Method:           "GET",
		Host:             "example.com",
		Path:             "/vuln",
		NucleiTemplateID: "xss-reflected",
		ScannerEvidence:  "reflected input in response body",
		Severity:         models.SeverityHigh,
		VulnClass:        models.VulnXSS,
		Hypothesis:       "The param parameter is reflected without encoding",
		Confidence:       0.90,
		Status:           models.StatusReported,
		ReportMarkdown:   "# XSS\n\nTest report content",
	}
}

// mockTelegramServer simulates the Telegram Bot API.
func mockTelegramServer(t *testing.T) (*httptest.Server, *mockState) {
	t.Helper()
	state := &mockState{
		sentMessages: make(map[int]string),
		nextMsgID:    100,
		updates:      make([]update, 0),
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Extract method from URL path: /bot<token>/<method>
		path := r.URL.Path
		// Find the method name after the last /
		lastSlash := -1
		for i := len(path) - 1; i >= 0; i-- {
			if path[i] == '/' {
				lastSlash = i
				break
			}
		}
		method := ""
		if lastSlash >= 0 {
			method = path[lastSlash+1:]
		}

		switch method {
		case "sendMessage":
			state.mu.Lock()
			msgID := state.nextMsgID
			state.nextMsgID++
			r.ParseForm()
			state.sentMessages[msgID] = r.FormValue("text")
			state.mu.Unlock()

			json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"result": map[string]any{
					"message_id": msgID,
					"chat":       map[string]any{"id": 12345},
				},
			})

		case "getUpdates":
			state.mu.Lock()
			updates := state.updates
			state.updates = nil
			state.mu.Unlock()

			json.NewEncoder(w).Encode(map[string]any{
				"ok":     true,
				"result": updates,
			})

		case "editMessageText":
			json.NewEncoder(w).Encode(map[string]any{
				"ok":     true,
				"result": map[string]any{"message_id": 1},
			})

		case "answerCallbackQuery":
			json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
			})

		default:
			json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
			})
		}
	})

	srv := httptest.NewServer(mux)
	return srv, state
}

type mockState struct {
	mu           sync.Mutex
	sentMessages map[int]string // msgID → text
	nextMsgID    int
	updates      []update
}

func (s *mockState) addCallback(updateID int, findingID, action string, msgID int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updates = append(s.updates, update{
		UpdateID: updateID,
		CallbackQuery: &callbackQuery{
			ID:   fmt.Sprintf("cb-%d", updateID),
			Data: fmt.Sprintf("%s:%s", action, findingID),
			Message: struct {
				MessageID int `json:"message_id"`
				Chat      struct {
					ID int64 `json:"id"`
				} `json:"chat"`
			}{
				MessageID: msgID,
			},
		},
	})
}

func TestSendFinding(t *testing.T) {
	srv, state := mockTelegramServer(t)
	defer srv.Close()

	bot := NewBot(Config{
		Token:   "test-token",
		ChatID:  12345,
		BaseURL: srv.URL,
	})

	finding := testFinding("f-001")
	msgID, err := bot.SendFinding(context.Background(), finding)
	if err != nil {
		t.Fatalf("SendFinding failed: %v", err)
	}

	if msgID == 0 {
		t.Fatal("expected non-zero message ID")
	}

	// Verify finding is tracked as pending
	if bot.PendingCount() != 1 {
		t.Errorf("expected 1 pending, got %d", bot.PendingCount())
	}

	// Verify message was sent
	state.mu.Lock()
	text, ok := state.sentMessages[msgID]
	state.mu.Unlock()
	if !ok {
		t.Fatal("message not found in mock state")
	}

	if !containsStr(text, "f-001") {
		t.Errorf("message should contain finding ID, got: %s", text[:100])
	}
	if !containsStr(text, "xss") {
		t.Errorf("message should contain vuln class, got: %s", text[:100])
	}
}

func TestSendBatch(t *testing.T) {
	srv, _ := mockTelegramServer(t)
	defer srv.Close()

	bot := NewBot(Config{
		Token:   "test-token",
		ChatID:  12345,
		BaseURL: srv.URL,
	})

	findings := []*models.Finding{
		testFinding("f-001"),
		testFinding("f-002"),
		testFinding("f-003"),
	}

	err := bot.SendBatch(context.Background(), findings)
	if err != nil {
		t.Fatalf("SendBatch failed: %v", err)
	}

	if bot.PendingCount() != 3 {
		t.Errorf("expected 3 pending, got %d", bot.PendingCount())
	}
}

func TestApproveCallback(t *testing.T) {
	srv, state := mockTelegramServer(t)
	defer srv.Close()

	var decisions []Decision
	var mu sync.Mutex

	bot := NewBot(Config{
		Token:  "test-token",
		ChatID: 12345,
		OnDecision: func(ctx context.Context, d Decision) error {
			mu.Lock()
			decisions = append(decisions, d)
			mu.Unlock()
			return nil
		},
		BaseURL: srv.URL,
	})

	finding := testFinding("f-approve-test")
	msgID, err := bot.SendFinding(context.Background(), finding)
	if err != nil {
		t.Fatalf("SendFinding failed: %v", err)
	}

	// Simulate approve callback
	state.addCallback(1, "f-approve-test", "approve", msgID)

	// Run one poll cycle
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go bot.StartPolling(ctx)
	time.Sleep(500 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(decisions) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(decisions))
	}
	if decisions[0].State != StateApproved {
		t.Errorf("expected approved, got %s", decisions[0].State)
	}
	if decisions[0].FindingID != "f-approve-test" {
		t.Errorf("expected finding ID f-approve-test, got %s", decisions[0].FindingID)
	}

	// Pending count should be 0 now
	if bot.PendingCount() != 0 {
		t.Errorf("expected 0 pending after approval, got %d", bot.PendingCount())
	}
}

func TestRejectCallback(t *testing.T) {
	srv, state := mockTelegramServer(t)
	defer srv.Close()

	var decisions []Decision
	var mu sync.Mutex

	bot := NewBot(Config{
		Token:  "test-token",
		ChatID: 12345,
		OnDecision: func(ctx context.Context, d Decision) error {
			mu.Lock()
			decisions = append(decisions, d)
			mu.Unlock()
			return nil
		},
		BaseURL: srv.URL,
	})

	finding := testFinding("f-reject-test")
	msgID, err := bot.SendFinding(context.Background(), finding)
	if err != nil {
		t.Fatalf("SendFinding failed: %v", err)
	}

	state.addCallback(1, "f-reject-test", "reject", msgID)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go bot.StartPolling(ctx)
	time.Sleep(500 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(decisions) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(decisions))
	}
	if decisions[0].State != StateRejected {
		t.Errorf("expected rejected, got %s", decisions[0].State)
	}
}

func TestTimeout(t *testing.T) {
	srv, _ := mockTelegramServer(t)
	defer srv.Close()

	var decisions []Decision
	var mu sync.Mutex

	bot := NewBot(Config{
		Token:   "test-token",
		ChatID:  12345,
		Timeout: 100 * time.Millisecond, // very short timeout for test
		OnDecision: func(ctx context.Context, d Decision) error {
			mu.Lock()
			decisions = append(decisions, d)
			mu.Unlock()
			return nil
		},
		BaseURL: srv.URL,
	})

	finding := testFinding("f-timeout-test")
	_, err := bot.SendFinding(context.Background(), finding)
	if err != nil {
		t.Fatalf("SendFinding failed: %v", err)
	}

	// Wait for timeout
	time.Sleep(200 * time.Millisecond)
	bot.CheckTimeouts(context.Background())

	mu.Lock()
	defer mu.Unlock()
	if len(decisions) != 1 {
		t.Fatalf("expected 1 timeout decision, got %d", len(decisions))
	}
	if decisions[0].State != StateTimedOut {
		t.Errorf("expected timed_out, got %s", decisions[0].State)
	}
	if bot.PendingCount() != 0 {
		t.Errorf("expected 0 pending after timeout, got %d", bot.PendingCount())
	}
}

func TestDuplicateDecision(t *testing.T) {
	srv, state := mockTelegramServer(t)
	defer srv.Close()

	callCount := 0
	var mu sync.Mutex

	bot := NewBot(Config{
		Token:  "test-token",
		ChatID: 12345,
		OnDecision: func(ctx context.Context, d Decision) error {
			mu.Lock()
			callCount++
			mu.Unlock()
			return nil
		},
		BaseURL: srv.URL,
	})

	finding := testFinding("f-dup-test")
	msgID, _ := bot.SendFinding(context.Background(), finding)

	// Send approve twice
	state.addCallback(1, "f-dup-test", "approve", msgID)
	state.addCallback(2, "f-dup-test", "approve", msgID)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go bot.StartPolling(ctx)
	time.Sleep(500 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	// Only the first callback should trigger a decision
	if callCount != 1 {
		t.Errorf("expected exactly 1 decision call (idempotent), got %d", callCount)
	}
}

func TestFormatFinding(t *testing.T) {
	f := testFinding("f-format-test")
	text := formatFinding(f)

	checks := []string{
		"f-format-test",
		"example.com/vuln",
		"xss",
		"high",
		"90%",
		"XSS",
	}

	for _, check := range checks {
		if !containsStr(text, check) {
			t.Errorf("formatted text should contain %q", check)
		}
	}
}

func TestFormatFindingLongReport(t *testing.T) {
	f := testFinding("f-long-report")
	f.ReportMarkdown = string(make([]byte, 3000)) // 3000 bytes of zeros
	text := formatFinding(f)

	if !containsStr(text, "обрезан") {
		t.Error("long report should be truncated with 'обрезан' marker")
	}

	// Total should be under Telegram's ~4096 limit (we truncate at 2000 + overhead)
	if len(text) > 4096 {
		t.Errorf("formatted text too long for Telegram: %d chars", len(text))
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && searchStr(s, substr)
}

func searchStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
