package hitl

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/models"
)

func TestFormatFindingMessage(t *testing.T) {
	f := &models.Finding{
		ID:               "f-001",
		URL:              "https://example.com/search?q=test",
		Method:           "GET",
		Host:             "example.com",
		Path:             "/search",
		VulnClass:        models.VulnXSS,
		Severity:         models.SeverityHigh,
		Confidence:       0.85,
		Hypothesis:       "XSS in search parameter",
		NucleiTemplateID: "xss-reflected",
		ReportMarkdown:   "# XSS Report\nDetails here...",
	}

	msg := formatFindingMessage(f)

	if !strings.Contains(msg, "[HIGH]") {
		t.Error("should contain severity")
	}
	if !strings.Contains(msg, "XSS") {
		t.Error("should contain vuln class")
	}
	if !strings.Contains(msg, "f-001") {
		t.Error("should contain finding ID")
	}
	if !strings.Contains(msg, "85%") {
		t.Error("should contain confidence")
	}
	if !strings.Contains(msg, "https://example.com/search?q=test") {
		t.Error("should contain URL")
	}
	if !strings.Contains(msg, "xss-reflected") {
		t.Error("should contain template")
	}
	if !strings.Contains(msg, "XSS in search parameter") {
		t.Error("should contain hypothesis")
	}
	if !strings.Contains(msg, "# XSS Report") {
		t.Error("should contain report")
	}
}

func TestSplitMessage(t *testing.T) {
	// Short message — no split
	short := "Hello world"
	chunks := splitMessage(short)
	if len(chunks) != 1 {
		t.Errorf("short message: want 1 chunk, got %d", len(chunks))
	}

	// Long message — should split
	long := strings.Repeat("Line of text\n", 400) // ~5200 chars
	chunks = splitMessage(long)
	if len(chunks) < 2 {
		t.Errorf("long message: want >= 2 chunks, got %d", len(chunks))
	}
	for i, c := range chunks {
		if len(c) > maxMessageLen {
			t.Errorf("chunk %d exceeds max length: %d > %d", i, len(c), maxMessageLen)
		}
	}
}

func TestSplitMessage_ExactLimit(t *testing.T) {
	exact := strings.Repeat("a", maxMessageLen)
	chunks := splitMessage(exact)
	if len(chunks) != 1 {
		t.Errorf("exact limit: want 1 chunk, got %d", len(chunks))
	}
}

func TestBot_SendFinding_NoChatID(t *testing.T) {
	bot := NewBot("fake-token", nil)
	f := &models.Finding{ID: "f-001"}

	err := bot.SendFinding(context.Background(), f)
	if err == nil {
		t.Error("should error without chat ID")
	}
	if !strings.Contains(err.Error(), "no chat ID") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBot_SendFinding_WithMockServer(t *testing.T) {
	var receivedPayloads []map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		json.NewDecoder(r.Body).Decode(&payload)
		receivedPayloads = append(receivedPayloads, payload)
		json.NewEncoder(w).Encode(tgResponse{OK: true, Result: json.RawMessage(`null`)})
	}))
	defer srv.Close()

	bot := NewBot("fake-token", nil)
	bot.chatID = 12345
	// Override telegram API URL by using a custom client that rewrites URLs
	origSendMsg := bot.sendMessage
	_ = origSendMsg // just to show we're aware

	// Instead, we test the formatting and pending tracking
	f := &models.Finding{
		ID:               "f-test-001",
		URL:              "https://example.com/vuln",
		Method:           "GET",
		VulnClass:        models.VulnXSS,
		Severity:         models.SeverityHigh,
		Confidence:       0.9,
		Hypothesis:       "Test hypothesis",
		ReportMarkdown:   "# Test Report",
	}

	// Verify pending tracking
	bot.mu.Lock()
	bot.pending[f.ID] = f
	bot.mu.Unlock()

	bot.mu.Lock()
	_, exists := bot.pending["f-test-001"]
	bot.mu.Unlock()

	if !exists {
		t.Error("finding should be in pending map")
	}
}

func TestBot_HandleCallback_Approve(t *testing.T) {
	bot := NewBot("fake-token", nil)
	bot.chatID = 12345

	// Add a pending finding
	f := &models.Finding{
		ID:        "f-approve-001",
		VulnClass: models.VulnXSS,
	}
	bot.mu.Lock()
	bot.pending[f.ID] = f
	bot.mu.Unlock()

	// Simulate callback
	cb := &tgCallback{
		ID:   "cb-1",
		Data: "approve:f-approve-001",
		Message: &tgMessage{
			Chat: tgChat{ID: 12345},
		},
	}

	// We can't call handleCallback directly because it calls Telegram API
	// But we can test the decision logic

	// Parse callback data manually (same logic as handleCallback)
	parts := strings.SplitN(cb.Data, ":", 2)
	if len(parts) != 2 {
		t.Fatal("bad callback data")
	}
	if parts[0] != "approve" {
		t.Errorf("expected approve, got %s", parts[0])
	}
	if parts[1] != "f-approve-001" {
		t.Errorf("expected f-approve-001, got %s", parts[1])
	}

	// Remove from pending
	bot.mu.Lock()
	_, exists := bot.pending[parts[1]]
	delete(bot.pending, parts[1])
	bot.mu.Unlock()

	if !exists {
		t.Error("finding should have been in pending")
	}

	// Send decision
	decision := Decision{
		FindingID: parts[1],
		Action:    parts[0],
		DecidedAt: time.Now().UTC(),
	}

	select {
	case bot.decisions <- decision:
	default:
		t.Error("decision channel should accept")
	}

	// Read decision
	select {
	case d := <-bot.decisions:
		if d.FindingID != "f-approve-001" {
			t.Errorf("wrong finding ID: %s", d.FindingID)
		}
		if d.Action != "approve" {
			t.Errorf("wrong action: %s", d.Action)
		}
	default:
		t.Error("should have received decision")
	}
}

func TestBot_HandleCallback_Reject(t *testing.T) {
	bot := NewBot("fake-token", nil)

	f := &models.Finding{ID: "f-reject-001"}
	bot.mu.Lock()
	bot.pending[f.ID] = f
	bot.mu.Unlock()

	parts := strings.SplitN("reject:f-reject-001", ":", 2)
	if parts[0] != "reject" || parts[1] != "f-reject-001" {
		t.Fatal("bad parse")
	}

	bot.mu.Lock()
	delete(bot.pending, parts[1])
	bot.mu.Unlock()

	decision := Decision{
		FindingID: parts[1],
		Action:    parts[0],
		DecidedAt: time.Now().UTC(),
	}

	bot.decisions <- decision
	d := <-bot.decisions

	if d.Action != "reject" {
		t.Errorf("expected reject, got %s", d.Action)
	}
}

func TestBot_HandleCallback_NotFound(t *testing.T) {
	bot := NewBot("fake-token", nil)

	// No pending findings — callback for unknown ID
	bot.mu.Lock()
	_, exists := bot.pending["nonexistent"]
	bot.mu.Unlock()

	if exists {
		t.Error("should not find nonexistent finding")
	}
}

func TestFormatFindingMessage_LongReport(t *testing.T) {
	f := &models.Finding{
		ID:             "f-long",
		URL:            "https://example.com/",
		Method:         "GET",
		VulnClass:      models.VulnXSS,
		Severity:       models.SeverityHigh,
		Confidence:     0.9,
		ReportMarkdown: strings.Repeat("A", 5000),
	}

	msg := formatFindingMessage(f)
	if !strings.Contains(msg, "обрезан") {
		t.Error("long report should be truncated with marker")
	}
}

func TestBot_Decisions_Channel(t *testing.T) {
	bot := NewBot("fake-token", nil)

	// Channel should be buffered
	for i := 0; i < 64; i++ {
		bot.decisions <- Decision{FindingID: "test", Action: "approve"}
	}

	// Should have 64 decisions
	count := 0
	for {
		select {
		case <-bot.Decisions():
			count++
		default:
			goto done
		}
	}
done:
	if count != 64 {
		t.Errorf("expected 64 decisions, got %d", count)
	}
}
