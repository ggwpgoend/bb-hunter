// Package hitl implements the Human-In-The-Loop Telegram bot.
// Findings flow: reported → sent to Telegram → human approves/rejects →
// decision recorded in DB + audit log.
//
// FSM per finding:
//
//	PENDING → APPROVED (human clicks ✅) → status=approved
//	PENDING → REJECTED (human clicks ❌) → status=rejected
//	PENDING → TIMED_OUT (no response within timeout) → status=rejected
package hitl

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/models"
)

// DecisionState is the current state of a finding in the HITL FSM.
type DecisionState string

const (
	StatePending  DecisionState = "pending"
	StateApproved DecisionState = "approved"
	StateRejected DecisionState = "rejected"
	StateTimedOut DecisionState = "timed_out"
)

// Decision captures the human's approve/reject decision.
type Decision struct {
	FindingID string
	State     DecisionState
	Reason    string
	DecidedAt time.Time
}

// DecisionHandler is called when a human makes a decision on a finding.
type DecisionHandler func(ctx context.Context, decision Decision) error

// PendingFinding tracks a finding waiting for human review.
type PendingFinding struct {
	Finding   *models.Finding
	MessageID int
	SentAt    time.Time
	State     DecisionState
}

// Bot is the Telegram HITL bot.
type Bot struct {
	token   string
	chatID  int64
	baseURL string

	onDecision DecisionHandler
	timeout    time.Duration

	mu       sync.Mutex
	pending  map[string]*PendingFinding // finding_id → PendingFinding
	msgToFid map[int]string             // message_id → finding_id (for callback routing)

	log    *slog.Logger
	client *http.Client
	cancel context.CancelFunc
}

// Config holds the bot configuration.
type Config struct {
	Token      string
	ChatID     int64
	OnDecision DecisionHandler
	Timeout    time.Duration // per-finding timeout; default 1h
	Logger     *slog.Logger
	BaseURL    string // override for testing; default https://api.telegram.org
}

// NewBot creates a new Telegram HITL bot.
func NewBot(cfg Config) *Bot {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 1 * time.Hour
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.telegram.org"
	}
	return &Bot{
		token:      cfg.Token,
		chatID:     cfg.ChatID,
		baseURL:    cfg.BaseURL,
		onDecision: cfg.OnDecision,
		timeout:    cfg.Timeout,
		pending:    make(map[string]*PendingFinding),
		msgToFid:   make(map[int]string),
		log:        cfg.Logger,
		client:     &http.Client{Timeout: 30 * time.Second},
	}
}

// apiURL builds the full Telegram Bot API URL for a method.
func (b *Bot) apiURL(method string) string {
	return fmt.Sprintf("%s/bot%s/%s", b.baseURL, b.token, method)
}

// SendFinding sends a finding report to Telegram with approve/reject buttons.
// Returns the message ID of the sent message.
func (b *Bot) SendFinding(ctx context.Context, finding *models.Finding) (int, error) {
	text := formatFinding(finding)

	// Inline keyboard: Approve / Reject
	keyboard := inlineKeyboard(finding.ID)
	kbJSON, _ := json.Marshal(keyboard)

	params := url.Values{
		"chat_id":      {fmt.Sprintf("%d", b.chatID)},
		"text":         {text},
		"parse_mode":   {"Markdown"},
		"reply_markup": {string(kbJSON)},
	}

	msgID, err := b.sendMessage(ctx, params)
	if err != nil {
		return 0, fmt.Errorf("hitl: send finding failed: %w", err)
	}

	b.mu.Lock()
	pf := &PendingFinding{
		Finding:   finding,
		MessageID: msgID,
		SentAt:    time.Now(),
		State:     StatePending,
	}
	b.pending[finding.ID] = pf
	b.msgToFid[msgID] = finding.ID
	b.mu.Unlock()

	b.log.Info("hitl: finding sent to Telegram",
		"finding_id", finding.ID,
		"message_id", msgID,
		"vuln_class", finding.VulnClass,
	)

	return msgID, nil
}

// SendBatch sends multiple findings to Telegram.
func (b *Bot) SendBatch(ctx context.Context, findings []*models.Finding) error {
	for _, f := range findings {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, err := b.SendFinding(ctx, f); err != nil {
			b.log.Error("hitl: batch send failed", "finding_id", f.ID, "error", err)
			continue
		}
		// Telegram rate limit: max 30 messages/sec, be conservative
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

// StartPolling begins long-polling for Telegram updates (callback queries).
// Blocks until ctx is cancelled.
func (b *Bot) StartPolling(ctx context.Context) {
	ctx, b.cancel = context.WithCancel(ctx)
	var offset int

	b.log.Info("hitl: starting Telegram polling")

	for {
		select {
		case <-ctx.Done():
			b.log.Info("hitl: polling stopped")
			return
		default:
		}

		updates, err := b.getUpdates(ctx, offset, 30)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			b.log.Error("hitl: getUpdates failed", "error", err)
			time.Sleep(5 * time.Second)
			continue
		}

		for _, u := range updates {
			if u.UpdateID >= offset {
				offset = u.UpdateID + 1
			}
			if u.CallbackQuery != nil {
				b.handleCallback(ctx, u.CallbackQuery)
			}
		}
	}
}

// Stop stops the polling loop.
func (b *Bot) Stop() {
	if b.cancel != nil {
		b.cancel()
	}
}

// CheckTimeouts checks all pending findings and times out stale ones.
func (b *Bot) CheckTimeouts(ctx context.Context) {
	b.mu.Lock()
	var timedOut []string
	now := time.Now()
	for fid, pf := range b.pending {
		if pf.State == StatePending && now.Sub(pf.SentAt) > b.timeout {
			timedOut = append(timedOut, fid)
		}
	}
	b.mu.Unlock()

	for _, fid := range timedOut {
		b.resolveDecision(ctx, fid, StateTimedOut, "timed out: no human response")
	}
}

// PendingCount returns the number of findings awaiting human decision.
func (b *Bot) PendingCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	count := 0
	for _, pf := range b.pending {
		if pf.State == StatePending {
			count++
		}
	}
	return count
}

// WaitForAll blocks until all pending findings are decided or ctx is cancelled.
// Periodically checks for timeouts.
func (b *Bot) WaitForAll(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.CheckTimeouts(ctx)
			if b.PendingCount() == 0 {
				return
			}
		}
	}
}

// handleCallback processes an inline keyboard button press.
func (b *Bot) handleCallback(ctx context.Context, cb *callbackQuery) {
	// data format: "approve:<finding_id>" or "reject:<finding_id>"
	parts := strings.SplitN(cb.Data, ":", 2)
	if len(parts) != 2 {
		b.log.Warn("hitl: invalid callback data", "data", cb.Data)
		return
	}

	action := parts[0]
	findingID := parts[1]

	var state DecisionState
	var reason string

	switch action {
	case "approve":
		state = StateApproved
		reason = "approved by human via Telegram"
	case "reject":
		state = StateRejected
		reason = "rejected by human via Telegram"
	default:
		b.log.Warn("hitl: unknown callback action", "action", action)
		return
	}

	b.resolveDecision(ctx, findingID, state, reason)

	// Answer callback query to remove loading spinner
	b.answerCallback(ctx, cb.ID, fmt.Sprintf("Finding %s: %s", findingID[:8], action))
}

// resolveDecision processes a decision (approve/reject/timeout) for a finding.
func (b *Bot) resolveDecision(ctx context.Context, findingID string, state DecisionState, reason string) {
	b.mu.Lock()
	pf, ok := b.pending[findingID]
	if !ok || pf.State != StatePending {
		b.mu.Unlock()
		return
	}
	pf.State = state
	b.mu.Unlock()

	decision := Decision{
		FindingID: findingID,
		State:     state,
		Reason:    reason,
		DecidedAt: time.Now(),
	}

	b.log.Info("hitl: decision made",
		"finding_id", findingID,
		"state", state,
		"reason", reason,
	)

	if b.onDecision != nil {
		if err := b.onDecision(ctx, decision); err != nil {
			b.log.Error("hitl: decision handler failed",
				"finding_id", findingID,
				"error", err,
			)
		}
	}

	// Update Telegram message to show decision
	b.updateDecisionMessage(ctx, pf, state)
}

// updateDecisionMessage edits the Telegram message to reflect the decision.
func (b *Bot) updateDecisionMessage(ctx context.Context, pf *PendingFinding, state DecisionState) {
	var statusEmoji string
	switch state {
	case StateApproved:
		statusEmoji = "APPROVED"
	case StateRejected:
		statusEmoji = "REJECTED"
	case StateTimedOut:
		statusEmoji = "TIMED OUT"
	}

	newText := formatFinding(pf.Finding) + fmt.Sprintf("\n\n*Status: %s*", statusEmoji)

	params := url.Values{
		"chat_id":    {fmt.Sprintf("%d", b.chatID)},
		"message_id": {fmt.Sprintf("%d", pf.MessageID)},
		"text":       {newText},
		"parse_mode": {"Markdown"},
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		b.apiURL("editMessageText"),
		strings.NewReader(params.Encode()),
	)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := b.client.Do(req)
	if err != nil {
		b.log.Error("hitl: editMessageText failed", "error", err)
		return
	}
	defer resp.Body.Close()
}

// --- Telegram API helpers ---

func (b *Bot) sendMessage(ctx context.Context, params url.Values) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "POST",
		b.apiURL("sendMessage"),
		strings.NewReader(params.Encode()),
	)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := b.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("read response: %w", err)
	}

	var result struct {
		OK     bool `json:"ok"`
		Result struct {
			MessageID int `json:"message_id"`
		} `json:"result"`
		Description string `json:"description"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return 0, fmt.Errorf("unmarshal response: %w", err)
	}
	if !result.OK {
		return 0, fmt.Errorf("telegram API error: %s", result.Description)
	}

	return result.Result.MessageID, nil
}

func (b *Bot) getUpdates(ctx context.Context, offset, timeout int) ([]update, error) {
	params := url.Values{
		"offset":          {fmt.Sprintf("%d", offset)},
		"timeout":         {fmt.Sprintf("%d", timeout)},
		"allowed_updates": {"[\"callback_query\"]"},
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		b.apiURL("getUpdates"),
		strings.NewReader(params.Encode()),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var result struct {
		OK     bool     `json:"ok"`
		Result []update `json:"result"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal updates: %w", err)
	}

	return result.Result, nil
}

func (b *Bot) answerCallback(ctx context.Context, callbackID, text string) {
	params := url.Values{
		"callback_query_id": {callbackID},
		"text":              {text},
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		b.apiURL("answerCallbackQuery"),
		strings.NewReader(params.Encode()),
	)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := b.client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// --- Telegram data types (minimal) ---

type update struct {
	UpdateID      int            `json:"update_id"`
	CallbackQuery *callbackQuery `json:"callback_query,omitempty"`
}

type callbackQuery struct {
	ID   string `json:"id"`
	Data string `json:"data"`
	From struct {
		ID       int    `json:"id"`
		Username string `json:"username"`
	} `json:"from"`
	Message struct {
		MessageID int `json:"message_id"`
		Chat      struct {
			ID int64 `json:"id"`
		} `json:"chat"`
	} `json:"message"`
}

// --- Formatting ---

func formatFinding(f *models.Finding) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("*[BB-Hunter] Новая находка*\n\n"))
	sb.WriteString(fmt.Sprintf("*ID:* `%s`\n", f.ID))
	sb.WriteString(fmt.Sprintf("*URL:* `%s`\n", f.URL))
	sb.WriteString(fmt.Sprintf("*Метод:* %s\n", f.Method))

	if f.VulnClass != "" {
		sb.WriteString(fmt.Sprintf("*Класс:* %s\n", f.VulnClass))
	}
	if f.Severity != "" {
		sb.WriteString(fmt.Sprintf("*Severity:* %s\n", f.Severity))
	}
	if f.Confidence > 0 {
		sb.WriteString(fmt.Sprintf("*Confidence:* %.0f%%\n", f.Confidence*100))
	}
	if f.Hypothesis != "" {
		sb.WriteString(fmt.Sprintf("\n*Гипотеза:*\n%s\n", f.Hypothesis))
	}
	if f.NucleiTemplateID != "" {
		sb.WriteString(fmt.Sprintf("\n*Template:* `%s`\n", f.NucleiTemplateID))
	}

	// Truncate report if too long for Telegram (4096 char limit)
	if f.ReportMarkdown != "" {
		report := f.ReportMarkdown
		if len(report) > 2000 {
			report = report[:2000] + "\n\n_(отчёт обрезан)_"
		}
		sb.WriteString(fmt.Sprintf("\n--- Отчёт ---\n%s\n", report))
	}

	return sb.String()
}

// inlineKeyboard builds the approve/reject inline keyboard markup.
func inlineKeyboard(findingID string) map[string]any {
	return map[string]any{
		"inline_keyboard": [][]map[string]string{
			{
				{"text": "Approve", "callback_data": "approve:" + findingID},
				{"text": "Reject", "callback_data": "reject:" + findingID},
			},
		},
	}
}
