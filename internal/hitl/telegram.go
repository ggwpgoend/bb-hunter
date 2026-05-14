// Package hitl implements the Human-In-The-Loop Telegram bot.
// Sends vulnerability reports to a Telegram chat for approve/reject decisions.
package hitl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/models"
)

const (
	telegramAPI    = "https://api.telegram.org/bot"
	maxMessageLen  = 4096 // Telegram message limit
	pollTimeout    = 30   // long-polling timeout seconds
	maxReportChunk = 3500 // leave room for header in message
)

// Decision represents a human decision on a finding.
type Decision struct {
	FindingID string
	Action    string // "approve" or "reject"
	Reason    string
	DecidedAt time.Time
}

// Bot is the Telegram HITL bot.
type Bot struct {
	token    string
	chatID   int64 // authorized chat ID (set on first /start)
	client   *http.Client
	log      *slog.Logger
	mu       sync.Mutex
	pending  map[string]*models.Finding // findingID → Finding awaiting decision
	decisions chan Decision
	offset   int // Telegram update offset
}

// NewBot creates a new Telegram HITL bot.
func NewBot(token string, logger *slog.Logger) *Bot {
	if logger == nil {
		logger = slog.Default()
	}
	return &Bot{
		token:    token,
		client:   &http.Client{Timeout: time.Duration(pollTimeout+10) * time.Second},
		log:      logger,
		pending:  make(map[string]*models.Finding),
		decisions: make(chan Decision, 64),
	}
}

// SetChatID sets the authorized chat ID (for testing or pre-configuration).
func (b *Bot) SetChatID(chatID int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.chatID = chatID
}

// Decisions returns the channel of human decisions.
func (b *Bot) Decisions() <-chan Decision {
	return b.decisions
}

// SendFinding sends a finding report to the Telegram chat for review.
// Returns error if no chat ID is set (bot hasn't received /start yet).
func (b *Bot) SendFinding(ctx context.Context, finding *models.Finding) error {
	b.mu.Lock()
	chatID := b.chatID
	b.mu.Unlock()

	if chatID == 0 {
		return fmt.Errorf("hitl: no chat ID — send /start to the bot first")
	}

	// Format the message
	msg := formatFindingMessage(finding)

	// Split long messages
	chunks := splitMessage(msg)
	for i, chunk := range chunks {
		if i == len(chunks)-1 {
			// Last chunk gets inline keyboard
			if err := b.sendMessageWithKeyboard(ctx, chatID, chunk, finding.ID); err != nil {
				return err
			}
		} else {
			if err := b.sendMessage(ctx, chatID, chunk); err != nil {
				return err
			}
		}
	}

	b.mu.Lock()
	b.pending[finding.ID] = finding
	b.mu.Unlock()

	b.log.Info("hitl: sent finding for review",
		"finding_id", finding.ID,
		"vuln_class", finding.VulnClass,
		"chat_id", chatID,
	)

	return nil
}

// PollUpdates starts long-polling for Telegram updates.
// Blocks until context is cancelled.
func (b *Bot) PollUpdates(ctx context.Context) error {
	b.log.Info("hitl: starting Telegram long-polling")
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		updates, err := b.getUpdates(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			b.log.Warn("hitl: poll error, retrying", "error", err)
			select {
			case <-time.After(5 * time.Second):
			case <-ctx.Done():
				return ctx.Err()
			}
			continue
		}

		for _, update := range updates {
			b.handleUpdate(ctx, update)
			if update.UpdateID >= b.offset {
				b.offset = update.UpdateID + 1
			}
		}
	}
}

// --- Telegram API types ---

type tgUpdate struct {
	UpdateID      int            `json:"update_id"`
	Message       *tgMessage     `json:"message,omitempty"`
	CallbackQuery *tgCallback    `json:"callback_query,omitempty"`
}

type tgMessage struct {
	MessageID int    `json:"message_id"`
	Chat      tgChat `json:"chat"`
	Text      string `json:"text"`
}

type tgChat struct {
	ID int64 `json:"id"`
}

type tgCallback struct {
	ID      string     `json:"id"`
	Message *tgMessage `json:"message,omitempty"`
	Data    string     `json:"data"`
}

type tgResponse struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result"`
	Desc   string          `json:"description,omitempty"`
}

// --- Internal methods ---

func (b *Bot) handleUpdate(ctx context.Context, update tgUpdate) {
	// Handle /start command
	if update.Message != nil && strings.HasPrefix(update.Message.Text, "/start") {
		b.mu.Lock()
		b.chatID = update.Message.Chat.ID
		b.mu.Unlock()
		b.log.Info("hitl: chat registered", "chat_id", update.Message.Chat.ID)
		b.sendMessage(ctx, update.Message.Chat.ID, "BB-Hunter HITL бот активирован.\n\nЯ буду отправлять сюда находки для проверки. Используй кнопки Approve/Reject для принятия решения.")
		return
	}

	// Handle /status command
	if update.Message != nil && strings.HasPrefix(update.Message.Text, "/status") {
		b.mu.Lock()
		pendingCount := len(b.pending)
		b.mu.Unlock()
		b.sendMessage(ctx, update.Message.Chat.ID, fmt.Sprintf("Ожидают решения: %d находок", pendingCount))
		return
	}

	// Handle callback (approve/reject buttons)
	if update.CallbackQuery != nil {
		b.handleCallback(ctx, update.CallbackQuery)
		return
	}
}

func (b *Bot) handleCallback(ctx context.Context, cb *tgCallback) {
	// Parse callback data: "approve:findingID" or "reject:findingID"
	parts := strings.SplitN(cb.Data, ":", 2)
	if len(parts) != 2 {
		b.answerCallback(ctx, cb.ID, "Неизвестная команда")
		return
	}

	action := parts[0]
	findingID := parts[1]

	if action != "approve" && action != "reject" {
		b.answerCallback(ctx, cb.ID, "Неизвестное действие")
		return
	}

	b.mu.Lock()
	_, exists := b.pending[findingID]
	if exists {
		delete(b.pending, findingID)
	}
	b.mu.Unlock()

	if !exists {
		b.answerCallback(ctx, cb.ID, "Находка не найдена или уже обработана")
		return
	}

	decision := Decision{
		FindingID: findingID,
		Action:    action,
		DecidedAt: time.Now().UTC(),
	}

	select {
	case b.decisions <- decision:
	default:
		b.log.Warn("hitl: decision channel full, dropping", "finding_id", findingID)
	}

	// Respond
	var emoji, label string
	if action == "approve" {
		emoji = "+"
		label = "APPROVED"
	} else {
		emoji = "-"
		label = "REJECTED"
	}

	b.answerCallback(ctx, cb.ID, fmt.Sprintf("%s %s", emoji, label))

	if cb.Message != nil {
		b.sendMessage(ctx, cb.Message.Chat.ID,
			fmt.Sprintf("[%s] %s: %s", emoji, label, findingID))
	}

	b.log.Info("hitl: decision received",
		"finding_id", findingID,
		"action", action,
	)
}

func (b *Bot) getUpdates(ctx context.Context) ([]tgUpdate, error) {
	url := fmt.Sprintf("%s%s/getUpdates?offset=%d&timeout=%d",
		telegramAPI, b.token, b.offset, pollTimeout)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var tgResp tgResponse
	if err := json.Unmarshal(body, &tgResp); err != nil {
		return nil, fmt.Errorf("hitl: parse response: %w", err)
	}

	if !tgResp.OK {
		return nil, fmt.Errorf("hitl: telegram error: %s", tgResp.Desc)
	}

	var updates []tgUpdate
	if err := json.Unmarshal(tgResp.Result, &updates); err != nil {
		return nil, fmt.Errorf("hitl: parse updates: %w", err)
	}

	return updates, nil
}

func (b *Bot) sendMessage(ctx context.Context, chatID int64, text string) error {
	url := fmt.Sprintf("%s%s/sendMessage", telegramAPI, b.token)

	payload := map[string]any{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "Markdown",
	}

	return b.postJSON(ctx, url, payload)
}

func (b *Bot) sendMessageWithKeyboard(ctx context.Context, chatID int64, text string, findingID string) error {
	url := fmt.Sprintf("%s%s/sendMessage", telegramAPI, b.token)

	keyboard := map[string]any{
		"inline_keyboard": [][]map[string]string{
			{
				{"text": "Approve", "callback_data": "approve:" + findingID},
				{"text": "Reject", "callback_data": "reject:" + findingID},
			},
		},
	}

	payload := map[string]any{
		"chat_id":      chatID,
		"text":         text,
		"parse_mode":   "Markdown",
		"reply_markup": keyboard,
	}

	return b.postJSON(ctx, url, payload)
}

func (b *Bot) answerCallback(ctx context.Context, callbackID string, text string) {
	url := fmt.Sprintf("%s%s/answerCallbackQuery", telegramAPI, b.token)
	payload := map[string]any{
		"callback_query_id": callbackID,
		"text":              text,
	}
	b.postJSON(ctx, url, payload)
}

func (b *Bot) postJSON(ctx context.Context, url string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var tgResp tgResponse
	if err := json.Unmarshal(body, &tgResp); err != nil {
		return fmt.Errorf("hitl: parse response: %w", err)
	}

	if !tgResp.OK {
		return fmt.Errorf("hitl: telegram error: %s", tgResp.Desc)
	}

	return nil
}

// --- Message formatting ---

func formatFindingMessage(f *models.Finding) string {
	var sb strings.Builder

	// Header
	severityEmoji := map[models.Severity]string{
		models.SeverityInfo:     "INFO",
		models.SeverityLow:      "LOW",
		models.SeverityMedium:   "MED",
		models.SeverityHigh:     "HIGH",
		models.SeverityCritical: "CRIT",
	}

	sev := severityEmoji[f.Severity]
	if sev == "" {
		sev = string(f.Severity)
	}

	sb.WriteString(fmt.Sprintf("*[%s] %s*\n", sev, strings.ToUpper(string(f.VulnClass))))
	sb.WriteString(fmt.Sprintf("ID: `%s`\n", f.ID))
	sb.WriteString(fmt.Sprintf("Confidence: %.0f%%\n\n", f.Confidence*100))

	// Location
	sb.WriteString(fmt.Sprintf("URL: `%s`\n", f.URL))
	sb.WriteString(fmt.Sprintf("Method: %s\n", f.Method))
	if f.NucleiTemplateID != "" {
		sb.WriteString(fmt.Sprintf("Template: `%s`\n", f.NucleiTemplateID))
	}
	sb.WriteString("\n")

	// Hypothesis
	if f.Hypothesis != "" {
		sb.WriteString(fmt.Sprintf("*Hypothesis:*\n%s\n\n", f.Hypothesis))
	}

	// Report (truncated)
	if f.ReportMarkdown != "" {
		report := f.ReportMarkdown
		if len(report) > maxReportChunk {
			report = report[:maxReportChunk] + "\n\n_...отчёт обрезан..._"
		}
		sb.WriteString("*Report:*\n")
		sb.WriteString(report)
	}

	return sb.String()
}

func splitMessage(msg string) []string {
	if len(msg) <= maxMessageLen {
		return []string{msg}
	}

	var chunks []string
	for len(msg) > 0 {
		end := maxMessageLen
		if end > len(msg) {
			end = len(msg)
		}

		// Try to split at newline
		if end < len(msg) {
			lastNewline := strings.LastIndex(msg[:end], "\n")
			if lastNewline > maxMessageLen/2 {
				end = lastNewline + 1
			}
		}

		chunks = append(chunks, msg[:end])
		msg = msg[end:]
	}

	return chunks
}
