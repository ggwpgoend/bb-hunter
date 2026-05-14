// Package audit implements a tamper-evident hash-chain audit logger.
// Every entry contains the hash of the previous entry, so any
// modification or deletion is detectable.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/db"
	"github.com/ggwpgoend/bb-hunter/internal/models"
)

// Logger writes audit entries with hash-chain integrity.
type Logger struct {
	writer   *db.Writer
	mu       sync.Mutex
	seq      uint64
	prevHash string
}

// NewLogger creates a new audit logger, resuming from the last entry in the DB.
func NewLogger(writer *db.Writer) (*Logger, error) {
	l := &Logger{
		writer:   writer,
		seq:      0,
		prevHash: models.GenesisHash,
	}

	// Resume from last entry if DB has data
	var lastSeq uint64
	var lastHash string
	err := writer.GetDB().QueryRow("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").Scan(&lastSeq, &lastHash)
	if err == nil {
		l.seq = lastSeq
		l.prevHash = lastHash
	}
	// If no rows, that's fine — start from genesis

	return l, nil
}

// Log writes an audit entry with the given action and details.
// Thread-safe — uses a mutex to guarantee hash chain ordering.
func (l *Logger) Log(ctx context.Context, action models.AuditAction, actor string, details any) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("audit: cannot marshal details: %w", err)
	}

	l.seq++
	now := time.Now().UTC()

	hash := models.ComputeEntryHash(l.seq, now, l.prevHash, action, actor, detailsJSON)

	entry := &models.AuditEntry{
		Seq:       l.seq,
		Timestamp: now,
		PrevHash:  l.prevHash,
		Hash:      hash,
		Action:    action,
		Actor:     actor,
		Details:   detailsJSON,
	}

	l.prevHash = hash

	return l.writer.WriteAudit(ctx, entry)
}

// Verify checks the integrity of the entire audit log.
// Returns the number of entries verified and any integrity error.
func (l *Logger) Verify() (int, error) {
	rows, err := l.writer.GetDB().Query("SELECT seq, timestamp, prev_hash, hash, action, actor, details FROM audit_log ORDER BY seq ASC")
	if err != nil {
		return 0, fmt.Errorf("audit: query failed: %w", err)
	}
	defer rows.Close()

	expectedPrev := models.GenesisHash
	count := 0

	for rows.Next() {
		var entry models.AuditEntry
		var detailsStr string
		if err := rows.Scan(&entry.Seq, &entry.Timestamp, &entry.PrevHash, &entry.Hash, &entry.Action, &entry.Actor, &detailsStr); err != nil {
			return count, fmt.Errorf("audit: scan failed at entry %d: %w", count+1, err)
		}
		entry.Details = json.RawMessage(detailsStr)

		// Check chain linkage
		if entry.PrevHash != expectedPrev {
			return count, fmt.Errorf("audit: chain broken at seq %d: expected prev_hash %s, got %s", entry.Seq, expectedPrev, entry.PrevHash)
		}

		// Recompute hash
		computed := models.ComputeEntryHash(entry.Seq, entry.Timestamp, entry.PrevHash, entry.Action, entry.Actor, entry.Details)
		if entry.Hash != computed {
			return count, fmt.Errorf("audit: tampered entry at seq %d: stored hash %s != computed %s", entry.Seq, entry.Hash, computed)
		}

		expectedPrev = entry.Hash
		count++
	}

	return count, rows.Err()
}
