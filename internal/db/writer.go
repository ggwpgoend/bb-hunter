// Package db implements the DBWriter — a single-goroutine SQLite writer
// with bounded channel, batch commits, and WAL mode.
//
// Design decisions (from v4 architecture):
//   - Single writer goroutine: eliminates SQLite lock contention
//   - Bounded channel: backpressure when write rate exceeds capacity
//   - Batch commits: groups multiple writes into a single transaction
//   - WAL mode: allows concurrent readers during writes
//   - Priority channel: audit log entries are written before findings
package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/models"
	_ "modernc.org/sqlite"
)

const (
	defaultChannelSize = 1024
	defaultBatchSize   = 50
	defaultFlushInterval = 500 * time.Millisecond
)

// WriteOp represents a pending write operation.
type WriteOp struct {
	Type string // "finding", "scan_run", "audit"
	Data any
}

// Writer is the single-goroutine database writer.
type Writer struct {
	db     *sql.DB
	ch     chan WriteOp
	priCh  chan WriteOp // priority channel (audit entries)
	done   chan struct{}
	wg     sync.WaitGroup
	logger *slog.Logger
}

// NewWriter creates a new DBWriter connected to the given SQLite path.
func NewWriter(dbPath string, logger *slog.Logger) (*Writer, error) {
	if logger == nil {
		logger = slog.Default()
	}

	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)&_pragma=synchronous(normal)")
	if err != nil {
		return nil, fmt.Errorf("db: open failed: %w", err)
	}

	// Only 1 connection for writer (single-writer pattern)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	w := &Writer{
		db:     db,
		ch:     make(chan WriteOp, defaultChannelSize),
		priCh:  make(chan WriteOp, 256),
		done:   make(chan struct{}),
		logger: logger,
	}

	if err := w.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("db: migration failed: %w", err)
	}

	return w, nil
}

// Start begins the writer goroutine. Must be called before sending writes.
func (w *Writer) Start() {
	w.wg.Add(1)
	go w.loop()
}

// Close flushes pending writes and closes the database.
func (w *Writer) Close() error {
	close(w.done)
	w.wg.Wait()
	return w.db.Close()
}

// WriteFinding queues a finding for writing. Blocks if channel is full.
func (w *Writer) WriteFinding(ctx context.Context, f *models.Finding) error {
	select {
	case w.ch <- WriteOp{Type: "finding", Data: f}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-w.done:
		return fmt.Errorf("db: writer closed")
	}
}

// WriteScanRun queues a scan run for writing.
func (w *Writer) WriteScanRun(ctx context.Context, sr *models.ScanRun) error {
	select {
	case w.ch <- WriteOp{Type: "scan_run", Data: sr}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-w.done:
		return fmt.Errorf("db: writer closed")
	}
}

// WriteAudit queues an audit entry with priority.
func (w *Writer) WriteAudit(ctx context.Context, entry *models.AuditEntry) error {
	select {
	case w.priCh <- WriteOp{Type: "audit", Data: entry}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-w.done:
		return fmt.Errorf("db: writer closed")
	}
}

// GetDB returns the underlying database for read operations.
func (w *Writer) GetDB() *sql.DB {
	return w.db
}

// loop is the single-goroutine write loop.
func (w *Writer) loop() {
	defer w.wg.Done()

	batch := make([]WriteOp, 0, defaultBatchSize)
	ticker := time.NewTicker(defaultFlushInterval)
	defer ticker.Stop()

	for {
		// Priority: drain audit channel first
		select {
		case op := <-w.priCh:
			batch = append(batch, op)
			if len(batch) >= defaultBatchSize {
				w.flush(batch)
				batch = batch[:0]
			}
			continue
		default:
		}

		select {
		case op := <-w.priCh:
			batch = append(batch, op)
		case op := <-w.ch:
			batch = append(batch, op)
		case <-ticker.C:
			if len(batch) > 0 {
				w.flush(batch)
				batch = batch[:0]
			}
		case <-w.done:
			// Drain remaining
			w.drainAndFlush(batch)
			return
		}

		if len(batch) >= defaultBatchSize {
			w.flush(batch)
			batch = batch[:0]
		}
	}
}

// drainAndFlush drains both channels and flushes everything.
func (w *Writer) drainAndFlush(batch []WriteOp) {
	for {
		select {
		case op := <-w.priCh:
			batch = append(batch, op)
		case op := <-w.ch:
			batch = append(batch, op)
		default:
			if len(batch) > 0 {
				w.flush(batch)
			}
			return
		}
	}
}

// flush writes a batch of operations in a single transaction.
func (w *Writer) flush(ops []WriteOp) {
	tx, err := w.db.Begin()
	if err != nil {
		w.logger.Error("db: begin tx failed", "error", err)
		return
	}

	for _, op := range ops {
		var execErr error
		switch op.Type {
		case "finding":
			f, ok := op.Data.(*models.Finding)
			if !ok {
				w.logger.Error("db: invalid data type for finding")
				continue
			}
			execErr = w.insertFinding(tx, f)
		case "scan_run":
			sr, ok := op.Data.(*models.ScanRun)
			if !ok {
				w.logger.Error("db: invalid data type for scan_run")
				continue
			}
			execErr = w.insertScanRun(tx, sr)
		case "audit":
			e, ok := op.Data.(*models.AuditEntry)
			if !ok {
				w.logger.Error("db: invalid data type for audit")
				continue
			}
			execErr = w.insertAudit(tx, e)
		default:
			w.logger.Warn("db: unknown op type", "type", op.Type)
		}
		if execErr != nil {
			w.logger.Error("db: write failed", "type", op.Type, "error", execErr)
		}
	}

	if err := tx.Commit(); err != nil {
		w.logger.Error("db: commit failed", "error", err)
		tx.Rollback()
	}
}

func (w *Writer) insertFinding(tx *sql.Tx, f *models.Finding) error {
	paramJSON, _ := json.Marshal(f.ParamNames)
	_, err := tx.Exec(`
		INSERT INTO findings (
			id, finding_key, created_at, updated_at,
			program_id, scan_run_id,
			url, method, host, path,
			nuclei_template_id, scanner_evidence, severity,
			vuln_class, hypothesis, confidence,
			status, report_markdown,
			hitl_decision, hitl_decided_at,
			param_names
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			updated_at = excluded.updated_at,
			vuln_class = excluded.vuln_class,
			hypothesis = excluded.hypothesis,
			confidence = excluded.confidence,
			status = excluded.status,
			report_markdown = excluded.report_markdown,
			hitl_decision = excluded.hitl_decision,
			hitl_decided_at = excluded.hitl_decided_at
	`,
		f.ID, f.FindingKey, f.CreatedAt, f.UpdatedAt,
		f.ProgramID, f.ScanRunID,
		f.URL, f.Method, f.Host, f.Path,
		f.NucleiTemplateID, f.ScannerEvidence, f.Severity,
		f.VulnClass, f.Hypothesis, f.Confidence,
		f.Status, f.ReportMarkdown,
		f.HITLDecision, f.HITLDecidedAt,
		string(paramJSON),
	)
	return err
}

func (w *Writer) insertScanRun(tx *sql.Tx, sr *models.ScanRun) error {
	errorsJSON, _ := json.Marshal(sr.Errors)
	_, err := tx.Exec(`
		INSERT INTO scan_runs (
			id, program_id, started_at, finished_at,
			run_type,
			hosts_scanned, urls_crawled,
			findings_total, findings_new, findings_dup,
			errors, has_new_findings
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			finished_at = excluded.finished_at,
			hosts_scanned = excluded.hosts_scanned,
			urls_crawled = excluded.urls_crawled,
			findings_total = excluded.findings_total,
			findings_new = excluded.findings_new,
			findings_dup = excluded.findings_dup,
			errors = excluded.errors,
			has_new_findings = excluded.has_new_findings
	`,
		sr.ID, sr.ProgramID, sr.StartedAt, sr.FinishedAt,
		sr.RunType,
		sr.HostsScanned, sr.URLsCrawled,
		sr.FindingsTotal, sr.FindingsNew, sr.FindingsDup,
		string(errorsJSON), sr.HasNewFindings,
	)
	return err
}

func (w *Writer) insertAudit(tx *sql.Tx, e *models.AuditEntry) error {
	_, err := tx.Exec(`
		INSERT INTO audit_log (seq, timestamp, prev_hash, hash, action, actor, details)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`,
		e.Seq, e.Timestamp, e.PrevHash, e.Hash, e.Action, e.Actor, string(e.Details),
	)
	return err
}

// migrate creates tables if they don't exist.
func (w *Writer) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS findings (
			id TEXT PRIMARY KEY,
			finding_key TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			program_id TEXT NOT NULL,
			scan_run_id TEXT NOT NULL,
			url TEXT NOT NULL,
			method TEXT NOT NULL DEFAULT 'GET',
			host TEXT NOT NULL,
			path TEXT NOT NULL,
			nuclei_template_id TEXT,
			scanner_evidence TEXT,
			severity TEXT NOT NULL DEFAULT 'info',
			vuln_class TEXT,
			hypothesis TEXT,
			confidence REAL DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'new',
			report_markdown TEXT,
			hitl_decision TEXT,
			hitl_decided_at DATETIME,
			param_names TEXT DEFAULT '[]'
		)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_key ON findings(finding_key)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_program ON findings(program_id)`,

		`CREATE TABLE IF NOT EXISTS scan_runs (
			id TEXT PRIMARY KEY,
			program_id TEXT NOT NULL,
			started_at DATETIME NOT NULL,
			finished_at DATETIME,
			run_type TEXT NOT NULL DEFAULT 'full',
			hosts_scanned INTEGER DEFAULT 0,
			urls_crawled INTEGER DEFAULT 0,
			findings_total INTEGER DEFAULT 0,
			findings_new INTEGER DEFAULT 0,
			findings_dup INTEGER DEFAULT 0,
			errors TEXT DEFAULT '[]',
			has_new_findings BOOLEAN DEFAULT FALSE
		)`,

		`CREATE TABLE IF NOT EXISTS audit_log (
			seq INTEGER PRIMARY KEY,
			timestamp DATETIME NOT NULL,
			prev_hash TEXT NOT NULL,
			hash TEXT NOT NULL,
			action TEXT NOT NULL,
			actor TEXT NOT NULL,
			details TEXT DEFAULT '{}'
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)`,
	}

	for _, stmt := range stmts {
		if _, err := w.db.Exec(stmt); err != nil {
			return fmt.Errorf("migration failed: %w\nSQL: %s", err, stmt)
		}
	}

	return nil
}
