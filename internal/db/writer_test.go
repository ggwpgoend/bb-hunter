package db

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/models"
)

func newTestWriter(t *testing.T) *Writer {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	w, err := NewWriter(dbPath, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	w.Start()
	t.Cleanup(func() { w.Close() })
	return w
}

func TestWriter_CreateAndMigrate(t *testing.T) {
	w := newTestWriter(t)

	// Verify tables exist
	var count int
	err := w.GetDB().QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('findings','scan_runs','audit_log')").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Errorf("expected 3 tables, got %d", count)
	}
}

func TestWriter_WriteFinding(t *testing.T) {
	w := newTestWriter(t)
	ctx := context.Background()

	now := time.Now()
	f := &models.Finding{
		ID:               "f-001",
		FindingKey:       models.ComputeFindingKey("GET", "https://example.com/api", "xss-reflected", []string{"q"}),
		CreatedAt:        now,
		UpdatedAt:        now,
		ProgramID:        "prog-1",
		ScanRunID:        "run-1",
		URL:              "https://example.com/api?q=test",
		Method:           "GET",
		Host:             "example.com",
		Path:             "/api",
		NucleiTemplateID: "xss-reflected",
		ScannerEvidence:  "reflected param q in response body",
		Severity:         models.SeverityMedium,
		Status:           models.StatusNew,
		ParamNames:       []string{"q"},
	}

	if err := w.WriteFinding(ctx, f); err != nil {
		t.Fatal(err)
	}

	// Wait for flush
	time.Sleep(700 * time.Millisecond)

	// Verify
	var id, status string
	err := w.GetDB().QueryRow("SELECT id, status FROM findings WHERE id = ?", "f-001").Scan(&id, &status)
	if err != nil {
		t.Fatal(err)
	}
	if status != string(models.StatusNew) {
		t.Errorf("status = %q, want %q", status, models.StatusNew)
	}
}

func TestWriter_WriteFinding_Upsert(t *testing.T) {
	w := newTestWriter(t)
	ctx := context.Background()

	now := time.Now()
	f := &models.Finding{
		ID:        "f-002",
		FindingKey: "key-002",
		CreatedAt: now,
		UpdatedAt: now,
		ProgramID: "prog-1",
		ScanRunID: "run-1",
		URL:       "https://example.com/",
		Method:    "GET",
		Host:      "example.com",
		Path:      "/",
		Severity:  models.SeverityLow,
		Status:    models.StatusNew,
	}

	w.WriteFinding(ctx, f)
	time.Sleep(700 * time.Millisecond)

	// Update status
	f.Status = models.StatusAnalyzed
	f.VulnClass = models.VulnXSS
	f.UpdatedAt = time.Now()

	w.WriteFinding(ctx, f)
	time.Sleep(700 * time.Millisecond)

	var status, vulnClass string
	err := w.GetDB().QueryRow("SELECT status, vuln_class FROM findings WHERE id = ?", "f-002").Scan(&status, &vulnClass)
	if err != nil {
		t.Fatal(err)
	}
	if status != string(models.StatusAnalyzed) {
		t.Errorf("status after upsert = %q, want %q", status, models.StatusAnalyzed)
	}
	if vulnClass != string(models.VulnXSS) {
		t.Errorf("vuln_class = %q, want %q", vulnClass, models.VulnXSS)
	}
}

func TestWriter_WriteAudit_Priority(t *testing.T) {
	w := newTestWriter(t)
	ctx := context.Background()

	entry := &models.AuditEntry{
		Seq:       1,
		Timestamp: time.Now(),
		PrevHash:  models.GenesisHash,
		Hash:      "testhash",
		Action:    models.AuditScanStarted,
		Actor:     "scanner",
		Details:   []byte(`{"program":"test"}`),
	}

	if err := w.WriteAudit(ctx, entry); err != nil {
		t.Fatal(err)
	}

	time.Sleep(700 * time.Millisecond)

	var seq int
	err := w.GetDB().QueryRow("SELECT seq FROM audit_log WHERE seq = 1").Scan(&seq)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 1 {
		t.Errorf("seq = %d, want 1", seq)
	}
}

func TestWriter_WriteScanRun(t *testing.T) {
	w := newTestWriter(t)
	ctx := context.Background()

	sr := &models.ScanRun{
		ID:             "run-001",
		ProgramID:      "prog-1",
		StartedAt:      time.Now(),
		RunType:        "full",
		HostsScanned:   42,
		URLsCrawled:    500,
		FindingsTotal:  10,
		FindingsNew:    3,
		FindingsDup:    7,
		HasNewFindings: true,
	}

	if err := w.WriteScanRun(ctx, sr); err != nil {
		t.Fatal(err)
	}

	time.Sleep(700 * time.Millisecond)

	var hosts int
	err := w.GetDB().QueryRow("SELECT hosts_scanned FROM scan_runs WHERE id = ?", "run-001").Scan(&hosts)
	if err != nil {
		t.Fatal(err)
	}
	if hosts != 42 {
		t.Errorf("hosts_scanned = %d, want 42", hosts)
	}
}

func TestWriter_BatchFlush(t *testing.T) {
	w := newTestWriter(t)
	ctx := context.Background()

	// Write many findings quickly — they should batch
	for i := 0; i < 100; i++ {
		now := time.Now()
		f := &models.Finding{
			ID:        fmt.Sprintf("batch-%03d", i),
			FindingKey: fmt.Sprintf("batchkey-%03d", i),
			CreatedAt: now,
			UpdatedAt: now,
			ProgramID: "prog-1",
			ScanRunID: "run-1",
			URL:       fmt.Sprintf("https://example.com/path/%d", i),
			Method:    "GET",
			Host:      "example.com",
			Path:      fmt.Sprintf("/path/%d", i),
			Severity:  models.SeverityInfo,
			Status:    models.StatusNew,
		}
		w.WriteFinding(ctx, f)
	}

	// Wait for flush
	time.Sleep(2 * time.Second)

	var count int
	w.GetDB().QueryRow("SELECT count(*) FROM findings WHERE id LIKE 'batch-%'").Scan(&count)
	if count != 100 {
		t.Errorf("expected 100 batch findings, got %d", count)
	}
}
