package audit

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/db"
	"github.com/ggwpgoend/bb-hunter/internal/models"
)

func newTestLogger(t *testing.T) (*Logger, *db.Writer) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "audit_test.db")
	w, err := db.NewWriter(dbPath, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	w.Start()

	l, err := NewLogger(w)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { w.Close() })
	return l, w
}

func TestLogger_SingleEntry(t *testing.T) {
	l, _ := newTestLogger(t)
	ctx := context.Background()

	err := l.Log(ctx, models.AuditScanStarted, "scanner", map[string]string{"program": "test"})
	if err != nil {
		t.Fatal(err)
	}

	// Wait for DB flush
	time.Sleep(700 * time.Millisecond)

	count, err := l.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected 1 verified entry, got %d", count)
	}
}

func TestLogger_ChainIntegrity(t *testing.T) {
	l, _ := newTestLogger(t)
	ctx := context.Background()

	// Write 10 entries
	for i := 0; i < 10; i++ {
		err := l.Log(ctx, models.AuditFindingCreated, "scanner", map[string]int{"index": i})
		if err != nil {
			t.Fatal(err)
		}
	}

	time.Sleep(700 * time.Millisecond)

	count, err := l.Verify()
	if err != nil {
		t.Fatalf("chain verification failed: %v", err)
	}
	if count != 10 {
		t.Errorf("expected 10 verified entries, got %d", count)
	}
}

func TestLogger_TamperDetection(t *testing.T) {
	l, w := newTestLogger(t)
	ctx := context.Background()

	// Write 5 entries
	for i := 0; i < 5; i++ {
		l.Log(ctx, models.AuditFindingCreated, "scanner", map[string]int{"i": i})
	}
	time.Sleep(700 * time.Millisecond)

	// Tamper with entry 3 by modifying its details
	_, err := w.GetDB().Exec("UPDATE audit_log SET details = '{\"tampered\":true}' WHERE seq = 3")
	if err != nil {
		t.Fatal(err)
	}

	// Verify should detect tampering
	_, err = l.Verify()
	if err == nil {
		t.Error("expected tamper detection error, got nil")
	}
}

func TestLogger_Resume(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "resume_test.db")

	// Session 1: write 3 entries
	w1, err := db.NewWriter(dbPath, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	w1.Start()

	l1, err := NewLogger(w1)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		l1.Log(ctx, models.AuditScanStarted, "test", map[string]int{"i": i})
	}
	time.Sleep(700 * time.Millisecond)
	w1.Close()

	// Session 2: resume and write 2 more
	w2, err := db.NewWriter(dbPath, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	w2.Start()
	defer w2.Close()

	l2, err := NewLogger(w2)
	if err != nil {
		t.Fatal(err)
	}

	for i := 3; i < 5; i++ {
		l2.Log(ctx, models.AuditScanFinished, "test", map[string]int{"i": i})
	}
	time.Sleep(700 * time.Millisecond)

	// Verify entire chain (5 entries)
	count, err := l2.Verify()
	if err != nil {
		t.Fatalf("chain verification after resume failed: %v", err)
	}
	if count != 5 {
		t.Errorf("expected 5 entries after resume, got %d", count)
	}
}
