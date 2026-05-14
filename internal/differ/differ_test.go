package differ

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/models"
	_ "modernc.org/sqlite"
)

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:?_pragma=journal_mode(wal)")
	if err != nil {
		t.Fatal(err)
	}

	stmts := []string{
		`CREATE TABLE findings (
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
		`CREATE TABLE scan_runs (
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
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}

	return db
}

func insertFinding(t *testing.T, db *sql.DB, id, key, scanRunID string, severity models.Severity, vulnClass models.VulnClass) {
	t.Helper()
	now := time.Now()
	_, err := db.Exec(`
		INSERT INTO findings (id, finding_key, created_at, updated_at, program_id, scan_run_id,
			url, method, host, path, severity, vuln_class, status)
		VALUES (?, ?, ?, ?, 'prog1', ?, 'https://example.com/test', 'GET', 'example.com', '/test', ?, ?, 'new')
	`, id, key, now, now, scanRunID, severity, vulnClass)
	if err != nil {
		t.Fatal(err)
	}
}

func insertScanRun(t *testing.T, db *sql.DB, id, programID string, startedAt time.Time) {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO scan_runs (id, program_id, started_at, run_type)
		VALUES (?, ?, ?, 'full')
	`, id, programID, startedAt)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDiffFirstRun(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	insertFinding(t, db, "f1", "key1", "run1", models.SeverityHigh, models.VulnXSS)
	insertFinding(t, db, "f2", "key2", "run1", models.SeverityMedium, models.VulnSQLi)

	d := New(db)
	result, err := d.Diff("", "run1")
	if err != nil {
		t.Fatal(err)
	}

	if result.NewCount != 2 {
		t.Errorf("expected 2 new, got %d", result.NewCount)
	}
	if result.GoneCount != 0 {
		t.Errorf("expected 0 gone, got %d", result.GoneCount)
	}
	if len(result.Entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(result.Entries))
	}
	for _, e := range result.Entries {
		if e.ChangeType != ChangeNew {
			t.Errorf("expected new, got %s", e.ChangeType)
		}
		if e.Current == nil {
			t.Error("new entry should have Current")
		}
	}
}

func TestDiffNewAndGone(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Previous run: key1, key2
	insertFinding(t, db, "f1", "key1", "run1", models.SeverityHigh, models.VulnXSS)
	insertFinding(t, db, "f2", "key2", "run1", models.SeverityMedium, models.VulnSQLi)

	// Current run: key2, key3 (key1 gone, key3 new)
	insertFinding(t, db, "f3", "key2", "run2", models.SeverityMedium, models.VulnSQLi)
	insertFinding(t, db, "f4", "key3", "run2", models.SeverityLow, models.VulnSSRF)

	d := New(db)
	result, err := d.Diff("run1", "run2")
	if err != nil {
		t.Fatal(err)
	}

	if result.NewCount != 1 {
		t.Errorf("expected 1 new, got %d", result.NewCount)
	}
	if result.GoneCount != 1 {
		t.Errorf("expected 1 gone, got %d", result.GoneCount)
	}
	if result.UnchangedCount != 1 {
		t.Errorf("expected 1 unchanged, got %d", result.UnchangedCount)
	}

	// Verify entries
	counts := map[ChangeType]int{}
	for _, e := range result.Entries {
		counts[e.ChangeType]++
		switch e.ChangeType {
		case ChangeNew:
			if e.FindingKey != "key3" {
				t.Errorf("new finding should be key3, got %s", e.FindingKey)
			}
		case ChangeGone:
			if e.FindingKey != "key1" {
				t.Errorf("gone finding should be key1, got %s", e.FindingKey)
			}
			if e.Previous == nil {
				t.Error("gone entry should have Previous")
			}
			if e.Current != nil {
				t.Error("gone entry should NOT have Current")
			}
		}
	}
}

func TestDiffChanged(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Previous: key1 = high/xss
	insertFinding(t, db, "f1", "key1", "run1", models.SeverityHigh, models.VulnXSS)

	// Current: key1 = critical/xss (severity changed)
	insertFinding(t, db, "f2", "key1", "run2", models.SeverityCritical, models.VulnXSS)

	d := New(db)
	result, err := d.Diff("run1", "run2")
	if err != nil {
		t.Fatal(err)
	}

	if result.ChangedCount != 1 {
		t.Errorf("expected 1 changed, got %d", result.ChangedCount)
	}

	entry := result.Entries[0]
	if entry.ChangeType != ChangeChanged {
		t.Errorf("expected changed, got %s", entry.ChangeType)
	}
	if entry.Previous.Severity != models.SeverityHigh {
		t.Errorf("previous severity should be high, got %s", entry.Previous.Severity)
	}
	if entry.Current.Severity != models.SeverityCritical {
		t.Errorf("current severity should be critical, got %s", entry.Current.Severity)
	}
}

func TestDiffUnchanged(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	insertFinding(t, db, "f1", "key1", "run1", models.SeverityHigh, models.VulnXSS)
	insertFinding(t, db, "f2", "key1", "run2", models.SeverityHigh, models.VulnXSS)

	d := New(db)
	result, err := d.Diff("run1", "run2")
	if err != nil {
		t.Fatal(err)
	}

	if result.UnchangedCount != 1 {
		t.Errorf("expected 1 unchanged, got %d", result.UnchangedCount)
	}
	if result.NewCount != 0 || result.GoneCount != 0 || result.ChangedCount != 0 {
		t.Errorf("expected only unchanged, got new=%d gone=%d changed=%d",
			result.NewCount, result.GoneCount, result.ChangedCount)
	}
}

func TestDiffEmpty(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	d := New(db)
	result, err := d.Diff("run1", "run2")
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Entries) != 0 {
		t.Errorf("expected 0 entries for empty runs, got %d", len(result.Entries))
	}
}

func TestLatestRunID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	now := time.Now()
	insertScanRun(t, db, "run1", "prog1", now.Add(-2*time.Hour))
	insertScanRun(t, db, "run2", "prog1", now.Add(-1*time.Hour))
	insertScanRun(t, db, "run3", "prog1", now)

	d := New(db)

	// Excluding run3 should return run2
	runID, err := d.LatestRunID("prog1", "run3")
	if err != nil {
		t.Fatal(err)
	}
	if runID != "run2" {
		t.Errorf("expected run2, got %s", runID)
	}

	// Excluding run1 should return run3
	runID, err = d.LatestRunID("prog1", "run1")
	if err != nil {
		t.Fatal(err)
	}
	if runID != "run3" {
		t.Errorf("expected run3, got %s", runID)
	}

	// No previous for unknown program
	runID, err = d.LatestRunID("unknown", "run1")
	if err != nil {
		t.Fatal(err)
	}
	if runID != "" {
		t.Errorf("expected empty, got %s", runID)
	}
}

func TestDiffClassChange(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Previous: key1 = high/xss
	insertFinding(t, db, "f1", "key1", "run1", models.SeverityHigh, models.VulnXSS)
	// Current: key1 = high/sqli (class changed, severity same)
	insertFinding(t, db, "f2", "key1", "run2", models.SeverityHigh, models.VulnSQLi)

	d := New(db)
	result, err := d.Diff("run1", "run2")
	if err != nil {
		t.Fatal(err)
	}

	if result.ChangedCount != 1 {
		t.Errorf("expected 1 changed (class change), got %d", result.ChangedCount)
	}
}

func TestDiffLargeSet(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// 100 findings in run1, 100 in run2
	// 50 same, 25 new in run2, 25 gone from run1, 25 changed
	for i := 0; i < 50; i++ {
		key := fmt.Sprintf("same-%d", i)
		insertFinding(t, db, fmt.Sprintf("r1-%d", i), key, "run1", models.SeverityHigh, models.VulnXSS)
		insertFinding(t, db, fmt.Sprintf("r2-%d", i), key, "run2", models.SeverityHigh, models.VulnXSS)
	}
	for i := 0; i < 25; i++ {
		insertFinding(t, db, fmt.Sprintf("r1-gone-%d", i), fmt.Sprintf("gone-%d", i), "run1", models.SeverityHigh, models.VulnXSS)
	}
	for i := 0; i < 25; i++ {
		insertFinding(t, db, fmt.Sprintf("r2-new-%d", i), fmt.Sprintf("new-%d", i), "run2", models.SeverityMedium, models.VulnSQLi)
	}

	d := New(db)
	result, err := d.Diff("run1", "run2")
	if err != nil {
		t.Fatal(err)
	}

	if result.NewCount != 25 {
		t.Errorf("expected 25 new, got %d", result.NewCount)
	}
	if result.GoneCount != 25 {
		t.Errorf("expected 25 gone, got %d", result.GoneCount)
	}
	if result.UnchangedCount != 50 {
		t.Errorf("expected 50 unchanged, got %d", result.UnchangedCount)
	}
}
