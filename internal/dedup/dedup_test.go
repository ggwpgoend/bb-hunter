package dedup

import (
	"database/sql"
	"testing"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/models"
	_ "modernc.org/sqlite"
)

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
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
		`CREATE INDEX idx_findings_key ON findings(finding_key)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("migrate: %v", err)
		}
	}

	return db
}

func insertTestFinding(t *testing.T, db *sql.DB, id, key, host, path, vulnClass, status string) {
	t.Helper()
	now := time.Now()
	_, err := db.Exec(`
		INSERT INTO findings (id, finding_key, created_at, updated_at, program_id, scan_run_id,
			url, method, host, path, severity, vuln_class, status)
		VALUES (?, ?, ?, ?, 'test', 'run-1', ?, 'GET', ?, ?, 'medium', ?, ?)`,
		id, key, now, now, "https://"+host+path, host, path, vulnClass, status,
	)
	if err != nil {
		t.Fatalf("insert finding: %v", err)
	}
}

func TestCheck_ExactKeyMatch(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert a previously approved finding
	insertTestFinding(t, db, "old-1", "key-abc", "example.com", "/api/users", "xss", "approved")

	checker := NewChecker(db, nil)
	f := &models.Finding{
		ID:         "new-1",
		FindingKey: "key-abc",
		Host:       "example.com",
		Path:       "/api/users",
		VulnClass:  models.VulnXSS,
	}

	result, err := checker.Check(f)
	if err != nil {
		t.Fatalf("check: %v", err)
	}

	if result.Verdict != VerdictConfirmed {
		t.Errorf("expected confirmed_duplicate, got %s", result.Verdict)
	}
	if result.Similarity != 1.0 {
		t.Errorf("expected similarity 1.0, got %f", result.Similarity)
	}
	if result.MatchedID != "old-1" {
		t.Errorf("expected matched_id old-1, got %s", result.MatchedID)
	}
}

func TestCheck_SimilarPath(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert a finding with similar path (different ID segment)
	insertTestFinding(t, db, "old-1", "key-xyz", "example.com", "/api/users/123/profile", "xss", "approved")

	checker := NewChecker(db, nil)
	f := &models.Finding{
		ID:        "new-1",
		FindingKey: "key-different",
		Host:      "example.com",
		Path:      "/api/users/456/profile",
		VulnClass: models.VulnXSS,
	}

	result, err := checker.Check(f)
	if err != nil {
		t.Fatalf("check: %v", err)
	}

	if result.Verdict != VerdictLikely {
		t.Errorf("expected likely_duplicate, got %s", result.Verdict)
	}
	if result.Similarity < 0.8 {
		t.Errorf("expected similarity >= 0.8, got %f", result.Similarity)
	}
}

func TestCheck_NewFinding(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert unrelated finding
	insertTestFinding(t, db, "old-1", "key-other", "other.com", "/different/path", "sqli", "approved")

	checker := NewChecker(db, nil)
	f := &models.Finding{
		ID:         "new-1",
		FindingKey: "key-brand-new",
		Host:       "example.com",
		Path:       "/api/users",
		VulnClass:  models.VulnXSS,
	}

	result, err := checker.Check(f)
	if err != nil {
		t.Fatalf("check: %v", err)
	}

	if result.Verdict != VerdictNew {
		t.Errorf("expected new, got %s", result.Verdict)
	}
}

func TestCheck_RejectedNotMatched(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert a previously rejected finding — should NOT match
	insertTestFinding(t, db, "old-1", "key-abc", "example.com", "/api/users", "xss", "rejected")

	checker := NewChecker(db, nil)
	f := &models.Finding{
		ID:         "new-1",
		FindingKey: "key-abc",
		Host:       "example.com",
		Path:       "/api/users",
		VulnClass:  models.VulnXSS,
	}

	result, err := checker.Check(f)
	if err != nil {
		t.Fatalf("check: %v", err)
	}

	if result.Verdict != VerdictNew {
		t.Errorf("rejected findings should not trigger dedup, got %s", result.Verdict)
	}
}

func TestCheck_DifferentVulnClass(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Same host+path but different vuln class — should not match as similar
	insertTestFinding(t, db, "old-1", "key-other", "example.com", "/api/users", "sqli", "approved")

	checker := NewChecker(db, nil)
	f := &models.Finding{
		ID:         "new-1",
		FindingKey: "key-new",
		Host:       "example.com",
		Path:       "/api/users",
		VulnClass:  models.VulnXSS,
	}

	result, err := checker.Check(f)
	if err != nil {
		t.Fatalf("check: %v", err)
	}

	if result.Verdict != VerdictNew {
		t.Errorf("different vuln class should be new, got %s", result.Verdict)
	}
}

func TestCheckBatch(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	insertTestFinding(t, db, "old-1", "key-dup", "example.com", "/api/v1", "xss", "approved")

	checker := NewChecker(db, nil)
	findings := []*models.Finding{
		{ID: "f1", FindingKey: "key-dup", Host: "example.com", Path: "/api/v1", VulnClass: models.VulnXSS},
		{ID: "f2", FindingKey: "key-unique", Host: "new.com", Path: "/new", VulnClass: models.VulnSQLi},
	}

	results, err := checker.CheckBatch(findings)
	if err != nil {
		t.Fatalf("batch: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].Verdict != VerdictConfirmed {
		t.Errorf("first should be confirmed_duplicate, got %s", results[0].Verdict)
	}
	if results[1].Verdict != VerdictNew {
		t.Errorf("second should be new, got %s", results[1].Verdict)
	}
}

func TestPathSimilarity(t *testing.T) {
	tests := []struct {
		a, b     string
		minSim   float64
		maxSim   float64
	}{
		{"/api/users", "/api/users", 1.0, 1.0},
		{"/api/users/123/profile", "/api/users/456/profile", 0.9, 1.0},
		{"/api/users", "/totally/different", 0.0, 0.1},
		{"/", "/", 1.0, 1.0},
		{"", "", 1.0, 1.0},
		{"/api/v1/users", "/api/v2/users", 0.5, 0.8},
	}

	for _, tt := range tests {
		sim := pathSimilarity(tt.a, tt.b)
		if sim < tt.minSim || sim > tt.maxSim {
			t.Errorf("pathSimilarity(%q, %q) = %f, want [%f, %f]", tt.a, tt.b, sim, tt.minSim, tt.maxSim)
		}
	}
}

func TestLooksLikeID(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"123", true},
		{"456789", true},
		{"abc123", false},
		{"550e8400-e29b-41d4-a716-446655440000", true}, // UUID
		{"abcdef1234567890", true},                      // 16-char hex
		{"users", false},
		{"api", false},
		{"v1", false},
		{"", false},
	}

	for _, tt := range tests {
		got := looksLikeID(tt.input)
		if got != tt.want {
			t.Errorf("looksLikeID(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
