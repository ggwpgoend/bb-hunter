// Package differ compares findings between scan runs to detect
// new, gone, changed, and unchanged vulnerabilities.
//
// The Differ operates on finding_key (dedup hash) to correlate
// findings across runs without relying on finding IDs.
package differ

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/models"
)

// ChangeType classifies a finding's change between two scan runs.
type ChangeType string

const (
	ChangeNew       ChangeType = "new"       // present in current, absent in previous
	ChangeGone      ChangeType = "gone"      // absent in current, present in previous
	ChangeChanged   ChangeType = "changed"   // present in both, but severity/class differs
	ChangeUnchanged ChangeType = "unchanged" // present in both, no material difference
)

// DiffEntry represents one finding's change between runs.
type DiffEntry struct {
	ChangeType ChangeType      `json:"change_type"`
	FindingKey string          `json:"finding_key"`
	Current    *models.Finding `json:"current,omitempty"`  // nil for "gone"
	Previous   *models.Finding `json:"previous,omitempty"` // nil for "new"
}

// DiffResult is the complete diff between two scan runs.
type DiffResult struct {
	PreviousRunID string      `json:"previous_run_id"`
	CurrentRunID  string      `json:"current_run_id"`
	ComputedAt    time.Time   `json:"computed_at"`
	Entries       []DiffEntry `json:"entries"`

	// Summary counts
	NewCount       int `json:"new_count"`
	GoneCount      int `json:"gone_count"`
	ChangedCount   int `json:"changed_count"`
	UnchangedCount int `json:"unchanged_count"`
}

// Differ compares findings between scan runs.
type Differ struct {
	db *sql.DB
}

// New creates a Differ from an open database.
func New(db *sql.DB) *Differ {
	return &Differ{db: db}
}

// Diff compares findings between previousRunID and currentRunID.
// If previousRunID is empty, all current findings are treated as "new".
func (d *Differ) Diff(previousRunID, currentRunID string) (*DiffResult, error) {
	current, err := d.loadFindings(currentRunID)
	if err != nil {
		return nil, fmt.Errorf("differ: load current run %s: %w", currentRunID, err)
	}

	result := &DiffResult{
		PreviousRunID: previousRunID,
		CurrentRunID:  currentRunID,
		ComputedAt:    time.Now(),
	}

	if previousRunID == "" {
		// First run: everything is new
		for _, f := range current {
			result.Entries = append(result.Entries, DiffEntry{
				ChangeType: ChangeNew,
				FindingKey: f.FindingKey,
				Current:    f,
			})
		}
		result.NewCount = len(current)
		return result, nil
	}

	previous, err := d.loadFindings(previousRunID)
	if err != nil {
		return nil, fmt.Errorf("differ: load previous run %s: %w", previousRunID, err)
	}

	// Index previous findings by key
	prevByKey := make(map[string]*models.Finding, len(previous))
	for _, f := range previous {
		prevByKey[f.FindingKey] = f
	}

	// Index current findings by key
	currByKey := make(map[string]*models.Finding, len(current))
	for _, f := range current {
		currByKey[f.FindingKey] = f
	}

	// Check current findings against previous
	for key, curr := range currByKey {
		prev, existed := prevByKey[key]
		if !existed {
			result.Entries = append(result.Entries, DiffEntry{
				ChangeType: ChangeNew,
				FindingKey: key,
				Current:    curr,
			})
			result.NewCount++
		} else if findingChanged(prev, curr) {
			result.Entries = append(result.Entries, DiffEntry{
				ChangeType: ChangeChanged,
				FindingKey: key,
				Current:    curr,
				Previous:   prev,
			})
			result.ChangedCount++
		} else {
			result.Entries = append(result.Entries, DiffEntry{
				ChangeType: ChangeUnchanged,
				FindingKey: key,
				Current:    curr,
				Previous:   prev,
			})
			result.UnchangedCount++
		}
	}

	// Check for gone findings (in previous but not in current)
	for key, prev := range prevByKey {
		if _, exists := currByKey[key]; !exists {
			result.Entries = append(result.Entries, DiffEntry{
				ChangeType: ChangeGone,
				FindingKey: key,
				Previous:   prev,
			})
			result.GoneCount++
		}
	}

	return result, nil
}

// LatestRunID returns the most recent scan run ID for a program,
// excluding the given currentRunID.
func (d *Differ) LatestRunID(programID, excludeRunID string) (string, error) {
	var runID string
	err := d.db.QueryRow(
		`SELECT id FROM scan_runs 
		 WHERE program_id = ? AND id != ? 
		 ORDER BY started_at DESC LIMIT 1`,
		programID, excludeRunID,
	).Scan(&runID)

	if err == sql.ErrNoRows {
		return "", nil // no previous run
	}
	if err != nil {
		return "", fmt.Errorf("differ: latest run query: %w", err)
	}
	return runID, nil
}

// findingChanged checks if a finding has materially changed between runs.
func findingChanged(prev, curr *models.Finding) bool {
	return prev.Severity != curr.Severity ||
		prev.VulnClass != curr.VulnClass ||
		prev.Status != curr.Status
}

// loadFindings loads all findings for a scan run from the database.
func (d *Differ) loadFindings(scanRunID string) ([]*models.Finding, error) {
	rows, err := d.db.Query(`
		SELECT id, finding_key, created_at, updated_at,
			program_id, scan_run_id,
			url, method, host, path,
			nuclei_template_id, scanner_evidence, severity,
			vuln_class, hypothesis, confidence,
			status, report_markdown,
			hitl_decision, hitl_decided_at,
			param_names
		FROM findings
		WHERE scan_run_id = ?
	`, scanRunID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []*models.Finding
	for rows.Next() {
		f := &models.Finding{}
		var paramJSON string
		var hitlDecidedAt sql.NullTime
		var nucleiTmpl, evidence, vulnClass, hypothesis, report, hitlDecision sql.NullString

		err := rows.Scan(
			&f.ID, &f.FindingKey, &f.CreatedAt, &f.UpdatedAt,
			&f.ProgramID, &f.ScanRunID,
			&f.URL, &f.Method, &f.Host, &f.Path,
			&nucleiTmpl, &evidence, &f.Severity,
			&vulnClass, &hypothesis, &f.Confidence,
			&f.Status, &report,
			&hitlDecision, &hitlDecidedAt,
			&paramJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}

		if nucleiTmpl.Valid {
			f.NucleiTemplateID = nucleiTmpl.String
		}
		if evidence.Valid {
			f.ScannerEvidence = evidence.String
		}
		if vulnClass.Valid {
			f.VulnClass = models.VulnClass(vulnClass.String)
		}
		if hypothesis.Valid {
			f.Hypothesis = hypothesis.String
		}
		if report.Valid {
			f.ReportMarkdown = report.String
		}
		if hitlDecision.Valid {
			f.HITLDecision = hitlDecision.String
		}
		if hitlDecidedAt.Valid {
			t := hitlDecidedAt.Time
			f.HITLDecidedAt = &t
		}

		if paramJSON != "" {
			json.Unmarshal([]byte(paramJSON), &f.ParamNames)
		}

		findings = append(findings, f)
	}

	return findings, rows.Err()
}
