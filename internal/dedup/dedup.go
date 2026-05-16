// Package dedup implements duplicate finding detection.
//
// Borrowed concept: pentest-agents' /dupcheck command.
// BB-Hunter implementation: query SQLite for previously approved/submitted
// findings with matching finding_key, vuln_class, or URL+param combination.
// Marks probable duplicates before they reach HITL to save reviewer time
// and protect platform reputation.
package dedup

import (
	"database/sql"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ggwpgoend/bb-hunter/internal/models"
)

// Verdict is the dedup decision for a finding.
type Verdict string

const (
	VerdictNew       Verdict = "new"
	VerdictLikely    Verdict = "likely_duplicate"
	VerdictConfirmed Verdict = "confirmed_duplicate"
)

// Result holds the dedup analysis for a single finding.
type Result struct {
	FindingID  string  `json:"finding_id"`
	Verdict    Verdict `json:"verdict"`
	Similarity float64 `json:"similarity"` // 0.0–1.0
	MatchedID  string  `json:"matched_id,omitempty"`
	Reason     string  `json:"reason,omitempty"`
}

// Checker performs duplicate detection against the findings history.
type Checker struct {
	db  *sql.DB
	log *slog.Logger
}

// NewChecker creates a new duplicate checker.
func NewChecker(db *sql.DB, logger *slog.Logger) *Checker {
	if logger == nil {
		logger = slog.Default()
	}
	return &Checker{db: db, log: logger}
}

// Check evaluates a finding against historical data and returns a dedup verdict.
func (c *Checker) Check(f *models.Finding) (*Result, error) {
	result := &Result{
		FindingID: f.ID,
		Verdict:   VerdictNew,
	}

	// Level 1: exact finding_key match (strongest signal)
	if match, err := c.findByKey(f); err == nil && match != nil {
		result.Verdict = VerdictConfirmed
		result.Similarity = 1.0
		result.MatchedID = match.id
		result.Reason = fmt.Sprintf("exact key match: same URL+method+params+template (previously %s)", match.status)
		c.log.Info("dedup: confirmed duplicate",
			"finding_id", f.ID,
			"matched_id", match.id,
			"key", f.FindingKey,
		)
		return result, nil
	}

	// Level 2: same host + vuln_class + similar path
	if match, sim, err := c.findSimilar(f); err == nil && match != nil {
		if sim >= 0.8 {
			result.Verdict = VerdictLikely
			result.Similarity = sim
			result.MatchedID = match.id
			result.Reason = fmt.Sprintf("similar finding: %s on %s (%.0f%% match, previously %s)", match.vulnClass, match.host, sim*100, match.status)
			c.log.Info("dedup: likely duplicate",
				"finding_id", f.ID,
				"matched_id", match.id,
				"similarity", sim,
			)
			return result, nil
		}
	}

	c.log.Debug("dedup: new finding", "finding_id", f.ID)
	return result, nil
}

// CheckBatch runs dedup check on multiple findings.
func (c *Checker) CheckBatch(findings []*models.Finding) ([]*Result, error) {
	results := make([]*Result, 0, len(findings))
	for _, f := range findings {
		r, err := c.Check(f)
		if err != nil {
			c.log.Warn("dedup: check failed", "finding_id", f.ID, "error", err)
			results = append(results, &Result{
				FindingID: f.ID,
				Verdict:   VerdictNew,
			})
			continue
		}
		results = append(results, r)
	}
	return results, nil
}

type matchedFinding struct {
	id        string
	status    string
	host      string
	path      string
	vulnClass string
}

// findByKey searches for an exact finding_key match in previous scan runs.
func (c *Checker) findByKey(f *models.Finding) (*matchedFinding, error) {
	if f.FindingKey == "" {
		return nil, nil
	}

	row := c.db.QueryRow(`
		SELECT id, status, host, path, vuln_class
		FROM findings
		WHERE finding_key = ?
		  AND id != ?
		  AND status NOT IN ('rejected')
		ORDER BY created_at DESC
		LIMIT 1
	`, f.FindingKey, f.ID)

	var m matchedFinding
	var vulnClass sql.NullString
	err := row.Scan(&m.id, &m.status, &m.host, &m.path, &vulnClass)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("dedup: findByKey query failed: %w", err)
	}
	m.vulnClass = vulnClass.String
	return &m, nil
}

// findSimilar searches for findings with the same host + vuln_class
// and computes path similarity.
func (c *Checker) findSimilar(f *models.Finding) (*matchedFinding, float64, error) {
	if f.Host == "" || f.VulnClass == "" {
		return nil, 0, nil
	}

	rows, err := c.db.Query(`
		SELECT id, status, host, path, vuln_class
		FROM findings
		WHERE host = ?
		  AND vuln_class = ?
		  AND id != ?
		  AND status NOT IN ('rejected')
		ORDER BY created_at DESC
		LIMIT 10
	`, f.Host, string(f.VulnClass), f.ID)
	if err != nil {
		return nil, 0, fmt.Errorf("dedup: findSimilar query failed: %w", err)
	}
	defer rows.Close()

	var bestMatch *matchedFinding
	var bestSim float64

	for rows.Next() {
		var m matchedFinding
		var vulnClass sql.NullString
		if err := rows.Scan(&m.id, &m.status, &m.host, &m.path, &vulnClass); err != nil {
			continue
		}
		m.vulnClass = vulnClass.String

		sim := pathSimilarity(f.Path, m.path)
		if sim > bestSim {
			bestSim = sim
			match := m
			bestMatch = &match
		}
	}

	return bestMatch, bestSim, nil
}

// pathSimilarity computes similarity between two URL paths (0.0–1.0).
// Uses normalized segment comparison.
func pathSimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}

	segA := splitPath(a)
	segB := splitPath(b)

	if len(segA) == 0 && len(segB) == 0 {
		return 1.0
	}

	maxLen := len(segA)
	if len(segB) > maxLen {
		maxLen = len(segB)
	}
	if maxLen == 0 {
		return 1.0
	}

	matching := 0
	minLen := len(segA)
	if len(segB) < minLen {
		minLen = len(segB)
	}

	for i := 0; i < minLen; i++ {
		if segA[i] == segB[i] {
			matching++
		} else if looksLikeID(segA[i]) && looksLikeID(segB[i]) {
			// Both segments look like IDs (numeric, UUID-like) — treat as equivalent
			matching++
		}
	}

	return float64(matching) / float64(maxLen)
}

// splitPath splits a URL path into non-empty segments.
func splitPath(p string) []string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	result := make([]string, 0, len(parts))
	for _, s := range parts {
		if s != "" {
			result = append(result, strings.ToLower(s))
		}
	}
	return result
}

// looksLikeID returns true if a path segment looks like a dynamic ID
// (numeric, UUID-like, or hex string).
func looksLikeID(s string) bool {
	if len(s) == 0 {
		return false
	}

	// All digits
	allDigits := true
	for _, c := range s {
		if c < '0' || c > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return true
	}

	// UUID-like (contains hyphens, hex chars)
	if len(s) >= 8 && strings.Contains(s, "-") {
		hexChars := 0
		for _, c := range s {
			if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == '-' {
				hexChars++
			}
		}
		return hexChars == len(s)
	}

	// Long hex string (>= 16 chars, all hex)
	if len(s) >= 16 {
		allHex := true
		for _, c := range s {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				allHex = false
				break
			}
		}
		return allHex
	}

	return false
}
