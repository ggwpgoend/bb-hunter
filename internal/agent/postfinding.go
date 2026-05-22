package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// processFinding runs the full post-finding pipeline for a freshly reported
// finding. It mutates a local copy of f, enriching it with verifier / gate /
// exploiter / sandbox / reporter results, then returns:
//
//   - mutated   — the enriched finding (only meaningful when accepted=true)
//   - accepted  — false if the verifier or gate killed the finding
//   - status    — short human-readable status string (joined to the LLM
//     observation so the agent learns what happened to its finding)
//
// The pipeline is best-effort: every stage degrades gracefully if its
// callback is not configured or returns an error. The only hard reject
// conditions are (a) browser verifier rejection for XSS-class findings,
// and (b) explicit gate verdict KILL.
func (a *Agent) processFinding(ctx context.Context, f Finding) (Finding, bool, string) {
	mutated := f
	if mutated.ID == "" {
		mutated.ID = fmt.Sprintf("agent-%d", time.Now().UnixNano())
	}

	// LLM-supplied confidence/proof_level may be missing or absurd; clamp.
	if mutated.Confidence < 0 {
		mutated.Confidence = 0
	}
	if mutated.Confidence > 1 {
		mutated.Confidence = 1
	}
	if mutated.ProofLevel == "" {
		mutated.ProofLevel = inferProofLevel(mutated.Confidence)
	}

	var statusParts []string

	// (1) Browser verifier — only runs for XSS-family findings (existing
	// behaviour). If it rejects, finding is dropped.
	if a.cfg.VerifyFinding != nil && findingNeedsBrowserVerification(f) {
		vr, err := a.cfg.VerifyFinding(ctx, f)
		if err != nil {
			a.log.Warn("agent: browser verification failed", "finding_id", mutated.ID, "error", err)
		}
		if err != nil || !vr.Verified {
			reason := strings.TrimSpace(vr.Reason)
			if reason == "" && err != nil {
				reason = err.Error()
			}
			return mutated, false, "browser verification rejected finding: " + reason
		}
		if vr.Reason != "" {
			statusParts = append(statusParts, "browser verification accepted: "+vr.Reason)
		}
	}

	// (2) Gate (LLM-backed via callback; the wiring may fall back to
	// algorithmic gate internally).
	if a.cfg.GateFinding != nil {
		gd, err := a.cfg.GateFinding(ctx, mutated)
		if err != nil {
			a.log.Warn("agent: finding gate failed", "finding_id", mutated.ID, "error", err)
			gd = GateDecision{Verdict: "KILL", Reason: err.Error()}
		}
		mutated.GateVerdict = strings.ToUpper(gd.Verdict)
		mutated.GateScore = gd.Score
		mutated.GateReasoning = gd.Reason
		switch mutated.GateVerdict {
		case "KILL":
			return mutated, false, fmt.Sprintf("gate killed finding (score=%d): %s", gd.Score, gd.Reason)
		case "DOWNGRADE":
			mutated.Severity = downgradeSeverity(mutated.Severity)
			statusParts = append(statusParts, fmt.Sprintf("gate downgraded to %s: %s", mutated.Severity, gd.Reason))
		default:
			if gd.Reason != "" {
				statusParts = append(statusParts, fmt.Sprintf("gate passed (score=%d): %s", gd.Score, gd.Reason))
			} else {
				statusParts = append(statusParts, fmt.Sprintf("gate passed (score=%d)", gd.Score))
			}
		}
	}

	// (3) Exploiter — generate safe PoC. Failure is non-fatal.
	if a.cfg.GeneratePoC != nil {
		poc, err := a.cfg.GeneratePoC(ctx, mutated)
		if err != nil {
			a.log.Warn("agent: PoC generation failed", "finding_id", mutated.ID, "error", err)
			statusParts = append(statusParts, "PoC generation failed: "+err.Error())
		} else {
			mutated.PoCScript = poc.Script
			mutated.PoCInterpreter = poc.Interpreter
			mutated.PoCDescription = poc.Description
			statusParts = append(statusParts, fmt.Sprintf("PoC generated (%s, %d bytes)", poc.Interpreter, len(poc.Script)))

			// (4) Sandbox — execute the PoC. Only runs when a PoC is in hand.
			if a.cfg.RunPoC != nil {
				res, err := a.cfg.RunPoC(ctx, mutated, poc)
				if err != nil {
					a.log.Warn("agent: PoC execution failed", "finding_id", mutated.ID, "error", err)
					statusParts = append(statusParts, "sandbox run failed: "+err.Error())
				} else {
					mutated.SandboxVerified = res.Verified
					mutated.SandboxEvidence = res.Evidence
					mutated.SandboxStdout = res.Stdout
					mutated.SandboxStderr = res.Stderr
					mutated.SandboxExitCode = res.ExitCode
					if res.Error != "" {
						statusParts = append(statusParts, "sandbox infra error: "+res.Error)
					} else if res.TimedOut {
						statusParts = append(statusParts, "sandbox timed out")
					} else if res.Verified {
						statusParts = append(statusParts, "sandbox verified: "+truncEvidence(res.Evidence, 120))
						if mutated.ProofLevel != "direct" {
							mutated.ProofLevel = "direct"
						}
						if mutated.Confidence < 0.85 {
							mutated.Confidence = 0.85
						}
					} else {
						statusParts = append(statusParts, "sandbox did NOT verify finding")
						// Sandbox couldn't reproduce -> downgrade proof_level
						// only when the LLM claimed something stronger.
						if mutated.ProofLevel == "direct" {
							mutated.ProofLevel = "behavioral"
						}
						if mutated.Confidence > 0.7 {
							mutated.Confidence = 0.7
						}
					}
				}
			}
		}
	}

	// (5) Reporter — generate Russian-language markdown report.
	if a.cfg.GenerateReport != nil {
		md, err := a.cfg.GenerateReport(ctx, mutated)
		if err != nil {
			a.log.Warn("agent: report generation failed", "finding_id", mutated.ID, "error", err)
			statusParts = append(statusParts, "reporter failed: "+err.Error())
		} else {
			mutated.ReportMarkdown = md
			statusParts = append(statusParts, fmt.Sprintf("reporter generated %d bytes of markdown", len(md)))
		}
	}

	// (6) Persist artifacts to disk if FindingsDir is configured.
	if a.cfg.FindingsDir != "" {
		dir, err := persistFinding(a.cfg.FindingsDir, mutated)
		if err != nil {
			a.log.Warn("agent: persist finding failed", "finding_id", mutated.ID, "error", err)
		} else {
			mutated.FindingDir = dir
			statusParts = append(statusParts, "persisted to "+dir)
		}
	}

	status := strings.Join(statusParts, " | ")
	if status == "" {
		status = "finding accepted"
	}
	return mutated, true, status
}

// persistFinding writes the finding and its artifacts to
// <baseDir>/<finding-id>/{finding.json, report.ru.md, poc.<ext>,
// sandbox.json}. Returns the per-finding directory path.
func persistFinding(baseDir string, f Finding) (string, error) {
	dir := filepath.Join(baseDir, f.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir: %w", err)
	}

	// finding.json — full serialised finding (sans heavy fields below; the
	// markdown/PoC/sandbox are also written separately for convenience).
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return dir, fmt.Errorf("marshal finding: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "finding.json"), data, 0o644); err != nil {
		return dir, fmt.Errorf("write finding.json: %w", err)
	}

	if f.ReportMarkdown != "" {
		if err := os.WriteFile(filepath.Join(dir, "report.ru.md"), []byte(f.ReportMarkdown), 0o644); err != nil {
			return dir, fmt.Errorf("write report.ru.md: %w", err)
		}
	}

	if f.PoCScript != "" {
		ext := pocExtension(f.PoCInterpreter)
		name := "poc." + ext
		if err := os.WriteFile(filepath.Join(dir, name), []byte(f.PoCScript), 0o644); err != nil {
			return dir, fmt.Errorf("write poc: %w", err)
		}
	}

	if f.SandboxStdout != "" || f.SandboxStderr != "" {
		sb := struct {
			Verified bool   `json:"verified"`
			Evidence string `json:"evidence"`
			ExitCode int    `json:"exit_code"`
			Stdout   string `json:"stdout"`
			Stderr   string `json:"stderr"`
		}{
			Verified: f.SandboxVerified,
			Evidence: f.SandboxEvidence,
			ExitCode: f.SandboxExitCode,
			Stdout:   f.SandboxStdout,
			Stderr:   f.SandboxStderr,
		}
		sbData, _ := json.MarshalIndent(sb, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, "sandbox.json"), sbData, 0o644); err != nil {
			return dir, fmt.Errorf("write sandbox.json: %w", err)
		}
	}

	return dir, nil
}

func pocExtension(interpreter string) string {
	switch strings.ToLower(strings.TrimSpace(interpreter)) {
	case "python3", "python", "py":
		return "py"
	case "bash", "sh":
		return "sh"
	case "curl":
		return "sh"
	case "node", "nodejs", "javascript", "js":
		return "js"
	case "ruby", "rb":
		return "rb"
	case "":
		return "txt"
	default:
		return "txt"
	}
}

func inferProofLevel(confidence float64) string {
	switch {
	case confidence >= 0.8:
		return "direct"
	case confidence >= 0.35:
		return "behavioral"
	default:
		return "inferred"
	}
}

func downgradeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "high"
	case "high":
		return "medium"
	case "medium":
		return "low"
	case "low", "info":
		return "info"
	default:
		return "low"
	}
}

func truncEvidence(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// passiveEvidencePatterns maps a vuln class to one or more regexes that
// indicate "direct" evidence is present in the agent-supplied Evidence
// string. Used by EvidenceAssessment to detect when the LLM claimed direct
// proof but the evidence does not actually contain it.
var passiveEvidencePatterns = map[string][]*regexp.Regexp{
	"lfi": {
		regexp.MustCompile(`(?m)^root:x:0:0:`),
		regexp.MustCompile(`(?i)\[boot loader\]`),
	},
	"sqli": {
		regexp.MustCompile(`(?i)SQL syntax|ORA-\d{4,5}|SQLite[A-Za-z]*Exception|mysql_fetch|pg_query|unclosed quotation|sqlstate\[`),
	},
	"ssrf": {
		regexp.MustCompile(`(?i)ami-id|iam/security-credentials|metadata\.google\.internal`),
	},
	"info_disclosure": {
		regexp.MustCompile(`(?i)AWS_ACCESS_KEY_ID|AKIA[0-9A-Z]{16}|-----BEGIN .+ PRIVATE KEY-----`),
		regexp.MustCompile(`(?m)^ref: refs/heads/`),
	},
	"open_redirect": {
		regexp.MustCompile(`(?i)^Location:\s*https?://`),
	},
}

// AssessEvidence returns true when the supplied Evidence/Description contains
// pattern matches consistent with the declared vuln_class at "direct"
// proof level. Used by the post-finding pipeline as a sanity check on the
// LLM's self-assessed proof_level.
func AssessEvidence(vulnClass, evidence, description string) bool {
	patterns, ok := passiveEvidencePatterns[strings.ToLower(vulnClass)]
	if !ok {
		return false
	}
	hay := evidence + "\n" + description
	for _, re := range patterns {
		if re.MatchString(hay) {
			return true
		}
	}
	return false
}
