package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// CheckFfufBinary returns nil if `ffuf` is in PATH and runnable, error otherwise.
func CheckFfufBinary(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ffuf", "-V")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ffuf not available: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// ffufResult is one row from ffuf's JSON output.
type ffufResult struct {
	Status int    `json:"status"`
	Length int    `json:"length"`
	Input  struct {
		FUZZ string `json:"FUZZ"`
	} `json:"input"`
}

// ffufOutput is the top-level JSON structure from ffuf -of json.
type ffufOutput struct {
	Results []ffufResult `json:"results"`
}

// runFfuf executes `ffuf -w <wordlist> -u <url with FUZZ> -mc all -of json`
// and parses the JSON result. Returns a compact summary line per hit:
//
//	200  43b  /admin
//	403  120b /backup
func (te *ToolExecutor) runFfuf(ctx context.Context, args string) string {
	parts := strings.Fields(strings.TrimSpace(args))
	if len(parts) < 2 {
		return "ERROR: usage: run_ffuf <url_with_FUZZ> <wordlist_path> [filter_status_codes]"
	}

	url := parts[0]
	wordlistPath := parts[1]

	if !strings.Contains(url, "FUZZ") {
		return "ERROR: URL must contain the keyword FUZZ for ffuf to substitute"
	}

	if _, err := os.Stat(wordlistPath); os.IsNotExist(err) {
		return fmt.Sprintf("ERROR: wordlist file not found: %s", wordlistPath)
	}

	cmdArgs := []string{"-w", wordlistPath, "-u", url, "-mc", "all", "-of", "json", "-s"}

	// Optional status-code filter: e.g. "200,301,403"
	if len(parts) > 2 {
		cmdArgs = append(cmdArgs, "-mc", parts[2])
		// Remove the earlier "-mc all" — ffuf uses the last -mc.
		// Actually ffuf processes flags in order; we replace the initial -mc all.
		// Rebuild without the default -mc all.
		cmdArgs = []string{"-w", wordlistPath, "-u", url, "-mc", parts[2], "-of", "json", "-s"}
	}

	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ffuf", cmdArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	_ = cmd.Run() // ffuf exits non-zero when no results; still parse output

	if stdout.Len() == 0 {
		if ctx.Err() == context.DeadlineExceeded {
			return "TIMEOUT: ffuf timed out after 120s"
		}
		errText := strings.TrimSpace(stderr.String())
		if errText != "" {
			return fmt.Sprintf("ERROR: ffuf: %s", truncateStr(errText, 500))
		}
		return "OK: ffuf returned no results"
	}

	var out ffufOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return fmt.Sprintf("ERROR: failed to parse ffuf JSON: %v\nRaw (first 500 chars): %s",
			err, truncateStr(stdout.String(), 500))
	}

	if len(out.Results) == 0 {
		return "OK: ffuf returned no results"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("ffuf: %d results\n", len(out.Results)))
	for _, r := range out.Results {
		sb.WriteString(fmt.Sprintf("  %d  %db  %s\n", r.Status, r.Length, r.Input.FUZZ))
	}
	return truncateStr(sb.String(), 80000)
}

// truncateStr is a local helper identical to truncate in tools.go but avoids
// import cycles if this file is ever split into a sub-package.
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "\n... (truncated)"
}
