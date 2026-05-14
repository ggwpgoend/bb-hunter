package scanner

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// parseHttpxLine parses a line from httpx output.
// Format: "URL [STATUS] [TITLE] [TECH1,TECH2]"
func parseHttpxLine(line string) HostResult {
	result := HostResult{}

	// httpx with -status-code -title -tech-detect outputs:
	// https://example.com [200] [Example Domain] [Nginx,PHP]
	parts := strings.SplitN(line, " ", 2)
	if len(parts) == 0 {
		return result
	}

	result.URL = strings.TrimSpace(parts[0])

	if len(parts) < 2 {
		return result
	}

	remainder := parts[1]

	// Extract bracketed fields
	brackets := extractBrackets(remainder)
	if len(brackets) >= 1 {
		// Status code
		code := strings.TrimSpace(brackets[0])
		fmt.Sscanf(code, "%d", &result.StatusCode)
	}
	if len(brackets) >= 2 {
		result.Title = strings.TrimSpace(brackets[1])
	}
	if len(brackets) >= 3 {
		techStr := strings.TrimSpace(brackets[2])
		if techStr != "" {
			result.Tech = strings.Split(techStr, ",")
			for i := range result.Tech {
				result.Tech[i] = strings.TrimSpace(result.Tech[i])
			}
		}
	}

	return result
}

// extractBrackets extracts content from [brackets] in a string.
func extractBrackets(s string) []string {
	var results []string
	for {
		start := strings.Index(s, "[")
		if start == -1 {
			break
		}
		end := strings.Index(s[start:], "]")
		if end == -1 {
			break
		}
		results = append(results, s[start+1:start+end])
		s = s[start+end+1:]
	}
	return results
}

// nucleiJSON represents nuclei JSONL output format.
type nucleiJSON struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
	MatchedAt string `json:"matched-at"`
	Matched   string `json:"matcher-name"`
	Timestamp string `json:"timestamp"`
	CurlCmd   string `json:"curl-command"`
	Request   string `json:"request,omitempty"`
	Response  string `json:"response,omitempty"`
}

// parseNucleiJSON parses a single nuclei JSONL line.
func parseNucleiJSON(line string) (NucleiResult, error) {
	var nj nucleiJSON
	if err := json.Unmarshal([]byte(line), &nj); err != nil {
		return NucleiResult{}, fmt.Errorf("parse nuclei JSON: %w", err)
	}

	ts, _ := time.Parse(time.RFC3339, nj.Timestamp)

	// Build evidence from available data
	var evidence strings.Builder
	if nj.Matched != "" {
		evidence.WriteString("matcher: ")
		evidence.WriteString(nj.Matched)
		evidence.WriteString("\n")
	}
	if nj.CurlCmd != "" {
		evidence.WriteString("curl: ")
		evidence.WriteString(nj.CurlCmd)
		evidence.WriteString("\n")
	}
	// Truncate response to first 2KB (avoid DB bloat)
	if nj.Response != "" {
		resp := nj.Response
		if len(resp) > 2048 {
			resp = resp[:2048] + "...[truncated]"
		}
		evidence.WriteString("response_snippet: ")
		evidence.WriteString(resp)
	}

	return NucleiResult{
		TemplateID: nj.TemplateID,
		Name:       nj.Info.Name,
		Severity:   nj.Info.Severity,
		URL:        nj.MatchedAt,
		Matched:    nj.Matched,
		Evidence:   evidence.String(),
		Timestamp:  ts,
	}, nil
}
