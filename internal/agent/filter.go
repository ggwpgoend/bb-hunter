package agent

import (
	"fmt"
	"strconv"
	"strings"
)

// httpFilterErrorBodyBudget is the maximum number of body bytes kept for a
// 4xx/5xx HTTP response observation before the rest is replaced with a marker.
const httpFilterErrorBodyBudget = 200

// httpFilterHTMLBodyBudget is the maximum number of body bytes kept for a
// 2xx HTML response observation before the rest is replaced with a marker.
// JSON 2xx responses are NEVER trimmed (signal).
const httpFilterHTMLBodyBudget = 500

// filterHTTPObservation compresses HTTP tool observations so they take less
// space in the agent's context window without dropping the diagnostic signal.
//
// Rules:
//   - 4xx / 5xx: keep status line + all headers + first 200 bytes of body
//     (the rest is replaced with a truncation marker).
//   - 2xx with HTML body > 500 bytes: trim body to 500 bytes (marker appended).
//   - 2xx with JSON body or any other content type: untouched (signal).
//
// Input format must match what httpGet / httpRaw produce:
//
//	"HTTP <code> <statusText>\n<Header>: <Value>\n...\n\n<body>"
//
// If the input does not match this shape (e.g. an "ERROR:" string) it is
// returned unchanged.
func filterHTTPObservation(observation string) string {
	if !strings.HasPrefix(observation, "HTTP ") {
		return observation
	}

	statusLine, rest, ok := splitOnce(observation, "\n")
	if !ok {
		return observation
	}

	code, ok := parseStatusCode(statusLine)
	if !ok {
		return observation
	}

	headerBlock, body, ok := splitHeadersBody(rest)
	if !ok {
		return observation
	}

	switch {
	case code >= 400 && code < 600:
		body = trimWithMarker(body, httpFilterErrorBodyBudget, "body")
	case code >= 200 && code < 300:
		if isHTML(headerBlock) {
			body = trimWithMarker(body, httpFilterHTMLBodyBudget, "HTML body")
		}
	}

	return statusLine + "\n" + headerBlock + "\n\n" + body
}

// parseStatusCode extracts the numeric status from a status line shaped
// "HTTP <code> <text>". Returns (0, false) on any parse failure.
func parseStatusCode(statusLine string) (int, bool) {
	parts := strings.Fields(statusLine)
	if len(parts) < 2 {
		return 0, false
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil || code < 100 || code > 599 {
		return 0, false
	}
	return code, true
}

// splitHeadersBody splits a "headers\n\nbody" blob. Returns (headers, body, true)
// when the empty-line separator is present; otherwise ("","",false).
func splitHeadersBody(rest string) (string, string, bool) {
	idx := strings.Index(rest, "\n\n")
	if idx < 0 {
		return "", "", false
	}
	return rest[:idx], rest[idx+2:], true
}

// isHTML reports whether the headers indicate an HTML/XHTML content type.
func isHTML(headers string) bool {
	ct := extractHeader(headers, "Content-Type")
	ctLower := strings.ToLower(ct)
	return strings.Contains(ctLower, "text/html") ||
		strings.Contains(ctLower, "application/xhtml")
}

// extractHeader returns the first matching header value (case-insensitive)
// or "" if not present.
func extractHeader(headers, name string) string {
	wantLower := strings.ToLower(name)
	for _, line := range strings.Split(headers, "\n") {
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		if strings.ToLower(strings.TrimSpace(line[:colon])) == wantLower {
			return strings.TrimSpace(line[colon+1:])
		}
	}
	return ""
}

// trimWithMarker returns body unchanged if its length is within budget,
// otherwise returns the first `budget` bytes followed by a marker describing
// how many bytes were dropped.
func trimWithMarker(body string, budget int, label string) string {
	if len(body) <= budget {
		return body
	}
	dropped := len(body) - budget
	return body[:budget] + fmt.Sprintf("\n[... %s truncated, %d bytes elided ...]", label, dropped)
}

// splitOnce splits s on the first occurrence of sep. Returns (before, after, true)
// when sep is found.
func splitOnce(s, sep string) (string, string, bool) {
	idx := strings.Index(s, sep)
	if idx < 0 {
		return "", "", false
	}
	return s[:idx], s[idx+len(sep):], true
}
