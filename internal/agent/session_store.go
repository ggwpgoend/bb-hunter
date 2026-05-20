package agent

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// EndpointRecord tracks a discovered endpoint.
type EndpointRecord struct {
	URL    string
	Method string
	Status int
	Step   int
	Note   string // one-line description from summariser
}

// ResponseRecord stores a full HTTP response for recall.
type ResponseRecord struct {
	URL     string
	Method  string
	Status  int
	Headers string
	Body    string
	Step    int
}

// SessionStore is an in-memory store for agent session data.
//
// It replaces the growing conversation history as the primary data store:
// full observations go into the store, and only compact summaries are added
// to the LLM context. The agent can recall full data on demand via the
// "recall" tool.
type SessionStore struct {
	mu        sync.RWMutex
	endpoints []EndpointRecord
	responses map[string]ResponseRecord // key: METHOD|URL
	jsFiles   map[string]string         // url → JS source
	recon     map[string]string         // key: tool|args → output
	notes     []string
	step      int
}

// NewSessionStore creates an empty session store.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		responses: make(map[string]ResponseRecord),
		jsFiles:   make(map[string]string),
		recon:     make(map[string]string),
	}
}

// Record stores the full output of a tool execution and returns a compact
// summary suitable for the LLM context window. The summary is generated
// by deterministic heuristics (no LLM call).
func (s *SessionStore) Record(step int, tool, args, observation string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.step = step

	switch tool {
	case "http_get":
		return s.recordHTTP("GET", args, observation, step)
	case "http_raw":
		return s.recordHTTPRaw(args, observation, step)
	case "run_katana":
		return s.recordRecon(tool, args, observation)
	case "run_subfinder":
		return s.recordRecon(tool, args, observation)
	case "run_nuclei":
		return s.recordRecon(tool, args, observation)
	case "run_httpx":
		return s.recordRecon(tool, args, observation)
	case "run_cmd":
		return s.recordRecon(tool, args, observation)
	case "browser_snapshot":
		return s.recordBrowserSnapshot(observation)
	case "browser_eval":
		return s.recordBrowserEval(args, observation)
	case "browser_open":
		return s.recordBrowserOpen(args, observation)
	case "browser_click":
		return observation // pass through; clicks are short
	case "browser_type":
		return observation
	case "browser_screenshot":
		return observation
	case "report_finding":
		return observation
	default:
		return observation
	}
}

// Recall retrieves stored data. Supported queries:
//   - "endpoints"           — list all discovered endpoints
//   - "http <url>"          — full HTTP response for a URL
//   - "js <url>"            — JS source for a URL
//   - "search <keyword>"    — full-text search across all stores
func (s *SessionStore) Recall(query string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	parts := strings.SplitN(strings.TrimSpace(query), " ", 2)
	if len(parts) == 0 {
		return "ERROR: recall requires a query type: endpoints, http <url>, js <url>, search <keyword>"
	}

	switch parts[0] {
	case "endpoints":
		return s.recallEndpoints()
	case "http":
		if len(parts) < 2 {
			return "ERROR: usage: recall http <url>"
		}
		return s.recallHTTP(strings.TrimSpace(parts[1]))
	case "js":
		if len(parts) < 2 {
			return "ERROR: usage: recall js <url>"
		}
		return s.recallJS(strings.TrimSpace(parts[1]))
	case "search":
		if len(parts) < 2 {
			return "ERROR: usage: recall search <keyword>"
		}
		return s.recallSearch(strings.TrimSpace(parts[1]))
	default:
		return fmt.Sprintf("ERROR: unknown recall type %q. Use: endpoints, http, js, search", parts[0])
	}
}

// MemoryBlock generates the [SESSION MEMORY] block injected into every LLM
// call. It provides a compact index of what the agent has discovered so far.
func (s *SessionStore) MemoryBlock(hypotheses []hypothesis) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString("[SESSION MEMORY]\n")
	sb.WriteString(fmt.Sprintf("Step: %d | Endpoints: %d | HTTP stored: %d | JS analyzed: %d\n",
		s.step, len(s.endpoints), len(s.responses), len(s.jsFiles)))

	// Hypotheses section
	if len(hypotheses) > 0 {
		sb.WriteString("\nHYPOTHESES:\n")
		// Show most recent first, cap at 10
		start := 0
		if len(hypotheses) > 10 {
			start = len(hypotheses) - 10
		}
		for i := len(hypotheses) - 1; i >= start; i-- {
			h := hypotheses[i]
			sb.WriteString(fmt.Sprintf("- %s @ %s :: %s\n", h.Class, h.URL, h.Why))
		}
		if start > 0 {
			sb.WriteString(fmt.Sprintf("- (... %d older hypotheses omitted ...)\n", start))
		}
	}

	// Attack surface section: unique paths from endpoints
	if len(s.endpoints) > 0 {
		sb.WriteString("\nATTACK SURFACE:\n")
		seen := make(map[string]bool)
		count := 0
		for _, ep := range s.endpoints {
			key := ep.Method + " " + ep.URL
			if seen[key] {
				continue
			}
			seen[key] = true
			note := ""
			if ep.Note != "" {
				note = " — " + ep.Note
			}
			sb.WriteString(fmt.Sprintf("- %s %s [%d]%s\n", ep.Method, ep.URL, ep.Status, note))
			count++
			if count >= 15 {
				remaining := len(s.endpoints) - count
				if remaining > 0 {
					sb.WriteString(fmt.Sprintf("- (... %d more endpoints, use `recall endpoints` for full list ...)\n", remaining))
				}
				break
			}
		}
	}

	sb.WriteString("\nUse `recall <type> [filter]` for full data.\n")
	sb.WriteString("[/SESSION MEMORY]")
	return sb.String()
}

// --- internal recording methods ---

func (s *SessionStore) recordHTTP(method, rawURL, observation string, step int) string {
	rawURL = strings.TrimSpace(rawURL)
	rawURL = stripOuterQuotes(rawURL)

	status, headers, body := parseHTTPObservation(observation)

	key := method + "|" + rawURL
	s.responses[key] = ResponseRecord{
		URL: rawURL, Method: method, Status: status,
		Headers: headers, Body: body, Step: step,
	}
	s.addEndpoint(rawURL, method, status, step, "")

	// Check if it's a JS file and store source
	if strings.HasSuffix(rawURL, ".js") && status >= 200 && status < 300 {
		s.jsFiles[rawURL] = body
	}

	return summarizeHTTP(method, rawURL, status, headers, body)
}

func (s *SessionStore) recordHTTPRaw(args, observation string, step int) string {
	parts := splitArgsQuoteAware(args)
	method := "GET"
	rawURL := ""
	if len(parts) >= 1 {
		method = strings.ToUpper(parts[0])
	}
	if len(parts) >= 2 {
		rawURL = parts[1]
	}

	status, headers, body := parseHTTPObservation(observation)

	if rawURL != "" {
		key := method + "|" + rawURL
		s.responses[key] = ResponseRecord{
			URL: rawURL, Method: method, Status: status,
			Headers: headers, Body: body, Step: step,
		}
		s.addEndpoint(rawURL, method, status, step, "")
	}

	return summarizeHTTP(method, rawURL, status, headers, body)
}

func (s *SessionStore) recordRecon(tool, args, observation string) string {
	key := tool + "|" + args
	s.recon[key] = observation

	if strings.HasPrefix(observation, "ERROR:") || strings.HasPrefix(observation, "TIMEOUT:") {
		return observation
	}

	lines := strings.Split(strings.TrimSpace(observation), "\n")
	count := len(lines)

	switch tool {
	case "run_katana":
		// Extract unique paths
		paths := extractPaths(lines, 8)
		return fmt.Sprintf("Found %d endpoints. Key paths: %s. Full list stored — use `recall search <keyword>` to find specific endpoints.",
			count, strings.Join(paths, ", "))
	case "run_subfinder":
		return fmt.Sprintf("Found %d subdomains. First: %s. Full list stored.",
			count, strings.Join(firstN(lines, 5), ", "))
	case "run_nuclei":
		if observation == "" || strings.HasPrefix(observation, "OK:") {
			return observation
		}
		return fmt.Sprintf("Nuclei found %d results. Full output stored — use `recall search nuclei` to review.",
			count)
	case "run_httpx":
		return fmt.Sprintf("Probed %d hosts. Results stored.", count)
	default:
		if len(observation) > 300 {
			return observation[:300] + fmt.Sprintf("\n[... %d bytes total, stored — use `recall search <keyword>` ...]", len(observation))
		}
		return observation
	}
}

func (s *SessionStore) recordBrowserSnapshot(observation string) string {
	if strings.HasPrefix(observation, "ERROR:") {
		return observation
	}

	// Extract page title from the first few lines
	lines := strings.Split(observation, "\n")
	title := ""
	for _, line := range lines[:min(5, len(lines))] {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "[") && !strings.HasPrefix(trimmed, "@") {
			title = trimmed
			break
		}
	}

	// Count interactive elements
	elemCount := strings.Count(observation, "@e")

	if len(observation) > 2000 {
		summary := fmt.Sprintf("Page: %s. %d interactive elements.", title, elemCount)
		// Keep first 1500 chars of the snapshot for immediate context
		return observation[:1500] + fmt.Sprintf("\n[... snapshot truncated. %s ...]", summary)
	}
	return observation
}

func (s *SessionStore) recordBrowserEval(args, observation string) string {
	// If fetching JS source, store it
	if strings.Contains(args, "fetch(") || strings.Contains(args, "xhr") {
		return observation
	}
	return observation
}

func (s *SessionStore) recordBrowserOpen(args, observation string) string {
	return observation
}

// addEndpoint adds an endpoint to the list, deduplicating by method+url.
func (s *SessionStore) addEndpoint(rawURL, method string, status, step int, note string) {
	for i, ep := range s.endpoints {
		if ep.URL == rawURL && ep.Method == method {
			s.endpoints[i].Status = status
			s.endpoints[i].Step = step
			if note != "" {
				s.endpoints[i].Note = note
			}
			return
		}
	}
	s.endpoints = append(s.endpoints, EndpointRecord{
		URL: rawURL, Method: method, Status: status, Step: step, Note: note,
	})
}

// --- recall methods ---

func (s *SessionStore) recallEndpoints() string {
	if len(s.endpoints) == 0 {
		return "No endpoints discovered yet."
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Discovered %d endpoints:\n", len(s.endpoints)))
	for _, ep := range s.endpoints {
		note := ""
		if ep.Note != "" {
			note = " — " + ep.Note
		}
		sb.WriteString(fmt.Sprintf("  %s %s [%d]%s (step %d)\n", ep.Method, ep.URL, ep.Status, note, ep.Step))
	}
	return sb.String()
}

func (s *SessionStore) recallHTTP(rawURL string) string {
	// Try exact match first, then prefix match
	for _, method := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"} {
		key := method + "|" + rawURL
		if r, ok := s.responses[key]; ok {
			return fmt.Sprintf("HTTP %d %s %s\n%s\n\n%s", r.Status, r.Method, r.URL, r.Headers, r.Body)
		}
	}
	// Fuzzy match: check if URL is a substring
	for key, r := range s.responses {
		if strings.Contains(key, rawURL) {
			return fmt.Sprintf("HTTP %d %s %s\n%s\n\n%s", r.Status, r.Method, r.URL, r.Headers, r.Body)
		}
	}
	return fmt.Sprintf("No stored HTTP response for %q. Use `recall endpoints` to see what's available.", rawURL)
}

func (s *SessionStore) recallJS(rawURL string) string {
	if src, ok := s.jsFiles[rawURL]; ok {
		return src
	}
	// Fuzzy match
	for u, src := range s.jsFiles {
		if strings.Contains(u, rawURL) {
			return fmt.Sprintf("// Source: %s\n%s", u, src)
		}
	}
	return fmt.Sprintf("No stored JS source for %q.", rawURL)
}

func (s *SessionStore) recallSearch(keyword string) string {
	kw := strings.ToLower(keyword)
	var results []string

	// Search endpoints
	for _, ep := range s.endpoints {
		if strings.Contains(strings.ToLower(ep.URL), kw) {
			results = append(results, fmt.Sprintf("[endpoint] %s %s [%d]", ep.Method, ep.URL, ep.Status))
		}
	}

	// Search responses
	for _, r := range s.responses {
		if strings.Contains(strings.ToLower(r.URL), kw) ||
			strings.Contains(strings.ToLower(r.Headers), kw) ||
			strings.Contains(strings.ToLower(r.Body), kw) {
			bodyPreview := r.Body
			if len(bodyPreview) > 200 {
				bodyPreview = bodyPreview[:200] + "..."
			}
			results = append(results, fmt.Sprintf("[http %d] %s %s: %s", r.Status, r.Method, r.URL, bodyPreview))
		}
	}

	// Search recon
	for key, output := range s.recon {
		if strings.Contains(strings.ToLower(output), kw) || strings.Contains(strings.ToLower(key), kw) {
			preview := output
			if len(preview) > 300 {
				preview = preview[:300] + "..."
			}
			results = append(results, fmt.Sprintf("[recon %s] %s", key, preview))
		}
	}

	// Search JS
	for u, src := range s.jsFiles {
		if strings.Contains(strings.ToLower(src), kw) || strings.Contains(strings.ToLower(u), kw) {
			// Find the line containing the keyword
			for _, line := range strings.Split(src, "\n") {
				if strings.Contains(strings.ToLower(line), kw) {
					results = append(results, fmt.Sprintf("[js %s] %s", u, strings.TrimSpace(line)))
					break
				}
			}
		}
	}

	if len(results) == 0 {
		return fmt.Sprintf("No results for %q.", keyword)
	}

	sort.Strings(results)
	if len(results) > 30 {
		results = append(results[:30], fmt.Sprintf("... and %d more results", len(results)-30))
	}
	return strings.Join(results, "\n")
}

// --- helpers ---

// parseHTTPObservation extracts status, headers, body from the standard
// observation format: "HTTP <code> ...\n<headers>\n\n<body>"
func parseHTTPObservation(obs string) (status int, headers, body string) {
	if !strings.HasPrefix(obs, "HTTP ") {
		return 0, "", obs
	}

	statusLine, rest, ok := splitOnce(obs, "\n")
	if !ok {
		return 0, "", obs
	}

	code, ok := parseStatusCode(statusLine)
	if !ok {
		return 0, "", obs
	}

	hdrs, bod, ok := splitHeadersBody(rest)
	if !ok {
		return code, rest, ""
	}

	return code, hdrs, bod
}

// summarizeHTTP creates a compact one-line summary of an HTTP response.
func summarizeHTTP(method, rawURL string, status int, headers, body string) string {
	ct := extractHeader(headers, "Content-Type")
	bodyLen := len(body)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("HTTP %d", status))

	if ct != "" {
		// Shorten content type
		short := ct
		if idx := strings.Index(ct, ";"); idx > 0 {
			short = strings.TrimSpace(ct[:idx])
		}
		sb.WriteString(fmt.Sprintf(" %s", short))
	}
	sb.WriteString(fmt.Sprintf(" %dB.", bodyLen))

	// Highlight security-relevant headers
	interesting := []string{"X-Frame-Options", "Content-Security-Policy", "X-CSRF-Token",
		"Set-Cookie", "Location", "WWW-Authenticate", "Access-Control-Allow-Origin"}
	var found []string
	for _, h := range interesting {
		if v := extractHeader(headers, h); v != "" {
			short := v
			if len(short) > 40 {
				short = short[:40] + "..."
			}
			found = append(found, h+"="+short)
		}
	}
	if len(found) > 0 {
		sb.WriteString(" Headers: " + strings.Join(found, "; ") + ".")
	}

	// For HTML: count forms and JS includes
	if strings.Contains(strings.ToLower(ct), "text/html") && status >= 200 && status < 300 {
		formCount := strings.Count(strings.ToLower(body), "<form")
		scriptCount := strings.Count(strings.ToLower(body), "<script")
		if formCount > 0 || scriptCount > 0 {
			sb.WriteString(fmt.Sprintf(" Forms: %d, Scripts: %d.", formCount, scriptCount))
		}
	}

	// For error responses, include first line of body
	if status >= 400 && bodyLen > 0 {
		firstLine := strings.SplitN(body, "\n", 2)[0]
		if len(firstLine) > 100 {
			firstLine = firstLine[:100] + "..."
		}
		sb.WriteString(fmt.Sprintf(" Body: %s", firstLine))
	}

	sb.WriteString(" (full response stored)")
	return sb.String()
}

// extractPaths extracts unique URL paths from a list of full URLs.
func extractPaths(lines []string, maxPaths int) []string {
	seen := make(map[string]bool)
	var paths []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		u, err := url.Parse(line)
		if err != nil {
			continue
		}
		p := u.Path
		if p == "" || p == "/" {
			continue
		}
		if u.RawQuery != "" {
			p += "?" + u.RawQuery
		}
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
			if len(paths) >= maxPaths {
				break
			}
		}
	}
	return paths
}

func firstN(items []string, n int) []string {
	if len(items) <= n {
		return items
	}
	return items[:n]
}


