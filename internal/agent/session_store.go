package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

// RequestRecord stores every HTTP probe, including repeated POSTs to the same
// endpoint. The latest response map is kept for backwards-compatible recall,
// while this append-only ledger preserves investigation history.
type RequestRecord struct {
	ID          string
	Tool        string
	Method      string
	URL         string
	Status      int
	Headers     string
	Body        string
	RequestBody string
	BodyHash    string
	Step        int
	OutcomeTags []string
}

// EvidenceRecord is compact deterministic state extracted from observations.
type EvidenceRecord struct {
	Class     string
	URL       string
	Primitive string
	Status    string
	Reason    string
	Step      int
	RequestID string
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
	requests  []RequestRecord
	evidence  []EvidenceRecord
	jsFiles   map[string]string // url → JS source
	recon     map[string]string // key: tool|args → output
	notes     []string
	findings  []Finding
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
	case "http_request":
		return s.recordHTTPRequest(args, observation, step)
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
		s.recordFinding(args)
		return observation
	default:
		return observation
	}
}

// Recall retrieves stored data. Supported queries:
//   - "endpoints"           — list all discovered endpoints
//   - "endpoint <filter>"   — list endpoints / HTTP tests matching a filter
//   - "http <url>"          — full latest HTTP response for a URL
//   - "last_response"       — full most recent HTTP response
//   - "tests [filter]"      — HTTP test ledger
//   - "negative"            — negative / abandoned evidence ledger
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
	case "endpoint":
		if len(parts) < 2 {
			return "ERROR: usage: recall endpoint <filter>"
		}
		return s.recallEndpoint(strings.TrimSpace(parts[1]))
	case "http":
		if len(parts) < 2 {
			return "ERROR: usage: recall http <url>"
		}
		return s.recallHTTP(strings.TrimSpace(parts[1]))
	case "last_response":
		return s.recallLastResponse()
	case "tests":
		filter := ""
		if len(parts) == 2 {
			filter = strings.TrimSpace(parts[1])
		}
		return s.recallTests(filter)
	case "negative":
		return s.recallEvidence("negative")
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
		return fmt.Sprintf("ERROR: unknown recall type %q. Use: endpoints, endpoint, http, last_response, tests, negative, js, search", parts[0])
	}
}

// MemoryBlock generates the [SESSION MEMORY] block injected into every LLM
// call. It provides a compact index of what the agent has discovered so far.
func (s *SessionStore) MemoryBlock(hypotheses []hypothesis) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString("[SESSION MEMORY]\n")
	sb.WriteString(fmt.Sprintf("Step: %d | Endpoints: %d | HTTP tests: %d | JS analyzed: %d | Findings: %d\n",
		s.step, len(s.endpoints), len(s.requests), len(s.jsFiles), len(s.findings)))

	if len(s.evidence) > 0 || len(s.requests) > 0 {
		sb.WriteString("\nINVESTIGATION STATE:\n")
		neg := lastEvidenceByStatus(s.evidence, "negative", 6)
		if len(neg) > 0 {
			sb.WriteString("Negative / do-not-repeat without new evidence:\n")
			for _, ev := range neg {
				sb.WriteString(fmt.Sprintf("- %s @ %s (%s): %s [step %d]\n", ev.Class, ev.URL, ev.Primitive, ev.Reason, ev.Step))
			}
		}
		recent := lastRequests(s.requests, 5)
		if len(recent) > 0 {
			sb.WriteString("Recent HTTP tests:\n")
			for _, r := range recent {
				tags := strings.Join(r.OutcomeTags, ",")
				if tags == "" {
					tags = "no-tags"
				}
				sb.WriteString(fmt.Sprintf("- %s %s %s -> %d (%s) [step %d]\n", r.ID, r.Method, r.URL, r.Status, tags, r.Step))
			}
		}
	}

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

	if len(s.findings) > 0 {
		sb.WriteString("\nFINDINGS:\n")
		start := 0
		if len(s.findings) > 5 {
			start = len(s.findings) - 5
		}
		for i := start; i < len(s.findings); i++ {
			f := s.findings[i]
			sb.WriteString(fmt.Sprintf("- %s %s @ %s\n", f.Severity, f.VulnClass, f.URL))
		}
		if start > 0 {
			sb.WriteString(fmt.Sprintf("- (... %d older findings omitted ...)\n", start))
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

	sb.WriteString("\nUse `recall tests [filter]`, `recall negative`, `recall last_response`, or `recall <type> [filter]` for full data.\n")
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
	req := s.appendRequestRecord(step, "http_get", method, rawURL, "", status, headers, body)
	s.updateEvidenceFromRequest(req)

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
	headers, requestBody := parseHTTPRawParts(parts[2:])

	status, responseHeaders, body := parseHTTPObservation(observation)

	if rawURL != "" {
		key := method + "|" + rawURL
		s.responses[key] = ResponseRecord{
			URL: rawURL, Method: method, Status: status,
			Headers: responseHeaders, Body: body, Step: step,
		}
		s.addEndpoint(rawURL, method, status, step, "")
		req := s.appendRequestRecord(step, "http_raw", method, rawURL, requestBody, status, responseHeaders, body)
		if len(headers) > 0 && !containsString(req.OutcomeTags, "custom_headers") {
			req.OutcomeTags = append(req.OutcomeTags, "custom_headers")
			s.requests[len(s.requests)-1] = req
		}
		s.updateEvidenceFromRequest(req)
	}

	return summarizeHTTP(method, rawURL, status, responseHeaders, body)
}

func (s *SessionStore) recordHTTPRequest(args, observation string, step int) string {
	reqSpec, err := parseHTTPRequestSpec(args)
	if err != nil {
		return fmt.Sprintf("ERROR: could not parse http_request args: %v", err)
	}

	status, responseHeaders, body := parseHTTPObservation(observation)
	key := reqSpec.Method + "|" + reqSpec.URL
	s.responses[key] = ResponseRecord{
		URL: reqSpec.URL, Method: reqSpec.Method, Status: status,
		Headers: responseHeaders, Body: body, Step: step,
	}
	s.addEndpoint(reqSpec.URL, reqSpec.Method, status, step, "")
	rec := s.appendRequestRecord(step, "http_request", reqSpec.Method, reqSpec.URL, reqSpec.Body, status, responseHeaders, body)
	s.updateEvidenceFromRequest(rec)
	return summarizeHTTP(reqSpec.Method, reqSpec.URL, status, responseHeaders, body)
}

func (s *SessionStore) recordRecon(tool, args, observation string) string {
	key := tool + "|" + args
	s.recon[key] = observation

	// For katana, extract URLs into endpoints even from TIMEOUT output.
	if tool == "run_katana" {
		return s.recordKatana(observation)
	}

	if strings.HasPrefix(observation, "ERROR:") || strings.HasPrefix(observation, "TIMEOUT:") {
		return truncateStoredObservation(observation, 500)
	}

	lines := strings.Split(strings.TrimSpace(observation), "\n")
	count := len(lines)

	switch tool {
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

// recordKatana parses katana output (including TIMEOUT partial output) and
// registers discovered URLs as endpoints so they appear in recall endpoints.
func (s *SessionStore) recordKatana(observation string) string {
	if strings.HasPrefix(observation, "ERROR:") {
		return truncateStoredObservation(observation, 500)
	}

	lines := strings.Split(strings.TrimSpace(observation), "\n")
	var urlLines []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			urlLines = append(urlLines, line)
		}
	}

	// Register each discovered URL as an endpoint.
	for _, u := range urlLines {
		s.addEndpoint(u, "GET", 0, s.step, "katana")
	}

	paths := extractPaths(urlLines, 8)
	prefix := ""
	if strings.HasPrefix(observation, "TIMEOUT:") {
		prefix = "(partial) "
	}
	return fmt.Sprintf("%sFound %d endpoints. Key paths: %s. Full list stored — use `recall endpoints` or `recall search <keyword>` to find specific endpoints.",
		prefix, len(urlLines), strings.Join(paths, ", "))
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
		return truncateStoredObservation(observation, 1200)
	}
	return truncateStoredObservation(observation, 1200)
}

func (s *SessionStore) recordBrowserOpen(args, observation string) string {
	return observation
}

func (s *SessionStore) recordFinding(args string) {
	var f Finding
	if err := json.Unmarshal([]byte(strings.TrimSpace(args)), &f); err != nil {
		return
	}
	s.findings = append(s.findings, f)
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
	rawURL = stripOuterQuotes(strings.TrimSpace(rawURL))
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

func (s *SessionStore) recallLastResponse() string {
	if len(s.requests) == 0 {
		return "No stored HTTP responses yet."
	}
	r := s.requests[len(s.requests)-1]
	return fmt.Sprintf("HTTP TEST %s step %d\n%s %s -> %d\nRequest body sha256=%s\nOutcome tags: %s\n%s\n\n%s",
		r.ID, r.Step, r.Method, r.URL, r.Status, r.BodyHash, strings.Join(r.OutcomeTags, ", "), r.Headers, r.Body)
}

func (s *SessionStore) recallEndpoint(filter string) string {
	filter = strings.ToLower(stripOuterQuotes(strings.TrimSpace(filter)))
	var rows []string
	for _, ep := range s.endpoints {
		if filter == "" || strings.Contains(strings.ToLower(ep.URL), filter) {
			rows = append(rows, fmt.Sprintf("[endpoint] %s %s [%d] step=%d %s", ep.Method, ep.URL, ep.Status, ep.Step, ep.Note))
		}
	}
	for _, r := range s.requests {
		hay := strings.ToLower(r.Method + " " + r.URL + " " + strings.Join(r.OutcomeTags, " "))
		if filter == "" || strings.Contains(hay, filter) {
			rows = append(rows, formatRequestRecord(r))
		}
	}
	if len(rows) == 0 {
		return fmt.Sprintf("No endpoint/test records matching %q.", filter)
	}
	if len(rows) > 40 {
		rows = append(rows[:40], fmt.Sprintf("... and %d more records", len(rows)-40))
	}
	return strings.Join(rows, "\n")
}

func (s *SessionStore) recallTests(filter string) string {
	filter = strings.ToLower(strings.TrimSpace(filter))
	var rows []string
	for _, r := range s.requests {
		hay := strings.ToLower(r.ID + " " + r.Tool + " " + r.Method + " " + r.URL + " " + r.RequestBody + " " + r.Body + " " + strings.Join(r.OutcomeTags, " "))
		if filter == "" || strings.Contains(hay, filter) {
			rows = append(rows, formatRequestRecord(r))
		}
	}
	if len(rows) == 0 {
		return fmt.Sprintf("No HTTP tests matching %q.", filter)
	}
	if len(rows) > 30 {
		rows = append(rows[:30], fmt.Sprintf("... and %d more tests", len(rows)-30))
	}
	return strings.Join(rows, "\n")
}

func (s *SessionStore) recallEvidence(status string) string {
	var rows []string
	for _, ev := range s.evidence {
		if ev.Status == status {
			rows = append(rows, fmt.Sprintf("- %s @ %s (%s): %s [step %d request=%s]", ev.Class, ev.URL, ev.Primitive, ev.Reason, ev.Step, ev.RequestID))
		}
	}
	if len(rows) == 0 {
		return fmt.Sprintf("No %s evidence recorded.", status)
	}
	return strings.Join(rows, "\n")
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

	for _, r := range s.requests {
		hay := strings.ToLower(r.ID + " " + r.Method + " " + r.URL + " " + r.RequestBody + " " + r.Body + " " + strings.Join(r.OutcomeTags, " "))
		if strings.Contains(hay, kw) {
			results = append(results, "[test] "+formatRequestRecord(r))
		}
	}

	for _, ev := range s.evidence {
		hay := strings.ToLower(ev.Class + " " + ev.URL + " " + ev.Primitive + " " + ev.Status + " " + ev.Reason)
		if strings.Contains(hay, kw) {
			results = append(results, fmt.Sprintf("[evidence %s] %s @ %s: %s", ev.Status, ev.Class, ev.URL, ev.Reason))
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

type httpRequestSpec struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

func parseHTTPRequestSpec(args string) (httpRequestSpec, error) {
	var spec httpRequestSpec
	if err := json.Unmarshal([]byte(strings.TrimSpace(args)), &spec); err != nil {
		return spec, err
	}
	spec.Method = strings.ToUpper(strings.TrimSpace(spec.Method))
	if spec.Method == "" {
		spec.Method = "GET"
	}
	spec.URL = strings.TrimSpace(spec.URL)
	if spec.URL == "" {
		return spec, fmt.Errorf("url is required")
	}
	return spec, nil
}

func parseHTTPRawParts(parts []string) (map[string]string, string) {
	headers := make(map[string]string)
	var bodyStr string
	for _, p := range parts {
		p = stripBrackets(p)
		if p == "" {
			continue
		}
		switch {
		case strings.HasPrefix(p, "body:"):
			bodyStr = strings.TrimSpace(strings.TrimPrefix(p, "body:"))
		case strings.HasPrefix(p, "body="):
			bodyStr = strings.TrimSpace(strings.TrimPrefix(p, "body="))
		case looksLikeJSONBody(p):
			bodyStr = p
		default:
			if idx := strings.Index(p, ":"); idx > 0 {
				name := strings.TrimSpace(p[:idx])
				value := strings.TrimSpace(p[idx+1:])
				if name != "" && isValidHeaderName(name) {
					headers[name] = value
				} else if name != "" {
					bodyStr = p
				}
			}
		}
	}
	return headers, bodyStr
}

func (s *SessionStore) appendRequestRecord(step int, tool, method, rawURL, requestBody string, status int, headers, body string) RequestRecord {
	id := fmt.Sprintf("http-%03d", len(s.requests)+1)
	req := RequestRecord{
		ID:          id,
		Tool:        tool,
		Method:      method,
		URL:         rawURL,
		Status:      status,
		Headers:     headers,
		Body:        body,
		RequestBody: requestBody,
		BodyHash:    shortSHA256(requestBody),
		Step:        step,
		OutcomeTags: classifyHTTPOutcome(status, headers, body, requestBody),
	}
	s.requests = append(s.requests, req)
	return req
}

func (s *SessionStore) updateEvidenceFromRequest(r RequestRecord) {
	classes := inferVulnClasses(r.RequestBody + "\n" + r.URL)
	if len(classes) == 0 {
		return
	}
	for _, class := range classes {
		status, reason := evidenceStatusFor(class, r)
		if status == "" {
			continue
		}
		s.evidence = append(s.evidence, EvidenceRecord{
			Class:     class,
			URL:       r.URL,
			Primitive: primitiveFor(class, r),
			Status:    status,
			Reason:    reason,
			Step:      r.Step,
			RequestID: r.ID,
		})
	}
}

func inferVulnClasses(text string) []string {
	lower := strings.ToLower(text)
	var out []string
	if strings.Contains(lower, "<!doctype") || strings.Contains(lower, "<!entity") ||
		strings.Contains(lower, "file:///") || strings.Contains(lower, "system \"http") {
		out = append(out, "xxe")
	}
	if strings.Contains(lower, "<script") || strings.Contains(lower, "onerror=") ||
		strings.Contains(lower, "onload=") || strings.Contains(lower, "javascript:") {
		out = append(out, "xss")
	}
	if strings.Contains(lower, "' or '1'='1") || strings.Contains(lower, " union select ") ||
		strings.Contains(lower, "sleep(") || strings.Contains(lower, "benchmark(") {
		out = append(out, "sqli")
	}
	return out
}

func evidenceStatusFor(class string, r RequestRecord) (string, string) {
	bodyLower := strings.ToLower(r.Body)
	allLower := strings.ToLower(r.Headers + "\n" + r.Body)
	switch class {
	case "xxe":
		if strings.Contains(allLower, "entities are not allowed") ||
			strings.Contains(allLower, "doctype is disallowed") ||
			strings.Contains(allLower, "external entity") ||
			strings.Contains(allLower, "entity resolution is disabled") {
			return "negative", firstReason(r.Body, "XML entity expansion rejected by parser/security controls")
		}
		if strings.Contains(bodyLower, "root:x:0:0:") || strings.Contains(bodyLower, "daemon:x:") {
			return "confirmed", "response contains /etc/passwd markers"
		}
		if r.Status >= 200 && r.Status < 300 && looksNumericOnly(r.Body) {
			return "negative", "response is only numeric/text stock data, not entity disclosure"
		}
	case "xss":
		if !requestPayloadReflected(r.RequestBody, r.Body) && r.Status >= 200 && r.Status < 300 {
			return "negative", "payload markers were not reflected in response"
		}
	case "sqli":
		if containsSQLError(r.Body) {
			return "confirmed", "response contains SQL error marker"
		}
	}
	return "", ""
}

func classifyHTTPOutcome(status int, headers, body, requestBody string) []string {
	var tags []string
	if status >= 400 {
		tags = append(tags, fmt.Sprintf("http_%d", status))
	}
	if shouldPreviewHTTPBody(status, extractHeader(headers, "Content-Type"), body) {
		tags = append(tags, "body_previewed")
	}
	lowerBody := strings.ToLower(body)
	if strings.Contains(lowerBody, "entities are not allowed") {
		tags = append(tags, "entities_blocked")
	}
	if looksNumericOnly(body) {
		tags = append(tags, "numeric_body")
	}
	for _, class := range inferVulnClasses(requestBody) {
		tags = append(tags, "probe_"+class)
	}
	return uniqueStrings(tags)
}

func primitiveFor(class string, r RequestRecord) string {
	body := strings.ToLower(r.RequestBody)
	switch class {
	case "xxe":
		switch {
		case strings.Contains(body, "file:///"):
			return "file_entity"
		case strings.Contains(body, "system \"http") || strings.Contains(body, "system 'http"):
			return "external_entity"
		default:
			return "entity"
		}
	case "xss":
		return "reflection"
	case "sqli":
		return "injection"
	default:
		return "probe"
	}
}

func formatRequestRecord(r RequestRecord) string {
	bodyPreview := strings.TrimSpace(r.Body)
	if len(bodyPreview) > 120 {
		bodyPreview = bodyPreview[:120] + "..."
	}
	tags := strings.Join(r.OutcomeTags, ",")
	if tags == "" {
		tags = "no-tags"
	}
	return fmt.Sprintf("[%s step=%d] %s %s -> %d tags=%s req_sha=%s body=%q",
		r.ID, r.Step, r.Method, r.URL, r.Status, tags, r.BodyHash, bodyPreview)
}

func lastRequests(items []RequestRecord, n int) []RequestRecord {
	if len(items) <= n {
		return items
	}
	return items[len(items)-n:]
}

func lastEvidenceByStatus(items []EvidenceRecord, status string, n int) []EvidenceRecord {
	var filtered []EvidenceRecord
	for _, ev := range items {
		if ev.Status == status {
			filtered = append(filtered, ev)
		}
	}
	if len(filtered) <= n {
		return filtered
	}
	return filtered[len(filtered)-n:]
}

func firstReason(body, fallback string) string {
	line := strings.TrimSpace(body)
	if line == "" {
		return fallback
	}
	line = strings.SplitN(line, "\n", 2)[0]
	if len(line) > 140 {
		line = line[:140] + "..."
	}
	return line
}

func looksNumericOnly(body string) bool {
	body = strings.TrimSpace(body)
	if body == "" || len(body) > 32 {
		return false
	}
	for _, r := range body {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func requestPayloadReflected(requestBody, responseBody string) bool {
	markers := []string{"<script", "onerror=", "onload=", "javascript:"}
	rb := strings.ToLower(responseBody)
	req := strings.ToLower(requestBody)
	for _, marker := range markers {
		if strings.Contains(req, marker) && strings.Contains(rb, marker) {
			return true
		}
	}
	return false
}

func containsSQLError(body string) bool {
	lower := strings.ToLower(body)
	markers := []string{"sql syntax", "mysql", "postgresql", "ora-", "sqlite", "unterminated quoted string"}
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func shortSHA256(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}

func uniqueStrings(items []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, item := range items {
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
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

	if shouldPreviewHTTPBody(status, ct, body) {
		preview := strings.TrimSpace(body)
		if len(preview) > 220 {
			preview = preview[:220] + "..."
		}
		sb.WriteString(fmt.Sprintf(" BodyPreview: %q", preview))
	}

	sb.WriteString(" (full response stored)")
	return sb.String()
}

func shouldPreviewHTTPBody(status int, contentType, body string) bool {
	body = strings.TrimSpace(body)
	if body == "" {
		return false
	}
	lct := strings.ToLower(contentType)
	if status >= 400 {
		return true
	}
	if len(body) <= 500 && (strings.Contains(lct, "text/plain") ||
		strings.Contains(lct, "application/json") ||
		strings.Contains(lct, "application/xml") ||
		strings.Contains(lct, "text/xml")) {
		return true
	}
	lb := strings.ToLower(body)
	interesting := []string{"not allowed", "invalid", "forbidden", "error", "stack", "trace", "token", "admin", "exception"}
	for _, marker := range interesting {
		if strings.Contains(lb, marker) {
			return true
		}
	}
	return false
}

func truncateStoredObservation(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + fmt.Sprintf("\n[... %d bytes total, stored — use recall if needed ...]", len(s))
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
