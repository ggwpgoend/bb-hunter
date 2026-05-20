package agent

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSessionStore_RecordHTTPGet(t *testing.T) {
	s := NewSessionStore()

	obs := "HTTP 200 200 OK\nContent-Type: text/html; charset=utf-8\nX-Frame-Options: DENY\n\n<html><body><form action=\"/login\" method=\"POST\"><input name=\"user\"/></form><script src=\"/js/app.js\"></script></body></html>"

	compact := s.Record(1, "http_get", "https://example.com/", obs)

	// Compact summary should mention status, content type, and be short
	if !strings.Contains(compact, "HTTP 200") {
		t.Errorf("compact should contain status, got: %s", compact)
	}
	if !strings.Contains(compact, "stored") {
		t.Errorf("compact should mention stored, got: %s", compact)
	}

	// Full response should be stored
	full := s.Recall("http https://example.com/")
	if !strings.Contains(full, "X-Frame-Options") {
		t.Errorf("recalled response should contain full headers, got: %s", full)
	}
	if !strings.Contains(full, "<form") {
		t.Errorf("recalled response should contain full body, got: %s", full)
	}

	// Endpoints should be tracked
	eps := s.Recall("endpoints")
	if !strings.Contains(eps, "https://example.com/") {
		t.Errorf("endpoints should list the URL, got: %s", eps)
	}
}

func TestSessionStore_RecordHTTPRaw(t *testing.T) {
	s := NewSessionStore()

	obs := "HTTP 200 200 OK\nContent-Type: application/json\n\n{\"id\":1,\"name\":\"test\"}"

	compact := s.Record(2, "http_raw", `POST https://example.com/api/users "Content-Type: application/json" "body:{\"name\":\"test\"}"`, obs)

	if !strings.Contains(compact, "HTTP 200") {
		t.Errorf("compact should contain status, got: %s", compact)
	}

	full := s.Recall("http https://example.com/api/users")
	if !strings.Contains(full, `"name":"test"`) {
		t.Errorf("recalled response should contain JSON body, got: %s", full)
	}
}

func TestSessionStore_RecordKatana(t *testing.T) {
	s := NewSessionStore()

	lines := []string{
		"https://example.com/",
		"https://example.com/login",
		"https://example.com/api/v1/users",
		"https://example.com/catalog?id=1",
		"https://example.com/search?q=test",
	}
	obs := strings.Join(lines, "\n")

	compact := s.Record(3, "run_katana", "https://example.com", obs)

	if !strings.Contains(compact, "5 endpoints") {
		t.Errorf("compact should mention endpoint count, got: %s", compact)
	}
	if !strings.Contains(compact, "stored") {
		t.Errorf("compact should mention stored, got: %s", compact)
	}

	// Full output should be searchable
	search := s.Recall("search users")
	if !strings.Contains(search, "users") {
		t.Errorf("search for 'users' should find the recon output, got: %s", search)
	}
}

func TestSessionStore_RecordJSFile(t *testing.T) {
	s := NewSessionStore()

	jsBody := "function checkStock(id) { return fetch('/api/stock/' + id); }"
	obs := fmt.Sprintf("HTTP 200 200 OK\nContent-Type: application/javascript\n\n%s", jsBody)

	s.Record(4, "http_get", "https://example.com/js/stockCheck.js", obs)

	// JS source should be stored
	js := s.Recall("js stockCheck")
	if !strings.Contains(js, "checkStock") {
		t.Errorf("recalled JS should contain source, got: %s", js)
	}
}

func TestSessionStore_RecallSearch(t *testing.T) {
	s := NewSessionStore()

	// Record some data
	s.Record(1, "http_get", "https://example.com/login",
		"HTTP 200 200 OK\nContent-Type: text/html\n\n<html><form><input name='csrf_token' value='abc123'/></form></html>")
	s.Record(2, "http_get", "https://example.com/api/users",
		"HTTP 200 200 OK\nContent-Type: application/json\n\n{\"users\":[{\"id\":1}]}")

	results := s.Recall("search csrf")
	if !strings.Contains(results, "csrf") {
		t.Errorf("search should find csrf in body, got: %s", results)
	}

	results = s.Recall("search nonexistent_keyword_xyz")
	if !strings.Contains(results, "No results") {
		t.Errorf("search for nonexistent should return no results, got: %s", results)
	}
}

func TestSessionStore_RecallEndpointsEmpty(t *testing.T) {
	s := NewSessionStore()
	result := s.Recall("endpoints")
	if !strings.Contains(result, "No endpoints") {
		t.Errorf("empty store should say no endpoints, got: %s", result)
	}
}

func TestSessionStore_RecallErrors(t *testing.T) {
	s := NewSessionStore()

	tests := []struct {
		query    string
		wantErr  string
	}{
		{"", "ERROR:"},
		{"http", "ERROR:"},
		{"js", "ERROR:"},
		{"search", "ERROR:"},
		{"unknown_type", "ERROR:"},
	}

	for _, tt := range tests {
		result := s.Recall(tt.query)
		if !strings.HasPrefix(result, tt.wantErr) {
			t.Errorf("Recall(%q) = %q, want prefix %q", tt.query, result, tt.wantErr)
		}
	}
}

func TestSessionStore_MemoryBlock(t *testing.T) {
	s := NewSessionStore()

	// Record some data
	s.Record(1, "http_get", "https://example.com/",
		"HTTP 200 200 OK\nContent-Type: text/html\n\n<html></html>")
	s.Record(2, "http_get", "https://example.com/api/v1/users",
		"HTTP 200 200 OK\nContent-Type: application/json\n\n{}")

	hypotheses := []hypothesis{
		{Class: "idor", URL: "https://example.com/api/v1/users", Why: "numeric id in URL", Created: time.Now(), Updated: time.Now(), Mentions: 1},
	}

	block := s.MemoryBlock(hypotheses)

	if !strings.Contains(block, "[SESSION MEMORY]") {
		t.Error("block should contain [SESSION MEMORY] header")
	}
	if !strings.Contains(block, "[/SESSION MEMORY]") {
		t.Error("block should contain [/SESSION MEMORY] footer")
	}
	if !strings.Contains(block, "idor") {
		t.Error("block should contain hypothesis")
	}
	if !strings.Contains(block, "Endpoints: 2") {
		t.Errorf("block should show endpoint count, got:\n%s", block)
	}
	if !strings.Contains(block, "ATTACK SURFACE") {
		t.Error("block should contain attack surface section")
	}
	if !strings.Contains(block, "recall") {
		t.Error("block should mention recall tool")
	}
}

func TestSessionStore_MemoryBlockEmpty(t *testing.T) {
	s := NewSessionStore()
	block := s.MemoryBlock(nil)

	if !strings.Contains(block, "Step: 0") {
		t.Errorf("empty store block should show step 0, got:\n%s", block)
	}
	if strings.Contains(block, "HYPOTHESES") {
		t.Error("empty store should not have hypotheses section")
	}
}

func TestSessionStore_EndpointDedup(t *testing.T) {
	s := NewSessionStore()

	// Same endpoint fetched twice: should not duplicate
	s.Record(1, "http_get", "https://example.com/api",
		"HTTP 200 200 OK\nContent-Type: application/json\n\n{}")
	s.Record(5, "http_get", "https://example.com/api",
		"HTTP 200 200 OK\nContent-Type: application/json\n\n{\"updated\":true}")

	s.mu.RLock()
	count := len(s.endpoints)
	s.mu.RUnlock()

	if count != 1 {
		t.Errorf("expected 1 endpoint after dedup, got %d", count)
	}

	// Latest response should be stored
	full := s.Recall("http https://example.com/api")
	if !strings.Contains(full, "updated") {
		t.Error("latest response should be stored")
	}
}

func TestSessionStore_RecordPassthrough(t *testing.T) {
	s := NewSessionStore()

	// Tools that should pass through without modification
	passthroughTools := []struct {
		tool string
		args string
		obs  string
	}{
		{"browser_click", "@e30", "OK: clicked @e30"},
		{"browser_type", "@e4 test", "OK: typed into @e4"},
		{"browser_screenshot", "shot.png", "OK: screenshot saved to screenshots/shot.png"},
		{"report_finding", `{"vuln_class":"xss"}`, "OK: finding #1 reported"},
	}

	for _, tt := range passthroughTools {
		compact := s.Record(1, tt.tool, tt.args, tt.obs)
		if compact != tt.obs {
			t.Errorf("Record(%q) = %q, want passthrough %q", tt.tool, compact, tt.obs)
		}
	}
}

func TestSessionStore_ErrorObservationPassthrough(t *testing.T) {
	s := NewSessionStore()

	compact := s.Record(1, "run_katana", "https://example.com",
		"ERROR: katana: command not found")

	if !strings.HasPrefix(compact, "ERROR:") {
		t.Errorf("error observations should pass through, got: %s", compact)
	}
}

func TestSummarizeHTTP(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		url     string
		status  int
		headers string
		body    string
		wantContains []string
	}{
		{
			name:    "HTML with forms",
			method:  "GET",
			url:     "https://example.com/",
			status:  200,
			headers: "Content-Type: text/html; charset=utf-8\nX-Frame-Options: DENY",
			body:    "<html><body><form action='/login'><input/></form><script src='/app.js'></script></body></html>",
			wantContains: []string{"HTTP 200", "text/html", "Forms: 1", "Scripts: 1", "stored"},
		},
		{
			name:    "JSON API response",
			method:  "GET",
			url:     "https://example.com/api/users",
			status:  200,
			headers: "Content-Type: application/json",
			body:    `{"users":[]}`,
			wantContains: []string{"HTTP 200", "application/json", "stored"},
		},
		{
			name:    "404 error",
			method:  "GET",
			url:     "https://example.com/notfound",
			status:  404,
			headers: "Content-Type: text/html",
			body:    "Not Found",
			wantContains: []string{"HTTP 404", "Body: Not Found", "stored"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := summarizeHTTP(tt.method, tt.url, tt.status, tt.headers, tt.body)
			for _, want := range tt.wantContains {
				if !strings.Contains(result, want) {
					t.Errorf("summarizeHTTP() = %q, missing %q", result, want)
				}
			}
		})
	}
}

func TestExtractPaths(t *testing.T) {
	lines := []string{
		"https://example.com/",
		"https://example.com/login",
		"https://example.com/api/v1/users?id=1",
		"https://example.com/api/v1/users?id=2",
		"https://example.com/search?q=test",
	}

	paths := extractPaths(lines, 10)
	if len(paths) != 4 { // /login, /api/v1/users?id=1, /api/v1/users?id=2, /search?q=test (/ is skipped)
		t.Errorf("extractPaths returned %d paths, want 4: %v", len(paths), paths)
	}
}

func TestRecallToolViaExecutor(t *testing.T) {
	te := NewToolExecutor("", "", "")
	store := NewSessionStore()
	te.store = store

	// Record some data
	store.Record(1, "http_get", "https://example.com/",
		"HTTP 200 200 OK\nContent-Type: text/html\n\n<html></html>")

	// Recall via executor — recall doesn't need ctx but Execute wraps it
	ctx := t.Context()
	result := te.Execute(ctx, "recall", "endpoints")
	if !strings.Contains(result, "https://example.com/") {
		t.Errorf("recall via executor should work, got: %s", result)
	}
}

func TestRecallToolWithoutStore(t *testing.T) {
	te := NewToolExecutor("", "", "")
	// No store set
	ctx := t.Context()
	result := te.Execute(ctx, "recall", "endpoints")
	if !strings.HasPrefix(result, "ERROR:") {
		t.Errorf("recall without store should error, got: %s", result)
	}
}
