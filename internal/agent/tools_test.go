package agent

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestStripOuterQuotes(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{`"`, `"`},
		{`'`, `'`},
		{`"a"`, `a`},
		{`'a'`, `a`},
		{`"hello world"`, `hello world`},
		{`'hello world'`, `hello world`},
		{`  "hello"  `, `hello`},
		{`hello`, `hello`},
		{`"unbalanced`, `"unbalanced`},
		{`unbalanced"`, `unbalanced"`},
		{`"mixed'`, `"mixed'`},
		{`""`, ``},
		{`''`, ``},
		// URL with single quotes inside double-quote pair (the failing case from the log).
		{`"https://example.com/?p=1' OR '1'='1"`, `https://example.com/?p=1' OR '1'='1`},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := stripOuterQuotes(tc.in); got != tc.want {
				t.Fatalf("stripOuterQuotes(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSplitArgsQuoteAware(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"a b c", []string{"a", "b", "c"}},
		{`a  "b c"  d`, []string{"a", "b c", "d"}},
		{`a 'b c' d`, []string{"a", "b c", "d"}},
		{`"only one"`, []string{"only one"}},
		// Header-value with space inside double quotes.
		{`POST https://x "Content-Type: application/xml" "body:<?xml v?>"`,
			[]string{"POST", "https://x", "Content-Type: application/xml", "body:<?xml v?>"}},
		// Backslash-escaped inner quote: \"hello\" inside "..."
		{`"\"hello\""`, []string{`"hello"`}},
		{`a "b \"c\" d" e`, []string{"a", `b "c" d`, "e"}},
		// Unterminated quote: keep the partial field.
		{`a "unterminated`, []string{"a", "unterminated"}},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := splitArgsQuoteAware(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("splitArgsQuoteAware(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

func TestSplitFirstField(t *testing.T) {
	cases := []struct {
		in          string
		first, rest string
		ok          bool
	}{
		{"", "", "", false},
		{"only", "only", "", true},
		{"a b c", "a", "b c", true},
		{`#sel "hello world"`, "#sel", "hello world", true},
		{`#sel hello world`, "#sel", "hello world", true},
		{`"#sel with space" rest of text`, "#sel with space", "rest of text", true},
		{`@e5 some "quoted text"`, "@e5", `some "quoted text"`, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			first, rest, ok := splitFirstField(tc.in)
			if ok != tc.ok || first != tc.first || rest != tc.rest {
				t.Fatalf("splitFirstField(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tc.in, first, rest, ok, tc.first, tc.rest, tc.ok)
			}
		})
	}
}

// TestHttpGetStripsOuterQuotes reproduces the failure from the agent log
// where the LLM wrapped the URL in double quotes and the URL parser rejected
// the literal " character ("first path segment in URL cannot contain colon").
func TestHttpGetStripsOuterQuotes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "ok:"+r.URL.RawQuery)
	}))
	defer srv.Close()

	te := NewToolExecutor("", "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The exact SQLi probe the LLM tried in the log, URL-encoded so it's a
	// well-formed URL once the outer quotes have been removed.
	quoted := `"` + srv.URL + `?productId=1%27%20OR%20%271%27%3D%271"`
	got := te.httpGet(ctx, quoted)
	if strings.Contains(got, "first path segment in URL cannot contain colon") {
		t.Fatalf("httpGet still mishandles quoted URL: %s", got)
	}
	if !strings.Contains(got, "HTTP 200") {
		t.Fatalf("expected HTTP 200, got: %s", got)
	}
	if !strings.Contains(got, "ok:productId=") {
		t.Fatalf("expected querystring to reach server, got: %s", got)
	}

	// Single-quoted form should also work.
	quoted = `'` + srv.URL + `?q=hello'`
	got = te.httpGet(ctx, quoted)
	if !strings.Contains(got, "HTTP 200") {
		t.Fatalf("single-quoted URL: expected HTTP 200, got: %s", got)
	}
	if !strings.Contains(got, "ok:q=hello") {
		t.Fatalf("single-quoted URL: querystring missing: %s", got)
	}
}

// TestHttpRawHandlesHeaderAndBodyWithSpaces reproduces the failures in the log
// where invocations like
//
//	http_raw POST <url> "Content-Type: application/xml" "<xml body>"
//
// produced  invalid header field name "\"Content-Type"  and never sent
// anything to the server.
func TestHttpRawHandlesHeaderAndBodyWithSpaces(t *testing.T) {
	var (
		gotMethod      string
		gotContentType string
		gotBody        string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "received")
	}))
	defer srv.Close()

	te := NewToolExecutor("", "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	xml := `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>`

	// Shell-escaped inner double quotes (\" inside "..."). This is the
	// exact wire form the LLM produced in the original log; it should now
	// reach the server intact.
	escaped := strings.ReplaceAll(xml, `"`, `\"`)
	args := "POST " + srv.URL + ` "Content-Type: application/xml" "body:` + escaped + `"`

	got := te.httpRaw(ctx, args)
	if strings.Contains(got, "invalid header field name") {
		t.Fatalf("httpRaw still produces invalid-header-field error: %s", got)
	}
	if !strings.Contains(got, "HTTP 200") {
		t.Fatalf("expected HTTP 200, got: %s", got)
	}
	if gotMethod != "POST" {
		t.Fatalf("want POST, got %q", gotMethod)
	}
	if gotContentType != "application/xml" {
		t.Fatalf("want Content-Type 'application/xml', got %q", gotContentType)
	}
	if gotBody != xml {
		t.Fatalf("body mismatch.\nwant: %s\ngot:  %s", xml, gotBody)
	}

	// Single-quoted outer with un-escaped inner double quotes is also a
	// natural form for XML payloads and must work unchanged.
	gotBody = ""
	args = "POST " + srv.URL + ` "Content-Type: application/xml" 'body:` + xml + `'`
	got = te.httpRaw(ctx, args)
	if !strings.Contains(got, "HTTP 200") {
		t.Fatalf("single-quoted outer: expected HTTP 200, got: %s", got)
	}
	if gotBody != xml {
		t.Fatalf("single-quoted outer body mismatch.\nwant: %s\ngot:  %s", xml, gotBody)
	}
}

func TestHttpRequestStructuredJSON(t *testing.T) {
	var (
		gotMethod      string
		gotContentType string
		gotBody        string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	te := NewToolExecutor("", "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	args := `{"method":"POST","url":"` + srv.URL + `","headers":{"Content-Type":"application/xml"},"body":"<?xml version=\"1.0\"?><stockCheck><productId>1</productId></stockCheck>"}`
	got := te.httpRequest(ctx, args)
	if !strings.Contains(got, "HTTP 200") {
		t.Fatalf("expected HTTP 200, got: %s", got)
	}
	if gotMethod != "POST" {
		t.Fatalf("method = %q, want POST", gotMethod)
	}
	if gotContentType != "application/xml" {
		t.Fatalf("content type = %q", gotContentType)
	}
	if !strings.Contains(gotBody, "<stockCheck>") {
		t.Fatalf("body did not reach server: %q", gotBody)
	}
}

// TestHttpRawAcceptsLegacyUnquotedSyntax ensures we didn't regress the
// pre-existing (no-spaces) usage.
func TestHttpRawAcceptsLegacyUnquotedSyntax(t *testing.T) {
	var gotCustom string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCustom = r.Header.Get("X-Probe")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	te := NewToolExecutor("", "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got := te.httpRaw(ctx, "GET "+srv.URL+" X-Probe:hello")
	if !strings.Contains(got, "HTTP 200") {
		t.Fatalf("expected HTTP 200, got: %s", got)
	}
	if gotCustom != "hello" {
		t.Fatalf("want X-Probe 'hello', got %q", gotCustom)
	}
}

// TestRunCmdStripsOuterQuotes reproduces the failure mode where the LLM wrote
//
//	ACTION: run_cmd "curl -X POST ..."
//
// and sh saw a leading " and reported "Syntax error: Unterminated quoted string".
func TestRunCmdStripsOuterQuotes(t *testing.T) {
	te := NewToolExecutor("", "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got := te.runCmd(ctx, `"echo hello-from-quoted-cmd"`)
	if strings.Contains(got, "Unterminated quoted string") {
		t.Fatalf("runCmd still hits unterminated-quote error: %s", got)
	}
	if !strings.Contains(got, "hello-from-quoted-cmd") {
		t.Fatalf("expected echo output, got: %s", got)
	}

	// Single-quoted form should also work.
	got = te.runCmd(ctx, `'echo hello-from-single-quoted'`)
	if !strings.Contains(got, "hello-from-single-quoted") {
		t.Fatalf("expected echo output for single-quoted form, got: %s", got)
	}

	// Legacy un-quoted form is unaffected.
	got = te.runCmd(ctx, `echo legacy-form`)
	if !strings.Contains(got, "legacy-form") {
		t.Fatalf("legacy form regressed: %s", got)
	}
}

// TestRunCmdStillBlocksDestructive guards against the strip helper accidentally
// bypassing the destructive-command filter.
func TestRunCmdStillBlocksDestructive(t *testing.T) {
	te := NewToolExecutor("", "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	got := te.runCmd(ctx, `"rm -rf /"`)
	if !strings.Contains(got, "destructive commands are not allowed") {
		t.Fatalf("destructive filter regressed: %s", got)
	}
}

// TestBrowserDefaults verifies the new ToolExecutor browser-knob defaults
// are sane and that the WithBrowser* setters propagate.
func TestBrowserDefaults(t *testing.T) {
	te := NewToolExecutor("", "", "")
	if te.browserDefaultTimeoutMS != 60_000 {
		t.Fatalf("default AGENT_BROWSER_DEFAULT_TIMEOUT = %d, want 60_000", te.browserDefaultTimeoutMS)
	}
	if te.browserSessionName != "bb-hunter" {
		t.Fatalf("default --session = %q, want bb-hunter", te.browserSessionName)
	}
	if !te.browserCloseOnTimeout {
		t.Fatalf("default browserCloseOnTimeout should be true")
	}

	te.WithBrowserSession("verifier").WithBrowserDefaultTimeoutMS(90_000)
	if te.browserSessionName != "verifier" {
		t.Fatalf("WithBrowserSession failed: %q", te.browserSessionName)
	}
	if te.browserDefaultTimeoutMS != 90_000 {
		t.Fatalf("WithBrowserDefaultTimeoutMS failed: %d", te.browserDefaultTimeoutMS)
	}
}

// TestBrowserHealthCheckMissingBinary ensures the doctor disables the
// browser when the binary is missing, instead of every browser_* paying
// the 60s timeout cost on Chrome cold-starts that will never happen.
func TestBrowserHealthCheckMissingBinary(t *testing.T) {
	te := NewToolExecutor("agent-browser-definitely-not-installed-xyz", "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	te.BrowserHealthCheck(ctx)

	if !te.browserDisabled {
		t.Fatalf("expected browserDisabled=true after missing-binary doctor, got false")
	}
	if !strings.Contains(te.browserDoctorReason, "not found on PATH") {
		t.Fatalf("expected reason to mention PATH, got %q", te.browserDoctorReason)
	}

	// Subsequent browser_* must fast-fail with the hint, no spawn.
	got := te.browserOpen(ctx, "https://example.com")
	if !strings.Contains(got, "agent-browser disabled") {
		t.Fatalf("expected disabled-hint ERROR, got: %s", got)
	}
	if !strings.Contains(got, "http_get") {
		t.Fatalf("expected fallback hint, got: %s", got)
	}
}

// TestIsCDPTimeoutErr — the regex/substring detector for the
// "✗ CDP command timed out" stderr pattern that triggers daemon reset.
func TestIsCDPTimeoutErr(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"some unrelated error\n", false},
		{"✗ CDP command timed out: Page.navigate", true},
		{"WARN CDP command timed out: Runtime.evaluate\n", true},
		{"Error: Failed to connect to Chrome on 127.0.0.1:9222", true},
		{"No such session found in daemon", true},
		{"Selector @e3 not found", false}, // a well-formed CLI error, NOT a daemon failure
	}
	for _, tc := range cases {
		if got := isCDPTimeoutErr(tc.in); got != tc.want {
			t.Errorf("isCDPTimeoutErr(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestArgsPreviewTruncation guards that very long eval payloads are
// length-capped before going into slog (avoids unreadable log lines).
func TestArgsPreviewTruncation(t *testing.T) {
	long := strings.Repeat("a", 200)
	got := argsPreview([]string{"eval", long})
	if !strings.Contains(got, "...") {
		t.Fatalf("expected truncation marker, got: %s", got)
	}
	if len(got) > 200 {
		t.Fatalf("preview too long (%d chars): %s", len(got), got)
	}
}
