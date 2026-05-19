package agent

import (
	"fmt"
	"strings"
	"testing"
)

func buildObs(status, contentType, body string) string {
	return fmt.Sprintf("HTTP %s\nContent-Type: %s\nX-Trace: abc123\n\n%s", status, contentType, body)
}

func TestFilter_404TrimsBodyToBudget(t *testing.T) {
	bigBody := strings.Repeat("a", 5000)
	obs := buildObs("404 Not Found", "text/html; charset=utf-8", bigBody)

	out := filterHTTPObservation(obs)

	if !strings.HasPrefix(out, "HTTP 404") {
		t.Fatalf("status line dropped: %q", firstLine(out))
	}
	if !strings.Contains(out, "Content-Type: text/html; charset=utf-8") {
		t.Errorf("Content-Type header should be preserved: %q", out)
	}
	if !strings.Contains(out, "X-Trace: abc123") {
		t.Errorf("custom header should be preserved: %q", out)
	}
	if !strings.Contains(out, "truncated") {
		t.Errorf("truncation marker missing: %q", out)
	}
	if len(out) > 1500 {
		t.Errorf("filtered 404 should be small; got %d bytes", len(out))
	}
}

func TestFilter_500TrimsBodyToBudget(t *testing.T) {
	obs := buildObs("500 Internal Server Error", "application/json", strings.Repeat("x", 2000))
	out := filterHTTPObservation(obs)
	if !strings.HasPrefix(out, "HTTP 500") {
		t.Fatalf("status line dropped: %q", out)
	}
	if !strings.Contains(out, "truncated") {
		t.Errorf("body should be truncated for 5xx regardless of content-type")
	}
}

func TestFilter_200HTMLTrimsBodyOver500Bytes(t *testing.T) {
	bigHTML := strings.Repeat("<p>x</p>", 200) // ~1600 bytes
	obs := buildObs("200 OK", "text/html", bigHTML)

	out := filterHTTPObservation(obs)

	if !strings.Contains(out, "HTML body truncated") {
		t.Errorf("expected HTML truncation marker: %q", out)
	}
	// Should keep first ~500 bytes of body
	body := strings.SplitN(out, "\n\n", 2)
	if len(body) != 2 {
		t.Fatalf("malformed filtered output: %q", out)
	}
	if !strings.Contains(body[1], "<p>x</p>") {
		t.Errorf("first chunk of HTML should remain: %q", body[1])
	}
}

func TestFilter_200HTMLShortBodyUntouched(t *testing.T) {
	smallHTML := "<html><body>tiny</body></html>"
	obs := buildObs("200 OK", "text/html", smallHTML)

	out := filterHTTPObservation(obs)
	if out != obs {
		t.Errorf("short HTML 200 should be returned unchanged.\nin:  %q\nout: %q", obs, out)
	}
}

func TestFilter_200JSONUntouchedEvenWhenLarge(t *testing.T) {
	bigJSON := `{"items":[` + strings.Repeat(`"x",`, 1000) + `"end"]}`
	obs := buildObs("200 OK", "application/json", bigJSON)

	out := filterHTTPObservation(obs)
	if out != obs {
		t.Errorf("JSON 200 must NOT be trimmed regardless of size; got %d bytes (in %d)", len(out), len(obs))
	}
}

func TestFilter_200JSONUntouchedWhenContentTypeHasParams(t *testing.T) {
	bigJSON := `{"k":"` + strings.Repeat("v", 2000) + `"}`
	obs := buildObs("200 OK", "application/json; charset=utf-8", bigJSON)

	out := filterHTTPObservation(obs)
	if out != obs {
		t.Errorf("application/json; charset=utf-8 must NOT trigger filter")
	}
}

func TestFilter_204NoContentUntouched(t *testing.T) {
	obs := buildObs("204 No Content", "text/plain", "")
	out := filterHTTPObservation(obs)
	if out != obs {
		t.Errorf("2xx non-HTML untouched expected; got %q", out)
	}
}

func TestFilter_300RedirectUntouched(t *testing.T) {
	obs := buildObs("302 Found", "text/html", "redirecting")
	out := filterHTTPObservation(obs)
	if out != obs {
		t.Errorf("3xx redirect should be untouched; got %q", out)
	}
}

func TestFilter_NonHTTPInputUnchanged(t *testing.T) {
	cases := []string{
		"ERROR: connection refused",
		"OK: finding recorded",
		"plain text observation from a non-HTTP tool",
		"",
		"HTTP",                 // malformed
		"HTTP 200",             // no body
		"HTTP not-a-status\n\n", // bad code
	}
	for _, in := range cases {
		if out := filterHTTPObservation(in); out != in {
			t.Errorf("non-HTTP input mutated.\nin:  %q\nout: %q", in, out)
		}
	}
}

func TestFilter_4xxKeepsFirstBytesOfBody(t *testing.T) {
	body := "FORBIDDEN: token expired at 2025-11-20T10:00:00Z, please refresh via /auth/refresh"
	obs := buildObs("403 Forbidden", "text/plain", body+strings.Repeat("z", 5000))

	out := filterHTTPObservation(obs)
	if !strings.Contains(out, "FORBIDDEN: token expired") {
		t.Errorf("first 200B of body must remain; got %q", out)
	}
}

func firstLine(s string) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		return s[:i]
	}
	return s
}
