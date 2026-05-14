package scanner

import (
	"testing"
)

func TestParseHttpxLine_Full(t *testing.T) {
	line := "https://example.com [200] [Example Domain] [Nginx,PHP]"
	hr := parseHttpxLine(line)

	if hr.URL != "https://example.com" {
		t.Errorf("URL = %q, want %q", hr.URL, "https://example.com")
	}
	if hr.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", hr.StatusCode)
	}
	if hr.Title != "Example Domain" {
		t.Errorf("Title = %q, want %q", hr.Title, "Example Domain")
	}
	if len(hr.Tech) != 2 || hr.Tech[0] != "Nginx" || hr.Tech[1] != "PHP" {
		t.Errorf("Tech = %v, want [Nginx PHP]", hr.Tech)
	}
}

func TestParseHttpxLine_URLOnly(t *testing.T) {
	line := "https://example.com"
	hr := parseHttpxLine(line)

	if hr.URL != "https://example.com" {
		t.Errorf("URL = %q, want %q", hr.URL, "https://example.com")
	}
	if hr.StatusCode != 0 {
		t.Errorf("StatusCode = %d, want 0", hr.StatusCode)
	}
}

func TestParseHttpxLine_NoTech(t *testing.T) {
	line := "https://example.com [301] [Moved]"
	hr := parseHttpxLine(line)

	if hr.URL != "https://example.com" {
		t.Errorf("URL = %q", hr.URL)
	}
	if hr.StatusCode != 301 {
		t.Errorf("StatusCode = %d, want 301", hr.StatusCode)
	}
	if hr.Title != "Moved" {
		t.Errorf("Title = %q, want %q", hr.Title, "Moved")
	}
}

func TestParseHttpxLine_Empty(t *testing.T) {
	hr := parseHttpxLine("")
	if hr.URL != "" {
		t.Errorf("empty line should produce empty result")
	}
}

func TestParseNucleiJSON_Valid(t *testing.T) {
	line := `{"template-id":"http-missing-security-headers","info":{"name":"Missing Security Headers","severity":"info"},"matched-at":"https://example.com","matcher-name":"x-frame-options","timestamp":"2024-01-15T10:30:00Z","curl-command":"curl -X GET https://example.com"}`

	nr, err := parseNucleiJSON(line)
	if err != nil {
		t.Fatal(err)
	}

	if nr.TemplateID != "http-missing-security-headers" {
		t.Errorf("TemplateID = %q", nr.TemplateID)
	}
	if nr.Severity != "info" {
		t.Errorf("Severity = %q", nr.Severity)
	}
	if nr.URL != "https://example.com" {
		t.Errorf("URL = %q", nr.URL)
	}
	if nr.Matched != "x-frame-options" {
		t.Errorf("Matched = %q", nr.Matched)
	}
}

func TestParseNucleiJSON_Invalid(t *testing.T) {
	_, err := parseNucleiJSON("not json")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseNucleiJSON_WithResponse(t *testing.T) {
	line := `{"template-id":"xss-reflected","info":{"name":"XSS","severity":"high"},"matched-at":"https://example.com/search?q=test","matcher-name":"body","timestamp":"2024-01-15T10:30:00Z","response":"<html><body>test</body></html>"}`

	nr, err := parseNucleiJSON(line)
	if err != nil {
		t.Fatal(err)
	}

	if nr.Evidence == "" {
		t.Error("expected evidence from response")
	}
}

func TestExtractBrackets(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"[200] [Title] [Tech]", 3},
		{"[200]", 1},
		{"no brackets", 0},
		{"[200] text [Title]", 2},
		{"", 0},
	}

	for _, tc := range tests {
		got := extractBrackets(tc.input)
		if len(got) != tc.want {
			t.Errorf("extractBrackets(%q) = %d items, want %d", tc.input, len(got), tc.want)
		}
	}
}

func TestDedup(t *testing.T) {
	input := []string{"a", "b", "a", "c", "b", "d"}
	got := dedup(input)
	want := []string{"a", "b", "c", "d"}

	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i, v := range got {
		if v != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, v, want[i])
		}
	}
}

func TestSplitLines(t *testing.T) {
	input := "line1\nline2\n\nline3\n"
	got := splitLines(input)
	if len(got) != 3 {
		t.Errorf("len = %d, want 3", len(got))
	}
}
