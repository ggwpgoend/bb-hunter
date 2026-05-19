package agent

import (
	"strings"
	"testing"
)

func TestNav_NormaliseEvalURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`"https://example.com/"`, "https://example.com/"},
		{`"https://example.com/"` + "\n", "https://example.com/"},
		{"  '" + "https://x.io/foo" + "'  ", "https://x.io/foo"},
		{"https://x.io", "https://x.io"},
		{"", ""},
		{`""`, ""},
		{"  ", ""},
		{`"https://example.com/?a=1&b=2"`, "https://example.com/?a=1&b=2"},
	}
	for _, c := range cases {
		got := normaliseEvalURL(c.in)
		if got != c.want {
			t.Errorf("normaliseEvalURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNav_ClassifyNavigation(t *testing.T) {
	cases := []struct {
		name           string
		before, after  string
		want           navResult
	}{
		{"changed", `"https://x.io/"`, `"https://x.io/page"`, navOK},
		{"changed_no_quotes", "https://x.io/", "https://x.io/page", navOK},
		{"unchanged", `"https://x.io/"`, `"https://x.io/"`, navUnchanged},
		{"unchanged_whitespace_diff", `"https://x.io/"` + "\n", `  "https://x.io/"  `, navUnchanged},
		{"unknown_before", "", `"https://x.io/"`, navUnknown},
		{"unknown_after", `"https://x.io/"`, "", navUnknown},
		{"unknown_both", "", "", navUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyNavigation(c.before, c.after)
			if got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestNav_DescribeNavigation_OK(t *testing.T) {
	got := describeNavigation(navOK, `"https://x.io/"`, `"https://x.io/page"`)
	if !strings.Contains(got, "NAV:") {
		t.Errorf("missing NAV: marker: %q", got)
	}
	if !strings.Contains(got, "https://x.io/") || !strings.Contains(got, "https://x.io/page") {
		t.Errorf("before/after URLs missing: %q", got)
	}
}

func TestNav_DescribeNavigation_Unchanged_NudgesAgent(t *testing.T) {
	got := describeNavigation(navUnchanged, `"https://x.io/"`, `"https://x.io/"`)
	if !strings.Contains(got, "WARNING") {
		t.Errorf("missing WARNING: %q", got)
	}
	if !strings.Contains(got, "browser_open") {
		t.Errorf("must reference browser_open fallback: %q", got)
	}
	if !strings.Contains(got, "SPA") {
		t.Errorf("must mention SPA router: %q", got)
	}
}

func TestNav_DescribeNavigation_UnknownIsEmpty(t *testing.T) {
	if got := describeNavigation(navUnknown, "", ""); got != "" {
		t.Errorf("navUnknown should produce no suffix; got %q", got)
	}
}

func TestNav_ComposeClickObservation(t *testing.T) {
	cases := []struct {
		name        string
		click, suf  string
		want        string
	}{
		{"both", "OK: clicked @e30", "NAV: URL changed: a -> b", "OK: clicked @e30\nNAV: URL changed: a -> b"},
		{"click_only", "OK: clicked @e30", "", "OK: clicked @e30"},
		{"suffix_only", "", "WARNING: ...", "WARNING: ..."},
		{"strips_trailing_newlines", "OK: clicked\n\n", "NAV: changed", "OK: clicked\nNAV: changed"},
		{"both_empty", "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := composeClickObservation(c.click, c.suf)
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}
