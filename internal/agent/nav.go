package agent

import (
	"fmt"
	"strings"
)

// navResult is the outcome of comparing window.location.href before and after
// a browser_click. The agent's run loop uses the suffix returned by
// describeNavigation to know whether the click "took effect".
type navResult int

const (
	navOK         navResult = iota // URL changed after the click
	navUnchanged                   // URL did NOT change (likely SPA-swallowed)
	navUnknown                     // could not determine (eval failed pre or post)
)

// classifyNavigation compares pre/post URLs after a browser_click. Empty
// strings are treated as "unknown" — the upstream eval probably failed.
func classifyNavigation(before, after string) navResult {
	before = normaliseEvalURL(before)
	after = normaliseEvalURL(after)
	if before == "" || after == "" {
		return navUnknown
	}
	if before == after {
		return navUnchanged
	}
	return navOK
}

// describeNavigation returns the diagnostic suffix to append to the click
// observation so the agent can react on its next turn.
//
//   - navOK        -> "NAV: URL changed: <before> -> <after>"
//   - navUnchanged -> a WARNING that nudges the agent toward browser_open
//   - navUnknown   -> empty string (do not bloat the observation)
func describeNavigation(r navResult, before, after string) string {
	switch r {
	case navOK:
		return fmt.Sprintf("NAV: URL changed: %s -> %s", normaliseEvalURL(before), normaliseEvalURL(after))
	case navUnchanged:
		return fmt.Sprintf(
			"WARNING: URL did not change after click (still %s). The click may have been swallowed by an SPA router or the element was not a link. If you expected navigation, run: ACTION: browser_open <expected_url>. Otherwise verify any in-page side effects with browser_snapshot.",
			normaliseEvalURL(after),
		)
	default:
		return ""
	}
}

// normaliseEvalURL strips the wrapping quotes and surrounding whitespace
// that the agent-browser eval helper typically returns when it stringifies
// a JS expression like `window.location.href`.
//
// Examples (input -> output):
//
//	"\"https://example.com/\"\n"  -> "https://example.com/"
//	"  'https://x.io/foo'  "       -> "https://x.io/foo"
//	"https://x.io"                 -> "https://x.io"
//	""                             -> ""
func normaliseEvalURL(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			s = s[1 : len(s)-1]
		}
	}
	return strings.TrimSpace(s)
}

// composeClickObservation joins the original click output with the navigation
// suffix using a single newline separator. Empty suffix means "do not append".
func composeClickObservation(clickOutput, navSuffix string) string {
	clickOutput = strings.TrimRight(clickOutput, "\n")
	if navSuffix == "" {
		return clickOutput
	}
	if clickOutput == "" {
		return navSuffix
	}
	return clickOutput + "\n" + navSuffix
}
