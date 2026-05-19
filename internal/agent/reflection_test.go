package agent

import (
	"fmt"
	"strings"
	"testing"
)

func TestReflect_NoTriggerOnFreshState(t *testing.T) {
	r := newReflectState()
	note, ok := r.Observe(1, "http_get", "https://example.com", resultOK)
	if ok || note != "" {
		t.Errorf("fresh state should not fire, got (%q, %v)", note, ok)
	}
}

func TestReflect_FiresOn5ConsecutiveErrors(t *testing.T) {
	r := newReflectState()
	var fired string
	// Use different args each step so the action-repeat trigger does not fire first.
	for i := 1; i <= 5; i++ {
		note, ok := r.Observe(i, "http_get", fmt.Sprintf("https://example.com/x%d", i), resultErr)
		if ok {
			fired = note
		}
	}
	if fired == "" {
		t.Fatal("expected 5 consecutive errors to fire a note, none fired")
	}
	if !strings.Contains(fired, "5 consecutive errors") {
		t.Errorf("note text missing trigger description: %q", fired)
	}
}

func TestReflect_DoesNotFireOn4ConsecutiveErrors(t *testing.T) {
	r := newReflectState()
	for i := 1; i <= 4; i++ {
		if note, ok := r.Observe(i, "http_get", fmt.Sprintf("https://example.com/x%d", i), resultErr); ok {
			t.Fatalf("step %d fired unexpectedly: %q", i, note)
		}
	}
}

func TestReflect_FiresOn3NoActionTurns(t *testing.T) {
	r := newReflectState()
	var fired string
	for i := 1; i <= 3; i++ {
		note, ok := r.Observe(i, "", "", resultNoAction)
		if ok {
			fired = note
		}
	}
	if fired == "" || !strings.Contains(fired, "3 consecutive turns") {
		t.Errorf("expected 3 no-action turns to fire; got %q", fired)
	}
}

func TestReflect_FiresOnActionRepeat3InARow(t *testing.T) {
	r := newReflectState()
	r.Observe(1, "http_get", "https://example.com/a", resultOK)
	r.Observe(2, "http_get", "https://example.com/a", resultOK)
	note, ok := r.Observe(3, "http_get", "https://example.com/a", resultOK)
	if !ok {
		t.Fatal("expected action-repeat trigger to fire on step 3")
	}
	if !strings.Contains(note, "3 times in a row") {
		t.Errorf("note text missing trigger description: %q", note)
	}
	if !strings.Contains(note, "http_get") {
		t.Errorf("note should name the repeated tool: %q", note)
	}
}

func TestReflect_DoesNotFireOnAlternatingActions(t *testing.T) {
	r := newReflectState()
	// ABA — same tool but not 3-in-a-row
	r.Observe(1, "http_get", "https://example.com/a", resultOK)
	r.Observe(2, "browser_open", "https://example.com/b", resultOK)
	if note, ok := r.Observe(3, "http_get", "https://example.com/a", resultOK); ok {
		t.Fatalf("unexpected fire on ABA: %q", note)
	}
}

func TestReflect_FiresOnABABABOscillation(t *testing.T) {
	r := newReflectState()
	pairs := []struct {
		tool, args string
	}{
		{"browser_click", "@e30"},
		{"browser_snapshot", ""},
		{"browser_click", "@e30"},
		{"browser_snapshot", ""},
		{"browser_click", "@e30"},
		{"browser_snapshot", ""},
	}
	var fired string
	for i, p := range pairs {
		note, ok := r.Observe(i+1, p.tool, p.args, resultOK)
		if ok {
			fired = note
		}
	}
	if fired == "" {
		t.Fatal("expected ABAB oscillation trigger to fire")
	}
	if !strings.Contains(fired, "oscillating") {
		t.Errorf("note text missing oscillation description: %q", fired)
	}
}

func TestReflect_CooldownSuppressesRepeatNotes(t *testing.T) {
	r := newReflectState()
	// 5 errors with distinct args → only the errors trigger applies.
	var firstStep int
	for i := 1; i <= 5; i++ {
		_, ok := r.Observe(i, "http_get", fmt.Sprintf("https://example.com/x%d", i), resultErr)
		if ok {
			firstStep = i
		}
	}
	if firstStep != 5 {
		t.Fatalf("expected first note at step 5, got %d", firstStep)
	}
	// Steps 6..9 are within the cooldown window (cooldown=4 → cooldownUntil=9).
	for i := 6; i <= 9; i++ {
		if _, ok := r.Observe(i, "http_get", fmt.Sprintf("https://example.com/x%d", i), resultErr); ok {
			t.Fatalf("note fired during cooldown at step %d", i)
		}
	}
	// Step 10 is past cooldown. Five distinct-arg errors still queued → fires.
	note, ok := r.Observe(10, "http_get", "https://example.com/x10", resultErr)
	if !ok {
		t.Errorf("expected re-fire after cooldown, got (%q, %v)", note, ok)
	}
}

func TestReflect_ArgsHashIgnoresWhitespaceAndCase(t *testing.T) {
	a := hashArgs("https://example.com/path?id=1")
	b := hashArgs("  https://example.com/path?id=1  ")
	c := hashArgs("HTTPS://EXAMPLE.COM/path?id=1")
	if a != b {
		t.Errorf("whitespace difference changed hash: %q vs %q", a, b)
	}
	if a != c {
		t.Errorf("case difference changed hash: %q vs %q", a, c)
	}
	if a == hashArgs("https://example.com/path?id=2") {
		t.Errorf("different args produced identical hash")
	}
}
