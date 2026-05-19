package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// actionResult is the outcome class of a single agent turn, used by
// reflectState to spot patterns.
type actionResult int

const (
	resultOK       actionResult = iota // observation did not start with "ERROR:"
	resultErr                          // observation started with "ERROR:"
	resultNoAction                     // LLM failed to emit a valid ACTION
)

// actionEntry is a single recorded turn for loop detection.
type actionEntry struct {
	Step     int
	Tool     string
	ArgsHash string
	Result   actionResult
}

// reflectState tracks recent agent actions to detect loops and error storms,
// and emits a SYSTEM NOTE that the run loop injects into history to nudge
// the agent out of unproductive patterns.
//
// Triggers (first-match wins, evaluated each turn):
//  1. 5 consecutive ERROR results (any args)
//  2. 3 consecutive no-ACTION turns
//  3. Same (tool, argsHash) 3 times in a row
//  4. 2-action ABAB oscillation over the last 6 entries
//
// After firing, a cooldown of `cooldown` steps suppresses further notes so
// the agent has a chance to react before another note lands.
type reflectState struct {
	history       []actionEntry
	maxHistory    int
	cooldown      int
	cooldownUntil int // step number; while step < cooldownUntil no note fires
}

func newReflectState() *reflectState {
	return &reflectState{
		history:    make([]actionEntry, 0, 16),
		maxHistory: 10,
		cooldown:   4,
	}
}

// Observe records a turn and returns (note, true) if reflection wants the
// caller to inject a SYSTEM NOTE into the conversation. Otherwise returns
// ("", false).
//
// step is the 1-based loop iteration number. tool may be "" when the LLM
// failed to emit an ACTION (in which case result MUST be resultNoAction).
func (r *reflectState) Observe(step int, tool, args string, result actionResult) (string, bool) {
	r.history = append(r.history, actionEntry{
		Step:     step,
		Tool:     tool,
		ArgsHash: hashArgs(args),
		Result:   result,
	})
	if len(r.history) > r.maxHistory {
		r.history = r.history[len(r.history)-r.maxHistory:]
	}

	if step <= r.cooldownUntil {
		return "", false
	}

	if note, ok := r.checkConsecutiveErrors(); ok {
		r.cooldownUntil = step + r.cooldown
		return note, true
	}
	if note, ok := r.checkConsecutiveNoAction(); ok {
		r.cooldownUntil = step + r.cooldown
		return note, true
	}
	if note, ok := r.checkActionRepeat(); ok {
		r.cooldownUntil = step + r.cooldown
		return note, true
	}
	if note, ok := r.checkOscillation(); ok {
		r.cooldownUntil = step + r.cooldown
		return note, true
	}
	return "", false
}

func (r *reflectState) checkConsecutiveErrors() (string, bool) {
	const want = 5
	n := len(r.history)
	if n < want {
		return "", false
	}
	for i := n - want; i < n; i++ {
		if r.history[i].Result != resultErr {
			return "", false
		}
	}
	return "SYSTEM NOTE: you produced 5 consecutive errors. The current approach is not working. Try a DIFFERENT tool, a DIFFERENT target (URL / endpoint / parameter), or a DIFFERENT vuln class. Do NOT retry the same action.", true
}

func (r *reflectState) checkConsecutiveNoAction() (string, bool) {
	const want = 3
	n := len(r.history)
	if n < want {
		return "", false
	}
	for i := n - want; i < n; i++ {
		if r.history[i].Result != resultNoAction {
			return "", false
		}
	}
	return "SYSTEM NOTE: you failed to emit a valid ACTION in 3 consecutive turns. Output MUST be: 'THINK: <reasoning>' followed by 'ACTION: <tool> <args>' on its own line. Pick the simplest action available right now and execute it.", true
}

func (r *reflectState) checkActionRepeat() (string, bool) {
	const want = 3
	n := len(r.history)
	if n < want {
		return "", false
	}
	last := r.history[n-want:]
	key := actionKey(last[0])
	for i := 1; i < want; i++ {
		if actionKey(last[i]) != key {
			return "", false
		}
	}
	return fmt.Sprintf("SYSTEM NOTE: you repeated the same action ('%s' with identical args) 3 times in a row. This is a loop. Change the tool, the target, or the arguments now.", last[0].Tool), true
}

func (r *reflectState) checkOscillation() (string, bool) {
	const window = 6
	n := len(r.history)
	if n < window {
		return "", false
	}
	last := r.history[n-window:]
	a := actionKey(last[0])
	b := actionKey(last[1])
	if a == b {
		return "", false
	}
	if actionKey(last[2]) != a ||
		actionKey(last[3]) != b ||
		actionKey(last[4]) != a ||
		actionKey(last[5]) != b {
		return "", false
	}
	return fmt.Sprintf("SYSTEM NOTE: you are oscillating between two actions ('%s' and '%s'). Break the loop: pick a THIRD tool, or move to a different target/endpoint.", last[0].Tool, last[1].Tool), true
}

func actionKey(e actionEntry) string {
	return e.Tool + "|" + e.ArgsHash
}

// hashArgs returns a short hash of args for dedup comparison.
// Whitespace is collapsed and the string is lower-cased so trivial
// formatting differences do not defeat the dedup check.
func hashArgs(args string) string {
	if args == "" {
		return ""
	}
	normalised := strings.ToLower(strings.Join(strings.Fields(args), " "))
	sum := sha256.Sum256([]byte(normalised))
	return hex.EncodeToString(sum[:6])
}
