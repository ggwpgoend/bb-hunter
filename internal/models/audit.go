package models

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// AuditAction categorizes the type of audit event.
type AuditAction string

const (
	AuditScanStarted    AuditAction = "scan_started"
	AuditScanFinished   AuditAction = "scan_finished"
	AuditFindingCreated AuditAction = "finding_created"
	AuditFindingUpdated AuditAction = "finding_updated"
	AuditLLMRequest     AuditAction = "llm_request"
	AuditLLMResponse    AuditAction = "llm_response"
	AuditHITLDecision   AuditAction = "hitl_decision"
	AuditScopeCheck     AuditAction = "scope_check"
	AuditScopeBlocked   AuditAction = "scope_blocked"
	AuditKillSwitch     AuditAction = "kill_switch"
	AuditConfigLoaded   AuditAction = "config_loaded"
)

// AuditEntry is a single entry in the tamper-evident audit log.
// Each entry contains the hash of the previous entry, forming a hash chain.
type AuditEntry struct {
	// Sequence number (monotonically increasing)
	Seq uint64 `json:"seq"`

	// Timestamp
	Timestamp time.Time `json:"ts"`

	// Hash of the previous entry (hex-encoded SHA-256).
	// First entry has PrevHash = "0" * 64
	PrevHash string `json:"prev_hash"`

	// Hash of this entry (hex-encoded SHA-256)
	Hash string `json:"hash"`

	// Action type
	Action AuditAction `json:"action"`

	// Actor: which component generated this entry
	Actor string `json:"actor"`

	// Details: action-specific structured data
	Details json.RawMessage `json:"details"`
}

// GenesisHash is the prev_hash for the first entry in the chain.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// ComputeEntryHash computes the SHA-256 hash of an audit entry.
// The hash covers: seq, timestamp, prev_hash, action, actor, details.
// The entry's own Hash field is NOT included (it's what we're computing).
func ComputeEntryHash(seq uint64, ts time.Time, prevHash string, action AuditAction, actor string, details json.RawMessage) string {
	raw := struct {
		Seq      uint64          `json:"seq"`
		Ts       time.Time       `json:"ts"`
		PrevHash string          `json:"prev_hash"`
		Action   AuditAction     `json:"action"`
		Actor    string          `json:"actor"`
		Details  json.RawMessage `json:"details"`
	}{
		Seq:      seq,
		Ts:       ts,
		PrevHash: prevHash,
		Action:   action,
		Actor:    actor,
		Details:  details,
	}

	data, err := json.Marshal(raw)
	if err != nil {
		panic("audit: cannot marshal entry for hashing: " + err.Error())
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
