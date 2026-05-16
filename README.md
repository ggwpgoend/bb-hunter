# BB-Hunter

Automated bug bounty hunter powered by free cloud LLMs.
Designed for Russian BB platforms (Standoff, BI.ZONE, Bugbounty.ru).

## Architecture

- **4 LLM agents**: Analyst, Historian, Exploiter (+Verifier), Reporter
- **6 Go services**: Scheduler, Scanner, Differ, ScopeEnforcer, Sandbox, Audit Logger
- **Egress proxy**: all subprocess tools (nuclei, katana, etc.) route through a scope-enforcing HTTP proxy

## Requirements

- Go 1.22+
- Docker (rootless) — for PoC sandbox
- VPN — for API access to geo-blocked LLM providers

## Quick Start

```bash
# Build
go build -o bb-hunter ./cmd/bb-hunter

# Configure scope
cp scope.yaml.example scope.yaml
# Edit scope.yaml with your target program's domains

# Run
./bb-hunter -scope scope.yaml
```

## Project Structure

```
cmd/bb-hunter/         — main entry point
internal/
  scope/               — ScopeEnforcer (pinned-IP dialer, IP blocklist, domain matching)
  proxy/               — Egress HTTP proxy for subprocess scope enforcement
  config/              — Configuration loader (scope.yaml)
  models/              — Core domain types (Finding, ScanRun, AuditEntry)
  db/                  — SQLite writer (single-goroutine, WAL, batch commits)
  audit/               — Tamper-evident hash-chain audit logger
  llm/                 — Multi-provider LLM client (Gemini, OpenAI-compat)
  cost/                — Per-provider quota tracker with kill switch
  ratelimit/           — Per-host token bucket rate limiter
  scanner/             — Recon pipeline (subfinder→httpx→katana→nuclei)
  analyst/             — LLM-based vulnerability classifier
  reporter/            — LLM-based report generator (Russian, Standoff format)
  hitl/                — Telegram HITL bot (approve/reject findings)
  differ/              — Scan diff engine (new/gone/changed findings)
  historian/           — LLM-based trend analysis between scans
  scheduler/           — Cron-like scan scheduler (interval/daily/weekly)
  sandbox/             — Rootless Docker sandbox for PoC execution
  exploiter/           — LLM-based PoC generator + Verifier (P0 #3, #4)
  dedup/               — Duplicate finding detection (exact key + similarity)
  gate/                — 7-Question Gate quality validator (LLM + algorithmic)
  chainer/             — Exploit chain builder (12 patterns + LLM discovery)
```

## Security

- **Pinned-IP dialer**: DNS is resolved once, verified against blocklist, then the verified IP is used for the connection. Eliminates DNS rebinding TOCTOU.
- **IP blocklist**: RFC1918, loopback, link-local, cloud metadata (169.254.169.254), IPv6 ULA — all blocked by default.
- **Egress proxy**: subprocess tools can only reach in-scope targets.
- **Redirect checking**: every redirect destination is re-validated against scope.
- **PoC safety validator**: blocks eval(), exec(), system(), destructive HTTP methods, XSS payloads, SQL injection in generated PoCs.
- **P0 #3 — PoC determinism**: PoCs use safe canary strings, read-only operations, structured JSON output.
- **P0 #4 — Verifier raw-finding leak**: Verifier does NOT pass raw scanner evidence to LLM; only PoC execution results.

## Phase 1 Status

- [x] ScopeEnforcer with pinned-IP dialer
- [x] IP blocklist (RFC1918, loopback, link-local, cloud metadata, IPv6)
- [x] Hostname normalization (IDNA/punycode, trailing dot)
- [x] Redirect validation
- [x] Egress proxy (HTTP + CONNECT tunneling)
- [x] Config loader with validation
- [x] Scanner pipeline
- [x] Analyst agent (LLM classification)
- [x] Reporter agent (Russian reports)
- [x] Audit Logger (hash-chain)
- [x] Telegram HITL (approve/reject via bot)
- [x] DBWriter (SQLite, WAL, batch commits)
- [x] Cost Tracker (per-provider quotas, kill switch)
- [x] Rate Limiter (per-host token bucket)
- [x] LLM Client (Gemini + OpenAI-compat with failover)

## Phase 2 Status

- [x] Differ — scan comparison engine (new/gone/changed/unchanged)
- [x] Historian — LLM-based trend analysis + algorithmic fallback
- [x] Scheduler — cron-like scan scheduling (interval/daily/weekly)
- [x] Sandbox — rootless Docker PoC execution (security-hardened)
- [x] Exploiter — LLM-based safe PoC generation with safety validator
- [x] Verifier — sandbox-based PoC execution + structured output parsing
- [x] P0 #3 fix — PoC test-payload determinism
- [x] P0 #4 fix — Verifier raw-finding leak prevention
- [x] Pipeline wiring — full 6-stage pipeline in main.go

## Phase 3a Status

- [x] Duplicate Detection — exact key match + similarity-based dedup
- [x] 7-Question Gate — LLM + algorithmic quality validation (PASS/KILL/DOWNGRADE)
- [x] Nuclei -ai integration — dynamic AI-generated nuclei templates
- [x] Exploit Chain Builder — 12 known patterns + LLM creative chain discovery
- [x] Pipeline wiring — dedup → gate → chainer stages in main.go
