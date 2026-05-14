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
```

## Security

- **Pinned-IP dialer**: DNS is resolved once, verified against blocklist, then the verified IP is used for the connection. Eliminates DNS rebinding TOCTOU.
- **IP blocklist**: RFC1918, loopback, link-local, cloud metadata (169.254.169.254), IPv6 ULA — all blocked by default.
- **Egress proxy**: subprocess tools can only reach in-scope targets.
- **Redirect checking**: every redirect destination is re-validated against scope.

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
