package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/analyst"
	"github.com/ggwpgoend/bb-hunter/internal/audit"
	"github.com/ggwpgoend/bb-hunter/internal/chainer"
	"github.com/ggwpgoend/bb-hunter/internal/config"
	"github.com/ggwpgoend/bb-hunter/internal/cost"
	"github.com/ggwpgoend/bb-hunter/internal/db"
	"github.com/ggwpgoend/bb-hunter/internal/dedup"
	"github.com/ggwpgoend/bb-hunter/internal/differ"
	"github.com/ggwpgoend/bb-hunter/internal/exploiter"
	"github.com/ggwpgoend/bb-hunter/internal/gate"
	"github.com/ggwpgoend/bb-hunter/internal/historian"
	"github.com/ggwpgoend/bb-hunter/internal/hitl"
	"github.com/ggwpgoend/bb-hunter/internal/llm"
	"github.com/ggwpgoend/bb-hunter/internal/models"
	"github.com/ggwpgoend/bb-hunter/internal/proxy"
	"github.com/ggwpgoend/bb-hunter/internal/ratelimit"
	"github.com/ggwpgoend/bb-hunter/internal/reporter"
	"github.com/ggwpgoend/bb-hunter/internal/sandbox"
	"github.com/ggwpgoend/bb-hunter/internal/scanner"
	"github.com/ggwpgoend/bb-hunter/internal/scope"
)

func main() {
	scopePath := flag.String("scope", "scope.yaml", "path to scope.yaml")
	proxyAddr := flag.String("proxy-addr", "127.0.0.1:18080", "egress proxy listen address")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, error")
	dbPath := flag.String("db", "bb-hunter.db", "path to SQLite database")
	geminiKey := flag.String("gemini-key", "", "Google AI Studio API key (env: GEMINI_API_KEY)")
	cerebrasKey := flag.String("cerebras-key", "", "Cerebras API key (env: CEREBRAS_API_KEY)")
	groqKey := flag.String("groq-key", "", "Groq API key (env: GROQ_API_KEY)")
	sambaKey := flag.String("samba-key", "", "SambaNova API key (env: SAMBA_API_KEY)")
	telegramToken := flag.String("telegram-token", "", "Telegram bot token (env: TELEGRAM_BOT_TOKEN)")
	telegramChatID := flag.String("telegram-chat-id", "", "Telegram chat ID for HITL (env: TELEGRAM_CHAT_ID)")
	hitlTimeout := flag.Duration("hitl-timeout", 1*time.Hour, "HITL decision timeout")
	sandboxImage := flag.String("sandbox-image", "python:3.12-slim", "Docker image for PoC sandbox")
	sandboxMemory := flag.String("sandbox-memory", "256m", "sandbox memory limit")
	sandboxTimeout := flag.Duration("sandbox-timeout", 30*time.Second, "sandbox execution timeout")
	enableExploiter := flag.Bool("exploit", false, "enable Exploiter+Verifier (requires Docker)")
	ratePerSecond := flag.Float64("rate", 10, "requests per second to target")
	dryRun := flag.Bool("dry-run", false, "parse scope and validate config without scanning")
	flag.Parse()

	// Fallback to env vars for Telegram config
	if *telegramToken == "" {
		*telegramToken = os.Getenv("TELEGRAM_BOT_TOKEN")
	}
	if *telegramChatID == "" {
		*telegramChatID = os.Getenv("TELEGRAM_CHAT_ID")
	}

	// Fallback to env vars for API keys
	if *geminiKey == "" {
		*geminiKey = os.Getenv("GEMINI_API_KEY")
	}
	if *cerebrasKey == "" {
		*cerebrasKey = os.Getenv("CEREBRAS_API_KEY")
	}
	if *groqKey == "" {
		*groqKey = os.Getenv("GROQ_API_KEY")
	}
	if *sambaKey == "" {
		*sambaKey = os.Getenv("SAMBA_API_KEY")
	}

	// Setup structured logging
	var level slog.Level
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	// Load scope config
	sf, err := config.LoadScopeFile(*scopePath)
	if err != nil {
		logger.Error("failed to load scope", "error", err)
		os.Exit(1)
	}
	logger.Info("scope loaded",
		"program", sf.Program,
		"platform", sf.Platform,
		"domains", sf.Domains,
	)

	scopeCfg, err := sf.ToScopeConfig()
	if err != nil {
		logger.Error("failed to create scope config", "error", err)
		os.Exit(1)
	}

	// Create scope enforcer
	enforcer, err := scope.New(scopeCfg)
	if err != nil {
		logger.Error("failed to create scope enforcer", "error", err)
		os.Exit(1)
	}

	// Start egress proxy
	egressProxy := proxy.NewEgressProxy(enforcer, *proxyAddr, logger)
	go func() {
		if err := egressProxy.ListenAndServe(); err != nil {
			logger.Error("egress proxy failed", "error", err)
		}
	}()
	logger.Info("egress proxy started", "addr", *proxyAddr)

	// Print banner
	fmt.Fprintf(os.Stderr, "\n=== BB-Hunter ===\n")
	fmt.Fprintf(os.Stderr, "Program:    %s\n", sf.Program)
	fmt.Fprintf(os.Stderr, "Platform:   %s\n", sf.Platform)
	fmt.Fprintf(os.Stderr, "Domains:    %v\n", sf.Domains)
	fmt.Fprintf(os.Stderr, "Proxy:      %s\n", *proxyAddr)
	fmt.Fprintf(os.Stderr, "DB:         %s\n", *dbPath)
	fmt.Fprintf(os.Stderr, "Rate:       %.0f req/s\n", *ratePerSecond)
	fmt.Fprintf(os.Stderr, "=========================\n\n")

	if *dryRun {
		fmt.Fprintf(os.Stderr, "Dry run: config valid. Exiting.\n")
		return
	}

	// Initialize context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("shutting down", "signal", sig.String())
		cancel()
	}()

	// Initialize SQLite writer
	writer, err := db.NewWriter(*dbPath, logger)
	if err != nil {
		logger.Error("failed to create DB writer", "error", err)
		os.Exit(1)
	}
	defer writer.Close()
	logger.Info("database initialized", "path", *dbPath)

	// Initialize audit logger
	auditLogger, err := audit.NewLogger(writer)
	if err != nil {
		logger.Error("failed to create audit logger", "error", err)
		os.Exit(1)
	}
	auditLogger.Log(ctx, "system_start", "bb-hunter", map[string]string{
		"program":  sf.Program,
		"platform": sf.Platform,
	})

	// Build LLM provider quotas and providers
	var providers []llm.Provider
	var quotas []cost.ProviderQuota

	if *geminiKey != "" {
		providers = append(providers, llm.NewGeminiProvider(*geminiKey, "gemini-2.5-flash"))
		quotas = append(quotas, cost.ProviderQuota{Name: "gemini", DailyRequests: 500})
		logger.Info("LLM provider added", "name", "gemini", "model", "gemini-2.5-flash")
	}
	if *cerebrasKey != "" {
		providers = append(providers, llm.NewOpenAICompatProvider("cerebras", "https://api.cerebras.ai/v1", *cerebrasKey, "qwen3-235b"))
		quotas = append(quotas, cost.ProviderQuota{Name: "cerebras", DailyRequests: 200})
		logger.Info("LLM provider added", "name", "cerebras", "model", "qwen3-235b")
	}
	if *groqKey != "" {
		providers = append(providers, llm.NewOpenAICompatProvider("groq", "https://api.groq.com/openai/v1", *groqKey, "llama-3.3-70b-versatile"))
		quotas = append(quotas, cost.ProviderQuota{Name: "groq", DailyRequests: 200})
		logger.Info("LLM provider added", "name", "groq", "model", "llama-3.3-70b")
	}
	if *sambaKey != "" {
		providers = append(providers, llm.NewOpenAICompatProvider("sambanova", "https://api.sambanova.ai/v1", *sambaKey, "Meta-Llama-3.1-70B-Instruct"))
		quotas = append(quotas, cost.ProviderQuota{Name: "sambanova", DailyRequests: 200})
		logger.Info("LLM provider added", "name", "sambanova", "model", "Meta-Llama-3.1-70B")
	}

	if len(providers) == 0 {
		logger.Error("no LLM providers configured — provide at least one API key (--gemini-key, --cerebras-key, --groq-key, --samba-key or env vars)")
		os.Exit(1)
	}

	// Initialize cost tracker
	tracker := cost.NewTracker(quotas, logger)
	tracker.OnKillSwitch = func() {
		logger.Error("KILL SWITCH ACTIVATED — cost threshold exceeded")
		cancel()
	}

	// Initialize rate limiter
	governor := ratelimit.NewGovernor(*ratePerSecond, int(*ratePerSecond)*2)

	llmClient, err := llm.NewClient(providers...)
	if err != nil {
		logger.Error("failed to create LLM client", "error", err)
		os.Exit(1)
	}

	// Initialize agents
	analystAgent := analyst.NewAnalyst(llmClient, enforcer, logger)
	reporterAgent := reporter.NewReporter(llmClient, sf.Platform, logger)
	historian := historian.NewHistorian(llmClient, logger)
	exploiterAgent := exploiter.NewExploiter(llmClient, logger)
	chainBuilder := chainer.NewChainer(llmClient, logger)
	qualityGate := gate.NewGate(llmClient, logger)
	dupChecker := dedup.NewChecker(writer.GetDB(), logger)

	// Initialize differ
	diffEngine := differ.New(writer.GetDB())

	// Initialize sandbox + verifier (if Docker available and enabled)
	var verifier *exploiter.Verifier
	if *enableExploiter {
		sbCfg := sandbox.Config{
			BaseImage:   *sandboxImage,
			MemoryLimit: *sandboxMemory,
			Timeout:     *sandboxTimeout,
			ProxyAddr:   "http://" + *proxyAddr,
			Logger:      logger,
		}
		sb := sandbox.New(sbCfg)
		if sb.Available() {
			verifier = exploiter.NewVerifier(sb, logger)
			logger.Info("sandbox available", "image", *sandboxImage)
		} else {
			logger.Warn("Docker not available — Exploiter/Verifier disabled")
		}
	}

	// Initialize scanner pipeline
	pipeline := scanner.NewPipeline(scanner.PipelineConfig{
		Domains:        sf.Domains,
		ProxyAddr:      "http://" + *proxyAddr,
		RateLimit:      *ratePerSecond,
		NucleiSeverity: "medium,high,critical",
		KatanaDepth:    3,
		Tools:          scanner.DefaultToolPaths(),
		Logger:         logger,
	})
	orchestrator := scanner.NewOrchestrator(pipeline, sf.Program, logger)

	// Log pipeline start
	auditLogger.Log(ctx, "scan_started", "scanner", map[string]string{
		"domains": strings.Join(sf.Domains, ","),
		"rate":    fmt.Sprintf("%.0f", *ratePerSecond),
	})

	logger.Info("starting scan pipeline",
		"domains", sf.Domains,
		"rate", *ratePerSecond,
		"providers", len(providers),
	)

	// === PIPELINE: scan → analyze → report ===

	// Stage 1: Run scanner
	scanResult, err := orchestrator.RunFull(ctx)
	if err != nil {
		logger.Error("scan failed", "error", err)
		auditLogger.Log(ctx, "scan_failed", "scanner", map[string]string{"error": err.Error()})
		os.Exit(1)
	}

	auditLogger.Log(ctx, "scan_completed", "scanner", map[string]string{
		"findings": fmt.Sprintf("%d", scanResult.Run.FindingsTotal),
		"hosts":    fmt.Sprintf("%d", scanResult.Run.HostsScanned),
		"urls":     fmt.Sprintf("%d", scanResult.Run.URLsCrawled),
	})

	// Write scan run to DB
	writer.WriteScanRun(ctx, scanResult.Run)

	if len(scanResult.Findings) == 0 {
		logger.Info("no findings from scanner — nothing to analyze")
		fmt.Fprintf(os.Stderr, "\nNo findings. Scan complete.\n")
		return
	}

	// Write raw findings to DB
	for _, f := range scanResult.Findings {
		writer.WriteFinding(ctx, f)
		auditLogger.Log(ctx, "finding_created", "scanner", map[string]string{
			"finding_id":  f.ID,
			"url":         f.URL,
			"template_id": f.NucleiTemplateID,
			"severity":    string(f.Severity),
		})
	}

	logger.Info("scanner produced findings", "count", len(scanResult.Findings))

	// Stage 2: Analyze findings
	if ctx.Err() != nil {
		return
	}

	// Rate limit LLM calls per host
	for _, f := range scanResult.Findings {
		governor.Wait(ctx, f.Host)
	}

	analyzed, err := analystAgent.AnalyzeBatch(ctx, scanResult.Findings)
	if err != nil {
		logger.Error("analysis failed", "error", err)
	}

	// Update analyzed findings in DB + track cost
	for _, f := range analyzed {
		writer.WriteFinding(ctx, f)
		auditLogger.Log(ctx, "finding_analyzed", "analyst", map[string]string{
			"finding_id": f.ID,
			"vuln_class": string(f.VulnClass),
			"confidence": fmt.Sprintf("%.2f", f.Confidence),
			"status":     string(f.Status),
		})
		tracker.Record(providers[0].Name(), 100, 50) // approximate token usage
	}

	logger.Info("analyst classified findings",
		"total", len(scanResult.Findings),
		"analyzed", len(analyzed),
	)

	// Stage 3: Generate reports
	if ctx.Err() != nil {
		return
	}

	reported, err := reporterAgent.GenerateReportBatch(ctx, analyzed)
	if err != nil {
		logger.Error("report generation failed", "error", err)
	}

	// Update reported findings in DB
	for _, f := range reported {
		writer.WriteFinding(ctx, f)
		auditLogger.Log(ctx, "report_generated", "reporter", map[string]string{
			"finding_id":  f.ID,
			"report_size": fmt.Sprintf("%d", len(f.ReportMarkdown)),
		})
	}

	logger.Info("reporter generated reports", "count", len(reported))

	// Output reports to stdout
	for i, f := range reported {
		fmt.Fprintf(os.Stdout, "\n===== REPORT %d/%d =====\n", i+1, len(reported))
		fmt.Fprintf(os.Stdout, "Finding: %s\n", f.ID)
		fmt.Fprintf(os.Stdout, "URL:     %s\n", f.URL)
		fmt.Fprintf(os.Stdout, "Class:   %s\n", f.VulnClass)
		fmt.Fprintf(os.Stdout, "Conf:    %.0f%%\n", f.Confidence*100)
		fmt.Fprintf(os.Stdout, "Status:  %s\n\n", f.Status)
		fmt.Fprintf(os.Stdout, "%s\n", f.ReportMarkdown)
	}

	// Stage 4: Differ + Historian — compare with previous scan
	if ctx.Err() != nil {
		return
	}

	previousRunID, _ := diffEngine.LatestRunID(sf.Program, scanResult.Run.ID)
	if previousRunID != "" {
		logger.Info("diffing with previous scan", "previous", previousRunID, "current", scanResult.Run.ID)
		diffResult, diffErr := diffEngine.Diff(previousRunID, scanResult.Run.ID)
		if diffErr != nil {
			logger.Error("diff failed", "error", diffErr)
		} else {
			logger.Info("diff complete",
				"new", diffResult.NewCount,
				"gone", diffResult.GoneCount,
				"changed", diffResult.ChangedCount,
				"unchanged", diffResult.UnchangedCount,
			)

			// Historian analysis
			analysis := historian.AnalyzeWithoutLLM(diffResult)
			logger.Info("historian analysis",
				"risk_level", analysis.RiskLevel,
				"summary", analysis.Summary,
			)

			auditLogger.Log(ctx, "diff_analysis", "historian", map[string]string{
				"previous_run": previousRunID,
				"current_run":  scanResult.Run.ID,
				"risk_level":   analysis.RiskLevel,
				"new":          fmt.Sprintf("%d", diffResult.NewCount),
				"gone":         fmt.Sprintf("%d", diffResult.GoneCount),
			})
		}
	} else {
		logger.Info("first scan for program — no diff available")
	}

	// Stage 5a: Duplicate Detection
	if ctx.Err() != nil {
		return
	}

	logger.Info("running duplicate detection", "findings", len(reported))
	dedupResults, _ := dupChecker.CheckBatch(reported)
	var dedupFiltered []*models.Finding
	for i, dr := range dedupResults {
		switch dr.Verdict {
		case dedup.VerdictConfirmed:
			reported[i].Status = models.StatusDuplicate
			writer.WriteFinding(ctx, reported[i])
			auditLogger.Log(ctx, "dedup_confirmed", "dedup", map[string]string{
				"finding_id": dr.FindingID,
				"matched_id": dr.MatchedID,
				"reason":     dr.Reason,
			})
			logger.Info("duplicate detected — skipping", "finding_id", dr.FindingID, "matched", dr.MatchedID)
		case dedup.VerdictLikely:
			logger.Warn("possible duplicate — keeping with warning",
				"finding_id", dr.FindingID,
				"matched_id", dr.MatchedID,
				"similarity", dr.Similarity,
			)
			dedupFiltered = append(dedupFiltered, reported[i])
		default:
			dedupFiltered = append(dedupFiltered, reported[i])
		}
	}
	logger.Info("dedup complete", "before", len(reported), "after", len(dedupFiltered))

	// Stage 5b: 7-Question Gate
	if ctx.Err() != nil {
		return
	}

	logger.Info("running 7-Question Gate", "findings", len(dedupFiltered))
	var gateFiltered []*models.Finding
	gateResults, _ := qualityGate.EvaluateBatch(ctx, dedupFiltered)
	for i, gr := range gateResults {
		switch gr.Verdict {
		case gate.VerdictKill:
			logger.Info("gate: KILL — dropping finding",
				"finding_id", gr.FindingID,
				"score", gr.Score,
				"reason", gr.Reasoning,
			)
			auditLogger.Log(ctx, "gate_kill", "gate", map[string]string{
				"finding_id": gr.FindingID,
				"score":      fmt.Sprintf("%d/7", gr.Score),
				"reason":     gr.Reasoning,
			})
		case gate.VerdictDowngrade:
			logger.Info("gate: DOWNGRADE — reducing severity",
				"finding_id", gr.FindingID,
				"score", gr.Score,
				"suggested_severity", gr.SuggestedSeverity,
			)
			if gr.SuggestedSeverity != "" {
				dedupFiltered[i].Severity = models.Severity(gr.SuggestedSeverity)
				writer.WriteFinding(ctx, dedupFiltered[i])
			}
			gateFiltered = append(gateFiltered, dedupFiltered[i])
		default: // PASS
			gateFiltered = append(gateFiltered, dedupFiltered[i])
		}
	}
	logger.Info("gate complete", "before", len(dedupFiltered), "after", len(gateFiltered))

	// Stage 5c: Exploit Chain Builder
	if ctx.Err() != nil {
		return
	}

	if len(gateFiltered) >= 2 {
		logger.Info("running exploit chain analysis", "findings", len(gateFiltered))
		chains, chainErr := chainBuilder.FindChains(ctx, gateFiltered)
		if chainErr != nil {
			logger.Warn("chain analysis failed", "error", chainErr)
		} else if len(chains) > 0 {
			logger.Info("exploit chains found", "count", len(chains))
			for _, ch := range chains {
				logger.Info("chain",
					"name", ch.Name,
					"severity", ch.Severity,
					"confidence", ch.Confidence,
					"steps", len(ch.Steps),
				)
				auditLogger.Log(ctx, "exploit_chain", "chainer", map[string]string{
					"chain_id":   ch.ID,
					"name":       ch.Name,
					"severity":   ch.Severity,
					"confidence": fmt.Sprintf("%.2f", ch.Confidence),
				})

				// Print chain to stdout
				fmt.Fprintf(os.Stdout, "\n===== EXPLOIT CHAIN: %s =====\n", ch.Name)
				fmt.Fprintf(os.Stdout, "Severity: %s | Confidence: %.0f%%\n", ch.Severity, ch.Confidence*100)
				fmt.Fprintf(os.Stdout, "Impact: %s\n", ch.Impact)
				for _, step := range ch.Steps {
					fmt.Fprintf(os.Stdout, "  Step %d: [%s] %s — %s\n", step.Order, step.VulnClass, step.URL, step.Action)
				}
			}
		} else {
			logger.Info("no exploit chains found")
		}
	}

	// Stage 5d: Exploiter + Verifier (optional)
	if ctx.Err() != nil {
		return
	}

	if *enableExploiter && verifier != nil {
		logger.Info("running Exploiter+Verifier", "findings", len(reported))
		for _, f := range reported {
			if ctx.Err() != nil {
				break
			}

			poc, pocErr := exploiterAgent.GeneratePoC(ctx, f)
			if pocErr != nil {
				logger.Warn("PoC generation failed", "finding_id", f.ID, "error", pocErr)
				auditLogger.Log(ctx, "poc_failed", "exploiter", map[string]string{
					"finding_id": f.ID,
					"error":      pocErr.Error(),
				})
				continue
			}

			result, verifyErr := verifier.Verify(ctx, poc)
			if verifyErr != nil {
				logger.Warn("PoC verification failed", "finding_id", f.ID, "error", verifyErr)
				continue
			}

			auditLogger.Log(ctx, "poc_verified", "verifier", map[string]string{
				"finding_id": f.ID,
				"verified":   fmt.Sprintf("%t", result.Verified),
				"evidence":   result.Evidence,
				"duration":   result.Duration.String(),
			})

			if result.Verified {
				logger.Info("PoC VERIFIED", "finding_id", f.ID, "evidence", result.Evidence)
			} else {
				logger.Info("PoC not verified", "finding_id", f.ID, "evidence", result.Evidence)
			}
		}
	}

	// Stage 6: HITL — send to Telegram for human review (use gate-filtered list)
	reported = gateFiltered // replace reported with gate-filtered for HITL
	var approved []*models.Finding
	if *telegramToken != "" && *telegramChatID != "" {
		chatID, parseErr := strconv.ParseInt(*telegramChatID, 10, 64)
		if parseErr != nil {
			logger.Error("invalid telegram-chat-id", "error", parseErr)
			os.Exit(1)
		}

		hitlBot := hitl.NewBot(hitl.Config{
			Token:   *telegramToken,
			ChatID:  chatID,
			Timeout: *hitlTimeout,
			Logger:  logger,
			OnDecision: func(dctx context.Context, d hitl.Decision) error {
				now := time.Now()
				var newStatus models.FindingStatus
				switch d.State {
				case hitl.StateApproved:
					newStatus = models.StatusApproved
				case hitl.StateRejected, hitl.StateTimedOut:
					newStatus = models.StatusRejected
				default:
					newStatus = models.StatusRejected
				}

				// Find and update the finding
				for _, f := range reported {
					if f.ID == d.FindingID {
						f.Status = newStatus
						f.HITLDecision = d.Reason
						f.HITLDecidedAt = &now
						f.UpdatedAt = now
						writer.WriteFinding(dctx, f)

						if newStatus == models.StatusApproved {
							approved = append(approved, f)
						}
						break
					}
				}

				auditLogger.Log(dctx, models.AuditHITLDecision, "hitl", map[string]string{
					"finding_id": d.FindingID,
					"state":      string(d.State),
					"reason":     d.Reason,
				})

				return nil
			},
		})

		// Start polling in background
		go hitlBot.StartPolling(ctx)

		// Send findings to Telegram
		logger.Info("sending findings to Telegram for review", "count", len(reported))
		if err := hitlBot.SendBatch(ctx, reported); err != nil {
			logger.Error("failed to send findings to Telegram", "error", err)
		}

		// Wait for all decisions
		logger.Info("waiting for human decisions via Telegram",
			"pending", hitlBot.PendingCount(),
			"timeout", hitlTimeout.String(),
		)
		hitlBot.WaitForAll(ctx)
		hitlBot.Stop()

		logger.Info("HITL decisions completed", "approved", len(approved))
	} else {
		logger.Info("HITL skipped — no Telegram token/chat-id configured")
		approved = reported
	}

	// Final summary
	fmt.Fprintf(os.Stderr, "\n=== Scan Complete ===\n")
	fmt.Fprintf(os.Stderr, "Hosts scanned:   %d\n", scanResult.Run.HostsScanned)
	fmt.Fprintf(os.Stderr, "URLs crawled:    %d\n", scanResult.Run.URLsCrawled)
	fmt.Fprintf(os.Stderr, "Raw findings:    %d\n", len(scanResult.Findings))
	fmt.Fprintf(os.Stderr, "Analyzed:        %d\n", len(analyzed))
	fmt.Fprintf(os.Stderr, "Reports:         %d\n", len(reported))
	fmt.Fprintf(os.Stderr, "Approved:        %d\n", len(approved))
	fmt.Fprintf(os.Stderr, "Gate filtered:   %d\n", len(gateFiltered))
	fmt.Fprintf(os.Stderr, "Exploiter:       %v\n", *enableExploiter)
	fmt.Fprintf(os.Stderr, "====================\n")

	auditLogger.Log(ctx, "pipeline_completed", "system", map[string]string{
		"raw_findings": fmt.Sprintf("%d", len(scanResult.Findings)),
		"analyzed":     fmt.Sprintf("%d", len(analyzed)),
		"reported":     fmt.Sprintf("%d", len(reported)),
		"approved":     fmt.Sprintf("%d", len(approved)),
	})

	// Verify audit log integrity
	count, err := auditLogger.Verify()
	if err != nil {
		logger.Error("audit log integrity check FAILED", "error", err)
	} else {
		logger.Info("audit log integrity verified", "entries", count)
	}

	// Graceful shutdown
	egressProxy.Shutdown(ctx)
}
