package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"time"

	"github.com/ggwpgoend/bb-hunter/internal/analyst"
	"github.com/ggwpgoend/bb-hunter/internal/audit"
	"github.com/ggwpgoend/bb-hunter/internal/config"
	"github.com/ggwpgoend/bb-hunter/internal/cost"
	"github.com/ggwpgoend/bb-hunter/internal/db"
	"github.com/ggwpgoend/bb-hunter/internal/hitl"
	"github.com/ggwpgoend/bb-hunter/internal/llm"
	"github.com/ggwpgoend/bb-hunter/internal/models"
	"github.com/ggwpgoend/bb-hunter/internal/proxy"
	"github.com/ggwpgoend/bb-hunter/internal/ratelimit"
	"github.com/ggwpgoend/bb-hunter/internal/reporter"
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
	telegramChat := flag.Int64("telegram-chat", 0, "Telegram chat ID (auto-detected on /start)")
	ratePerSecond := flag.Float64("rate", 10, "requests per second to target")
	dryRun := flag.Bool("dry-run", false, "parse scope and validate config without scanning")
	flag.Parse()

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
	if *telegramToken == "" {
		*telegramToken = os.Getenv("TELEGRAM_BOT_TOKEN")
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
	fmt.Fprintf(os.Stderr, "\n=== BB-Hunter Phase 1 ===\n")
	fmt.Fprintf(os.Stderr, "Program:    %s\n", sf.Program)
	fmt.Fprintf(os.Stderr, "Platform:   %s\n", sf.Platform)
	fmt.Fprintf(os.Stderr, "Domains:    %v\n", sf.Domains)
	fmt.Fprintf(os.Stderr, "Proxy:      %s\n", *proxyAddr)
	fmt.Fprintf(os.Stderr, "DB:         %s\n", *dbPath)
	fmt.Fprintf(os.Stderr, "Rate:       %.0f req/s\n", *ratePerSecond)
	if *telegramToken != "" {
		fmt.Fprintf(os.Stderr, "Telegram:   enabled\n")
	}
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

	// Initialize Telegram HITL bot (optional)
	var telegramBot *hitl.Bot
	if *telegramToken != "" {
		telegramBot = hitl.NewBot(*telegramToken, logger)
		if *telegramChat != 0 {
			telegramBot.SetChatID(*telegramChat)
		}
		go telegramBot.PollUpdates(ctx)
		logger.Info("telegram HITL bot started")
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

	// Stage 4: HITL — send to Telegram for approval
	if telegramBot != nil && len(reported) > 0 {
		logger.Info("sending findings to Telegram for HITL review", "count", len(reported))
		for _, f := range reported {
			if err := telegramBot.SendFinding(ctx, f); err != nil {
				logger.Warn("hitl: failed to send finding", "finding_id", f.ID, "error", err)
			}
		}

		// Wait for decisions (with timeout)
		fmt.Fprintf(os.Stderr, "\nWaiting for HITL decisions via Telegram... (Ctrl+C to exit)\n")
		decisionCount := 0
		hitlTimeout := time.After(30 * time.Minute)
	hitlLoop:
		for decisionCount < len(reported) {
			select {
			case d := <-telegramBot.Decisions():
				decisionCount++
				now := d.DecidedAt
				for _, f := range reported {
					if f.ID == d.FindingID {
						if d.Action == "approve" {
							f.Status = models.StatusApproved
						} else {
							f.Status = models.StatusRejected
						}
						f.HITLDecision = d.Action
						f.HITLDecidedAt = &now
						f.UpdatedAt = now
						writer.WriteFinding(ctx, f)
						auditLogger.Log(ctx, "hitl_decision", "human", map[string]string{
							"finding_id": f.ID,
							"action":     d.Action,
						})
						logger.Info("hitl: decision applied",
							"finding_id", f.ID,
							"action", d.Action,
							"remaining", len(reported)-decisionCount,
						)
						break
					}
				}
			case <-hitlTimeout:
				logger.Warn("hitl: timeout waiting for decisions", "pending", len(reported)-decisionCount)
				break hitlLoop
			case <-ctx.Done():
				break hitlLoop
			}
		}
		logger.Info("hitl: review complete", "decided", decisionCount, "total", len(reported))
	}

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

	// Final summary
	fmt.Fprintf(os.Stderr, "\n=== Scan Complete ===\n")
	fmt.Fprintf(os.Stderr, "Hosts scanned:   %d\n", scanResult.Run.HostsScanned)
	fmt.Fprintf(os.Stderr, "URLs crawled:    %d\n", scanResult.Run.URLsCrawled)
	fmt.Fprintf(os.Stderr, "Raw findings:    %d\n", len(scanResult.Findings))
	fmt.Fprintf(os.Stderr, "Analyzed:        %d\n", len(analyzed))
	fmt.Fprintf(os.Stderr, "Reports:         %d\n", len(reported))
	fmt.Fprintf(os.Stderr, "====================\n")

	auditLogger.Log(ctx, "pipeline_completed", "system", map[string]string{
		"raw_findings": fmt.Sprintf("%d", len(scanResult.Findings)),
		"analyzed":     fmt.Sprintf("%d", len(analyzed)),
		"reported":     fmt.Sprintf("%d", len(reported)),
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
