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
	"sync"
	"syscall"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/agent"
	"github.com/ggwpgoend/bb-hunter/internal/analyst"
	"github.com/ggwpgoend/bb-hunter/internal/audit"
	"github.com/ggwpgoend/bb-hunter/internal/browser"
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
	"github.com/ggwpgoend/bb-hunter/internal/scheduler"
	"github.com/ggwpgoend/bb-hunter/internal/scope"
	"github.com/ggwpgoend/bb-hunter/internal/submit"
)

// stageModelCfg defines which model to use per provider for a given pipeline stage.
type stageModelCfg struct {
	Cerebras    string // fastest free reasoning tier (Qwen-3-235B); free deprecates 2026-05-27
	Groq        string // LPU inference, Llama / Qwen / GPT-OSS catalog
	Gemini      string // huge context (1M), good for analyst-style large-input stages
	Samba       string
	FreeTheAI   string
	Canopy      string
	CloseRouter string // pay-per-use; only used on premium stages by default
	LLM7        string
	UncloseAI   string
	Pollinations string
}

// stageDefaults maps pipeline stages to optimal model selections.
// Each stage uses the best model for its specific task type:
//   - analyst:   classification & reasoning → strongest reasoning models
//   - reporter:  writing vulnerability reports → best writers
//   - historian: diff analysis (lightweight) → fast models
//   - gate:      7-question validation (accuracy) → accurate structured output
//   - chainer:   exploit chain discovery (creative) → creative reasoning
//   - exploiter: PoC code generation → coding models
//   - agent:     autonomous bug hunting → best reasoning + tool use
var stageDefaults = map[string]stageModelCfg{
	// analyst: Deep processing of large data (scan outputs, DOMs). Needs large context + reasoning.
	// Gemini 2.5 Flash (1M ctx) is ideal here; Cerebras / Groq cover the reasoning fallback.
	"analyst": {
		Cerebras:     "qwen-3-235b-a22b-instruct-2507",
		Groq:         "llama-3.3-70b-versatile",
		Gemini:       "gemini-2.5-flash",
		Samba:        "DeepSeek-V3.2",
		FreeTheAI:    "gemini-2.5-flash",
		Canopy:       "moonshotai/kimi-k2.6", // Kimi has massive context
		CloseRouter:  "anthropic/claude-3-5-sonnet-20241022",
		LLM7:         "gpt-o3-2025-04-16", // o3 is great at reasoning
		UncloseAI:    "hf.co/unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF:Q4_K_M",
		Pollinations: "openai-large",
	},
	// reporter: Writing high-quality bug bounty reports. Needs good formatting and clarity.
	"reporter": {
		Cerebras:     "qwen-3-235b-a22b-instruct-2507",
		Groq:         "llama-3.3-70b-versatile",
		Gemini:       "gemini-2.5-flash",
		Samba:        "MiniMax-M2.7",
		FreeTheAI:    "gemini-2.5-flash",
		Canopy:       "moonshotai/kimi-k2.6",
		CloseRouter:  "anthropic/claude-3-5-sonnet-20241022",
		LLM7:         "mistral-large-2411",
		UncloseAI:    "hf.co/unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF:Q4_K_M",
		Pollinations: "openai-large",
	},
	// historian: Diffing states, tracking what changed over time. Needs large context.
	"historian": {
		Cerebras:     "qwen-3-235b-a22b-instruct-2507",
		Groq:         "llama-3.3-70b-versatile",
		Gemini:       "gemini-2.5-flash",
		Samba:        "gemma-3-12b-it",
		FreeTheAI:    "gemini-2.5-flash",
		Canopy:       "moonshotai/kimi-k2.6",
		CloseRouter:  "anthropic/claude-3-haiku-20240307",
		LLM7:         "gpt-4o-mini-2024-07-18",
		UncloseAI:    "hf.co/unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF:Q4_K_M",
		Pollinations: "openai",
	},
	// gate: Fast validation filter (7 questions). Needs speed and strict logic.
	"gate": {
		Cerebras:     "qwen-3-235b-a22b-instruct-2507",
		Groq:         "llama-3.3-70b-versatile",
		Gemini:       "gemini-2.5-flash",
		Samba:        "DeepSeek-V3.2",
		FreeTheAI:    "gemini-2.5-flash",
		Canopy:       "minimax/minimax-m2.5",
		CloseRouter:  "anthropic/claude-3-haiku-20240307",
		LLM7:         "deepseek-r1-0528",
		UncloseAI:    "hf.co/unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF:Q4_K_M",
		Pollinations: "openai",
	},
	// chainer: Building exploit chains. Needs top-tier reasoning.
	"chainer": {
		Cerebras:     "qwen-3-235b-a22b-instruct-2507", // best free reasoning option
		Groq:         "llama-3.3-70b-versatile",
		Gemini:       "gemini-2.5-flash",
		Samba:        "DeepSeek-V3.1",
		FreeTheAI:    "gemini-2.5-flash",
		Canopy:       "minimax/minimax-m2.5",
		CloseRouter:  "anthropic/claude-opus-4.7",
		LLM7:         "deepseek-r1-0528",
		UncloseAI:    "hf.co/unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF:Q4_K_M",
		Pollinations: "openai-large",
	},
	// exploiter: Writing PoC code, tampers, bypasses. Needs best coding models.
	"exploiter": {
		Cerebras:     "qwen-3-235b-a22b-instruct-2507",
		Groq:         "llama-3.3-70b-versatile",
		Gemini:       "gemini-2.5-flash",
		Samba:        "DeepSeek-V3.2",
		FreeTheAI:    "gemini-2.5-flash",
		Canopy:       "xiaomimimo/mimo-v2.5",
		CloseRouter:  "anthropic/claude-3-5-sonnet-20241022",
		LLM7:         "qwen2.5-coder-32b-instruct", // Specifically for coding
		UncloseAI:    "hf.co/unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF:Q4_K_M", // Coding specialist
		Pollinations: "qwen-coder",
	},
	// agent: The main autonomous driver. Needs absolute best tool calling and planning.
	"agent": {
		Cerebras:     "qwen-3-235b-a22b-instruct-2507",
		Groq:         "llama-3.3-70b-versatile",
		Gemini:       "gemini-2.5-flash",
		Samba:        "DeepSeek-V3.2",
		FreeTheAI:    "gemini-2.5-flash", // Claude Opus 4.7 is unmatched for agent tool calling
		Canopy:       "minimax/minimax-m2.5",
		CloseRouter:  "anthropic/claude-opus-4.7",
		LLM7:         "gpt-o3-2025-04-16", // o3 as fallback
		UncloseAI:    "hf.co/unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF:Q4_K_M",
		Pollinations: "deepseek-v3",
	},
}

// stageBuildOpts bundles every key/model knob used when constructing per-stage
// clients. Grouping these into a struct keeps buildStageClient's signature
// stable as more providers (e.g. CloseRouter) are added.
type stageBuildOpts struct {
	CerebrasKey      string
	GroqKey          string
	GeminiKey        string
	SambaKey         string
	FreeTheAIKey     string
	CanopyKey        string
	CanopyFastKey    string
	LLM7Key          string
	UncloseAIKey     string
	CloseRouterKey   string
	CloseRouterModel string  // overrides stageDefaults.CloseRouter when non-empty
	CloseRouterUSD   float64 // daily USD spending cap for CloseRouter
}

// buildStageClient creates an LLM client optimized for a specific pipeline stage.
// It selects the best model per provider based on the stage's requirements.
// canopyFastKey is used for speed-critical stages (analyst, gate, chainer, exploiter).
//
// Provider order matters: round-robin walks providers in append order, so the
// fastest / most-capable free providers are appended first. CloseRouter (when
// configured) leads on premium stages until its daily USD budget is exhausted,
// after which Available()=false and the free chain takes over.
func buildStageClient(stage string, opts stageBuildOpts, logger *slog.Logger) *llm.Client {
	cfg, ok := stageDefaults[stage]
	if !ok {
		logger.Warn("unknown stage for model routing, using analyst defaults", "stage", stage)
		cfg = stageDefaults["analyst"]
	}

	var providers []llm.Provider

	// CloseRouter first so the premium model leads round-robin until budget runs out.
	crModel := opts.CloseRouterModel
	if crModel == "" {
		crModel = cfg.CloseRouter
	}
	if opts.CloseRouterKey != "" && crModel != "" {
		providers = append(providers, llm.NewCloseRouterProvider(
			opts.CloseRouterKey, crModel, opts.CloseRouterUSD))
	}

	// Free premium tier — Cerebras (fastest free reasoning at ~200ms, Qwen-3-235B),
	// Groq (LPU inference at ~250-400ms), Gemini Flash (1M context, 500 RPD).
	// These cover the role CloseRouter used to fill in dev.
	//
	// Per-provider soft timeouts ensure slow responses fail fast so the
	// round-robin can try the next provider. MaxCooldown caps exponential
	// backoff for providers with per-minute rate limits.
	if opts.CerebrasKey != "" && cfg.Cerebras != "" {
		providers = append(providers, llm.NewOpenAICompatProvider(
			"cerebras", "https://api.cerebras.ai/v1", opts.CerebrasKey, cfg.Cerebras).
			WithMaxCooldown(65).
			WithSoftTimeout(10*time.Second))
	}
	if opts.GroqKey != "" && cfg.Groq != "" {
		providers = append(providers, llm.NewOpenAICompatProvider(
			"groq", "https://api.groq.com/openai/v1", opts.GroqKey, cfg.Groq).
			WithMaxCooldown(65).
			WithSoftTimeout(10*time.Second))
	}
	if opts.GeminiKey != "" && cfg.Gemini != "" {
		providers = append(providers, llm.NewGeminiProvider(opts.GeminiKey, cfg.Gemini))
	}

	if opts.SambaKey != "" {
		providers = append(providers, llm.NewOpenAICompatProvider(
			"samba", "https://api.sambanova.ai/v1", opts.SambaKey, cfg.Samba).
			WithSoftTimeout(45*time.Second))
	}
	if opts.FreeTheAIKey != "" {
		providers = append(providers, llm.NewOpenAICompatProvider(
			"freetheai", "https://api.freetheai.xyz/v1", opts.FreeTheAIKey, cfg.FreeTheAI).
			WithSoftTimeout(30*time.Second))
	}

	// Speed-critical stages use Fast Bundle key, heavy stages use Unlimited key
	ck := opts.CanopyKey
	switch stage {
	case "analyst", "gate", "chainer", "exploiter":
		if opts.CanopyFastKey != "" {
			ck = opts.CanopyFastKey
		}
	}
	if ck != "" {
		providers = append(providers, llm.NewOpenAICompatProvider(
			"canopy", "https://inference.canopywave.io/v1", ck, cfg.Canopy).
			WithSoftTimeout(60*time.Second))
	}

	// LLM7 and UncloseAI are last-resort free fallbacks; they're slower and
	// less reliable, but help when everything else is exhausted.
	if opts.LLM7Key != "" && cfg.LLM7 != "" {
		providers = append(providers, llm.NewOpenAICompatProvider(
			"llm7", "https://api.llm7.io/v1", opts.LLM7Key, cfg.LLM7).
			WithSoftTimeout(30*time.Second))
	}
	if opts.UncloseAIKey != "" && cfg.UncloseAI != "" {
		providers = append(providers, llm.NewOpenAICompatProvider(
			"uncloseai", "https://hermes.ai.unturf.com/v1", opts.UncloseAIKey, cfg.UncloseAI).
			WithSoftTimeout(45*time.Second))
	}

	if len(providers) == 0 {
		return nil
	}

	client, _ := llm.NewClient(providers...)

	logger.Info("stage client ready",
		"stage", stage,
		"providers", len(providers),
		"cerebras", cfg.Cerebras,
		"groq", cfg.Groq,
		"gemini", cfg.Gemini,
		"samba", cfg.Samba,
		"freetheai", cfg.FreeTheAI,
		"canopy", cfg.Canopy,
		"llm7", cfg.LLM7,
		"uncloseai", cfg.UncloseAI,
		"closerouter", crModel,
	)

	return client
}

func main() {
	scopePath := flag.String("scope", "scope.yaml", "path to scope.yaml")
	proxyAddr := flag.String("proxy-addr", "127.0.0.1:18080", "egress proxy listen address")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, error")
	dbPath := flag.String("db", "bb-hunter.db", "path to SQLite database")
	geminiKey := flag.String("gemini-key", "", "Google AI Studio API key (env: GEMINI_API_KEY)")
	cerebrasKey := flag.String("cerebras-key", "", "Cerebras API key (env: CEREBRAS_API_KEY)")
	groqKey := flag.String("groq-key", "", "Groq API key (env: GROQ_API_KEY)")
	sambaKey := flag.String("samba-key", "", "SambaNova API key (env: SAMBA_API_KEY)")
	openrouterKey := flag.String("openrouter-key", "", "OpenRouter API key (env: OPENROUTER_API_KEY)")
	openrouterModel := flag.String("openrouter-model", "deepseek/deepseek-v4-flash:free", "OpenRouter model name (env: OPENROUTER_MODEL). Default :free model rotates; many :free models share an upstream throttle so set OPENROUTER_MODEL or buy $10 credit to lift the limit.")
	togetherKey := flag.String("together-key", "", "Together AI API key (env: TOGETHER_API_KEY)")
	nvidiaNimKey := flag.String("nvidia-key", "", "NVIDIA NIM API key (env: NVIDIA_API_KEY)")
	glhfKey := flag.String("glhf-key", "", "GLHF.chat API key (env: GLHF_API_KEY)")
	chutesKey := flag.String("chutes-key", "", "Chutes AI API key (env: CHUTES_API_KEY)")
	chutesModel := flag.String("chutes-model", "deepseek-ai/DeepSeek-V3.2-TEE", "Chutes AI model name (env: CHUTES_MODEL). Old default meta-llama/Llama-3.3-70B-Instruct was removed from the Chutes catalog.")
	freetheaiKey := flag.String("freetheai-key", "", "FreeTheAI API key (env: FREETHEAI_API_KEY)")
	freetheaiModel := flag.String("freetheai-model", "cat/gemini-3-flash", "FreeTheAI model name (env: FREETHEAI_MODEL)")
	canopywaveKey := flag.String("canopywave-key", "", "Canopy Wave API key — Unlimited plan (env: CANOPYWAVE_API_KEY)")
	canopywaveFastKey := flag.String("canopywave-fast-key", "", "Canopy Wave API key — Fast Bundle (env: CANOPYWAVE_FAST_KEY)")
	canopywaveModel := flag.String("canopywave-model", "minimax/minimax-m2.5", "Canopy Wave model name (env: CANOPYWAVE_MODEL)")
	closerouterKey := flag.String("closerouter-key", "", "CloseRouter API key — pay-per-use (env: CLOSEROUTER_API_KEY)")
	closerouterModel := flag.String("closerouter-model", "", "CloseRouter model override; empty=per-stage default (env: CLOSEROUTER_MODEL)")
	closerouterBudget := flag.Float64("closerouter-daily-usd", 1.0, "Client-side daily USD spending cap for CloseRouter (0 = disabled, server-side cap still applies)")
	llm7Key := flag.String("llm7-key", "", "LLM7.io API key")
	llm7Model := flag.String("llm7-model", "qwen2.5-coder-32b-instruct", "LLM7.io model name")
	uncloseaiKey := flag.String("uncloseai-key", "", "UncloseAI API key")
	uncloseaiModel := flag.String("uncloseai-model", "hf.co/unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF:Q4_K_M", "UncloseAI model name")
	pollinationsModel := flag.String("pollinations-model", "openai", "Pollinations.ai model name")

	telegramToken := flag.String("telegram-token", "", "Telegram bot token (env: TELEGRAM_BOT_TOKEN)")
	telegramChatID := flag.String("telegram-chat-id", "", "Telegram chat ID for HITL (env: TELEGRAM_CHAT_ID)")
	hitlTimeout := flag.Duration("hitl-timeout", 1*time.Hour, "HITL decision timeout")
	sandboxImage := flag.String("sandbox-image", "python:3.12-slim", "Docker image for PoC sandbox")
	sandboxMemory := flag.String("sandbox-memory", "256m", "sandbox memory limit")
	sandboxTimeout := flag.Duration("sandbox-timeout", 30*time.Second, "sandbox execution timeout")
	enableExploiter := flag.Bool("exploit", false, "enable Exploiter+Verifier (requires Docker)")
	enableBrowser := flag.Bool("browser-poc", false, "enable browser-based PoC evidence (requires agent-browser)")
	screenshotDir := flag.String("screenshot-dir", "screenshots", "directory for browser PoC screenshots")
	parallelWorkers := flag.Int("parallel", 0, "number of parallel domain scan workers (0 = sequential)")
	autoSubmit := flag.Bool("auto-submit", false, "auto-submit approved findings to platform")
	monitorMode := flag.Bool("monitor", false, "enable continuous monitoring mode")
	monitorInterval := flag.Duration("monitor-interval", 6*time.Hour, "interval between monitor scans")
	ratePerSecond := flag.Float64("rate", 10, "requests per second to target")
	dryRun := flag.Bool("dry-run", false, "parse scope and validate config without scanning")
	checkLLM := flag.Bool("check-llm", false, "check LLM provider availability and exit")
	checkFfuf := flag.Bool("check-ffuf", false, "verify ffuf binary is in PATH and exit")
	agentMode := flag.Bool("agent", false, "enable autonomous LLM agent mode (AI drives the tools)")
	agentMaxSteps := flag.Int("agent-steps", 0, "max steps for agent mode (0 = unlimited; first Ctrl+C requests a graceful stop, second hard-kills)")
	agentDelayMs := flag.Int("agent-delay", 3000, "delay between LLM calls in ms (100 = 10 req/sec)")
	flag.Parse()

	// Fallback to env vars for Telegram config
	if *telegramToken == "" {
		*telegramToken = os.Getenv("TELEGRAM_BOT_TOKEN")
	}
	if *llm7Key == "" {
		*llm7Key = os.Getenv("LLM7_API_KEY")
	}
	if *uncloseaiKey == "" {
		*uncloseaiKey = os.Getenv("UNCLOSEAI_API_KEY")
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
	if *openrouterKey == "" {
		*openrouterKey = os.Getenv("OPENROUTER_API_KEY")
	}
	if *togetherKey == "" {
		*togetherKey = os.Getenv("TOGETHER_API_KEY")
	}
	if *nvidiaNimKey == "" {
		*nvidiaNimKey = os.Getenv("NVIDIA_API_KEY")
	}
	if *glhfKey == "" {
		*glhfKey = os.Getenv("GLHF_API_KEY")
	}
	if *chutesKey == "" {
		*chutesKey = os.Getenv("CHUTES_API_KEY")
	}
	if *freetheaiKey == "" {
		*freetheaiKey = os.Getenv("FREETHEAI_API_KEY")
	}
	if *freetheaiModel == "" || *freetheaiModel == "cat/gemini-3-flash" {
		if env := os.Getenv("FREETHEAI_MODEL"); env != "" {
			*freetheaiModel = env
		}
	}
	if *canopywaveKey == "" {
		*canopywaveKey = os.Getenv("CANOPYWAVE_API_KEY")
	}
	if *canopywaveModel == "" || *canopywaveModel == "minimax/minimax-m2.5" {
		if env := os.Getenv("CANOPYWAVE_MODEL"); env != "" {
			*canopywaveModel = env
		}
	}
	if *canopywaveFastKey == "" {
		*canopywaveFastKey = os.Getenv("CANOPYWAVE_FAST_KEY")
	}
	if *closerouterKey == "" {
		*closerouterKey = os.Getenv("CLOSEROUTER_API_KEY")
	}
	if *closerouterModel == "" {
		*closerouterModel = os.Getenv("CLOSEROUTER_MODEL")
	}
	if env := os.Getenv("OPENROUTER_MODEL"); env != "" {
		*openrouterModel = env
	}
	if env := os.Getenv("CHUTES_MODEL"); env != "" {
		*chutesModel = env
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

	// Start egress proxy (skip in agent mode — direct connections are more reliable)
	var egressProxy *proxy.EgressProxy
	if !*agentMode {
		egressProxy = proxy.NewEgressProxy(enforcer, *proxyAddr, logger)
		go func() {
			if err := egressProxy.ListenAndServe(); err != nil {
				logger.Error("egress proxy failed", "error", err)
			}
		}()
		logger.Info("egress proxy started", "addr", *proxyAddr)
	} else {
		logger.Info("egress proxy skipped (agent mode)")
	}

	// Print banner
	fmt.Fprintf(os.Stderr, "\n=== BB-Hunter ===\n")
	fmt.Fprintf(os.Stderr, "Program:    %s\n", sf.Program)
	fmt.Fprintf(os.Stderr, "Platform:   %s\n", sf.Platform)
	fmt.Fprintf(os.Stderr, "Domains:    %v\n", sf.Domains)
	if *agentMode {
		fmt.Fprintf(os.Stderr, "Proxy:      disabled (agent mode)\n")
	} else {
		fmt.Fprintf(os.Stderr, "Proxy:      %s\n", *proxyAddr)
	}
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

	// Two-stage shutdown: first SIGINT optionally fires a "graceful stop"
	// callback (set by agent mode when the agent is created). Second SIGINT
	// (or any SIGTERM) cancels the context for a hard exit.
	var (
		gracefulStop   func()
		gracefulStopMu sync.Mutex
	)
	setGracefulStop := func(f func()) {
		gracefulStopMu.Lock()
		gracefulStop = f
		gracefulStopMu.Unlock()
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		firstSeen := false
		for sig := range sigCh {
			if sig == syscall.SIGTERM {
				logger.Info("shutting down (SIGTERM)", "signal", sig.String())
				cancel()
				return
			}
			gracefulStopMu.Lock()
			gs := gracefulStop
			gracefulStopMu.Unlock()
			if !firstSeen && gs != nil {
				firstSeen = true
				fmt.Fprintf(os.Stderr, "\n[Ctrl+C] Graceful stop requested — agent will commit findings and exit. Press Ctrl+C again to hard-kill.\n\n")
				gs()
				continue
			}
			logger.Info("shutting down", "signal", sig.String())
			cancel()
			return
		}
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
		providers = append(providers, llm.NewOpenAICompatProvider("cerebras", "https://api.cerebras.ai/v1", *cerebrasKey, "qwen-3-235b-a22b-instruct-2507"))
		quotas = append(quotas, cost.ProviderQuota{Name: "cerebras", DailyRequests: 200})
		logger.Info("LLM provider added", "name", "cerebras", "model", "qwen-3-235b-a22b")
	}
	if *groqKey != "" {
		providers = append(providers, llm.NewOpenAICompatProvider("groq", "https://api.groq.com/openai/v1", *groqKey, "llama-3.3-70b-versatile"))
		quotas = append(quotas, cost.ProviderQuota{Name: "groq", DailyRequests: 200})
		logger.Info("LLM provider added", "name", "groq", "model", "llama-3.3-70b")
	}
	if *sambaKey != "" {
		providers = append(providers, llm.NewOpenAICompatProvider("sambanova", "https://api.sambanova.ai/v1", *sambaKey, "Meta-Llama-3.3-70B-Instruct"))
		quotas = append(quotas, cost.ProviderQuota{Name: "sambanova", DailyRequests: 200})
		logger.Info("LLM provider added", "name", "sambanova", "model", "Meta-Llama-3.3-70B")
	}
	if *openrouterKey != "" {
		providers = append(providers, llm.NewOpenAICompatProvider("openrouter", "https://openrouter.ai/api/v1", *openrouterKey, *openrouterModel))
		quotas = append(quotas, cost.ProviderQuota{Name: "openrouter", DailyRequests: 200})
		logger.Info("LLM provider added", "name", "openrouter", "model", *openrouterModel)
	}
	if *togetherKey != "" {
		providers = append(providers, llm.NewOpenAICompatProvider("together", "https://api.together.xyz/v1", *togetherKey, "meta-llama/Llama-3.3-70B-Instruct-Turbo-Free"))
		quotas = append(quotas, cost.ProviderQuota{Name: "together", DailyRequests: 200})
		logger.Info("LLM provider added", "name", "together", "model", "Llama-3.3-70B-Instruct-Turbo-Free")
	}
	if *nvidiaNimKey != "" {
		providers = append(providers, llm.NewOpenAICompatProvider("nvidia", "https://integrate.api.nvidia.com/v1", *nvidiaNimKey, "meta/llama-3.3-70b-instruct"))
		quotas = append(quotas, cost.ProviderQuota{Name: "nvidia", DailyRequests: 200})
		logger.Info("LLM provider added", "name", "nvidia", "model", "llama-3.3-70b-instruct")
	}
	if *glhfKey != "" {
		providers = append(providers, llm.NewOpenAICompatProvider("glhf", "https://glhf.chat/api/openai/v1", *glhfKey, "hf:meta-llama/Llama-3.3-70B-Instruct"))
		quotas = append(quotas, cost.ProviderQuota{Name: "glhf", DailyRequests: 200})
		logger.Info("LLM provider added", "name", "glhf", "model", "Llama-3.3-70B-Instruct")
	}
	if *chutesKey != "" {
		providers = append(providers, llm.NewOpenAICompatProvider("chutes", "https://llm.chutes.ai/v1", *chutesKey, *chutesModel))
		quotas = append(quotas, cost.ProviderQuota{Name: "chutes", DailyRequests: 200})
		logger.Info("LLM provider added", "name", "chutes", "model", *chutesModel)
	}
	if *canopywaveKey != "" {
		providers = append(providers, llm.NewOpenAICompatProvider("canopywave", "https://inference.canopywave.io/v1", *canopywaveKey, *canopywaveModel))
		quotas = append(quotas, cost.ProviderQuota{Name: "canopywave", DailyRequests: 50000})
		logger.Info("LLM provider added", "name", "canopywave", "model", *canopywaveModel, "plan", "unlimited")
	}
	if *canopywaveFastKey != "" {
		providers = append(providers, llm.NewOpenAICompatProvider("canopywave-fast", "https://inference.canopywave.io/v1", *canopywaveFastKey, *canopywaveModel))
		quotas = append(quotas, cost.ProviderQuota{Name: "canopywave-fast", DailyRequests: 50000})
		logger.Info("LLM provider added", "name", "canopywave-fast", "model", *canopywaveModel, "plan", "fast-bundle")
	}
	if *closerouterKey != "" {
		// Default to claude-opus-4.7 if no global override was provided; per-stage
		// routing (when enabled) uses its own model selection from stageDefaults.
		model := *closerouterModel
		if model == "" {
			model = "anthropic/claude-opus-4.7"
		}
		providers = append(providers, llm.NewCloseRouterProvider(*closerouterKey, model, *closerouterBudget))
		logger.Info("LLM provider added", "name", "closerouter", "model", model, "daily_usd_cap", *closerouterBudget)
	}

	if *llm7Key != "" {
		providers = append(providers, llm.NewOpenAICompatProvider("llm7", "https://api.llm7.io/v1", *llm7Key, *llm7Model))
		quotas = append(quotas, cost.ProviderQuota{Name: "llm7", DailyRequests: 15000})
		logger.Info("LLM provider added", "name", "llm7", "model", *llm7Model)
	}

	if *uncloseaiKey != "" {
		providers = append(providers, llm.NewOpenAICompatProvider("uncloseai", "https://qwen.ai.unturf.com/v1", *uncloseaiKey, *uncloseaiModel))
		quotas = append(quotas, cost.ProviderQuota{Name: "uncloseai", DailyRequests: 10000})
		logger.Info("LLM provider added", "name", "uncloseai", "model", *uncloseaiModel)
	}

	// Pollinations is free and doesn't require a key
	providers = append(providers, llm.NewOpenAICompatProvider("pollinations", "https://text.pollinations.ai/openai", "anonymous", *pollinationsModel))
	quotas = append(quotas, cost.ProviderQuota{Name: "pollinations", DailyRequests: 5000})
	logger.Info("LLM provider added", "name", "pollinations", "model", *pollinationsModel)


	if len(providers) == 0 {
		logger.Error("no LLM providers configured — provide at least one API key (--gemini-key, --cerebras-key, --groq-key, --samba-key, --openrouter-key, --together-key, --nvidia-key, --glhf-key, --chutes-key, --freetheai-key or env vars)")
		os.Exit(1)
	}

	// Per-stage model routing: if any of the optimised providers is configured,
	// build per-stage clients with optimal model selection for each pipeline stage.
	// Cerebras / Groq / Gemini are first-class here so that dev runs can drop
	// CloseRouter entirely and still get strong per-stage routing.
	usePerStage := *cerebrasKey != "" || *groqKey != "" || *geminiKey != "" ||
		*sambaKey != "" || *freetheaiKey != "" ||
		*canopywaveKey != "" || *canopywaveFastKey != "" ||
		*llm7Key != "" || *uncloseaiKey != "" ||
		*closerouterKey != ""
	var (
		analystLLM   *llm.Client
		reporterLLM  *llm.Client
		historianLLM *llm.Client
		gateLLM      *llm.Client
		chainerLLM   *llm.Client
		exploiterLLM *llm.Client
	)
	stageOpts := stageBuildOpts{
		CerebrasKey:      *cerebrasKey,
		GroqKey:          *groqKey,
		GeminiKey:        *geminiKey,
		SambaKey:         *sambaKey,
		FreeTheAIKey:     *freetheaiKey,
		CanopyKey:        *canopywaveKey,
		CanopyFastKey:    *canopywaveFastKey,
		LLM7Key:          *llm7Key,
		UncloseAIKey:     *uncloseaiKey,
		CloseRouterKey:   *closerouterKey,
		CloseRouterModel: *closerouterModel,
		CloseRouterUSD:   *closerouterBudget,
	}
	if usePerStage {
		logger.Info("per-stage model routing enabled")
		analystLLM = buildStageClient("analyst", stageOpts, logger)
		reporterLLM = buildStageClient("reporter", stageOpts, logger)
		historianLLM = buildStageClient("historian", stageOpts, logger)
		gateLLM = buildStageClient("gate", stageOpts, logger)
		chainerLLM = buildStageClient("chainer", stageOpts, logger)
		exploiterLLM = buildStageClient("exploiter", stageOpts, logger)
	}

	// --agent mode: autonomous LLM-driven bug hunting
	if *agentMode {
		var agentClient *llm.Client
		if usePerStage {
			agentClient = buildStageClient("agent", stageOpts, logger)
		} else {
			agentClient, _ = llm.NewClient(providers...)
		}

		// Set up HITL callback if Telegram is configured
		var onFinding agent.FindingCallback
		var hitlBot *hitl.Bot
		chatIDNum, _ := strconv.ParseInt(*telegramChatID, 10, 64)
		if *telegramToken != "" && chatIDNum != 0 {
			hitlBot = hitl.NewBot(hitl.Config{
				Token:   *telegramToken,
				ChatID:  chatIDNum,
				Timeout: *hitlTimeout,
				Logger:  logger,
			})
			go hitlBot.StartPolling(ctx)
			logger.Info("HITL Telegram bot started for agent mode")

			onFinding = func(fctx context.Context, f agent.Finding) error {
				mf := &models.Finding{
					ID:        fmt.Sprintf("agent-%d", time.Now().UnixNano()),
					URL:       f.URL,
					VulnClass: models.VulnClass(f.VulnClass),
					Severity:  models.Severity(f.Severity),
					ScannerEvidence: f.Evidence,
					ReportMarkdown:  f.Description,
					Status:    models.StatusNew,
				}
				_, err := hitlBot.SendFinding(fctx, mf)
				return err
			}
		}

		ag := agent.New(agent.Config{
			Target:          sf.Domains[0],
			Domains:         sf.Domains,
			LLMClient:       agentClient,
			AgentBrowserBin: "agent-browser",
			ScreenshotDir:   *screenshotDir,
			ProxyAddr:       "",
			MaxSteps:        *agentMaxSteps,
			Logger:          logger,
			OnFinding:       onFinding,
			LLMDelayMs:      *agentDelayMs,
		})

		// Wire the first-Ctrl+C signal to the agent's graceful stop hook.
		// A second Ctrl+C will fall through and cancel ctx for a hard exit.
		setGracefulStop(ag.RequestStop)

		findings, agentErr := ag.Run(ctx)
		if agentErr != nil {
			logger.Error("agent mode failed", "error", agentErr)
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "\nAgent found %d potential vulnerabilities.\n", len(findings))
		for i, f := range findings {
			fmt.Fprintf(os.Stdout, "[%d] %s %s — %s\n    %s\n\n", i+1, f.Severity, f.VulnClass, f.URL, f.Description)
		}

		// Wait for HITL decisions if Telegram is configured and there are findings
		if hitlBot != nil && len(findings) > 0 {
			fmt.Fprintf(os.Stderr, "\nWaiting for HITL decisions via Telegram...\n")
			hitlBot.WaitForAll(ctx)
			hitlBot.Stop()
		}
		os.Exit(0)
	}

	// --check-ffuf: verify ffuf binary is in PATH and exit
	if *checkFfuf {
		if err := agent.CheckFfufBinary(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: ffuf binary check failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("OK: ffuf is available")
		os.Exit(0)
	}

	// --check-llm: verify provider connectivity and exit
	if *checkLLM {
		tmpClient, _ := llm.NewClient(providers...)
		fmt.Println("🔍 Checking LLM provider availability...")
		fmt.Println()
		results := tmpClient.CheckHealth(ctx)
		allOK := true
		for _, r := range results {
			if r.OK {
				fmt.Printf("  ✅ %-12s %-30s %s\n", r.Provider, r.Model, r.Latency.Round(time.Millisecond))
			} else {
				allOK = false
				errMsg := r.Error
				if len(errMsg) > 80 {
					errMsg = errMsg[:80] + "..."
				}
				fmt.Printf("  ❌ %-12s %-30s %s\n", r.Provider, r.Model, errMsg)
			}
		}
		fmt.Println()
		if allOK {
			fmt.Printf("All %d providers available.\n", len(results))
		} else {
			okCount := 0
			for _, r := range results {
				if r.OK {
					okCount++
				}
			}
			fmt.Printf("%d/%d providers available.\n", okCount, len(results))
		}
		os.Exit(0)
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

	// Startup health check: verify at least one LLM provider is reachable
	logger.Info("checking LLM provider availability...")
	healthResults := llmClient.CheckHealth(ctx)
	availableCount := 0
	for _, hr := range healthResults {
		if hr.OK {
			availableCount++
			logger.Info("LLM provider available",
				"provider", hr.Provider,
				"model", hr.Model,
				"latency", hr.Latency.Round(time.Millisecond),
			)
		} else {
			logger.Warn("LLM provider unavailable",
				"provider", hr.Provider,
				"model", hr.Model,
				"error", hr.Error,
			)
		}
	}
	if availableCount == 0 {
		logger.Error("no LLM providers are reachable — check API keys, network, and VPN")
		os.Exit(1)
	}
	logger.Info("LLM health check complete",
		"available", availableCount,
		"total", len(healthResults),
	)

	// Initialize agents — use per-stage clients when available, fallback to shared client
	aLLM, rLLM, hLLM, gLLM, cLLM, eLLM := llmClient, llmClient, llmClient, llmClient, llmClient, llmClient
	if usePerStage {
		if analystLLM != nil {
			aLLM = analystLLM
		}
		if reporterLLM != nil {
			rLLM = reporterLLM
		}
		if historianLLM != nil {
			hLLM = historianLLM
		}
		if gateLLM != nil {
			gLLM = gateLLM
		}
		if chainerLLM != nil {
			cLLM = chainerLLM
		}
		if exploiterLLM != nil {
			eLLM = exploiterLLM
		}
	}
	analystAgent := analyst.NewAnalyst(aLLM, enforcer, logger)
	reporterAgent := reporter.NewReporter(rLLM, sf.Platform, logger)
	historian := historian.NewHistorian(hLLM, logger)
	exploiterAgent := exploiter.NewExploiter(eLLM, logger)
	chainBuilder := chainer.NewChainer(cLLM, logger)
	qualityGate := gate.NewGate(gLLM, logger)
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

	// Initialize scanner pipeline config
	pipelineCfg := scanner.PipelineConfig{
		Domains:        sf.Domains,
		ProxyAddr:      "http://" + *proxyAddr,
		RateLimit:      *ratePerSecond,
		NucleiSeverity: "medium,high,critical",
		KatanaDepth:    3,
		Tools:          scanner.DefaultToolPaths(),
		Logger:         logger,
	}

	// Log pipeline start
	auditLogger.Log(ctx, "scan_started", "scanner", map[string]string{
		"domains":  strings.Join(sf.Domains, ","),
		"rate":     fmt.Sprintf("%.0f", *ratePerSecond),
		"parallel": fmt.Sprintf("%d", *parallelWorkers),
		"monitor":  fmt.Sprintf("%t", *monitorMode),
	})

	logger.Info("starting scan pipeline",
		"domains", sf.Domains,
		"rate", *ratePerSecond,
		"providers", len(providers),
		"parallel", *parallelWorkers,
		"monitor", *monitorMode,
	)

	// === PIPELINE: scan → analyze → report ===

	// Stage 1: Run scanner (sequential or parallel)
	var scanResult *scanner.ScanResult
	if *parallelWorkers > 0 {
		po := scanner.NewParallelOrchestrator(pipelineCfg, sf.Program, *parallelWorkers, logger)
		domainResults, parallelErr := po.RunParallel(ctx)
		if parallelErr != nil {
			logger.Error("parallel scan failed", "error", parallelErr)
			auditLogger.Log(ctx, "scan_failed", "scanner", map[string]string{"error": parallelErr.Error()})
			os.Exit(1)
		}
		scanResult = scanner.MergeResults(domainResults, sf.Program)
	} else {
		pipeline := scanner.NewPipeline(pipelineCfg)
		orchestrator := scanner.NewOrchestrator(pipeline, sf.Program, logger)
		var scanErr error
		scanResult, scanErr = orchestrator.RunFull(ctx)
		if scanErr != nil {
			logger.Error("scan failed", "error", scanErr)
			auditLogger.Log(ctx, "scan_failed", "scanner", map[string]string{"error": scanErr.Error()})
			os.Exit(1)
		}
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

	// Stage 5e: Browser PoC evidence (optional)
	if ctx.Err() != nil {
		return
	}

	if *enableBrowser {
		browserEngine := browser.NewEngine(browser.Config{
			ProxyAddr:     "http://" + *proxyAddr,
			ScreenshotDir: *screenshotDir,
			Logger:        logger,
		})

		if browserEngine.Available() {
			logger.Info("running browser PoC evidence", "findings", len(gateFiltered))
			browserVulnClasses := map[string]bool{
				"xss": true, "csrf": true, "open_redirect": true,
				"clickjacking": true, "info_disclosure": true,
			}

			var browserInputs []browser.FindingInput
			for _, f := range gateFiltered {
				if browserVulnClasses[string(f.VulnClass)] {
					browserInputs = append(browserInputs, browser.FindingInput{
						FindingID: f.ID,
						VulnClass: string(f.VulnClass),
						URL:       f.URL,
						Params:    f.ParamNames,
					})
				}
			}

			if len(browserInputs) > 0 {
				evidences := browserEngine.BatchEvidence(ctx, browserInputs)
				for _, ev := range evidences {
					if ev.Verified {
						logger.Info("browser PoC VERIFIED",
							"finding_id", ev.FindingID,
							"vuln_class", ev.VulnClass,
							"description", ev.Description,
							"screenshots", len(ev.Screenshots),
						)
						fmt.Fprintf(os.Stdout, "\n===== BROWSER PoC: %s =====\n", ev.FindingID)
						fmt.Fprintf(os.Stdout, "Vuln: %s | URL: %s\n", ev.VulnClass, ev.URL)
						fmt.Fprintf(os.Stdout, "Description: %s\n", ev.Description)
						for _, s := range ev.Screenshots {
							fmt.Fprintf(os.Stdout, "Screenshot: %s\n", s)
						}
					} else {
						logger.Info("browser PoC not verified",
							"finding_id", ev.FindingID,
							"error", ev.Error,
						)
					}

					auditLogger.Log(ctx, "browser_poc", "browser", map[string]string{
						"finding_id": ev.FindingID,
						"vuln_class": ev.VulnClass,
						"verified":   fmt.Sprintf("%t", ev.Verified),
						"duration":   ev.Duration.String(),
					})
				}
			}

			browserEngine.Close(ctx)
		} else {
			logger.Warn("browser PoC skipped: agent-browser not available")
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

	// Stage 7: Auto-submit approved findings to platform (stub)
	if *autoSubmit && len(approved) > 0 {
		var submitter submit.Submitter
		switch sf.Platform {
		case "bizone":
			submitter = submit.NewBizoneSubmitter("", "", logger)
		default:
			submitter = submit.NewStandoffSubmitter("", "", logger)
		}

		logger.Info("auto-submitting approved findings",
			"count", len(approved),
			"platform", submitter.Name(),
		)
		submitResults := submit.BatchSubmit(ctx, submitter, approved, logger)
		for _, sr := range submitResults {
			auditLogger.Log(ctx, "finding_submitted", "submit", map[string]string{
				"finding_id": sr.FindingID,
				"platform":   sr.Platform,
				"success":    fmt.Sprintf("%t", sr.Success),
			})
		}
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
	fmt.Fprintf(os.Stderr, "Auto-submit:     %v\n", *autoSubmit)
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

	// Continuous monitoring mode
	if *monitorMode {
		logger.Info("entering continuous monitoring mode",
			"interval", monitorInterval.String(),
		)
		fmt.Fprintf(os.Stderr, "\n=== Monitor Mode ===\n")
		fmt.Fprintf(os.Stderr, "Interval: %s\n", monitorInterval.String())
		fmt.Fprintf(os.Stderr, "Press Ctrl+C to stop.\n\n")

		monSched := scheduler.New([]scheduler.Schedule{
			{
				ProgramID: sf.Program,
				Type:      scheduler.ScheduleInterval,
				Interval:  *monitorInterval,
				RunType:   "delta",
				Enabled:   true,
			},
		}, func(sctx context.Context, programID, runType string) error {
			logger.Info("monitor: starting scheduled scan",
				"program", programID,
				"run_type", runType,
			)
			auditLogger.Log(sctx, "monitor_scan_started", "scheduler", map[string]string{
				"program":  programID,
				"run_type": runType,
			})

			var monResult *scanner.ScanResult
			if *parallelWorkers > 0 {
				po := scanner.NewParallelOrchestrator(pipelineCfg, programID, *parallelWorkers, logger)
				dr, pErr := po.RunParallel(sctx)
				if pErr != nil {
					return pErr
				}
				monResult = scanner.MergeResults(dr, programID)
			} else {
				p := scanner.NewPipeline(pipelineCfg)
				o := scanner.NewOrchestrator(p, programID, logger)
				var sErr error
				monResult, sErr = o.RunFull(sctx)
				if sErr != nil {
					return sErr
				}
			}

			writer.WriteScanRun(sctx, monResult.Run)
			logger.Info("monitor: scan complete",
				"findings", monResult.Run.FindingsTotal,
				"hosts", monResult.Run.HostsScanned,
			)

			auditLogger.Log(sctx, "monitor_scan_completed", "scheduler", map[string]string{
				"findings": fmt.Sprintf("%d", monResult.Run.FindingsTotal),
			})

			return nil
		}, logger)

		monSched.Start(ctx) // blocks until ctx is cancelled
	}

	// Graceful shutdown
	if egressProxy != nil {
		egressProxy.Shutdown(ctx)
	}
}
