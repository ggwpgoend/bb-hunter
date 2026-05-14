package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/ggwpgoend/bb-hunter/internal/config"
	"github.com/ggwpgoend/bb-hunter/internal/proxy"
	"github.com/ggwpgoend/bb-hunter/internal/scope"
)

func main() {
	scopePath := flag.String("scope", "scope.yaml", "path to scope.yaml")
	proxyAddr := flag.String("proxy-addr", "127.0.0.1:18080", "egress proxy listen address")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, error")
	flag.Parse()

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

	// Print the scope-enforced HTTP client info
	_ = enforcer.Client()
	fmt.Fprintf(os.Stderr, "\n=== BB-Hunter Phase 1 ===\n")
	fmt.Fprintf(os.Stderr, "Program:    %s\n", sf.Program)
	fmt.Fprintf(os.Stderr, "Platform:   %s\n", sf.Platform)
	fmt.Fprintf(os.Stderr, "Domains:    %v\n", sf.Domains)
	fmt.Fprintf(os.Stderr, "Proxy:      %s\n", *proxyAddr)
	fmt.Fprintf(os.Stderr, "=========================\n\n")

	// Wait for shutdown signal
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		logger.Info("shutting down", "signal", sig.String())
		cancel()
		egressProxy.Shutdown(ctx)
	case <-ctx.Done():
	}
}
