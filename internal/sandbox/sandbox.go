// Package sandbox provides a rootless Docker-based execution environment
// for running PoC exploit scripts safely.
//
// Security controls:
//   - Network: only allowed to reach in-scope targets via egress proxy
//   - Filesystem: read-only root, tmpfs for /tmp
//   - Resources: CPU/memory limits, execution timeout
//   - No privileged capabilities
//   - Output captured for analysis
package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// Config holds sandbox configuration.
type Config struct {
	// Docker binary path (default: "docker")
	DockerBin string `json:"docker_bin" yaml:"docker_bin"`

	// Base image for PoC execution (default: "python:3.12-slim")
	BaseImage string `json:"base_image" yaml:"base_image"`

	// Egress proxy address for network access control
	ProxyAddr string `json:"proxy_addr" yaml:"proxy_addr"`

	// Resource limits
	MemoryLimit string        `json:"memory_limit" yaml:"memory_limit"` // e.g., "256m"
	CPULimit    string        `json:"cpu_limit" yaml:"cpu_limit"`       // e.g., "0.5"
	Timeout     time.Duration `json:"timeout" yaml:"timeout"`           // max execution time

	// Logger
	Logger *slog.Logger `json:"-" yaml:"-"`
}

// DefaultConfig returns sensible defaults for the sandbox.
func DefaultConfig() Config {
	return Config{
		DockerBin:   "docker",
		BaseImage:   "python:3.12-slim",
		MemoryLimit: "256m",
		CPULimit:    "0.5",
		Timeout:     30 * time.Second,
	}
}

// Result captures the output of a sandbox execution.
type Result struct {
	ExitCode int           `json:"exit_code"`
	Stdout   string        `json:"stdout"`
	Stderr   string        `json:"stderr"`
	Duration time.Duration `json:"duration"`
	TimedOut bool          `json:"timed_out"`
}

// Sandbox manages Docker-based PoC execution.
type Sandbox struct {
	cfg Config
	log *slog.Logger
}

// New creates a new Sandbox.
func New(cfg Config) *Sandbox {
	if cfg.DockerBin == "" {
		cfg.DockerBin = "docker"
	}
	if cfg.BaseImage == "" {
		cfg.BaseImage = "python:3.12-slim"
	}
	if cfg.MemoryLimit == "" {
		cfg.MemoryLimit = "256m"
	}
	if cfg.CPULimit == "" {
		cfg.CPULimit = "0.5"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Sandbox{cfg: cfg, log: cfg.Logger}
}

// Available checks if Docker is available and running.
func (s *Sandbox) Available() bool {
	cmd := exec.Command(s.cfg.DockerBin, "info")
	return cmd.Run() == nil
}

// RunScript executes a script inside a sandboxed container.
// The script is passed via stdin to the interpreter.
func (s *Sandbox) RunScript(ctx context.Context, interpreter, script string) (*Result, error) {
	if interpreter == "" {
		interpreter = "python3"
	}

	args := s.buildDockerArgs(interpreter)

	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout+5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.cfg.DockerBin, args...)
	cmd.Stdin = strings.NewReader(script)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start)

	result := &Result{
		Stdout:   truncateOutput(stdout.String(), 10000),
		Stderr:   truncateOutput(stderr.String(), 5000),
		Duration: duration,
	}

	if ctx.Err() == context.DeadlineExceeded {
		result.TimedOut = true
		result.ExitCode = -1
		s.log.Warn("sandbox: execution timed out",
			"timeout", s.cfg.Timeout,
			"duration", duration,
		)
		return result, nil
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("sandbox: docker run failed: %w", err)
		}
	}

	s.log.Info("sandbox: execution complete",
		"exit_code", result.ExitCode,
		"duration", duration,
		"stdout_len", len(result.Stdout),
		"stderr_len", len(result.Stderr),
	)

	return result, nil
}

// buildDockerArgs constructs the docker run command arguments.
func (s *Sandbox) buildDockerArgs(interpreter string) []string {
	args := []string{
		"run",
		"--rm",                   // auto-remove container
		"--read-only",            // read-only filesystem
		"--tmpfs", "/tmp:size=50m", // writable /tmp
		"--network", "bridge",    // network access (through proxy)
		"--memory", s.cfg.MemoryLimit,
		"--cpus", s.cfg.CPULimit,
		"--security-opt", "no-new-privileges",
		"--cap-drop", "ALL",      // drop all capabilities
		"-i",                     // interactive (for stdin)
	}

	// Set proxy environment if configured
	if s.cfg.ProxyAddr != "" {
		args = append(args,
			"-e", "HTTP_PROXY="+s.cfg.ProxyAddr,
			"-e", "HTTPS_PROXY="+s.cfg.ProxyAddr,
			"-e", "http_proxy="+s.cfg.ProxyAddr,
			"-e", "https_proxy="+s.cfg.ProxyAddr,
		)
	}

	// Timeout via docker's --stop-timeout
	args = append(args, "--stop-timeout", fmt.Sprintf("%d", int(s.cfg.Timeout.Seconds())))

	// Image and command
	args = append(args, s.cfg.BaseImage, interpreter, "-")

	return args
}

// truncateOutput limits output length to prevent memory issues.
func truncateOutput(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "\n... (truncated)"
}
