package sandbox

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.DockerBin != "docker" {
		t.Errorf("expected docker, got %s", cfg.DockerBin)
	}
	if cfg.BaseImage != "python:3.12-slim" {
		t.Errorf("expected python:3.12-slim, got %s", cfg.BaseImage)
	}
	if cfg.MemoryLimit != "256m" {
		t.Errorf("expected 256m, got %s", cfg.MemoryLimit)
	}
	if cfg.Timeout != 30*time.Second {
		t.Errorf("expected 30s, got %v", cfg.Timeout)
	}
}

func TestBuildDockerArgs(t *testing.T) {
	s := New(Config{
		DockerBin:   "docker",
		BaseImage:   "python:3.12-slim",
		ProxyAddr:   "http://127.0.0.1:18080",
		MemoryLimit: "128m",
		CPULimit:    "0.25",
		Timeout:     15 * time.Second,
	})

	args := s.buildDockerArgs("python3")

	// Check essential security flags
	checks := map[string]bool{
		"--rm":                  false,
		"--read-only":           false,
		"--security-opt":        false,
		"--cap-drop":            false,
		"-i":                    false,
	}

	for _, arg := range args {
		if _, ok := checks[arg]; ok {
			checks[arg] = true
		}
	}

	for flag, found := range checks {
		if !found {
			t.Errorf("missing security flag: %s", flag)
		}
	}

	// Check proxy env vars
	hasProxy := false
	for i, arg := range args {
		if arg == "-e" && i+1 < len(args) {
			if args[i+1] == "HTTP_PROXY=http://127.0.0.1:18080" {
				hasProxy = true
			}
		}
	}
	if !hasProxy {
		t.Error("missing HTTP_PROXY environment variable")
	}

	// Check image and interpreter at the end
	lastTwo := args[len(args)-2:]
	if lastTwo[0] != "python3" || lastTwo[1] != "-" {
		t.Errorf("expected [python3, -] at end, got %v", lastTwo)
	}
}

func TestBuildDockerArgsNoProxy(t *testing.T) {
	s := New(Config{
		DockerBin: "docker",
		BaseImage: "python:3.12-slim",
		// no proxy
	})

	args := s.buildDockerArgs("python3")

	for _, arg := range args {
		if arg == "HTTP_PROXY" {
			t.Error("should not have HTTP_PROXY without proxy config")
		}
	}
}

func TestTruncateOutput(t *testing.T) {
	short := "hello"
	if truncateOutput(short, 100) != short {
		t.Error("short output should not be truncated")
	}

	long := make([]byte, 200)
	for i := range long {
		long[i] = 'a'
	}
	result := truncateOutput(string(long), 100)
	if len(result) > 120 { // 100 + "... (truncated)" + newline
		t.Errorf("truncated output too long: %d", len(result))
	}
	if result[len(result)-len("... (truncated)")-1:] != "\n... (truncated)" {
		t.Error("truncated output should end with truncation marker")
	}
}

func TestNewSandboxDefaults(t *testing.T) {
	s := New(Config{})

	if s.cfg.DockerBin != "docker" {
		t.Errorf("expected docker, got %s", s.cfg.DockerBin)
	}
	if s.cfg.BaseImage != "python:3.12-slim" {
		t.Errorf("expected python:3.12-slim, got %s", s.cfg.BaseImage)
	}
	if s.cfg.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", s.cfg.Timeout)
	}
}
