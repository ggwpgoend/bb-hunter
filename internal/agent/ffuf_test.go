package agent

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestCheckFfufBinary_OK(t *testing.T) {
	err := CheckFfufBinary(context.Background())
	if err != nil {
		t.Skipf("ffuf not in PATH, skipping: %v", err)
	}
}

func TestCheckFfufBinary_Missing(t *testing.T) {
	// Override PATH to an empty temp dir so ffuf cannot be found.
	tmp := t.TempDir()
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", tmp)
	defer os.Setenv("PATH", origPath)

	err := CheckFfufBinary(context.Background())
	if err == nil {
		t.Fatal("expected error when ffuf is not in PATH")
	}
	if !strings.Contains(err.Error(), "ffuf not available") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestRunFfuf_RejectsURLWithoutFUZZ(t *testing.T) {
	te := NewToolExecutor("", "", "")
	result := te.runFfuf(context.Background(), "https://example.com/path /tmp/wordlist.txt")
	if !strings.Contains(result, "ERROR") || !strings.Contains(result, "FUZZ") {
		t.Fatalf("expected error about missing FUZZ keyword, got: %s", result)
	}
}

func TestRunFfuf_RejectsMissingWordlistFile(t *testing.T) {
	te := NewToolExecutor("", "", "")
	result := te.runFfuf(context.Background(), "https://example.com/FUZZ /nonexistent/wordlist.txt")
	if !strings.Contains(result, "ERROR") || !strings.Contains(result, "not found") {
		t.Fatalf("expected error about missing wordlist, got: %s", result)
	}
}

func TestRunFfuf_RejectsMissingArgs(t *testing.T) {
	te := NewToolExecutor("", "", "")
	result := te.runFfuf(context.Background(), "https://example.com/FUZZ")
	if !strings.Contains(result, "ERROR") || !strings.Contains(result, "usage") {
		t.Fatalf("expected usage error, got: %s", result)
	}
}
