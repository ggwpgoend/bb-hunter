package agent

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestExtractPaths_DedupesAndSorts(t *testing.T) {
	text := `https://example.com/admin
https://example.com/login
https://example.com/admin
https://example.com/api/v1
https://example.com/Login
`
	got := ExtractPaths(text, "example.com")
	want := []string{"/admin", "/api/v1", "/login"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExtractPaths dedup+sort:\ngot  %v\nwant %v", got, want)
	}
}

func TestExtractPaths_IgnoresPathsForOtherHosts(t *testing.T) {
	text := `https://example.com/admin
https://other.com/secret
https://example.com/login
/bare-path
`
	got := ExtractPaths(text, "example.com")
	want := []string{"/admin", "/bare-path", "/login"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExtractPaths host filter:\ngot  %v\nwant %v", got, want)
	}
}

func TestExtractPaths_EmptyInput(t *testing.T) {
	got := ExtractPaths("", "example.com")
	if len(got) != 0 {
		t.Fatalf("expected empty result for empty input, got %v", got)
	}
}

func TestExtractPaths_BarePathsOnly(t *testing.T) {
	text := `/admin
/login
/admin
not-a-path
`
	got := ExtractPaths(text, "example.com")
	want := []string{"/admin", "/login"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExtractPaths bare paths:\ngot  %v\nwant %v", got, want)
	}
}

func TestWriteWordlist_OneLineEach(t *testing.T) {
	paths := []string{"/admin", "/login", "/api/v1"}
	fpath, err := WriteWordlist(paths)
	if err != nil {
		t.Fatalf("WriteWordlist error: %v", err)
	}
	defer os.Remove(fpath)

	data, err := os.ReadFile(fpath)
	if err != nil {
		t.Fatalf("read temp file error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if !reflect.DeepEqual(lines, paths) {
		t.Fatalf("WriteWordlist lines:\ngot  %v\nwant %v", lines, paths)
	}
}

func TestBuildWordlistTool_OK(t *testing.T) {
	te := NewToolExecutor("", "", "")
	tmp := t.TempDir() + "/wl.txt"
	args := tmp + "\n/admin\n/login\n/api"
	result := te.buildWordlistTool(args)
	if !strings.Contains(result, "OK") || !strings.Contains(result, "3 entries") {
		t.Fatalf("expected OK with 3 entries, got: %s", result)
	}

	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	want := []string{"/admin", "/login", "/api"}
	if !reflect.DeepEqual(lines, want) {
		t.Fatalf("file content:\ngot  %v\nwant %v", lines, want)
	}
}

func TestBuildWordlistTool_MissingArgs(t *testing.T) {
	te := NewToolExecutor("", "", "")
	result := te.buildWordlistTool("/tmp/out.txt")
	if !strings.Contains(result, "ERROR") {
		t.Fatalf("expected error for missing paths, got: %s", result)
	}
}
