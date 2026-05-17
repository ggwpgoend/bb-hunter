package agent

import (
	"context"
	"testing"
	"time"
)

func TestParseResponse(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantThink string
		wantTool  string
		wantArgs  string
	}{
		{
			name:      "basic think and action",
			input:     "THINK: I should start by opening the target\nACTION: browser_open https://example.com",
			wantThink: "I should start by opening the target",
			wantTool:  "browser_open",
			wantArgs:  "https://example.com",
		},
		{
			name:      "multiline think",
			input:     "THINK: First line of reasoning.\nSecond line of reasoning.\nACTION: http_get https://example.com",
			wantThink: "First line of reasoning. Second line of reasoning.",
			wantTool:  "http_get",
			wantArgs:  "https://example.com",
		},
		{
			name:      "action without args",
			input:     "THINK: Get the DOM tree\nACTION: browser_snapshot",
			wantThink: "Get the DOM tree",
			wantTool:  "browser_snapshot",
			wantArgs:  "",
		},
		{
			name:      "done action",
			input:     "THINK: Investigation complete\nACTION: done Found 2 vulnerabilities",
			wantThink: "Investigation complete",
			wantTool:  "done",
			wantArgs:  "Found 2 vulnerabilities",
		},
		{
			name:      "no action",
			input:     "THINK: I need to think more about this",
			wantThink: "I need to think more about this",
			wantTool:  "",
			wantArgs:  "",
		},
		{
			name:      "empty input",
			input:     "",
			wantThink: "",
			wantTool:  "",
			wantArgs:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			think, tool, args := parseResponse(tt.input)
			if think != tt.wantThink {
				t.Errorf("think = %q, want %q", think, tt.wantThink)
			}
			if tool != tt.wantTool {
				t.Errorf("tool = %q, want %q", tool, tt.wantTool)
			}
			if args != tt.wantArgs {
				t.Errorf("args = %q, want %q", args, tt.wantArgs)
			}
		})
	}
}

func TestToolExecutor_ReportFinding(t *testing.T) {
	te := NewToolExecutor("", "", "")

	// Valid finding
	result := te.reportFinding(`{"vuln_class":"xss","severity":"high","url":"https://example.com/search?q=test","description":"Reflected XSS","evidence":"<script>alert(1)</script>"}`)
	if !startsWith(result, "OK:") {
		t.Errorf("expected OK, got %s", result)
	}
	if len(te.Findings()) != 1 {
		t.Errorf("expected 1 finding, got %d", len(te.Findings()))
	}

	// Invalid JSON
	result = te.reportFinding("not json")
	if !startsWith(result, "ERROR:") {
		t.Errorf("expected ERROR for invalid JSON, got %s", result)
	}

	// Missing required fields
	result = te.reportFinding(`{"severity":"high"}`)
	if !startsWith(result, "ERROR:") {
		t.Errorf("expected ERROR for missing fields, got %s", result)
	}
}

func TestToolExecutor_RunCmd_BlocksDestructive(t *testing.T) {
	te := NewToolExecutor("", "", "")
	ctx := context.Background()

	destructive := []string{
		"rm -rf /",
		"rm file.txt",
		"mkfs /dev/sda",
		"dd if=/dev/zero of=/dev/sda",
		"shutdown -h now",
		"reboot",
	}

	for _, cmd := range destructive {
		result := te.Execute(ctx, "run_cmd", cmd)
		if !startsWith(result, "ERROR:") {
			t.Errorf("expected blocked for %q, got %s", cmd, result)
		}
	}
}

func TestToolExecutor_Execute_UnknownTool(t *testing.T) {
	te := NewToolExecutor("", "", "")
	ctx := context.Background()

	result := te.Execute(ctx, "nonexistent_tool", "args")
	if !startsWith(result, "ERROR:") {
		t.Errorf("expected ERROR for unknown tool, got %s", result)
	}
}

func TestToolsPrompt(t *testing.T) {
	prompt := ToolsPrompt()
	if !startsWith(prompt, "Available tools:") {
		t.Error("ToolsPrompt should start with 'Available tools:'")
	}
	tools := AllTools()
	for _, tool := range tools {
		if !containsStr(prompt, tool.Name) {
			t.Errorf("ToolsPrompt missing tool: %s", tool.Name)
		}
	}
}

func TestTruncate(t *testing.T) {
	short := "hello"
	if truncate(short, 100) != short {
		t.Error("truncate should not modify short strings")
	}

	long := "abcdefghij"
	result := truncate(long, 5)
	if len(result) <= 5 {
		// result includes the truncation marker
	}
	if !containsStr(result, "truncated") {
		t.Error("truncate should add truncation marker")
	}
}

func TestDisplay(t *testing.T) {
	// Smoke test — just ensure no panics
	d := NewDisplay()
	d.Banner("example.com", 3)
	d.Think("Testing the display")
	d.Action("http_get", "https://example.com")
	d.Observation("HTTP 200 OK\nContent-Type: text/html")
	d.Finding("xss", "high", "https://example.com/q=<script>", "Reflected XSS found")
	d.Error("something went wrong")
	d.Info("informational message")
	d.Summary(1, 5, 30*time.Second)
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
