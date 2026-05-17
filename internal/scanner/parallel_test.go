package scanner

import (
	"fmt"
	"testing"

	"github.com/ggwpgoend/bb-hunter/internal/models"
)

func TestGroupDomains(t *testing.T) {
	tests := []struct {
		name    string
		domains []string
		want    int // number of groups
	}{
		{
			name:    "single domain",
			domains: []string{"example.com"},
			want:    1,
		},
		{
			name:    "domain with wildcard",
			domains: []string{"example.com", "*.example.com"},
			want:    1,
		},
		{
			name:    "multiple domains",
			domains: []string{"example.com", "target.ru"},
			want:    2,
		},
		{
			name:    "mixed",
			domains: []string{"example.com", "*.example.com", "target.ru", "*.target.ru", "other.net"},
			want:    3,
		},
		{
			name:    "empty",
			domains: nil,
			want:    0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			groups := groupDomains(tc.domains)
			if len(groups) != tc.want {
				t.Errorf("groupDomains(%v) = %d groups, want %d", tc.domains, len(groups), tc.want)
			}
		})
	}
}

func TestGroupDomainsContent(t *testing.T) {
	domains := []string{"example.com", "*.example.com", "target.ru"}
	groups := groupDomains(domains)

	exGroup, ok := groups["example.com"]
	if !ok {
		t.Fatal("expected 'example.com' group")
	}
	if len(exGroup) != 2 {
		t.Errorf("example.com group has %d entries, want 2", len(exGroup))
	}

	tgGroup, ok := groups["target.ru"]
	if !ok {
		t.Fatal("expected 'target.ru' group")
	}
	if len(tgGroup) != 1 {
		t.Errorf("target.ru group has %d entries, want 1", len(tgGroup))
	}
}

func TestNewParallelOrchestrator_Defaults(t *testing.T) {
	cfg := PipelineConfig{Domains: []string{"example.com"}}
	po := NewParallelOrchestrator(cfg, "test", 0, nil)

	if po.workers != 3 {
		t.Errorf("default workers = %d, want 3", po.workers)
	}
	if po.programID != "test" {
		t.Errorf("programID = %q, want 'test'", po.programID)
	}
}

func TestNewParallelOrchestrator_CustomWorkers(t *testing.T) {
	cfg := PipelineConfig{Domains: []string{"example.com"}}
	po := NewParallelOrchestrator(cfg, "test", 5, nil)

	if po.workers != 5 {
		t.Errorf("workers = %d, want 5", po.workers)
	}
}

func TestMergeResults_Empty(t *testing.T) {
	merged := MergeResults(nil, "test")
	if merged.Run == nil {
		t.Fatal("merged.Run should not be nil")
	}
	if merged.Run.RunType != "parallel" {
		t.Errorf("RunType = %q, want 'parallel'", merged.Run.RunType)
	}
	if len(merged.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(merged.Findings))
	}
}

func TestMergeResults_WithErrors(t *testing.T) {
	results := []DomainResult{
		{Domain: "fail.com", Error: fmt.Errorf("scan failed")},
		{Domain: "ok.com", Result: &ScanResult{
			Run:      &models.ScanRun{HostsScanned: 5, URLsCrawled: 20},
			Findings: make([]*models.Finding, 3),
		}},
	}

	merged := MergeResults(results, "test")
	if merged.Run.HostsScanned != 5 {
		t.Errorf("HostsScanned = %d, want 5", merged.Run.HostsScanned)
	}
	if merged.Run.URLsCrawled != 20 {
		t.Errorf("URLsCrawled = %d, want 20", merged.Run.URLsCrawled)
	}
	if len(merged.Findings) != 3 {
		t.Errorf("Findings = %d, want 3", len(merged.Findings))
	}
	if len(merged.Run.Errors) != 1 {
		t.Errorf("Errors = %d, want 1", len(merged.Run.Errors))
	}
}
