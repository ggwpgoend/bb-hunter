package submit

import (
	"context"
	"testing"

	"github.com/ggwpgoend/bb-hunter/internal/models"
)

func TestStandoffSubmitterName(t *testing.T) {
	s := NewStandoffSubmitter("", "", nil)
	if s.Name() != "standoff" {
		t.Errorf("Name() = %q, want 'standoff'", s.Name())
	}
}

func TestBizoneSubmitterName(t *testing.T) {
	b := NewBizoneSubmitter("", "", nil)
	if b.Name() != "bizone" {
		t.Errorf("Name() = %q, want 'bizone'", b.Name())
	}
}

func TestStandoffSubmitStub(t *testing.T) {
	s := NewStandoffSubmitter("", "test-key", nil)
	finding := &models.Finding{
		ID:       "f-001",
		URL:      "https://example.com/vuln",
		Severity: models.SeverityHigh,
		Status:   models.StatusApproved,
	}

	result, err := s.Submit(context.Background(), finding)
	if err == nil {
		t.Error("stub should return error")
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if result.Success {
		t.Error("stub should not report success")
	}
	if result.Platform != "standoff" {
		t.Errorf("Platform = %q, want 'standoff'", result.Platform)
	}
}

func TestBizoneSubmitStub(t *testing.T) {
	b := NewBizoneSubmitter("", "test-key", nil)
	finding := &models.Finding{
		ID:       "f-002",
		URL:      "https://target.ru/admin",
		Severity: models.SeverityCritical,
		Status:   models.StatusApproved,
	}

	result, err := b.Submit(context.Background(), finding)
	if err == nil {
		t.Error("stub should return error")
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if result.Platform != "bizone" {
		t.Errorf("Platform = %q, want 'bizone'", result.Platform)
	}
}

func TestBatchSubmit_OnlyApproved(t *testing.T) {
	s := NewStandoffSubmitter("", "key", nil)
	findings := []*models.Finding{
		{ID: "f-1", Status: models.StatusApproved, Severity: models.SeverityHigh},
		{ID: "f-2", Status: models.StatusRejected, Severity: models.SeverityMedium},
		{ID: "f-3", Status: models.StatusApproved, Severity: models.SeverityCritical},
	}

	results := BatchSubmit(context.Background(), s, findings, nil)

	// Only approved findings should be submitted (2 out of 3)
	if len(results) != 2 {
		t.Errorf("expected 2 submit results, got %d", len(results))
	}
}

func TestBatchSubmit_Empty(t *testing.T) {
	s := NewStandoffSubmitter("", "key", nil)
	results := BatchSubmit(context.Background(), s, nil, nil)
	if len(results) != 0 {
		t.Errorf("expected 0 results for nil findings, got %d", len(results))
	}
}

func TestStandoffCheckStatusStub(t *testing.T) {
	s := NewStandoffSubmitter("", "key", nil)
	_, err := s.CheckStatus(context.Background(), "ext-123")
	if err == nil {
		t.Error("stub CheckStatus should return error")
	}
}

func TestDefaultURLs(t *testing.T) {
	s := NewStandoffSubmitter("", "key", nil)
	if s.apiURL != "https://bugbounty.standoff365.com/api/v1" {
		t.Errorf("standoff default URL = %q", s.apiURL)
	}

	b := NewBizoneSubmitter("", "key", nil)
	if b.apiURL != "https://bugbounty.bi.zone/api/v1" {
		t.Errorf("bizone default URL = %q", b.apiURL)
	}
}
