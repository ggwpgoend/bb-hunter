// Package submit provides interfaces and implementations for auto-submitting
// approved findings to bug bounty platforms (Standoff 365, BI.ZONE Bug Bounty).
package submit

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/models"
)

// SubmitResult holds the outcome of a submission attempt.
type SubmitResult struct {
	FindingID    string
	Platform     string
	SubmittedAt  time.Time
	ExternalID   string // platform-assigned report ID
	ExternalURL  string // link to the report on the platform
	Success      bool
	ErrorMessage string
}

// Submitter is the interface for platform-specific submission logic.
type Submitter interface {
	// Name returns the platform name (e.g., "standoff", "bizone").
	Name() string

	// Submit sends an approved finding to the platform.
	Submit(ctx context.Context, finding *models.Finding) (*SubmitResult, error)

	// CheckStatus polls the platform for report status updates.
	CheckStatus(ctx context.Context, externalID string) (string, error)
}

// StandoffSubmitter submits findings to the Standoff 365 Bug Bounty platform.
type StandoffSubmitter struct {
	apiURL string
	apiKey string
	log    *slog.Logger
}

// NewStandoffSubmitter creates a Standoff submitter.
// TODO: replace stub with real API integration when Standoff API docs are available.
func NewStandoffSubmitter(apiURL, apiKey string, logger *slog.Logger) *StandoffSubmitter {
	if logger == nil {
		logger = slog.Default()
	}
	if apiURL == "" {
		apiURL = "https://bugbounty.standoff365.com/api/v1"
	}
	return &StandoffSubmitter{
		apiURL: apiURL,
		apiKey: apiKey,
		log:    logger,
	}
}

func (s *StandoffSubmitter) Name() string { return "standoff" }

func (s *StandoffSubmitter) Submit(ctx context.Context, finding *models.Finding) (*SubmitResult, error) {
	s.log.Info("standoff: submitting finding",
		"finding_id", finding.ID,
		"url", finding.URL,
		"severity", finding.Severity,
	)

	// TODO: implement real Standoff 365 API call
	// POST /api/v1/reports
	// Headers: Authorization: Bearer <apiKey>
	// Body: { program_id, title, description (markdown), severity, url, evidence }
	return &SubmitResult{
		FindingID:    finding.ID,
		Platform:     "standoff",
		SubmittedAt:  time.Now(),
		Success:      false,
		ErrorMessage: "standoff API integration not yet implemented",
	}, fmt.Errorf("standoff API integration not yet implemented — use manual submission")
}

func (s *StandoffSubmitter) CheckStatus(ctx context.Context, externalID string) (string, error) {
	return "", fmt.Errorf("standoff status check not yet implemented")
}

// BizoneSubmitter submits findings to the BI.ZONE Bug Bounty platform.
type BizoneSubmitter struct {
	apiURL string
	apiKey string
	log    *slog.Logger
}

// NewBizoneSubmitter creates a BI.ZONE submitter.
// TODO: replace stub with real API integration when BI.ZONE API docs are available.
func NewBizoneSubmitter(apiURL, apiKey string, logger *slog.Logger) *BizoneSubmitter {
	if logger == nil {
		logger = slog.Default()
	}
	if apiURL == "" {
		apiURL = "https://bugbounty.bi.zone/api/v1"
	}
	return &BizoneSubmitter{
		apiURL: apiURL,
		apiKey: apiKey,
		log:    logger,
	}
}

func (b *BizoneSubmitter) Name() string { return "bizone" }

func (b *BizoneSubmitter) Submit(ctx context.Context, finding *models.Finding) (*SubmitResult, error) {
	b.log.Info("bizone: submitting finding",
		"finding_id", finding.ID,
		"url", finding.URL,
		"severity", finding.Severity,
	)

	// TODO: implement real BI.ZONE API call
	// POST /api/v1/reports
	// Headers: X-API-Key: <apiKey>
	// Body: { program_id, title, description, severity, evidence_url }
	return &SubmitResult{
		FindingID:    finding.ID,
		Platform:     "bizone",
		SubmittedAt:  time.Now(),
		Success:      false,
		ErrorMessage: "bizone API integration not yet implemented",
	}, fmt.Errorf("bizone API integration not yet implemented — use manual submission")
}

func (b *BizoneSubmitter) CheckStatus(ctx context.Context, externalID string) (string, error) {
	return "", fmt.Errorf("bizone status check not yet implemented")
}

// BatchSubmit sends approved findings to the appropriate platform submitter.
func BatchSubmit(ctx context.Context, submitter Submitter, findings []*models.Finding, logger *slog.Logger) []SubmitResult {
	if logger == nil {
		logger = slog.Default()
	}
	var results []SubmitResult

	for _, f := range findings {
		if ctx.Err() != nil {
			break
		}

		if f.Status != models.StatusApproved {
			continue
		}

		result, err := submitter.Submit(ctx, f)
		if err != nil {
			logger.Warn("submit failed",
				"finding_id", f.ID,
				"platform", submitter.Name(),
				"error", err,
			)
			if result == nil {
				result = &SubmitResult{
					FindingID:    f.ID,
					Platform:     submitter.Name(),
					SubmittedAt:  time.Now(),
					Success:      false,
					ErrorMessage: err.Error(),
				}
			}
		}

		results = append(results, *result)
	}

	return results
}
