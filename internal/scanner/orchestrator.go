package scanner

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/models"
)

// Orchestrator runs the full scan pipeline and produces Findings.
type Orchestrator struct {
	pipeline  *Pipeline
	programID string
	log       *slog.Logger
}

// NewOrchestrator creates a scan orchestrator.
func NewOrchestrator(pipeline *Pipeline, programID string, logger *slog.Logger) *Orchestrator {
	if logger == nil {
		logger = slog.Default()
	}
	return &Orchestrator{
		pipeline:  pipeline,
		programID: programID,
		log:       logger,
	}
}

// ScanResult contains the full output of a scan run.
type ScanResult struct {
	Run      *models.ScanRun
	Findings []*models.Finding
}

// RunFull executes the full recon pipeline:
// subfinder → httpx → katana+gau → nuclei → produce Findings
func (o *Orchestrator) RunFull(ctx context.Context) (*ScanResult, error) {
	runID := generateID("run")
	now := time.Now()

	run := &models.ScanRun{
		ID:        runID,
		ProgramID: o.programID,
		StartedAt: now,
		RunType:   "full",
	}

	o.log.Info("orchestrator: starting full scan", "run_id", runID, "program", o.programID)

	var allURLs []string
	var errors []string

	// Stage 1: Subdomain enumeration
	subResult, err := o.pipeline.RunSubfinder(ctx)
	if err != nil {
		o.log.Error("orchestrator: subfinder failed", "error", err)
		errors = append(errors, fmt.Sprintf("subfinder: %v", err))
	}

	var hosts []string
	if subResult != nil {
		hosts = subResult.Subdomains
	}

	// Also add base domains (non-wildcard)
	for _, d := range o.pipeline.cfg.Domains {
		d = strings.TrimPrefix(d, "*.")
		hosts = append(hosts, d)
	}
	hosts = dedup(hosts)

	// Stage 2: Probe live hosts
	httpxResults, err := o.pipeline.RunHttpx(ctx, hosts)
	if err != nil {
		o.log.Error("orchestrator: httpx failed", "error", err)
		errors = append(errors, fmt.Sprintf("httpx: %v", err))
	}

	run.HostsScanned = len(httpxResults)
	var liveURLs []string
	for _, hr := range httpxResults {
		if hr.URL != "" {
			liveURLs = append(liveURLs, hr.URL)
		}
	}

	// Stage 3: Crawl live hosts
	crawlResult, err := o.pipeline.RunKatana(ctx, liveURLs)
	if err != nil {
		o.log.Error("orchestrator: katana failed", "error", err)
		errors = append(errors, fmt.Sprintf("katana: %v", err))
	}
	if crawlResult != nil {
		allURLs = append(allURLs, crawlResult.URLs...)
	}

	// Stage 4: Historical URLs
	baseDomains := make([]string, 0, len(o.pipeline.cfg.Domains))
	for _, d := range o.pipeline.cfg.Domains {
		baseDomains = append(baseDomains, strings.TrimPrefix(d, "*."))
	}
	gauResult, err := o.pipeline.RunGau(ctx, baseDomains)
	if err != nil {
		o.log.Error("orchestrator: gau failed", "error", err)
		errors = append(errors, fmt.Sprintf("gau: %v", err))
	}
	if gauResult != nil {
		allURLs = append(allURLs, gauResult.URLs...)
	}

	// Merge live URLs + crawled + historical
	allURLs = append(allURLs, liveURLs...)
	allURLs = dedup(allURLs)
	run.URLsCrawled = len(allURLs)

	// Stage 5: Nuclei scan
	nucleiResults, err := o.pipeline.RunNuclei(ctx, allURLs)
	if err != nil {
		o.log.Error("orchestrator: nuclei failed", "error", err)
		errors = append(errors, fmt.Sprintf("nuclei: %v", err))
	}

	// Convert nuclei results to Findings
	findings := o.nucleiToFindings(nucleiResults, runID)

	// Finalize run
	finishedAt := time.Now()
	run.FinishedAt = &finishedAt
	run.FindingsTotal = len(findings)
	run.FindingsNew = len(findings) // All new on first run
	run.HasNewFindings = len(findings) > 0
	run.Errors = errors

	o.log.Info("orchestrator: scan complete",
		"run_id", runID,
		"hosts", run.HostsScanned,
		"urls", run.URLsCrawled,
		"findings", run.FindingsTotal,
		"errors", len(errors),
		"duration", time.Since(now),
	)

	return &ScanResult{Run: run, Findings: findings}, nil
}

// nucleiToFindings converts nuclei results to Finding models.
func (o *Orchestrator) nucleiToFindings(results []NucleiResult, scanRunID string) []*models.Finding {
	var findings []*models.Finding

	for _, nr := range results {
		now := time.Now()

		// Parse URL components
		u, _ := url.Parse(nr.URL)
		host := ""
		path := ""
		method := "GET"
		var paramNames []string

		if u != nil {
			host = u.Hostname()
			path = u.Path

			// Extract query parameter names
			for k := range u.Query() {
				paramNames = append(paramNames, k)
			}
			sort.Strings(paramNames)
		}

		// Map nuclei severity to model severity
		severity := mapSeverity(nr.Severity)

		findingKey := models.ComputeFindingKey(method, nr.URL, nr.TemplateID, paramNames)

		f := &models.Finding{
			ID:               generateID("f"),
			FindingKey:       findingKey,
			CreatedAt:        now,
			UpdatedAt:        now,
			ProgramID:        o.programID,
			ScanRunID:        scanRunID,
			URL:              nr.URL,
			Method:           method,
			Host:             host,
			Path:             path,
			NucleiTemplateID: nr.TemplateID,
			ScannerEvidence:  nr.Evidence,
			Severity:         severity,
			Status:           models.StatusNew,
			ParamNames:       paramNames,
		}

		findings = append(findings, f)
	}

	return findings
}

func mapSeverity(s string) models.Severity {
	switch strings.ToLower(s) {
	case "info":
		return models.SeverityInfo
	case "low":
		return models.SeverityLow
	case "medium":
		return models.SeverityMedium
	case "high":
		return models.SeverityHigh
	case "critical":
		return models.SeverityCritical
	default:
		return models.SeverityInfo
	}
}

func generateID(prefix string) string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%s-%x", prefix, b)
}
