package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/ggwpgoend/bb-hunter/internal/models"
)

// ParallelOrchestrator runs scans across multiple domains concurrently.
type ParallelOrchestrator struct {
	baseCfg   PipelineConfig
	programID string
	workers   int
	log       *slog.Logger
}

// NewParallelOrchestrator creates an orchestrator that scans domains in parallel.
func NewParallelOrchestrator(baseCfg PipelineConfig, programID string, workers int, logger *slog.Logger) *ParallelOrchestrator {
	if logger == nil {
		logger = slog.Default()
	}
	if workers <= 0 {
		workers = 3
	}
	return &ParallelOrchestrator{
		baseCfg:   baseCfg,
		programID: programID,
		workers:   workers,
		log:       logger,
	}
}

// DomainResult holds the scan result for a single domain group.
type DomainResult struct {
	Domain string
	Result *ScanResult
	Error  error
}

// RunParallel scans domain groups concurrently using a worker pool.
// Each domain (or wildcard group) gets its own pipeline instance.
func (po *ParallelOrchestrator) RunParallel(ctx context.Context) ([]DomainResult, error) {
	domains := po.baseCfg.Domains
	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains configured")
	}

	po.log.Info("parallel scan starting",
		"domains", len(domains),
		"workers", po.workers,
	)

	start := time.Now()

	// Deduplicate base domains
	groups := groupDomains(domains)

	type job struct {
		domain  string
		domains []string
	}

	jobs := make(chan job, len(groups))
	for base, domList := range groups {
		jobs <- job{domain: base, domains: domList}
	}
	close(jobs)

	var mu sync.Mutex
	var results []DomainResult

	workerCount := po.workers
	if workerCount > len(groups) {
		workerCount = len(groups)
	}

	var wg sync.WaitGroup
	wg.Add(workerCount)

	for i := 0; i < workerCount; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}

				po.log.Info("worker scanning domain",
					"worker", workerID,
					"domain", j.domain,
				)

				cfg := po.baseCfg
				cfg.Domains = j.domains

				pipeline := NewPipeline(cfg)
				orch := NewOrchestrator(pipeline, po.programID, po.log)

				result, err := orch.RunFull(ctx)

				mu.Lock()
				results = append(results, DomainResult{
					Domain: j.domain,
					Result: result,
					Error:  err,
				})
				mu.Unlock()

				if err != nil {
					po.log.Warn("worker scan failed",
						"worker", workerID,
						"domain", j.domain,
						"error", err,
					)
				} else {
					findingsCount := 0
					if result != nil {
						findingsCount = len(result.Findings)
					}
					po.log.Info("worker scan complete",
						"worker", workerID,
						"domain", j.domain,
						"findings", findingsCount,
					)
				}
			}
		}(i)
	}

	wg.Wait()

	po.log.Info("parallel scan complete",
		"domains", len(groups),
		"duration", time.Since(start),
		"results", len(results),
	)

	return results, nil
}

// MergeResults combines multiple DomainResults into a single ScanResult.
func MergeResults(results []DomainResult, programID string) *ScanResult {
	runID := generateID("prun")
	now := time.Now()

	merged := &ScanResult{
		Run: &models.ScanRun{
			ID:        runID,
			ProgramID: programID,
			StartedAt: now,
			RunType:   "parallel",
		},
	}

	var totalHosts, totalURLs int
	var allErrors []string

	for _, dr := range results {
		if dr.Error != nil {
			allErrors = append(allErrors, fmt.Sprintf("%s: %v", dr.Domain, dr.Error))
			continue
		}
		if dr.Result == nil {
			continue
		}

		merged.Findings = append(merged.Findings, dr.Result.Findings...)

		if dr.Result.Run != nil {
			totalHosts += dr.Result.Run.HostsScanned
			totalURLs += dr.Result.Run.URLsCrawled
			allErrors = append(allErrors, dr.Result.Run.Errors...)
		}
	}

	finishedAt := time.Now()
	merged.Run.FinishedAt = &finishedAt
	merged.Run.HostsScanned = totalHosts
	merged.Run.URLsCrawled = totalURLs
	merged.Run.FindingsTotal = len(merged.Findings)
	merged.Run.FindingsNew = len(merged.Findings)
	merged.Run.HasNewFindings = len(merged.Findings) > 0
	merged.Run.Errors = allErrors

	return merged
}

// groupDomains groups domain patterns by their base domain.
// e.g., ["example.com", "*.example.com", "target.ru"] → {"example.com": [...], "target.ru": [...]}
func groupDomains(domains []string) map[string][]string {
	groups := make(map[string][]string)
	for _, d := range domains {
		base := strings.TrimPrefix(d, "*.")
		groups[base] = append(groups[base], d)
	}
	return groups
}
