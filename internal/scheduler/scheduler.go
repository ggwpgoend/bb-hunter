// Package scheduler implements a cron-like scheduler for periodic scans.
// It manages scan schedules per program and triggers scan runs at configured intervals.
//
// Schedule types:
//   - interval: run every N duration (e.g., every 6h)
//   - daily: run at a specific time each day (e.g., 03:00 UTC)
//   - weekly: run on specific weekdays at a given time
package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Schedule defines when scans should run for a program.
type Schedule struct {
	ProgramID string        `json:"program_id" yaml:"program_id"`
	Type      ScheduleType  `json:"type" yaml:"type"`
	Interval  time.Duration `json:"interval,omitempty" yaml:"interval,omitempty"`
	TimeOfDay string        `json:"time_of_day,omitempty" yaml:"time_of_day,omitempty"` // HH:MM format
	Weekdays  []time.Weekday `json:"weekdays,omitempty" yaml:"weekdays,omitempty"`
	RunType   string        `json:"run_type" yaml:"run_type"` // "full", "delta"
	Enabled   bool          `json:"enabled" yaml:"enabled"`
}

// ScheduleType is the kind of schedule.
type ScheduleType string

const (
	ScheduleInterval ScheduleType = "interval"
	ScheduleDaily    ScheduleType = "daily"
	ScheduleWeekly   ScheduleType = "weekly"
)

// ScanFunc is called when a scheduled scan should start.
type ScanFunc func(ctx context.Context, programID, runType string) error

// Scheduler manages periodic scan execution.
type Scheduler struct {
	schedules []Schedule
	scanFunc  ScanFunc
	log       *slog.Logger

	mu       sync.Mutex
	lastRun  map[string]time.Time // program_id → last run time
	cancel   context.CancelFunc
	running  bool
}

// New creates a scheduler with the given schedules and scan function.
func New(schedules []Schedule, scanFunc ScanFunc, logger *slog.Logger) *Scheduler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Scheduler{
		schedules: schedules,
		scanFunc:  scanFunc,
		log:       logger,
		lastRun:   make(map[string]time.Time),
	}
}

// Start begins the scheduler loop. Blocks until ctx is cancelled.
func (s *Scheduler) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
	s.running = true

	s.log.Info("scheduler: started", "schedules", len(s.schedules))

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Check immediately on start
	s.checkAll(ctx)

	for {
		select {
		case <-ctx.Done():
			s.log.Info("scheduler: stopped")
			s.running = false
			return
		case <-ticker.C:
			s.checkAll(ctx)
		}
	}
}

// Stop stops the scheduler.
func (s *Scheduler) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}

// IsRunning returns whether the scheduler is currently active.
func (s *Scheduler) IsRunning() bool {
	return s.running
}

// checkAll evaluates all schedules and triggers due scans.
func (s *Scheduler) checkAll(ctx context.Context) {
	now := time.Now().UTC()

	for _, sched := range s.schedules {
		if !sched.Enabled {
			continue
		}
		if ctx.Err() != nil {
			return
		}

		if s.isDue(sched, now) {
			s.log.Info("scheduler: triggering scan",
				"program", sched.ProgramID,
				"type", sched.RunType,
				"schedule_type", sched.Type,
			)

			s.mu.Lock()
			s.lastRun[sched.ProgramID] = now
			s.mu.Unlock()

			go func(sc Schedule) {
				if err := s.scanFunc(ctx, sc.ProgramID, sc.RunType); err != nil {
					s.log.Error("scheduler: scan failed",
						"program", sc.ProgramID,
						"error", err,
					)
				}
			}(sched)
		}
	}
}

// isDue checks if a schedule should trigger now.
func (s *Scheduler) isDue(sched Schedule, now time.Time) bool {
	s.mu.Lock()
	last, hasRun := s.lastRun[sched.ProgramID]
	s.mu.Unlock()

	switch sched.Type {
	case ScheduleInterval:
		if !hasRun {
			return true // first run
		}
		return now.Sub(last) >= sched.Interval

	case ScheduleDaily:
		tod, err := parseTimeOfDay(sched.TimeOfDay)
		if err != nil {
			s.log.Error("scheduler: invalid time_of_day", "value", sched.TimeOfDay, "error", err)
			return false
		}
		target := time.Date(now.Year(), now.Month(), now.Day(), tod.hour, tod.minute, 0, 0, time.UTC)

		// Within 1 minute of target time and haven't run today
		if now.Sub(target).Abs() <= time.Minute {
			if !hasRun || last.Day() != now.Day() || last.Month() != now.Month() {
				return true
			}
		}
		return false

	case ScheduleWeekly:
		tod, err := parseTimeOfDay(sched.TimeOfDay)
		if err != nil {
			return false
		}
		target := time.Date(now.Year(), now.Month(), now.Day(), tod.hour, tod.minute, 0, 0, time.UTC)

		// Check weekday
		isCorrectDay := false
		for _, wd := range sched.Weekdays {
			if now.Weekday() == wd {
				isCorrectDay = true
				break
			}
		}
		if !isCorrectDay {
			return false
		}

		if now.Sub(target).Abs() <= time.Minute {
			if !hasRun || last.Day() != now.Day() {
				return true
			}
		}
		return false

	default:
		return false
	}
}

// NextRun calculates the next run time for a schedule.
func NextRun(sched Schedule, now time.Time) (time.Time, error) {
	switch sched.Type {
	case ScheduleInterval:
		return now.Add(sched.Interval), nil

	case ScheduleDaily:
		tod, err := parseTimeOfDay(sched.TimeOfDay)
		if err != nil {
			return time.Time{}, err
		}
		next := time.Date(now.Year(), now.Month(), now.Day(), tod.hour, tod.minute, 0, 0, time.UTC)
		if next.Before(now) || next.Equal(now) {
			next = next.Add(24 * time.Hour)
		}
		return next, nil

	case ScheduleWeekly:
		tod, err := parseTimeOfDay(sched.TimeOfDay)
		if err != nil {
			return time.Time{}, err
		}
		for i := 0; i < 8; i++ {
			candidate := now.Add(time.Duration(i) * 24 * time.Hour)
			target := time.Date(candidate.Year(), candidate.Month(), candidate.Day(),
				tod.hour, tod.minute, 0, 0, time.UTC)

			for _, wd := range sched.Weekdays {
				if target.Weekday() == wd && target.After(now) {
					return target, nil
				}
			}
		}
		return time.Time{}, fmt.Errorf("no valid next run found")

	default:
		return time.Time{}, fmt.Errorf("unknown schedule type: %s", sched.Type)
	}
}

type timeOfDay struct {
	hour   int
	minute int
}

func parseTimeOfDay(s string) (timeOfDay, error) {
	var h, m int
	n, err := fmt.Sscanf(s, "%d:%d", &h, &m)
	if err != nil || n != 2 {
		return timeOfDay{}, fmt.Errorf("invalid time format %q (expected HH:MM)", s)
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return timeOfDay{}, fmt.Errorf("time out of range: %02d:%02d", h, m)
	}
	return timeOfDay{hour: h, minute: m}, nil
}
