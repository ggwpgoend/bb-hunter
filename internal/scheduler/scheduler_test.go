package scheduler

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestIntervalScheduleFirstRun(t *testing.T) {
	s := New([]Schedule{
		{ProgramID: "prog1", Type: ScheduleInterval, Interval: 1 * time.Hour, RunType: "full", Enabled: true},
	}, nil, nil)

	now := time.Now().UTC()
	if !s.isDue(s.schedules[0], now) {
		t.Error("interval schedule should be due on first run")
	}
}

func TestIntervalScheduleNotDue(t *testing.T) {
	s := New([]Schedule{
		{ProgramID: "prog1", Type: ScheduleInterval, Interval: 1 * time.Hour, RunType: "full", Enabled: true},
	}, nil, nil)

	now := time.Now().UTC()
	s.mu.Lock()
	s.lastRun["prog1"] = now.Add(-30 * time.Minute) // ran 30 min ago
	s.mu.Unlock()

	if s.isDue(s.schedules[0], now) {
		t.Error("interval schedule should NOT be due (only 30 min elapsed of 1h interval)")
	}
}

func TestIntervalScheduleDue(t *testing.T) {
	s := New([]Schedule{
		{ProgramID: "prog1", Type: ScheduleInterval, Interval: 1 * time.Hour, RunType: "full", Enabled: true},
	}, nil, nil)

	now := time.Now().UTC()
	s.mu.Lock()
	s.lastRun["prog1"] = now.Add(-2 * time.Hour) // ran 2h ago
	s.mu.Unlock()

	if !s.isDue(s.schedules[0], now) {
		t.Error("interval schedule should be due (2h elapsed > 1h interval)")
	}
}

func TestDailySchedule(t *testing.T) {
	s := New([]Schedule{
		{ProgramID: "prog1", Type: ScheduleDaily, TimeOfDay: "03:00", RunType: "full", Enabled: true},
	}, nil, nil)

	// Exactly at 03:00
	now := time.Date(2026, 5, 14, 3, 0, 0, 0, time.UTC)
	if !s.isDue(s.schedules[0], now) {
		t.Error("daily schedule should be due at 03:00")
	}

	// At 03:00 but already ran today
	s.mu.Lock()
	s.lastRun["prog1"] = now
	s.mu.Unlock()

	if s.isDue(s.schedules[0], now) {
		t.Error("daily schedule should NOT be due (already ran today)")
	}

	// At 15:00 — not due
	afternoon := time.Date(2026, 5, 14, 15, 0, 0, 0, time.UTC)
	s.mu.Lock()
	delete(s.lastRun, "prog1")
	s.mu.Unlock()

	if s.isDue(s.schedules[0], afternoon) {
		t.Error("daily schedule should NOT be due at 15:00 (scheduled for 03:00)")
	}
}

func TestWeeklySchedule(t *testing.T) {
	// May 14, 2026 is a Thursday
	s := New([]Schedule{
		{ProgramID: "prog1", Type: ScheduleWeekly, TimeOfDay: "02:00",
			Weekdays: []time.Weekday{time.Monday, time.Thursday}, RunType: "full", Enabled: true},
	}, nil, nil)

	// Thursday at 02:00 — should be due
	thursday := time.Date(2026, 5, 14, 2, 0, 0, 0, time.UTC)
	if !s.isDue(s.schedules[0], thursday) {
		t.Error("weekly schedule should be due on Thursday at 02:00")
	}

	// Wednesday at 02:00 — should NOT be due
	wednesday := time.Date(2026, 5, 13, 2, 0, 0, 0, time.UTC)
	if s.isDue(s.schedules[0], wednesday) {
		t.Error("weekly schedule should NOT be due on Wednesday")
	}
}

func TestDisabledSchedule(t *testing.T) {
	var calls int32

	s := New([]Schedule{
		{ProgramID: "prog1", Type: ScheduleInterval, Interval: 1 * time.Second, RunType: "full", Enabled: false},
	}, func(ctx context.Context, programID, runType string) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	go s.Start(ctx)
	time.Sleep(150 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)

	if atomic.LoadInt32(&calls) != 0 {
		t.Error("disabled schedule should NOT trigger scans")
	}
}

func TestSchedulerTriggersScans(t *testing.T) {
	var mu sync.Mutex
	var triggered []string

	s := New([]Schedule{
		{ProgramID: "prog1", Type: ScheduleInterval, Interval: 1 * time.Millisecond, RunType: "delta", Enabled: true},
	}, func(ctx context.Context, programID, runType string) error {
		mu.Lock()
		triggered = append(triggered, programID)
		mu.Unlock()
		return nil
	}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go s.Start(ctx)
	time.Sleep(200 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(triggered) == 0 {
		t.Error("scheduler should have triggered at least one scan")
	}
	if triggered[0] != "prog1" {
		t.Errorf("expected prog1, got %s", triggered[0])
	}
}

func TestNextRunInterval(t *testing.T) {
	sched := Schedule{Type: ScheduleInterval, Interval: 6 * time.Hour}
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)

	next, err := NextRun(sched, now)
	if err != nil {
		t.Fatal(err)
	}

	expected := now.Add(6 * time.Hour)
	if !next.Equal(expected) {
		t.Errorf("expected %v, got %v", expected, next)
	}
}

func TestNextRunDaily(t *testing.T) {
	sched := Schedule{Type: ScheduleDaily, TimeOfDay: "03:00"}
	now := time.Date(2026, 5, 14, 15, 0, 0, 0, time.UTC) // 15:00 → next is tomorrow 03:00

	next, err := NextRun(sched, now)
	if err != nil {
		t.Fatal(err)
	}

	expected := time.Date(2026, 5, 15, 3, 0, 0, 0, time.UTC)
	if !next.Equal(expected) {
		t.Errorf("expected %v, got %v", expected, next)
	}
}

func TestNextRunWeekly(t *testing.T) {
	sched := Schedule{Type: ScheduleWeekly, TimeOfDay: "02:00", Weekdays: []time.Weekday{time.Monday}}
	// Thursday May 14 → next Monday is May 18
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)

	next, err := NextRun(sched, now)
	if err != nil {
		t.Fatal(err)
	}

	expected := time.Date(2026, 5, 18, 2, 0, 0, 0, time.UTC)
	if !next.Equal(expected) {
		t.Errorf("expected %v, got %v", expected, next)
	}
}

func TestParseTimeOfDay(t *testing.T) {
	tests := []struct {
		input    string
		valid    bool
		hour     int
		minute   int
	}{
		{"03:00", true, 3, 0},
		{"23:59", true, 23, 59},
		{"00:00", true, 0, 0},
		{"24:00", false, 0, 0},
		{"12:60", false, 0, 0},
		{"abc", false, 0, 0},
		{"", false, 0, 0},
	}

	for _, tt := range tests {
		tod, err := parseTimeOfDay(tt.input)
		if tt.valid && err != nil {
			t.Errorf("parseTimeOfDay(%q) should succeed, got error: %v", tt.input, err)
		}
		if !tt.valid && err == nil {
			t.Errorf("parseTimeOfDay(%q) should fail", tt.input)
		}
		if tt.valid {
			if tod.hour != tt.hour || tod.minute != tt.minute {
				t.Errorf("parseTimeOfDay(%q) = %d:%d, want %d:%d", tt.input, tod.hour, tod.minute, tt.hour, tt.minute)
			}
		}
	}
}
