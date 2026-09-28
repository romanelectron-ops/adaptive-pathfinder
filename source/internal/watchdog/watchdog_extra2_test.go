package watchdog

// watchdog_extra2_test.go — covers remaining uncovered branches via injection:
//   • isPIDAlive windows branch: "no tasks running" → return false, nil
//   • isPIDAlive default branch: kill -0 fails    → return false, nil
//   • isPIDAlive default branch: kill -0 succeeds → return true, nil

import (
	"errors"
	"testing"
)

// ─── Windows branch: "no tasks are running" → return false, nil ──────────────

func TestIsPIDAlive_NoTasksRunning(t *testing.T) {
	origTasklist := runTasklist
	origGOOS := watchdogGOOS
	defer func() {
		runTasklist = origTasklist
		watchdogGOOS = origGOOS
	}()

	watchdogGOOS = "windows"
	runTasklist = func(pid int) ([]byte, error) {
		return []byte("INFO: No tasks are running which match the specified criteria."), nil
	}

	alive, err := isPIDAlive(12345)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alive {
		t.Error("expected alive=false when tasklist reports no tasks running")
	}
	t.Log("OK: isPIDAlive windows 'no tasks' branch covered")
}

// ─── Default (non-Windows) branch: kill -0 fails → return false, nil ─────────

func TestIsPIDAlive_Default_ProcessDead(t *testing.T) {
	origGOOS := watchdogGOOS
	origKill := killCheckFn
	defer func() {
		watchdogGOOS = origGOOS
		killCheckFn = origKill
	}()

	watchdogGOOS = "linux"
	killCheckFn = func(pid int) error {
		return errors.New("no such process")
	}

	alive, err := isPIDAlive(99999)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alive {
		t.Error("expected alive=false when kill -0 fails")
	}
	t.Log("OK: isPIDAlive default dead-process branch covered")
}

// ─── Default (non-Windows) branch: kill -0 succeeds → return true, nil ──────

func TestIsPIDAlive_Default_ProcessAlive(t *testing.T) {
	origGOOS := watchdogGOOS
	origKill := killCheckFn
	defer func() {
		watchdogGOOS = origGOOS
		killCheckFn = origKill
	}()

	watchdogGOOS = "linux"
	killCheckFn = func(pid int) error {
		return nil // process is alive
	}

	alive, err := isPIDAlive(1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !alive {
		t.Error("expected alive=true when kill -0 succeeds")
	}
	t.Log("OK: isPIDAlive default alive-process branch covered")
}
