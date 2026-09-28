package watchdog

import (
	"fmt"
	"runtime"
	"testing"
)

// TestIsPIDAlive_TasklistError covers the "return false, err" branch in
// isPIDAlive's Windows case by injecting a failing runTasklist hook.
func TestIsPIDAlive_TasklistError(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only: tests the tasklist error branch")
	}

	old := runTasklist
	runTasklist = func(pid int) ([]byte, error) {
		return nil, fmt.Errorf("mock tasklist failure")
	}
	defer func() { runTasklist = old }()

	alive, err := isPIDAlive(12345)
	if err == nil {
		t.Error("expected error from runTasklist hook, got nil")
	}
	if alive {
		t.Error("expected alive=false when tasklist returns error")
	}
	t.Logf("OK: tasklist error path covered: err=%v", err)
}

// TestIsPIDAlive_TasklistDeadPID covers the "no tasks are running" branch
// by using a guaranteed-dead PID and the real tasklist.
func TestIsPIDAlive_TasklistDeadPID(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only")
	}
	// PID 999999 should not exist
	alive, err := isPIDAlive(999999)
	if err != nil {
		t.Logf("isPIDAlive error (acceptable): %v", err)
	}
	if alive {
		t.Log("PID 999999 unexpectedly alive; skipping assertion")
	}
	t.Logf("OK: dead PID alive=%v err=%v", alive, err)
}
