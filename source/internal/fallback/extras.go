// extras.go - supplementary methods and helpers for the fallback package.
package fallback

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// ── Watchdog history ─────────────────────────────────────────────────────────

var historyMu sync.RWMutex

const maxHistoryLen = 64

// appendHistory appends a timestamped entry to the watchdog history log.
func (w *Watchdog) appendHistory(entry string) {
	historyMu.Lock()
	w.historyLog = append(w.historyLog,
		fmt.Sprintf("%s %s", time.Now().Format("15:04:05"), entry))
	if len(w.historyLog) > maxHistoryLen {
		w.historyLog = w.historyLog[len(w.historyLog)-maxHistoryLen:]
	}
	historyMu.Unlock()
}

// GetHistoryLog returns a snapshot copy of the watchdog history log.
// Always returns at least one entry. Safe for concurrent use.
func (w *Watchdog) GetHistoryLog() []string {
	historyMu.RLock()
	out := make([]string, len(w.historyLog))
	copy(out, w.historyLog)
	historyMu.RUnlock()
	if len(out) == 0 {
		out = []string{"watchdog initialized"}
	}
	return out
}

// ── Exponential backoff ───────────────────────────────────────────────────────

const backoffMax = 30 * time.Second

// backoffDuration returns the wait before the attempt-th retry.
// Sequence: 1s, 2s, 4s, 8s, 16s, 30s (capped).
func backoffDuration(attempt int) time.Duration {
	if attempt <= 0 {
		return time.Second
	}
	d := time.Second << uint(attempt) // 2s, 4s, 8s, 16s, 32s...
	if d > backoffMax {
		return backoffMax
	}
	return d
}

// ── PsiphonManager helpers ────────────────────────────────────────────────────

// IsAvailable returns true if the psiphond binary exists in binDir.
func (m *PsiphonManager) IsAvailable(binDir string) bool {
	binName := "psiphond"
	if runtime.GOOS == "windows" {
		binName = "psiphond.exe"
	}
	_, err := os.Stat(filepath.Join(binDir, binName))
	return err == nil
}
