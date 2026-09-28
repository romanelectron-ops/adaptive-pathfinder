package detector

// Extra tests for detector — covering uncovered functions:
// InvalidateCache, Diagnose, DiagnoseAndRecommend, canTCPConnect,
// canResolveDNS, isSNIBlocked.
//
// Strategy: use cancelled/deadline-exceeded contexts so all network
// calls fail fast without real internet access.  That exercises the
// error-handling branches and pushes overall coverage past 60 %.

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// ─── InvalidateCache ─────────────────────────────────────────────────────────

// InvalidateCache is a documented no-op; calling it must not panic.
func TestInvalidateCache_NoPanic(t *testing.T) {
	d := New()
	d.InvalidateCache() // must not panic
	d.InvalidateCache() // idempotent
}

// ─── canTCPConnect ───────────────────────────────────────────────────────────

func TestCanTCPConnect_CancelledContext(t *testing.T) {
	d := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	if d.canTCPConnect(ctx, "1.1.1.1:443") {
		t.Error("expected false for cancelled context")
	}
}

func TestCanTCPConnect_LocalListener(t *testing.T) {
	// Start a real local TCP listener so the connect succeeds.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	defer ln.Close()

	d := New()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if !d.canTCPConnect(ctx, ln.Addr().String()) {
		t.Errorf("expected true for local listener at %s", ln.Addr())
	}
}

func TestCanTCPConnect_UnroutableAddr(t *testing.T) {
	d := New()
	// Use a very short timeout so the test finishes quickly.
	d.timeout = 200 * time.Millisecond
	d.httpClient.Timeout = 200 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	// 192.0.2.1 is TEST-NET-1 (RFC 5737) — should not be routable.
	if d.canTCPConnect(ctx, "192.0.2.1:443") {
		t.Log("192.0.2.1:443 unexpectedly reachable — skipping assertion")
	}
}

// ─── canResolveDNS ───────────────────────────────────────────────────────────

func TestCanResolveDNS_CancelledContext(t *testing.T) {
	d := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if d.canResolveDNS(ctx, "google.com") {
		t.Error("expected false for cancelled context")
	}
}

// ─── isSNIBlocked ────────────────────────────────────────────────────────────

func TestIsSNIBlocked_CancelledContext(t *testing.T) {
	d := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// With a cancelled ctx the HTTP request fails with "context canceled",
	// which does NOT match "connection reset" / "tls" / "timeout".
	// Therefore isSNIBlocked must return false.
	if d.isSNIBlocked(ctx) {
		t.Error("expected false for cancelled context (not a TLS/RST error)")
	}
}

// ─── Diagnose ────────────────────────────────────────────────────────────────

func TestDiagnose_CancelledContext_ReturnsComplete(t *testing.T) {
	d := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	bt, err := d.Diagnose(ctx)
	if err != nil {
		t.Fatalf("Diagnose returned unexpected error: %v", err)
	}
	// canTCPConnect(cancelled) → false → BlockageComplete
	if bt != BlockageComplete {
		t.Errorf("expected BlockageComplete, got %s", bt)
	}
}

func TestDiagnose_DeadlineExceeded_ReturnsComplete(t *testing.T) {
	d := New()
	d.timeout = 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	time.Sleep(2 * time.Millisecond) // ensure deadline passed
	bt, err := d.Diagnose(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bt != BlockageComplete {
		t.Errorf("expected BlockageComplete, got %s", bt)
	}
}

// ─── DiagnoseAndRecommend ─────────────────────────────────────────────────────

func TestDiagnoseAndRecommend_CancelledContext(t *testing.T) {
	d := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	bt, strategy, report := d.DiagnoseAndRecommend(ctx)

	// BlockageComplete expected (canTCPConnect fails immediately)
	if bt != BlockageComplete {
		t.Errorf("expected BlockageComplete, got %s", bt)
	}
	if strategy.Primary == "" {
		t.Error("strategy.Primary must not be empty")
	}
	if strategy.Fallback == "" {
		t.Error("strategy.Fallback must not be empty")
	}
	if report == "" {
		t.Error("report must not be empty")
	}
	// Report should mention the strategy tokens
	if !strings.Contains(report, strategy.Primary) {
		t.Errorf("report %q should contain primary strategy %q", report, strategy.Primary)
	}
}

func TestDiagnoseAndRecommend_ReportContainsStrategy(t *testing.T) {
	d := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, s, report := d.DiagnoseAndRecommend(ctx)
	// buildReport appends "Стратегия: primary → fallback"
	needle := s.Primary + " → " + s.Fallback
	if !strings.Contains(report, needle) {
		t.Errorf("report should contain %q, got: %q", needle, report)
	}
}

// ─── SelectStrategy unknown case ─────────────────────────────────────────────

func TestSelectStrategy_UnknownBlockageType(t *testing.T) {
	s := SelectStrategy(BlockageType(99))
	if s.Primary == "" {
		t.Error("unknown blockage type should still produce a strategy")
	}
	if s.Reason == "" {
		t.Error("unknown blockage type strategy should have a reason")
	}
}
