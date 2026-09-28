package dpi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestCanaryTester_Test_TimingAndEntropyInjected covers the score branches:
//
//	score += 25 (result.TimingAnomaly == true)
//	score += 20 (result.EntropyHigh   == true)
//
// Both are unreachable via real network in CI (timing anomaly needs RTT>150ms,
// entropy needs a real SOCKS server). Injection hooks added to CanaryTester
// make these branches deterministically testable.
func TestCanaryTester_Test_TimingAndEntropyInjected(t *testing.T) {
	// Mock TLS fingerprint endpoint — returns no golang indicator (leaked=false)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, `{"ja3":"chrome","tls":"ok"}`)
	}))
	defer srv.Close()

	orig := tlsFingerprintURL
	tlsFingerprintURL = srv.URL
	defer func() { tlsFingerprintURL = orig }()

	c := NewCanaryTester("")
	// Inject: timing anomaly is always true, entropy is always true
	c.timingAnomalyFn = func(ctx context.Context) bool { return true }
	c.entropyHighFn = func(ctx context.Context) bool { return true }

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := c.Test(ctx)
	if err != nil {
		t.Fatalf("Test() returned error: %v", err)
	}

	if !result.TimingAnomaly {
		t.Error("expected TimingAnomaly=true from injected hook")
	}
	if !result.EntropyHigh {
		t.Error("expected EntropyHigh=true from injected hook")
	}
	// score should include +25 (timing) + +20 (entropy) = 45
	if result.Score < 45 {
		t.Errorf("Score=%d, want >= 45 (timing=25 + entropy=20)", result.Score)
	}
	t.Logf("OK: score=%d timing=%v entropy=%v", result.Score, result.TimingAnomaly, result.EntropyHigh)
}
