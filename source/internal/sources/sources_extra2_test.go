package sources

import (
	"context"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── fetchSubscription — NewRequestWithContext error (line 91-93) ─────────────

func TestFetchSubscription_InvalidURL(t *testing.T) {
	// A URL with a null byte causes http.NewRequestWithContext to fail (line 92).
	mgr := New(&models.AppConfig{})
	src := models.SourceConfig{
		ID:   "invalid-url",
		Name: "Invalid",
		URL:  "\x00://bad",
		Type: "subscription",
	}
	_, err := mgr.fetchSubscription(context.Background(), src)
	if err == nil {
		t.Error("expected error for invalid request URL")
	}
	t.Logf("OK: fetchSubscription invalid URL → %v", err)
}

// ─── fetchTorBridges — NewRequestWithContext error continue (line 140) ────────

func TestFetchTorBridges_InvalidURL(t *testing.T) {
	// К2-E П8 (свод C, трек 1 №8; 2026-09-07): a URL with a null byte causes
	// http.NewRequestWithContext to fail (line ~140). It is the only broker URL, so
	// zero bridges are obtained overall — that is now a real error, not a silent nil.
	origURLs := torBridgeURLs
	torBridgeURLs = []string{"\x00://invalid"}
	defer func() { torBridgeURLs = origURLs }()

	mgr := New(&models.AppConfig{})
	nodes, err := mgr.fetchTorBridges(context.Background())
	if err == nil {
		t.Fatalf("fetchTorBridges should return an error when the only broker URL is invalid (П8)")
	}
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes for invalid URL, got %d", len(nodes))
	}
	t.Logf("OK: fetchTorBridges invalid URL → error: %v", err)
}
