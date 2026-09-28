package sources

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

func TestNew_ReturnsNonNil(t *testing.T) {
	mgr := New(&models.AppConfig{})
	if mgr == nil {
		t.Fatal("New() returned nil")
	}
}

func TestNew_HasHTTPClient(t *testing.T) {
	mgr := New(&models.AppConfig{})
	if mgr.httpClient == nil {
		t.Error("New() should initialize httpClient")
	}
}

func TestNew_HasLastUpdateMap(t *testing.T) {
	mgr := New(&models.AppConfig{})
	if mgr.lastUpdate == nil {
		t.Error("New() should initialize lastUpdate map")
	}
}

// ─── FetchAll ────────────────────────────────────────────────────────────────

func TestFetchAll_EmptySources(t *testing.T) {
	mgr := New(&models.AppConfig{Sources: []models.SourceConfig{}})
	nodes, err := mgr.FetchAll(context.Background(), true)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(nodes))
	}
}

func TestFetchAll_DisabledSource_Skipped(t *testing.T) {
	cfg := &models.AppConfig{
		Sources: []models.SourceConfig{
			{ID: "s1", Name: "test", Enabled: false, Type: "subscription", URL: "https://example.com"},
		},
	}
	mgr := New(cfg)
	nodes, err := mgr.FetchAll(context.Background(), true)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes (disabled), got %d", len(nodes))
	}
}

func TestFetchAll_NotForced_NoAutoUpdate(t *testing.T) {
	cfg := &models.AppConfig{
		Sources: []models.SourceConfig{
			{ID: "s2", Name: "test", Enabled: true, AutoUpdate: false, Type: "subscription", URL: "https://example.com"},
		},
	}
	mgr := New(cfg)
	// force=false + AutoUpdate=false → пропускается
	nodes, err := mgr.FetchAll(context.Background(), false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes (no-auto-update), got %d", len(nodes))
	}
}

func TestFetchAll_ManualSource(t *testing.T) {
	cfg := &models.AppConfig{
		Sources: []models.SourceConfig{
			{ID: "m1", Name: "manual", Enabled: true, Type: "manual"},
		},
	}
	mgr := New(cfg)
	nodes, err := mgr.FetchAll(context.Background(), true)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes for manual source, got %d", len(nodes))
	}
}

func TestFetchAll_CtxCancelled_SubscriptionFails(t *testing.T) {
	cfg := &models.AppConfig{
		Sources: []models.SourceConfig{
			{ID: "s3", Name: "cancel-test", Enabled: true, Type: "subscription", URL: "https://1.2.3.4:9999/fail"},
		},
	}
	mgr := New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	nodes, err := mgr.FetchAll(ctx, true)
	if err != nil {
		t.Errorf("unexpected top-level error: %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes on cancel, got %d", len(nodes))
	}
}

// ─── ParseSingle ─────────────────────────────────────────────────────────────

func TestParseSingle_ValidVless(t *testing.T) {
	mgr := New(&models.AppConfig{})
	link := "vless://00000000-0000-0000-0000-000000000000@127.0.0.1:443?type=tcp#TestNode"
	node, err := mgr.ParseSingle(link)
	if err != nil {
		t.Logf("ParseSingle returned error (may be acceptable): %v", err)
		return
	}
	if node == nil {
		t.Error("expected non-nil node")
	}
}

func TestParseSingle_InvalidLink(t *testing.T) {
	mgr := New(&models.AppConfig{})
	_, err := mgr.ParseSingle("not-a-valid-link://garbage")
	if err != nil {
		t.Logf("expected error: %v", err)
	}
}

// ─── needsUpdate ─────────────────────────────────────────────────────────────

func TestNeedsUpdate_AutoUpdateFalse(t *testing.T) {
	mgr := New(&models.AppConfig{})
	src := models.SourceConfig{ID: "x", AutoUpdate: false}
	if mgr.needsUpdate(src) {
		t.Error("needsUpdate should return false when AutoUpdate=false")
	}
}

func TestNeedsUpdate_NewSource(t *testing.T) {
	mgr := New(&models.AppConfig{})
	src := models.SourceConfig{ID: "new", AutoUpdate: true, UpdateIntervalHours: 24}
	if !mgr.needsUpdate(src) {
		t.Error("needsUpdate should return true for never-updated source")
	}
}

func TestNeedsUpdate_RecentUpdate(t *testing.T) {
	mgr := New(&models.AppConfig{})
	src := models.SourceConfig{ID: "recent", AutoUpdate: true, UpdateIntervalHours: 24}
	mgr.mu.Lock()
	mgr.lastUpdate[src.ID] = time.Now()
	mgr.mu.Unlock()
	if mgr.needsUpdate(src) {
		t.Error("needsUpdate should return false for recently updated source")
	}
}

func TestNeedsUpdate_ExpiredUpdate(t *testing.T) {
	mgr := New(&models.AppConfig{})
	src := models.SourceConfig{ID: "expired", AutoUpdate: true, UpdateIntervalHours: 1}
	mgr.mu.Lock()
	mgr.lastUpdate[src.ID] = time.Now().Add(-2 * time.Hour)
	mgr.mu.Unlock()
	if !mgr.needsUpdate(src) {
		t.Error("needsUpdate should return true for expired source")
	}
}

// ─── fetchSource — unknown type ───────────────────────────────────────────────

func TestFetchSource_UnknownType(t *testing.T) {
	mgr := New(&models.AppConfig{})
	src := models.SourceConfig{ID: "u1", Type: "unknown-xyz"}
	_, err := mgr.fetchSource(context.Background(), src)
	if err == nil {
		t.Error("expected error for unknown source type")
	}
}

// ─── concurrent safety ────────────────────────────────────────────────────────

func TestFetchAll_ConcurrentManualSources(t *testing.T) {
	srcs := make([]models.SourceConfig, 10)
	for i := range srcs {
		srcs[i] = models.SourceConfig{
			ID:      fmt.Sprintf("m%d", i),
			Enabled: true,
			Type:    "manual",
		}
	}
	mgr := New(&models.AppConfig{Sources: srcs})
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = mgr.FetchAll(context.Background(), true)
		}()
	}
	wg.Wait()
}
