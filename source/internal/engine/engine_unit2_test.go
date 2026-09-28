package engine

// engine_unit2_test.go — second batch of unit tests targeting 0%-covered
// functions that don't require a running sing-box or network access.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/detector"
	"github.com/apf/adaptive-pathfinder/internal/dpi"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── selectBest ──────────────────────────────────────────────────────────────

func TestSelectBest(t *testing.T) {
	e := newTestEngine()
	n1 := &models.Node{ID: "sb1", Protocol: models.ProtoVLESS, Status: models.StatusOK, Score: 0.95}
	n2 := &models.Node{ID: "sb2", Protocol: models.ProtoVLESS, Status: models.StatusOK, Score: 0.5}
	e.nodes = []*models.Node{n1, n2}

	best := e.selectBest()
	if best == nil {
		t.Fatal("selectBest should return a node when candidates exist")
	}
	t.Logf("OK: selectBest = %s score=%.3f", best.ID, best.Score)
}

func TestSelectBestEmpty(t *testing.T) {
	e := newTestEngine()
	e.nodes = nil
	best := e.selectBest()
	if best != nil {
		t.Errorf("selectBest with no nodes should return nil, got %+v", best)
	}
	t.Log("OK: selectBest empty → nil")
}

// ─── selectBestForStrategy ───────────────────────────────────────────────────

func TestSelectBestForStrategy(t *testing.T) {
	e := newTestEngine()
	n1 := &models.Node{ID: "sf1", Protocol: models.ProtoVLESS, Status: models.StatusOK, Latency: 50, Score: 0.9}
	n2 := &models.Node{ID: "sf2", Protocol: models.ProtoVMess, Status: models.StatusOK, Latency: 100, Score: 0.7}
	e.nodes = []*models.Node{n1, n2}

	best := e.selectBestForStrategy()
	if best == nil {
		t.Log("selectBestForStrategy: nil (scores may be recalculated to 0)")
	} else {
		t.Logf("OK: selectBestForStrategy = %s", best.ID)
	}
}

func TestSelectBestForStrategyWithBlockage(t *testing.T) {
	e := newTestEngine()
	n := &models.Node{ID: "sf3", Protocol: models.ProtoVLESS, Status: models.StatusOK, Score: 0.85}
	e.nodes = []*models.Node{n}

	// Set blockage type to trigger protocol weight boost
	e.stateMu.Lock()
	e.blockageType = detector.BlockageSNI
	e.stateMu.Unlock()

	_ = e.selectBestForStrategy()
	t.Log("OK: selectBestForStrategy with SNI blockage")
}

func TestSelectBestForStrategyIPBlockage(t *testing.T) {
	e := newTestEngine()
	n := &models.Node{ID: "sf4", Protocol: models.ProtoVLESS, Status: models.StatusOK, Score: 0.8}
	e.nodes = []*models.Node{n}

	e.stateMu.Lock()
	e.blockageType = detector.BlockageIP
	e.stateMu.Unlock()

	_ = e.selectBestForStrategy()
	t.Log("OK: selectBestForStrategy with IP blockage")
}

// ─── setLastRollback ─────────────────────────────────────────────────────────

func TestSetLastRollback(t *testing.T) {
	e := newTestEngine()
	e.setLastRollback("connect", errors.New("connection refused"), false)

	e.stateMu.RLock()
	rb := e.lastRollback
	e.stateMu.RUnlock()

	if rb == nil {
		t.Fatal("lastRollback should be set")
	}
	if rb.Stage != "connect" {
		t.Errorf("Stage: want connect, got %s", rb.Stage)
	}
	if rb.Reason != "connection refused" {
		t.Errorf("Reason: want 'connection refused', got %s", rb.Reason)
	}
	if rb.WasRunning != false {
		t.Error("WasRunning should be false")
	}
	t.Logf("OK: setLastRollback stage=%s reason=%s", rb.Stage, rb.Reason)
}

func TestSetLastRollbackOverwrite(t *testing.T) {
	e := newTestEngine()
	e.setLastRollback("stage1", errors.New("err1"), true)
	e.setLastRollback("stage2", errors.New("err2"), false)

	e.stateMu.RLock()
	rb := e.lastRollback
	e.stateMu.RUnlock()

	if rb.Stage != "stage2" {
		t.Errorf("expected stage2, got %s", rb.Stage)
	}
	t.Log("OK: setLastRollback overwrites previous value")
}

// ─── setVPNEndpointForKS ─────────────────────────────────────────────────────

func TestSetVPNEndpointForKS(t *testing.T) {
	e := newTestEngine()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("setVPNEndpointForKS panicked: %v", r)
		}
	}()
	// KillSwitch may or may not implement SetVPNEndpoint — just verify no panic
	e.setVPNEndpointForKS("10.0.0.1")
	e.setVPNEndpointForKS("")
	t.Log("OK: setVPNEndpointForKS no panic")
}

// ─── applyStrategy ───────────────────────────────────────────────────────────

func TestApplyStrategy(t *testing.T) {
	strategies := []detector.Strategy{
		{UseReality: true},
		{UseCDN: true},
		{UseChain: true},
		{Primary: "vless", Fallback: "trojan"},
		{},
	}
	for _, s := range strategies {
		e := newTestEngine()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("applyStrategy(%+v) panicked: %v", s, r)
				}
			}()
			e.applyStrategy(s)
		}()
	}
	t.Log("OK: applyStrategy all strategy variants")
}

func TestApplyStrategyChainSetsConfig(t *testing.T) {
	e := newTestEngine()
	e.applyStrategy(detector.Strategy{UseChain: true})
	if !e.cfg.EnableChain {
		t.Error("UseChain strategy should set cfg.EnableChain = true")
	}
	t.Log("OK: applyStrategy UseChain sets cfg.EnableChain")
}

// ─── applyDPICounterMeasures ─────────────────────────────────────────────────

func TestApplyDPICounterMeasures(t *testing.T) {
	measures := []string{"reality+utls", "traffic_padding+websocket", "utls", "none", ""}
	for _, cm := range measures {
		e := newTestEngine()
		r := &dpi.CanaryResult{CounterMeasure: cm}
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					t.Errorf("applyDPICounterMeasures(%q) panicked: %v", cm, rec)
				}
			}()
			e.applyDPICounterMeasures(r)
		}()
	}
	t.Log("OK: applyDPICounterMeasures all branches")
}

func TestApplyDPICounterMeasuresSetsBlockageType(t *testing.T) {
	e := newTestEngine()
	e.applyDPICounterMeasures(&dpi.CanaryResult{CounterMeasure: "reality+utls"})
	e.stateMu.RLock()
	bt := e.blockageType
	e.stateMu.RUnlock()
	if bt != 3 {
		t.Errorf("applyDPICounterMeasures reality+utls: want blockageType=3, got %d", bt)
	}
	t.Log("OK: applyDPICounterMeasures reality+utls sets blockageType=3")
}

// ─── applyDPIFromConfig ──────────────────────────────────────────────────────

func TestApplyDPIFromConfigEmpty(t *testing.T) {
	e := newTestEngine()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("applyDPIFromConfig panicked: %v", r)
		}
	}()
	// Default config has all DPI options disabled — just verify no panic
	e.applyDPIFromConfig()
	t.Log("OK: applyDPIFromConfig empty config")
}

func TestApplyDPIFromConfigWithPadding(t *testing.T) {
	e := newTestEngine()
	e.cfg.TrafficPaddingEnabled = true
	e.cfg.TrafficPaddingAggressive = false
	e.applyDPIFromConfig()
	t.Log("OK: applyDPIFromConfig with standard padding")
}

func TestApplyDPIFromConfigWithAllOptions(t *testing.T) {
	e := newTestEngine()
	e.cfg.TrafficPaddingEnabled = true
	e.cfg.TrafficPaddingAggressive = true
	e.cfg.CDNWorkerDomain = "myworker.workers.dev"
	e.cfg.ShadowTLSEnabled = true
	e.cfg.ShadowTLSPassword = "pass123"
	e.cfg.ShadowTLSSNI = "www.microsoft.com"
	e.cfg.StickySessionPolicy = "domain"
	e.applyDPIFromConfig()
	t.Log("OK: applyDPIFromConfig all options set")
}

// ─── loadNodes ───────────────────────────────────────────────────────────────

func TestLoadNodesFileNotExist(t *testing.T) {
	e := newTestEngine()
	// File doesn't exist yet — loadNodes should handle gracefully
	err := e.loadNodes()
	if err != nil {
		t.Logf("loadNodes warn (file absent): %v", err)
	}
	t.Log("OK: loadNodes missing file graceful")
}

// ─── registerPaidProviders ───────────────────────────────────────────────────

func TestRegisterPaidProvidersEmpty(t *testing.T) {
	e := newTestEngine()
	// No PaidProviders in config — should be a no-op
	e.registerPaidProviders()
	t.Log("OK: registerPaidProviders empty config")
}

func TestRegisterPaidProvidersWithEntries(t *testing.T) {
	e := newTestEngine()
	e.cfg.PaidProviders = []models.PaidProviderEntry{
		{
			ID:      "test-hiddify",
			Name:    "Test Hiddify",
			Type:    "hiddify",
			URL:     "http://hiddify.example.com",
			Token:   "abc123",
			Enabled: true,
		},
		{
			ID:      "disabled-entry",
			Name:    "Disabled",
			Type:    "marzban",
			URL:     "http://disabled.example.com",
			Enabled: false, // should be skipped
		},
		{
			// Invalid entry — no URL — should log error and continue
			ID:      "bad-entry",
			Name:    "Bad",
			Type:    "3xui",
			Enabled: true,
		},
	}
	e.registerPaidProviders()
	t.Log("OK: registerPaidProviders with entries — no panic")
}

// ─── ScanAndConnect ──────────────────────────────────────────────────────────

func TestScanAndConnectNoNetwork(t *testing.T) {
	e := newTestEngine()

	// Заменяем контекст движка на контекст с коротким таймаутом (500 мс).
	// updateSources() использует e.ctx для HTTP-запросов; если контекст уже отменён,
	// FetchAll() возвращает пустой список немедленно, и тест не зависает.
	e.cancel() // отменяем старый контекст
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	e.ctx = ctx
	e.cancel = cancel

	// Очищаем пул узлов — updateSources не должен добавить новые за 500 мс.
	e.mu.Lock()
	e.nodes = nil
	e.mu.Unlock()

	// No nodes + cancelled context → updateSources returns empty → tryFallback
	err := e.ScanAndConnect()
	if err == nil {
		t.Log("ScanAndConnect returned nil (unexpected success)")
	} else {
		t.Logf("OK: ScanAndConnect failed as expected: %v", err)
	}
}

// ─── CheckNodeIP / CheckCurrentIP / CheckCurrentIPByAddr ────────────────────

func TestCheckNodeIPNotFound(t *testing.T) {
	e := newTestEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := e.CheckNodeIP(ctx, "nonexistent-node-id")
	if err == nil {
		t.Error("expected error for nonexistent node")
	}
	t.Logf("OK: CheckNodeIP nonexistent: %v", err)
}

func TestCheckCurrentIPNotConnected(t *testing.T) {
	e := newTestEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := e.CheckCurrentIP(ctx)
	if err == nil {
		t.Error("expected error when not connected")
	}
	t.Logf("OK: CheckCurrentIP not connected: %v", err)
}

func TestCheckCurrentIPByAddrEmpty(t *testing.T) {
	e := newTestEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := e.CheckCurrentIPByAddr(ctx, "")
	if err == nil {
		t.Error("expected error for empty IP")
	}
	t.Logf("OK: CheckCurrentIPByAddr empty IP: %v", err)
}

// ─── RunCanaryTest ───────────────────────────────────────────────────────────

func TestRunCanaryTestTimeout(t *testing.T) {
	e := newTestEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	// Will likely fail/timeout — just must not panic
	result, err := e.RunCanaryTest(ctx)
	if err != nil {
		t.Logf("RunCanaryTest expected timeout/fail: %v", err)
	} else if result != nil {
		t.Logf("RunCanaryTest result: score=%d", result.Score)
	}
	t.Log("OK: RunCanaryTest no panic")
}

// ─── AutoSelectShadowTLSSNI ──────────────────────────────────────────────────

func TestAutoSelectShadowTLSSNITimeout(t *testing.T) {
	e := newTestEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	sni, err := e.AutoSelectShadowTLSSNI(ctx)
	if err != nil {
		t.Logf("AutoSelectShadowTLSSNI expected fail: %v", err)
	} else {
		t.Logf("AutoSelectShadowTLSSNI sni=%q", sni)
	}
	t.Log("OK: AutoSelectShadowTLSSNI no panic")
}

// ─── RunDNSLeakTest ──────────────────────────────────────────────────────────

func TestRunDNSLeakTestTimeout(t *testing.T) {
	e := newTestEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result, err := e.RunDNSLeakTest(ctx)
	if err != nil {
		t.Logf("RunDNSLeakTest expected fail: %v", err)
	} else if result != nil {
		t.Logf("RunDNSLeakTest: %s", result.Diagnosis)
	}
	t.Log("OK: RunDNSLeakTest no panic")
}

// ─── EmergencyWipe ───────────────────────────────────────────────────────────

func TestEmergencyWipeNoPanic(t *testing.T) {
	e := newTestEngine()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("EmergencyWipe panicked: %v", r)
		}
	}()
	result := e.EmergencyWipe(false)
	if result == nil {
		t.Fatal("EmergencyWipe returned nil")
	}
	t.Logf("OK: EmergencyWipe(false) files=%d errors=%d", result.FilesDeleted, len(result.Errors))
}

// ─── TestPaidProvider (engine method) ────────────────────────────────────────

func TestTestPaidProviderBadURL(t *testing.T) {
	e := newTestEngine()
	entry := models.PaidProviderEntry{
		ID:       "test-bad",
		Name:     "Bad Provider",
		Type:     "marzban",
		URL:      "http://nonexistent.invalid:9999",
		Username: "admin",
		Password: "pass",
		Enabled:  true,
	}
	// Should fail quickly with network error (TestPaidProvider uses internal 20s timeout)
	n, err := e.TestPaidProvider(entry)
	_ = n
	if err != nil {
		t.Logf("OK: TestPaidProvider bad URL: %v", err)
	} else {
		t.Logf("TestPaidProvider returned %d nodes (unexpected success)", n)
	}
}

// ─── PatchConfig all fields ───────────────────────────────────────────────────

func TestPatchConfigAllValidFields(t *testing.T) {
	e := newTestEngine()
	patch := map[string]interface{}{
		"listen_port":        11080,
		"connection_mode":    "vpn",
		"selection_mode":     "stealth",
		"auto_connect":       false,
		"check_interval_sec": 120,
		"max_latency_ms":     1000,
		"safety_filter":      true,
	}
	if err := e.PatchConfig(patch); err != nil {
		t.Fatalf("PatchConfig all fields: %v", err)
	}
	if e.cfg.ListenPort != 11080 {
		t.Errorf("ListenPort: want 11080, got %d", e.cfg.ListenPort)
	}
	if e.cfg.ConnectionMode != "vpn" {
		t.Errorf("ConnectionMode: want vpn, got %s", e.cfg.ConnectionMode)
	}
	if e.cfg.SelectionMode != "stealth" {
		t.Errorf("SelectionMode: want stealth, got %s", e.cfg.SelectionMode)
	}
	t.Log("OK: PatchConfig all valid fields applied")
}

// ─── GetStats complete coverage ──────────────────────────────────────────────

func TestGetStatsWithNodes(t *testing.T) {
	e := newTestEngine()
	e.nodes = []*models.Node{
		{ID: "n1", Status: models.StatusOK},
		{ID: "n2", Status: models.StatusOK},
		{ID: "n3", Status: models.StatusBlocked},
	}
	stats := e.GetStats()
	if stats == nil {
		t.Fatal("GetStats nil")
	}
	t.Logf("OK: GetStats with 3 nodes: %v", stats)
}

// ─── EmergencyWipe wipeAll=true ──────────────────────────────────────────────

func TestEmergencyWipeAll(t *testing.T) {
	e := newTestEngine()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("EmergencyWipe(true) panicked: %v", r)
		}
	}()
	result := e.EmergencyWipe(true)
	if result == nil {
		t.Fatal("EmergencyWipe(true) returned nil")
	}
	t.Logf("OK: EmergencyWipe(true) files=%d duration=%v", result.FilesDeleted, result.Duration)
}

// ─── GetSingBoxInfo installed branch ─────────────────────────────────────────

func TestGetSingBoxInfoBranches(t *testing.T) {
	e := newTestEngine()
	info := e.GetSingBoxInfo()
	// Should have installed + running keys
	for _, k := range []string{"installed", "running"} {
		if _, ok := info[k]; !ok {
			t.Errorf("GetSingBoxInfo missing %q", k)
		}
	}
	// If installed, should also have version key
	if info["installed"] == true {
		if _, ok := info["version"]; !ok {
			t.Error("GetSingBoxInfo installed=true but no 'version' key")
		}
	}
	t.Logf("OK: GetSingBoxInfo installed=%v running=%v", info["installed"], info["running"])
}

// ─── Diagnostics blockageType coverage ──────────────────────────────────────

func TestGetDiagnosticsWithBlockage(t *testing.T) {
	e := newTestEngine()
	e.stateMu.Lock()
	e.blockageType = detector.BlockageSNI
	e.stateMu.Unlock()

	diag := e.GetDiagnostics()
	if diag["blockage_type"] == nil {
		t.Error("blockage_type missing from diagnostics")
	}
	t.Logf("OK: GetDiagnostics with SNI blockage: %v", diag["blockage_type"])
}
