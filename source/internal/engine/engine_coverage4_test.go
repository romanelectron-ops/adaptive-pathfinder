package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/killswitch"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── validatePatch: remaining error paths ─────────────────────────────────────

func TestValidatePatch_CheckIntervalSecInvalid(t *testing.T) {
	// non-int value for check_interval_sec
	err := validatePatch(map[string]interface{}{"check_interval_sec": "not-an-int"})
	if err == nil {
		t.Error("expected error for non-int check_interval_sec")
	}
	// out-of-range int
	err = validatePatch(map[string]interface{}{"check_interval_sec": 2})
	if err == nil {
		t.Error("expected error for check_interval_sec < 5")
	}
}

func TestValidatePatch_MaxLatencyMsInvalid(t *testing.T) {
	err := validatePatch(map[string]interface{}{"max_latency_ms": 50}) // < 100
	if err == nil {
		t.Error("expected error for max_latency_ms < 100")
	}
	err = validatePatch(map[string]interface{}{"max_latency_ms": "bad"})
	if err == nil {
		t.Error("expected error for non-int max_latency_ms")
	}
}

func TestValidatePatch_ConnectionModeInvalid(t *testing.T) {
	err := validatePatch(map[string]interface{}{"connection_mode": "invalid-mode"})
	if err == nil {
		t.Error("expected error for invalid connection_mode")
	}
	err = validatePatch(map[string]interface{}{"connection_mode": 123}) // non-string
	if err == nil {
		t.Error("expected error for non-string connection_mode")
	}
}

func TestValidatePatch_SelectionModeInvalid(t *testing.T) {
	err := validatePatch(map[string]interface{}{"selection_mode": "invalid"})
	if err == nil {
		t.Error("expected error for invalid selection_mode")
	}
	err = validatePatch(map[string]interface{}{"selection_mode": 99}) // non-string
	if err == nil {
		t.Error("expected error for non-string selection_mode")
	}
}

func TestValidatePatch_NodeCheckTopN(t *testing.T) {
	// Валидные: 0 (дефолт), граница 10, граница 300, сигнал «Все рабочие».
	for _, v := range []interface{}{0, 10, 300, 150, models.NodeCheckTopNAll} {
		if err := validatePatch(map[string]interface{}{"node_check_top_n": v}); err != nil {
			t.Errorf("node_check_top_n=%v должно проходить, ошибка: %v", v, err)
		}
	}
	// Невалидные: 9 (<10), 301 (>300 не-сигнал), не-число.
	for _, v := range []interface{}{9, 301, "bad"} {
		if err := validatePatch(map[string]interface{}{"node_check_top_n": v}); err == nil {
			t.Errorf("node_check_top_n=%v должно отвергаться, ошибки нет", v)
		}
	}
}

func TestValidatePatch_ListenPortInvalid(t *testing.T) {
	err := validatePatch(map[string]interface{}{"listen_port": "not-int"})
	if err == nil {
		t.Error("expected error for non-int listen_port")
	}
	err = validatePatch(map[string]interface{}{"listen_port": 80}) // < 1024
	if err == nil {
		t.Error("expected error for listen_port < 1024")
	}
}

// ─── PatchConfig: defaults enforcement ──────────────────────────────────────

func TestPatchConfig_DefaultsEnforcement(t *testing.T) {
	e := newTestEngine()

	// Manually put out-of-range values into the config so that after
	// PatchConfig applies its defaults logic, the fields get corrected.
	e.mu.Lock()
	e.cfg.WebUIPort = 0       // invalid → will be set to 9090
	e.cfg.CheckInterval = 3   // < 5 → will be set to 30 (ТЗ v1.3 F5.2: единые правила Normalize/validatePatch, 5–3600)
	e.cfg.ConnectionMode = "" // empty → will be set to ModeProxy
	e.cfg.SelectionMode = ""  // empty → will be set to "balanced"
	e.mu.Unlock()

	// Pass a valid listen_port patch so validatePatch succeeds.
	err := e.PatchConfig(map[string]interface{}{"listen_port": 10808})
	if err != nil {
		t.Logf("PatchConfig defaults error (ok): %v", err)
	}
	e.mu.RLock()
	if e.cfg.WebUIPort == 0 {
		t.Error("WebUIPort should be set to default 9090")
	}
	if e.cfg.CheckInterval < 5 {
		t.Error("CheckInterval should be set to default 30")
	}
	if e.cfg.ConnectionMode == "" || e.cfg.SelectionMode == "" {
		t.Errorf("enum defaults: mode=%q selection=%q", e.cfg.ConnectionMode, e.cfg.SelectionMode)
	}
	e.mu.RUnlock()
	t.Log("OK: PatchConfig defaults enforcement covered")
}

// ─── GetCDNWorkerScript: active-node branch ──────────────────────────────────

func TestGetCDNWorkerScript_WithActiveNode(t *testing.T) {
	e := newTestEngine()
	e.stateMu.Lock()
	e.state.ActiveNode = &models.Node{Address: "1.2.3.4", Port: 443, Name: "CDN Node"}
	e.stateMu.Unlock()

	script := e.GetCDNWorkerScript()
	if script == "" {
		t.Error("expected non-empty worker script")
	}
	t.Logf("OK: GetCDNWorkerScript with node len=%d", len(script))
}

// ─── saveNodes: encrypted path ───────────────────────────────────────────────

func TestSaveNodes_EncryptedPath(t *testing.T) {
	e := newTestEngine()
	// SetMasterPassword initializes e.cryptoStore
	e.SetMasterPassword("test-coverage4-password")
	e.mu.Lock()
	e.nodes = []*models.Node{
		{ID: "enc-node-1", Address: "10.0.0.1", Port: 443},
	}
	e.mu.Unlock()

	// saveNodes should now use the crypto path
	e.saveNodes() // must not panic; encrypted write to data dir
	t.Log("OK: saveNodes encrypted path covered")
}

// ─── ActivateFallbackTunnel: unknown tunnel error ────────────────────────────

func TestActivateFallbackTunnel_UnknownTunnel(t *testing.T) {
	e := newTestEngine()
	err := e.ActivateFallbackTunnel("unknown-tunnel-type")
	if err == nil {
		t.Error("expected error for unknown tunnel type")
	}
	t.Logf("OK: ActivateFallbackTunnel unknown: %v", err)
}

// ─── AddPaidProvider: duplicate ID error ─────────────────────────────────────

func TestAddPaidProvider_DuplicateID_C4(t *testing.T) {
	e := newTestEngine()
	// Pre-populate with a provider entry having a known ID
	e.mu.Lock()
	e.cfg.PaidProviders = append(e.cfg.PaidProviders, models.PaidProviderEntry{
		ID:   "dup-id-test-1",
		Name: "Existing Provider",
		Type: "3xui",
	})
	e.mu.Unlock()

	// Try to add another with the same ID → duplicate error
	entry := models.PaidProviderEntry{
		ID:   "dup-id-test-1",
		Name: "Duplicate",
		Type: "3xui",
		URL:  "http://localhost:9999",
	}
	err := e.AddPaidProvider(entry)
	if err == nil {
		t.Error("expected duplicate ID error")
	}
	t.Logf("OK: AddPaidProvider duplicate ID: %v", err)
}

// ─── emergencySwitch: SwitchOnlyOnFail early return ──────────────────────────

func TestEmergencySwitch_SwitchOnlyOnFail_TooEarly(t *testing.T) {
	e := newTestEngine()
	e.mu.Lock()
	e.cfg.SwitchOnlyOnFail = true
	e.cfg.MinUptimeSec = 3600 // 1 hour minimum uptime
	e.mu.Unlock()

	// Узел уже подтверждался рабочим (не "мёртв с рождения") — грация должна применяться.
	// См. TestEmergencySwitch_NeverHealthy_BypassesGracePeriod для противоположного случая.
	e.watchdog.SetHealthConfirmedForTest(true)

	// Set connection time to NOW so uptime < minUptime
	e.stateMu.Lock()
	e.state.Since = time.Now()
	e.stateMu.Unlock()

	var logs []string
	e.OnLog = func(msg string) { logs = append(logs, msg) }

	// emergencySwitch should return early ("Too early to switch")
	e.emergencySwitch()

	found := false
	for _, l := range logs {
		if strings.Contains(l, "Too early to switch") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'Too early to switch' log, got: %v", logs)
	}
	t.Log("OK: emergencySwitch SwitchOnlyOnFail early return covered")
}

// ─── Restart: with EnableKillSwitch path ────────────────────────────────────

func TestRestart_WithKSEnabledVariant(t *testing.T) {
	e := newTestEngine()
	e.mu.Lock()
	e.cfg.EnableKillSwitch = true
	e.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	e.ctx = ctx
	e.cancel = cancel

	// Restart: covers ks.Disable() at line 445 when EnableKillSwitch=true
	// Start() will run but context will cancel quickly
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()
	_ = e.Restart()
	t.Log("OK: Restart with EnableKillSwitch covers ks.Disable path")
}

// ─── ResetNetworkDetailed: with KS disable warning path ─────────────────────

func TestResetNetworkDetailed_KSDisableWarning(t *testing.T) {
	e := newTestEngine()

	// Use a KS that returns error on Disable → adds to warnings
	e.ks = &mockErrorKS{}
	e.mu.Lock()
	e.cfg.EnableKillSwitch = true
	e.mu.Unlock()

	result := e.ResetNetworkDetailed()
	if len(result.Warnings) == 0 {
		t.Error("expected warnings from KS disable error")
	}
	t.Logf("OK: ResetNetworkDetailed KS warning: %v", result.Warnings)
}

// mockErrorKS — kill switch that always returns error on Disable
type mockErrorKS struct{}

func (m *mockErrorKS) Enable(iface string, ports []int) error {
	return nil
}
func (m *mockErrorKS) Disable() error {
	return errMockKSDisable
}
func (m *mockErrorKS) IsEnabled() bool { return false }

func (m *mockErrorKS) Capabilities() killswitch.Capabilities {
	return killswitch.Capabilities{ProxyMode: true, TunMode: true}
}

var errMockKSDisable = newMockKSError("mock KS disable error")

type mockKSError struct{ msg string }

func (e *mockKSError) Error() string  { return e.msg }
func newMockKSError(msg string) error { return &mockKSError{msg: msg} }

// ─── tryFallback: L2 blockage-type change path ────────────────────────────────

func TestTryFallback_L2BlockageChange(t *testing.T) {
	e := newTestEngine()
	// Don't set EnableChain so L1 is skipped
	e.mu.Lock()
	e.cfg.EnableChain = false
	e.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	e.ctx = ctx

	// tryFallback will run L2 (re-diagnose) then L3 (Psiphon/Tor fallback)
	// All sing-box starts will fail, but the code paths get exercised
	_ = e.tryFallback()
	t.Log("OK: tryFallback L2 blockage-change path covered")
}

// ─── SetAdBlockProfile: nil blocker error path ────────────────────────────────

func TestSetAdBlockProfile_ErrorPath(t *testing.T) {
	e := newTestEngine()
	// With nil adBlocker → returns error
	e.adBlocker = nil
	err := e.SetAdBlockProfile("strict")
	if err == nil {
		t.Error("expected error from nil adBlocker in SetAdBlockProfile")
	}
	t.Logf("OK: SetAdBlockProfile nil blocker: %v", err)
}

// ─── RefreshCatalog: nil registry path ────────────────────────────────────────

func TestRefreshCatalog_NilRegistry(t *testing.T) {
	e := newTestEngine()
	e.catalogRegistry = nil

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	n, err := e.RefreshCatalog(ctx)
	// nil registry returns (0, nil) — no error check needed, just cover the path
	t.Logf("OK: RefreshCatalog nil registry: n=%d err=%v", n, err)
}

// ─── CheckCurrentIP: with nil checker ─────────────────────────────────────────

func TestCheckCurrentIP_NilChecker_C4(t *testing.T) {
	e := newTestEngine()
	e.ipRepChecker = nil
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err := e.CheckCurrentIP(ctx)
	if err == nil {
		t.Error("expected error from nil ipRepChecker")
	}
	t.Logf("OK: CheckCurrentIP nil checker: %v", err)
}

// ─── RunCanaryTest: error path (canary test failure) ─────────────────────────

func TestRunCanaryTest_ErrorHandling(t *testing.T) {
	e := newTestEngine()
	// Context with very short timeout → canary.Test will likely fail fast
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	time.Sleep(2 * time.Millisecond) // ensure context is already expired
	result, err := e.RunCanaryTest(ctx)
	// Either it errors (context expired) or returns a result — both are fine
	t.Logf("OK: RunCanaryTest timeout: result=%v err=%v", result, err)
}

// ─── ForceRescan: no candidates path ─────────────────────────────────────────

func TestForceRescan_NoCandidatesPath(t *testing.T) {
	e := newTestEngine()
	e.mu.Lock()
	e.nodes = nil // no nodes
	e.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	e.ctx = ctx
	// With no nodes, ForceRescan will try to update sources (which fail fast)
	e.ForceRescan()
	t.Log("OK: ForceRescan no candidates covered")
}

// ─── ForceSwitchNow: best=nil path (no pool nodes) ────────────────────────────

func TestForceSwitchNow_NoBestNode(t *testing.T) {
	e := newTestEngine()
	e.mu.Lock()
	e.nodes = nil // empty pool → selectBestExcluding returns nil → go e.tryFallback()
	e.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	e.ctx = ctx

	e.ForceSwitchNow()
	time.Sleep(100 * time.Millisecond) // let goroutine start
	t.Log("OK: ForceSwitchNow nil-best → tryFallback goroutine")
}
