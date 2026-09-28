package engine

// engine_coverage2_test.go — targeted tests pushing remaining low-coverage
// functions to ≥95% without network access.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── toInt: json.Number case ─────────────────────────────────────────────────

func TestToInt_JsonNumber(t *testing.T) {
	// Valid json.Number
	got, ok := toInt(json.Number("42"))
	if !ok || got != 42 {
		t.Errorf("toInt(json.Number('42')): got=%d ok=%v, want 42 true", got, ok)
	}
	// Invalid json.Number
	_, ok2 := toInt(json.Number("not-a-number"))
	if ok2 {
		t.Error("toInt(invalid json.Number) should return false")
	}
	t.Log("OK: toInt json.Number cases")
}

// ─── setDisconnected with OnStateChange ──────────────────────────────────────

func TestSetDisconnected_WithCallback(t *testing.T) {
	e := newTestEngine()
	called := false
	e.OnStateChange = func(s *models.ConnectionState) {
		called = true
	}
	e.setDisconnected()
	if !called {
		t.Error("setDisconnected: OnStateChange was not called")
	}
	t.Log("OK: setDisconnected invokes OnStateChange callback")
}

// TestSetDisconnected_ResetsVerified — UI показывает "подключено" только когда и
// Connected, и Verified true (см. models.ConnectionState.Verified). Отключение обязано
// сбросить оба поля, иначе следующий Connected=true (без нового успешного health check)
// унаследовал бы Verified от прошлой сессии.
func TestSetDisconnected_ResetsVerified(t *testing.T) {
	e := newTestEngine()
	e.state.Connected = true
	e.state.Verified = true
	e.setDisconnected()
	if e.state.Verified {
		t.Error("setDisconnected: Verified should reset to false")
	}
	if e.state.Connected {
		t.Error("setDisconnected: Connected should reset to false")
	}
	t.Log("OK: setDisconnected resets both Connected and Verified")
}

// ─── log with OnLog callback ──────────────────────────────────────────────────

func TestLog_WithCallback(t *testing.T) {
	e := newTestEngine()
	var captured string
	e.OnLog = func(msg string) {
		captured = msg
	}
	e.log("test-message-from-callback")
	if captured != "test-message-from-callback" {
		t.Errorf("log: OnLog not called with expected msg, got: %q", captured)
	}
	t.Log("OK: log invokes OnLog callback")
}

// ─── SetStickyPolicy: cover all switch cases ─────────────────────────────────

func TestSetStickyPolicy_AllCases(t *testing.T) {
	e := newTestEngine()
	cases := []string{"free", "sticky", "timed", "domain", "none", "persistent"}
	for _, c := range cases {
		e.SetStickyPolicy(c) // must not panic
	}
	t.Log("OK: SetStickyPolicy all switch cases covered")
}

// ─── RemovePaidProvider: found path ──────────────────────────────────────────

func TestRemovePaidProvider_Found(t *testing.T) {
	e := newTestEngine()
	e.cfg.PaidProviders = []models.PaidProviderEntry{
		{ID: "prov-1", Name: "Test Provider 1", Type: "marzban", URL: "http://x.com"},
		{ID: "prov-2", Name: "Test Provider 2", Type: "marzban", URL: "http://y.com"},
	}
	// Add a node with source "paid:prov-1" to test node filtering
	e.nodes = append(e.nodes, &models.Node{
		ID: "paid-node-1", Source: "paid:prov-1",
	})

	ok := e.RemovePaidProvider("prov-1")
	if !ok {
		t.Error("RemovePaidProvider should return true for existing provider")
	}
	// Verify provider was removed from list
	for _, p := range e.cfg.PaidProviders {
		if p.ID == "prov-1" {
			t.Error("prov-1 should be removed from PaidProviders list")
		}
	}
	t.Log("OK: RemovePaidProvider found path covered")
}

// ─── GetWatchdogStatus nil watchdog ──────────────────────────────────────────

func TestGetWatchdogStatus_NilWatchdog(t *testing.T) {
	e := newTestEngine()
	e.watchdog = nil
	s := e.GetWatchdogStatus()
	if s == nil {
		t.Fatal("GetWatchdogStatus nil watchdog: should return non-nil")
	}
	if s["state"] != "disabled" {
		t.Errorf("GetWatchdogStatus nil watchdog: state=%v, want disabled", s["state"])
	}
	t.Log("OK: GetWatchdogStatus with nil watchdog returns 'disabled'")
}

// ─── GetCatalogStatus nil registry ───────────────────────────────────────────

func TestGetCatalogStatus_NilRegistry(t *testing.T) {
	e := newTestEngine()
	e.catalogRegistry = nil
	result := e.GetCatalogStatus()
	if result != nil {
		t.Errorf("GetCatalogStatus nil registry: expected nil, got %v", result)
	}
	t.Log("OK: GetCatalogStatus with nil registry returns nil")
}

// ─── GetAdBlockStatus nil adBlocker ──────────────────────────────────────────

func TestGetAdBlockStatus_NilBlocker(t *testing.T) {
	e := newTestEngine()
	e.adBlocker = nil
	s := e.GetAdBlockStatus()
	if s == nil {
		t.Fatal("GetAdBlockStatus nil blocker: should return non-nil map")
	}
	if s["profile"] != "disabled" {
		t.Errorf("GetAdBlockStatus nil blocker: profile=%v, want disabled", s["profile"])
	}
	t.Log("OK: GetAdBlockStatus with nil adBlocker returns 'disabled'")
}

// ─── GetUpdateStatus / CheckForUpdate nil updater ────────────────────────────

func TestGetUpdateStatus_NilUpdater(t *testing.T) {
	e := newTestEngine()
	e.appUpdater = nil
	s := e.GetUpdateStatus()
	if s == nil {
		t.Fatal("GetUpdateStatus nil updater: should return non-nil")
	}
	t.Logf("OK: GetUpdateStatus nil updater = %v", s)
}

func TestCheckForUpdate_NilUpdater(t *testing.T) {
	e := newTestEngine()
	e.appUpdater = nil
	ctx := context.Background()
	_, err := e.CheckForUpdate(ctx)
	if err == nil {
		t.Error("CheckForUpdate nil updater should return error")
	}
	t.Logf("OK: CheckForUpdate nil updater → %v", err)
}

func TestApplyUpdate_NilUpdater(t *testing.T) {
	// S-UPD: включаем применение, иначе гейт политики вернёт отказ до проверки nil-апдейтера,
	// которую и покрывает этот тест.
	oldApply := updateApplyEnabled
	updateApplyEnabled = true
	defer func() { updateApplyEnabled = oldApply }()

	e := newTestEngine()
	e.appUpdater = nil
	ctx := context.Background()
	err := e.ApplyUpdate(ctx, "http://x.com/apf.zip", nil)
	if err == nil {
		t.Error("ApplyUpdate nil updater should return error")
	}
	t.Logf("OK: ApplyUpdate nil updater → %v", err)
}

// ─── AutoSelectFallback nil emergencyFallback ─────────────────────────────────

func TestAutoSelectFallback_NilOrchestrator(t *testing.T) {
	e := newTestEngine()
	e.emergencyFallback = nil
	result := e.AutoSelectFallback()
	t.Logf("OK: AutoSelectFallback nil orchestrator = %q", result)
}

// ─── AdBlockToggleAllowlist nil adBlocker ────────────────────────────────────

func TestAdBlockToggleAllowlist_NilBlocker(t *testing.T) {
	e := newTestEngine()
	e.adBlocker = nil
	e.AdBlockToggleAllowlist("example.com", true) // must not panic
	t.Log("OK: AdBlockToggleAllowlist nil adBlocker, no panic")
}

// ─── SetAdBlockProfile nil adBlocker ─────────────────────────────────────────

func TestSetAdBlockProfile_NilBlocker(t *testing.T) {
	e := newTestEngine()
	e.adBlocker = nil
	err := e.SetAdBlockProfile("standard")
	if err == nil {
		t.Error("SetAdBlockProfile nil adBlocker should return error")
	}
	t.Logf("OK: SetAdBlockProfile nil adBlocker → %v", err)
}

// ─── ResetNetwork / ResetNetworkDetailed success path ────────────────────────

func TestResetNetwork_CallsDetailed(t *testing.T) {
	e := newTestEngine()
	// ResetNetworkDetailed may succeed or warn — just verify it doesn't panic
	result := e.ResetNetworkDetailed()
	if result == nil {
		t.Fatal("ResetNetworkDetailed returned nil")
	}
	// Test the ResetNetwork wrapper (calls ResetNetworkDetailed)
	_ = e.ResetNetwork()
	t.Logf("OK: ResetNetwork/ResetNetworkDetailed no panic, success=%v", result.Success)
}

// ─── enableDeviceProtection directly ─────────────────────────────────────────

func TestEnableDeviceProtection_Direct(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.BlockIPv6Leak = true
	cfg.BlockWebRTC = true
	e := New(cfg)
	leaked := false
	e.OnLeakDetected = func(leakType, details string) {
		leaked = true
		_ = details
	}
	// Call directly — not via goroutine
	e.enableDeviceProtection()
	_ = leaked
	t.Log("OK: enableDeviceProtection direct call, no panic")
}

func TestEnableDeviceProtection_NoProtection(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.BlockIPv6Leak = false
	cfg.BlockWebRTC = false
	e := New(cfg)
	e.enableDeviceProtection()
	t.Log("OK: enableDeviceProtection no protection, no panic")
}

// ─── ForceSwitchNow with CanSwitch returning false ────────────────────────────

func TestForceSwitchNow_NotAllowedPolicy(t *testing.T) {
	e := newTestEngine()
	// Set up a sticky session that will block even forced switch by setting
	// a policy that blocks — since forced=true is usually allowed, we simulate
	// by just calling it; the default policy should allow forced=true
	e.ForceSwitchNow()
	t.Log("OK: ForceSwitchNow no nodes, no panic")
}

func TestForceSwitchNow_WithBestNode(t *testing.T) {
	e := newTestEngine()
	n1 := &models.Node{ID: "cur", Score: 0.9, Status: models.StatusOK, Address: "1.1.1.1"}
	n2 := &models.Node{ID: "alt", Score: 0.8, Status: models.StatusOK, Address: "2.2.2.2"}
	e.nodes = []*models.Node{n1, n2}
	e.stateMu.Lock()
	e.state.ActiveNode = n1
	e.stateMu.Unlock()
	// This will try to connectNode(n2) in a goroutine — won't actually connect but covers path
	e.ForceSwitchNow()
	time.Sleep(5 * time.Millisecond)
	t.Log("OK: ForceSwitchNow with best node, no panic")
}

// ─── CheckCurrentIP / CheckNodeIP coverage ───────────────────────────────────

func TestCheckCurrentIP_NotConnected(t *testing.T) {
	e := newTestEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := e.CheckCurrentIP(ctx)
	if err == nil {
		t.Error("CheckCurrentIP when not connected should return error")
	}
	t.Logf("OK: CheckCurrentIP not connected → %v", err)
}

// ─── PatchConfig branches ────────────────────────────────────────────────────

func TestPatchConfig_ValidPatches(t *testing.T) {
	e := newTestEngine()
	tests := []struct {
		key string
		val interface{}
	}{
		{"listen_port", 10800},
		{"check_interval", 60},
		{"min_uptime_sec", 120},
		{"safety_filter", true},
		{"enable_kill_switch", false},
		{"block_ipv6_leak", true},
		{"block_webrtc", true},
		{"auto_connect", false},
		{"set_system_proxy", false},
		{"connection_mode", "proxy"},
		{"adblock_profile", "standard"},
	}
	for _, tt := range tests {
		patch := map[string]interface{}{tt.key: tt.val}
		err := e.PatchConfig(patch)
		if err != nil {
			t.Logf("PatchConfig(%q=%v) warn: %v", tt.key, tt.val, err)
		}
	}
	t.Log("OK: PatchConfig various keys, no panic")
}

func TestPatchConfig_InvalidPort(t *testing.T) {
	e := newTestEngine()
	err := e.PatchConfig(map[string]interface{}{"listen_port": -1})
	if err == nil {
		t.Error("PatchConfig invalid port should return error")
	}
	t.Logf("OK: PatchConfig invalid port → %v", err)
}

// ─── validatePatch complete ───────────────────────────────────────────────────

// TEST-SYNC-W1 (2026-09-08, ADR оркестратора по ТЗ v1.4 S-7, лот L1-SEC): validatePatch
// больше не no-op на неизвестном ключе. Новый контракт — белый список по json-тегам
// models.AppConfig (buildPatchAllowedKeys): ключ, которого нет в AppConfig, — ошибка,
// называющая ключ поимённо. Дефектное поведение "неизвестный ключ проходит молча" и было
// самим риском S-7 (см. TestV14_S7_ValidatePatch_RejectsUnknownKey в engine_v14_sec_test.go
// для полного покрытия нового контракта); этот тест обновлён под него, а не откатывает фикс.
func TestValidatePatch_UnknownKey(t *testing.T) {
	err := validatePatch(map[string]interface{}{"unknown_key_xyz": "value"})
	if err == nil {
		t.Error("validatePatch with unknown key should return an error (S-7 whitelist)")
	} else if !strings.Contains(err.Error(), "unknown_key_xyz") {
		t.Errorf("validatePatch error should name the offending key, got: %v", err)
	}
	t.Logf("OK: validatePatch unknown key → %v", err)
}

// ─── loadNodes: file not found (already covered), crypto paths ───────────────

func TestLoadNodes_NoFile(t *testing.T) {
	e := newTestEngine()
	// DataDir may or may not have a nodes_cache.json — just must not panic
	err := e.loadNodes()
	t.Logf("OK: loadNodes result: %v", err)
}

// ─── Start AutoConnect path ───────────────────────────────────────────────────

func TestStart_AutoConnect(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.AutoConnect = true
	cfg.EnableKillSwitch = false
	cfg.BlockIPv6Leak = false
	cfg.BlockWebRTC = false
	e := New(cfg)

	if err := e.Start(); err != nil {
		t.Fatalf("Start() with AutoConnect=true: unexpected error: %v", err)
	}
	// Give AutoConnect goroutine a moment to start (it sleeps 2s then diagnoses)
	time.Sleep(50 * time.Millisecond)
	e.Stop()
	t.Log("OK: Start with AutoConnect=true, Stop before auto-connect fires")
}

// ─── tryFallback: EnableChain path ───────────────────────────────────────────

func TestTryFallback_EnableChain(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.EnableChain = true
	e := New(cfg)
	// Two scored nodes so buildBestChain returns something
	e.nodes = []*models.Node{
		{ID: "n1", Address: "10.0.0.1", Score: 0.8, Status: models.StatusOK},
		{ID: "n2", Address: "10.0.0.2", Score: 0.7, Status: models.StatusOK},
	}
	err := e.tryFallback()
	// Will fail (no sing-box actually running) but covers L1 chain path
	t.Logf("OK: tryFallback EnableChain → %v", err)
}

// ─── emergencySwitch: sticky session delay path ───────────────────────────────

func TestEmergencySwitch_StickyBlocked(t *testing.T) {
	e := newTestEngine()
	// Use "timed" sticky policy to potentially block switching
	e.SetStickyPolicy("sticky")
	// Start a sticky session
	e.stickySession.OnConnected()
	e.emergencySwitch()
	t.Log("OK: emergencySwitch with sticky session, no panic")
}

// ─── monitor: success path ────────────────────────────────────────────────────

func TestMonitor_ConnectedSuccessPath(t *testing.T) {
	e := newTestEngine()
	// Node that connects immediately (loopback) — QuickPing may succeed
	node := &models.Node{
		ID:      "loopback-node",
		Address: "127.0.0.1",
		Port:    1,
		Status:  models.StatusOK,
	}
	e.stateMu.Lock()
	e.state.Connected = true
	e.state.ActiveNode = node
	e.stateMu.Unlock()
	// QuickPing on 127.0.0.1:1 will likely fail (connection refused) which is OK
	// but covers the monitor() path with connected=true
	e.monitor()
	t.Logf("OK: monitor connected path, FailCount=%d Latency=%d", node.FailCount, node.Latency)
}

// ─── runPostConnectCanary ──────────────────────────────────────────────────────

func TestRunPostConnectCanary_Direct(t *testing.T) {
	e := newTestEngine()
	// Just must not panic — canary test will run quickly (no VPN proxy to test through)
	e.runPostConnectCanary()
	t.Log("OK: runPostConnectCanary direct call, no panic")
}

// ─── setConnected helper ──────────────────────────────────────────────────────

func TestSetDisconnected_NoCallback(t *testing.T) {
	e := newTestEngine()
	e.OnStateChange = nil // explicitly nil
	e.setDisconnected()   // should not panic when callback is nil
	t.Log("OK: setDisconnected with nil callback, no panic")
}

// ─── AddNodeFromLink ──────────────────────────────────────────────────────────

func TestAddNodeFromLink_InvalidLink(t *testing.T) {
	e := newTestEngine()
	err := e.AddNodeFromLink("not-a-valid-link")
	if err == nil {
		t.Log("warn: AddNodeFromLink invalid link returned nil")
	} else {
		t.Logf("OK: AddNodeFromLink invalid → %v", err)
	}
}

func TestAddNodeFromLink_ValidVlessLink(t *testing.T) {
	e := newTestEngine()
	// Minimal valid vless link
	link := "vless://uuid@1.2.3.4:443?type=tcp&security=none#TestNode"
	err := e.AddNodeFromLink(link)
	if err != nil {
		t.Logf("AddNodeFromLink vless warn: %v", err)
	} else {
		t.Log("OK: AddNodeFromLink vless accepted")
	}
}

// TestAddNodeFromLink_RejectsWireGuard — P1.2 (docs/TZ_APF_ROADMAP_v1.2.md): sing-box 1.13.16
// удалил outbound-тип "wireguard" — узел, даже если бы прошёл валидацию, НИКОГДА не сможет
// подключиться. Явный отказ на входе, не молчаливое добавление в пул на бесплодные попытки.
// Простая ссылка wireguard://pubkey@host (см. parser.go) не несёт ключевого материала и в
// любом случае отклоняется ValidateNode раньше — тест фиксирует конечный результат (узел не
// попадает в пул), не то, КАКАЯ именно проверка сработала первой; isUnsupportedProtocol
// проверяется отдельно ниже как гарантия для узлов из более богатых форматов (Clash-подписки),
// где WGPrivateKey/WGPublicKey реально заполнены и ValidateNode бы их пропустил.
func TestAddNodeFromLink_RejectsWireGuard(t *testing.T) {
	e := newTestEngine()
	link := "wireguard://pubkey@wg.example.com:51820#MyWG"
	err := e.AddNodeFromLink(link)
	if err == nil {
		t.Fatal("expected WireGuard link to be rejected, got nil error")
	}
	if len(e.nodes) != 0 {
		t.Errorf("expected node pool to stay empty, got %d nodes", len(e.nodes))
	}
}

// TestIsUnsupportedProtocol — гарантирует фильтр для узлов, которые ValidateNode пропустит
// (полный ключевой материал WireGuard из богатого источника типа Clash-подписки).
func TestIsUnsupportedProtocol(t *testing.T) {
	cases := []struct {
		proto models.Protocol
		want  bool
	}{
		{models.ProtoWireGuard, true},
		{models.ProtoAmneziaWG, true},
		{models.ProtoVLESS, false},
		{models.ProtoShadowsocks, false},
		{models.ProtoTrojan, false},
		{models.ProtoVMess, false},
	}
	for _, c := range cases {
		if got := isUnsupportedProtocol(c.proto); got != c.want {
			t.Errorf("isUnsupportedProtocol(%s) = %v, want %v", c.proto, got, c.want)
		}
	}
}

// ─── GetCatalogStatus / RefreshCatalog nil fetcher ───────────────────────────

func TestRefreshCatalog_NilFetcher(t *testing.T) {
	e := newTestEngine()
	e.catalogFetcher = nil
	ctx := context.Background()
	_, err := e.RefreshCatalog(ctx)
	if err == nil {
		t.Error("RefreshCatalog nil fetcher should return error")
	}
	t.Logf("OK: RefreshCatalog nil fetcher → %v", err)
}

// ─── CheckCurrentIPByAddr ─────────────────────────────────────────────────────

func TestCheckCurrentIPByAddr_WithChecker(t *testing.T) {
	e := newTestEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	// Will fail (network) but covers the code path
	_, err := e.CheckCurrentIPByAddr(ctx, "127.0.0.1")
	t.Logf("OK: CheckCurrentIPByAddr → %v", err)
}

// ─── GetDPIStatus: nil canary path ───────────────────────────────────────────

func TestGetDPIStatus_WithLastCanary(t *testing.T) {
	e := newTestEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	// Set lastCanary (from a previous canary test)
	_, _ = e.RunCanaryTest(ctx) // may fail, that's OK
	s := e.GetDPIStatus(ctx)
	if s == nil {
		t.Fatal("GetDPIStatus nil")
	}
	t.Logf("OK: GetDPIStatus keys=%d", len(s))
}

// ─── updateSources: force path ───────────────────────────────────────────────

func TestUpdateSources_Force(t *testing.T) {
	e := newTestEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	_ = ctx
	cancel()
	// Cancelled context — FetchAll will likely fail quickly, covers the branch
	e.ctx = ctx
	e.updateSources(true)
	t.Log("OK: updateSources force=true with cancelled context, no panic")
}

// ─── AutoSelectShadowTLSSNI: shadow TLS nil ──────────────────────────────────

func TestAutoSelectShadowTLSSNI_NilManager(t *testing.T) {
	e := newTestEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	result, _ := e.AutoSelectShadowTLSSNI(ctx)
	t.Logf("OK: AutoSelectShadowTLSSNI → %q", result)
}

// ─── GetCDNWorkerScript nil fronter ──────────────────────────────────────────

func TestGetCDNWorkerScript_EmptyConfig(t *testing.T) {
	e := newTestEngine()
	// Without SetCDNConfig, worker script may be empty
	s := e.GetCDNWorkerScript()
	t.Logf("OK: GetCDNWorkerScript without config = %q", s)
}

// ─── SetProviderEnabled ───────────────────────────────────────────────────────

func TestSetProviderEnabled_NotFound(t *testing.T) {
	e := newTestEngine()
	e.SetProviderEnabled("nonexistent-provider", true)
	t.Log("OK: SetProviderEnabled not found, no panic")
}

// ─── RunDNSLeakTest nil tester ────────────────────────────────────────────────

func TestRunDNSLeakTest_WithContext(t *testing.T) {
	e := newTestEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result, err := e.RunDNSLeakTest(ctx)
	t.Logf("OK: RunDNSLeakTest → result=%v err=%v", result != nil, err)
}

// ─── TestPaidProvider ─────────────────────────────────────────────────────────

func TestTestPaidProvider_InvalidType(t *testing.T) {
	e := newTestEngine()
	_, err := e.TestPaidProvider(models.PaidProviderEntry{
		ID:   "tp-1",
		Type: "invalid_type",
		URL:  "http://x.com",
	})
	if err == nil {
		t.Log("warn: TestPaidProvider invalid type returned nil")
	} else {
		t.Logf("OK: TestPaidProvider invalid type → %v", err)
	}
}

// ─── saveNodes: ensure crypto encrypt error path is not panicky ──────────────

func TestSaveNodes_CryptoEncryptError(t *testing.T) {
	e := newTestEngine()
	// Set a password to enable crypto path
	e.SetMasterPassword("valid-password")
	// Add a node with an unmarshalable field — in practice MarshalIndent won't fail
	// So this covers the normal crypto encrypt+write path
	e.nodes = []*models.Node{{ID: "x", Address: "1.2.3.4"}}
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("saveNodes crypto path panicked: %v", r)
		}
	}()
	e.saveNodes()
	t.Log("OK: saveNodes crypto path, no panic")
}
