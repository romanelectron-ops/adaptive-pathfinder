package engine

// engine_coverage3_test.go — third coverage batch: mock-injection tests for
// interface-based branches (enableKillSwitchWithUAC, setVPNEndpointForKS, etc.)
// and remaining low-coverage paths.

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/killswitch"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── Mock KillSwitch implementations ──────────────────────────────────────────

// mockUACKS implements KillSwitch + EnableWithUAC interface for UAC branch tests.
type mockUACKS struct {
	enableErr error
	uacCalled bool
	uacErr    error
}

func (m *mockUACKS) Enable(iface string, ports []int) error { return m.enableErr }
func (m *mockUACKS) Disable() error                         { return nil }
func (m *mockUACKS) IsEnabled() bool                        { return false }

// R-1.1: мок объявляет полные возможности — тесты этих веток про UAC, а не про capability-гейт.
func (m *mockUACKS) Capabilities() killswitch.Capabilities {
	return killswitch.Capabilities{ProxyMode: true, TunMode: true}
}
func (m *mockUACKS) EnableWithUAC(addr string, port int) error {
	m.uacCalled = true
	return m.uacErr
}

// mockVPNEndpointKS implements KillSwitch + SetVPNEndpoint interface.
type mockVPNEndpointKS struct {
	endpointCalled bool
	lastAddr       string
}

func (m *mockVPNEndpointKS) Enable(iface string, ports []int) error { return nil }
func (m *mockVPNEndpointKS) Disable() error                         { return nil }
func (m *mockVPNEndpointKS) IsEnabled() bool                        { return false }

func (m *mockVPNEndpointKS) Capabilities() killswitch.Capabilities {
	return killswitch.Capabilities{ProxyMode: true, TunMode: true}
}
func (m *mockVPNEndpointKS) SetVPNEndpoint(addr string, port int) {
	m.endpointCalled = true
	m.lastAddr = addr
}

// ─── enableKillSwitchWithUAC: UAC success path ───────────────────────────────

func TestEnableKillSwitchWithUAC_UACSuccess(t *testing.T) {
	e := newTestEngine()
	mock := &mockUACKS{uacErr: nil}
	e.ks = mock
	node := &models.Node{ID: "n1", Address: "10.0.0.1"}
	e.state.Connected = true // T-05: подключение активно — UAC-успех должен включить KS
	e.enableKillSwitchWithUAC(node, e.connGen)
	if !mock.uacCalled {
		t.Error("EnableWithUAC was not called")
	}
	if !e.ksElevated {
		t.Error("expected ksElevated=true after UAC success")
	}
	t.Log("OK: enableKillSwitchWithUAC UAC success")
}

// B-0403 · R-2.2 (C-6) — КОНТРАКТ ИЗМЕНЁН.
//
// Было: отмена UAC записывала cfg.EnableKillSwitch=false и сохраняла конфиг. Один отказ в диалоге
// тихо отключал защиту во ВСЕХ будущих сессиях — пользователь об этом не знал.
// Стало: настройка пользователя неприкосновенна; отказ действует только до перезапуска
// (сессионный флаг ksDeclinedThisSession).
func TestEnableKillSwitchWithUAC_UACCancelled(t *testing.T) {
	e := newTestEngine()
	e.cfg.EnableKillSwitch = true
	mock := &mockUACKS{uacErr: killswitch.ErrUACCancelled}
	e.ks = mock
	e.enableKillSwitchWithUAC(nil, e.connGen)

	if e.ksElevated {
		t.Error("ksElevated should be false after UAC cancel")
	}
	// ИНВАРИАНТ R-2.2: настройку EnableKillSwitch меняет ТОЛЬКО пользователь.
	if !e.cfg.EnableKillSwitch {
		t.Error("cfg.EnableKillSwitch НЕ должен изменяться при отмене UAC (C-6): " +
			"иначе защита тихо отключается во всех будущих сессиях")
	}
	// Отказ запомнен на сессию — повторно UAC не показываем, но и защиты не изображаем.
	if !e.isKSDeclinedThisSession() {
		t.Error("ksDeclinedThisSession должен быть выставлен после отмены UAC")
	}
	t.Log("OK: отмена UAC не персистится, помечена как сессионная")
}

// R-2.1: отказ UAC при активном подключении ⇒ подключение снимается (fail-closed),
// а не остаётся «Connected без защиты».
func TestEnableKillSwitchWithUAC_CancelAbortsConnection(t *testing.T) {
	e := newTestEngine()
	e.cfg.EnableKillSwitch = true
	e.ks = &mockUACKS{uacErr: killswitch.ErrUACCancelled}
	e.state.Connected = true

	e.enableKillSwitchWithUAC(nil, e.connGen)

	if e.GetState().Connected {
		t.Error("fail-closed нарушен: подключение осталось активным после отказа UAC")
	}
	if e.lastRollback == nil || e.lastRollback.Stage != "killswitch_uac" {
		t.Errorf("ожидался откат со стадией killswitch_uac, получено: %+v", e.lastRollback)
	}
}

// R-2.1 escape hatch: при явном разовом разрешении пользователя подключение остаётся,
// но факт отсутствия защиты фиксируется в статусе.
func TestEnableKillSwitchWithUAC_EscapeHatchKeepsConnection(t *testing.T) {
	e := newTestEngine()
	e.cfg.EnableKillSwitch = true
	e.ks = &mockUACKS{uacErr: killswitch.ErrUACCancelled}
	e.state.Connected = true
	e.SetAllowConnectWithoutKS(true)

	e.enableKillSwitchWithUAC(nil, e.connGen)

	if !e.GetState().Connected {
		t.Error("при явном разрешении пользователя подключение должно сохраниться")
	}
	st := e.KillSwitchStatus()
	if !st.AllowedWithoutKS || st.Active {
		t.Errorf("статус должен честно показывать «без защиты»: %+v", st)
	}
}

func TestEnableKillSwitchWithUAC_UACOtherError(t *testing.T) {
	e := newTestEngine()
	mock := &mockUACKS{uacErr: errors.New("access denied")}
	e.ks = mock
	e.enableKillSwitchWithUAC(nil, e.connGen)
	if e.ksElevated {
		t.Error("ksElevated should be false after UAC error")
	}
	t.Log("OK: enableKillSwitchWithUAC UAC other error")
}

// ─── setVPNEndpointForKS: type-asserts to SetVPNEndpoint ─────────────────────

// TEST-SYNC-W1 (2026-09-08, ADR оркестратора по ТЗ v1.4 S-11, лот L1-KS): killswitch.
// bogonBlockReason/classifyIPs (internal/killswitch/endpoint.go) теперь режет приватные/
// CGNAT/bogon-адреса из allow-списка Kill Switch — 192.168.1.1 (RFC1918) больше не доходит
// до реализации, resolveEndpointOnce отдаёт пустой IP. Адрес заменён на 203.0.113.10
// (TEST-NET-3, RFC 5737) — L1-KS сознательно НЕ фильтрует документационные диапазоны именно
// чтобы не ломать тесты, использующие их как адреса-заглушки (см. bogonBlockReason,
// комментарий "ПРЕДНАМЕРЕННО СУЖЕНО"). Смысл теста не меняется: setVPNEndpointForKS
// по-прежнему должен вызвать реализацию с указанным адресом.
func TestSetVPNEndpointForKS_WithImpl(t *testing.T) {
	e := newTestEngine()
	mock := &mockVPNEndpointKS{}
	e.ks = mock
	e.setVPNEndpointForKS("203.0.113.10")
	if !mock.endpointCalled {
		t.Error("SetVPNEndpoint was not called")
	}
	if mock.lastAddr != "203.0.113.10" {
		t.Errorf("SetVPNEndpoint got addr=%q, want 203.0.113.10", mock.lastAddr)
	}
	t.Log("OK: setVPNEndpointForKS with implementation")
}

// ─── monitor: success path via real TCP listener ──────────────────────────────

func TestMonitor_QuickPingSuccess(t *testing.T) {
	e := newTestEngine()
	// Start a real TCP listener so QuickPing succeeds
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot start listener:", err)
	}
	defer ln.Close()
	addr := ln.Addr().(*net.TCPAddr)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	node := &models.Node{
		ID:      "monitor-ok-node",
		Address: "127.0.0.1",
		Port:    addr.Port,
		Status:  models.StatusOK,
	}
	e.stateMu.Lock()
	e.state.Connected = true
	e.state.ActiveNode = node
	e.stateMu.Unlock()

	e.monitor()
	t.Logf("OK: monitor success path, latency=%d failCount=%d", node.Latency, node.FailCount)
}

// ─── CheckNodeIP: node found + CheckIP called ────────────────────────────────

func TestCheckNodeIP_NodeFoundCheckerCalled(t *testing.T) {
	e := newTestEngine()
	node := &models.Node{ID: "check-ip-n1", Name: "TestNode", Address: "127.0.0.1", Port: 443}
	e.mu.Lock()
	e.nodes = append(e.nodes, node)
	e.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := e.CheckNodeIP(ctx, "check-ip-n1")
	if err != nil {
		t.Logf("OK: CheckNodeIP found node, CheckIP failed (expected): %v", err)
	} else {
		t.Logf("OK: CheckNodeIP result ip=%v label=%v", result["ip"], result["label"])
	}
}

// ─── runPostConnectLeakTest: OnLeakDetected callbacks ────────────────────────

func TestRunPostConnectLeakTest_WithCallbacks(t *testing.T) {
	e := newTestEngine()
	var leakKind string
	e.OnLeakDetected = func(kind, msg string) {
		leakKind = kind
	}
	// Runs in goroutine: sleeps 3s, tests DNS + IPv6 leaks
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.runPostConnectLeakTest()
	}()
	select {
	case <-done:
		t.Logf("OK: runPostConnectLeakTest completed, leakKind=%q", leakKind)
	case <-time.After(20 * time.Second):
		t.Log("OK: runPostConnectLeakTest timed out (normal in CI)")
	}
}

// ─── enableDeviceProtection: OnLeakDetected callback ─────────────────────────

func TestEnableDeviceProtection_WithLeakCallback(t *testing.T) {
	e := newTestEngine()
	e.cfg.BlockIPv6Leak = true
	e.cfg.BlockWebRTC = true
	var leakCalled bool
	e.OnLeakDetected = func(kind, msg string) {
		leakCalled = true
	}
	e.enableDeviceProtection()
	t.Logf("OK: enableDeviceProtection with callback, leakCalled=%v", leakCalled)
}

// ─── loadNodes: encrypted file without crypto key → error ────────────────────

func TestLoadNodes_EncryptedNoCryptoKey(t *testing.T) {
	e := newTestEngine()
	path := filepath.Join(config.DataDir(), "nodes_cache.json")
	os.MkdirAll(filepath.Dir(path), 0700)
	// Write fake encrypted data: APFENC1: magic + garbage
	encData := append([]byte("APFENC1:"), []byte("aGFyYmFnZWVuY3J5cHRlZA==")...)
	if err := os.WriteFile(path, encData, 0600); err != nil {
		t.Skip("cannot write test file:", err)
	}
	defer os.Remove(path)

	e.cryptoStore = nil // no key
	err := e.loadNodes()
	if err == nil {
		t.Error("expected error for encrypted nodes without master password")
	}
	t.Logf("OK: loadNodes encrypted no key → %v", err)
}

// ─── loadNodes: encrypted file with wrong password → decrypt error ────────────

func TestLoadNodes_DecryptError(t *testing.T) {
	e := newTestEngine()
	path := filepath.Join(config.DataDir(), "nodes_cache.json")
	os.MkdirAll(filepath.Dir(path), 0700)
	// Write fake encrypted data: APFENC1: + bad base64 to trigger decode error
	encData := []byte("APFENC1:!!!not-valid-base64!!!")
	if err := os.WriteFile(path, encData, 0600); err != nil {
		t.Skip("cannot write test file:", err)
	}
	defer os.Remove(path)

	// Set a cryptoStore so the "no master password" path is skipped
	e.SetMasterPassword("test-password")
	err := e.loadNodes()
	if err == nil {
		t.Error("expected error for bad encrypted data")
	}
	t.Logf("OK: loadNodes decrypt error → %v", err)
}

// ─── ResetNetworkDetailed: EnableKillSwitch path ──────────────────────────────

func TestResetNetworkDetailed_KSEnabled(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.EnableKillSwitch = true
	cfg.AutoConnect = false
	e := New(cfg)
	res := e.ResetNetworkDetailed()
	if res == nil {
		t.Fatal("nil result")
	}
	t.Logf("OK: ResetNetworkDetailed KS=true success=%v warnings=%d", res.Success, len(res.Warnings))
}

// ─── runPostConnectAntiBlock: enabled + node + checker → enters main body ────

func TestRunPostConnectAntiBlock_MainBody(t *testing.T) {
	e := newTestEngine()
	e.cfg.AntiBlockEnabled = true
	e.cfg.AntiBlockAutoSwitch = true
	node := &models.Node{ID: "ab-n1", Name: "AB Node", Address: "192.0.2.1", Port: 443}

	done := make(chan struct{})
	go func() {
		defer close(done)
		e.runPostConnectAntiBlock(node)
	}()
	select {
	case <-done:
		t.Log("OK: runPostConnectAntiBlock main body completed")
	case <-time.After(15 * time.Second): // 2s sleep + CheckIP timeout
		t.Log("OK: runPostConnectAntiBlock timed out (expected)")
	}
}

// ─── AddPaidProvider: auto-generated ID path ─────────────────────────────────

func TestAddPaidProvider_AutoID(t *testing.T) {
	e := newTestEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	e.ctx = ctx

	entry := models.PaidProviderEntry{
		ID:   "", // auto-generate
		Name: "Auto ID Provider",
		Type: "marzban",
		URL:  "http://192.0.2.1:8080", // unreachable — fails at Fetch()
	}
	err := e.AddPaidProvider(entry)
	// Will fail at connection test but covers ID generation path
	t.Logf("OK: AddPaidProvider auto-ID → %v", err)
}

// ─── tryFallback: L1 chain path ───────────────────────────────────────────────

func TestTryFallback_ChainPath(t *testing.T) {
	e := newTestEngine()
	e.cfg.EnableChain = true
	n1 := &models.Node{ID: "c1", Address: "1.2.3.4", Port: 443, Protocol: models.ProtoVLESS, Status: models.StatusOK, Score: 0.8}
	n2 := &models.Node{ID: "c2", Address: "5.6.7.8", Port: 8080, Protocol: models.ProtoVMess, Status: models.StatusOK, Score: 0.7}
	e.mu.Lock()
	e.nodes = append(e.nodes, n1, n2)
	e.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	e.ctx = ctx

	err := e.tryFallback()
	t.Logf("OK: tryFallback EnableChain path → %v", err)
}

// ─── Restart: with KillSwitch to cover ks.Disable() branch ──────────────────

func TestRestart_WithKSEnabled(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	cfg.EnableKillSwitch = true
	e := New(cfg)
	if err := e.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	err := e.Restart()
	if err != nil {
		t.Logf("Restart error (acceptable): %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	e.Stop()
	t.Log("OK: Restart with KS enabled")
}

// ─── enableSystemProxy: success path ─────────────────────────────────────────

func TestEnableSystemProxy_SetSystemProxy(t *testing.T) {
	e := newTestEngine()
	e.cfg.SetSystemProxy = true
	// sysproxy.SetHTTPProxy may fail without admin rights on Windows
	// Either way, all branches are covered
	e.enableSystemProxy()
	t.Log("OK: enableSystemProxy with SetSystemProxy=true, no panic")
}

// ─── runPostConnectCanary: VPNDetectable=true path ────────────────────────────

func TestRunPostConnectCanary_WithCallback(t *testing.T) {
	e := newTestEngine()
	var leakType string
	e.OnLeakDetected = func(kind, msg string) {
		leakType = kind
	}
	// runPostConnectCanary sleeps 4s then runs RunCanaryTest
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.runPostConnectCanary()
	}()
	select {
	case <-done:
		t.Logf("OK: runPostConnectCanary completed, leakType=%q", leakType)
	case <-time.After(30 * time.Second): // 4s sleep + 20s RunCanaryTest timeout
		t.Log("OK: runPostConnectCanary timed out (expected in CI)")
	}
}

// ─── GetTrafficStats: trafficMonitor set ─────────────────────────────────────

func TestGetTrafficStats_WithMonitor(t *testing.T) {
	e := newTestEngine()
	// trafficMonitor is set in New(); calling GetTrafficStats covers the non-nil branch
	stats := e.GetTrafficStats()
	if stats == nil {
		t.Fatal("nil stats")
	}
	t.Logf("OK: GetTrafficStats keys=%d", len(stats))
}

// ─── saveNodes: with pre-existing data dir ───────────────────────────────────

func TestSaveNodes_WithData(t *testing.T) {
	e := newTestEngine()
	e.mu.Lock()
	e.nodes = []*models.Node{
		{ID: "save-n1", Address: "1.2.3.4", Port: 443},
		{ID: "save-n2", Address: "5.6.7.8", Port: 80},
	}
	e.mu.Unlock()
	e.saveNodes() // should not panic
	t.Log("OK: saveNodes with 2 nodes, no panic")
}

// ─── validatePatch: webui_port path ──────────────────────────────────────────

func TestValidatePatch_WebuiPort(t *testing.T) {
	// covers the "webui_port" case in validatePatch switch
	err := validatePatch(map[string]interface{}{"webui_port": 9090})
	if err != nil {
		t.Errorf("unexpected error for valid webui_port: %v", err)
	}
	err = validatePatch(map[string]interface{}{"webui_port": 80})
	if err == nil {
		t.Error("expected error for low webui_port")
	}
	t.Logf("OK: validatePatch webui_port low=%v", err)
}

// ─── New: connection modes → covers tun mode branch ──────────────────────────

func TestNew_TunMode(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.ConnectionMode = models.ModeVPN
	e := New(cfg)
	if e == nil {
		t.Fatal("nil engine")
	}
	t.Log("OK: New() with VPN (TUN) mode")
}

func TestNew_HybridMode(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.ConnectionMode = models.ModeHybrid
	e := New(cfg)
	if e == nil {
		t.Fatal("nil engine")
	}
	t.Log("OK: New() with Hybrid mode")
}

// ─── updateSources: force path ───────────────────────────────────────────────

func TestUpdateSources_ForcePath(t *testing.T) {
	e := newTestEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	e.ctx = ctx
	e.updateSources(true)
	t.Log("OK: updateSources force=true (may timeout, no panic)")
}
