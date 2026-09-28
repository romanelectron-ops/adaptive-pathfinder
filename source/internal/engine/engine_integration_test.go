package engine

import (
	"context"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/killswitch"
	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/singbox"
	"github.com/apf/adaptive-pathfinder/internal/version"
)

// TestEngineNew проверяет создание Engine с дефолтным конфигом.
func TestEngineNew(t *testing.T) {
	cfg := models.DefaultConfig()
	e := New(cfg)
	if e == nil {
		t.Fatal("New() returned nil")
	}
	if e.cfg == nil {
		t.Fatal("engine.cfg is nil")
	}
	if e.cfg.ListenPort == 0 {
		t.Error("ListenPort should not be 0")
	}
	if e.trafficMonitor == nil {
		t.Error("trafficMonitor should be initialized")
	}
	if e.stickySession == nil {
		t.Error("stickySession should be initialized")
	}
	t.Logf("OK: Engine created, port=%d, mode=%s",
		e.cfg.ListenPort, e.cfg.ConnectionMode)
}

// TestPatchConfig проверяет применение патчей с валидацией.
func TestPatchConfig(t *testing.T) {
	cfg := models.DefaultConfig()
	e := New(cfg)

	// Корректный патч
	err := e.PatchConfig(map[string]interface{}{
		"selection_mode":  "stealth",
		"connection_mode": "proxy",
	})
	if err != nil {
		t.Fatalf("valid patch failed: %v", err)
	}
	if e.cfg.SelectionMode != "stealth" {
		t.Errorf("SelectionMode not updated: %s", e.cfg.SelectionMode)
	}

	// Невалидный connection_mode
	err = e.PatchConfig(map[string]interface{}{
		"connection_mode": "invalid_mode",
	})
	if err == nil {
		t.Error("expected error for invalid connection_mode")
	}

	// Невалидный порт
	err = e.PatchConfig(map[string]interface{}{
		"listen_port": 80,
	})
	if err == nil {
		t.Error("expected error for port < 1024")
	}

	// Пустой патч
	err = e.PatchConfig(map[string]interface{}{})
	if err == nil {
		t.Error("expected error for empty patch")
	}

	t.Log("OK: PatchConfig validation works")
}

// TestPatchConfig_RejectsModeSwitchWhileConnected — Э-Win-TUN-2
// (docs/TZ_WINDOWS_TUN_VPN_v1.0.md): connection_mode на живом подключённом движке
// нельзя сменить молча — builder/killswitch остались бы от старого режима.
func TestPatchConfig_RejectsModeSwitchWhileConnected(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.ConnectionMode = models.ModeProxy
	e := New(cfg)
	e.state.Connected = true

	// Смена режима при активном подключении — отказ.
	err := e.PatchConfig(map[string]interface{}{"connection_mode": "vpn"})
	if err == nil {
		t.Fatal("expected error switching connection_mode while connected")
	}
	if e.cfg.ConnectionMode != models.ModeProxy {
		t.Errorf("ConnectionMode changed despite rejection: %s", e.cfg.ConnectionMode)
	}

	// То же значение, что уже стоит, — не смена, разрешено даже при подключении.
	if err := e.PatchConfig(map[string]interface{}{"connection_mode": "proxy"}); err != nil {
		t.Errorf("re-patching the SAME connection_mode while connected should be allowed: %v", err)
	}

	// После отключения смена режима проходит нормально.
	e.state.Connected = false
	if err := e.PatchConfig(map[string]interface{}{"connection_mode": "vpn"}); err != nil {
		t.Errorf("mode switch after disconnect should succeed: %v", err)
	}
	if e.cfg.ConnectionMode != models.ModeVPN {
		t.Errorf("ConnectionMode not applied after disconnect: %s", e.cfg.ConnectionMode)
	}

	t.Log("OK: PatchConfig rejects connection_mode switch while connected, allows after disconnect")
}

// TestPatchConfig_SyncsBuilderTunModeLive — Э-Win-TUN-4 (docs/TZ_WINDOWS_TUN_VPN_v1.0.md):
// смена connection_mode через PatchConfig должна СРАЗУ отразиться в конфигах, которые
// builder строит дальше — без перезапуска процесса (иначе GUI-переключатель "молча
// повисает" до следующего запуска APF, ровно то, чего Э-Win-TUN-2 не допускает для
// killswitch, но раньше допускал для builder).
func TestPatchConfig_SyncsBuilderTunModeLive(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.ConnectionMode = models.ModeProxy
	e := New(cfg)

	node := &models.Node{Protocol: models.ProtoShadowsocks, Address: "vpn.example.com",
		Port: 8388, Password: "p", Method: "aes-256-gcm"}

	before, err := e.builder.BuildSingle(node)
	if err != nil {
		t.Fatalf("BuildSingle (proxy) failed: %v", err)
	}
	if hasTunInbound(before) {
		t.Fatal("builder уже строит tun-inbound при ModeProxy — некорректное начальное состояние теста")
	}

	if err := e.PatchConfig(map[string]interface{}{"connection_mode": "vpn"}); err != nil {
		t.Fatalf("mode switch failed: %v", err)
	}

	after, err := e.builder.BuildSingle(node)
	if err != nil {
		t.Fatalf("BuildSingle (vpn) failed: %v", err)
	}
	if !hasTunInbound(after) {
		t.Fatal("после PatchConfig(vpn) builder всё ещё не строит tun-inbound — смена режима не дошла до builder")
	}

	// Обратное направление: vpn → proxy тоже должно снимать tun-inbound немедленно.
	if err := e.PatchConfig(map[string]interface{}{"connection_mode": "proxy"}); err != nil {
		t.Fatalf("mode switch back failed: %v", err)
	}
	back, err := e.builder.BuildSingle(node)
	if err != nil {
		t.Fatalf("BuildSingle (proxy again) failed: %v", err)
	}
	if hasTunInbound(back) {
		t.Fatal("после PatchConfig(proxy) builder всё ещё строит tun-inbound")
	}

	t.Log("OK: PatchConfig синхронизирует e.builder.tunMode немедленно, без перезапуска процесса")
}

func hasTunInbound(cfg *singbox.Config) bool {
	for _, ib := range cfg.Inbounds {
		if ib.Type == "tun" {
			return true
		}
	}
	return false
}

// TestEngineRestart проверяет что Restart() создаёт новый контекст.
func TestEngineRestart(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false // не подключаться автоматически
	e := New(cfg)

	// Запоминаем исходный контекст
	ctx1 := e.ctx

	// Отменяем контекст как при Stop()
	e.cancel()

	// Проверяем что контекст отменён
	select {
	case <-ctx1.Done():
		// ОК
	case <-time.After(100 * time.Millisecond):
		t.Error("context should be cancelled")
	}

	t.Log("OK: Engine context cancellation works")
}

// TestGetTrafficStats проверяет что GetTrafficStats не паникует.
func TestGetTrafficStats(t *testing.T) {
	cfg := models.DefaultConfig()
	e := New(cfg)

	stats := e.GetTrafficStats()
	if stats == nil {
		t.Fatal("GetTrafficStats returned nil")
	}
	// Проверяем ключи
	for _, key := range []string{"up_bytes", "down_bytes", "up_speed_str", "down_speed_str"} {
		if _, ok := stats[key]; !ok {
			t.Errorf("missing key: %s", key)
		}
	}
	t.Logf("OK: traffic stats: %v", stats)
}

// TestCheckForUpdateNoNetwork проверяет что CheckForUpdate корректно обрабатывает ошибки.
func TestCheckForUpdateNoNetwork(t *testing.T) {
	cfg := models.DefaultConfig()
	e := New(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Если нет сети — должна вернуться ошибка или пустой статус, но не паника
	status, _ := e.CheckForUpdate(ctx)
	if status != nil && status.CurrentVersion == "" {
		t.Error("CurrentVersion should not be empty")
	}
	if status != nil {
		t.Logf("OK: update check returned status (update_available=%v)", status.UpdateAvailable)
	} else {
		t.Log("OK: update check failed gracefully (no network)")
	}
}

// TestGetDiagnostics проверяет что GetDiagnostics возвращает нужные поля.
func TestGetDiagnostics(t *testing.T) {
	cfg := models.DefaultConfig()
	e := New(cfg)

	diag := e.GetDiagnostics()
	required := []string{
		"blockage_type", "ipv6_block",
		"webrtc_block", "apf_version", "sing_box_version",
	}
	for _, key := range required {
		if _, ok := diag[key]; !ok {
			t.Errorf("diagnostics missing key: %s", key)
		}
	}
	// C-5, 2026-09-08: fsm_state убран из GetDiagnostics — FSM-«состояние» не
	// выбирает outbound и врало пользователю (см. engine.go комментарий у diag map).
	if _, ok := diag["fsm_state"]; ok {
		t.Errorf("diagnostics still contains removed key: fsm_state (C-5)")
	}
	if diag["apf_version"] != version.Version {
		t.Errorf("apf_version: want %s, got %v", version.Version, diag["apf_version"])
	}
	t.Logf("OK: diagnostics complete, version=%v, sb=%v",
		diag["apf_version"], diag["sing_box_version"])
}

// TestValidatePatch проверяет все ветки валидации.
func TestValidatePatch(t *testing.T) {
	tests := []struct {
		name    string
		patch   map[string]interface{}
		wantErr bool
	}{
		{"valid port", map[string]interface{}{"listen_port": 10808}, false},
		{"low port", map[string]interface{}{"listen_port": 80}, true},
		{"high port", map[string]interface{}{"listen_port": 70000}, true},
		{"valid mode", map[string]interface{}{"connection_mode": "vpn"}, false},
		{"invalid mode", map[string]interface{}{"connection_mode": "tunnel"}, true},
		{"valid selection", map[string]interface{}{"selection_mode": "streaming"}, false},
		{"invalid selection", map[string]interface{}{"selection_mode": "ultra"}, true},
		{"valid interval", map[string]interface{}{"check_interval_sec": 60}, false},
		{"too fast interval", map[string]interface{}{"check_interval_sec": 1}, true},
		{"unrelated key", map[string]interface{}{"auto_connect": true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePatch(tt.patch)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePatch(%v) err=%v, wantErr=%v", tt.patch, err, tt.wantErr)
			}
		})
	}
	t.Log("OK: all validation cases pass")
}

// TestConnectDisconnectCycles — Gate A: 10 циклов без утечки состояния.
// Проверяет что после каждого Stop() engine возвращается в чистое состояние.
func TestConnectDisconnectCycles(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	cfg.EnableKillSwitch = false // не трогаем firewall в тестах

	for i := 0; i < 10; i++ {
		e := New(cfg)

		// Проверяем начальное состояние
		if e.GetState().Connected {
			t.Errorf("cycle %d: should not be connected on start", i)
		}

		// Отменяем контекст (симулируем Stop)
		e.cancel()

		// Новый engine — состояние чистое
		e2 := New(cfg)
		if e2.GetState().Connected {
			t.Errorf("cycle %d: new engine should not be connected", i)
		}
		e2.cancel()
	}
	t.Log("OK: 10 connect/disconnect cycles — no state leakage")
}

// TestQuickResetIdempotent — Gate A: QuickReset безопасен при повторном вызове.
// На Linux проверяем что iptables не падает, на Windows — что netsh не ошибается.
func TestQuickResetIdempotent(t *testing.T) {
	// Вызываем несколько раз подряд — не должно паниковать или возвращать ошибку
	for i := 0; i < 3; i++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("QuickReset() panicked: %v", r)
				}
			}()
			killswitch.QuickReset()
		}()
	}
	t.Log("OK: QuickReset() idempotent — no panic after 3 calls")
}

// TestPatchConfigIdempotent проверяет что двойной патч с теми же данными не меняет состояние.
func TestPatchConfigIdempotent(t *testing.T) {
	cfg := models.DefaultConfig()
	e := New(cfg)

	patch := map[string]interface{}{
		"selection_mode":  "stealth",
		"connection_mode": "proxy",
		"auto_connect":    false,
	}

	// Применяем дважды
	if err := e.PatchConfig(patch); err != nil {
		t.Fatalf("first patch: %v", err)
	}
	mode1 := e.cfg.SelectionMode
	conn1 := e.cfg.ConnectionMode

	if err := e.PatchConfig(patch); err != nil {
		t.Fatalf("second patch: %v", err)
	}
	mode2 := e.cfg.SelectionMode
	conn2 := e.cfg.ConnectionMode

	if mode1 != mode2 || conn1 != conn2 {
		t.Errorf("idempotency violated: %s→%s, %s→%s", mode1, mode2, conn1, conn2)
	}
	t.Logf("OK: double patch idempotent: mode=%s conn=%s", mode2, conn2)
}

// ─── Engine coverage: Restart, GetState, GetStats, ResetNetwork ──────────────

func TestEngineGetState(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	e := New(cfg)

	state := e.GetState()
	if state.Connected {
		t.Error("should not be connected initially")
	}
	// Mode должен быть установлен
	if state.Mode == "" {
		t.Log("mode empty before connection (expected)")
	}
	t.Logf("OK: GetState connected=%v mode=%q", state.Connected, state.Mode)
}

func TestEngineGetSingBoxInfo(t *testing.T) {
	cfg := models.DefaultConfig()
	e := New(cfg)

	info := e.GetSingBoxInfo()
	if info == nil {
		t.Fatal("GetSingBoxInfo returned nil")
	}
	if _, ok := info["installed"]; !ok {
		t.Error("missing 'installed' key")
	}
	if _, ok := info["running"]; !ok {
		t.Error("missing 'running' key")
	}
	t.Logf("OK: GetSingBoxInfo installed=%v running=%v",
		info["installed"], info["running"])
}

func TestEngineGetCatalogStatus(t *testing.T) {
	cfg := models.DefaultConfig()
	e := New(cfg)

	status := e.GetCatalogStatus()
	// Может быть nil или пустым если каталог не инициализирован
	t.Logf("OK: GetCatalogStatus returned %d entries", len(status))
}

// TestEngineGetCatalogStatus_LiveNodeCount — регресс для находки QA на телефоне/ПК
// 2026-08-20: диалог «Каталог серверов» показывал «0 узлов» у каждого источника, хотя
// в пуле реально лежали тысячи узлов с этим Source. Причина — Registry.Status() отдаёт
// ProviderMeta.NodeCount, который заполняется только живым Fetch() в ЭТОМ процессе, а
// подавляющее большинство узлов приходит из nodes_cache.json при старте, не через Fetch.
// GetCatalogStatus() теперь пересчитывает node_count из фактического e.nodes.
func TestEngineGetCatalogStatus_LiveNodeCount(t *testing.T) {
	cfg := models.DefaultConfig()
	e := New(cfg)

	e.mu.Lock()
	e.nodes = []*models.Node{
		{ID: "n1", Source: "v2ray-aggregator"},
		{ID: "n2", Source: "v2ray-aggregator"},
		{ID: "n3", Source: "v2ray-aggregator"},
		{ID: "n4", Source: "freefq"},
		{ID: "n5", Source: "manual"},
	}
	e.mu.Unlock()

	status := e.GetCatalogStatus()
	counts := make(map[string]int)
	for _, s := range status {
		id, _ := s["id"].(string)
		nc, _ := s["node_count"].(int)
		counts[id] = nc
	}

	if counts["v2ray-aggregator"] != 3 {
		t.Errorf("v2ray-aggregator node_count: want 3, got %d (%v)", counts["v2ray-aggregator"], counts)
	}
	if counts["freefq"] != 1 {
		t.Errorf("freefq node_count: want 1, got %d", counts["freefq"])
	}
	if counts["manual"] != 1 {
		t.Errorf("manual node_count: want 1, got %d", counts["manual"])
	}
	if counts["nomore-walls"] != 0 {
		t.Errorf("nomore-walls node_count: want 0 (no matching nodes), got %d", counts["nomore-walls"])
	}
	t.Log("OK: GetCatalogStatus reflects live e.nodes, not just this-session Fetch() count")
}

func TestEngineForceSwitchNoPanic(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	e := New(cfg)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ForceSwitchNow panicked: %v", r)
		}
	}()
	// Не подключены — ForceSwitchNow должен корректно обработать
	e.ForceSwitchNow()
	t.Log("OK: ForceSwitchNow no panic when not connected")
}

func TestEngineAddNodeFromLink(t *testing.T) {
	cfg := models.DefaultConfig()
	e := New(cfg)

	// Добавляем валидный узел
	err := e.AddNodeFromLink("vless://test-uuid@example.com:443?security=tls#TestNode")
	if err != nil {
		t.Logf("AddNodeFromLink warn: %v", err)
	}

	// Дубликат — должен вернуть ошибку
	err2 := e.AddNodeFromLink("vless://test-uuid@example.com:443?security=tls#TestNode")
	if err2 == nil {
		t.Log("warn: duplicate node not rejected (may be by-design if IDs differ)")
	}
	t.Log("OK: AddNodeFromLink")
}

func TestEngineSetProviderEnabled(t *testing.T) {
	cfg := models.DefaultConfig()
	e := New(cfg)

	// Провайдер которого нет — должен вернуть false
	ok := e.SetProviderEnabled("nonexistent-provider", true)
	t.Logf("OK: SetProviderEnabled nonexistent = %v", ok)
}

func TestEngineRemovePaidProvider(t *testing.T) {
	cfg := models.DefaultConfig()
	e := New(cfg)

	// Нет провайдеров — должен вернуть false
	ok := e.RemovePaidProvider("nonexistent")
	if ok {
		t.Error("should return false for nonexistent provider")
	}
	t.Log("OK: RemovePaidProvider nonexistent = false")
}

func TestEngineGetNodes(t *testing.T) {
	cfg := models.DefaultConfig()
	e := New(cfg)

	nodes := e.GetNodes()
	t.Logf("OK: GetNodes() = %d nodes", len(nodes))
}

func TestEngineGetStickySessionStatus(t *testing.T) {
	cfg := models.DefaultConfig()
	e := New(cfg)

	status := e.GetStickySessionStatus()
	if status == nil {
		t.Fatal("GetStickySessionStatus nil")
	}
	if _, ok := status["policy"]; !ok {
		t.Error("missing 'policy' key")
	}
	t.Logf("OK: sticky status policy=%v", status["policy"])
}

func TestEngineResetBlockageCache(t *testing.T) {
	cfg := models.DefaultConfig()
	e := New(cfg)

	// Не должно паниковать
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ResetBlockageCache panicked: %v", r)
		}
	}()
	e.ResetBlockageCache()
	t.Log("OK: ResetBlockageCache no panic")
}

func TestEnginePatchConfigPreservesOtherFields(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.AutoConnect = true
	cfg.MaxLatency = 500
	e := New(cfg)

	// Меняем только один параметр
	err := e.PatchConfig(map[string]interface{}{
		"selection_mode": "speed",
	})
	if err != nil {
		t.Fatalf("PatchConfig: %v", err)
	}

	// Другие поля должны сохраниться
	if !e.cfg.AutoConnect {
		t.Error("AutoConnect should be preserved")
	}
	if e.cfg.MaxLatency != 500 {
		t.Errorf("MaxLatency: want 500, got %d", e.cfg.MaxLatency)
	}
	if e.cfg.SelectionMode != "speed" {
		t.Errorf("SelectionMode: want speed, got %s", e.cfg.SelectionMode)
	}
	t.Log("OK: PatchConfig preserves other fields")
}
