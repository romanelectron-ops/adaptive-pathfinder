// engine_v14_sec_test.go — лот L1-SEC ТЗ v1.4 (волна W1a): S-1, S-7, C-4 (движок), C-6.
//
// Каждый тест здесь написан ДО правки и на прежнем коде обязан падать — это условие метода
// «чёрных ящиков» (blackbox-tdd): без падения до фикса нельзя утверждать, что тест вообще
// проверяет заявленный дефект, а не просто повторяет уже существующее поведение.
package engine

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/fallback"
	"github.com/apf/adaptive-pathfinder/internal/killswitch"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── общий подставной бэкенд Kill Switch для этого файла ─────────────────────

// v14KS — бэкенд Kill Switch с управляемым «зависанием» SetVPNEndpoint.
//
// Зачем именно зависание, а не «SetVPNEndpoint вернул ошибку»: у метода нет возвращаемого
// значения (killswitch.KillSwitch, расширение SetVPNEndpoint(string, int)), поэтому
// единственный источник ошибки на этом пути — таймаут ksCall, то есть ровно тот сценарий,
// который дал живой инцидент 2026-08-19: WFP-вызов повис на BFE, адрес узла не попал в
// allow-список, а Kill Switch включился поверх этого и оставил машину без интернета.
type v14KS struct {
	caps killswitch.Capabilities

	// hang != nil — SetVPNEndpoint блокируется, пока канал не закроют (имитация зависшего
	// системного вызова). Закрывать обязан сам тест (defer), иначе горутина ksCall утечёт.
	hang chan struct{}

	enableErr  error
	disableErr error

	enables       atomic.Int32
	disables      atomic.Int32
	resets        atomic.Int32
	endpointCalls atomic.Int32
	lastEndpoint  atomic.Value // string
	enabled       atomic.Bool
}

func (k *v14KS) Enable(tunInterface string, allowedPorts []int) error {
	k.enables.Add(1)
	if k.enableErr != nil {
		return k.enableErr
	}
	k.enabled.Store(true)
	return nil
}

func (k *v14KS) Disable() error {
	k.disables.Add(1)
	k.enabled.Store(false)
	return k.disableErr
}

func (k *v14KS) IsEnabled() bool                       { return k.enabled.Load() }
func (k *v14KS) Capabilities() killswitch.Capabilities { return k.caps }
func (k *v14KS) Reset() error                          { k.resets.Add(1); return nil }
func (k *v14KS) ResetAll() error                       { return nil }

func (k *v14KS) SetVPNEndpoint(ip string, port int) {
	k.endpointCalls.Add(1)
	k.lastEndpoint.Store(ip)
	if k.hang != nil {
		<-k.hang
	}
}

func (k *v14KS) endpoint() string {
	if v, ok := k.lastEndpoint.Load().(string); ok {
		return v
	}
	return ""
}

// v14EngineWithKS — движок, у которого applyKillSwitch дойдёт до передачи адреса:
// proxy-режим с включённым системным прокси (иначе срабатывает более ранний гейт,
// см. комментарий в applyKillSwitch) и служебный путь применения (Enable идёт прямо
// в бэкенд, без UAC).
//
// Движок собирается через New(), а не литералом: на ПРЕЖНЕМ коде (до правки S-1) ошибка
// SetVPNEndpoint терялась, applyKillSwitch доходила до routeKillSwitchEnable и запускала
// отслеживаемую горутину UAC — литералу для этого не хватает контекста (goTracked).
// Реальные системные вызовы при этом не выполняются: барьер internal/hostguard под
// `go test` превращает netsh/WFP/UAC-пути в no-op (см. killswitch/ks_testguard*.go).
func v14EngineWithKS(ks killswitch.KillSwitch) *Engine {
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	cfg.ConnectionMode = models.ModeProxy
	cfg.SetSystemProxy = true
	cfg.EnableKillSwitch = true
	cfg.ListenPort = 10808
	e := New(cfg)
	e.ks = ks
	e.ksProbedAt = time.Now()
	e.ksIsService = true
	return e
}

// shortenKSCallTimeout — тот же test-seam, что уже применён в engine_r1_r4_test.go:
// ksCallTimeout объявлен var именно для этого.
func shortenKSCallTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	orig := ksCallTimeout
	ksCallTimeout = d
	t.Cleanup(func() { ksCallTimeout = orig })
}

// ─── S-1 · ksCall теряет ошибку на пути Kill Switch → fail-closed ────────────

// TestV14_S1_ApplyKillSwitch_FailClosed_WhenSetVPNEndpointHangs — главный тест пункта.
//
// До правки: `_ = e.ksCall("SetVPNEndpoint", …)` (engine.go:2405) выбрасывал ошибку таймаута,
// setVPNEndpointForKS возвращала nil, applyKillSwitch продолжала и включала Kill Switch,
// хотя адрес узла в allow-список НЕ попал. Результат для пользователя — «интернета нет
// совсем» до переустановки (инцидент 2026-08-19).
//
// После правки: ошибка доходит до applyKillSwitch, та отказывает. Fail-closed здесь означает
// «не трогать сеть», а не «заблокировать всё»: безопасное состояние — живой интернет без
// защиты, о которой честно сказано, а не мёртвая машина.
func TestV14_S1_ApplyKillSwitch_FailClosed_WhenSetVPNEndpointHangs(t *testing.T) {
	shortenKSCallTimeout(t, 40*time.Millisecond)

	ks := &v14KS{
		caps: killswitch.Capabilities{ProxyMode: true, TunMode: true},
		hang: make(chan struct{}),
	}
	defer close(ks.hang) // освобождаем зависшую горутину ksCall

	e := v14EngineWithKS(ks)

	err := e.applyKillSwitch(&models.Node{Address: "185.199.108.153", Port: 443}, nil)
	if err == nil {
		t.Fatal("applyKillSwitch вернула nil, хотя адрес узла не попал в allow-список Kill Switch — " +
			"это и есть инцидент 2026-08-19 (защита включена вслепую, интернета нет)")
	}
	if ks.endpointCalls.Load() == 0 {
		t.Fatal("SetVPNEndpoint даже не вызывался — тест не проверяет заявленный путь")
	}
	// Защита не должна включиться ни на этом бэкенде, ни на том, которым ksCall заменил его
	// после таймаута (самолечение): признак включения на служебном пути — ksElevated.
	if ks.enabled.Load() {
		t.Error("Kill Switch включён на бэкенде, который не принял адрес узла")
	}
	if e.isKSElevated() {
		t.Error("движок отметил Kill Switch применённым, хотя allow-список не поставлен")
	}
	t.Logf("OK: честный отказ — %v", err)
}

// TestV14_S1_ApplyKillSwitch_SuccessPathUnchanged — успешный путь не изменился: адрес узла
// уходит в бэкенд, Kill Switch включается, ошибки нет.
func TestV14_S1_ApplyKillSwitch_SuccessPathUnchanged(t *testing.T) {
	ks := &v14KS{caps: killswitch.Capabilities{ProxyMode: true, TunMode: true}}
	e := v14EngineWithKS(ks)

	if err := e.applyKillSwitch(&models.Node{Address: "185.199.108.153", Port: 443}, nil); err != nil {
		t.Fatalf("успешный путь сломан: %v", err)
	}
	if got := ks.endpoint(); got != "185.199.108.153" {
		t.Errorf("в Kill Switch ушёл адрес %q, ожидался 185.199.108.153", got)
	}
	if ks.enables.Load() != 1 {
		t.Errorf("Enable вызван %d раз(а), ожидался 1", ks.enables.Load())
	}
	t.Log("OK: успешный путь не изменился")
}

// TestV14_S1_ApplyKillSwitch_ChainEntryFailClosed — то же для цепочки: адрес ТОЧКИ ВХОДА
// (R-8) точно так же обязан быть принят бэкендом, иначе включать защиту нельзя.
func TestV14_S1_ApplyKillSwitch_ChainEntryFailClosed(t *testing.T) {
	shortenKSCallTimeout(t, 40*time.Millisecond)

	ks := &v14KS{
		caps: killswitch.Capabilities{ProxyMode: true, TunMode: true},
		hang: make(chan struct{}),
	}
	defer close(ks.hang)

	e := v14EngineWithKS(ks)
	chain := &models.Chain{Nodes: []*models.Node{
		{Address: "151.101.1.69", Port: 443},    // выход
		{Address: "185.199.109.153", Port: 443}, // вход
	}}

	if err := e.applyKillSwitch(nil, chain); err == nil {
		t.Fatal("цепочка: applyKillSwitch вернула nil, хотя адрес точки входа не принят бэкендом")
	}
	if e.isKSElevated() {
		t.Error("цепочка: Kill Switch отмечен применённым без allow-списка")
	}
	t.Log("OK: цепочка тоже отказывает честно")
}

// TestV14_S1_RollbackDisableStillNotDerailed — глушения ошибок на откатных путях
// (engine.go:2165 и :2189) остаются: там движок уже находится в безопасном состоянии и
// откат обязан доработать до конца, даже если Disable провалился.
func TestV14_S1_RollbackDisableStillNotDerailed(t *testing.T) {
	ks := &v14KS{
		caps:       killswitch.Capabilities{ProxyMode: true, TunMode: true},
		disableErr: errV14Disable,
	}
	e := v14EngineWithKS(ks)
	// connectionSuperseded(gen) == true: движок не Connected — откат обязателен.

	// Мок не реализует EnableWithUAC — идём ветвью «Linux/Android: применяем напрямую».
	e.enableKillSwitchWithUAC(&models.Node{Address: "185.199.108.153", Port: 443}, 0)

	if ks.enables.Load() != 1 {
		t.Fatalf("Enable вызван %d раз(а), ожидался 1", ks.enables.Load())
	}
	if ks.disables.Load() != 1 {
		t.Fatalf("откатный Disable вызван %d раз(а), ожидался 1", ks.disables.Load())
	}
	if ks.resets.Load() != 1 {
		t.Errorf("ksReset после провалившегося Disable не выполнен (resets=%d) — "+
			"проброс ошибки на откатном пути сорвал бы откат", ks.resets.Load())
	}
	if e.isKSElevated() {
		t.Error("после отката движок не должен считать Kill Switch применённым")
	}
	t.Log("OK: откат доходит до конца, несмотря на ошибку Disable")
}

// errV14Disable — ошибка подставного Disable (объявлена отдельно, чтобы не тянуть errors в
// каждый тест).
var errV14Disable = errV14("kill switch backend: disable failed")

type errV14 string

func (e errV14) Error() string { return string(e) }

// ─── S-7 · validatePatch: белый список ключей ───────────────────────────────

// TestV14_S7_ValidatePatch_RejectsUnknownKey — неизвестный ключ отвергается с именем ключа.
//
// До правки: switch по 6 ключам, default-ветки нет — любой посторонний ключ проходил и
// попадал в конфиг через слияние карт в applyPatchLocked.
func TestV14_S7_ValidatePatch_RejectsUnknownKey(t *testing.T) {
	err := validatePatch(map[string]interface{}{"unknown_key_xyz": "value"})
	if err == nil {
		t.Fatal("неизвестный ключ принят — белого списка нет")
	}
	if !strings.Contains(err.Error(), "unknown_key_xyz") {
		t.Errorf("ошибка обязана называть ключ, получено: %v", err)
	}
	t.Logf("OK: %v", err)
}

// TestV14_S7_ValidatePatch_UnvalidatedKeysNowChecked — ключи, которые ТЗ называет поимённо
// (S-7): раньше они проходили патч без всякой проверки типа.
func TestV14_S7_ValidatePatch_UnvalidatedKeysNowChecked(t *testing.T) {
	bad := []struct {
		name  string
		patch map[string]interface{}
	}{
		{"enable_kill_switch не bool", map[string]interface{}{"enable_kill_switch": "yes"}},
		{"set_system_proxy не bool", map[string]interface{}{"set_system_proxy": 1}},
		{"disallowed_apps не список строк", map[string]interface{}{"disallowed_apps": "com.example"}},
		{"relay_server_addr не строка", map[string]interface{}{"relay_server_addr": 8080}},
	}
	for _, tc := range bad {
		if err := validatePatch(tc.patch); err == nil {
			t.Errorf("%s: принято без ошибки", tc.name)
		} else {
			t.Logf("OK %s → %v", tc.name, err)
		}
	}

	good := []map[string]interface{}{
		{"enable_kill_switch": true},
		{"set_system_proxy": false},
		{"disallowed_apps": []interface{}{"ru.gosuslugi.app"}},
		{"relay_server_addr": "relay.example:443"},
	}
	for _, p := range good {
		if err := validatePatch(p); err != nil {
			t.Errorf("корректный патч %v отвергнут: %v", p, err)
		}
	}
}

// TestV14_S7_ValidatePatch_KnownKeysStillPass — ключи всех трёх интерфейсов (собраны grep-ом
// по /api/save-config и PatchConfig, см. result.md) обязаны проходить: белый список не должен
// запретить то, чем пользуется свой же UI.
func TestV14_S7_ValidatePatch_KnownKeysStillPass(t *testing.T) {
	uiPatches := []map[string]interface{}{
		// internal/web/server.go: saveSettings()
		{
			"connection_mode": "proxy", "enable_kill_switch": true, "set_system_proxy": false,
			"auto_connect": true, "switch_only_on_fail": true, "enable_chain": false,
			"multihop_enabled": false, "multihop_count": 2, "safety_filter": true,
			"block_ipv6_leak": true, "block_webrtc": true, "min_uptime_sec": 120,
			"listen_port": 10808, "check_interval_sec": 30, "dns_leak_test_interval": 300,
		},
		// internal/web/server.go: applySafeSettingsAndConnect()
		{
			"mode": "auto", "enable_chain": false, "enable_kill_switch": true,
			"switch_only_on_fail": true, "min_uptime_sec": 180, "safety_filter": true,
			"block_ipv6_leak": true, "block_webrtc": true, "dns_leak_test_interval": 300,
		},
		// internal/web/server.go: wizFinish()
		{
			"user_country": "RU", "mode": "stealth", "enable_chain": true,
			"enable_kill_switch": true, "safety_filter": true, "switch_only_on_fail": true,
			"block_ipv6_leak": true, "block_webrtc": true, "setup_done": true,
		},
		// internal/web/server.go: privFinish()
		{"block_ipv6_leak": true, "block_webrtc": false, "dns_leak_test_interval": 0,
			"adblock_profile": "standard"},
		// gui/frontend/src/index.html + gui/app.go + cmd/apf-tray + mobile/androidbridge
		{"connection_mode": "vpn"},
		{"enable_kill_switch": true, "set_system_proxy": true},
		{"node_auto_switch_enabled": true},
		{"cyclic_node_search": true},
		{"node_race_enabled": false},
		{"multihop_count": 3},
		{"check_interval_sec": 60},
		{"listen_port": 10809},
		{"relay_server_addr": "relay.example:443", "relay_server_fingerprint": "ab12"},
		// internal/engine (PatchConfigDetailed из тестов ТЗ v1.3 F5)
		{"shadowtls_enabled": false},
		{"shadowtls_server_addr": "example.com:8443"},
		{"notify_on_switch": true},
		{"webui_port": 9090},
		{"selection_mode": "speed"},
		{"traffic_padding_enabled": true},
		{"max_latency_ms": 3000},
	}
	for _, p := range uiPatches {
		if err := validatePatch(p); err != nil {
			t.Errorf("патч живого UI отвергнут: %v (патч %v)", err, p)
		}
	}
	t.Logf("OK: %d патчей трёх интерфейсов проходят", len(uiPatches))
}

// TestV14_S7_ValidatePatch_PinnedNodeStillRejected — уже существующий запрет (ТЗ v1.3 F2 I1)
// сохраняется: белый список не должен его отменить.
func TestV14_S7_ValidatePatch_PinnedNodeStillRejected(t *testing.T) {
	if err := validatePatch(map[string]interface{}{"pinned_node": map[string]interface{}{"id": "x"}}); err == nil {
		t.Error("pinned_node снова проходит через патч конфига")
	}
	if err := validatePatch(map[string]interface{}{"favorites": []interface{}{}}); err == nil {
		t.Error("favorites снова проходит через патч конфига")
	}
	t.Log("OK: pinned_node/favorites по-прежнему read-only")
}

// ─── C-4 · ошибка saveNodes не доходит до пользователя (часть движка) ────────

// v14EngineWithBrokenNodesCache — движок, у которого запись nodes_cache.json заведомо
// невозможна: на месте временного файла, через который идёт атомарная запись
// (writeFileAtomic пишет path+".tmp" и делает Rename), заранее создан КАТАЛОГ. os.WriteFile в
// каталог не пишет ни на одной ОС, поэтому saveNodes возвращает ошибку детерминированно и без
// подмены шифровальщика (apfcrypto.Store — конкретный тип, мока у него нет).
func v14EngineWithBrokenNodesCache(t *testing.T) (*Engine, string) {
	t.Helper()
	dir := withTempDataDir(t)
	if err := os.MkdirAll(filepath.Join(dir, "nodes_cache.json.tmp"), 0o700); err != nil {
		t.Fatalf("подготовка каталога-ловушки: %v", err)
	}
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	return New(cfg), dir
}

// TestV14_C4_SaveNodesFailure_ReachesEngineState — главный тест пункта.
//
// До правки: saveNodesDebounced звала saveNodes и выбрасывала её ошибку; единственным следом
// оставалась строка в логе. Пользователь продолжал добавлять узлы, не зная, что ни один из них
// не переживёт перезапуск (K2-E П11 сделал отказ fail-closed — файл НЕ пишется вовсе).
func TestV14_C4_SaveNodesFailure_ReachesEngineState(t *testing.T) {
	e, dir := v14EngineWithBrokenNodesCache(t)

	e.mu.Lock()
	e.nodes = []*models.Node{{ID: "v14-c4", Name: "n", Address: "185.199.108.153", Port: 443}}
	e.mu.Unlock()

	// Именно путь из ТЗ: фоновый дебаунсенный сброс, у которого нет вызывающего с error.
	e.saveNodesDebounced()

	got := e.LastPersistError()
	if got == "" {
		t.Fatal("движок молчит об отказе записи пула узлов: узлы пользователя не сохранены, " +
			"а состояние выглядит нормальным")
	}
	if e.LastPersistErrorAt().IsZero() {
		t.Error("время отказа не зафиксировано")
	}
	diag, _ := e.GetDiagnostics()["last_persist_error"].(string)
	if diag != got {
		t.Errorf("GetDiagnostics отдаёт last_persist_error=%q, ожидалось %q", diag, got)
	}
	t.Logf("OK: %s", got)

	// Успешная запись обязана снять предупреждение: причина бывает временной.
	if err := os.RemoveAll(filepath.Join(dir, "nodes_cache.json.tmp")); err != nil {
		t.Fatalf("снятие ловушки: %v", err)
	}
	if err := e.saveNodes(); err != nil {
		t.Fatalf("после снятия ловушки запись всё ещё не проходит: %v", err)
	}
	if left := e.LastPersistError(); left != "" {
		t.Errorf("предупреждение не снято после успешной записи: %q", left)
	}
}

// TestV14_C4_SaveNodesSuccess_LeavesNoWarning — обратная сторона: на здоровой машине поле
// пустое, иначе UI показывал бы вечное предупреждение.
func TestV14_C4_SaveNodesSuccess_LeavesNoWarning(t *testing.T) {
	withTempDataDir(t)
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	e := New(cfg)

	if err := e.saveNodes(); err != nil {
		t.Fatalf("обычная запись пула не удалась: %v", err)
	}
	if got := e.LastPersistError(); got != "" {
		t.Errorf("после успешной записи предупреждение непустое: %q", got)
	}
	if v, ok := e.GetDiagnostics()["last_persist_error"]; !ok {
		t.Error("GetDiagnostics не содержит ключ last_persist_error")
	} else if s, _ := v.(string); s != "" {
		t.Errorf("last_persist_error=%q на успешном пути", s)
	}
}

// ─── C-6 · Snowflake: результат GetSingBoxConfig выбрасывается ───────────────

func v14FallbackEngine(t *testing.T) *Engine {
	t.Helper()
	withTempDataDir(t)
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	return New(cfg)
}

// TestV14_C6_FailedActivation_DoesNotClaimTunnelActive — тест-до пункта.
//
// До правки: ActivateFallbackTunnel звала SetActive(ft) ДО единственной попытки поднять
// туннель и не откатывала её при провале. Поле active видно пользователю: GetFallbackStatus →
// FallbackOrchestrator.GetStatus → "active_tunnel". Отказ «Tor нечем исполнить» оставлял в
// интерфейсе «активен Tor» — то самое «применить или честный отказ» из C-6, только про
// состояние, а не про конфигурацию.
func TestV14_C6_FailedActivation_DoesNotClaimTunnelActive(t *testing.T) {
	e := v14FallbackEngine(t)
	if e.emergencyFallback.TorAvailable() {
		t.Skip("на этой машине есть исполняемый tor — сценарий отказа неприменим")
	}

	err := e.ActivateFallbackTunnel("tor")
	if err == nil {
		t.Fatal("активация Tor без бинарника tor обязана отказать")
	}
	if !errors.Is(err, ErrTorUnavailable) {
		t.Errorf("ожидалась ErrTorUnavailable, получено: %v", err)
	}

	status, _ := e.GetFallbackStatus()["fallback"].(map[string]interface{})
	active, _ := status["active_tunnel"].(string)
	if active == string(fallback.FallbackTor) {
		t.Fatal("статус резервов показывает активным Tor, который не запускался — " +
			"пользователь видит защиту, которой нет")
	}
	if got := e.emergencyFallback.GetActive(); got == fallback.FallbackTor {
		t.Errorf("GetActive()=%q после провалившейся активации", got)
	}
	t.Logf("OK: честный отказ (%v), active_tunnel=%q", err, active)
}

// TestV14_C6_EmergencyOutbound_SnowflakeNotSupported — контракт «(конфигурация, применима ли)»
// вместо голой nil-проверки: Snowflake оживлять запрещено (Н-6), и движок обязан знать об этом
// сам, а не полагаться на единственный ранний гейт.
func TestV14_C6_EmergencyOutbound_SnowflakeNotSupported(t *testing.T) {
	e := v14FallbackEngine(t)

	if _, supported := e.emergencyOutboundFor(fallback.FallbackSnowflake); supported {
		t.Error("движок считает конфигурацию Snowflake применимой: её ключи (torrc options) " +
			"не совпадают с вендорной схемой sing-box и до него не доходят")
	}
	if _, supported := e.emergencyOutboundFor(fallback.FallbackTor); !supported {
		t.Error("Tor обязан оставаться применимым резервом")
	}
	if _, supported := e.emergencyOutboundFor(fallback.FallbackNone); supported {
		t.Error("несуществующий резерв не может быть применимым")
	}
}

// TestV14_C6_ActivateSnowflake_HonestRefusal — регресс: ручная кнопка «Snowflake» отказывает
// одной и той же узнаваемой ошибкой и не оставляет ложного «активен».
func TestV14_C6_ActivateSnowflake_HonestRefusal(t *testing.T) {
	e := v14FallbackEngine(t)

	err := e.ActivateFallbackTunnel("tor_snowflake")
	if err == nil {
		t.Fatal("Snowflake активирован, хотя его конфигурация до sing-box не доходит")
	}
	if !errors.Is(err, fallback.ErrSnowflakeNotApplicable) {
		t.Errorf("отказ не узнаётся через errors.Is(ErrSnowflakeNotApplicable): %v", err)
	}
	if got := e.emergencyFallback.GetActive(); got == fallback.FallbackSnowflake {
		t.Error("Snowflake помечен активным после отказа")
	}
	t.Logf("OK: %v", err)
}
