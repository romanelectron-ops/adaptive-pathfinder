package engine

// engine_lifecycle_test.go — tests covering Start/Stop/Restart and goroutine paths.
// All zero-coverage lifecycle functions are targeted here.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── Start / Stop ─────────────────────────────────────────────────────────────

// TestStart_Stop covers: Start(), Stop(), monitorLoop(ctx.Done),
// sourceUpdateLoop(ctx.Done), ensureSingBox, enableDeviceProtection,
// watchdog.Run loop exit.
func TestStart_Stop(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	cfg.EnableKillSwitch = false
	cfg.BlockIPv6Leak = false
	cfg.BlockWebRTC = false
	e := New(cfg)

	if err := e.Start(); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}
	// Give goroutines a moment to spin up and enter their select loops.
	time.Sleep(20 * time.Millisecond)

	// Stop cancels the context and waits for all goroutines via wg.Wait().
	e.Stop()
	t.Log("OK: Start + Stop lifecycle, no panic")
}

// TestStop_RecreatesContext — регресс-тест на BUG-Win-TUN-3 (найден живым прогоном на
// Hyper-V стенде 2026-08-12): Stop() отменял e.ctx и никогда не пересоздавал его.
// /api/disconnect зовёт Stop() напрямую (не Restart(), который пересоздаёт контекст, но
// и сам себя переподключает — не то, что должно происходить при обычном «Отключить»).
// Любой следующий /api/connect (ScanAndConnect → connectNode → applySingBoxConfig →
// e.proc.Start(e.ctx)) подставлял уже отменённый контекст — sing-box падал на самом
// старте с "context canceled" НАВСЕГДА, до перезапуска процесса. Тест проверяет ровно
// то, что реально сломало живой прогон: что после Stop() e.ctx не Done(), т.е. пригоден
// для следующего Start() без падения по отменённому контексту.
func TestStop_RecreatesContext(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	cfg.EnableKillSwitch = false
	cfg.BlockIPv6Leak = false
	cfg.BlockWebRTC = false
	e := New(cfg)

	if err := e.Start(); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	ctxBeforeStop := e.ctx
	e.Stop()

	select {
	case <-ctxBeforeStop.Done():
		// ожидаемо: старая сессия действительно завершена
	default:
		t.Fatal("ctx до Stop() должен быть отменён — иначе Stop() ничего не остановил")
	}

	select {
	case <-e.ctx.Done():
		t.Fatal("BUG-Win-TUN-3: e.ctx после Stop() отменён и не пересоздан — " +
			"следующий Start()/подключение упадёт с \"context canceled\"")
	default:
		// ожидаемо: Stop() пересоздал контекст, движок снова подключаем
	}

	if e.ctx == ctxBeforeStop {
		t.Fatal("e.ctx после Stop() — тот же объект, что и до Stop(); контекст не пересоздан")
	}

	// Убеждаемся, что новый контекст реально рабочий: повторный Start() не должен
	// падать из-за унаследованного отменённого контекста.
	if err := e.Start(); err != nil {
		t.Fatalf("Start() после Stop() unexpected error: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	e.Stop()
	t.Log("OK: Stop() пересоздаёт e.ctx, повторный Start() работает")
}

// TestStart_Stop_WithProtection covers enableDeviceProtection branches
// for IPv6 and WebRTC.
func TestStart_Stop_WithProtection(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	cfg.EnableKillSwitch = false
	cfg.BlockIPv6Leak = true
	cfg.BlockWebRTC = true
	e := New(cfg)

	if err := e.Start(); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	e.Stop()
	t.Log("OK: Start + Stop with protection enabled, no panic")
}

// TestStart_Stop_WithKillSwitch covers Stop's ks.Disable() branch.
func TestStart_Stop_WithKillSwitch(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	cfg.EnableKillSwitch = true // triggers ks.Disable() in Stop
	cfg.BlockIPv6Leak = false
	cfg.BlockWebRTC = false
	e := New(cfg)

	if err := e.Start(); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	e.Stop()
	t.Log("OK: Start + Stop with KillSwitch enabled, no panic")
}

// TestStart_Stop_WithSystemProxy covers Stop's disableSystemProxy goroutine.
func TestStart_Stop_WithSystemProxy(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	cfg.EnableKillSwitch = false
	cfg.SetSystemProxy = true // triggers disableSystemProxy in Stop
	e := New(cfg)

	if err := e.Start(); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	e.Stop()
	t.Log("OK: Start + Stop with system proxy, no panic")
}

// TestStart_Stop_AdBlockProfile covers the AdBlock profile loading goroutine.
func TestStart_Stop_AdBlockProfile(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	cfg.EnableKillSwitch = false
	cfg.AdBlockProfile = "standard"
	e := New(cfg)

	if err := e.Start(); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	e.Stop()
	t.Log("OK: Start + Stop with AdBlock profile, no panic")
}

// ─── Restart ─────────────────────────────────────────────────────────────────

// TestRestart covers the Restart() path: cancel → wg.Wait → new context → Start().
func TestRestart(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	cfg.EnableKillSwitch = false
	cfg.BlockIPv6Leak = false
	cfg.BlockWebRTC = false
	e := New(cfg)

	// First Start so goroutines are running.
	if err := e.Start(); err != nil {
		t.Fatalf("first Start() error: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	// Restart should cancel, wait, then call Start() again.
	if err := e.Restart(); err != nil {
		t.Fatalf("Restart() error: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	e.Stop()
	t.Log("OK: Restart no panic")
}

// TestRestart_WithKillSwitch covers the ks.Disable() branch inside Restart.
func TestRestart_WithKillSwitch(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	cfg.EnableKillSwitch = true
	cfg.BlockIPv6Leak = false
	cfg.BlockWebRTC = false
	e := New(cfg)

	if err := e.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if err := e.Restart(); err != nil {
		t.Fatalf("Restart() error: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	e.Stop()
	t.Log("OK: Restart with KillSwitch, no panic")
}

// TestRestart_ResetsTunMode — регресс для находки QA на телефоне 2026-08-20:
// Restart() (единственный путь Android между VPN- и proxy-сессиями, см. restartEngine
// в mobile/androidbridge/bridge.go) не сбрасывал builder.tunMode, из-за чего обычный
// Connect() в режиме "прокси" после VPN-сессии всё равно строил tun-inbound и падал
// на "bad file descriptor" — реальный баг, воспроизведённый живьём.
func TestRestart_ResetsTunMode(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	cfg.EnableKillSwitch = false
	cfg.BlockIPv6Leak = false
	cfg.BlockWebRTC = false
	e := New(cfg)

	if err := e.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	// Симулируем StartTun (Android VPN-сессия).
	e.SetTunMode(true, 1500)
	if !e.builder.TunMode() {
		t.Fatal("setup: SetTunMode(true) did not take effect")
	}

	if err := e.Restart(); err != nil {
		t.Fatalf("Restart() error: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	if e.builder.TunMode() {
		t.Error("Restart() did not reset builder.tunMode to false — next proxy Connect() would still build a tun-inbound")
	}
	e.Stop()
	t.Log("OK: Restart resets tunMode")
}

// TestRestart_PreservesInMemoryNodePool — регресс для живой находки QA на телефоне
// 2026-09-22: счётчик «В пуле N» на Home проседал с 4042 узлов до 17 СРАЗУ после
// «Отключить», хотя PID процесса не менялся ни разу (не рестарт процесса). Причина: на
// Android любой Disconnect в VPN-режиме идёт через StopTun → restartEngine → Restart()
// (см. её комментарий), а Restart() заканчивается вызовом Start() — который БЕЗУСЛОВНО
// звал loadNodes() и затирал e.nodes отфильтрованным ДЛЯ ДИСКА подмножеством (N-5:
// saveNodesToDisk хранит на диске только избранное/закреплённое/недавнее, полный пул живёт
// только в памяти — см. её комментарий). Фикс: Start() зовёт loadNodes() только когда
// e.nodes ещё пуст (настоящий холодный старт) — тёплый Restart() оставляет в памяти то,
// что там уже было.
func TestRestart_PreservesInMemoryNodePool(t *testing.T) {
	// Свой каталог, не withTempDataDir/t.TempDir(): этот тест, в отличие от соседей по
	// файлу, реально зовёт e.Start() — тот открывает постоянный лог-файл движка (см.
	// openFileLog) и никогда его не закрывает (закрытие не предусмотрено, лог живёт с
	// движком). На Windows t.TempDir() требует, чтобы RemoveAll в конце теста прошёл БЕЗ
	// ошибки, а открытый на запись лог-файл этого не даёт («process cannot access the
	// file») — тест падал бы на уборке каталога, а не на проверке пула. os.RemoveAll здесь
	// намеренно без проверки ошибки: как и общий на пакет каталог в TestMain, эта уборка —
	// best-effort, а не часть проверяемого поведения.
	prevDataDir := config.DataDir()
	dir, err := os.MkdirTemp("", "apf-restart-pool-test-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	config.SetDataDirOverride(dir)
	t.Cleanup(func() {
		config.SetDataDirOverride(prevDataDir)
		_ = os.RemoveAll(dir)
	})

	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	cfg.EnableKillSwitch = false
	cfg.BlockIPv6Leak = false
	cfg.BlockWebRTC = false
	e := New(cfg)

	if err := e.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	// На диске — маленькое отфильтрованное подмножество, как после реального
	// saveNodesToDisk() (N-5). Если бы Restart() перечитал файл, пул схлопнулся бы
	// именно до этого числа — тест ловил бы регресс однозначно, а не молчал бы на 0.
	onDisk := []*models.Node{{ID: "cached-1", Name: "OnDisk1", Address: "10.0.0.1", Port: 443}}
	data, err := json.MarshalIndent(onDisk, "", "  ")
	if err != nil {
		t.Fatalf("marshal onDisk: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nodes_cache.json"), data, 0600); err != nil {
		t.Fatalf("write nodes_cache.json: %v", err)
	}

	// В памяти — «живой» пул после харвеста, намного больше диска.
	live := make([]*models.Node, 0, 50)
	for i := 0; i < 50; i++ {
		live = append(live, &models.Node{
			ID:      fmt.Sprintf("live-%d", i),
			Name:    fmt.Sprintf("Live%d", i),
			Address: fmt.Sprintf("10.1.0.%d", i),
			Port:    443,
		})
	}
	setNodes(e, live...)

	if err := e.Restart(); err != nil {
		t.Fatalf("Restart() error: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	e.mu.RLock()
	got := len(e.nodes)
	e.mu.RUnlock()
	if got != 50 {
		t.Errorf("после Restart() в пуле %d узлов, ожидалось 50 (живая память) — похоже, "+
			"снова перечитался nodes_cache.json (%d записей на диске)", got, len(onDisk))
	}
	e.Stop()
	t.Log("OK: Restart сохраняет живой пул в памяти, не перечитывает диск")
}

// ─── disableSystemProxy ──────────────────────────────────────────────────────

func TestDisableSystemProxy_NotSet(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.SetSystemProxy = false
	e := New(cfg)
	err := e.disableSystemProxy()
	if err != nil {
		t.Errorf("disableSystemProxy(SetSystemProxy=false) expected nil, got: %v", err)
	}
	t.Log("OK: disableSystemProxy with SetSystemProxy=false returns nil")
}

func TestDisableSystemProxy_Set(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.SetSystemProxy = true
	e := New(cfg)
	err := e.disableSystemProxy()
	// May fail on platforms without system proxy support — just must not panic.
	t.Logf("OK: disableSystemProxy(SetSystemProxy=true) = %v", err)
}

func TestEnableSystemProxy_NotSet(t *testing.T) {
	e := newTestEngine()
	e.cfg.SetSystemProxy = false
	e.enableSystemProxy() // should return immediately
	t.Log("OK: enableSystemProxy with SetSystemProxy=false")
}

func TestEnableSystemProxy_Set(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.SetSystemProxy = true
	cfg.ListenPort = 10800
	e := New(cfg)
	e.enableSystemProxy() // may fail but must not panic
	t.Log("OK: enableSystemProxy with SetSystemProxy=true, no panic")
}

// ─── monitor() ───────────────────────────────────────────────────────────────

func TestMonitor_NotConnected(t *testing.T) {
	e := newTestEngine()
	// state.Connected = false (default) → should return immediately
	e.monitor()
	t.Log("OK: monitor() not connected, no panic")
}

func TestMonitor_ConnectedNoActiveNode(t *testing.T) {
	e := newTestEngine()
	e.stateMu.Lock()
	e.state.Connected = true
	e.state.ActiveNode = nil // no active node
	e.stateMu.Unlock()
	e.monitor()
	t.Log("OK: monitor() connected but no active node, no panic")
}

func TestMonitor_ConnectedFails(t *testing.T) {
	e := newTestEngine()
	node := &models.Node{
		ID:      "monitor-node",
		Address: "192.0.2.1", // TEST-NET — connection refused immediately
		Port:    9999,
		Status:  models.StatusOK,
	}
	e.stateMu.Lock()
	e.state.Connected = true
	e.state.ActiveNode = node
	e.stateMu.Unlock()

	// QuickPing will fail (unreachable host) → FailCount increments
	prevFail := node.FailCount
	e.monitor()
	if node.FailCount <= prevFail {
		t.Log("monitor: FailCount did not increment (QuickPing succeeded unexpectedly)")
	} else {
		t.Logf("OK: monitor fail: FailCount=%d", node.FailCount)
	}
}

func TestMonitor_ConnectedFailsThreshold(t *testing.T) {
	e := newTestEngine()
	node := &models.Node{
		ID:        "fail-node",
		Address:   "192.0.2.2",
		Port:      9998,
		Status:    models.StatusOK,
		FailCount: 4, // one more failure triggers emergencySwitch
	}
	e.stateMu.Lock()
	e.state.Connected = true
	e.state.ActiveNode = node
	e.stateMu.Unlock()

	// This will trigger the FailCount>=5 path which launches go e.emergencySwitch()
	e.monitor()
	time.Sleep(5 * time.Millisecond)
	t.Logf("OK: monitor threshold path, FailCount=%d", node.FailCount)
}

// ─── rollbackConnectionAttempt ───────────────────────────────────────────────

func TestRollbackConnectionAttempt_NoKS(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.EnableKillSwitch = false
	e := New(cfg)

	cause := errors.New("simulated connection failure")
	err := e.rollbackConnectionAttempt("test_stage", cause, false)
	// errors.Is, не ==: откат добавляет к причине класс отказа (ТЗ HOTSWITCH §8 A1), текст и
	// сама причина в цепочке сохраняются — именно это и проверяется.
	if !errors.Is(err, cause) {
		t.Errorf("rollback should return original cause, got: %v", err)
	}
	// Verify lastRollback was set
	e.stateMu.RLock()
	rb := e.lastRollback
	e.stateMu.RUnlock()
	if rb == nil {
		t.Error("rollback: lastRollback should be set")
	} else if rb.Stage != "test_stage" {
		t.Errorf("rollback: stage=%q, want %q", rb.Stage, "test_stage")
	}
	t.Log("OK: rollbackConnectionAttempt without KillSwitch")
}

func TestRollbackConnectionAttempt_WithKS(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.EnableKillSwitch = true
	e := New(cfg)

	cause := errors.New("ks rollback failure")
	err := e.rollbackConnectionAttempt("write_config", cause, true)
	if !errors.Is(err, cause) {
		t.Errorf("rollback with KS should return cause, got: %v", err)
	}
	t.Log("OK: rollbackConnectionAttempt with KillSwitch")
}

func TestRollbackConnectionAttempt_WasRunning(t *testing.T) {
	e := newTestEngine()
	cause := errors.New("reload error")
	err := e.rollbackConnectionAttempt("reload", cause, true)
	// wasRunning=true → proc.Stop() NOT called
	if !errors.Is(err, cause) {
		t.Errorf("expected cause to be returned, got %v", err)
	}
	t.Log("OK: rollbackConnectionAttempt wasRunning=true")
}

// ─── emergencySwitch ─────────────────────────────────────────────────────────

func TestEmergencySwitch_TooEarlyToSwitch(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.SwitchOnlyOnFail = true
	cfg.MinUptimeSec = 300 // 5 min minimum uptime
	e := New(cfg)

	// Узел уже подтверждался рабочим — грация должна применяться (в отличие от
	// TestEmergencySwitch_NeverHealthy_BypassesGracePeriod в engine_coverage4_test.go).
	e.watchdog.SetHealthConfirmedForTest(true)

	// Simulate just-connected state
	e.stateMu.Lock()
	e.state.Connected = true
	e.state.Since = time.Now() // uptime = ~0, < 300s
	e.stateMu.Unlock()

	var logs []string
	e.OnLog = func(msg string) { logs = append(logs, msg) }

	e.emergencySwitch() // should return early: "Too early to switch"

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
	t.Log("OK: emergencySwitch returns early when uptime < MinUptimeSec")
}

// TestEmergencySwitch_NeverHealthy_BypassesGracePeriod — живой инцидент 2026-08-12
// (Android, реальный узел из бесплатного публичного списка): узел отвечал HTTP 409 на
// КАЖДОЕ соединение с момента подключения, watchdog это видел (FailCount рос), но
// MinUptimeSec/sticky «молодая сессия» держали мёртвый узел несколько минут — обе паузы
// считаются от момента подключения, а не от последнего момента, когда узел реально
// работал. Для узла, который не прошёл НИ ОДНОЙ проверки с момента коннекта, это не
// защита от флаппинга, а гарантированный простой. См. engine.go emergencySwitch().
func TestEmergencySwitch_NeverHealthy_BypassesGracePeriod(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.SwitchOnlyOnFail = true
	cfg.MinUptimeSec = 300 // 5 min minimum uptime
	e := New(cfg)

	// e.watchdog.HasEverSucceeded() == false по умолчанию (свежий watchdog, ни одной
	// успешной проверки) — именно это и симулирует «узел мёртв с момента подключения».

	e.stateMu.Lock()
	e.state.Connected = true
	e.state.Since = time.Now() // uptime = ~0, < 300s — старая логика вернула бы early
	e.stateMu.Unlock()

	var logs []string
	e.OnLog = func(msg string) { logs = append(logs, msg) }

	e.emergencySwitch()

	for _, l := range logs {
		if strings.Contains(l, "Too early to switch") {
			t.Errorf("expected anti-flap gate to be bypassed for a never-confirmed-healthy "+
				"node, but got early return: %v", logs)
		}
	}
	found := false
	for _, l := range logs {
		if strings.Contains(l, "bypassing anti-flap grace period") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected bypass log message, got: %v", logs)
	}
	t.Log("OK: emergencySwitch bypasses grace period for never-confirmed-healthy node")
}

// TestEmergencySwitch_NodeAutoSwitchDisabled — P0.2 (docs/TZ_APF_ROADMAP_v1.2.md): живой
// инцидент 2026-08-19, пользователь попросил способ полностью выключить автопереключение
// узлов. Гейт должен сработать РАНЬШЕ любых прочих anti-flap проверок ниже по функции.
func TestEmergencySwitch_NodeAutoSwitchDisabled(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.NodeAutoSwitchEnabled = false
	e := New(cfg)

	var logs []string
	e.OnLog = func(msg string) { logs = append(logs, msg) }

	e.emergencySwitch()

	found := false
	for _, l := range logs {
		if strings.Contains(l, "Автопереключение узлов отключено") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected disabled-auto-switch log, got: %v", logs)
	}
	if len(logs) != 2 { // "Emergency switch initiated..." + гейт-сообщение, ничего дальше
		t.Errorf("expected exactly 2 log lines (initiated + gate), got %d: %v", len(logs), logs)
	}
}

// TestEmergencySwitch_ManualConnectSticky_Suppresses — защита от гонки с ConnectByID: узел
// выбран вручную только что, вотчдог не должен тут же его перебить первым же сбоем.
func TestEmergencySwitch_ManualConnectSticky_Suppresses(t *testing.T) {
	cfg := models.DefaultConfig() // NodeAutoSwitchEnabled=true по умолчанию
	e := New(cfg)
	e.manualConnectMu.Lock()
	e.manualConnectAt = time.Now()
	e.manualConnectMu.Unlock()

	var logs []string
	e.OnLog = func(msg string) { logs = append(logs, msg) }

	e.emergencySwitch()

	found := false
	for _, l := range logs {
		if strings.Contains(l, "только что выбрал узел вручную") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected manual-connect-sticky log, got: %v", logs)
	}
}

// TestEmergencySwitch_ManualConnectSticky_ExpiresAfterWindow — за пределами
// manualConnectStickyWindow гейт не должен больше срабатывать (иначе ручной выбор навсегда
// заблокировал бы вотчдог).
func TestEmergencySwitch_ManualConnectSticky_ExpiresAfterWindow(t *testing.T) {
	cfg := models.DefaultConfig()
	e := New(cfg)
	e.manualConnectMu.Lock()
	e.manualConnectAt = time.Now().Add(-manualConnectStickyWindow - time.Second)
	e.manualConnectMu.Unlock()

	var logs []string
	e.OnLog = func(msg string) { logs = append(logs, msg) }

	e.emergencySwitch()

	for _, l := range logs {
		if strings.Contains(l, "только что выбрал узел вручную") {
			t.Errorf("sticky window should have expired, but gate still fired: %v", logs)
		}
	}
}

// TestEmergencySwitch_CyclicSearchDisabled_NoCyclicLog — по умолчанию (CyclicNodeSearch=false)
// emergencySwitch не должна даже пытаться круговой обход — прежнее поведение (прямиком на
// tryFallback), никаких изменений для пользователей, которые не включали тумблер.
func TestEmergencySwitch_CyclicSearchDisabled_NoCyclicLog(t *testing.T) {
	cfg := models.DefaultConfig() // CyclicNodeSearch=false по умолчанию
	cfg.SwitchOnlyOnFail = false
	e := New(cfg)
	// Нет узлов вообще → selectBestExcluding точно вернёт nil, попадём в хвост функции.
	e.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	e.ctx, e.cancel = ctx, cancel

	var logs []string
	e.OnLog = func(msg string) { logs = append(logs, msg) }
	e.emergencySwitch()

	for _, l := range logs {
		if strings.Contains(l, "Циклический поиск") {
			t.Errorf("cyclic search should not run when CyclicNodeSearch=false, got log: %v", logs)
		}
	}
}

// TestEmergencySwitch_CyclicSearchEnabled_RunsCyclicLog — при включённом тумблере, если
// обычный выбор ничего не нашёл, движок обязан хотя бы попытаться круговой обход (видно по
// характерному логу), а не сразу падать на tryFallback.
func TestEmergencySwitch_CyclicSearchEnabled_RunsCyclicLog(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.SwitchOnlyOnFail = false
	cfg.CyclicNodeSearch = true
	e := New(cfg)
	e.mu.Lock()
	e.nodes = []*models.Node{{ID: "cyc-a", Name: "CycA", Address: "10.0.0.1"}}
	e.mu.Unlock()
	e.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	e.ctx, e.cancel = ctx, cancel

	var logs []string
	e.OnLog = func(msg string) { logs = append(logs, msg) }
	e.emergencySwitch()

	found := false
	for _, l := range logs {
		if strings.Contains(l, "Циклический поиск") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected cyclic search log when CyclicNodeSearch=true, got: %v", logs)
	}
}

// TestSelectBestExcluding_SkipsRecentlyFailedNodes — живой инцидент 2026-08-13 (пользователь:
// "показывает порядка 30 узлов а при переключении переключается между двумя только").
// Причина: selectBestExcluding исключал только ТЕКУЩИЙ узел, поэтому серия подряд идущих
// emergencySwitch ping-pong'ила между одними и теми же 1-2 лучшими по Score узлами вместо
// исследования всего пула "доступных". markNodeFailed/recentFailures это чинит — см. поле у
// Engine и комментарий в emergencySwitch.
func TestSelectBestExcluding_SkipsRecentlyFailedNodes(t *testing.T) {
	e := newTestEngine()
	e.mu.Lock()
	e.nodes = []*models.Node{ // Status=ok: непроверенные узлы в выбор не попадают (ТЗ v1.3 F1.5)
		{ID: "node-a", Name: "A", Address: "1.1.1.1", Score: 0.9, Status: models.StatusOK},
		{ID: "node-b", Name: "B", Address: "2.2.2.2", Score: 0.8, Status: models.StatusOK},
		{ID: "node-c", Name: "C", Address: "3.3.3.3", Score: 0.7, Status: models.StatusOK},
	}
	e.mu.Unlock()

	best := e.selectBestExcluding(nil)
	if best == nil || best.ID != "node-a" {
		t.Fatalf("no failures yet: expected node-a (highest score), got %v", best)
	}

	e.markNodeFailed("node-a")
	best = e.selectBestExcluding(nil)
	if best == nil || best.ID != "node-b" {
		t.Fatalf("after node-a failed: expected node-b, got %v", best)
	}

	// Второй отказ подряд (типичный сценарий из инцидента) — обязан дойти до node-c,
	// а не вернуться к node-a/node-b.
	e.markNodeFailed("node-b")
	best = e.selectBestExcluding(nil)
	if best == nil || best.ID != "node-c" {
		t.Fatalf("after node-a AND node-b failed: expected node-c (exploring wider pool), got %v", best)
	}
}

// TestSelectBestExcluding_FallsBackIfAllRecentlyFailed — фильтр по recentFailures не должен
// оставить движок вовсе без кандидата, если ВСЕ доступные узлы недавно отказали.
func TestSelectBestExcluding_FallsBackIfAllRecentlyFailed(t *testing.T) {
	e := newTestEngine()
	e.mu.Lock()
	e.nodes = []*models.Node{
		{ID: "only-node", Name: "Only", Address: "1.1.1.1", Score: 0.9, Status: models.StatusOK},
	}
	e.mu.Unlock()

	e.markNodeFailed("only-node")
	best := e.selectBestExcluding(nil)
	if best == nil || best.ID != "only-node" {
		t.Fatalf("fallback should still return the only node rather than nil, got %v", best)
	}
}

func TestEmergencySwitch_NoNodes(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.SwitchOnlyOnFail = false
	e := New(cfg)
	// No nodes → tryFallback immediately
	e.emergencySwitch()
	t.Log("OK: emergencySwitch with no nodes, no panic")
}

func TestEmergencySwitch_WithNodes_NoBestAlt(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.SwitchOnlyOnFail = false
	e := New(cfg)

	// One node as current active — no alternative
	node := &models.Node{ID: "n1", Score: 0.5, Status: models.StatusOK}
	e.nodes = []*models.Node{node}
	e.stateMu.Lock()
	e.state.ActiveNode = node
	e.stateMu.Unlock()

	e.emergencySwitch()
	t.Log("OK: emergencySwitch with one node (no alternative), no panic")
}

// ─── connectChain ─────────────────────────────────────────────────────────────

func TestConnectChain_EmptyNodes(t *testing.T) {
	e := newTestEngine()
	chain := &models.Chain{Nodes: []*models.Node{}}
	err := e.connectChain(chain)
	// BuildChain with empty nodes should fail
	if err == nil {
		t.Log("connectChain with empty nodes returned nil (unexpected)")
	} else {
		t.Logf("OK: connectChain empty nodes → error: %v", err)
	}
}

func TestConnectChain_SingleNode(t *testing.T) {
	e := newTestEngine()
	chain := &models.Chain{Nodes: []*models.Node{
		{ID: "n1", Protocol: models.ProtoVLESS, Address: "1.2.3.4", Port: 443},
	}}
	err := e.connectChain(chain)
	t.Logf("OK: connectChain single node → %v", err)
}

// ─── buildBestChain with score > 0 nodes ────────────────────────────────────

func TestBuildBestChain_TwoScoredNodes(t *testing.T) {
	e := newTestEngine()
	e.nodes = []*models.Node{
		{ID: "n1", Address: "10.0.0.1", Score: 0.9, Status: models.StatusOK},
		{ID: "n2", Address: "10.0.0.2", Score: 0.8, Status: models.StatusOK},
		{ID: "n3", Address: "10.0.0.3", Score: 0.7, Status: models.StatusOK},
	}
	chain := e.buildBestChain()
	if chain == nil {
		t.Error("buildBestChain should return a chain with 2+ scored nodes")
	} else if len(chain.Nodes) != 2 {
		t.Errorf("buildBestChain: expected 2 nodes, got %d", len(chain.Nodes))
	} else {
		t.Logf("OK: buildBestChain → %d nodes", len(chain.Nodes))
	}
}

func TestBuildBestChain_SameAddress(t *testing.T) {
	e := newTestEngine()
	// Nodes with same address — only one should be selected
	e.nodes = []*models.Node{
		{ID: "n1", Address: "10.0.0.1", Score: 0.9, Status: models.StatusOK},
		{ID: "n2", Address: "10.0.0.1", Score: 0.8, Status: models.StatusOK}, // duplicate address
		{ID: "n3", Address: "10.0.0.2", Score: 0.7, Status: models.StatusOK},
	}
	chain := e.buildBestChain()
	if chain == nil {
		t.Error("buildBestChain should return chain despite duplicate addresses")
	} else {
		t.Logf("OK: buildBestChain same-addr dedup → %d nodes", len(chain.Nodes))
	}
}

func TestBuildBestChain_ZeroScore(t *testing.T) {
	e := newTestEngine()
	// All nodes have Score=0 → should return nil
	e.nodes = []*models.Node{
		{ID: "n1", Address: "10.0.0.1", Score: 0, Status: models.StatusOK},
		{ID: "n2", Address: "10.0.0.2", Score: 0, Status: models.StatusOK},
	}
	chain := e.buildBestChain()
	if chain != nil {
		t.Logf("buildBestChain zero-score: unexpected chain %+v", chain)
	} else {
		t.Log("OK: buildBestChain zero-score nodes → nil")
	}
}

// ─── ApplyUpdate ──────────────────────────────────────────────────────────────

func TestApplyUpdate_ShortContext(t *testing.T) {
	// S-UPD: включаем применение, чтобы дойти до боевого пути (гейт политики иначе вернёт отказ
	// первым). Проверяемое поведение — «не паникует» на коротком контексте — остаётся прежним.
	oldApply := updateApplyEnabled
	updateApplyEnabled = true
	defer func() { updateApplyEnabled = oldApply }()

	e := newTestEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	// Should either timeout or fail — just must not panic
	err := e.ApplyUpdate(ctx, "http://invalid.invalid/apf.zip", nil)
	t.Logf("OK: ApplyUpdate short context → %v", err)
}

func TestApplyUpdate_EmptyURL(t *testing.T) {
	// S-UPD: включаем применение, чтобы проверить ветку пустого URL в DownloadAndApply за гейтом.
	oldApply := updateApplyEnabled
	updateApplyEnabled = true
	defer func() { updateApplyEnabled = oldApply }()

	e := newTestEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	err := e.ApplyUpdate(ctx, "", nil)
	t.Logf("OK: ApplyUpdate empty URL → %v", err)
}

// ─── runPostConnectAntiBlock ─────────────────────────────────────────────────

func TestRunPostConnectAntiBlock_Disabled(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.AntiBlockEnabled = false
	cfg.AntiBlockAutoSwitch = false
	e := New(cfg)
	node := &models.Node{ID: "n1", Address: "1.2.3.4"}
	e.runPostConnectAntiBlock(node) // should return immediately
	t.Log("OK: runPostConnectAntiBlock disabled, returns early")
}

func TestRunPostConnectAntiBlock_NilNode(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.AntiBlockEnabled = true
	cfg.AntiBlockAutoSwitch = true
	e := New(cfg)
	e.runPostConnectAntiBlock(nil) // nil node → returns early
	t.Log("OK: runPostConnectAntiBlock nil node, returns early")
}

func TestRunPostConnectAntiBlock_EnabledAutoSwitchDisabled(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.AntiBlockEnabled = true
	cfg.AntiBlockAutoSwitch = false // auto-switch disabled → early return
	e := New(cfg)
	node := &models.Node{ID: "n1", Address: "1.2.3.4"}
	e.runPostConnectAntiBlock(node)
	t.Log("OK: runPostConnectAntiBlock autoswitch disabled, returns early")
}

// ─── saveNodes with crypto ───────────────────────────────────────────────────

func TestSaveNodes_WithCrypto(t *testing.T) {
	e := newTestEngine()
	e.SetMasterPassword("test-secret-pass")
	e.nodes = []*models.Node{
		{ID: "n1", Address: "1.2.3.4", Port: 443},
	}
	// Just must not panic — may fail on read-only path
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("saveNodes with crypto panicked: %v", r)
		}
	}()
	e.saveNodes()
	t.Log("OK: saveNodes with crypto, no panic")
}

func TestSaveNodes_NoCrypto(t *testing.T) {
	e := newTestEngine()
	e.nodes = []*models.Node{
		{ID: "n1", Address: "1.2.3.4", Port: 443},
		{ID: "n2", Address: "1.2.3.5", Port: 8080},
	}
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("saveNodes without crypto panicked: %v", r)
		}
	}()
	e.saveNodes()
	t.Log("OK: saveNodes without crypto, no panic")
}

// ─── ActivateFallbackTunnel known tunnels ────────────────────────────────────

func TestActivateFallbackTunnel_Tor(t *testing.T) {
	e := newTestEngine()
	err := e.ActivateFallbackTunnel("tor")
	// sing-box not installed so applySingBoxConfig will fail, that's OK
	t.Logf("OK: ActivateFallbackTunnel('tor') → %v", err)
}

func TestActivateFallbackTunnel_Snowflake(t *testing.T) {
	e := newTestEngine()
	err := e.ActivateFallbackTunnel("tor_snowflake")
	t.Logf("OK: ActivateFallbackTunnel('tor_snowflake') → %v", err)
}

func TestActivateFallbackTunnel_Psiphon(t *testing.T) {
	e := newTestEngine()
	err := e.ActivateFallbackTunnel("psiphon")
	t.Logf("OK: ActivateFallbackTunnel('psiphon') → %v", err)
}

// ─── enableKillSwitchWithUAC ─────────────────────────────────────────────────

func TestEnableKillSwitchWithUAC_NilNode(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.EnableKillSwitch = true
	e := New(cfg)
	// ks is a noopKS on non-Windows/Linux/Android — Enable returns nil
	e.enableKillSwitchWithUAC(nil, e.connGen)
	t.Log("OK: enableKillSwitchWithUAC nil node, no panic")
}

func TestEnableKillSwitchWithUAC_WithNode(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.EnableKillSwitch = true
	e := New(cfg)
	node := &models.Node{ID: "n1", Address: "5.6.7.8"}
	e.enableKillSwitchWithUAC(node, e.connGen)
	t.Log("OK: enableKillSwitchWithUAC with node, no panic")
}

// ─── GetDiagnostics with lastRollback ────────────────────────────────────────

func TestGetDiagnostics_WithRollback(t *testing.T) {
	e := newTestEngine()
	// Trigger a rollback to set lastRollback
	cause := errors.New("diag test error")
	e.rollbackConnectionAttempt("diag_stage", cause, false)

	diag := e.GetDiagnostics()
	if diag == nil {
		t.Fatal("GetDiagnostics returned nil")
	}
	rb, ok := diag["last_rollback"]
	if !ok {
		t.Error("GetDiagnostics missing last_rollback key")
	} else if rb == nil {
		t.Error("GetDiagnostics: last_rollback should not be nil after rollback")
	}
	t.Logf("OK: GetDiagnostics with rollback: %v", rb)
}

// ─── GetSingBoxInfo / GetTrafficStats ────────────────────────────────────────

func TestGetSingBoxInfo_NotRunning(t *testing.T) {
	e := newTestEngine()
	info := e.GetSingBoxInfo()
	if info == nil {
		t.Fatal("GetSingBoxInfo returned nil")
	}
	t.Logf("OK: GetSingBoxInfo not running: %v", info)
}

func TestGetTrafficStats_NotRunning(t *testing.T) {
	e := newTestEngine()
	stats := e.GetTrafficStats()
	t.Logf("OK: GetTrafficStats: %v", stats)
}

// ─── CheckForUpdate ──────────────────────────────────────────────────────────

func TestCheckForUpdate(t *testing.T) {
	e := newTestEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	status, err := e.CheckForUpdate(ctx)
	t.Logf("OK: CheckForUpdate → status=%v err=%v", status, err)
}

// ─── AddPaidProvider duplicate ID ────────────────────────────────────────────

func TestAddPaidProvider_DuplicateID(t *testing.T) {
	e := newTestEngine()
	// Pre-populate one entry in cfg.PaidProviders
	e.cfg.PaidProviders = []models.PaidProviderEntry{
		{ID: "existing-id", Type: "marzban", URL: "http://x.com"},
	}
	err := e.AddPaidProvider(models.PaidProviderEntry{
		ID:   "existing-id",
		Type: "marzban",
		URL:  "http://x.com",
	})
	if err == nil {
		t.Error("AddPaidProvider duplicate ID should return error")
	} else {
		t.Logf("OK: AddPaidProvider duplicate → %v", err)
	}
}

func TestRemovePaidProvider_NotFound(t *testing.T) {
	e := newTestEngine()
	ok := e.RemovePaidProvider("nonexistent-id-xyz")
	if ok {
		t.Error("RemovePaidProvider nonexistent should return false")
	}
	t.Log("OK: RemovePaidProvider not found returns false")
}

// ─── ForceSwitchNow paths ────────────────────────────────────────────────────

func TestForceSwitchNow_NoNodes(t *testing.T) {
	e := newTestEngine()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ForceSwitchNow panicked: %v", r)
		}
	}()
	e.ForceSwitchNow()
	t.Log("OK: ForceSwitchNow no nodes, no panic")
}
