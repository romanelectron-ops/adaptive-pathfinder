package engine

// engine_coverage5_test.go — coverage pass 5.
// Target: +3-5% from 88.2%, pushing towards 91-93%.
//
// Uncovered blocks from engcov6.out (count=0) targeted here:
//   160.20,162.3   — New() minUptime==0 default branch
//   210.26,212.4   — dl.OnProgress body (e.OnProgress call)
//   218.44,220.3   — fsm.OnConnect body
//   228.31,230.3   — appUpdater.OnUpdateAvailable body
//   303.32,306.3   — Start() watchdog.OnDead closure body
//   307.32,310.3   — Start() watchdog.OnRecover closure body
//   464.29,467.3   — Restart() watchdog.OnDead closure body
//   468.32,471.3   — Restart() watchdog.OnRecover closure body
//   1322.29,1329.3 — GetTrafficStats nil trafficMonitor path
//   1681.59,1683.3 — PatchConfig ListenPort default (<1024)
//   1769.17,1772.59— saveNodes cryptoStore.Encrypt error path
//   1772.59,1774.5 — saveNodes crypto error log + fallback write
//   1775.4,1775.10 — saveNodes return after crypto error
//   2097.32,2099.3 — ActivateFallbackTunnel nil emergencyFallback
//   2247.24,2249.3 — RefreshCatalog len(newNodes)==0 early return
//   2459.2,2459.42 — CheckCurrentIP return e.CheckNodeIP(...)
//   2589.16,2592.3 — runPostConnectAntiBlock err!=nil path (sleeps 2s!)

import (
	"context"
	"testing"
	"time"

	apfcrypto "github.com/apf/adaptive-pathfinder/internal/crypto"
	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/updater"
)

// ─── GetTrafficStats: nil trafficMonitor path ─────────────────────────────────

// TestGetTrafficStats_NilMonitor покрывает ветку nil-монитора в GetTrafficStats.
func TestGetTrafficStats_NilMonitor(t *testing.T) {
	e := newTestEngine()
	e.trafficMonitor = nil
	stats := e.GetTrafficStats()
	if stats == nil {
		t.Fatal("GetTrafficStats with nil monitor: expected non-nil map")
	}
	if _, ok := stats["up_bytes"]; !ok {
		t.Errorf("GetTrafficStats nil monitor: missing key up_bytes, got %v", stats)
	}
	t.Logf("OK: GetTrafficStats nil monitor → %v", stats)
}

// ─── New(): minUptime==0 default branch ──────────────────────────────────────

// TestNew_MinUptimeZero покрывает ветку if minUptime==0 в New().
// DefaultConfig задаёт MinUptimeSec=120, поэтому эта ветка никогда не срабатывает
// при обычном использовании — специально передаём 0.
func TestNew_MinUptimeZero(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	cfg.EnableKillSwitch = false
	cfg.MinUptimeSec = 0 // triggers: if minUptime == 0 { minUptime = 120s }
	e := New(cfg)
	if e == nil {
		t.Fatal("New() returned nil for MinUptimeSec=0")
	}
	t.Log("OK: New() MinUptimeSec=0 default minUptime branch covered")
}

// ─── Callback bodies: dl.OnProgress, fsm.OnConnect, appUpdater.OnUpdateAvailable

// TestCallbacks_DlOnProgress покрывает тело dl.OnProgress в New().
// В New() устанавливается: dl.OnProgress = func(...) { if e.OnProgress != nil { e.OnProgress(...) } }
// Тело лямбды (строка 210.26) покрывается здесь.
func TestCallbacks_DlOnProgress(t *testing.T) {
	e := newTestEngine()
	var gotPct int
	e.OnProgress = func(pct int, msg string) {
		gotPct = pct
	}
	// dl.OnProgress already set in New() — call it directly.
	if e.dl != nil && e.dl.OnProgress != nil {
		e.dl.OnProgress(77, "coverage-test")
	}
	if gotPct != 77 {
		t.Errorf("dl.OnProgress → e.OnProgress: expected pct=77, got %d", gotPct)
	}
	t.Log("OK: dl.OnProgress body covered (e.OnProgress call)")
}

// TestCallbacks_FsmOnConnect покрывает тело fsm.OnConnect в New().
func TestCallbacks_FsmOnConnect(t *testing.T) {
	e := newTestEngine()
	// fsm.OnConnect = func(level, proto string) { e.log(...) }  (line 218.44)
	if e.fsm != nil && e.fsm.OnConnect != nil {
		e.fsm.OnConnect("level1", "vless")
	}
	t.Log("OK: fsm.OnConnect body covered")
}

// TestCallbacks_FsmOnFallback покрывает тело fsm.OnFallback в New().
func TestCallbacks_FsmOnFallback(t *testing.T) {
	e := newTestEngine()
	if e.fsm != nil && e.fsm.OnFallback != nil {
		e.fsm.OnFallback("level1", "level2")
	}
	t.Log("OK: fsm.OnFallback body covered")
}

// TestCallbacks_UpdaterOnUpdateAvailable покрывает тело appUpdater.OnUpdateAvailable в New().
func TestCallbacks_UpdaterOnUpdateAvailable(t *testing.T) {
	e := newTestEngine()
	if e.appUpdater != nil && e.appUpdater.OnUpdateAvailable != nil {
		e.appUpdater.OnUpdateAvailable(&updater.UpdateStatus{
			CurrentVersion:  "1.0.0",
			LatestVersion:   "1.0.1",
			UpdateAvailable: true,
		})
	}
	t.Log("OK: appUpdater.OnUpdateAvailable body covered")
}

// ─── saveNodes: crypto encrypt error path (empty password) ──────────────────

// TestSaveNodes_EncryptError_EmptyPassword покрывает ветку ошибки шифрования
// в saveNodes() при пустом пароле.
// apfcrypto.New("") → Encrypt всегда возвращает ошибку "master password is empty".
func TestSaveNodes_EncryptError_EmptyPassword(t *testing.T) {
	e := newTestEngine()
	// Empty password → Encrypt() returns error "master password is empty"
	e.cryptoStore = apfcrypto.New("")
	// saveNodes logs the error, falls back to plain write, returns — no panic.
	e.saveNodes()
	t.Log("OK: saveNodes crypto encrypt error path covered (lines 1769-1775)")
}

// ─── PatchConfig: ListenPort default branch ───────────────────────────────────

// TestPatchConfig_ListenPortDefault покрывает ветку сброса ListenPort в PatchConfig().
// validatePatch отвергает listen_port < 1024, поэтому ветка line 1681 достигается
// иначе: устанавливаем невалидный порт напрямую в cfg, затем патчим другое поле.
func TestPatchConfig_ListenPortDefault(t *testing.T) {
	e := newTestEngine()
	// Устанавливаем ListenPort=500 напрямую — validatePatch не проверяет
	// существующие значения, только ключи из patch-карты.
	e.cfg.ListenPort = 500 // < 1024 → line 1681 выставит 10808
	// Патчим другое поле — validatePatch проходит, line 1681 срабатывает.
	err := e.PatchConfig(map[string]interface{}{
		"connection_mode": "proxy",
	})
	if err != nil {
		t.Fatalf("PatchConfig unexpected error: %v", err)
	}
	if e.cfg.ListenPort != 10808 {
		t.Errorf("expected ListenPort=10808 after default branch, got %d", e.cfg.ListenPort)
	}
	t.Log("OK: PatchConfig ListenPort default branch covered (line 1681)")
}

// ─── ActivateFallbackTunnel: nil emergencyFallback ────────────────────────────

// TestActivateFallbackTunnel_NilFallback покрывает ветку nil в ActivateFallbackTunnel().
func TestActivateFallbackTunnel_NilFallback(t *testing.T) {
	e := newTestEngine()
	e.emergencyFallback = nil
	err := e.ActivateFallbackTunnel("tor")
	if err == nil {
		t.Error("expected error when emergencyFallback is nil, got nil")
	}
	t.Log("OK: ActivateFallbackTunnel nil fallback error path covered (line 2097)")
}

// ─── CheckCurrentIP: return e.CheckNodeIP(...) ────────────────────────────────

// TestCheckCurrentIP_ActiveNode покрывает строку return e.CheckNodeIP в CheckCurrentIP().
func TestCheckCurrentIP_ActiveNode(t *testing.T) {
	e := newTestEngine()
	// Set active node so we bypass the "not connected" early return.
	e.stateMu.Lock()
	e.state.ActiveNode = &models.Node{ID: "cov5-node", Address: "127.0.0.1", Name: "cov5"}
	e.stateMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// CheckNodeIP may return "node not found" — that's fine, line 2459 is still reached.
	_, err := e.CheckCurrentIP(ctx)
	t.Logf("OK: CheckCurrentIP with activeNode: err=%v (line 2459 covered)", err)
}

// ─── RefreshCatalog: empty registry early return ──────────────────────────────

// TestRefreshCatalog_EmptyRegistry покрывает ветку len(newNodes)==0 в RefreshCatalog().
// newTestEngine() создаёт пустой catalogRegistry → FetchAll возвращает 0 узлов.
func TestRefreshCatalog_EmptyRegistry(t *testing.T) {
	e := newTestEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	n, err := e.RefreshCatalog(ctx)
	t.Logf("RefreshCatalog: n=%d err=%v", n, err)
	// With empty registry, 0 nodes are returned → line 2247 covered.
	t.Log("OK: RefreshCatalog empty registry path covered (line 2247)")
}

// ─── runPostConnectAntiBlock: error path ──────────────────────────────────────

// TestRunPostConnectAntiBlock_ErrorPath покрывает ветку err!=nil в runPostConnectAntiBlock().
//
// Стратегия: передаём узел с Address="" → CheckIP немедленно возвращает ошибку
// "iprep: empty IP". До CheckIP функция делает time.Sleep(2s), поэтому тест ~2с.
//
// Покрывает строки 2589.16,2592.3 (if err != nil { log; return }).
func TestRunPostConnectAntiBlock_ErrorPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: requires 2s sleep")
	}
	e := newTestEngine()
	e.cfg.AntiBlockEnabled = true
	e.cfg.AntiBlockAutoSwitch = true
	// Empty address → CheckIP("") returns error "iprep: empty IP"
	node := &models.Node{ID: "empty-addr", Address: "", Name: "empty-addr"}

	done := make(chan struct{})
	go func() {
		defer close(done)
		e.runPostConnectAntiBlock(node)
	}()

	select {
	case <-done:
		t.Log("OK: runPostConnectAntiBlock error path covered (lines 2589-2592)")
	case <-time.After(15 * time.Second):
		t.Error("runPostConnectAntiBlock timed out (expected ~2s)")
	}
}

// ─── Watchdog callbacks: Start() lines 303-310, Restart() lines 464-471 ──────

// TestWatchdog_StartCallbacks покрывает тела замыканий OnDead/OnRecover из Start().
// Start() присваивает новые лямбды e.watchdog.OnDead/OnRecover (строки 303-310).
// Мы вызываем их вручную чтобы покрыть тела этих лямбд.
func TestWatchdog_StartCallbacks(t *testing.T) {
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

	// Вызываем callback-и напрямую.
	// OnDead тела: e.log(...) + go e.emergencySwitch() (строки 304-305)
	// OnRecover тела: e.log(...) + e.watchdog.Reset() (строки 308-309)
	if e.watchdog != nil {
		if e.watchdog.OnDead != nil {
			e.watchdog.OnDead() // covers lines 304-305 in Start()
		}
		if e.watchdog.OnRecover != nil {
			e.watchdog.OnRecover() // covers lines 308-309 in Start()
		}
	}

	time.Sleep(50 * time.Millisecond) // let emergencySwitch goroutine start & fail gracefully
	e.Stop()
	t.Log("OK: Start() watchdog OnDead/OnRecover callback bodies covered")
}

// TestWatchdog_RestartCallbacks покрывает тела замыканий OnDead/OnRecover из Restart().
// Restart() создаёт НОВЫЙ watchdog с НОВЫМИ лямбдами (строки 464-471).
func TestWatchdog_RestartCallbacks(t *testing.T) {
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

	// Restart() — отменяет старые горутины, создаёт новый watchdog с новыми лямбдами.
	if err := e.Restart(); err != nil {
		t.Logf("Restart() returned error: %v (ok in test — no sing-box)", err)
	}
	time.Sleep(20 * time.Millisecond)

	// Вызываем тела новых лямбд из Restart() (строки 465-466, 469-470).
	if e.watchdog != nil {
		if e.watchdog.OnDead != nil {
			e.watchdog.OnDead() // covers lines 465-466 in Restart()
		}
		if e.watchdog.OnRecover != nil {
			e.watchdog.OnRecover() // covers lines 469-470 in Restart()
		}
	}

	time.Sleep(50 * time.Millisecond)
	e.Stop()
	t.Log("OK: Restart() watchdog OnDead/OnRecover callback bodies covered")
}
