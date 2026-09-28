// engine_p0_2_ks_probe_warning_test.go — P0-2 (ТЗ v1.6, живой прогон ПК 09-14): тесты детектора
// «Kill Switch активен + подключены на Windows ⇒ трафик-проба узлов лживо провалит ВСЕ узлы,
// кроме активного» (см. память apf-killswitch-blocks-traffic-probe-windows.md и комментарий у
// computeKillSwitchProbeWarning/killSwitchEnabledNow в node_check.go).
//
// Полностью офлайн и детерминированно: KS-бэкенд — fake (routedKS/blockingKS, уже определены в
// engine_r1_r4_test.go для тестов currentKS()/ksCall — переиспользуются как есть, без
// дублирования), проба узлов — fake e.probeFn (тот же приём, что весь node_check_test.go).
// Никакого реального sing-box/netsh/WFP; execCmdFn/netsh здесь вообще не задействуются, потому
// что routedKS/blockingKS — чистые Go-моки, не настоящие windowsKS/wfpKS.
package engine

import (
	"context"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/killswitch"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ksProbeWarnEngine — общий стенд для этого файла: newTestEngine() (тот же полный e.ctx/e.wg/
// checkMu каркас, которым пользуется весь node_check_test.go) плюс управляемые platform/
// connected/KS-enabled оси решётки из ТЗ лота.
func ksProbeWarnEngine(t *testing.T, goos string, connected bool, ksEnabled bool) *Engine {
	t.Helper()
	e := newTestEngine()
	e.directProbeGOOS = goos // probeGOOS() seam, тот же приём что node_check_test.go:334
	e.state.Connected = connected
	e.ks = &routedKS{caps: killswitch.Capabilities{ProxyMode: true, TunMode: true}, enabled: ksEnabled}
	return e
}

// ─── Решётка (decision matrix) из ТЗ лота: computeKillSwitchProbeWarning ──────────────────────

func TestKSProbeWarning_WindowsConnectedEnabled_Warns(t *testing.T) {
	e := ksProbeWarnEngine(t, "windows", true, true)
	got := e.computeKillSwitchProbeWarning()
	if got == "" {
		t.Fatal("computeKillSwitchProbeWarning() = \"\", want непустое предупреждение (windows+connected+KS-on)")
	}
	if got != killSwitchProbeWarningText {
		t.Errorf("текст предупреждения разошёлся с константой killSwitchProbeWarningText: %q", got)
	}
}

func TestKSProbeWarning_WindowsConnectedDisabled_NoWarning(t *testing.T) {
	e := ksProbeWarnEngine(t, "windows", true, false)
	if got := e.computeKillSwitchProbeWarning(); got != "" {
		t.Fatalf("computeKillSwitchProbeWarning() = %q, want \"\" (Kill Switch выключен)", got)
	}
}

func TestKSProbeWarning_WindowsNotConnectedEnabled_NoWarning(t *testing.T) {
	e := ksProbeWarnEngine(t, "windows", false, true)
	if got := e.computeKillSwitchProbeWarning(); got != "" {
		t.Fatalf("computeKillSwitchProbeWarning() = %q, want \"\" (не подключены — allow-список не сужен до одного endpoint, проба идёт egress хоста)", got)
	}
}

func TestKSProbeWarning_AndroidConnectedEnabled_NoWarning(t *testing.T) {
	e := ksProbeWarnEngine(t, "android", true, true)
	if got := e.computeKillSwitchProbeWarning(); got != "" {
		t.Fatalf("computeKillSwitchProbeWarning() = %q, want \"\" (Android KS — VpnService, per-endpoint allow не делает)", got)
	}
}

// Не входит в обязательную решётку ТЗ, но подтверждает, что детектор специфичен именно Windows
// (память: «это ЧИСТО Windows-дефект»), а не «любая не-Android платформа».
func TestKSProbeWarning_LinuxConnectedEnabled_NoWarning(t *testing.T) {
	e := ksProbeWarnEngine(t, "linux", true, true)
	if got := e.computeKillSwitchProbeWarning(); got != "" {
		t.Fatalf("computeKillSwitchProbeWarning() = %q, want \"\" (детектор гейтится probeGOOS()==\"windows\")", got)
	}
}

// ─── killSwitchEnabledNow: fallback без чистого хендла + hang-guard ───────────────────────────

// e.ks == nil не встречается в проде (New()/NewServiceHost всегда его ставят), но killSwitchEnabledNow
// обязан не паниковать и падать на cfg.EnableKillSwitch — ровно fallback, который ТЗ лота считает
// допустимым при отсутствии чистого хендла к менеджеру.
func TestKillSwitchEnabledNow_NilBackendFallsBackToConfig(t *testing.T) {
	e := newTestEngine()
	e.ks = nil

	e.cfg.EnableKillSwitch = true
	if !e.killSwitchEnabledNow() {
		t.Error("killSwitchEnabledNow() = false при e.ks==nil и cfg.EnableKillSwitch=true, want true (fallback)")
	}

	e.cfg.EnableKillSwitch = false
	if e.killSwitchEnabledNow() {
		t.Error("killSwitchEnabledNow() = true при e.ks==nil и cfg.EnableKillSwitch=false, want false")
	}
}

// TestKillSwitchEnabledNow_HungBackendTreatedAsFalse — зависший бэкенд (blockingKS — тот же мок,
// которым engine_r1_r4_test.go имитирует зависший BFE/WFP-вызов у currentKS()) обязан:
//  1. не повесить вызывающего дольше ksProbeTimeout (иначе StartNodeCheck зависал бы вместе с ним —
//     ровно риск, которого этот лот обязан избежать, см. ASSUMPTIONS в result.md);
//  2. трактоваться как "не знаю" → false, а не как "включён" — честнее промолчать, чем добавить
//     предупреждение поверх уже сломанного (зависшего) Kill Switch.
func TestKillSwitchEnabledNow_HungBackendTreatedAsFalse(t *testing.T) {
	orig := ksProbeTimeout
	ksProbeTimeout = 30 * time.Millisecond
	defer func() { ksProbeTimeout = orig }()

	// block намеренно не закрывается (см. комментарий у blockingKS в engine_r1_r4_test.go) —
	// внутренняя горутина ksIsEnabledWithTimeout остаётся висеть сама по себе, как и в
	// TestCurrentKS_SelfHealsWhenIsEnabledHangs; killSwitchEnabledNow всё равно обязан вернуться.
	stuck := &blockingKS{caps: killswitch.Capabilities{ProxyMode: true}, block: make(chan struct{})}
	e := newTestEngine()
	e.ks = stuck

	start := time.Now()
	got := e.killSwitchEnabledNow()
	elapsed := time.Since(start)

	if got {
		t.Error("killSwitchEnabledNow() = true на зависшем бэкенде, want false")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("killSwitchEnabledNow() занял %v — ksProbeTimeout не сработал", elapsed)
	}
}

// StartNodeCheck поверх зависшего KS-бэкенда обязан вернуться быстро и запустить пробу (пусть и
// без предупреждения, раз состояние KS не удалось узнать) — а не заблокироваться на неопределённое
// время. Это конкретно тот регресс, которого боится ASSUMPTIONS-раздел result.md: "новая
// синхронная проверка в StartNodeCheck не должна стать НОВЫМ способом подвесить сканирование".
func TestStartNodeCheck_HungKSBackendDoesNotBlockScanStart(t *testing.T) {
	withTempDataDir(t)
	orig := ksProbeTimeout
	ksProbeTimeout = 30 * time.Millisecond
	defer func() { ksProbeTimeout = orig }()

	e := newTestEngine()
	e.cfg.Sources = nil
	e.directProbeGOOS = "windows"
	e.state.Connected = true
	e.ks = &blockingKS{caps: killswitch.Capabilities{ProxyMode: true}, block: make(chan struct{})}

	setProbePool(e, []*models.Node{tcpAliveNode("a")})
	e.probeFn = func(ctx context.Context, node *models.Node, slot int) (int64, string, string, error) {
		return 1, "US", "203.0.113.9", nil
	}

	start := time.Now()
	err := e.StartNodeCheck(NodeCheckOptions{TopN: 1, TargetK: 1, Concurrency: 1, PerNode: time.Second})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("StartNodeCheck: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("StartNodeCheck занял %v на зависшем KS-бэкенде — обязан вернуться быстро (bounded by ksProbeTimeout)", elapsed)
	}

	st := waitNodeCheckDone(t, e, 5*time.Second)
	if st.Phase != "done" {
		t.Fatalf("phase = %q, want done — зависший KS-бэкенд не должен срывать пробу", st.Phase)
	}
	if st.KillSwitchWarning != "" {
		t.Errorf("KillSwitchWarning = %q, want \"\" — состояние KS не удалось узнать (hung), предупреждать нечестно", st.KillSwitchWarning)
	}
}

// ─── Интеграция со StartNodeCheck: снимок несёт предупреждение с первого опроса, скан НЕ прерван ──

// TestStartNodeCheck_FirstStatusPollCarriesWarning — ТЗ: "вычисляется синхронно, ДО async
// goTracked(runNodeCheck), чтобы САМЫЙ ПЕРВЫЙ NodeCheckStatus() уже нёс предупреждение". Пробер
// намеренно блокируется до сигнала теста, чтобы опрос гарантированно попал ДО завершения прогона.
func TestStartNodeCheck_FirstStatusPollCarriesWarning(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.Sources = nil
	e.directProbeGOOS = "windows"
	e.state.Connected = true
	e.ks = &routedKS{caps: killswitch.Capabilities{ProxyMode: true, TunMode: true}, enabled: true}

	setProbePool(e, []*models.Node{tcpAliveNode("a"), tcpAliveNode("b")})
	release := make(chan struct{})
	defer close(release)
	e.probeFn = func(ctx context.Context, node *models.Node, slot int) (int64, string, string, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return 1, "US", "203.0.113.9", nil
	}

	if err := e.StartNodeCheck(NodeCheckOptions{TopN: 2, TargetK: 2, Concurrency: 2, PerNode: 5 * time.Second}); err != nil {
		t.Fatalf("StartNodeCheck: %v", err)
	}

	st := e.NodeCheckStatus() // самый первый опрос сразу после возврата StartNodeCheck
	if !st.Running {
		t.Fatal("ожидался Running=true сразу после StartNodeCheck")
	}
	if st.KillSwitchWarning == "" {
		t.Fatal("KillSwitchWarning пуст на самом первом опросе — ожидалось, что он выставлен синхронно, ДО async-части")
	}

	e.CancelNodeCheck()
	waitNodeCheckDone(t, e, 5*time.Second)
}

// TestStartNodeCheck_WarningDoesNotAbortScan — вариант "a" ТЗ: предупреждение НЕ должно
// останавливать/отменять прогон. StartNodeCheck возвращает nil, проба доходит до "done" как
// обычно (вариант "b" — auto-suspend-KS — отклонён и намеренно не реализован).
func TestStartNodeCheck_WarningDoesNotAbortScan(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.Sources = nil
	e.directProbeGOOS = "windows"
	e.state.Connected = true
	e.ks = &routedKS{caps: killswitch.Capabilities{ProxyMode: true, TunMode: true}, enabled: true}

	nodes := []*models.Node{tcpAliveNode("a"), tcpAliveNode("b"), tcpAliveNode("c")}
	setProbePool(e, nodes)
	e.probeFn = func(ctx context.Context, node *models.Node, slot int) (int64, string, string, error) {
		return 1, "US", "203.0.113.9", nil
	}

	if err := e.StartNodeCheck(NodeCheckOptions{TopN: 3, TargetK: 3, Concurrency: 2, PerNode: time.Second}); err != nil {
		t.Fatalf("StartNodeCheck вернул ошибку — предупреждение не должно блокировать сканирование: %v", err)
	}
	st := waitNodeCheckDone(t, e, 5*time.Second)
	if st.Phase != "done" {
		t.Fatalf("phase = %q, want done — предупреждение не должно прерывать прогон", st.Phase)
	}
	if st.KillSwitchWarning == "" {
		t.Error("итоговый снимок потерял KillSwitchWarning — поле должно сохраняться до конца прогона (finishNodeCheck мутирует поля точечно)")
	}
	if st.Probed != 3 || st.Verified != 3 {
		t.Fatalf("probed=%d verified=%d, want 3/3 — проба обязана реально пройти по всем узлам несмотря на предупреждение", st.Probed, st.Verified)
	}
}

// TestStartNodeCheck_BusyPathReturnsBusyRegardlessOfWarning — вычисление предупреждения (чистое
// чтение вне checkMu) не должно нарушать однопоточность busy-гейта: конкурентная "уже идёт"
// попытка обязана получить ErrNodeCheckBusy.
func TestStartNodeCheck_BusyPathReturnsBusyRegardlessOfWarning(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.Sources = nil
	e.directProbeGOOS = "windows"
	e.state.Connected = true
	e.ks = &routedKS{caps: killswitch.Capabilities{ProxyMode: true, TunMode: true}, enabled: true}

	setProbePool(e, []*models.Node{tcpAliveNode("a")})
	block := make(chan struct{})
	defer close(block)
	e.probeFn = func(ctx context.Context, node *models.Node, slot int) (int64, string, string, error) {
		select {
		case <-block:
		case <-ctx.Done():
		}
		return 1, "US", "203.0.113.9", nil
	}

	if err := e.StartNodeCheck(NodeCheckOptions{TopN: 1, TargetK: 1, Concurrency: 1, PerNode: 5 * time.Second}); err != nil {
		t.Fatalf("первый StartNodeCheck: %v", err)
	}
	if err := e.StartNodeCheck(NodeCheckOptions{TopN: 1, TargetK: 1, Concurrency: 1, PerNode: time.Second}); err != ErrNodeCheckBusy {
		t.Fatalf("второй StartNodeCheck = %v, want ErrNodeCheckBusy", err)
	}

	e.CancelNodeCheck()
	waitNodeCheckDone(t, e, 5*time.Second)
}
