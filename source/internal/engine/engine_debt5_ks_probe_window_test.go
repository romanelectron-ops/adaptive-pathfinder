// engine_debt5_ks_probe_window_test.go — долг-5 (2026-09-21, см. память
// apf-killswitch-blocks-traffic-probe-windows.md): openKSProbeWindow открывает узкое временное окно
// сквозь активный Windows Kill Switch на время трафик-пробы скана и ГАРАНТИРОВАННО его закрывает
// (defer в probeCandidates); при успехе снимает ложное предупреждение P0-2, при невозможности —
// оставляет его. Полностью офлайн: KS — Go-мок (routedKS + ProbeAllower), проба — e.probeFn.
// Реального netsh/WFP/sing-box нет. Дополняет решётку P0-2 из engine_p0_2_ks_probe_warning_test.go
// (тот проверял только предупреждение; здесь — сам enforcement-фикс).
package engine

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/killswitch"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// probeAllowerKS — routedKS (полный killswitch.KillSwitch) + ProbeAllower с записью вызовов.
// Вызовы идут из ОДНОЙ горутины runNodeCheck (openKSProbeWindow — до пула воркеров, cleanup — по
// defer после workers.Wait()), плюс синхронизация через ksCall (канал) и checkMu — гонки на полях
// нет; тесты читают их только после waitNodeCheckDone (happens-after через checkMu).
type probeAllowerKS struct {
	*routedKS
	allowCalls [][]string
	clearCalls int
	allowErr   error
}

func newProbeAllowerKS(enabled bool) *probeAllowerKS {
	return &probeAllowerKS{routedKS: &routedKS{caps: killswitch.Capabilities{ProxyMode: true, TunMode: true}, enabled: enabled}}
}

func (k *probeAllowerKS) AllowProbeTargets(ips []string) error {
	k.allowCalls = append(k.allowCalls, append([]string{}, ips...))
	return k.allowErr
}
func (k *probeAllowerKS) ClearProbeTargets() error { k.clearCalls++; return nil }

func setProbeWarning(e *Engine, s string) {
	e.checkMu.Lock()
	e.checkStatus.KillSwitchWarning = s
	e.checkMu.Unlock()
}

// ─── probeCandidateIPs ────────────────────────────────────────────────────────

func TestProbeCandidateIPs_DedupBareIPsSkipGarbage(t *testing.T) {
	nodes := []*models.Node{
		{Address: "203.0.113.7"},
		{Address: "203.0.113.7"}, // дубль → один раз
		{Address: "2001:db8::1"},
		nil,                        // nil-узел пропускается
		{Address: "  198.51.100.9  "}, // пробелы обрезаются
		{Address: ""},              // пусто пропускается
		{Address: "not-an-ip-and-wont-resolve.invalid"}, // .invalid по RFC не резолвится → пропуск
	}
	got := probeCandidateIPs(nodes)
	set := map[string]bool{}
	for _, ip := range got {
		set[ip] = true
	}
	for _, want := range []string{"203.0.113.7", "2001:db8::1", "198.51.100.9"} {
		if !set[want] {
			t.Errorf("probeCandidateIPs потерял %q, got %v", want, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("ожидалось 3 уникальных IP, got %d (%v)", len(got), got)
	}
}

// ─── openKSProbeWindow: решётка ветвей ────────────────────────────────────────

// Windows + KS-on + бэкенд с ProbeAllower + кандидатов ≤ потолка → окно открывается, IP переданы,
// ложное предупреждение снято; возвращённый cleanup закрывает окно.
func TestOpenKSProbeWindow_OpensClearsWarning_CleanupCloses(t *testing.T) {
	e := newTestEngine()
	e.directProbeGOOS = "windows"
	e.state.Connected = true
	ks := newProbeAllowerKS(true)
	e.ks = ks
	setProbeWarning(e, killSwitchProbeWarningText) // как будто P0-2 выставил на старте

	cleanup := e.openKSProbeWindow([]*models.Node{{Address: "203.0.113.7"}, {Address: "198.51.100.9"}})
	if cleanup == nil {
		t.Fatal("openKSProbeWindow=nil, ожидалось открытие окна (windows+KS-on+ProbeAllower+≤потолка)")
	}
	if len(ks.allowCalls) != 1 {
		t.Fatalf("AllowProbeTargets вызван %d раз, want 1", len(ks.allowCalls))
	}
	if len(ks.allowCalls[0]) != 2 {
		t.Errorf("AllowProbeTargets получил %d IP, want 2: %v", len(ks.allowCalls[0]), ks.allowCalls[0])
	}
	if w := e.NodeCheckStatus().KillSwitchWarning; w != "" {
		t.Errorf("KillSwitchWarning=%q, want \"\" (окно открыто → проба честна)", w)
	}
	if ks.clearCalls != 0 {
		t.Errorf("ClearProbeTargets вызван %d раз ДО cleanup, want 0", ks.clearCalls)
	}
	cleanup()
	if ks.clearCalls == 0 {
		t.Error("cleanup не вызвал ClearProbeTargets — окно не закрыто")
	}
}

// Бэкенд без ProbeAllower (routedKS) → окно не открыть, честное предупреждение восстановлено.
func TestOpenKSProbeWindow_NoProbeAllower_DegradesWithWarning(t *testing.T) {
	e := newTestEngine()
	e.directProbeGOOS = "windows"
	e.state.Connected = true
	e.ks = &routedKS{caps: killswitch.Capabilities{ProxyMode: true}, enabled: true}
	setProbeWarning(e, "") // предупреждения ещё нет

	if cleanup := e.openKSProbeWindow([]*models.Node{{Address: "203.0.113.7"}}); cleanup != nil {
		t.Fatal("ожидался nil: routedKS не реализует ProbeAllower (WFP/VPN-режим) — деградация")
	}
	if w := e.NodeCheckStatus().KillSwitchWarning; w != killSwitchProbeWarningText {
		t.Errorf("KillSwitchWarning=%q, want честный текст P0-2 (деградация оставляет предупреждение)", w)
	}
}

// Кандидатов больше потолка (режим «Все рабочие») → окно не открываем (дешёвая отсечка ДО резолва),
// AllowProbeTargets не зовём, предупреждение стоит.
func TestOpenKSProbeWindow_TooManyCandidates_Degrades(t *testing.T) {
	e := newTestEngine()
	e.directProbeGOOS = "windows"
	e.state.Connected = true
	ks := newProbeAllowerKS(true)
	e.ks = ks

	nodes := make([]*models.Node, maxProbeAllowIPs+1)
	for i := range nodes {
		nodes[i] = &models.Node{Address: fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256)}
	}
	if cleanup := e.openKSProbeWindow(nodes); cleanup != nil {
		t.Fatal("ожидался nil при кандидатах > потолка (netsh не потянет тысячи remoteip)")
	}
	if len(ks.allowCalls) != 0 {
		t.Errorf("AllowProbeTargets не должен вызываться при > потолка, вызван %d раз", len(ks.allowCalls))
	}
	if w := e.NodeCheckStatus().KillSwitchWarning; w != killSwitchProbeWarningText {
		t.Errorf("KillSwitchWarning=%q, want честный текст P0-2", w)
	}
}

// Ошибка AllowProbeTargets → откат (ClearProbeTargets), nil, предупреждение восстановлено.
func TestOpenKSProbeWindow_AllowError_RollsBackAndWarns(t *testing.T) {
	e := newTestEngine()
	e.directProbeGOOS = "windows"
	e.state.Connected = true
	ks := newProbeAllowerKS(true)
	ks.allowErr = fmt.Errorf("netsh boom")
	e.ks = ks
	setProbeWarning(e, "")

	if cleanup := e.openKSProbeWindow([]*models.Node{{Address: "203.0.113.7"}}); cleanup != nil {
		t.Fatal("ожидался nil при ошибке AllowProbeTargets")
	}
	if ks.clearCalls == 0 {
		t.Error("ошибка AllowProbeTargets должна откатываться ClearProbeTargets (снять частичное)")
	}
	if w := e.NodeCheckStatus().KillSwitchWarning; w != killSwitchProbeWarningText {
		t.Errorf("KillSwitchWarning=%q, want честный текст P0-2 (окно не открылось)", w)
	}
}

// Не-Windows → окно не открывается (Android-KS — OS-level, per-endpoint allow не делает).
func TestOpenKSProbeWindow_NonWindows_Nil(t *testing.T) {
	e := newTestEngine()
	e.directProbeGOOS = "android"
	e.state.Connected = true
	ks := newProbeAllowerKS(true)
	e.ks = ks
	if cleanup := e.openKSProbeWindow([]*models.Node{{Address: "203.0.113.7"}}); cleanup != nil {
		t.Fatal("на не-Windows окно не открывается")
	}
	if len(ks.allowCalls) != 0 {
		t.Error("AllowProbeTargets не должен вызываться на не-Windows")
	}
}

// KS выключен → окна нет и предупреждения нет (проба идёт egress хоста напрямую).
func TestOpenKSProbeWindow_KSDisabled_Nil(t *testing.T) {
	e := newTestEngine()
	e.directProbeGOOS = "windows"
	e.state.Connected = true
	e.ks = newProbeAllowerKS(false) // IsEnabled()=false
	if cleanup := e.openKSProbeWindow([]*models.Node{{Address: "203.0.113.7"}}); cleanup != nil {
		t.Fatal("при выключенном KS окно не открывается")
	}
	if w := e.NodeCheckStatus().KillSwitchWarning; w != "" {
		t.Errorf("KillSwitchWarning=%q, want \"\" (KS выключен)", w)
	}
}

// ─── Интеграция: probeCandidates открывает окно и ГАРАНТИРОВАННО закрывает (defer) ────────────

func TestNodeCheck_KSProbeWindow_OpenedAndClosed(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.Sources = nil
	e.directProbeGOOS = "windows"
	e.state.Connected = true
	ks := newProbeAllowerKS(true)
	e.ks = ks

	setProbePool(e, []*models.Node{tcpAliveNode("a"), tcpAliveNode("b")})
	e.probeFn = func(ctx context.Context, node *models.Node, slot int) (int64, string, string, error) {
		return 1, "US", "203.0.113.9", nil
	}

	if err := e.StartNodeCheck(NodeCheckOptions{TopN: 2, TargetK: 2, Concurrency: 2, PerNode: time.Second}); err != nil {
		t.Fatalf("StartNodeCheck: %v", err)
	}
	st := waitNodeCheckDone(t, e, 5*time.Second)
	if st.Phase != "done" {
		t.Fatalf("phase=%q, want done", st.Phase)
	}
	if len(ks.allowCalls) == 0 {
		t.Error("AllowProbeTargets не вызван — окно пробы не открылось (windows+KS-on+ProbeAllower)")
	}
	if ks.clearCalls == 0 {
		t.Error("ClearProbeTargets не вызван — окно пробы не закрыто (defer cleanup в probeCandidates)")
	}
	if st.KillSwitchWarning != "" {
		t.Errorf("KillSwitchWarning=%q, want \"\" — окно открыто, проба честна", st.KillSwitchWarning)
	}
	if st.Probed != 2 || st.Verified != 2 {
		t.Fatalf("probed=%d verified=%d, want 2/2 — проба должна реально пройти", st.Probed, st.Verified)
	}
}

// Деградация в бою: KS без ProbeAllower (routedKS) — проба всё равно проходит (по фейку), окно не
// открывается, честное предупреждение сохраняется до конца прогона.
func TestNodeCheck_KSProbeWindow_NoProbeAllower_KeepsWarning(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.Sources = nil
	e.directProbeGOOS = "windows"
	e.state.Connected = true
	e.ks = &routedKS{caps: killswitch.Capabilities{ProxyMode: true, TunMode: true}, enabled: true}

	setProbePool(e, []*models.Node{tcpAliveNode("a")})
	e.probeFn = func(ctx context.Context, node *models.Node, slot int) (int64, string, string, error) {
		return 1, "US", "203.0.113.9", nil
	}
	if err := e.StartNodeCheck(NodeCheckOptions{TopN: 1, TargetK: 1, Concurrency: 1, PerNode: time.Second}); err != nil {
		t.Fatalf("StartNodeCheck: %v", err)
	}
	st := waitNodeCheckDone(t, e, 5*time.Second)
	if st.Phase != "done" {
		t.Fatalf("phase=%q, want done", st.Phase)
	}
	if st.KillSwitchWarning != killSwitchProbeWarningText {
		t.Errorf("KillSwitchWarning=%q, want честный текст P0-2 (бэкенд без ProbeAllower — деградация)", st.KillSwitchWarning)
	}
}
