package killswitch

import (
	"strings"
	"testing"
)

// Долг-5 (2026-09-21): windowsKS реализует ProbeAllower — временные allow-правила для IP кандидатов
// трафик-пробы скана, чтобы под активным Kill Switch (default-block, allow сужен до активного узла)
// сборка списка рабочих во время подключения не находила ложно 0 рабочих. Швы: execCmdFn = capturing
// fake — реальный netsh НЕ вызывается (DEF-08 барьер ks_testguard.go + локальная подмена). Проверяем
// раскладку по семействам, отсутствие cap-а maxClassifiedIPs, идемпотентность, снятие, аддитивность
// к базовому KS и участие суффиксов в очистке (инвариант «0 остатков APF»).

// probeExecFake — учёт netsh add/delete с сохранением remoteip= каждого правила по имени.
type probeExecFake struct {
	remoteip map[string]string // ruleName → значение remoteip=
	deletes  int
}

func newProbeExecFake() *probeExecFake { return &probeExecFake{remoteip: map[string]string{}} }

func (p *probeExecFake) exec(_ string, args ...string) error {
	name, remote := "", ""
	for _, a := range args {
		if strings.HasPrefix(a, "name=") {
			name = strings.TrimPrefix(a, "name=")
		} else if strings.HasPrefix(a, "remoteip=") {
			remote = strings.TrimPrefix(a, "remoteip=")
		}
	}
	switch {
	case len(args) >= 4 && args[2] == "add" && args[3] == "rule":
		if name != "" {
			p.remoteip[name] = remote
		}
	case len(args) >= 3 && args[2] == "delete":
		p.deletes++
		delete(p.remoteip, name)
	}
	return nil
}

func withProbeExecFake(p *probeExecFake, body func()) {
	orig := execCmdFn
	defer func() { execCmdFn = orig }()
	execCmdFn = p.exec
	body()
}

// (1) Раскладка по семействам: v4 → -allow-probe, v6 → -allow-probe6, семьи не смешаны.
func TestWindowsKS_AllowProbeTargets_SplitsByFamily(t *testing.T) {
	p := newProbeExecFake()
	withProbeExecFake(p, func() {
		k := &windowsKS{}
		if err := k.AllowProbeTargets([]string{"203.0.113.7", "2001:db8::1", "198.51.100.9"}); err != nil {
			t.Fatalf("AllowProbeTargets: %v", err)
		}
		v4 := p.remoteip[ksRuleName+"-allow-probe"]
		if !strings.Contains(v4, "203.0.113.7") || !strings.Contains(v4, "198.51.100.9") {
			t.Errorf("v4 probe remoteip=%q, ожидались оба v4-адреса", v4)
		}
		if strings.Contains(v4, "2001:db8") {
			t.Errorf("v6 просочился в v4-правило: %q (netsh отверг бы смешанное правило)", v4)
		}
		if got := p.remoteip[ksRuleName+"-allow-probe6"]; !strings.Contains(got, "2001:db8::1") {
			t.Errorf("v6 probe remoteip=%q, ожидался 2001:db8::1", got)
		}
	})
}

// (2) НЕТ cap-а maxClassifiedIPs=4: probe-окно разрешает ВСЕ переданные IP (в отличие от
// splitVPNIPs/classifyIPs, который режет активный endpoint до 4). Это суть фикса — без него скан
// на большем числе узлов молча разрешал бы только 4.
func TestWindowsKS_AllowProbeTargets_NoMaxClassifiedCap(t *testing.T) {
	p := newProbeExecFake()
	ips := []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4", "203.0.113.5", "203.0.113.6", "203.0.113.7"}
	withProbeExecFake(p, func() {
		k := &windowsKS{}
		if err := k.AllowProbeTargets(ips); err != nil {
			t.Fatalf("AllowProbeTargets: %v", err)
		}
		v4 := p.remoteip[ksRuleName+"-allow-probe"]
		got := strings.Count(v4, ".") / 3 // грубо: каждый IPv4 = 3 точки
		if got != len(ips) {
			t.Errorf("в probe-правиле %d адресов, ожидалось %d (cap maxClassifiedIPs не должен применяться): %q", got, len(ips), v4)
		}
		for _, want := range ips {
			if !strings.Contains(v4, want) {
				t.Errorf("probe-правило потеряло %q: %q", want, v4)
			}
		}
	})
}

// (3) Идемпотентность: повторный AllowProbeTargets сперва снимает прежние probe-правила, затем
// ставит новые — итог = ровно текущий набор, без накопления.
func TestWindowsKS_AllowProbeTargets_Idempotent(t *testing.T) {
	p := newProbeExecFake()
	withProbeExecFake(p, func() {
		k := &windowsKS{}
		_ = k.AllowProbeTargets([]string{"203.0.113.7"})
		_ = k.AllowProbeTargets([]string{"198.51.100.9"})
		if got := p.remoteip[ksRuleName+"-allow-probe"]; got != "198.51.100.9" {
			t.Errorf("после повторного AllowProbeTargets v4=%q, want 198.51.100.9 (перезапись, не накопление)", got)
		}
		if _, ok := p.remoteip[ksRuleName+"-allow-probe6"]; ok {
			t.Error("v6 probe-правила быть не должно (оба вызова только v4)")
		}
	})
}

// (4) ClearProbeTargets снимает оба probe-правила.
func TestWindowsKS_ClearProbeTargets_RemovesRules(t *testing.T) {
	p := newProbeExecFake()
	withProbeExecFake(p, func() {
		k := &windowsKS{}
		_ = k.AllowProbeTargets([]string{"203.0.113.7", "2001:db8::1"})
		if len(p.remoteip) == 0 {
			t.Fatal("подготовка: ожидались probe-правила")
		}
		if err := k.ClearProbeTargets(); err != nil {
			t.Fatalf("ClearProbeTargets: %v", err)
		}
		if len(p.remoteip) != 0 {
			t.Errorf("после ClearProbeTargets остались правила: %v", p.remoteip)
		}
	})
}

// (5) Пустой список — ни одного правила (best-effort снятие прежних всё равно вызывается).
func TestWindowsKS_AllowProbeTargets_Empty_NoRules(t *testing.T) {
	p := newProbeExecFake()
	withProbeExecFake(p, func() {
		k := &windowsKS{}
		if err := k.AllowProbeTargets(nil); err != nil {
			t.Fatalf("AllowProbeTargets(nil): %v", err)
		}
		if len(p.remoteip) != 0 {
			t.Errorf("пустой список не должен создавать правил, got %v", p.remoteip)
		}
	})
}

// (6) Аддитивность: probe-окно не трогает базовые allow-правила и политику blockoutbound активного
// KS; снятие окна тоже оставляет базовый KS целым. Используем fakeFW (учитывает правила + политику).
func TestWindowsKS_ProbeRules_AdditiveToBaseKS(t *testing.T) {
	f := newFakeFW()
	withFakeFW(f, func() {
		k := &windowsKS{}
		k.SetVPNEndpoint("203.0.113.7", 1080)
		if err := k.Enable("apf0", nil); err != nil {
			t.Fatalf("Enable: %v", err)
		}
		basePolicy, baseCount := f.policy, f.apfRuleCount()

		if err := k.AllowProbeTargets([]string{"198.51.100.9"}); err != nil {
			t.Fatalf("AllowProbeTargets: %v", err)
		}
		if f.policy != basePolicy {
			t.Errorf("probe-окно изменило политику брандмауэра: %q, было %q", f.policy, basePolicy)
		}
		for _, base := range []string{ksRuleName + "-allow-vpn", ksRuleName + "-allow-tun", ksRuleName + "-allow-loopback"} {
			if !f.rules[base] {
				t.Errorf("probe-окно снесло базовое правило %q", base)
			}
		}
		if !f.rules[ksRuleName+"-allow-probe"] {
			t.Error("probe-правило не создано")
		}
		if f.apfRuleCount() != baseCount+1 {
			t.Errorf("ожидалось base+1 (%d) правил, got %d", baseCount+1, f.apfRuleCount())
		}

		if err := k.ClearProbeTargets(); err != nil {
			t.Fatalf("ClearProbeTargets: %v", err)
		}
		if f.apfRuleCount() != baseCount {
			t.Errorf("после ClearProbeTargets ожидалось base=%d, got %d (базовый KS должен остаться цел)", baseCount, f.apfRuleCount())
		}
		if !f.rules[ksRuleName+"-allow-vpn"] || f.policy != basePolicy {
			t.Error("ClearProbeTargets повредил базовый KS (allow-vpn/политику)")
		}
	})
}

// (7) Инвариант «0 остатков»: суффиксы probe-правил входят в windowsRuleSuffixes и реально
// попадают в ksCleanupCommands — любая очистка/аварийный сброс KS их снимет, даже если defer
// в probeCandidates почему-то не отработает.
func TestProbeSuffixes_CoveredByCleanup(t *testing.T) {
	needProbe := "name=" + ksRuleName + "-allow-probe"
	needProbe6 := "name=" + ksRuleName + "-allow-probe6"
	haveProbe, haveProbe6 := false, false
	for _, c := range ksCleanupCommands() {
		last := c[len(c)-1]
		if last == needProbe {
			haveProbe = true
		}
		if last == needProbe6 {
			haveProbe6 = true
		}
	}
	if !haveProbe || !haveProbe6 {
		t.Errorf("ksCleanupCommands не снимает probe-правила: probe=%v probe6=%v — нарушен инвариант «0 остатков APF»", haveProbe, haveProbe6)
	}
}
