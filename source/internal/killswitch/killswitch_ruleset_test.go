package killswitch

import (
	"errors"
	"strings"
	"testing"
)

// D-31 · Я-31.1 (набор правил = default-block-outbound + только allow) и
// D-34 · Я-31.2 (честность enabled + fail-safe откат) — семантика windowsKS.Enable/Disable.
//
// Швы: execCmdFn подменяется фейковым «движком фаервола» (учёт правил + политики в памяти),
// поэтому проверяем СЕМАНТИКУ набора без реального netsh (уровень 1 ТЗ §7.1).

type fakeFW struct {
	rules     map[string]bool
	policy    string // текущая политика (последний аргумент set ... firewallpolicy)
	failMatch string // если joined-команда содержит это — вернуть ошибку (инъекция сбоя)
}

func newFakeFW() *fakeFW {
	return &fakeFW{rules: map[string]bool{}, policy: "blockinbound,allowoutbound"}
}

func fwRuleName(args []string) string {
	for _, a := range args {
		if strings.HasPrefix(a, "name=") {
			return strings.TrimPrefix(a, "name=")
		}
	}
	return ""
}

func (f *fakeFW) exec(_ string, args ...string) error {
	if f.failMatch != "" && strings.Contains(strings.Join(args, " "), f.failMatch) {
		return errors.New("injected failure: " + f.failMatch)
	}
	switch {
	case len(args) >= 4 && args[0] == "advfirewall" && args[1] == "firewall" && args[2] == "add" && args[3] == "rule":
		if n := fwRuleName(args); n != "" {
			f.rules[n] = true
		}
	case len(args) >= 3 && args[0] == "advfirewall" && args[1] == "firewall" && args[2] == "delete":
		if n := fwRuleName(args); n != "" {
			delete(f.rules, n)
		}
	case len(args) >= 3 && args[0] == "advfirewall" && args[1] == "set":
		f.policy = args[len(args)-1]
	}
	return nil
}

func (f *fakeFW) apfRuleCount() int {
	n := 0
	for name := range f.rules {
		if strings.HasPrefix(name, "APF-") {
			n++
		}
	}
	return n
}

func withFakeFW(f *fakeFW, body func()) {
	orig := execCmdFn
	defer func() { execCmdFn = orig }()
	execCmdFn = f.exec
	body()
}

// (1) Позитив: набор = allow×{loopback,lan,vpn,tun}, политика=blockoutbound, НЕТ явных block.
func TestWindowsKS_Enable_DefaultBlockAllow(t *testing.T) {
	f := newFakeFW()
	withFakeFW(f, func() {
		k := &windowsKS{}
		k.SetVPNEndpoint("203.0.113.7", 1080)
		if err := k.Enable("apf0", []int{1080}); err != nil {
			t.Fatalf("Enable: %v", err)
		}
		for _, want := range []string{
			ksRuleName + "-allow-loopback", ksRuleName + "-allow-lan",
			ksRuleName + "-allow-vpn", ksRuleName + "-allow-tun",
		} {
			if !f.rules[want] {
				t.Errorf("missing allow rule %q", want)
			}
		}
		for _, bad := range []string{ksRuleName + "-block-tcp", ksRuleName + "-block-udp"} {
			if f.rules[bad] {
				t.Errorf("explicit block rule must be ABSENT: %q", bad)
			}
		}
		if f.policy != "blockinbound,blockoutbound" {
			t.Errorf("policy=%q want blockinbound,blockoutbound", f.policy)
		}
		if !k.IsEnabled() {
			t.Error("IsEnabled must be true after successful Enable")
		}
	})
}

// (1b) Позитив: пустой vpnIP → allow-vpn отсутствует, остальные allow есть.
func TestWindowsKS_Enable_NoVPNIP_NoAllowVPN(t *testing.T) {
	f := newFakeFW()
	withFakeFW(f, func() {
		k := &windowsKS{}
		if err := k.Enable("apf0", nil); err != nil {
			t.Fatalf("Enable: %v", err)
		}
		if f.rules[ksRuleName+"-allow-vpn"] {
			t.Error("allow-vpn must be absent when vpnIP empty")
		}
		if !f.rules[ksRuleName+"-allow-loopback"] || !f.rules[ksRuleName+"-allow-tun"] {
			t.Error("loopback and tun allow rules must be present")
		}
	})
}

// (1c) Идемпотентность: двойной Enable → один набор (4 allow), без дублей block.
func TestWindowsKS_Enable_Idempotent(t *testing.T) {
	f := newFakeFW()
	withFakeFW(f, func() {
		k := &windowsKS{}
		k.SetVPNEndpoint("203.0.113.7", 0)
		_ = k.Enable("apf0", nil)
		_ = k.Enable("apf0", nil)
		if got := f.apfRuleCount(); got != 4 {
			t.Errorf("expected 4 APF allow rules after double Enable, got %d (%v)", got, f.rules)
		}
	})
}

// (TG-1 unit) Disable: 0 объектов APF, политика восстановлена на allowoutbound.
func TestWindowsKS_Disable_RemovesAllAndRestoresPolicy(t *testing.T) {
	f := newFakeFW()
	withFakeFW(f, func() {
		k := &windowsKS{}
		k.SetVPNEndpoint("203.0.113.7", 1080)
		_ = k.Enable("apf0", nil)
		if err := k.Disable(); err != nil {
			t.Fatalf("Disable: %v", err)
		}
		if got := f.apfRuleCount(); got != 0 {
			t.Errorf("expected 0 APF rules after Disable, got %d (%v)", got, f.rules)
		}
		if f.policy != "blockinbound,allowoutbound" {
			t.Errorf("policy=%q want allowoutbound restored", f.policy)
		}
		if k.IsEnabled() {
			t.Error("IsEnabled must be false after Disable")
		}
	})
}

// (TG-1 unit) Disable без Enable — no-op без ошибки.
func TestWindowsKS_Disable_WithoutEnable_NoError(t *testing.T) {
	f := newFakeFW()
	withFakeFW(f, func() {
		k := &windowsKS{}
		if err := k.Disable(); err != nil {
			t.Fatalf("Disable without Enable must be no-op, got %v", err)
		}
		if f.apfRuleCount() != 0 {
			t.Error("no APF rules expected")
		}
	})
}

// (D-34, fail-safe + честность) Инъекция ошибки на apply-команде → Enable возвращает error,
// enabled=false, частичные правила сняты, политика восстановлена (не «завис» blockoutbound).
func TestWindowsKS_Enable_PartialFailure_RollbackNotEnabled(t *testing.T) {
	f := newFakeFW()
	f.failMatch = "add rule name=" + ksRuleName + "-allow-lan"
	withFakeFW(f, func() {
		k := &windowsKS{}
		k.SetVPNEndpoint("203.0.113.7", 0)
		err := k.Enable("apf0", nil)
		if err == nil {
			t.Fatal("expected error on partial failure")
		}
		if k.IsEnabled() {
			t.Error("must NOT be enabled after partial failure (D-34)")
		}
		if got := f.apfRuleCount(); got != 0 {
			t.Errorf("partial rules must be rolled back, got %d (%v)", got, f.rules)
		}
		if f.policy != "blockinbound,allowoutbound" {
			t.Errorf("policy must be restored to allowoutbound on rollback, got %q", f.policy)
		}
	})
}
