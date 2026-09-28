package killswitch

import (
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
)

// D-36 · Я-31.0 — NormalizeEndpointIP(s): адрес узла → значение(я) для netsh remoteip=.
// Резолвер инжектируется через lookupIPFn (чистое ядро / нечистые края).
// B-0403 · R-2.3 (C-5) — контракт расширен: семейства возвращаются РАЗДЕЛЬНО.

func withLookup(fn func(string) ([]net.IP, error), body func()) {
	orig := lookupIPFn
	defer func() { lookupIPFn = orig }()
	lookupIPFn = fn
	body()
}

func testLookup(host string) ([]net.IP, error) {
	switch host {
	case "example.com":
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	case "multi.example":
		return []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2")}, nil
	case "dual.example":
		// Реальный кейс C-5: у узла есть и A, и AAAA.
		return []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2001:db8::1"), net.ParseIP("2.2.2.2")}, nil
	case "dup.example":
		return []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("1.1.1.1")}, nil
	}
	return nil, errors.New("unexpected host " + host)
}

// (1) Позитив: валидные входы (IP, IP:port, v6, [v6]:port, домены, trim) → ожидаемые выходы.
func TestNormalizeEndpointIP_Positive(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1.2.3.4", "1.2.3.4"},
		{"1.2.3.4:443", "1.2.3.4"},
		{"2001:db8::1", "2001:db8::1"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"example.com", "93.184.216.34"},
		{"example.com:443", "93.184.216.34"},
		{"multi.example", "1.1.1.1,2.2.2.2"},
		{"  1.2.3.4  ", "1.2.3.4"},
		// транспортная форма: сначала все v4, затем все v6
		{"dual.example", "1.1.1.1,2.2.2.2,2001:db8::1"},
	}
	withLookup(testLookup, func() {
		for _, c := range cases {
			got, err := NormalizeEndpointIP(c.in)
			if err != nil {
				t.Errorf("%q: unexpected err %v", c.in, err)
				continue
			}
			if got != c.want {
				t.Errorf("%q: got %q want %q", c.in, got, c.want)
			}
		}
	})
}

// (1b) Позитив R-2.3: семейства разделены; дубли схлопнуты.
func TestNormalizeEndpointIPs_Families(t *testing.T) {
	cases := []struct {
		in     string
		v4, v6 []string
	}{
		{"1.2.3.4:443", []string{"1.2.3.4"}, nil},
		{"[2001:db8::1]:443", nil, []string{"2001:db8::1"}},
		{"dual.example", []string{"1.1.1.1", "2.2.2.2"}, []string{"2001:db8::1"}},
		{"dup.example", []string{"1.1.1.1"}, nil},
		{"", nil, nil},
	}
	withLookup(testLookup, func() {
		for _, c := range cases {
			v4, v6, err := NormalizeEndpointIPs(c.in)
			if err != nil {
				t.Errorf("%q: unexpected err %v", c.in, err)
				continue
			}
			if !reflect.DeepEqual(v4, c.v4) || !reflect.DeepEqual(v6, c.v6) {
				t.Errorf("%q: got (%v,%v) want (%v,%v)", c.in, v4, v6, c.v4, c.v6)
			}
		}
	})
}

// (1c) ИНВАРИАНТ R-2.3: ни один возвращённый список не смешивает семейства.
func TestNormalizeEndpointIPs_InvariantNoFamilyMix(t *testing.T) {
	withLookup(testLookup, func() {
		v4, v6, err := NormalizeEndpointIPs("dual.example")
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range v4 {
			if ip := net.ParseIP(s); ip == nil || ip.To4() == nil {
				t.Errorf("v4 list contains non-IPv4 %q", s)
			}
		}
		for _, s := range v6 {
			if ip := net.ParseIP(s); ip == nil || ip.To4() != nil {
				t.Errorf("v6 list contains non-IPv6 %q", s)
			}
		}
	})
}

// (2) Негатив: недопустимые входы (нерезолвимый домен, пустой набор IP) → корректная ошибка.
func TestNormalizeEndpointIP_Negative(t *testing.T) {
	withLookup(func(string) ([]net.IP, error) { return nil, errors.New("nxdomain") }, func() {
		if _, err := NormalizeEndpointIP("bad.host"); err == nil {
			t.Error("expected error for unresolvable domain")
		}
		if _, _, err := NormalizeEndpointIPs("bad.host"); err == nil {
			t.Error("expected error for unresolvable domain (Ips)")
		}
	})
	withLookup(func(string) ([]net.IP, error) { return []net.IP{}, nil }, func() {
		if _, err := NormalizeEndpointIP("empty.records"); err == nil {
			t.Error("expected error when lookup returns no IPs")
		}
	})
}

// (3) Fail-safe: пустой вход → ("", nil), резолвер НЕ вызывается (валидное «без allow-vpn»).
func TestNormalizeEndpointIP_FailSafeEmpty(t *testing.T) {
	called := false
	withLookup(func(string) ([]net.IP, error) { called = true; return nil, nil }, func() {
		for _, in := range []string{"", "   "} {
			got, err := NormalizeEndpointIP(in)
			if err != nil || got != "" {
				t.Errorf("%q: got (%q,%v) want (\"\",nil)", in, got, err)
			}
		}
	})
	if called {
		t.Error("resolver must NOT be called for empty input")
	}
}

// (4) Стойкость: мусор, не являющийся IP и не резолвимый, → ошибка, а не «протёкший» выход.
func TestNormalizeEndpointIP_Robustness(t *testing.T) {
	withLookup(func(string) ([]net.IP, error) { return nil, errors.New("nope") }, func() {
		if got, err := NormalizeEndpointIP("1.2.3.4:443:x"); err == nil {
			t.Errorf("malformed input leaked %q instead of error", got)
		}
	})
}

// (4b) Стойкость splitVPNIPs: мусор в транспортной форме отбрасывается, валидное — сохраняется.
func TestSplitVPNIPs_Robustness(t *testing.T) {
	v4, v6 := splitVPNIPs(" 1.2.3.4 , not-an-ip ,, 2001:db8::1 ,localsubnet")
	if !reflect.DeepEqual(v4, []string{"1.2.3.4"}) {
		t.Errorf("v4 = %v, want [1.2.3.4]", v4)
	}
	if !reflect.DeepEqual(v6, []string{"2001:db8::1"}) {
		t.Errorf("v6 = %v, want [2001:db8::1]", v6)
	}
	if a, b := splitVPNIPs(""); a != nil || b != nil {
		t.Errorf("empty input must yield (nil,nil), got (%v,%v)", a, b)
	}
}

// R-2.3 · интеграция с набором netsh-команд: два адреса разных семейств → ДВА разных правила,
// и ни в одном remoteip= нет смешения (иначе netsh отвергнет правило → откат всего KS, D-34).
func TestKSApplyCommands_FamilySplit(t *testing.T) {
	cmds := ksApplyCommands([]string{"1.1.1.1", "2.2.2.2"}, []string{"2001:db8::1"})
	remoteByRule := map[string]string{}
	for _, c := range cmds {
		var name, remote string
		for _, a := range c {
			switch {
			case strings.HasPrefix(a, "name="):
				name = strings.TrimPrefix(a, "name=")
			case strings.HasPrefix(a, "remoteip="):
				remote = strings.TrimPrefix(a, "remoteip=")
			}
		}
		if name != "" && remote != "" {
			remoteByRule[name] = remote
		}
	}
	if got := remoteByRule[ksRuleName+"-allow-vpn"]; got != "1.1.1.1,2.2.2.2" {
		t.Errorf("allow-vpn remoteip=%q, want 1.1.1.1,2.2.2.2", got)
	}
	if got := remoteByRule[ksRuleName+"-allow-vpn6"]; got != "2001:db8::1" {
		t.Errorf("allow-vpn6 remoteip=%q, want 2001:db8::1", got)
	}
	// ИНВАРИАНТ: ни в одном remoteip= не смешаны семейства.
	for name, remote := range remoteByRule {
		if remote == "localsubnet" {
			continue
		}
		v4, v6 := splitVPNIPs(remote)
		if len(v4) > 0 && len(v6) > 0 {
			t.Errorf("rule %q mixes families in remoteip=%q", name, remote)
		}
	}
}

// R-2.3 · fail-safe: пустой список семейства ⇒ правило этого семейства не создаётся (не ошибка).
func TestKSApplyCommands_EmptyFamilySkipped(t *testing.T) {
	has := func(cmds [][]string, rule string) bool {
		for _, c := range cmds {
			for _, a := range c {
				if a == "name="+ksRuleName+rule {
					return true
				}
			}
		}
		return false
	}
	onlyV4 := ksApplyCommands([]string{"1.1.1.1"}, nil)
	if !has(onlyV4, "-allow-vpn") || has(onlyV4, "-allow-vpn6") {
		t.Error("v4-only endpoint must produce -allow-vpn and NOT -allow-vpn6")
	}
	onlyV6 := ksApplyCommands(nil, []string{"2001:db8::1"})
	if has(onlyV6, "-allow-vpn") || !has(onlyV6, "-allow-vpn6") {
		t.Error("v6-only endpoint must produce -allow-vpn6 and NOT -allow-vpn")
	}
	none := ksApplyCommands(nil, nil)
	if has(none, "-allow-vpn") || has(none, "-allow-vpn6") {
		t.Error("no endpoint must produce neither vpn rule")
	}
}

// TG-1 предпосылка: КАЖДОЕ правило, которое умеет создать ksApplyCommands, обязано удаляться
// ksCleanupCommands — иначе Disable оставит остаток (нарушение «0 правил APF»).
func TestKSRules_EveryAppliedRuleIsCleaned(t *testing.T) {
	cleaned := map[string]bool{}
	for _, c := range ksCleanupCommands() {
		for _, a := range c {
			if strings.HasPrefix(a, "name=") {
				cleaned[strings.TrimPrefix(a, "name=")] = true
			}
		}
	}
	for _, c := range ksApplyCommands([]string{"1.1.1.1"}, []string{"2001:db8::1"}) {
		for _, a := range c {
			if !strings.HasPrefix(a, "name=") {
				continue
			}
			if name := strings.TrimPrefix(a, "name="); !cleaned[name] {
				t.Errorf("rule %q is created but never deleted by ksCleanupCommands", name)
			}
		}
	}
}
