package engine

import (
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/killswitch"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── B-0403 · R-8 (C-14) · единый резолв адреса узла ─────────────────────────

// endpointKS запоминает, что именно движок передал в Kill Switch.
type endpointKS struct {
	routedKS
	gotIP   string
	gotPort int
	calls   int
}

func (k *endpointKS) SetVPNEndpoint(ip string, port int) {
	k.gotIP, k.gotPort = ip, port
	k.calls++
}

// Инвариант R-8: конфигурация sing-box и правила Kill Switch строятся по ОДНОМУ ответу резолвера.
// Второй вызов не должен резолвить заново — иначе round-robin мог бы дать другой адрес, и Kill
// Switch разрешил бы не тот IP, к которому пойдёт sing-box.
func TestResolveEndpointOnce_CachedPerAddress(t *testing.T) {
	e := &Engine{cfg: &models.AppConfig{ListenPort: 10808}}

	all1, pin1, err := e.resolveEndpointOnce("203.0.113.10")
	if err != nil {
		t.Fatalf("resolveEndpointOnce: %v", err)
	}
	if all1 != "203.0.113.10" || pin1 != "203.0.113.10" {
		t.Fatalf("got (%q,%q)", all1, pin1)
	}

	// Портим кэш «изнутри»: если функция резолвит заново, подмена будет затёрта.
	e.endpointMu.Lock()
	e.endpointAll, e.endpointPinned = "198.51.100.1", "198.51.100.1"
	e.endpointMu.Unlock()

	all2, pin2, err := e.resolveEndpointOnce("203.0.113.10")
	if err != nil {
		t.Fatalf("повторный resolveEndpointOnce: %v", err)
	}
	if all2 != "198.51.100.1" || pin2 != "198.51.100.1" {
		t.Errorf("повторный резолв не взял кэш: (%q,%q)", all2, pin2)
	}

	// Другой адрес — кэш не применяется.
	all3, _, err := e.resolveEndpointOnce("198.51.100.7")
	if err != nil {
		t.Fatalf("resolveEndpointOnce(другой адрес): %v", err)
	}
	if all3 != "198.51.100.7" {
		t.Errorf("кэш применён к чужому адресу: %q", all3)
	}
}

func TestResolveEndpointOnce_EmptyAndBadAddress(t *testing.T) {
	e := &Engine{cfg: &models.AppConfig{ListenPort: 10808}}

	if all, pin, err := e.resolveEndpointOnce(""); err != nil || all != "" || pin != "" {
		t.Errorf("пустой адрес: (%q,%q,%v)", all, pin, err)
	}
	// "[]" отвергается разбором до обращения к резолверу — тест не ходит в сеть.
	if _, _, err := e.resolveEndpointOnce("[]"); err == nil {
		t.Error("неразбираемый адрес обязан давать ошибку")
	}
	// Неудачный резолв не должен оставлять мусор в кэше.
	e.endpointMu.Lock()
	cached := e.endpointFor
	e.endpointMu.Unlock()
	if cached == "[]" {
		t.Error("неудачный резолв попал в кэш")
	}
}

// IPv4 предпочитается при закреплении: стратегия DNS в конфигурации — prefer_ipv4, а у узла
// AAAA-запись может существовать, но не иметь связности.
func TestResolveEndpointOnce_PrefersIPv4ForPinning(t *testing.T) {
	e := &Engine{cfg: &models.AppConfig{ListenPort: 10808}}
	if _, pin, err := e.resolveEndpointOnce("[2001:db8::1]"); err != nil || pin != "2001:db8::1" {
		t.Errorf("чистый v6: (%q,%v)", pin, err)
	}
	if _, pin, err := e.resolveEndpointOnce("198.51.100.7"); err != nil || pin != "198.51.100.7" {
		t.Errorf("чистый v4: (%q,%v)", pin, err)
	}
}

// R-8: у цепочки Kill Switch обязан разрешить адрес ТОЧКИ ВХОДА. Раньше сюда приходил node==nil,
// разрешающее правило не создавалось вовсе, и при default-block-outbound цепочка не поднималась.
func TestApplyKillSwitch_ChainAllowsEntryNode(t *testing.T) {
	ks := &endpointKS{routedKS: routedKS{caps: killswitch.Capabilities{ProxyMode: true, TunMode: true}}}
	e := &Engine{
		// SetSystemProxy: true — иначе применение KS в proxy-режиме отсекает новый гейт
		// (docs/TZ_CONFIG_RELOAD_AND_KS_SAFETY_v1.0.md, причина B); этот тест проверяет
		// R-8 (правильный IP точки входа), а не поведение гейта, так что фикстура должна
		// пройти его честно, а не обходить.
		cfg:         &models.AppConfig{ConnectionMode: models.ModeProxy, ListenPort: 10808, EnableKillSwitch: true, SetSystemProxy: true},
		ks:          ks,
		ksProbedAt:  time.Now(),
		ksIsService: true, // служебный путь: Enable идёт прямо в бэкенд, без UAC
	}

	chain := &models.Chain{Nodes: []*models.Node{
		{Address: "198.51.100.1", Port: 443}, // выход
		{Address: "203.0.113.10", Port: 443}, // вход — к нему подключается хост
	}}

	if err := e.applyKillSwitch(nil, chain); err != nil {
		t.Fatalf("applyKillSwitch(цепочка): %v", err)
	}
	if ks.calls == 0 {
		t.Fatal("SetVPNEndpoint не вызван — правило allow-vpn не будет создано, цепочка не поднимется")
	}
	if ks.gotIP != "203.0.113.10" {
		t.Errorf("разрешён адрес %q, а хост подключается к точке входа 203.0.113.10", ks.gotIP)
	}
	if ks.gotPort != 10808 {
		t.Errorf("port = %d, want 10808", ks.gotPort)
	}
	if ks.enables != 1 {
		t.Errorf("Enable вызван %d раз(а), ожидался 1", ks.enables)
	}
}

// Одиночный узел продолжает работать как раньше (регрессия на смену сигнатуры).
func TestApplyKillSwitch_SingleNodeStillUsesNodeAddress(t *testing.T) {
	ks := &endpointKS{routedKS: routedKS{caps: killswitch.Capabilities{ProxyMode: true, TunMode: true}}}
	e := &Engine{
		// SetSystemProxy: true — см. комментарий в TestApplyKillSwitch_ChainAllowsEntryNode выше.
		cfg:         &models.AppConfig{ConnectionMode: models.ModeProxy, ListenPort: 10808, EnableKillSwitch: true, SetSystemProxy: true},
		ks:          ks,
		ksProbedAt:  time.Now(),
		ksIsService: true,
	}

	if err := e.applyKillSwitch(&models.Node{Address: "203.0.113.55"}, nil); err != nil {
		t.Fatalf("applyKillSwitch(узел): %v", err)
	}
	if ks.gotIP != "203.0.113.55" {
		t.Errorf("разрешён адрес %q, want 203.0.113.55", ks.gotIP)
	}
}
