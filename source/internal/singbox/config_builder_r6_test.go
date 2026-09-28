package singbox

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
)

// ─── B-0403 · R-6.2 (C-11) · IPv6 не должен идти мимо туннеля ────────────────

func tunOptionsOf(t *testing.T, cfg *Config) *TunOptions {
	t.Helper()
	for _, in := range cfg.Inbounds {
		if in.Type == "tun" {
			if in.TunOptions == nil {
				t.Fatal("у tun-inbound нет TunOptions")
			}
			return in.TunOptions
		}
	}
	t.Fatal("tun-inbound не найден")
	return nil
}

func hasFamily(addrs []string, wantV6 bool) bool {
	for _, a := range addrs {
		ip, _, err := net.ParseCIDR(a)
		if err != nil {
			continue
		}
		isV6 := ip.To4() == nil
		if isV6 == wantV6 {
			return true
		}
	}
	return false
}

// Суть C-11: auto_route перехватывает только те семейства, адреса которых есть на интерфейсе.
// Пока у apf0 был один IPv4-адрес, «поднятый VPN» оставлял реальный IPv6 пользователя видимым.
func TestTunAddresses_IPv6PresentByDefault(t *testing.T) {
	b := NewBuilder(10808, true)
	opts := tunOptionsOf(t, b.baseConfig("proxy"))

	if !hasFamily(opts.Address, false) {
		t.Error("у TUN пропал IPv4-адрес")
	}
	if !hasFamily(opts.Address, true) {
		t.Fatalf("у TUN нет IPv6-адреса — весь v6-трафик пойдёт мимо туннеля: %v", opts.Address)
	}
}

// Отказ от защиты — только по явной воле пользователя (BlockIPv6Leak=false).
func TestTunAddresses_IPv6DisabledExplicitly(t *testing.T) {
	b := NewBuilder(10808, true)
	b.SetTunIPv6(false)
	opts := tunOptionsOf(t, b.baseConfig("proxy"))

	if hasFamily(opts.Address, true) {
		t.Errorf("IPv6-адрес выдан вопреки явному отказу: %v", opts.Address)
	}
	if !hasFamily(opts.Address, false) {
		t.Errorf("IPv4-адрес обязан остаться: %v", opts.Address)
	}
}

// Адрес туннеля обязан быть ULA (fc00::/7): глобальный адрес мог бы пересечься с реальной
// адресацией пользователя и увести чужой трафик в туннель.
func TestTunAddresses_IPv6IsUniqueLocal(t *testing.T) {
	ip, _, err := net.ParseCIDR(tunAddressV6)
	if err != nil {
		t.Fatalf("tunAddressV6 = %q не разбирается: %v", tunAddressV6, err)
	}
	if ip.To4() != nil {
		t.Fatalf("tunAddressV6 = %q — это IPv4", tunAddressV6)
	}
	if ip[0]&0xfe != 0xfc {
		t.Errorf("tunAddressV6 = %q не из ULA-диапазона fc00::/7", tunAddressV6)
	}
	if ip.IsGlobalUnicast() && !ip.IsPrivate() {
		t.Errorf("tunAddressV6 = %q — глобально маршрутизируемый адрес", tunAddressV6)
	}
}

func TestTunAddresses_V4RangeUnchanged(t *testing.T) {
	ip, _, err := net.ParseCIDR(tunAddressV4)
	if err != nil {
		t.Fatalf("tunAddressV4 = %q не разбирается: %v", tunAddressV4, err)
	}
	if !ip.IsPrivate() {
		t.Errorf("tunAddressV4 = %q должен быть из частного диапазона", tunAddressV4)
	}
}

// Проверка на уровне итогового JSON: sing-box получает оба адреса в поле address.
func TestTunAddresses_ReachSingBoxJSON(t *testing.T) {
	b := NewBuilder(10808, true)
	raw, err := json.Marshal(b.baseConfig("proxy"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(raw)
	if !strings.Contains(s, tunAddressV4) {
		t.Errorf("в конфиге нет %s", tunAddressV4)
	}
	if !strings.Contains(s, tunAddressV6) {
		t.Errorf("в конфиге нет %s — sing-box не поднимет v6 на apf0", tunAddressV6)
	}
}

// В proxy-режиме туннеля нет вовсе, и переключатель ничего не должен ломать.
func TestTunIPv6_IrrelevantWithoutTunMode(t *testing.T) {
	b := NewBuilder(10808, false)
	b.SetTunIPv6(true)
	cfg := b.baseConfig("proxy")
	for _, in := range cfg.Inbounds {
		if in.Type == "tun" {
			t.Fatal("tun-inbound появился в proxy-режиме")
		}
	}
}
