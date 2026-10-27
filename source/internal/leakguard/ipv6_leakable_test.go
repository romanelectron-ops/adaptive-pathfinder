package leakguard

import (
	"net"
	"testing"
)

// Регресс живого лога ПК 2026-10-27: собственный адрес TUN-адаптера apf0 (ULA fdfe:dcba:9876::1)
// принимался за утечку IPv6 — после каждого подключения в режиме VPN выскакивало «IPv6
// соединение работает мимо VPN». Утечкой считается только то, что может уйти в интернет.
func TestIsLeakableIPv6(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
		why  string
	}{
		{"2a00:1450:4010:c07::71", true, "глобальный unicast"},
		{"2001:db8::1", true, "глобальный unicast (документационный префикс)"},
		{"fdfe:dcba:9876::1", false, "ULA — собственный адрес TUN apf0"},
		{"fdfe:dcba:9876::2", false, "ULA — шлюз TUN"},
		{"fc00::1", false, "ULA fc00::/7"},
		{"fe80::1", false, "link-local"},
		{"::1", false, "loopback"},
		{"::", false, "unspecified"},
		{"ff02::1", false, "multicast"},
		{"192.0.2.10", false, "IPv4"},
		{"::ffff:192.0.2.10", false, "IPv4-mapped"},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("тест сломан: %q не разбирается", c.ip)
		}
		if got := isLeakableIPv6(ip); got != c.want {
			t.Errorf("isLeakableIPv6(%s) = %v, ожидалось %v (%s)", c.ip, got, c.want, c.why)
		}
	}
}
