package netutil

import (
	"strings"
	"testing"
)

func TestLinkHostWarning(t *testing.T) {
	cases := []struct {
		name    string
		host    string
		wantSub string // подстрока, которая должна встретиться в предупреждении; "" — ожидаем пустой результат
	}{
		// loopback
		{"loopback v4", "127.0.0.1", "loopback"},
		{"loopback v6", "::1", "loopback"},
		{"loopback v6 bracketed", "[::1]", "loopback"},
		{"localhost name", "localhost", "loopback"},
		{"localhost mixed case", "LocalHost", "loopback"},

		// private / LAN (RFC1918 + ULA + link-local)
		{"private v4 10/8", "10.0.0.37", "LAN"},
		{"private v4 172.16/12 low", "172.16.0.1", "LAN"},
		{"private v4 172.16/12 high", "172.31.255.255", "LAN"},
		{"private v4 192.168/16", "192.168.1.5", "LAN"},
		{"ULA v6", "fc00::1", "LAN"},
		{"ULA v6 fd", "fd12:3456:789a::1", "LAN"},
		{"link-local v4 APIPA", "169.254.1.1", "LAN"},
		{"link-local v6", "fe80::1", "LAN"},
		{"link-local v6 bracketed", "[fe80::abcd:1234]", "LAN"},

		// CGNAT
		{"CGNAT low", "100.64.0.1", "CGNAT"},
		{"CGNAT high", "100.127.255.255", "CGNAT"},

		// unspecified
		{"unspecified v4", "0.0.0.0", "любой интерфейс"},
		{"unspecified v6", "::", "любой интерфейс"},
		{"unspecified v6 bracketed", "[::]", "любой интерфейс"},

		// тест-диапазон 198.18.0.0/15 (RFC 2544; fake-ip виртуальных адаптеров/VPN)
		{"benchmark low", "198.18.0.1", "198.18.0.0/15"},
		{"benchmark high", "198.19.255.254", "198.18.0.0/15"},
		{"just below benchmark", "198.17.255.255", ""},
		{"just above benchmark", "198.20.0.1", ""},

		// multicast
		{"multicast v4 low", "224.0.0.1", "multicast"},
		{"multicast v4 ssdp", "239.255.255.250", "multicast"},
		{"multicast v6 all-nodes", "ff02::1", "multicast"},
		{"multicast v6 bracketed", "[ff05::2]", "multicast"},
		{"IPv4-mapped multicast", "::ffff:224.0.0.251", "multicast"},
		{"just below multicast", "223.255.255.255", ""},

		// зарезервированный 240.0.0.0/4 (+ широковещательный)
		{"reserved low", "240.0.0.1", "240.0.0.0/4"},
		{"reserved mid", "250.1.2.3", "240.0.0.0/4"},
		{"limited broadcast", "255.255.255.255", "240.0.0.0/4"},
		{"IPv4-mapped reserved", "::ffff:240.0.0.1", "240.0.0.0/4"},

		// «*.localhost» и «localhost.» — те же loopback-имена (RFC 6761)
		{"localhost trailing dot", "localhost.", "loopback"},
		{"localhost trailing dot upper", "LOCALHOST.", "loopback"},
		{"subdomain of localhost", "vpn.localhost", "loopback"},
		{"deep subdomain of localhost", "a.b.Localhost", "loopback"},
		{"subdomain of localhost trailing dot", "app.localhost.", "loopback"},
		{"not localhost: glued prefix", "notlocalhost", ""},
		{"not localhost: localhost as label", "localhost.example.com", ""},
		{"not localhost: suffix without dot", "mylocalhost", ""},

		// IPv6 с зоной (так адрес выглядит в ipconfig/ip a) — link-local, LAN
		{"link-local v6 with zone", "fe80::1%eth0", "LAN"},
		{"link-local v6 with zone bracketed", "[fe80::1%eth0]", "LAN"},

		// public — должно быть пусто
		{"public v4 google dns", "8.8.8.8", ""},
		{"public v4 cloudflare", "1.1.1.1", ""},
		{"public v4 just below CGNAT", "100.63.255.255", ""},
		{"public v4 just above CGNAT", "100.128.0.1", ""},
		{"public v4 just above 172.16/12", "172.32.0.1", ""},
		{"public v6 google dns", "2001:4860:4860::8888", ""},
		{"public v6 bracketed", "[2606:4700:4700::1111]", ""},

		// IPv4-mapped IPv6 — должен разворачиваться до классификации
		{"IPv4-mapped private", "::ffff:10.0.0.1", "LAN"},
		{"IPv4-mapped public", "::ffff:8.8.8.8", ""},
		{"IPv4-mapped loopback", "::ffff:127.0.0.1", "loopback"},

		// hostname — не резолвим, всегда ""
		{"hostname plain", "example.org", ""},
		{"hostname vpn provider", "my-vps.example-provider.net", ""},
		{"hostname punycode-ish", "xn--80ak6aa92e.com", ""},

		// края
		{"empty string", "", ""},
		{"whitespace only", "   ", ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := LinkHostWarning(c.host)
			if c.wantSub == "" {
				if got != "" {
					t.Errorf("LinkHostWarning(%q) = %q, ожидалось пустое предупреждение", c.host, got)
				}
				return
			}
			if got == "" {
				t.Errorf("LinkHostWarning(%q) = \"\", ожидалось предупреждение с подстрокой %q", c.host, c.wantSub)
				return
			}
			if !strings.Contains(got, c.wantSub) {
				t.Errorf("LinkHostWarning(%q) = %q, не содержит ожидаемую подстроку %q", c.host, got, c.wantSub)
			}
		})
	}
}

// TestLinkHostWarning_ClassesAreDistinct — предупреждения разных классов не должны совпадать
// дословно: иначе пользователь не поймёт, private это адрес, loopback или CGNAT.
func TestLinkHostWarning_ClassesAreDistinct(t *testing.T) {
	all := map[string]string{
		"loopback":    LinkHostWarning("127.0.0.1"),
		"private":     LinkHostWarning("192.168.1.1"),
		"cgnat":       LinkHostWarning("100.64.0.1"),
		"unspecified": LinkHostWarning("0.0.0.0"),
		"benchmark":   LinkHostWarning("198.18.0.1"),
		"multicast":   LinkHostWarning("224.0.0.1"),
		"reserved":    LinkHostWarning("240.0.0.1"),
	}
	seen := map[string]string{}
	for name, msg := range all {
		if msg == "" {
			t.Fatalf("%s: предупреждение неожиданно пустое", name)
		}
		if other, ok := seen[msg]; ok {
			t.Fatalf("%s и %s дают одинаковый текст предупреждения: %q", name, other, msg)
		}
		seen[msg] = name
	}
}
