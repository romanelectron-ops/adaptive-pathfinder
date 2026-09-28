// remote_target.go — ТЗ v1.3 F5.3 (консилиум 2026-09-03, GAP-43, V4): защита от заглушечных
// адресов в настройках, которые движок принимал за настоящие серверы. Живой инцидент
// 2026-09-02 на ПК пользователя: ShadowTLS остался включённым с example.com/5.6.7.8:8443 из
// плейсхолдера web-UI — КАЖДЫЙ outbound заворачивался в этот адрес, подключение не собиралось
// часами, а тумблер показывал «включено».
package netutil

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// placeholderIPs — «числовые заглушки», которые люди печатают вместо адреса.
var placeholderIPs = map[string]bool{
	"1.2.3.4": true, "5.6.7.8": true, "2.3.4.5": true, "9.9.9.9": false, // 9.9.9.9 — настоящий DNS Quad9
	"0.0.0.0": true, "255.255.255.255": true,
}

// placeholderHostSuffixes — зарезервированные (RFC 2606/6761) и локальные домены.
var placeholderHostSuffixes = []string{
	".example", ".example.com", ".example.net", ".example.org", ".test", ".invalid", ".local", ".localhost",
}

var placeholderHosts = map[string]bool{
	"localhost": true, "example": true, "example.com": true, "example.net": true, "example.org": true,
	"host": true, "server": true, "your-server": true, "your-vpn-server.example.com": true,
}

// ValidateRemoteTarget проверяет "host:port" настоящего удалённого сервера (ShadowTLS, CDN
// backend, relay): порт 1–65535, хост — не заглушка. RFC1918 (10/8, 172.16/12, 192.168/16) и
// CGNAT 100.64/10 РАЗРЕШЕНЫ — свои LAN/Tailscale-серверы легитимны (V4).
func ValidateRemoteTarget(hostport string) error {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(hostport))
	if err != nil {
		return fmt.Errorf("адрес должен быть в виде host:port: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("порт %q вне 1–65535", portStr)
	}
	return ValidateRemoteHost(host)
}

// ValidateRemoteHost проверяет только хост (IP или имя) — без порта (домен CDN-воркера и т.п.).
func ValidateRemoteHost(host string) error {
	h := strings.ToLower(strings.TrimSpace(strings.Trim(host, "[]")))
	if h == "" {
		return fmt.Errorf("пустой адрес")
	}
	if ip := net.ParseIP(h); ip != nil {
		return validateIP(ip, h)
	}
	if placeholderHosts[h] {
		return fmt.Errorf("«%s» — адрес-заглушка, а не настоящий сервер", h)
	}
	for _, suf := range placeholderHostSuffixes {
		if strings.HasSuffix(h, suf) {
			return fmt.Errorf("«%s» — зарезервированный/локальный домен (%s), не настоящий сервер", h, suf)
		}
	}
	for _, label := range strings.Split(h, ".") {
		if label == "example" {
			return fmt.Errorf("«%s» — домен из примера (метка example), не настоящий сервер", h)
		}
	}
	if strings.ContainsAny(h, " \t/\\@") {
		return fmt.Errorf("«%s» не похоже на имя хоста", h)
	}
	return nil
}

func validateIP(ip net.IP, raw string) error {
	if placeholderIPs[raw] {
		return fmt.Errorf("%s — IP-заглушка, а не настоящий сервер", raw)
	}
	switch {
	case ip.IsUnspecified():
		return fmt.Errorf("%s — неопределённый адрес", raw)
	case ip.IsLoopback():
		return fmt.Errorf("%s — loopback, удалённый сервер там быть не может", raw)
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsMulticast():
		return fmt.Errorf("%s — link-local/multicast адрес", raw)
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 0:
			return fmt.Errorf("%s — сеть 0.0.0.0/8", raw)
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 2,
			v4[0] == 198 && v4[1] == 51 && v4[2] == 100,
			v4[0] == 203 && v4[1] == 0 && v4[2] == 113:
			return fmt.Errorf("%s — документационная сеть (TEST-NET), такой адрес — из примера", raw)
		case v4[0] == 240 || v4.Equal(net.IPv4bcast):
			return fmt.Errorf("%s — зарезервированный диапазон", raw)
		}
	}
	return nil
}
