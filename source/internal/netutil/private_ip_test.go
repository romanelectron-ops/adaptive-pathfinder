package netutil

import (
	"net"
	"testing"
)

func TestIsPrivateIPv4(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.32.0.1", false},
		{"192.168.1.1", true},
		{"100.64.0.1", true},
		{"100.127.255.255", true},
		{"100.63.255.255", false},
		{"100.128.0.1", false},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip).To4()
		if ip == nil {
			t.Fatalf("не смог разобрать %q как IPv4", c.ip)
		}
		if got := IsPrivateIPv4(ip); got != c.want {
			t.Errorf("IsPrivateIPv4(%s) = %v, ожидалось %v", c.ip, got, c.want)
		}
	}
}

func TestIsPrivateIPv6_ULA(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"fc00::1", true},
		{"fd12:3456:789a::1", true},
		{"2001:db8::1", false},
		{"::1", false},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if got := IsPrivateIPv6(ip); got != c.want {
			t.Errorf("IsPrivateIPv6(%s) = %v, ожидалось %v", c.ip, got, c.want)
		}
	}
}

func TestIsLinkLocalIPv6(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"fe80::1", true},
		{"fe80::abcd:1234", true},
		{"fec0::1", false},
		{"2001:db8::1", false},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if got := IsLinkLocalIPv6(ip); got != c.want {
			t.Errorf("IsLinkLocalIPv6(%s) = %v, ожидалось %v", c.ip, got, c.want)
		}
	}
}

// IPv4-адрес, приведённый к 16-байтовому виду (net.ParseIP всегда возвращает 16 байт для
// валидного IPv4), не должен ошибочно классифицироваться как IPv6 ULA/link-local — длина
// среза сама по себе не различает представления, но первый байт диапазона (0xfc/0xfe) в
// IPv4-маппинге (::ffff:a.b.c.d) физически не встречается в первых двух байтах.
func TestIsPrivateIPv6_RejectsIPv4Mapped(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	if IsPrivateIPv6(ip) {
		t.Error("IsPrivateIPv6 не должен принимать IPv4-адрес за ULA")
	}
	if IsLinkLocalIPv6(ip) {
		t.Error("IsLinkLocalIPv6 не должен принимать IPv4-адрес за link-local")
	}
}
