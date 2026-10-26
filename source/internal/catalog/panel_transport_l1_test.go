package catalog

import (
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// Лот L1: панели (Marzban, 3X-UI) раньше превращали неизвестный транспорт (xhttp, kcp, quic) в «голый
// tcp»: узел принимался и никогда не подключался. Теперь тип сохраняется, и узел отвергается проверкой
// с понятной причиной.

func TestL1_MarzbanKeepsUnsupportedTransport(t *testing.T) {
	cases := map[string]string{"xhttp": "XHTTP", "kcp": "mKCP", "splithttp": "XHTTP (SplitHTTP)"}
	for network, want := range cases {
		n := marzbanInboundToNode(marzbanInbound{Tag: "t", Port: 443, Network: network, TLSType: "tls", SNI: "example.org"},
			models.ProtoVLESS, "panel.example.org", "P", "src")
		if n == nil {
			t.Fatalf("%s: узел не построен", network)
		}
		if got := models.UnsupportedTransport(n); got != want {
			t.Errorf("%s: UnsupportedTransport = %q, ожидалось %q (Transport=%+v)", network, got, want, n.Transport)
		}
	}
}

func TestL1_MarzbanPlainTCPAndH2(t *testing.T) {
	for _, network := range []string{"", "tcp", "raw"} {
		n := marzbanInboundToNode(marzbanInbound{Port: 443, Network: network}, models.ProtoVLESS, "h", "P", "s")
		if n.Transport != nil {
			t.Errorf("network=%q: для обычного TCP транспорт не нужен, получен %+v", network, n.Transport)
		}
	}
	n := marzbanInboundToNode(marzbanInbound{Port: 443, Network: "h2", Path: "/p", Host: "x.example.org"}, models.ProtoVLESS, "h", "P", "s")
	if n.Transport == nil || n.Transport.Type != "http" || n.Transport.Path != "/p" {
		t.Errorf("h2 должен стать транспортом http: %+v", n.Transport)
	}
	if models.UnsupportedTransport(n) != "" {
		t.Error("h2/http - поддерживаемый транспорт")
	}
}

func TestL1_ThreeXKeepsUnsupportedTransport(t *testing.T) {
	ib := threeXInbound{
		Remark: "r", Protocol: "vless", Port: 443, Enable: true,
		Settings:       `{"clients":[{"id":"00000000-0000-4000-8000-0000000000aa"}]}`,
		StreamSettings: `{"network":"xhttp","security":"tls","tlsSettings":{"serverName":"example.org"}}`,
	}
	n := threeXInboundToNode(ib, "panel.example.org", "P", "src")
	if n == nil {
		t.Fatal("узел не построен")
	}
	if got := models.UnsupportedTransport(n); got != "XHTTP" {
		t.Errorf("UnsupportedTransport = %q (Transport=%+v)", got, n.Transport)
	}
	ib.StreamSettings = `{"network":"tcp","security":"tls"}`
	if n := threeXInboundToNode(ib, "panel.example.org", "P", "src"); n == nil || n.Transport != nil {
		t.Errorf("обычный tcp: транспорт не нужен, получен %+v", n)
	}
}
