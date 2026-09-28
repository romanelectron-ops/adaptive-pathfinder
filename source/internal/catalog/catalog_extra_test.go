package catalog

// catalog_extra_test.go — дополнительные тесты для повышения покрытия catalog.
// Цель: +2% — закрыть tryBase64Decode и marzbanInboundToNode.

import (
	"encoding/base64"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── tryBase64Decode ──────────────────────────────────────────────────────────

func TestTryBase64Decode_StdEncoding(t *testing.T) {
	original := "hello, APF world!"
	encoded := base64.StdEncoding.EncodeToString([]byte(original))
	got, err := tryBase64Decode(encoded)
	if err != nil {
		t.Fatalf("tryBase64Decode(StdEncoding) error: %v", err)
	}
	if got != original {
		t.Errorf("got %q, want %q", got, original)
	}
	t.Logf("OK: tryBase64Decode StdEncoding: %q", got)
}

func TestTryBase64Decode_RawEncoding(t *testing.T) {
	// RawStdEncoding — без символа '=' на конце.
	original := "raw base64 test"
	encoded := base64.RawStdEncoding.EncodeToString([]byte(original))
	got, err := tryBase64Decode(encoded)
	if err != nil {
		t.Fatalf("tryBase64Decode(RawStdEncoding) error: %v", err)
	}
	if got != original {
		t.Errorf("got %q, want %q", got, original)
	}
	t.Logf("OK: tryBase64Decode RawStdEncoding: %q", got)
}

func TestTryBase64Decode_Invalid(t *testing.T) {
	_, err := tryBase64Decode("this is NOT base64 !!!")
	if err == nil {
		t.Error("tryBase64Decode invalid: expected error, got nil")
	}
	t.Logf("OK: tryBase64Decode invalid returns error: %v", err)
}

func TestTryBase64Decode_WithWhitespace(t *testing.T) {
	original := "trimmed"
	encoded := "  " + base64.StdEncoding.EncodeToString([]byte(original)) + "\n"
	got, err := tryBase64Decode(encoded)
	if err != nil {
		t.Fatalf("tryBase64Decode(whitespace) error: %v", err)
	}
	if got != original {
		t.Errorf("got %q, want %q", got, original)
	}
	t.Log("OK: tryBase64Decode with surrounding whitespace")
}

// ─── marzbanInboundToNode ─────────────────────────────────────────────────────

func TestMarzbanInboundToNode_PortZero(t *testing.T) {
	ib := marzbanInbound{Tag: "test", Port: 0}
	n := marzbanInboundToNode(ib, models.ProtoVLESS, "host.example.com", "Panel", "paid:test")
	if n != nil {
		t.Errorf("marzbanInboundToNode: expected nil for port=0, got %+v", n)
	}
	t.Log("OK: marzbanInboundToNode port=0 returns nil")
}

func TestMarzbanInboundToNode_BasicTCP(t *testing.T) {
	ib := marzbanInbound{
		Tag:  "vless-tcp",
		Port: 443,
	}
	n := marzbanInboundToNode(ib, models.ProtoVLESS, "host.example.com", "MyPanel", "paid:test")
	if n == nil {
		t.Fatal("marzbanInboundToNode: expected non-nil node for port=443")
	}
	if n.Protocol != models.ProtoVLESS {
		t.Errorf("protocol: want vless, got %s", n.Protocol)
	}
	if n.Address != "host.example.com" {
		t.Errorf("address: want host.example.com, got %s", n.Address)
	}
	if n.Port != 443 {
		t.Errorf("port: want 443, got %d", n.Port)
	}
	if n.Transport != nil {
		t.Errorf("transport should be nil for tcp, got %+v", n.Transport)
	}
	if n.TLS != nil {
		t.Errorf("TLS should be nil when tlsType empty, got %+v", n.TLS)
	}
	t.Logf("OK: marzbanInboundToNode basic TCP: %s:%d", n.Address, n.Port)
}

func TestMarzbanInboundToNode_WSTransport(t *testing.T) {
	ib := marzbanInbound{
		Tag:     "vless-ws",
		Port:    443,
		Network: "ws",
		Path:    "/ws",
		Host:    "cdn.example.com",
	}
	n := marzbanInboundToNode(ib, models.ProtoVLESS, "host.example.com", "Panel", "paid:test")
	if n == nil {
		t.Fatal("node is nil")
	}
	if n.Transport == nil {
		t.Fatal("Transport is nil for ws network")
	}
	if n.Transport.Type != "ws" {
		t.Errorf("Transport.Type: want ws, got %s", n.Transport.Type)
	}
	if n.Transport.Path != "/ws" {
		t.Errorf("Transport.Path: want /ws, got %s", n.Transport.Path)
	}
	if n.Transport.Host != "cdn.example.com" {
		t.Errorf("Transport.Host: want cdn.example.com, got %s", n.Transport.Host)
	}
	t.Log("OK: marzbanInboundToNode WS transport")
}

func TestMarzbanInboundToNode_GRPCTransport(t *testing.T) {
	ib := marzbanInbound{
		Tag:     "vless-grpc",
		Port:    443,
		Network: "grpc",
		Path:    "grpc-service",
	}
	n := marzbanInboundToNode(ib, models.ProtoVLESS, "host.example.com", "Panel", "paid:test")
	if n == nil {
		t.Fatal("node is nil")
	}
	if n.Transport == nil {
		t.Fatal("Transport is nil for grpc network")
	}
	if n.Transport.Type != "grpc" {
		t.Errorf("Transport.Type: want grpc, got %s", n.Transport.Type)
	}
	t.Log("OK: marzbanInboundToNode gRPC transport")
}

func TestMarzbanInboundToNode_TLS(t *testing.T) {
	ib := marzbanInbound{
		Tag:     "trojan-tls",
		Port:    8443,
		TLSType: "tls",
		SNI:     "vpn.example.com",
	}
	n := marzbanInboundToNode(ib, models.ProtoTrojan, "host.example.com", "Panel", "paid:test")
	if n == nil {
		t.Fatal("node is nil")
	}
	if n.TLS == nil {
		t.Fatal("TLS is nil for tls type")
	}
	if !n.TLS.Enabled {
		t.Error("TLS.Enabled should be true")
	}
	if n.TLS.ServerName != "vpn.example.com" {
		t.Errorf("TLS.ServerName: want vpn.example.com, got %s", n.TLS.ServerName)
	}
	if n.TLS.Reality != nil {
		t.Error("TLS.Reality should be nil for plain TLS")
	}
	t.Log("OK: marzbanInboundToNode TLS")
}

func TestMarzbanInboundToNode_Reality(t *testing.T) {
	ib := marzbanInbound{
		Tag:     "vless-reality",
		Port:    443,
		TLSType: "reality",
		SNI:     "www.microsoft.com",
	}
	n := marzbanInboundToNode(ib, models.ProtoVLESS, "host.example.com", "Panel", "paid:test")
	if n == nil {
		t.Fatal("node is nil")
	}
	if n.TLS == nil {
		t.Fatal("TLS is nil for reality type")
	}
	if n.TLS.Reality == nil {
		t.Fatal("TLS.Reality is nil for reality type")
	}
	if !n.TLS.Enabled {
		t.Error("TLS.Enabled should be true")
	}
	if n.TLS.ServerName != "www.microsoft.com" {
		t.Errorf("TLS.ServerName: want www.microsoft.com, got %s", n.TLS.ServerName)
	}
	t.Log("OK: marzbanInboundToNode Reality TLS")
}

func TestMarzbanInboundToNode_TagFallback(t *testing.T) {
	// When tag is empty, name should contain protocol string.
	ib := marzbanInbound{
		Tag:  "",
		Port: 1080,
	}
	n := marzbanInboundToNode(ib, models.ProtoShadowsocks, "host.example.com", "Panel", "paid:test")
	if n == nil {
		t.Fatal("node is nil")
	}
	if n.Name == "" {
		t.Error("node Name should not be empty")
	}
	t.Logf("OK: marzbanInboundToNode tag fallback, Name=%q", n.Name)
}
