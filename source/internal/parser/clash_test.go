package parser

import (
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ---------------------------------------------------------------------------
// ParseClashYAML — многострочный формат
// ---------------------------------------------------------------------------

func TestParseClashYAML_SS(t *testing.T) {
	yaml := `
proxies:
  - name: MySS
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: secret123
`
	nodes, err := ParseClashYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	n := nodes[0]
	if n.Protocol != models.ProtoShadowsocks {
		t.Errorf("protocol: want ss, got %s", n.Protocol)
	}
	if n.Address != "1.2.3.4" {
		t.Errorf("address: want 1.2.3.4, got %s", n.Address)
	}
	if n.Port != 8388 {
		t.Errorf("port: want 8388, got %d", n.Port)
	}
	if n.Method != "aes-256-gcm" {
		t.Errorf("cipher: want aes-256-gcm, got %s", n.Method)
	}
	if n.Password != "secret123" {
		t.Errorf("password: want secret123, got %s", n.Password)
	}
	if n.Name != "MySS" {
		t.Errorf("name: want MySS, got %s", n.Name)
	}
	t.Logf("OK: %s %s:%d method=%s", n.Protocol, n.Address, n.Port, n.Method)
}

func TestParseClashYAML_VMess(t *testing.T) {
	yaml := `
proxies:
  - name: MyVMess
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 12345678-abcd-abcd-abcd-123456789012
    alterId: 0
    tls: true
    network: ws
    ws-path: /ray
`
	nodes, err := ParseClashYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	n := nodes[0]
	if n.Protocol != models.ProtoVMess {
		t.Errorf("protocol: want vmess, got %s", n.Protocol)
	}
	if n.UUID != "12345678-abcd-abcd-abcd-123456789012" {
		t.Errorf("uuid mismatch: %s", n.UUID)
	}
	if n.TLS == nil || !n.TLS.Enabled {
		t.Error("TLS should be enabled")
	}
	if n.Transport == nil || n.Transport.Type != "ws" {
		t.Errorf("transport type: want ws, got %v", n.Transport)
	}
	if n.Transport.Path != "/ray" {
		t.Errorf("ws-path: want /ray, got %s", n.Transport.Path)
	}
	t.Logf("OK: %s %s:%d tls=%v ws-path=%s", n.Protocol, n.Address, n.Port, n.TLS.Enabled, n.Transport.Path)
}

func TestParseClashYAML_Trojan(t *testing.T) {
	yaml := `
proxies:
  - name: MyTrojan
    type: trojan
    server: trojan.example.com
    port: 443
    password: trojanpass
    sni: trojan.example.com
`
	nodes, err := ParseClashYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	n := nodes[0]
	if n.Protocol != models.ProtoTrojan {
		t.Errorf("protocol: want trojan, got %s", n.Protocol)
	}
	if n.Password != "trojanpass" {
		t.Errorf("password mismatch: %s", n.Password)
	}
	if n.TLS == nil || n.TLS.ServerName != "trojan.example.com" {
		t.Errorf("TLS SNI: want trojan.example.com, got %v", n.TLS)
	}
	t.Logf("OK: %s %s:%d sni=%s", n.Protocol, n.Address, n.Port, n.TLS.ServerName)
}

func TestParseClashYAML_VLESS(t *testing.T) {
	yaml := `
proxies:
  - name: MyVLESS
    type: vless
    server: vless.example.com
    port: 443
    uuid: aaaabbbb-cccc-dddd-eeee-ffffaaaabbbb
    tls: true
    flow: xtls-rprx-vision
    network: tcp
`
	nodes, err := ParseClashYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	n := nodes[0]
	if n.Protocol != models.ProtoVLESS {
		t.Errorf("protocol: want vless, got %s", n.Protocol)
	}
	if n.UUID != "aaaabbbb-cccc-dddd-eeee-ffffaaaabbbb" {
		t.Errorf("uuid mismatch: %s", n.UUID)
	}
	if n.Flow != "xtls-rprx-vision" {
		t.Errorf("flow mismatch: %s", n.Flow)
	}
	if n.TLS == nil || !n.TLS.Enabled {
		t.Error("TLS should be enabled")
	}
	// network=tcp → Transport должен быть nil
	if n.Transport != nil {
		t.Errorf("tcp network should not set Transport, got %v", n.Transport)
	}
	t.Logf("OK: %s %s:%d flow=%s", n.Protocol, n.Address, n.Port, n.Flow)
}

// ---------------------------------------------------------------------------
// ParseClashYAML — инлайн формат
// ---------------------------------------------------------------------------

func TestParseClashYAML_InlineSS(t *testing.T) {
	yaml := `proxies:
  - {name: InlineSS, type: ss, server: 5.6.7.8, port: 1080, cipher: chacha20-ietf-poly1305, password: inline_pass}
`
	nodes, err := ParseClashYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	n := nodes[0]
	if n.Protocol != models.ProtoShadowsocks {
		t.Errorf("protocol: want ss, got %s", n.Protocol)
	}
	if n.Method != "chacha20-ietf-poly1305" {
		t.Errorf("cipher mismatch: %s", n.Method)
	}
	if n.Password != "inline_pass" {
		t.Errorf("password mismatch: %s", n.Password)
	}
	t.Logf("OK inline: %s %s:%d", n.Protocol, n.Address, n.Port)
}

// ---------------------------------------------------------------------------
// ParseClashYAML — граничные случаи
// ---------------------------------------------------------------------------

func TestParseClashYAML_UnknownType(t *testing.T) {
	yaml := `
proxies:
  - name: Unknown
    type: wireguard
    server: wg.example.com
    port: 51820
`
	nodes, err := ParseClashYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// wireguard не поддерживается в Clash-парсере — должно вернуть 0 узлов
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes for unknown type, got %d", len(nodes))
	}
	t.Log("OK: unknown type silently skipped")
}

func TestParseClashYAML_EmptyProxies(t *testing.T) {
	yaml := `
rules:
  - DOMAIN-SUFFIX,example.com,DIRECT
proxies:
`
	nodes, err := ParseClashYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(nodes))
	}
	t.Log("OK: empty proxies section")
}

func TestParseClashYAML_MissingFields(t *testing.T) {
	// Нет server — должно молча пропустить
	yaml := `
proxies:
  - name: Incomplete
    type: ss
    port: 8388
    cipher: aes-256-gcm
    password: pass
`
	nodes, err := ParseClashYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes (missing server), got %d", len(nodes))
	}
	t.Log("OK: missing server → skipped")
}

func TestParseClashYAML_InvalidPort(t *testing.T) {
	yaml := `
proxies:
  - name: BadPort
    type: ss
    server: 1.2.3.4
    port: 99999
    cipher: aes-256-gcm
    password: pass
`
	nodes, err := ParseClashYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes (invalid port), got %d", len(nodes))
	}
	t.Log("OK: invalid port → skipped")
}

func TestParseClashYAML_MultipleProxies(t *testing.T) {
	yaml := `
proxies:
  - name: SS1
    type: ss
    server: 1.1.1.1
    port: 8388
    cipher: aes-256-gcm
    password: pass1
  - name: Trojan1
    type: trojan
    server: 2.2.2.2
    port: 443
    password: trpass
    sni: srv.example.com
  - name: BadType
    type: http
    server: 3.3.3.3
    port: 8080
`
	nodes, err := ParseClashYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// http не поддерживается → 2 узла
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}
	if nodes[0].Protocol != models.ProtoShadowsocks {
		t.Errorf("first node: want ss, got %s", nodes[0].Protocol)
	}
	if nodes[1].Protocol != models.ProtoTrojan {
		t.Errorf("second node: want trojan, got %s", nodes[1].Protocol)
	}
	t.Logf("OK: parsed %d nodes (http skipped)", len(nodes))
}

func TestParseClashYAML_IDIsStable(t *testing.T) {
	yaml := `
proxies:
  - name: StableID
    type: ss
    server: 10.0.0.1
    port: 1234
    cipher: aes-128-gcm
    password: pwd
`
	nodes1, _ := ParseClashYAML([]byte(yaml))
	nodes2, _ := ParseClashYAML([]byte(yaml))

	if len(nodes1) != 1 || len(nodes2) != 1 {
		t.Fatal("expected 1 node each parse")
	}
	if nodes1[0].ID != nodes2[0].ID {
		t.Errorf("ID should be stable: %s vs %s", nodes1[0].ID, nodes2[0].ID)
	}
	if nodes1[0].ID == "" {
		t.Error("ID should not be empty")
	}
	t.Logf("OK: stable ID=%s", nodes1[0].ID)
}

// ---------------------------------------------------------------------------
// clashBuildNode — прямое юнит-тестирование вспомогательной функции
// ---------------------------------------------------------------------------

func TestClashBuildNode_AutoName(t *testing.T) {
	f := map[string]string{
		"type":     "ss",
		"server":   "9.9.9.9",
		"port":     "9999",
		"cipher":   "aes-256-gcm",
		"password": "p",
		// name намеренно отсутствует
	}
	n := clashBuildNode(f)
	if n == nil {
		t.Fatal("expected non-nil node")
	}
	// Имя должно быть автоматически сгенерировано
	if n.Name == "" {
		t.Error("Name should be auto-generated when missing")
	}
	t.Logf("OK: auto-name=%s", n.Name)
}

func TestClashBuildNode_EmptyType(t *testing.T) {
	f := map[string]string{"server": "1.2.3.4", "port": "443"}
	if clashBuildNode(f) != nil {
		t.Error("empty type should return nil")
	}
}

func TestClashBuildNode_EmptyServer(t *testing.T) {
	f := map[string]string{"type": "ss", "port": "443", "cipher": "aes-256-gcm", "password": "x"}
	if clashBuildNode(f) != nil {
		t.Error("empty server should return nil")
	}
}

func TestClashParseField_Basic(t *testing.T) {
	f := make(map[string]string)
	clashParseField("server: example.com", f)
	if f["server"] != "example.com" {
		t.Errorf("want example.com, got %s", f["server"])
	}
}

func TestClashParseField_QuotedValue(t *testing.T) {
	f := make(map[string]string)
	clashParseField(`name: "My Server"`, f)
	if f["name"] != "My Server" {
		t.Errorf("want 'My Server', got %s", f["name"])
	}
}

func TestClashParseField_NoColon(t *testing.T) {
	f := make(map[string]string)
	clashParseField("no-colon-here", f)
	if len(f) != 0 {
		t.Error("no colon should produce no field")
	}
}
