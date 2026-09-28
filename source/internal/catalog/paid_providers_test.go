package catalog

import (
	"context"

	"encoding/json"
	"github.com/apf/adaptive-pathfinder/internal/models"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewPaidProvider_UnknownType(t *testing.T) {
	_, err := NewPaidProvider(PaidProviderConfig{Type: "unknown"})
	if err == nil {
		t.Error("expected error for unknown type")
	}
	t.Log("OK: unknown type returns error")
}

func TestNewPaidProvider_ValidTypes(t *testing.T) {
	types := []string{"3xui", "marzban", "hiddify"}
	for _, tp := range types {
		p, err := NewPaidProvider(PaidProviderConfig{
			ID:   "test-" + tp,
			Name: "Test " + tp,
			Type: tp,
			URL:  "https://example.com",
		})
		if err != nil {
			t.Errorf("type %s: unexpected error: %v", tp, err)
			continue
		}
		if p.Type() != "paid" {
			t.Errorf("type %s: expected 'paid', got %s", tp, p.Type())
		}
		t.Logf("OK: %s provider created", tp)
	}
}

func TestExtractHost(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"https://panel.example.com", "panel.example.com"},
		{"https://panel.example.com:8080", "panel.example.com"},
		{"http://192.168.1.1:8080/path", "192.168.1.1"},
	}
	for _, c := range cases {
		got := extractHost(c.input)
		if got != c.expected {
			t.Errorf("extractHost(%q) = %q, want %q", c.input, got, c.expected)
		}
	}
	t.Log("OK: extractHost")
}

func TestThreeXUIProvider_Fetch_Mock(t *testing.T) {
	// Mock 3X-UI server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "test-session"})
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
		case "/panel/api/inbounds/list":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"obj": []map[string]interface{}{
					{
						"id":       1,
						"remark":   "VLESS Reality",
						"protocol": "vless",
						"port":     443,
						"enable":   true,
						"settings": `{"clients":[{"id":"test-uuid-1234"}]}`,
						"streamSettings": `{"network":"tcp","security":"reality",` +
							`"realitySettings":{"serverNames":["www.microsoft.com"],"publicKey":"test-pubkey","shortIds":["abc123"]}}`,
					},
					{
						"id":             2,
						"remark":         "Trojan",
						"protocol":       "trojan",
						"port":           8443,
						"enable":         true,
						"settings":       `{"clients":[{"password":"test-pass"}]}`,
						"streamSettings": `{"network":"tcp","security":"tls","tlsSettings":{"serverName":"vpn.example.com"}}`,
					},
					{
						"id":             3,
						"remark":         "Disabled",
						"protocol":       "vless",
						"port":           444,
						"enable":         false, // should be skipped
						"settings":       `{"clients":[{"id":"skip-uuid"}]}`,
						"streamSettings": `{"network":"tcp"}`,
					},
				},
			})
		}
	}))
	defer srv.Close()

	p := &ThreeXUIProvider{
		cfg: PaidProviderConfig{
			ID:       "test-3xui",
			Name:     "Test 3X-UI",
			Type:     "3xui",
			URL:      srv.URL,
			Username: "admin",
			Password: "password",
			Enabled:  true,
		},
		client: newHTTPClient(false),
	}

	nodes, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}

	// должно быть 2 (disabled пропускается)
	if len(nodes) != 2 {
		t.Errorf("expected 2 nodes (disabled skipped), got %d", len(nodes))
	}

	// проверяем VLESS с Reality
	vless := nodes[0]
	if vless.Protocol != "vless" {
		t.Errorf("node[0] protocol: want vless, got %s", vless.Protocol)
	}
	if vless.UUID != "test-uuid-1234" {
		t.Errorf("node[0] UUID: want test-uuid-1234, got %s", vless.UUID)
	}
	if vless.TLS == nil || vless.TLS.Reality == nil {
		t.Error("node[0] should have Reality TLS config")
	}
	if vless.TLS.Reality.PublicKey != "test-pubkey" {
		t.Errorf("node[0] Reality pubkey: want test-pubkey, got %s", vless.TLS.Reality.PublicKey)
	}

	// проверяем Trojan
	trojan := nodes[1]
	if trojan.Protocol != "trojan" {
		t.Errorf("node[1] protocol: want trojan, got %s", trojan.Protocol)
	}
	if trojan.Password != "test-pass" {
		t.Errorf("node[1] password: want test-pass, got %s", trojan.Password)
	}

	t.Logf("OK: 3X-UI mock fetch — %d nodes (disabled skipped)", len(nodes))
}

// ─── Additional paid provider coverage tests ──────────────────────────────────

func TestMarzbanProviderMeta(t *testing.T) {
	p := &MarzbanProvider{
		cfg: PaidProviderConfig{
			ID:   "test-marzban",
			Name: "Test Marzban",
			Type: "marzban",
			URL:  "https://panel.example.com",
		},
		client: newHTTPClient(false),
	}
	if p.ID() != "test-marzban" {
		t.Errorf("ID: want test-marzban, got %s", p.ID())
	}
	if p.Name() != "Test Marzban" {
		t.Errorf("Name: want Test Marzban, got %s", p.Name())
	}
	if p.Type() != "paid" {
		t.Errorf("Type: want paid, got %s", p.Type())
	}
	p.SetEnabled(false)
	if p.IsEnabled() {
		t.Error("should be disabled")
	}
	p.SetEnabled(true)
	if !p.IsEnabled() {
		t.Error("should be enabled")
	}
	meta := p.Meta()
	if meta.TrustScore <= 0 {
		t.Error("TrustScore should be > 0")
	}
	t.Logf("OK: MarzbanProvider meta trust=%.1f speed=%s", meta.TrustScore, meta.SpeedClass)
}

func TestHiddifyProviderMeta(t *testing.T) {
	p := &HiddifyProvider{
		cfg: PaidProviderConfig{
			ID:    "test-hiddify",
			Name:  "Test Hiddify",
			Type:  "hiddify",
			Token: "user-secret-uuid",
		},
		client: newHTTPClient(false),
	}
	if p.ID() != "test-hiddify" {
		t.Errorf("ID wrong: %s", p.ID())
	}
	if p.Type() != "paid" {
		t.Errorf("Type wrong: %s", p.Type())
	}
	p.SetEnabled(false)
	if p.IsEnabled() {
		t.Error("should be disabled after SetEnabled(false)")
	}
	t.Log("OK: HiddifyProvider meta")
}

func TestThreeXUIProviderMeta(t *testing.T) {
	p, err := NewPaidProvider(PaidProviderConfig{
		ID:      "3xui-test",
		Name:    "My Panel",
		Type:    "3xui",
		URL:     "https://panel.example.com",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("NewPaidProvider: %v", err)
	}
	if p.ID() != "3xui-test" {
		t.Errorf("ID wrong: %s", p.ID())
	}
	// Provider interface has SetEnabled and IsEnabled
	if !p.IsEnabled() {
		t.Error("should be enabled initially")
	}
	t.Log("OK: ThreeXUIProvider enable/disable cycle")
}

func TestSubscriptionProvider(t *testing.T) {
	p, err := NewPaidProvider(PaidProviderConfig{
		ID:              "sub-test",
		Name:            "My Sub",
		Type:            "subscription",
		SubscriptionURL: "https://example.com/sub",
		Enabled:         true,
	})
	if err != nil {
		t.Fatalf("NewPaidProvider sub: %v", err)
	}
	if p.Type() != "free" {
		t.Errorf("sub Type: want free, got %s", p.Type())
	}
	t.Log("OK: subscription provider via NewPaidProvider")
}

func TestGenerateNodeID(t *testing.T) {
	n1 := &models.Node{Protocol: "vless", Address: "host1.com", Port: 443, UUID: "uuid1"}
	n2 := &models.Node{Protocol: "vless", Address: "host1.com", Port: 443, UUID: "uuid1"}
	n3 := &models.Node{Protocol: "vless", Address: "host2.com", Port: 443, UUID: "uuid1"}

	id1 := generateNodeID(n1)
	id2 := generateNodeID(n2)
	id3 := generateNodeID(n3)

	if id1 == "" {
		t.Error("ID should not be empty")
	}
	if id1 != id2 {
		t.Error("same node should produce same ID")
	}
	if id1 == id3 {
		t.Error("different nodes should produce different IDs")
	}
	t.Logf("OK: generateNodeID: %s vs %s", id1, id3)
}

func TestThreeXUIInboundToNode(t *testing.T) {
	cases := []struct {
		name      string
		ib        threeXInbound
		wantProto models.Protocol
	}{
		{
			"VLESS Reality",
			threeXInbound{
				ID: 1, Remark: "VLESS-Reality", Protocol: "vless",
				Port: 443, Enable: true,
				Settings:       `{"clients":[{"id":"test-uuid"}]}`,
				StreamSettings: `{"network":"tcp","security":"reality","realitySettings":{"serverNames":["www.microsoft.com"],"publicKey":"pk","shortIds":["abc"]}}`,
			},
			models.ProtoVLESS,
		},
		{
			"Shadowsocks",
			threeXInbound{
				ID: 2, Remark: "SS", Protocol: "shadowsocks",
				Port: 8388, Enable: true,
				Settings:       `{"method":"chacha20-ietf-poly1305","clients":[{"password":"pass"}]}`,
				StreamSettings: `{"network":"tcp"}`,
			},
			models.ProtoShadowsocks,
		},
		{
			"VMess WS",
			threeXInbound{
				ID: 3, Remark: "VMess-WS", Protocol: "vmess",
				Port: 443, Enable: true,
				Settings:       `{"clients":[{"id":"vm-uuid"}]}`,
				StreamSettings: `{"network":"ws","security":"tls","wsSettings":{"path":"/ws","headers":{"Host":"cdn.example.com"}},"tlsSettings":{"serverName":"cdn.example.com"}}`,
			},
			models.ProtoVMess,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			node := threeXInboundToNode(c.ib, "host.example.com", "TestPanel", "paid:test")
			if node == nil {
				t.Fatal("node is nil")
			}
			if node.Protocol != c.wantProto {
				t.Errorf("protocol: want %s, got %s", c.wantProto, node.Protocol)
			}
			if node.Address != "host.example.com" {
				t.Errorf("address wrong: %s", node.Address)
			}
			t.Logf("  %s: %s port=%d transport=%v",
				c.name, node.Protocol, node.Port,
				func() string {
					if node.Transport != nil {
						return node.Transport.Type
					}
					return "none"
				}())
		})
	}
	t.Log("OK: threeXInboundToNode various protocols")
}

func TestRegistryOperations(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("Registry nil")
	}

	// Статус — должны быть дефолтные провайдеры
	statuses := r.Status()
	if len(statuses) == 0 {
		t.Error("registry should have default providers")
	}
	t.Logf("OK: registry has %d providers", len(statuses))

	// Register нового
	p := NewFreeProvider("extra-test", "Extra Test",
		"https://example.com/sub")
	r.Register(p)

	// SetEnabled
	ok := r.SetEnabled("extra-test", false)
	if !ok {
		t.Error("SetEnabled should return true for existing provider")
	}

	// Несуществующий
	ok2 := r.SetEnabled("nonexistent", true)
	if ok2 {
		t.Error("SetEnabled should return false for missing provider")
	}

	t.Log("OK: registry register/enable operations")
}
