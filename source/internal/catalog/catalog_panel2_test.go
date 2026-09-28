package catalog

// catalog_panel2_test.go — covers trivial provider methods and Fetch paths
// that were at 0% in panel_providers.go and providers.go.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── ThreeXUIProvider trivial methods ────────────────────────────────────────

func TestThreeXUIProvider_TrivialMethods(t *testing.T) {
	p := &ThreeXUIProvider{
		cfg:     PaidProviderConfig{ID: "3x-1", Name: "My3XUI"},
		client:  http.DefaultClient,
		enabled: false,
	}

	if got := p.Name(); got != "My3XUI" {
		t.Errorf("Name() = %q, want %q", got, "My3XUI")
	}
	p.SetEnabled(true)
	if !p.IsEnabled() {
		t.Error("SetEnabled(true): IsEnabled() = false")
	}
	p.SetEnabled(false)
	if p.IsEnabled() {
		t.Error("SetEnabled(false): IsEnabled() = true")
	}

	// Meta with zero TrustScore → defaultPanelMeta()
	m := p.Meta()
	if m.TrustScore <= 0 {
		t.Error("Meta() with zero TrustScore should return defaultPanelMeta (TrustScore > 0)")
	}

	// Meta with positive TrustScore → returns stored meta
	p.meta = ProviderMeta{TrustScore: 0.8, Region: "EU"}
	m2 := p.Meta()
	if m2.TrustScore != 0.8 || m2.Region != "EU" {
		t.Errorf("Meta() with stored TrustScore=0.8: got %+v", m2)
	}
}

// ─── MarzbanProvider trivial methods ─────────────────────────────────────────

func TestMarzbanProvider_TrivialMethods(t *testing.T) {
	p := &MarzbanProvider{
		cfg:     PaidProviderConfig{ID: "mrz-1", Name: "MyMarzban"},
		client:  http.DefaultClient,
		enabled: true,
	}

	if got := p.Name(); got != "MyMarzban" {
		t.Errorf("Name() = %q", got)
	}
	if !p.IsEnabled() {
		t.Error("IsEnabled() should be true")
	}
	p.SetEnabled(false)
	if p.IsEnabled() {
		t.Error("SetEnabled(false) did not take effect")
	}

	// Meta zero TrustScore → defaultPanelMeta
	m := p.Meta()
	if m.TrustScore <= 0 {
		t.Errorf("Meta() default: TrustScore should be > 0, got %v", m.TrustScore)
	}

	// Meta with positive TrustScore
	p.meta = ProviderMeta{TrustScore: 0.95}
	m2 := p.Meta()
	if m2.TrustScore != 0.95 {
		t.Errorf("Meta() stored: got TrustScore=%v", m2.TrustScore)
	}
}

// TestMarzbanProvider_Fetch_Mock exercises the full Fetch path with a mock server.
func TestMarzbanProvider_Fetch_Mock(t *testing.T) {
	mux := http.NewServeMux()

	// 1. Token endpoint
	mux.HandleFunc("/api/admin/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-bearer-token",
		})
	})

	// 2. Inbounds endpoint — return vless + unknown protocol
	mux.HandleFunc("/api/inbounds", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-bearer-token" {
			http.Error(w, "unauthorized", 401)
			return
		}
		inbounds := map[string][]marzbanInbound{
			"vless": {
				{
					Tag:     "vless-inbound",
					Port:    443,
					Network: "tcp",
					TLSType: "tls",
					SNI:     "example.com",
				},
			},
			"unknownproto": { // should be skipped (mapXProtocol → "")
				{Tag: "skip-me", Port: 1234},
			},
		}
		json.NewEncoder(w).Encode(inbounds)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := &MarzbanProvider{
		cfg: PaidProviderConfig{
			ID:       "mrz-test",
			Name:     "TestMarzban",
			URL:      srv.URL,
			Username: "admin",
			Password: "secret",
		},
		client: srv.Client(),
	}

	nodes, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	_ = nodes
	if p.meta.LastUpdated.IsZero() {
		t.Error("LastUpdated not set after Fetch")
	}
}

// TestMarzbanProvider_Fetch_AuthError exercises the auth HTTP error path.
func TestMarzbanProvider_Fetch_AuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	p := &MarzbanProvider{
		cfg:    PaidProviderConfig{URL: srv.URL},
		client: srv.Client(),
	}
	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Error("expected error on auth failure")
	}
}

// ─── HiddifyProvider trivial methods ─────────────────────────────────────────

func TestHiddifyProvider_TrivialMethods(t *testing.T) {
	p := &HiddifyProvider{
		cfg:     PaidProviderConfig{ID: "hid-1", Name: "MyHiddify"},
		client:  http.DefaultClient,
		enabled: false,
	}

	if got := p.Name(); got != "MyHiddify" {
		t.Errorf("Name() = %q", got)
	}
	if p.IsEnabled() {
		t.Error("IsEnabled() should be false initially")
	}
	p.SetEnabled(true)
	if !p.IsEnabled() {
		t.Error("SetEnabled(true) did not take effect")
	}

	// Meta zero TrustScore → defaultPanelMeta
	m := p.Meta()
	if m.TrustScore <= 0 {
		t.Errorf("Meta() default: TrustScore should be > 0, got %v", m.TrustScore)
	}

	// Meta with positive TrustScore
	p.meta = ProviderMeta{TrustScore: 0.7, Region: "AS"}
	m2 := p.Meta()
	if m2.TrustScore != 0.7 {
		t.Errorf("Meta() stored: got TrustScore=%v", m2.TrustScore)
	}
}

// TestHiddifyProvider_Fetch_Mock exercises HiddifyProvider.Fetch via mock server.
func TestHiddifyProvider_Fetch_Mock(t *testing.T) {
	vlessURI := "vless://12345678-1234-1234-1234-123456789012@192.168.1.1:443?type=tcp&security=tls#test-node"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(vlessURI + "\n"))
	}))
	defer srv.Close()

	p := &HiddifyProvider{
		cfg: PaidProviderConfig{
			ID:              "hid-test",
			Name:            "TestHiddify",
			SubscriptionURL: srv.URL + "/sub",
		},
		client: srv.Client(),
	}

	nodes, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	_ = nodes
	if p.meta.LastUpdated.IsZero() {
		t.Error("LastUpdated not set after Fetch")
	}
}

// TestHiddifyProvider_Fetch_HTTPError exercises the HTTP error branch.
func TestHiddifyProvider_Fetch_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	p := &HiddifyProvider{
		cfg:    PaidProviderConfig{SubscriptionURL: srv.URL},
		client: srv.Client(),
	}
	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Error("expected error on HTTP 404")
	}
}

// ─── FreeSubscriptionProvider.Fetch ─────────────────────────────────────────

// TestFreeSubscriptionProvider_Fetch_Mock exercises providers.go:83 Fetch.
func TestFreeSubscriptionProvider_Fetch_Mock(t *testing.T) {
	vlessURI := "vless://12345678-1234-1234-1234-123456789012@10.0.0.1:443?type=tcp#free-node"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(vlessURI + "\n"))
	}))
	defer srv.Close()

	p := NewFreeProvider("free-test", "FreeSub", srv.URL)
	p.client = srv.Client()

	nodes, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	for _, n := range nodes {
		if n.Source != "free-test" {
			t.Errorf("node.Source = %q, want %q", n.Source, "free-test")
		}
	}
}

// TestFreeSubscriptionProvider_Fetch_HTTPError tests non-200 response.
func TestFreeSubscriptionProvider_Fetch_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	p := NewFreeProvider("free-err", "FreeErr", srv.URL)
	p.client = srv.Client()

	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Error("expected error on HTTP 503")
	}
}

// ─── mapXProtocol missing branches ──────────────────────────────────────────

func TestMapXProtocol_AllBranches(t *testing.T) {
	cases := []struct {
		input string
		want  models.Protocol
	}{
		{"vless", models.ProtoVLESS},
		{"VLESS", models.ProtoVLESS},
		{"vmess", models.ProtoVMess},
		{"trojan", models.ProtoTrojan},
		{"shadowsocks", models.ProtoShadowsocks},
		{"wireguard", models.ProtoWireGuard},
		{"unknown", ""},
		{"grpc", ""},
	}
	for _, c := range cases {
		got := mapXProtocol(c.input)
		if got != c.want {
			t.Errorf("mapXProtocol(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

// ─── Registry.SetEnabled not-found ───────────────────────────────────────────

func TestRegistry_SetEnabled_IDMissing(t *testing.T) {
	r := NewRegistry()
	ok := r.SetEnabled("nonexistent-provider-id-panel2", true)
	if ok {
		t.Error("SetEnabled on nonexistent ID should return false")
	}
}

// ─── ManualProvider.RemoveNode — node found ───────────────────────────────────

func TestManualProvider_RemoveNode_Found(t *testing.T) {
	mp, ok := NewRegistry().Get("manual")
	if !ok {
		t.Skip("manual provider not in registry")
	}
	manual, ok := mp.(*ManualProvider)
	if !ok {
		t.Skip("unexpected type for manual provider")
	}

	n1 := &models.Node{ID: "keep-me-p2", Protocol: models.ProtoVLESS}
	n2 := &models.Node{ID: "remove-me-p2", Protocol: models.ProtoVMess}
	manual.AddNode(n1)
	manual.AddNode(n2)

	manual.RemoveNode("remove-me-p2")

	nodes, _ := manual.Fetch(context.Background())
	for _, n := range nodes {
		if n.ID == "remove-me-p2" {
			t.Error("node 'remove-me-p2' should have been removed")
		}
	}
}

// ─── newHTTPClient branches ───────────────────────────────────────────────────

func TestNewHTTPClient_Insecure(t *testing.T) {
	c := newHTTPClient(true)
	if c == nil {
		t.Error("expected non-nil http.Client")
	}
}

func TestNewHTTPClient_Secure(t *testing.T) {
	c := newHTTPClient(false)
	if c == nil {
		t.Error("expected non-nil http.Client")
	}
}

// ─── NewPaidProvider URL-required branches ────────────────────────────────────

func TestNewPaidProvider_3XUI_NoURL(t *testing.T) {
	_, err := NewPaidProvider(PaidProviderConfig{Type: "3xui", Name: "test"})
	if err == nil {
		t.Error("expected error when URL is empty for 3xui")
	}
}

func TestNewPaidProvider_Marzban_NoURL(t *testing.T) {
	_, err := NewPaidProvider(PaidProviderConfig{Type: "marzban", Name: "test"})
	if err == nil {
		t.Error("expected error when URL is empty for marzban")
	}
}

func TestNewPaidProvider_Hiddify_NoURLNoToken(t *testing.T) {
	_, err := NewPaidProvider(PaidProviderConfig{Type: "hiddify", Name: "test"})
	if err == nil {
		t.Error("expected error when URL, Token, and SubscriptionURL are all empty for hiddify")
	}
}

func TestNewPaidProvider_Subscription_NoURL(t *testing.T) {
	_, err := NewPaidProvider(PaidProviderConfig{Type: "subscription", Name: "test"})
	if err == nil {
		t.Error("expected error when URL is empty for subscription")
	}
}

func TestNewPaidProvider_Subscription_WithURL(t *testing.T) {
	p, err := NewPaidProvider(PaidProviderConfig{
		Type: "subscription",
		Name: "test-sub",
		URL:  "https://example.com/sub",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Type() != "free" {
		t.Errorf("Type() = %q, want free", p.Type())
	}
}
