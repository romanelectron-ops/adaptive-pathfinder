package catalog

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ─── extractHost — url.Parse error path ──────────────────────────────────────

func TestExtractHost_InvalidURL(t *testing.T) {
	// A URL with a null byte is rejected by url.Parse → extractHost returns rawURL.
	raw := "\x00://bad"
	got := extractHost(raw)
	if got != raw {
		t.Errorf("extractHost(%q) = %q, want raw string back", raw, got)
	}
	t.Logf("OK: extractHost invalid → returned raw %q", got)
}

// ─── threeXInboundToNode — unknown protocol → nil ────────────────────────────

func TestThreeXInboundToNode_UnknownProtocol(t *testing.T) {
	ib := threeXInbound{Protocol: "unknown_xyz", Port: 443, Enable: true}
	node := threeXInboundToNode(ib, "host.example.com", "TestPanel", "paid:test")
	if node != nil {
		t.Errorf("expected nil for unknown protocol, got %+v", node)
	}
	t.Log("OK: threeXInboundToNode unknown protocol → nil")
}

// ─── threeXInboundToNode — grpc transport (lines 429-433) ────────────────────

func TestThreeXInboundToNode_GRPCTransport(t *testing.T) {
	stream := `{"network":"grpc","grpcSettings":{"serviceName":"my-svc"}}`
	ib := threeXInbound{
		Protocol:       "vless",
		Port:           443,
		Enable:         true,
		Settings:       `{"clients":[{"id":"test-uuid","password":""}]}`,
		StreamSettings: stream,
	}
	node := threeXInboundToNode(ib, "grpc.example.com", "GRPCPanel", "paid:test")
	if node == nil {
		t.Fatal("expected non-nil node for grpc transport")
	}
	if node.Transport == nil {
		t.Fatal("expected Transport to be set for grpc")
	}
	if node.Transport.Type != "grpc" {
		t.Errorf("Transport.Type = %q, want %q", node.Transport.Type, "grpc")
	}
	if node.Transport.Path != "my-svc" {
		t.Errorf("Transport.Path = %q, want %q", node.Transport.Path, "my-svc")
	}
	t.Logf("OK: threeXInboundToNode grpc transport → path=%q", node.Transport.Path)
}

func TestThreeXInboundToNode_GRPCTransport_NilGRPC(t *testing.T) {
	// grpc network but no grpcSettings → Transport set but Path stays empty.
	stream := `{"network":"grpc"}`
	ib := threeXInbound{
		Protocol:       "vmess",
		Port:           8080,
		Enable:         true,
		StreamSettings: stream,
	}
	node := threeXInboundToNode(ib, "grpc2.example.com", "P2", "paid:test")
	if node == nil {
		t.Fatal("expected non-nil node")
	}
	if node.Transport == nil || node.Transport.Type != "grpc" {
		t.Errorf("expected grpc transport, got %+v", node.Transport)
	}
	if node.Transport.Path != "" {
		t.Errorf("expected empty Path for nil grpcSettings, got %q", node.Transport.Path)
	}
	t.Log("OK: threeXInboundToNode grpc nil GRPC settings → empty path")
}

// ─── Registry.SetEnabled — non-toggler provider (line 137) ───────────────────

func TestRegistry_SetEnabled_NoToggler(t *testing.T) {
	// ManualProvider and TorBridgeProvider have no SetEnabled method.
	// NewRegistry registers both.  Calling SetEnabled on "manual" must return false.
	r := NewRegistry()
	got := r.SetEnabled("manual", false)
	if got {
		t.Error("SetEnabled on ManualProvider (no toggler) should return false")
	}
	t.Log("OK: Registry.SetEnabled non-toggler → false")
}

// ─── FreeSubscriptionProvider.Fetch — invalid URL (lines 84-86) ──────────────

func TestFreeSubscriptionProvider_Fetch_InvalidURL(t *testing.T) {
	// A URL with a null byte causes http.NewRequestWithContext to fail.
	p := NewFreeProvider("bad-url", "BadURL", "\x00://invalid")
	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Error("expected error for invalid request URL")
	}
	t.Logf("OK: Fetch invalid URL → %v", err)
}

// ─── FreeSubscriptionProvider.Fetch — client.Do error (lines 90-92) ─────────

type errRoundTripper struct{ err error }

func (e *errRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, e.err
}

func TestFreeSubscriptionProvider_Fetch_DoError(t *testing.T) {
	p := NewFreeProvider("do-err", "DoErr", "http://127.0.0.1:0/sub")
	p.client = &http.Client{
		Transport: &errRoundTripper{err: errors.New("dial refused")},
	}
	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Error("expected error when client.Do fails")
	}
	t.Logf("OK: Fetch client.Do error → %v", err)
}

// ─── FreeSubscriptionProvider.Fetch — base64 body (lines 105-107) ────────────

func TestFreeSubscriptionProvider_Fetch_Base64Body(t *testing.T) {
	// Serve a base64-encoded vless URI so tryBase64Decode succeeds.
	vlessURI := "vless://12345678-1234-1234-1234-123456789012@10.0.0.1:443?type=tcp#b64-node"
	b64body := base64.StdEncoding.EncodeToString([]byte(vlessURI))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(b64body))
	}))
	defer srv.Close()

	p := NewFreeProvider("b64-test", "B64Sub", srv.URL)
	p.client = srv.Client()

	nodes, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch base64 body: %v", err)
	}
	if len(nodes) == 0 {
		t.Error("expected at least one node from decoded base64 subscription")
	}
	t.Logf("OK: Fetch base64 body → %d node(s)", len(nodes))
}
