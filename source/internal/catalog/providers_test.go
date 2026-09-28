package catalog

import (
	"context"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// newEmptyRegistry создаёт Registry без дефолтных провайдеров (для изолированных тестов)
func newEmptyRegistry() *Registry {
	return &Registry{providers: make(map[string]Provider)}
}

// ── FreeSubscriptionProvider ──────────────────────────────────────────────────

func TestFreeProvider_ID_Name_Type(t *testing.T) {
	p := NewFreeProvider("my-id", "My Name", "https://example.com/sub")
	if p.ID() != "my-id" {
		t.Errorf("ID() = %q, want %q", p.ID(), "my-id")
	}
	if p.Name() != "My Name" {
		t.Errorf("Name() = %q, want %q", p.Name(), "My Name")
	}
	if p.Type() != "free" {
		t.Errorf("Type() = %q, want free", p.Type())
	}
}

func TestFreeProvider_EnabledByDefault(t *testing.T) {
	p := NewFreeProvider("x", "X", "https://x.com")
	if !p.IsEnabled() {
		t.Error("provider should be enabled by default")
	}
	p.SetEnabled(false)
	if p.IsEnabled() {
		t.Error("provider should be disabled after SetEnabled(false)")
	}
	p.SetEnabled(true)
	if !p.IsEnabled() {
		t.Error("provider should be enabled after SetEnabled(true)")
	}
}

func TestFreeProvider_Meta_Free(t *testing.T) {
	p := NewFreeProvider("test-id", "Test Provider", "https://example.com")
	meta := p.Meta()
	if !meta.Free {
		t.Error("FreeSubscriptionProvider should have Free=true")
	}
	if meta.TrustScore <= 0 {
		t.Error("TrustScore should be positive")
	}
}

// ── Registry (пустой) ─────────────────────────────────────────────────────────

func TestRegistry_EmptyRegister(t *testing.T) {
	r := newEmptyRegistry()
	if len(r.All()) != 0 {
		t.Errorf("empty registry should have 0 providers, got %d", len(r.All()))
	}
}

func TestRegistry_Register(t *testing.T) {
	r := newEmptyRegistry()
	p1 := NewFreeProvider("p1", "Provider 1", "https://p1.com")
	p2 := NewFreeProvider("p2", "Provider 2", "https://p2.com")
	r.Register(p1)
	r.Register(p2)

	if len(r.All()) != 2 {
		t.Errorf("expected 2 providers, got %d", len(r.All()))
	}
}

func TestRegistry_Register_Dedup(t *testing.T) {
	r := newEmptyRegistry()
	p := NewFreeProvider("dup", "Dup", "https://dup.com")
	r.Register(p)
	r.Register(p) // повторная регистрация того же ID

	if len(r.All()) != 1 {
		t.Errorf("duplicate registration should not add twice, got %d", len(r.All()))
	}
}

func TestRegistry_Enabled(t *testing.T) {
	r := newEmptyRegistry()
	p1 := NewFreeProvider("e1", "Enabled", "https://e1.com")
	p2 := NewFreeProvider("d1", "Disabled", "https://d1.com")
	p2.SetEnabled(false)
	r.Register(p1)
	r.Register(p2)

	enabled := r.Enabled()
	if len(enabled) != 1 {
		t.Errorf("expected 1 enabled provider, got %d", len(enabled))
	}
	if enabled[0].ID() != "e1" {
		t.Errorf("expected provider e1, got %s", enabled[0].ID())
	}
}

func TestRegistry_SetEnabled(t *testing.T) {
	r := newEmptyRegistry()
	p := NewFreeProvider("toggle", "Toggle", "https://toggle.com")
	r.Register(p)

	ok := r.SetEnabled("toggle", false)
	if !ok {
		t.Error("SetEnabled should return true for existing provider")
	}
	if len(r.Enabled()) != 0 {
		t.Error("no providers should be enabled after disabling")
	}

	r.SetEnabled("toggle", true)
	if len(r.Enabled()) != 1 {
		t.Error("provider should be enabled after SetEnabled(true)")
	}
}

func TestRegistry_SetEnabled_NotFound(t *testing.T) {
	r := newEmptyRegistry()
	ok := r.SetEnabled("nonexistent", true)
	if ok {
		t.Error("SetEnabled should return false for unknown provider")
	}
}

func TestRegistry_Get(t *testing.T) {
	r := newEmptyRegistry()
	p := NewFreeProvider("find-me", "Find Me", "https://find.com")
	r.Register(p)

	got, ok := r.Get("find-me")
	if !ok {
		t.Fatal("Get should find registered provider")
	}
	if got.ID() != "find-me" {
		t.Errorf("got.ID() = %q, want find-me", got.ID())
	}

	_, notok := r.Get("missing")
	if notok {
		t.Error("Get should return false for missing provider")
	}
}

func TestRegistry_Status(t *testing.T) {
	r := newEmptyRegistry()
	p := NewFreeProvider("s1", "Status Test", "https://s1.com")
	r.Register(p)

	status := r.Status()
	if len(status) != 1 {
		t.Fatalf("expected 1 status entry, got %d", len(status))
	}
	s := status[0]
	if s["id"] != "s1" {
		t.Errorf("status id = %v, want s1", s["id"])
	}
	if s["name"] != "Status Test" {
		t.Errorf("status name = %v, want Status Test", s["name"])
	}
	if _, ok := s["enabled"]; !ok {
		t.Error("status should have 'enabled' field")
	}
	if _, ok := s["type"]; !ok {
		t.Error("status should have 'type' field")
	}
}

// ── Fetcher ───────────────────────────────────────────────────────────────────

func TestFetcher_NoEnabledProviders(t *testing.T) {
	r := newEmptyRegistry()
	f := NewFetcher(r)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	nodes, results := f.FetchAll(ctx)
	if nodes != nil {
		t.Error("expected nil nodes for empty registry")
	}
	if results != nil {
		t.Error("expected nil results for empty registry")
	}
}

func TestFetcher_DisabledProviders(t *testing.T) {
	r := newEmptyRegistry()
	p := NewFreeProvider("disabled", "Disabled", "https://disabled.example.com")
	p.SetEnabled(false)
	r.Register(p)

	f := NewFetcher(r)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	nodes, results := f.FetchAll(ctx)
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes from disabled providers, got %d", len(nodes))
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results from disabled providers, got %d", len(results))
	}
}

// ── mockProvider для тестирования Fetcher ─────────────────────────────────────

type mockProvider struct {
	id      string
	enabled bool
	nodes   []*models.Node
	err     error
}

func (m *mockProvider) ID() string         { return m.id }
func (m *mockProvider) Name() string       { return "Mock " + m.id }
func (m *mockProvider) Type() string       { return "mock" }
func (m *mockProvider) IsEnabled() bool    { return m.enabled }
func (m *mockProvider) Meta() ProviderMeta { return ProviderMeta{TrustScore: 0.5, Free: true} }
func (m *mockProvider) Fetch(_ context.Context) ([]*models.Node, error) {
	return m.nodes, m.err
}

func TestFetcher_WithMockProvider(t *testing.T) {
	r := newEmptyRegistry()
	nodes := []*models.Node{
		{ID: "node-1", Name: "Node 1", Protocol: models.ProtoVLESS, Address: "1.2.3.4", Port: 443},
		{ID: "node-2", Name: "Node 2", Protocol: models.ProtoShadowsocks, Address: "5.6.7.8", Port: 8388},
	}
	mock := &mockProvider{id: "mock1", enabled: true, nodes: nodes}
	r.Register(mock)

	f := NewFetcher(r)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	gotNodes, results := f.FetchAll(ctx)
	if len(gotNodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(gotNodes))
	}
	if len(results) != 1 {
		t.Errorf("expected 1 fetch result, got %d", len(results))
	}
	if results[0].Error != nil {
		t.Errorf("unexpected error: %v", results[0].Error)
	}
}

func TestFetcher_Deduplication(t *testing.T) {
	r := newEmptyRegistry()
	shared := &models.Node{ID: "shared", Name: "Shared", Protocol: models.ProtoVLESS, Address: "1.1.1.1", Port: 443}
	unique := &models.Node{ID: "unique", Name: "Unique", Protocol: models.ProtoVLESS, Address: "2.2.2.2", Port: 443}

	m1 := &mockProvider{id: "m1", enabled: true, nodes: []*models.Node{shared, unique}}
	m2 := &mockProvider{id: "m2", enabled: true, nodes: []*models.Node{shared}} // дубль
	r.Register(m1)
	r.Register(m2)

	f := NewFetcher(r)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	gotNodes, _ := f.FetchAll(ctx)
	if len(gotNodes) != 2 {
		t.Errorf("expected 2 deduplicated nodes, got %d", len(gotNodes))
	}
}

func TestFetcher_PartialError(t *testing.T) {
	r := newEmptyRegistry()
	okNodes := []*models.Node{
		{ID: "ok-1", Name: "OK", Protocol: models.ProtoVLESS, Address: "1.1.1.1", Port: 443},
	}
	m1 := &mockProvider{id: "ok", enabled: true, nodes: okNodes}
	m2 := &mockProvider{id: "fail", enabled: true, err: context.DeadlineExceeded}
	r.Register(m1)
	r.Register(m2)

	f := NewFetcher(r)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	gotNodes, results := f.FetchAll(ctx)
	if len(gotNodes) != 1 {
		t.Errorf("expected 1 node from successful provider, got %d", len(gotNodes))
	}
	var errCount int
	for _, res := range results {
		if res.Error != nil {
			errCount++
		}
	}
	if errCount != 1 {
		t.Errorf("expected 1 error result, got %d", errCount)
	}
}

// ── Tor & Manual providers ────────────────────────────────────────────────────

func TestTorBridgeProvider_Fields(t *testing.T) {
	p := NewTorBridgeProvider()
	if p.ID() != "tor-bridges" {
		t.Errorf("ID() = %q, want tor-bridges", p.ID())
	}
	if p.Type() != "tor" {
		t.Errorf("Type() = %q, want tor", p.Type())
	}
	if !p.IsEnabled() {
		t.Error("TorBridgeProvider should be enabled by default")
	}
	if !p.Meta().Free {
		t.Error("Tor bridges should be free")
	}
}

func TestTorBridgeProvider_Fetch(t *testing.T) {
	p := NewTorBridgeProvider()
	nodes, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("TorBridgeProvider.Fetch() error: %v", err)
	}
	if len(nodes) == 0 {
		t.Error("TorBridgeProvider should return at least one node")
	}
	if nodes[0].Protocol != models.ProtoTor {
		t.Errorf("expected tor protocol, got %s", nodes[0].Protocol)
	}
}

func TestManualProvider_Fields(t *testing.T) {
	p := NewManualProvider()
	if p.ID() != "manual" {
		t.Errorf("ID() = %q, want manual", p.ID())
	}
	if p.Type() != "manual" {
		t.Errorf("Type() = %q, want manual", p.Type())
	}
}

func TestManualProvider_AddRemoveNode(t *testing.T) {
	p := NewManualProvider()
	n := &models.Node{ID: "manual-1", Name: "Manual", Protocol: models.ProtoVLESS, Address: "1.2.3.4", Port: 443}
	p.AddNode(n)

	nodes, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if len(nodes) != 1 {
		t.Errorf("expected 1 node, got %d", len(nodes))
	}

	p.RemoveNode("manual-1")
	nodes2, _ := p.Fetch(context.Background())
	if len(nodes2) != 0 {
		t.Errorf("after remove, expected 0 nodes, got %d", len(nodes2))
	}
}

// ── DefaultFreeProviders ──────────────────────────────────────────────────────

func TestDefaultFreeProviders_Count(t *testing.T) {
	providers := DefaultFreeProviders()
	if len(providers) < 2 {
		t.Errorf("expected at least 2 default providers, got %d", len(providers))
	}
}

func TestDefaultFreeProviders_Fields(t *testing.T) {
	for _, p := range DefaultFreeProviders() {
		if p.ID() == "" {
			t.Error("provider has empty ID")
		}
		if p.Name() == "" {
			t.Errorf("provider %s has empty name", p.ID())
		}
		if !p.IsEnabled() {
			t.Errorf("default provider %s should be enabled", p.ID())
		}
		if p.Type() != "free" {
			t.Errorf("default provider %s should be type free, got %s", p.ID(), p.Type())
		}
	}
}

// ── NewRegistry (со встроенными провайдерами) ─────────────────────────────────

func TestNewRegistry_HasDefaultProviders(t *testing.T) {
	r := NewRegistry()
	all := r.All()
	if len(all) == 0 {
		t.Error("NewRegistry should have default providers")
	}
	// Должен быть Tor и Manual
	hasManual, hasTor := false, false
	for _, p := range all {
		if p.ID() == "manual" {
			hasManual = true
		}
		if p.ID() == "tor-bridges" {
			hasTor = true
		}
	}
	if !hasManual {
		t.Error("NewRegistry should have manual provider")
	}
	if !hasTor {
		t.Error("NewRegistry should have tor-bridges provider")
	}
}
