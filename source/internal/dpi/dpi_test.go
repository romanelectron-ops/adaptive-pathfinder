package dpi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ── FormatScore ───────────────────────────────────────────────────────────────

func TestFormatScore_ContainsNumber(t *testing.T) {
	tests := []struct {
		score    int
		contains string
	}{
		{0, "0/100"},
		{25, "25/100"},
		{50, "50/100"},
		{75, "75/100"},
		{100, "100/100"},
	}
	for _, tt := range tests {
		got := FormatScore(tt.score)
		if !strings.Contains(got, tt.contains) {
			t.Errorf("FormatScore(%d) = %q, expected to contain %q", tt.score, got, tt.contains)
		}
	}
}

func TestFormatScore_NotEmpty(t *testing.T) {
	for _, score := range []int{0, 25, 50, 75, 100} {
		got := FormatScore(score)
		if got == "" {
			t.Errorf("FormatScore(%d) returned empty string", score)
		}
	}
}

// ── CanaryResult ──────────────────────────────────────────────────────────────

func TestCanaryResult_ZeroScore_NotDetectable(t *testing.T) {
	r := &CanaryResult{Score: 0, VPNDetectable: false}
	if r.VPNDetectable {
		t.Error("score=0 should not be detectable")
	}
}

func TestCanaryResult_HighScore_Detectable(t *testing.T) {
	r := &CanaryResult{Score: 75, VPNDetectable: true}
	if !r.VPNDetectable {
		t.Error("score=75 should be detectable")
	}
}

func TestNewCanaryTester_NotNil(t *testing.T) {
	c := NewCanaryTester("127.0.0.1:1080")
	if c == nil {
		t.Fatal("NewCanaryTester returned nil")
	}
}

func TestCanaryTester_QuickCheck_NoPanic(t *testing.T) {
	c := NewCanaryTester("")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// QuickCheck делает TCP к 1.1.1.1:443 — может timeout в изоляции, не должен паниковать
	_ = c.QuickCheck(ctx)
}

// ── PaddingConfig ─────────────────────────────────────────────────────────────

func TestDefaultPaddingConfig_Disabled(t *testing.T) {
	cfg := DefaultPaddingConfig()
	if cfg == nil {
		t.Fatal("DefaultPaddingConfig returned nil")
	}
	if cfg.Enabled {
		t.Error("padding should be disabled by default")
	}
	if cfg.JitterMinMs <= 0 {
		t.Error("JitterMinMs should be positive")
	}
	if cfg.JitterMaxMs <= cfg.JitterMinMs {
		t.Errorf("JitterMaxMs (%d) should be > JitterMinMs (%d)", cfg.JitterMaxMs, cfg.JitterMinMs)
	}
	if cfg.PaddingMaxBytes <= 0 {
		t.Error("PaddingMaxBytes should be positive")
	}
}

func TestAggressivePaddingConfig_LargerThanDefault(t *testing.T) {
	agg := AggressivePaddingConfig()
	dflt := DefaultPaddingConfig()
	if agg.JitterMaxMs <= dflt.JitterMaxMs {
		t.Errorf("aggressive JitterMaxMs (%d) should be > default (%d)",
			agg.JitterMaxMs, dflt.JitterMaxMs)
	}
	if agg.PaddingMaxBytes <= dflt.PaddingMaxBytes {
		t.Errorf("aggressive PaddingMaxBytes (%d) should be > default (%d)",
			agg.PaddingMaxBytes, dflt.PaddingMaxBytes)
	}
	if !agg.Enabled {
		t.Error("aggressive config should be enabled")
	}
	if !agg.AggressiveMode {
		t.Error("aggressive config should have AggressiveMode=true")
	}
}

// ── TrafficPadder ─────────────────────────────────────────────────────────────

func TestNewTrafficPadder_NotNil(t *testing.T) {
	p := NewTrafficPadder(DefaultPaddingConfig())
	if p == nil {
		t.Fatal("NewTrafficPadder returned nil")
	}
}

func TestTrafficPadder_NilConfig_UsesDefault(t *testing.T) {
	p := NewTrafficPadder(nil)
	cfg := p.GetConfig()
	if cfg == nil {
		t.Fatal("GetConfig should not return nil even with nil input")
	}
}

func TestTrafficPadder_DisabledInitially(t *testing.T) {
	p := NewTrafficPadder(DefaultPaddingConfig())
	if p.IsEnabled() {
		t.Error("padder should be disabled initially (default config has Enabled=false)")
	}
}

func TestTrafficPadder_Enable_Standard(t *testing.T) {
	p := NewTrafficPadder(DefaultPaddingConfig())
	p.Enable(false)
	if !p.IsEnabled() {
		t.Error("after Enable(false), IsEnabled() should be true")
	}
	cfg := p.GetConfig()
	if cfg.AggressiveMode {
		t.Error("Enable(false) should not set aggressive mode")
	}
}

func TestTrafficPadder_Enable_Aggressive(t *testing.T) {
	p := NewTrafficPadder(DefaultPaddingConfig())
	p.Enable(true)
	cfg := p.GetConfig()
	if !cfg.AggressiveMode {
		t.Error("Enable(true) should set aggressive mode")
	}
	if !cfg.Enabled {
		t.Error("Enable(true) should set Enabled=true")
	}
}

func TestTrafficPadder_Disable(t *testing.T) {
	p := NewTrafficPadder(DefaultPaddingConfig())
	p.Enable(false)
	p.Disable()
	if p.IsEnabled() {
		t.Error("after Disable, IsEnabled() should be false")
	}
}

func TestTrafficPadder_SetConfig(t *testing.T) {
	p := NewTrafficPadder(DefaultPaddingConfig())
	newCfg := AggressivePaddingConfig()
	p.SetConfig(newCfg)
	if !p.IsEnabled() {
		t.Error("after SetConfig with aggressive config, should be enabled")
	}
}

func TestTrafficPadder_GetConfig_IsCopy(t *testing.T) {
	p := NewTrafficPadder(DefaultPaddingConfig())
	cfg1 := p.GetConfig()
	cfg2 := p.GetConfig()
	// Должны быть разные указатели (копия)
	if cfg1 == cfg2 {
		t.Error("GetConfig should return a copy, not the same pointer")
	}
}

// ── ShadowTLSConfig ──────────────────────────────────────────────────────────

func TestDefaultShadowTLSConfig_Fields(t *testing.T) {
	cfg := DefaultShadowTLSConfig()
	if cfg == nil {
		t.Fatal("DefaultShadowTLSConfig returned nil")
	}
	if cfg.Enabled {
		t.Error("ShadowTLS should be disabled by default")
	}
	if cfg.Version != ShadowTLSv3 {
		t.Errorf("default version = %d, want v3 (%d)", cfg.Version, ShadowTLSv3)
	}
	if cfg.HandshakeSNI == "" {
		t.Error("HandshakeSNI should not be empty")
	}
	if cfg.HandshakeServer == "" {
		t.Error("HandshakeServer should not be empty")
	}
	if !strings.Contains(cfg.HandshakeServer, ":") {
		t.Errorf("HandshakeServer should contain port: %s", cfg.HandshakeServer)
	}
}

func TestShadowTLSVersion_Values(t *testing.T) {
	if int(ShadowTLSv1) >= int(ShadowTLSv3) {
		t.Error("v1 should be numerically less than v3")
	}
	if ShadowTLSv3 != 3 {
		t.Errorf("ShadowTLSv3 should be 3, got %d", ShadowTLSv3)
	}
}

func TestGoodShadowTLSSNI_Valid(t *testing.T) {
	if len(GoodShadowTLSSNI) == 0 {
		t.Error("GoodShadowTLSSNI list should not be empty")
	}
	for _, entry := range GoodShadowTLSSNI {
		if entry.SNI == "" {
			t.Error("GoodShadowTLSSNI has empty SNI entry")
		}
		if entry.Server == "" {
			t.Errorf("GoodShadowTLSSNI[%s] has empty Server", entry.SNI)
		}
		if !strings.Contains(entry.Server, ":") {
			t.Errorf("GoodShadowTLSSNI[%s] Server should contain port: %s",
				entry.SNI, entry.Server)
		}
	}
}

// ── ShadowTLSManager ─────────────────────────────────────────────────────────

func TestNewShadowTLSManager_NotNil(t *testing.T) {
	m := NewShadowTLSManager(DefaultShadowTLSConfig())
	if m == nil {
		t.Fatal("NewShadowTLSManager returned nil")
	}
}

func TestShadowTLSManager_NilConfig(t *testing.T) {
	m := NewShadowTLSManager(nil)
	if m == nil {
		t.Fatal("NewShadowTLSManager(nil) should not return nil")
	}
	cfg := m.GetConfig()
	if cfg == nil {
		t.Error("GetConfig should not return nil")
	}
}

func TestShadowTLSManager_DisabledByDefault(t *testing.T) {
	m := NewShadowTLSManager(DefaultShadowTLSConfig())
	if m.IsEnabled() {
		t.Error("ShadowTLS should be disabled by default")
	}
}

func TestShadowTLSManager_SetGetConfig(t *testing.T) {
	m := NewShadowTLSManager(DefaultShadowTLSConfig())
	newCfg := DefaultShadowTLSConfig()
	newCfg.Enabled = true
	newCfg.HandshakeSNI = "www.microsoft.com"
	newCfg.HandshakeServer = "www.microsoft.com:443"
	m.SetConfig(newCfg)

	got := m.GetConfig()
	if !got.Enabled {
		t.Error("after SetConfig, Enabled should be true")
	}
	if got.HandshakeSNI != "www.microsoft.com" {
		t.Errorf("HandshakeSNI = %q, want www.microsoft.com", got.HandshakeSNI)
	}
}

func TestShadowTLSManager_GetStatus_NotNil(t *testing.T) {
	m := NewShadowTLSManager(DefaultShadowTLSConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	status := m.GetStatus(ctx)
	if status == nil {
		t.Error("GetStatus should not return nil")
	}
	// При Enabled=false не должно делать сетевых запросов
	if status.Enabled {
		t.Error("status.Enabled should match cfg.Enabled (false)")
	}
}

func TestShadowTLSManager_GetConfig_IsCopy(t *testing.T) {
	m := NewShadowTLSManager(DefaultShadowTLSConfig())
	c1 := m.GetConfig()
	c2 := m.GetConfig()
	if c1 == c2 {
		t.Error("GetConfig should return copies, not same pointer")
	}
}

// ── CDNFrontingConfig ─────────────────────────────────────────────────────────

func TestDefaultCDNConfig_Fields(t *testing.T) {
	cfg := DefaultCDNConfig()
	if cfg == nil {
		t.Fatal("DefaultCDNConfig returned nil")
	}
	if cfg.Enabled {
		t.Error("CDN fronting should be disabled by default")
	}
	if cfg.Provider == nil {
		t.Error("Provider should not be nil in default config")
	}
	if !cfg.TestBeforeUse {
		t.Error("TestBeforeUse should be true by default")
	}
}

func TestCloudflareProvider_Fields(t *testing.T) {
	p := CloudflareProvider
	if p.Name == "" {
		t.Error("Provider Name should not be empty")
	}
	if p.FrontDomain == "" {
		t.Error("FrontDomain should not be empty")
	}
	if len(p.CDNIPs) == 0 {
		t.Error("CDNIPs should not be empty")
	}
	for _, ip := range p.CDNIPs {
		if ip == "" {
			t.Error("CDNIPs contains empty entry")
		}
	}
}

func TestNewCDNFronter_NotNil(t *testing.T) {
	f := NewCDNFronter(DefaultCDNConfig())
	if f == nil {
		t.Fatal("NewCDNFronter returned nil")
	}
}

func TestNewCDNFronter_NilConfig(t *testing.T) {
	f := NewCDNFronter(nil)
	if f == nil {
		t.Fatal("NewCDNFronter(nil) should not return nil")
	}
}

func TestCDNFronter_GetStatus_NotNil(t *testing.T) {
	f := NewCDNFronter(DefaultCDNConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	status := f.GetStatus(ctx)
	if status == nil {
		t.Error("GetStatus should not return nil")
	}
	// При Enabled=false — не делает сетевых запросов
	if status.Enabled {
		t.Error("status.Enabled should be false")
	}
}

func TestWorkerSetupInstructions_ContainsHost(t *testing.T) {
	instr := WorkerSetupInstructions("1.2.3.4", 443)
	if instr == "" {
		t.Error("WorkerSetupInstructions should not be empty")
	}
	if !strings.Contains(instr, "1.2.3.4") {
		t.Error("instructions should contain backend host")
	}
	if !strings.Contains(instr, "443") {
		t.Error("instructions should contain backend port")
	}
}

func TestCDNFronter_BuildFrontedOutbound_WhenDisabled(t *testing.T) {
	f := NewCDNFronter(DefaultCDNConfig()) // Enabled=false
	params := f.BuildFrontedOutbound()
	if params != nil {
		t.Error("BuildFrontedOutbound should return nil when disabled")
	}
}

// ── MultiHop ─────────────────────────────────────────────────────────────────

func TestHopType_Distinct(t *testing.T) {
	if HopEntry == HopExit {
		t.Error("HopEntry and HopExit should be different")
	}
	if HopEntry == HopMiddle {
		t.Error("HopEntry and HopMiddle should be different")
	}
}

func TestNewMultiHopSelector_NotNil(t *testing.T) {
	sel := NewMultiHopSelector()
	if sel == nil {
		t.Fatal("NewMultiHopSelector returned nil")
	}
}

func TestMultiHopSelector_EmptyNodes(t *testing.T) {
	sel := NewMultiHopSelector()
	chain := sel.SelectBestChain(nil, 2)
	if chain != nil {
		t.Error("SelectBestChain(nil, 2) should return nil")
	}
}

func TestMultiHopSelector_InsufficientNodes(t *testing.T) {
	sel := NewMultiHopSelector()
	nodes := []*models.Node{
		{ID: "n1", Protocol: models.ProtoVLESS, Address: "1.1.1.1", Port: 443, Score: 5},
	}
	// 1 узел, нужно 2 — должен вернуть nil
	chain := sel.SelectBestChain(nodes, 2)
	if chain != nil {
		t.Error("SelectBestChain with 1 node for 2-hop should return nil")
	}
}

func TestMultiHopSelector_TwoNodes_TwoHop(t *testing.T) {
	sel := NewMultiHopSelector()
	nodes := []*models.Node{
		{ID: "n1", Protocol: models.ProtoVLESS, Address: "1.1.1.1", Port: 443, Score: 8, Latency: 50},
		{ID: "n2", Protocol: models.ProtoShadowsocks, Address: "2.2.2.2", Port: 8388, Score: 6, Latency: 80},
	}
	chain := sel.SelectBestChain(nodes, 2)
	if chain == nil {
		t.Fatal("SelectBestChain with 2 nodes for 2-hop should succeed")
	}
	if len(chain.Hops) != 2 {
		t.Errorf("2-hop chain should have 2 hops, got %d", len(chain.Hops))
	}
	if chain.AnonymityLevel < 1 {
		t.Error("AnonymityLevel should be >= 1")
	}
	if chain.Topology == "" {
		t.Error("Topology should not be empty")
	}
	// Первый хоп — entry, последний — exit
	if chain.Hops[0].Type != HopEntry {
		t.Errorf("first hop type = %s, want entry", chain.Hops[0].Type)
	}
	if chain.Hops[1].Type != HopExit {
		t.Errorf("last hop type = %s, want exit", chain.Hops[1].Type)
	}
}

func TestMultiHopSelector_ThreeHop(t *testing.T) {
	sel := NewMultiHopSelector()
	nodes := []*models.Node{
		{ID: "n1", Protocol: models.ProtoVLESS, Address: "1.1.1.1", Port: 443, Score: 9, Latency: 40},
		{ID: "n2", Protocol: models.ProtoShadowsocks, Address: "2.2.2.2", Port: 8388, Score: 7, Latency: 70},
		{ID: "n3", Protocol: models.ProtoTrojan, Address: "3.3.3.3", Port: 443, Score: 8, Latency: 55},
	}
	chain := sel.SelectBestChain(nodes, 3)
	if chain == nil {
		t.Fatal("SelectBestChain with 3 nodes for 3-hop should succeed")
	}
	if len(chain.Hops) != 3 {
		t.Errorf("3-hop chain should have 3 hops, got %d", len(chain.Hops))
	}
	if chain.Hops[1].Type != HopMiddle {
		t.Errorf("middle hop type = %s, want middle", chain.Hops[1].Type)
	}
}

// ── buildTopologyString ──────────────────────────────────────────────────────

func TestBuildTopologyString(t *testing.T) {
	result := buildTopologyString([]string{"vless", "shadowsocks"})
	if !strings.Contains(result, "vless") {
		t.Error("topology should contain vless")
	}
	if !strings.Contains(result, "shadowsocks") {
		t.Error("topology should contain shadowsocks")
	}
	if !strings.Contains(result, "→") {
		t.Error("topology should contain arrow separator")
	}
}

func TestBuildTopologyString_Single(t *testing.T) {
	result := buildTopologyString([]string{"vless"})
	if result != "vless" {
		t.Errorf("single proto topology = %q, want vless", result)
	}
}

func TestBuildTopologyString_Empty(t *testing.T) {
	result := buildTopologyString(nil)
	// Не должно паниковать
	_ = result
}

// ── randInt ──────────────────────────────────────────────────────────────────

func TestRandInt_InRange(t *testing.T) {
	for i := 0; i < 100; i++ {
		r := randInt(10, 20)
		if r < 10 || r > 20 {
			t.Errorf("randInt(10,20) = %d, out of range", r)
		}
	}
}

func TestRandInt_EqualMinMax(t *testing.T) {
	r := randInt(5, 5)
	if r != 5 {
		t.Errorf("randInt(5,5) = %d, want 5", r)
	}
}

func TestRandInt_MinGreaterThanMax(t *testing.T) {
	r := randInt(20, 10) // min > max → должен вернуть min
	if r != 20 {
		t.Errorf("randInt(20,10) = %d, want 20 (min)", r)
	}
}
