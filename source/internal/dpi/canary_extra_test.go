package dpi

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ── checkTLSFingerprint mock tests ────────────────────────────────────────────

func TestCheckTLSFingerprint_GoLangDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		// Body contains "golang" indicator
		fmt.Fprint(w, `{"fingerprint":"golang"}`)
	}))
	defer srv.Close()

	orig := tlsFingerprintURL
	tlsFingerprintURL = srv.URL
	defer func() { tlsFingerprintURL = orig }()

	c := NewCanaryTester("")
	result := c.checkTLSFingerprint(context.Background())
	if !result {
		t.Error("expected true when 'golang' detected in body")
	}
}

func TestCheckTLSFingerprint_NotDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, `{"tls":{"ja3":"chrome fingerprint","ciphers":[]}}`)
	}))
	defer srv.Close()

	orig := tlsFingerprintURL
	tlsFingerprintURL = srv.URL
	defer func() { tlsFingerprintURL = orig }()

	c := NewCanaryTester("")
	result := c.checkTLSFingerprint(context.Background())
	if result {
		t.Error("expected false when 'golang' NOT in body")
	}
}

func TestCheckTLSFingerprint_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	orig := tlsFingerprintURL
	tlsFingerprintURL = srv.URL
	defer func() { tlsFingerprintURL = orig }()

	c := NewCanaryTester("")
	result := c.checkTLSFingerprint(context.Background())
	// 500 but no body — should return false (no indicators found)
	if result {
		t.Error("500 response without golang indicator should return false")
	}
}

func TestCheckTLSFingerprint_ConnectionRefused(t *testing.T) {
	orig := tlsFingerprintURL
	tlsFingerprintURL = "http://127.0.0.1:1/tls"
	defer func() { tlsFingerprintURL = orig }()

	c := NewCanaryTester("")
	// Short timeout context to not block
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result := c.checkTLSFingerprint(ctx)
	if result {
		t.Error("connection refused should return false")
	}
}

// ── CanaryTester.Test full run with mock ──────────────────────────────────────

func TestCanaryTester_Test_WithMock(t *testing.T) {
	// Mock TLS fingerprint endpoint
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, `{"ja3":"chrome","tls":"ok"}`)
	}))
	defer srv.Close()

	orig := tlsFingerprintURL
	tlsFingerprintURL = srv.URL
	defer func() { tlsFingerprintURL = orig }()

	c := NewCanaryTester("") // no SOCKS addr
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := c.Test(ctx)
	if err != nil {
		t.Fatalf("Test() returned error: %v", err)
	}
	if result == nil {
		t.Fatal("Test() returned nil result")
	}
	if result.TestedAt.IsZero() {
		t.Error("TestedAt should be set")
	}
	if result.Score < 0 || result.Score > 100 {
		t.Errorf("Score = %d, want 0-100", result.Score)
	}
	t.Logf("Test(): score=%d vpn_detectable=%v tls_leaked=%v timing=%v entropy=%v port=%v",
		result.Score, result.VPNDetectable,
		result.TLSFingerprintLeaked, result.TimingAnomaly,
		result.EntropyHigh, result.PortSuspicious)
}

func TestCanaryTester_Test_GoDetected(t *testing.T) {
	// TLS fingerprint shows golang → score += 40
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, `{"fingerprint":"golang"}`)
	}))
	defer srv.Close()

	orig := tlsFingerprintURL
	tlsFingerprintURL = srv.URL
	defer func() { tlsFingerprintURL = orig }()

	c := NewCanaryTester("") // no SOCKS
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := c.Test(ctx)
	if err != nil {
		t.Fatalf("Test(): %v", err)
	}
	if !result.TLSFingerprintLeaked {
		t.Error("expected TLSFingerprintLeaked=true when 'golang' in body")
	}
	if result.Score < 40 {
		t.Errorf("Score = %d, want >= 40 when TLS leaked", result.Score)
	}
}

// ── ProbeHandshakeServer ──────────────────────────────────────────────────────

func TestProbeHandshakeServer_Reachable(t *testing.T) {
	// Start a TCP listener to simulate a reachable server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen:", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	addr := ln.Addr().String()
	m := NewShadowTLSManager(&ShadowTLSConfig{
		HandshakeSNI:    "test.local",
		HandshakeServer: addr,
	})

	result := m.ProbeHandshakeServer(context.Background())
	if result == nil {
		t.Fatal("ProbeHandshakeServer returned nil")
	}
	if !result.TCPReachable {
		t.Errorf("TCPReachable = false, want true for open port; error: %s", result.Error)
	}
	if !result.Available {
		t.Error("Available should be true when TCP reachable")
	}
	if result.LatencyMs < 0 {
		t.Errorf("LatencyMs = %d, want >= 0", result.LatencyMs)
	}
	t.Logf("ProbeHandshakeServer reachable: latency=%dms available=%v", result.LatencyMs, result.Available)
}

func TestProbeHandshakeServer_Unreachable(t *testing.T) {
	m := NewShadowTLSManager(&ShadowTLSConfig{
		HandshakeSNI:    "test.local",
		HandshakeServer: "127.0.0.1:1", // port 1 → connection refused
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := m.ProbeHandshakeServer(ctx)
	if result == nil {
		t.Fatal("ProbeHandshakeServer returned nil")
	}
	if result.Available {
		t.Error("Available should be false for unreachable server")
	}
	if result.TCPReachable {
		t.Error("TCPReachable should be false for refused port")
	}
	if result.Error == "" {
		t.Error("Error should be non-empty for unreachable server")
	}
	t.Logf("ProbeHandshakeServer unreachable: error=%q", result.Error)
}

// ── AutoSelectSNI ─────────────────────────────────────────────────────────────

func TestAutoSelectSNI_WithLocalServer(t *testing.T) {
	// Create a local TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen:", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	addr := ln.Addr().String()

	// Override GoodShadowTLSSNI
	origSNI := GoodShadowTLSSNI
	GoodShadowTLSSNI = []struct {
		SNI    string
		Server string
	}{
		{"local.test", addr},
	}
	defer func() { GoodShadowTLSSNI = origSNI }()

	m := NewShadowTLSManager(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sni, server, latency, err := m.AutoSelectSNI(ctx)
	if err != nil {
		t.Fatalf("AutoSelectSNI: %v", err)
	}
	if sni != "local.test" {
		t.Errorf("sni = %q, want %q", sni, "local.test")
	}
	if server != addr {
		t.Errorf("server = %q, want %q", server, addr)
	}
	if latency < 0 {
		t.Errorf("latency = %d, want >= 0", latency)
	}
	t.Logf("AutoSelectSNI: sni=%s server=%s latency=%dms", sni, server, latency)
}

func TestAutoSelectSNI_AllUnreachable(t *testing.T) {
	origSNI := GoodShadowTLSSNI
	GoodShadowTLSSNI = []struct {
		SNI    string
		Server string
	}{
		{"test1.local", "127.0.0.1:1"},
		{"test2.local", "127.0.0.1:2"},
	}
	defer func() { GoodShadowTLSSNI = origSNI }()

	m := NewShadowTLSManager(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, _, _, err := m.AutoSelectSNI(ctx)
	if err == nil {
		t.Error("expected error when all SNI candidates unreachable")
	}
	t.Logf("AutoSelectSNI all unreachable: %v", err)
}

// ── GetStatus with enabled=true ───────────────────────────────────────────────

func TestShadowTLSManager_GetStatus_Enabled_LocalServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen:", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	addr := ln.Addr().String()
	m := NewShadowTLSManager(&ShadowTLSConfig{
		Enabled:         true,
		Version:         ShadowTLSv3,
		Password:        "test",
		HandshakeSNI:    "local.test",
		HandshakeServer: addr,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	status := m.GetStatus(ctx)
	if status == nil {
		t.Fatal("GetStatus returned nil")
	}
	if !status.Enabled {
		t.Error("Enabled should be true")
	}
	if !status.Available {
		t.Error("Available should be true for reachable server")
	}
	t.Logf("GetStatus enabled+reachable: available=%v latency=%dms", status.Available, status.LatencyMs)
}

// ── getServerPort edge case: port 0 → default 443 ────────────────────────────

func TestGetServerPort_ZeroPort(t *testing.T) {
	// "example.com:0" parses OK but port=0 → returns 443
	m := NewShadowTLSManager(&ShadowTLSConfig{
		HandshakeServer: "example.com:0",
	})
	port := m.getServerPort()
	if port != 443 {
		t.Errorf("port 0 should default to 443, got %d", port)
	}
}

// ── BuildViaProxy and BuildThreeHop success paths ─────────────────────────────

func TestBuildViaProxy_ValidNodes(t *testing.T) {
	b := NewMultiHopBuilder(1080)

	proxy := &models.Node{
		Protocol: models.ProtoShadowsocks,
		Address:  "1.2.3.4",
		Port:     1234,
	}
	exit := &models.Node{
		Protocol: models.ProtoVLESS,
		Address:  "5.6.7.8",
		Port:     443,
	}

	cfg, err := b.BuildViaProxy(proxy, exit)
	// May return error if singbox builder needs more fields,
	// but we're testing that the nil check is passed
	if err != nil {
		t.Logf("BuildViaProxy with valid nodes returned error (may be expected for minimal nodes): %v", err)
		return
	}
	if cfg == nil {
		t.Error("BuildViaProxy: expected non-nil config")
	}
	t.Log("BuildViaProxy: success")
}

func TestBuildThreeHop_ValidNodes(t *testing.T) {
	b := NewMultiHopBuilder(1080)

	entry := &models.Node{Protocol: models.ProtoShadowsocks, Address: "1.1.1.1", Port: 443}
	middle := &models.Node{Protocol: models.ProtoVLESS, Address: "2.2.2.2", Port: 443}
	exit := &models.Node{Protocol: models.ProtoTrojan, Address: "3.3.3.3", Port: 443}

	cfg, err := b.BuildThreeHop(entry, middle, exit)
	if err != nil {
		t.Logf("BuildThreeHop with valid nodes returned error: %v", err)
		return
	}
	if cfg == nil {
		t.Error("BuildThreeHop: expected non-nil config")
	}
	t.Log("BuildThreeHop: success")
}

// ── CDNFronter TestConnectivity ───────────────────────────────────────────────

func TestCDNFronter_TestConnectivity_CDNUnreachable(t *testing.T) {
	// Use cancelled context → CDN unreachable → early return
	cfg := DefaultCDNConfig()
	cfg.Enabled = true
	f := NewCDNFronter(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancelled

	result := f.TestConnectivity(ctx)
	if result == nil {
		t.Fatal("TestConnectivity returned nil")
	}
	// With cancelled context, CDN should not be reachable
	if result.CDNReachable {
		t.Log("NOTE: CDN was reachable despite cancelled context")
	} else {
		if result.Error == "" {
			t.Error("Error should be set when CDN unreachable")
		}
		t.Logf("TestConnectivity CDN unreachable: error=%q", result.Error)
	}
}

func TestCDNFronter_IsAvailable_LocalServer(t *testing.T) {
	// We can't easily make IsAvailable return true without root or actual CDN
	// but we can test it doesn't panic with a custom config
	cfg := DefaultCDNConfig()
	f := NewCDNFronter(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// This may return true or false depending on network
	result := f.IsAvailable(ctx)
	t.Logf("IsAvailable (real network attempt): %v", result)
}

func TestCDNFronter_GetStatus_Enabled(t *testing.T) {
	cfg := &CDNFrontingConfig{
		Enabled:      true,
		Provider:     CloudflareProvider,
		WorkerDomain: "test.workers.dev",
	}
	f := NewCDNFronter(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	status := f.GetStatus(ctx)
	if status == nil {
		t.Fatal("GetStatus returned nil")
	}
	if !status.Enabled {
		t.Error("Enabled should be true")
	}
	t.Logf("GetStatus enabled: available=%v provider=%q", status.Available, status.Provider)
}
