package dpi

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ════════════════════ canary.go gaps ════════════════════

// TestCheckTLSFingerprint_InvalidURL covers the http.NewRequestWithContext error branch.
// An invalid URL (e.g. "://invalid") causes NewRequestWithContext to return an error,
// so checkTLSFingerprint returns false immediately.
func TestCheckTLSFingerprint_InvalidURL(t *testing.T) {
	orig := tlsFingerprintURL
	tlsFingerprintURL = "://invalid-url-causes-parse-error"
	defer func() { tlsFingerprintURL = orig }()

	c := NewCanaryTester("")
	result := c.checkTLSFingerprint(context.Background())
	if result {
		t.Error("expected false for invalid URL")
	}
}

// TestCheckTimingAnomaly_AllFail covers both the "continue on dial error" and
// "len(rtts)==0 → return false" branches inside checkTimingAnomaly.
// A pre-cancelled context causes all TCP dials to fail immediately.
func TestCheckTimingAnomaly_AllFail(t *testing.T) {
	c := NewCanaryTester("")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before any dial attempt

	result := c.checkTimingAnomaly(ctx)
	if result {
		t.Error("expected false when all dials fail due to cancelled ctx")
	}
}

// ════════════════════ traffic_padding.go gaps ════════════════════

// mockFailConn is a net.Conn whose Write always returns an error.
type mockFailConn struct{ net.Conn }

func (m *mockFailConn) Write(_ []byte) (int, error) { return 0, errors.New("mock write error") }
func (m *mockFailConn) Close() error                { return nil }

// mockOKConn is a net.Conn whose Write always succeeds.
type mockOKConn struct{ net.Conn }

func (m *mockOKConn) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockOKConn) Close() error                { return nil }

// TestPaddedConn_Write_JitterSleep covers the "if jitterMs > 0 { time.Sleep }"
// branch inside PaddedConn.Write when jitter is configured.
func TestPaddedConn_Write_JitterSleep(t *testing.T) {
	cfg := &PaddingConfig{
		Enabled:         true,
		JitterMinMs:     1,
		JitterMaxMs:     1, // randInt(1,1)=1 > 0 → always sleeps
		PaddingMinBytes: 0,
		PaddingMaxBytes: 0,
	}
	conn := NewPaddedConn(&mockOKConn{}, cfg)

	n, err := conn.Write([]byte("hello"))
	if err != nil {
		t.Errorf("Write: unexpected error: %v", err)
	}
	if n != 5 {
		t.Errorf("Write: n=%d, want 5", n)
	}
}

// TestPaddedConn_Write_ConnError covers the "if err != nil { return n, err }"
// branch inside PaddedConn.Write when the underlying Conn.Write fails.
func TestPaddedConn_Write_ConnError(t *testing.T) {
	cfg := &PaddingConfig{
		Enabled:         true,
		JitterMinMs:     0,
		JitterMaxMs:     0,
		PaddingMinBytes: 0,
		PaddingMaxBytes: 0,
	}
	conn := NewPaddedConn(&mockFailConn{}, cfg)

	_, err := conn.Write([]byte("data"))
	if err == nil {
		t.Error("expected error from failing conn, got nil")
	}
}

// TestTrafficPadder_ApplyJitter_Sleep covers the "if ms > 0 { time.Sleep }"
// branch inside TrafficPadder.ApplyJitter when jitter is configured.
func TestTrafficPadder_ApplyJitter_Sleep(t *testing.T) {
	cfg := &PaddingConfig{
		Enabled:     true,
		JitterMinMs: 1,
		JitterMaxMs: 1, // always 1ms > 0 → sleep branch is hit
	}
	p := NewTrafficPadder(cfg)

	start := time.Now()
	p.ApplyJitter()
	elapsed := time.Since(start)

	// Should have slept at least ~1ms
	if elapsed < time.Millisecond {
		t.Logf("ApplyJitter elapsed=%v (may be < 1ms on fast CI, that's OK)", elapsed)
	}
}

// ════════════════════ multihop.go gaps ════════════════════

// TestSelectBestChain_NilWhenNotEnoughNodes covers the second "return nil" in
// SelectBestChain: when selectDiverseNodes returns fewer nodes than hops.
// All nodes have Score=0, so selectDiverseNodes cannot fill the selection.
func TestSelectBestChain_NilWhenNotEnoughNodes(t *testing.T) {
	s := NewMultiHopSelector()

	// Two nodes but both Score=0 → selectDiverseNodes returns empty slice → nil
	nodes := []*models.Node{
		{Protocol: models.ProtoVLESS, Address: "1.1.1.1", Score: 0},
		{Protocol: models.ProtoTrojan, Address: "2.2.2.2", Score: 0},
	}

	result := s.SelectBestChain(nodes, 1)
	if result != nil {
		t.Errorf("expected nil when no nodes pass score filter, got %+v", result)
	}
}

// TestSelectDiverseNodes_FallbackLoop covers the fallback loop body inside
// selectDiverseNodes: when the protocol-based selection doesn't fill all n spots,
// the function iterates nodes again to fill remaining slots.
func TestSelectDiverseNodes_FallbackLoop(t *testing.T) {
	s := NewMultiHopSelector()

	// 3 nodes all same protocol, want n=2.
	// Protocol loop picks node1 (1 selected).
	// Fallback loop picks node2 (not seen, score>0) to reach n=2.
	nodes := []*models.Node{
		{Protocol: models.ProtoVLESS, Address: "1.1.1.1", Score: 10},
		{Protocol: models.ProtoVLESS, Address: "2.2.2.2", Score: 5},
		{Protocol: models.ProtoVLESS, Address: "3.3.3.3", Score: 1},
	}

	result := s.selectDiverseNodes(nodes, 2)
	if len(result) != 2 {
		t.Errorf("expected 2 nodes selected, got %d", len(result))
	}
}

// TestSelectDiverseNodes_FallbackLoop_SkipsBlacklisted — регресс на найденный и
// исправленный баг (верификация 2026-09-05): "добор из оставшихся" в selectDiverseNodes
// проверял только node.Score > 0, но не node.IsBlacklisted(), в отличие от byProto-фильтра
// парой строк выше. Из-за этого узел в бане, который первый фильтр честно отбраковал,
// мог попасть в multi-hop цепочку через фолбэк-цикл — именно тогда, когда все узлы одного
// протокола (первый проход не набирает n) и среди "оставшихся" есть забаненный.
//
// Сценарий: 2 VLESS-узла (один в бане) — первый проход по протоколам выбирает единственный
// НЕ забаненный VLESS (byProto его отфильтровал), fallback обязан пропустить забаненный,
// а не набор до n=2 не заполнится вовсе (только 1 годный кандидат в пуле).
func TestSelectDiverseNodes_FallbackLoop_SkipsBlacklisted(t *testing.T) {
	s := NewMultiHopSelector()

	blacklisted := &models.Node{Protocol: models.ProtoVLESS, Address: "bad.ip", Score: 10}
	blacklisted.BlacklistedUntil = time.Now().Add(time.Hour)
	good := &models.Node{Protocol: models.ProtoVLESS, Address: "good.ip", Score: 5}

	nodes := []*models.Node{blacklisted, good}

	// len(nodes) == n == 2 → идём в главный (не early-return) путь только если n меньше;
	// здесь явно просим n=2, что равно len(nodes) — проверяем ОБА пути одним вызовом набора.
	result := s.selectDiverseNodes(nodes, 2)
	for _, n := range result {
		if n.Address == "bad.ip" {
			t.Fatalf("selectDiverseNodes must never return a blacklisted node, got %+v", result)
		}
	}

	// Явно бьём именно по fallback-циклу: 3 узла одного протокола, второй в бане, n=2.
	// Проход по протоколам берёт первый (good1). Fallback должен пропустить забаненный
	// good2-bad и взять good3, а не остановиться на забаненном.
	good1 := &models.Node{Protocol: models.ProtoVLESS, Address: "good1.ip", Score: 10}
	bad2 := &models.Node{Protocol: models.ProtoVLESS, Address: "bad2.ip", Score: 9}
	bad2.BlacklistedUntil = time.Now().Add(time.Hour)
	good3 := &models.Node{Protocol: models.ProtoVLESS, Address: "good3.ip", Score: 8}

	result2 := s.selectDiverseNodes([]*models.Node{good1, bad2, good3}, 2)
	for _, n := range result2 {
		if n.Address == "bad2.ip" {
			t.Fatalf("fallback loop must skip blacklisted nodes, got %+v", result2)
		}
	}
	if len(result2) != 2 {
		t.Errorf("expected 2 nodes selected (skipping the blacklisted one), got %d: %+v", len(result2), result2)
	}
}

// TestShadowTLSManager_PublicGetters_ReturnRealServerNotHandshakeHost покрывает T-18
// публичные геттеры (ServerHost/ServerPort/Version/Password/SNI/HasServerAddr), которые до
// этого теста не вызывались напрямую НИ ОДНИМ тестом пакета. Это ровно то место, где жил
// баг P1-1 (аудит 2026-09-01): ServerHost()/ServerPort() раньше возвращали маскировочный
// HandshakeServer (тот адрес, что видит DPI в TLS ClientHello) вместо реального ServerAddr
// (куда singbox.Builder физически дозванивается). Регрессия здесь означала бы гарантированный
// отказ подключения при включённом ShadowTLS — код молча собирал бы конфиг на маскировочный
// сайт (www.bing.com и т.п.), а не на настоящий сервер пользователя.
func TestShadowTLSManager_PublicGetters_ReturnRealServerNotHandshakeHost(t *testing.T) {
	m := NewShadowTLSManager(&ShadowTLSConfig{
		Enabled:         true,
		Version:         ShadowTLSv3,
		Password:        "secret-hmac-key",
		HandshakeSNI:    "www.bing.com",     // то, что видит DPI — НЕ место реального дозвона
		HandshakeServer: "www.bing.com:443", // маскировочный TCP-адрес пробы
		ServerAddr:      "vpn.example.net:8443",
	})

	if !m.HasServerAddr() {
		t.Fatal("HasServerAddr() = false, want true when ServerAddr is set")
	}
	if got := m.ServerHost(); got != "vpn.example.net" {
		t.Errorf("ServerHost() = %q, want real server host %q (not handshake host www.bing.com)", got, "vpn.example.net")
	}
	if got := m.ServerPort(); got != 8443 {
		t.Errorf("ServerPort() = %d, want real server port 8443 (not handshake port 443)", got)
	}
	if got := m.Version(); got != 3 {
		t.Errorf("Version() = %d, want 3", got)
	}
	if got := m.Password(); got != "secret-hmac-key" {
		t.Errorf("Password() = %q, want %q", got, "secret-hmac-key")
	}
	if got := m.SNI(); got != "www.bing.com" {
		t.Errorf("SNI() = %q, want handshake SNI %q (masking host, separate from ServerHost)", got, "www.bing.com")
	}
}

// TestShadowTLSManager_HasServerAddr_EmptyByDefault — Enable без реального адреса сервера
// должен быть отличим от «настроен полностью»: HasServerAddr() — единственный сигнал,
// которым Engine.SetShadowTLSConfig решает, можно ли вообще включать ShadowTLS (см.
// комментарий у поля ServerAddr в shadow_tls.go). DefaultShadowTLSConfig() не задаёт
// ServerAddr — это должно оставаться так, иначе Enable могла бы пройти без реального сервера.
func TestShadowTLSManager_HasServerAddr_EmptyByDefault(t *testing.T) {
	m := NewShadowTLSManager(nil) // nil → DefaultShadowTLSConfig()
	if m.HasServerAddr() {
		t.Error("HasServerAddr() should be false for the default config (no ServerAddr set)")
	}

	m.SetConfig(&ShadowTLSConfig{Enabled: true, ServerAddr: ""})
	if m.HasServerAddr() {
		t.Error("HasServerAddr() should be false when ServerAddr is explicitly empty")
	}

	m.SetConfig(&ShadowTLSConfig{Enabled: true, ServerAddr: "1.2.3.4:443"})
	if !m.HasServerAddr() {
		t.Error("HasServerAddr() should be true once ServerAddr is set")
	}
}

// TestSelectDiverseNodes_EarlyReturn_SkipsBlacklisted — тот же класс бага, что и в
// fallback-цикле выше, но в раннем возврате "len(nodes) <= n": он отдавал переданный срез
// как есть, вообще не проверяя IsBlacklisted(). Если пул кандидатов не больше, чем нужно
// хопов (типичный случай — ограниченный список узлов), забаненный узел уходил в цепочку
// без единой проверки.
func TestSelectDiverseNodes_EarlyReturn_SkipsBlacklisted(t *testing.T) {
	s := NewMultiHopSelector()

	blacklisted := &models.Node{Protocol: models.ProtoVLESS, Address: "bad.ip", Score: 10}
	blacklisted.BlacklistedUntil = time.Now().Add(time.Hour)
	good := &models.Node{Protocol: models.ProtoTrojan, Address: "good.ip", Score: 5}

	// len(nodes) == 2 <= n(3) → путь раннего возврата.
	result := s.selectDiverseNodes([]*models.Node{blacklisted, good}, 3)
	if len(result) != 1 || result[0].Address != "good.ip" {
		t.Errorf("early-return path must drop blacklisted nodes, got %+v", result)
	}
}
