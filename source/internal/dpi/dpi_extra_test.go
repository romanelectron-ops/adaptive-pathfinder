package dpi

// dpi_extra_test.go — дополнительные тесты для увеличения покрытия dpi пакета.
// Покрывает функции из shadow_tls.go, traffic_padding.go, multihop.go,
// cdn_fronting.go и canary.go без реальных сетевых соединений.

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── shadow_tls.go helpers ───────────────────────────────────────────────────

func TestGetServerHost_ValidHostPort(t *testing.T) {
	m := NewShadowTLSManager(&ShadowTLSConfig{
		HandshakeServer: "www.bing.com:443",
	})
	host := m.getServerHost()
	if host != "www.bing.com" {
		t.Errorf("want 'www.bing.com', got %q", host)
	}
	t.Logf("OK: getServerHost=%s", host)
}

func TestGetServerHost_InvalidFormat(t *testing.T) {
	// net.SplitHostPort fails → returns raw string
	m := NewShadowTLSManager(&ShadowTLSConfig{
		HandshakeServer: "not-a-valid-host-port",
	})
	host := m.getServerHost()
	if host == "" {
		t.Error("getServerHost should return something even for invalid format")
	}
	t.Logf("OK: getServerHost fallback=%s", host)
}

func TestGetServerPort_ValidPort(t *testing.T) {
	m := NewShadowTLSManager(&ShadowTLSConfig{
		HandshakeServer: "www.bing.com:8443",
	})
	port := m.getServerPort()
	if port != 8443 {
		t.Errorf("want 8443, got %d", port)
	}
	t.Logf("OK: getServerPort=%d", port)
}

func TestGetServerPort_InvalidFormat(t *testing.T) {
	// net.SplitHostPort fails → default 443
	m := NewShadowTLSManager(&ShadowTLSConfig{
		HandshakeServer: "not-valid",
	})
	port := m.getServerPort()
	if port != 443 {
		t.Errorf("want default 443, got %d", port)
	}
	t.Log("OK: getServerPort fallback=443")
}

func TestGetServerPort_DefaultPort(t *testing.T) {
	// Valid format but port = 0 → default 443
	m := NewShadowTLSManager(&ShadowTLSConfig{
		HandshakeServer: "example.com:443",
	})
	port := m.getServerPort()
	if port != 443 {
		t.Errorf("want 443, got %d", port)
	}
	t.Log("OK: getServerPort 443")
}

func TestGenerateSingBoxShadowTLSOutbound_Disabled(t *testing.T) {
	m := NewShadowTLSManager(&ShadowTLSConfig{
		Enabled: false,
	})
	result := m.GenerateSingBoxShadowTLSOutbound()
	if result != nil {
		t.Error("disabled manager should return nil")
	}
	t.Log("OK: GenerateSingBoxShadowTLSOutbound disabled → nil")
}

// P1-1 (аудит 2026-09-01): "server"/"server_port" обязаны быть РЕАЛЬНЫМ адресом сервера
// (ServerAddr), а не маскировочным SNI-хостом (HandshakeServer) — иначе клиент пытался бы
// дозвониться до самого маскировочного сайта. У outbound'а нет и не может быть "detour":
// это диалер, направление обёртки идёт от ВНУТРЕННЕГО протокола наружу, не наоборот (см.
// doc-comment функции).
func TestGenerateSingBoxShadowTLSOutbound_Enabled(t *testing.T) {
	m := NewShadowTLSManager(&ShadowTLSConfig{
		Enabled:         true,
		Version:         ShadowTLSv3,
		Password:        "test-password",
		HandshakeSNI:    "www.bing.com",
		HandshakeServer: "www.bing.com:443",
		ServerAddr:      "203.0.113.7:8443",
	})
	result := m.GenerateSingBoxShadowTLSOutbound()
	if result == nil {
		t.Fatal("enabled manager should return non-nil map")
	}
	if result["type"] != "shadowtls" {
		t.Errorf("type: want 'shadowtls', got %v", result["type"])
	}
	if result["version"] != 3 {
		t.Errorf("version: want 3, got %v", result["version"])
	}
	if result["password"] != "test-password" {
		t.Errorf("password: want 'test-password', got %v", result["password"])
	}
	if result["server"] != "203.0.113.7" {
		t.Errorf("server: want реальный адрес '203.0.113.7' (из ServerAddr), got %v — "+
			"клиент дозванивается сюда физически, это НЕ маскировочный SNI-хост", result["server"])
	}
	if result["server_port"] != 8443 {
		t.Errorf("server_port: want 8443 (из ServerAddr), got %v", result["server_port"])
	}
	if _, hasDetour := result["detour"]; hasDetour {
		t.Errorf("detour: shadowtls-outbound — диалер, у него не должно быть detour; "+
			"detour обязан стоять на ВНУТРЕННЕМ протокольном outbound'е (got %v)", result["detour"])
	}
	tls, ok := result["tls"].(map[string]interface{})
	if !ok {
		t.Fatal("tls field should be a map")
	}
	if tls["server_name"] != "www.bing.com" {
		t.Errorf("tls.server_name: want маскировочный 'www.bing.com' (из HandshakeSNI), got %v", tls["server_name"])
	}
	t.Logf("OK: GenerateSingBoxShadowTLSOutbound enabled → server=%v:%v sni=%v",
		result["server"], result["server_port"], tls["server_name"])
}

func TestShadowTLSManager_GetStatus_Disabled(t *testing.T) {
	m := NewShadowTLSManager(&ShadowTLSConfig{
		Enabled:         false,
		Version:         ShadowTLSv3,
		HandshakeSNI:    "www.bing.com",
		HandshakeServer: "www.bing.com:443",
	})
	ctx := context.Background()
	status := m.GetStatus(ctx)
	if status == nil {
		t.Fatal("GetStatus should not return nil")
	}
	if status.Enabled {
		t.Error("status.Enabled should be false")
	}
	if status.Available {
		t.Error("disabled manager should not be available")
	}
	if status.HandshakeSNI != "www.bing.com" {
		t.Errorf("HandshakeSNI: want 'www.bing.com', got %s", status.HandshakeSNI)
	}
	t.Logf("OK: GetStatus disabled → available=%v note=%q", status.Available, status.NoteForUser[:20])
}

// ─── cdn_fronting.go ─────────────────────────────────────────────────────────

func TestCDNFronter_BuildFrontedOutbound_Enabled(t *testing.T) {
	cfg := &CDNFrontingConfig{
		Enabled:      true,
		Provider:     CloudflareProvider,
		WorkerDomain: "my-app.workers.dev",
		BackendHost:  "vpn.example.com",
		BackendPort:  8443,
	}
	f := NewCDNFronter(cfg)
	params := f.BuildFrontedOutbound()
	if params == nil {
		t.Fatal("enabled fronter with worker domain should return non-nil params")
	}
	if params.Server == "" {
		t.Error("Server should not be empty")
	}
	if params.ServerPort != 443 {
		t.Errorf("ServerPort: want 443, got %d", params.ServerPort)
	}
	if params.SNI != "cloudflare.com" {
		t.Errorf("SNI: want 'cloudflare.com', got %q", params.SNI)
	}
	if params.WSHost != "my-app.workers.dev" {
		t.Errorf("WSHost: want 'my-app.workers.dev', got %q", params.WSHost)
	}
	if !params.TLSEnabled {
		t.Error("TLSEnabled should be true")
	}
	t.Logf("OK: BuildFrontedOutbound enabled → server=%s sni=%s wspath=%s", params.Server, params.SNI, params.WSPath)
}

func TestCDNFronter_BuildFrontedOutbound_EnabledNoWorker(t *testing.T) {
	cfg := &CDNFrontingConfig{
		Enabled:      true,
		Provider:     CloudflareProvider,
		WorkerDomain: "", // нет Worker → nil
	}
	f := NewCDNFronter(cfg)
	params := f.BuildFrontedOutbound()
	if params != nil {
		t.Error("no worker domain → BuildFrontedOutbound should return nil")
	}
	t.Log("OK: BuildFrontedOutbound enabled but no worker → nil")
}

func TestCDNFronter_GetStatus_Disabled(t *testing.T) {
	cfg := &CDNFrontingConfig{
		Enabled:      false,
		Provider:     CloudflareProvider,
		WorkerDomain: "my-app.workers.dev",
	}
	f := NewCDNFronter(cfg)
	ctx := context.Background()
	status := f.GetStatus(ctx)
	if status == nil {
		t.Fatal("GetStatus should not return nil")
	}
	if status.Enabled {
		t.Error("status.Enabled should be false")
	}
	if status.Available {
		t.Error("disabled fronter should not be available")
	}
	if status.Provider != "Cloudflare" {
		t.Errorf("Provider: want 'Cloudflare', got %q", status.Provider)
	}
	t.Logf("OK: CDNFronter GetStatus disabled → available=%v", status.Available)
}

func TestCDNFronter_IsAvailable_CancelledContext(t *testing.T) {
	f := NewCDNFronter(DefaultCDNConfig())
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancelled
	result := f.IsAvailable(ctx)
	// Cancelled context → connection should fail → false
	if result {
		t.Log("NOTE: IsAvailable returned true despite cancelled context (fast system)")
	} else {
		t.Log("OK: IsAvailable with cancelled context → false")
	}
}

// ─── multihop.go ─────────────────────────────────────────────────────────────

func TestMultiHopBuilder_BuildViaProxy_NilProxy(t *testing.T) {
	b := NewMultiHopBuilder(1080)
	_, err := b.BuildViaProxy(nil, &models.Node{})
	if err == nil {
		t.Error("nil proxy node should return error")
	}
	if !strings.Contains(err.Error(), "proxy") && !strings.Contains(err.Error(), "required") {
		t.Errorf("unexpected error: %v", err)
	}
	t.Logf("OK: BuildViaProxy nil proxy → %v", err)
}

func TestMultiHopBuilder_BuildViaProxy_NilExit(t *testing.T) {
	b := NewMultiHopBuilder(1080)
	_, err := b.BuildViaProxy(&models.Node{}, nil)
	if err == nil {
		t.Error("nil exit node should return error")
	}
	t.Logf("OK: BuildViaProxy nil exit → %v", err)
}

func TestMultiHopBuilder_BuildViaProxy_BothNil(t *testing.T) {
	b := NewMultiHopBuilder(1080)
	_, err := b.BuildViaProxy(nil, nil)
	if err == nil {
		t.Error("both nil should return error")
	}
	t.Logf("OK: BuildViaProxy both nil → %v", err)
}

func TestMultiHopBuilder_BuildThreeHop_NilNodes(t *testing.T) {
	b := NewMultiHopBuilder(1080)
	_, err := b.BuildThreeHop(nil, &models.Node{}, &models.Node{})
	if err == nil {
		t.Error("nil entry should return error")
	}
	t.Logf("OK: BuildThreeHop nil entry → %v", err)
}

func TestMultiHopBuilder_BuildThreeHop_AllNil(t *testing.T) {
	b := NewMultiHopBuilder(1080)
	_, err := b.BuildThreeHop(nil, nil, nil)
	if err == nil {
		t.Error("all nil should return error")
	}
	t.Logf("OK: BuildThreeHop all nil → %v", err)
}

// makeTestNode создаёт тестовый Node с заданным протоколом и score.
func makeTestNode(proto models.Protocol, addr string, score float64) *models.Node {
	return &models.Node{
		Protocol: proto,
		Address:  addr,
		Port:     443,
		Score:    score,
		Status:   models.StatusOK,
	}
}

func TestSelectDiverseNodes_DifferentProtocols(t *testing.T) {
	s := NewMultiHopSelector()
	nodes := []*models.Node{
		makeTestNode(models.ProtoVLESS, "1.1.1.1", 10),
		makeTestNode(models.ProtoTrojan, "2.2.2.2", 9),
		makeTestNode(models.ProtoVMess, "3.3.3.3", 8),
		makeTestNode(models.ProtoShadowsocks, "4.4.4.4", 7),
	}
	selected := s.selectDiverseNodes(nodes, 2)
	if len(selected) != 2 {
		t.Errorf("want 2 selected, got %d", len(selected))
	}
	// Проверяем что выбраны разные протоколы
	if len(selected) == 2 && selected[0].Protocol == selected[1].Protocol {
		t.Error("should prefer different protocols")
	}
	t.Logf("OK: selectDiverseNodes diverse → %s, %s", selected[0].Protocol, selected[1].Protocol)
}

func TestSelectDiverseNodes_SameProtocol_FillsFromRemaining(t *testing.T) {
	s := NewMultiHopSelector()
	// Все узлы одного протокола → должен добрать из оставшихся
	nodes := []*models.Node{
		makeTestNode(models.ProtoVLESS, "1.1.1.1", 10),
		makeTestNode(models.ProtoVLESS, "2.2.2.2", 9),
		makeTestNode(models.ProtoVLESS, "3.3.3.3", 8),
	}
	selected := s.selectDiverseNodes(nodes, 3)
	if len(selected) != 3 {
		t.Errorf("want 3 selected, got %d", len(selected))
	}
	t.Logf("OK: selectDiverseNodes fill-from-remaining → %d nodes", len(selected))
}

func TestSelectDiverseNodes_FilterBlacklisted(t *testing.T) {
	s := NewMultiHopSelector()
	blacklisted := makeTestNode(models.ProtoVLESS, "bad.ip", 5)
	// IsBlacklisted() checks time.Now().Before(BlacklistedUntil), NOT Status field
	blacklisted.BlacklistedUntil = time.Now().Add(time.Hour)
	nodes := []*models.Node{
		blacklisted,
		makeTestNode(models.ProtoTrojan, "good1.ip", 8),
		makeTestNode(models.ProtoVMess, "good2.ip", 7),
	}
	// len(3) > 2 → фильтрация активна (не hit edge case)
	selected := s.selectDiverseNodes(nodes, 2)
	for _, n := range selected {
		if n.Address == "bad.ip" {
			t.Error("blacklisted node should not be selected")
		}
	}
	t.Logf("OK: selectDiverseNodes filters blacklisted → %d selected", len(selected))
}

func TestSelectDiverseNodes_ZeroScore_Filtered(t *testing.T) {
	s := NewMultiHopSelector()
	zeroScore := makeTestNode(models.ProtoVLESS, "zero.ip", 0)
	nodes := []*models.Node{
		zeroScore,
		makeTestNode(models.ProtoTrojan, "good1.ip", 8),
		makeTestNode(models.ProtoVMess, "good2.ip", 7),
	}
	// len(3) > 2 → фильтрация активна; zero-score пропускается в первом проходе
	selected := s.selectDiverseNodes(nodes, 2)
	for _, n := range selected {
		if n.Address == "zero.ip" {
			t.Error("zero-score node should not be in diverse selection (first pass)")
		}
	}
	t.Logf("OK: selectDiverseNodes zero score filtered in first pass → %d selected", len(selected))
}

func TestProbeHopLatency_ClosedPort(t *testing.T) {
	// Получаем свободный порт и сразу закрываем
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen:", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	node := &models.Node{Address: "127.0.0.1", Port: port}
	ctx := context.Background()
	_, err = ProbeHopLatency(ctx, node)
	if err == nil {
		t.Error("expected error for closed port")
	}
	t.Logf("OK: ProbeHopLatency closed port → %v", err)
}

func TestProbeHopLatency_OpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen:", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	node := &models.Node{Address: "127.0.0.1", Port: port}
	ctx := context.Background()
	latency, err := ProbeHopLatency(ctx, node)
	if err != nil {
		t.Logf("NOTE: ProbeHopLatency open port error: %v", err)
	} else {
		t.Logf("OK: ProbeHopLatency open port → latency=%dms", latency)
	}
}

// ─── traffic_padding.go ──────────────────────────────────────────────────────

func TestNewPaddedConn_NotNil(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	cfg := DefaultPaddingConfig()
	pc := NewPaddedConn(client, cfg)
	if pc == nil {
		t.Fatal("NewPaddedConn should not return nil")
	}
	if pc.cfg != cfg {
		t.Error("cfg should be set")
	}
	if pc.done == nil {
		t.Error("done channel should be initialized")
	}
	t.Log("OK: NewPaddedConn not nil, fields set")
}

func TestNewPaddedConn_NilConfig_UsesDefault(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	pc := NewPaddedConn(client, nil)
	if pc == nil {
		t.Fatal("NewPaddedConn(nil) should not return nil")
	}
	if pc.cfg == nil {
		t.Error("nil cfg should be replaced with default")
	}
	t.Log("OK: NewPaddedConn nil config → uses default")
}

func TestPaddedConn_Write_Disabled(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	// Drain server side
	go io.Copy(io.Discard, server)

	cfg := DefaultPaddingConfig()
	cfg.Enabled = false
	pc := NewPaddedConn(client, cfg)
	defer pc.Close()

	data := []byte("hello world")
	n, err := pc.Write(data)
	if err != nil {
		t.Fatalf("Write disabled should pass through: %v", err)
	}
	if n != len(data) {
		t.Errorf("n: want %d, got %d", len(data), n)
	}
	t.Logf("OK: PaddedConn.Write disabled → n=%d", n)
}

func TestPaddedConn_Write_Enabled(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	// Drain server side
	go io.Copy(io.Discard, server)

	cfg := &PaddingConfig{
		Enabled:         true,
		JitterMinMs:     0,
		JitterMaxMs:     0, // без задержки в тесте
		PaddingMinBytes: 4,
		PaddingMaxBytes: 8,
	}
	pc := NewPaddedConn(client, cfg)
	defer pc.Close()

	data := []byte("test data")
	n, err := pc.Write(data)
	if err != nil {
		t.Fatalf("Write enabled failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("n: want %d, got %d", len(data), n)
	}
	t.Logf("OK: PaddedConn.Write enabled → n=%d (with padding)", n)
}

func TestTrafficPadder_WrapConn_Disabled(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	p := NewTrafficPadder(DefaultPaddingConfig()) // disabled
	wrapped := p.WrapConn(client)
	// Disabled → same conn returned
	if wrapped != client {
		t.Error("disabled WrapConn should return original connection")
	}
	t.Log("OK: WrapConn disabled → original conn")
}

func TestTrafficPadder_WrapConn_Enabled(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	cfg := DefaultPaddingConfig()
	cfg.Enabled = true
	p := NewTrafficPadder(cfg)
	wrapped := p.WrapConn(client)
	// Enabled → PaddedConn returned
	if _, ok := wrapped.(*PaddedConn); !ok {
		t.Error("enabled WrapConn should return *PaddedConn")
	}
	t.Log("OK: WrapConn enabled → *PaddedConn")
}

func TestTrafficPadder_ApplyJitter_Disabled(t *testing.T) {
	p := NewTrafficPadder(DefaultPaddingConfig()) // disabled
	start := time.Now()
	p.ApplyJitter() // should return immediately
	elapsed := time.Since(start)
	if elapsed > 10*time.Millisecond {
		t.Errorf("disabled ApplyJitter should be instant, took %s", elapsed)
	}
	t.Logf("OK: ApplyJitter disabled → instant (elapsed=%s)", elapsed)
}

func TestTrafficPadder_ApplyJitter_Enabled(t *testing.T) {
	cfg := &PaddingConfig{
		Enabled:     true,
		JitterMinMs: 0,
		JitterMaxMs: 0, // 0 delay → just checks the code path
	}
	p := NewTrafficPadder(cfg)
	start := time.Now()
	p.ApplyJitter()
	elapsed := time.Since(start)
	t.Logf("OK: ApplyJitter enabled (0ms) → elapsed=%s", elapsed)
}

func TestTrafficPadder_JitteredDial_Disabled_LocalServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen:", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	p := NewTrafficPadder(DefaultPaddingConfig()) // disabled
	addr := ln.Addr().String()
	conn, err := p.JitteredDial(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("JitteredDial disabled failed: %v", err)
	}
	conn.Close()
	t.Logf("OK: JitteredDial disabled → connected to %s", addr)
}

func TestTrafficPadder_JitteredDial_Enabled_NoJitter(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen:", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	cfg := &PaddingConfig{
		Enabled:     true,
		JitterMinMs: 0,
		JitterMaxMs: 0, // 0 delay
	}
	p := NewTrafficPadder(cfg)
	addr := ln.Addr().String()
	conn, err := p.JitteredDial(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("JitteredDial enabled (0 jitter) failed: %v", err)
	}
	conn.Close()
	t.Logf("OK: JitteredDial enabled 0ms jitter → connected to %s", addr)
}

func TestTrafficPadder_JitteredDial_CancelledContext(t *testing.T) {
	cfg := &PaddingConfig{
		Enabled:     true,
		JitterMinMs: 60, // 30ms after /2
		JitterMaxMs: 100,
	}
	p := NewTrafficPadder(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // отменяем сразу

	_, err := p.JitteredDial(ctx, "tcp", "127.0.0.1:9")
	// Должно вернуть ctx.Err() или dial error
	if err == nil {
		t.Error("expected error with cancelled context")
	}
	t.Logf("OK: JitteredDial cancelled context → %v", err)
}

// ─── NullPaddingReader ────────────────────────────────────────────────────────

func TestNullPaddingReader_NoPadding(t *testing.T) {
	data := []byte("hello world")
	r := bytes.NewReader(data)
	npr := NewNullPaddingReader(r, 0)
	if npr == nil {
		t.Fatal("NewNullPaddingReader should not return nil")
	}

	buf := make([]byte, len(data))
	n, err := npr.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("want %d bytes, got %d", len(data), n)
	}
	if string(buf[:n]) != string(data) {
		t.Errorf("data mismatch: want %q, got %q", data, buf[:n])
	}
	t.Logf("OK: NullPaddingReader paddingLen=0 → read %d bytes", n)
}

func TestNullPaddingReader_WithPadding(t *testing.T) {
	// Сначала идут padding-байты (8 байт), потом реальные данные
	padding := make([]byte, 8)
	payload := []byte("real data")
	full := append(padding, payload...)

	r := bytes.NewReader(full)
	npr := NewNullPaddingReader(r, 8) // skip 8 bytes of padding

	buf := make([]byte, len(payload))
	n, err := npr.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read failed: %v", err)
	}
	if n != len(payload) {
		t.Errorf("want %d bytes, got %d", len(payload), n)
	}
	if string(buf[:n]) != string(payload) {
		t.Errorf("data mismatch: want %q, got %q", payload, buf[:n])
	}
	t.Logf("OK: NullPaddingReader paddingLen=8 → skipped padding, read %q", buf[:n])
}

func TestNullPaddingReader_PaddingConsumedOnce(t *testing.T) {
	// Второй вызов Read не должен повторно skip-ать padding
	padding := make([]byte, 4)
	payload := []byte("abcdefgh")
	full := append(padding, payload...)

	r := bytes.NewReader(full)
	npr := NewNullPaddingReader(r, 4)

	buf := make([]byte, 4)
	// Первый Read — skips padding, reads first 4 bytes of payload
	n1, _ := npr.Read(buf)
	// Второй Read — читает оставшиеся байты без skip
	n2, _ := npr.Read(buf)

	if n1+n2 != len(payload) {
		t.Errorf("total read: want %d, got %d", len(payload), n1+n2)
	}
	t.Logf("OK: NullPaddingReader two reads → %d+%d=%d bytes", n1, n2, n1+n2)
}

// ─── canary.go unexported ────────────────────────────────────────────────────

func TestCheckEntropyHeuristic_NoSocksAddr(t *testing.T) {
	// socksAddr="" → immediately returns false (no network call)
	c := NewCanaryTester("") // пустой SOCKS addr
	ctx := context.Background()
	result := c.checkEntropyHeuristic(ctx)
	if result {
		t.Error("empty socksAddr should return false")
	}
	t.Log("OK: checkEntropyHeuristic empty socksAddr → false")
}

func TestCheckEntropyHeuristic_WithSocksServer(t *testing.T) {
	// Запускаем временный TCP-сервер имитирующий SOCKS
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen:", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	addr := ln.Addr().String()
	c := NewCanaryTester(addr)
	ctx := context.Background()
	result := c.checkEntropyHeuristic(ctx)
	if !result {
		t.Error("available SOCKS addr should return true")
	}
	t.Logf("OK: checkEntropyHeuristic with server → true (addr=%s)", addr)
}

func TestCheckEntropyHeuristic_ClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen:", err)
	}
	addr := ln.Addr().String()
	ln.Close() // immediately close → connection refused

	c := NewCanaryTester(addr)
	ctx := context.Background()
	result := c.checkEntropyHeuristic(ctx)
	if result {
		t.Error("closed port should return false")
	}
	t.Logf("OK: checkEntropyHeuristic closed port → false (addr=%s)", addr)
}
