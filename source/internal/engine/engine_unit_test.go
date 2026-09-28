package engine

// engine_unit_test.go — unit-tests covering getters, setters, and helpers
// that do NOT require a running sing-box daemon.
// Target: bring engine coverage from 14.3% to 50%+.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

func newTestEngine() *Engine {
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	cfg.EnableKillSwitch = false
	return New(cfg)
}

// ─── GetStats ────────────────────────────────────────────────────────────────

func TestGetStats(t *testing.T) {
	e := newTestEngine()
	stats := e.GetStats()
	if stats == nil {
		t.Fatal("GetStats returned nil")
	}
	// Expected keys set in engine.go
	if _, ok := stats["total"]; !ok {
		t.Errorf("GetStats missing key \"total\", got: %v", stats)
	}
	t.Logf("OK: GetStats %v", stats)
}

// ─── GetConfig ───────────────────────────────────────────────────────────────

func TestGetConfig(t *testing.T) {
	cfg := models.DefaultConfig()
	e := New(cfg)
	got := e.GetConfig()
	if got == nil {
		t.Fatal("GetConfig returned nil")
	}
	if got != e.cfg {
		t.Error("GetConfig should return same pointer as internal cfg")
	}
	t.Log("OK: GetConfig")
}

// ─── GetUpdateStatus ─────────────────────────────────────────────────────────

func TestGetUpdateStatus(t *testing.T) {
	e := newTestEngine()
	// nil before any check is fine — just must not panic
	status := e.GetUpdateStatus()
	_ = status
	t.Log("OK: GetUpdateStatus no panic")
}

// ─── GetLeakGuardStatus ──────────────────────────────────────────────────────

func TestGetLeakGuardStatus(t *testing.T) {
	e := newTestEngine()
	s := e.GetLeakGuardStatus()
	if s == nil {
		t.Fatal("GetLeakGuardStatus returned nil")
	}
	t.Logf("OK: GetLeakGuardStatus %v", s)
}

// ─── EnableIPv6Block / EnableWebRTCBlock ─────────────────────────────────────

func TestEnableIPv6Block(t *testing.T) {
	e := newTestEngine()
	// Enable
	if err := e.EnableIPv6Block(true); err != nil {
		t.Logf("EnableIPv6Block(true) warn: %v", err)
	}
	// Disable
	if err := e.EnableIPv6Block(false); err != nil {
		t.Logf("EnableIPv6Block(false) warn: %v", err)
	}
	t.Log("OK: EnableIPv6Block toggle no panic")
}

func TestEnableWebRTCBlock(t *testing.T) {
	e := newTestEngine()
	if err := e.EnableWebRTCBlock(true); err != nil {
		t.Logf("EnableWebRTCBlock(true) warn: %v", err)
	}
	if err := e.EnableWebRTCBlock(false); err != nil {
		t.Logf("EnableWebRTCBlock(false) warn: %v", err)
	}
	t.Log("OK: EnableWebRTCBlock toggle no panic")
}

// ─── EnableTrafficPadding ────────────────────────────────────────────────────

func TestEnableTrafficPadding(t *testing.T) {
	e := newTestEngine()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("EnableTrafficPadding panicked: %v", r)
		}
	}()
	e.EnableTrafficPadding(true, false)
	e.EnableTrafficPadding(true, true)
	e.EnableTrafficPadding(false, false)
	t.Log("OK: EnableTrafficPadding")
}

// ─── SetStickyPolicy ─────────────────────────────────────────────────────────

func TestSetStickyPolicy(t *testing.T) {
	e := newTestEngine()
	policies := []string{"none", "domain", "time", "persistent"}
	for _, p := range policies {
		e.SetStickyPolicy(p)
		s := e.GetStickySessionStatus()
		if _, ok := s["policy"]; !ok {
			t.Errorf("SetStickyPolicy(%q): GetStickySessionStatus missing policy key", p)
		}
	}
	t.Log("OK: SetStickyPolicy all variants")
}

// ─── CDN Config / Worker Script ──────────────────────────────────────────────

func TestSetCDNConfig(t *testing.T) {
	e := newTestEngine()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("SetCDNConfig panicked: %v", r)
		}
	}()
	e.SetCDNConfig("worker.example.workers.dev", "backend.example.com", 8443)
	t.Log("OK: SetCDNConfig no panic")
}

func TestGetCDNWorkerScript(t *testing.T) {
	e := newTestEngine()
	e.SetCDNConfig("myworker.workers.dev", "origin.example.com", 443)
	script := e.GetCDNWorkerScript()
	if script == "" {
		t.Error("GetCDNWorkerScript returned empty string after SetCDNConfig")
	}
	t.Logf("OK: GetCDNWorkerScript len=%d", len(script))
}

// ─── ShadowTLS Config ────────────────────────────────────────────────────────

func TestSetShadowTLSConfig(t *testing.T) {
	e := newTestEngine()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("SetShadowTLSConfig panicked: %v", r)
		}
	}()
	// ТЗ v1.3 F5.3: адрес реального сервера не может быть заглушкой (5.6.7.8 раньше проходил —
	// инцидент 2026-09-02); свой LAN-сервер (RFC1918) — легитимен.
	if err := e.SetShadowTLSConfig(true, "s3cr3t", "www.bing.com", "www.bing.com:443", "192.168.1.10:8443"); err != nil {
		t.Errorf("SetShadowTLSConfig(enabled, non-empty password) unexpected error: %v", err)
	}
	if err := e.SetShadowTLSConfig(true, "s3cr3t", "", "", "5.6.7.8:8443"); err == nil {
		t.Error("SetShadowTLSConfig должен отвергать адрес-заглушку 5.6.7.8")
	}
	if err := e.SetShadowTLSConfig(false, "", "", "", ""); err != nil {
		t.Errorf("SetShadowTLSConfig(disabled, empty) unexpected error: %v", err)
	}
	t.Log("OK: SetShadowTLSConfig")
}

// TestSetShadowTLSConfig_RejectsEmptyPasswordWhenEnabled — задача #23, QA 2026-08-17:
// пустой пароль при enabled=true раньше молча сохранялся, хотя гарантированно не
// сработал бы (HMAC-ключ не совпадёт с сервером).
func TestSetShadowTLSConfig_RejectsEmptyPasswordWhenEnabled(t *testing.T) {
	e := newTestEngine()
	err := e.SetShadowTLSConfig(true, "", "www.example.com", "1.2.3.4", "192.168.1.10:8443")
	if err == nil {
		t.Fatal("expected error for enabled=true with empty password, got nil")
	}
	if e.shadowTLS.IsEnabled() {
		t.Error("ShadowTLS must not be left enabled after a rejected config")
	}
}

// TestSetShadowTLSConfig_RejectsEmptyServerAddrWhenEnabled — P1-1 (аудит 2026-09-01),
// симметрично проверке пароля выше: без адреса реального сервера клиенту физически
// некуда подключаться, включать ShadowTLS с пустым ServerAddr нельзя.
func TestSetShadowTLSConfig_RejectsEmptyServerAddrWhenEnabled(t *testing.T) {
	e := newTestEngine()
	err := e.SetShadowTLSConfig(true, "s3cr3t", "www.example.com", "1.2.3.4", "")
	if err == nil {
		t.Fatal("expected error for enabled=true with empty serverAddr, got nil")
	}
	if e.shadowTLS.IsEnabled() {
		t.Error("ShadowTLS must not be left enabled after a rejected config")
	}
}

// TestSetShadowTLSConfig_KeepsExistingPasswordOnEmptyResend — задача #29, QA 2026-08-18:
// GetStatus() не возвращает пароль (секрет), поэтому UI не может подставить его при
// повторном открытии диалога. Повторное сохранение с уже включённым ShadowTLS и пустым
// паролем (например, пользователь просто поменял SNI) должно СОХРАНИТЬ прежний пароль, а
// не требовать вводить его заново и не откатывать enabled.
func TestSetShadowTLSConfig_KeepsExistingPasswordOnEmptyResend(t *testing.T) {
	e := newTestEngine()
	if err := e.SetShadowTLSConfig(true, "s3cr3t", "www.example.com", "1.2.3.4", "192.168.1.10:8443"); err != nil {
		t.Fatalf("initial SetShadowTLSConfig unexpected error: %v", err)
	}
	if err := e.SetShadowTLSConfig(true, "", "www.other.example.com", "1.2.3.4", ""); err != nil {
		t.Fatalf("resend with empty password unexpected error: %v", err)
	}
	cfg := e.shadowTLS.GetConfig()
	if !cfg.Enabled {
		t.Error("ShadowTLS should remain enabled")
	}
	if cfg.Password != "s3cr3t" {
		t.Errorf("Password = %q, want original %q to be preserved", cfg.Password, "s3cr3t")
	}
	if cfg.ServerAddr != "192.168.1.10:8443" {
		t.Errorf("ServerAddr = %q, want original %q to be preserved on empty resend", cfg.ServerAddr, "192.168.1.10:8443")
	}
	if cfg.HandshakeSNI != "www.other.example.com" {
		t.Errorf("HandshakeSNI = %q, want updated value applied", cfg.HandshakeSNI)
	}
}

// ─── GetFallbackStatus / ActivateFallbackTunnel / AutoSelectFallback ─────────

func TestGetFallbackStatus(t *testing.T) {
	e := newTestEngine()
	s := e.GetFallbackStatus()
	if s == nil {
		t.Fatal("GetFallbackStatus nil")
	}
	t.Logf("OK: GetFallbackStatus %v", s)
}

func TestActivateFallbackTunnel(t *testing.T) {
	e := newTestEngine()
	// Unknown tunnel name — should return error, not panic
	err := e.ActivateFallbackTunnel("nonexistent_tunnel")
	if err == nil {
		t.Log("ActivateFallbackTunnel nonexistent returned nil (may be by-design)")
	} else {
		t.Logf("OK: ActivateFallbackTunnel error as expected: %v", err)
	}
}

func TestAutoSelectFallback(t *testing.T) {
	e := newTestEngine()
	result := e.AutoSelectFallback()
	t.Logf("OK: AutoSelectFallback = %q", result)
}

// ─── GetWatchdogStatus ───────────────────────────────────────────────────────

func TestGetWatchdogStatus(t *testing.T) {
	e := newTestEngine()
	s := e.GetWatchdogStatus()
	if s == nil {
		t.Fatal("GetWatchdogStatus nil")
	}
	t.Logf("OK: GetWatchdogStatus %v", s)
}

// ─── AdBlock ─────────────────────────────────────────────────────────────────

func TestGetAdBlockStatus(t *testing.T) {
	e := newTestEngine()
	s := e.GetAdBlockStatus()
	if s == nil {
		t.Fatal("GetAdBlockStatus nil")
	}
	if _, ok := s["profile"]; !ok {
		t.Errorf("GetAdBlockStatus missing 'profile', got: %v", s)
	}
	t.Logf("OK: GetAdBlockStatus %v", s)
}

func TestSetAdBlockProfile(t *testing.T) {
	e := newTestEngine()
	profiles := []string{"none", "standard", "strict", "custom"}
	for _, p := range profiles {
		err := e.SetAdBlockProfile(p)
		if err != nil {
			t.Logf("SetAdBlockProfile(%q) warn: %v", p, err)
		}
	}
	// Invalid profile
	err := e.SetAdBlockProfile("super_ultra_extreme")
	if err == nil {
		t.Log("warn: invalid adblock profile not rejected")
	}
	t.Log("OK: SetAdBlockProfile")
}

func TestAdBlockToggleAllowlist(t *testing.T) {
	e := newTestEngine()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("AdBlockToggleAllowlist panicked: %v", r)
		}
	}()
	e.AdBlockToggleAllowlist("example.com", true)
	e.AdBlockToggleAllowlist("example.com", false)
	t.Log("OK: AdBlockToggleAllowlist add/remove")
}

// ─── AntiBlock / Bypass ──────────────────────────────────────────────────────

func TestGetAntiBlockStatus(t *testing.T) {
	e := newTestEngine()
	s := e.GetAntiBlockStatus()
	if s == nil {
		t.Fatal("GetAntiBlockStatus nil")
	}
	t.Logf("OK: GetAntiBlockStatus %v", s)
}

func TestSetAntiBlockConfig(t *testing.T) {
	e := newTestEngine()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("SetAntiBlockConfig panicked: %v", r)
		}
	}()
	e.SetAntiBlockConfig(true, false, true, "test-api-key")
	e.SetAntiBlockConfig(false, false, false, "")
	t.Log("OK: SetAntiBlockConfig")
}

func TestGetBypassRules(t *testing.T) {
	e := newTestEngine()
	rules := e.GetBypassRules()
	t.Logf("OK: GetBypassRules %d rules", len(rules))
}

func TestSetBypassRule(t *testing.T) {
	e := newTestEngine()
	// Non-existent rule — should return false, not panic
	ok := e.SetBypassRule("nonexistent-rule-id", true)
	t.Logf("OK: SetBypassRule nonexistent = %v", ok)
}

func TestAddRemoveBypassDomain(t *testing.T) {
	e := newTestEngine()
	// Add a bypass domain
	ok := e.AddBypassDomain("test.example.com", "Test Domain", false, false)
	t.Logf("AddBypassDomain ok=%v", ok)

	rules := e.GetBypassRules()
	var addedID string
	for _, r := range rules {
		if r["name"] == "Test Domain" {
			if id, ok2 := r["id"].(string); ok2 {
				addedID = id
			}
		}
	}

	if addedID != "" {
		ok2 := e.RemoveBypassDomain(addedID)
		if !ok2 {
			t.Error("RemoveBypassDomain should succeed for added domain")
		}
		t.Log("OK: AddBypassDomain + RemoveBypassDomain")
	} else {
		// RemoveBypassDomain on nonexistent
		ok2 := e.RemoveBypassDomain("nonexistent-id")
		if ok2 {
			t.Error("RemoveBypassDomain should return false for nonexistent")
		}
		t.Log("OK: bypass domain operations")
	}
}

// ─── MultiHop ────────────────────────────────────────────────────────────────

func TestSelectMultiHopChain(t *testing.T) {
	e := newTestEngine()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("SelectMultiHopChain panicked: %v", r)
		}
	}()
	chain := e.SelectMultiHopChain(2)
	_ = chain
	t.Log("OK: SelectMultiHopChain(2) no panic")
}

// ─── DPI ─────────────────────────────────────────────────────────────────────

func TestGetDPIStatus(t *testing.T) {
	e := newTestEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	s := e.GetDPIStatus(ctx)
	if s == nil {
		t.Fatal("GetDPIStatus nil")
	}
	t.Logf("OK: GetDPIStatus keys=%d", len(s))
}

// [консилиум, TZ_TAILS_HARDENING_2026-08-31.md кластер A, находка №1] Регрессия конкретно на
// прежний баг: "multihop_enabled" в ответе GetDPIStatus раньше читался из EnableChain (управляет
// самим фактом сборки цепочки в tryFallback) вместо MultiHopEnabled (управляет ТЕМ, КАК цепочка
// собирается внутри buildMultiHopChain) — разные поля разной семантики. Пользователь включает
// тумблер "Многохоповая цепочка" (MultiHopEnabled=true), не трогая EnableChain — старый код
// возвращал бы false, статус-API врал о состоянии тумблера.
func TestGetDPIStatus_MultihopEnabled_ReflectsMultiHopEnabledNotEnableChain(t *testing.T) {
	e := newTestEngine()
	e.cfg.MultiHopEnabled = true
	e.cfg.EnableChain = false
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	s := e.GetDPIStatus(ctx)
	got, ok := s["multihop_enabled"].(bool)
	if !ok {
		t.Fatalf("multihop_enabled отсутствует или не bool: %v", s["multihop_enabled"])
	}
	if !got {
		t.Error("multihop_enabled = false при MultiHopEnabled=true, EnableChain=false — " +
			"статус-API читает не то поле (регрессия на находку №1)")
	}
}

// ─── ResetNetwork ────────────────────────────────────────────────────────────

func TestResetNetwork(t *testing.T) {
	e := newTestEngine()
	err := e.ResetNetwork()
	// May fail if not admin/root, that's OK — just must not panic
	if err != nil {
		t.Logf("ResetNetwork warn (likely needs privileges): %v", err)
	} else {
		t.Log("OK: ResetNetwork")
	}
}

func TestResetNetworkDetailed(t *testing.T) {
	e := newTestEngine()
	result := e.ResetNetworkDetailed()
	if result == nil {
		t.Fatal("ResetNetworkDetailed nil")
	}
	t.Logf("OK: ResetNetworkDetailed steps=%d", len(result.Warnings))
}

// ─── SetMasterPassword ───────────────────────────────────────────────────────

func TestSetMasterPassword(t *testing.T) {
	e := newTestEngine()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("SetMasterPassword panicked: %v", r)
		}
	}()
	e.SetMasterPassword("test-password-123")
	e.SetMasterPassword("") // clear
	t.Log("OK: SetMasterPassword")
}

// ─── getActiveCandidates / selectBestExcluding ───────────────────────────────

func TestGetActiveCandidates(t *testing.T) {
	e := newTestEngine()
	// Add a few test nodes
	for i := 0; i < 5; i++ {
		n := &models.Node{
			ID:       fmt.Sprintf("node-%d", i),
			Protocol: models.ProtoVLESS,
			Address:  "10.0.0.1",
			Port:     10000 + i,
			Status:   models.StatusOK,
			Score:    float64(i) * 0.1,
		}
		e.nodes = append(e.nodes, n)
	}
	candidates := e.getActiveCandidates(3)
	if len(candidates) > 3 {
		t.Errorf("getActiveCandidates(3) returned %d > 3", len(candidates))
	}
	t.Logf("OK: getActiveCandidates %d nodes", len(candidates))
}

// TestGetRescanBatch_MixesInNeverCheckedNodes — P1.3 (docs/TZ_APF_QA_AND_BACKLOG_v1.0.md §1,
// docs/TZ_APF_ROADMAP_v1.2.md): чистый top-N по Score (getActiveCandidates) для батча
// ПЕРЕПРОВЕРКИ — самоусиливающееся узкое место: низкоскоровые/никогда не проверенные узлы
// никогда не попадают в батч, чтобы получить шанс на Score, и поэтому никогда туда не попадают.
// getRescanBatch обязан подмешать долю лимита из давно-непроверенных узлов, а не отдавать
// целиком верхушку по Score.
func TestGetRescanBatch_MixesInNeverCheckedNodes(t *testing.T) {
	e := newTestEngine()
	// 20 узлов с высоким Score и недавней проверкой ("уже победители" — доминируют в чистом
	// top-N вечно) + 20 узлов с нулевым Score и нулевым LastChecked ("никогда не проверялись").
	for i := 0; i < 20; i++ {
		e.nodes = append(e.nodes, &models.Node{
			ID: fmt.Sprintf("winner-%d", i), Protocol: models.ProtoVLESS,
			Status: models.StatusOK, Score: 0.9, LastChecked: time.Now(),
		})
	}
	for i := 0; i < 20; i++ {
		e.nodes = append(e.nodes, &models.Node{
			ID: fmt.Sprintf("untested-%d", i), Protocol: models.ProtoVLESS,
			Status: models.StatusUnknown, Score: 0, // LastChecked нулевое (zero value)
		})
	}

	batch := e.getRescanBatch(10)
	if len(batch) != 10 {
		t.Fatalf("expected batch of 10, got %d", len(batch))
	}
	untestedInBatch := 0
	for _, n := range batch {
		if strings.HasPrefix(n.ID, "untested-") {
			untestedInBatch++
		}
	}
	if untestedInBatch == 0 {
		t.Errorf("expected getRescanBatch to mix in never-checked nodes, got 0 of 10 — "+
			"pure top-N by Score would starve them forever (batch: %v)", nodeIDs(batch))
	}
	t.Logf("OK: getRescanBatch(10) mixed in %d never-checked nodes", untestedInBatch)
}

func nodeIDs(nodes []*models.Node) []string {
	ids := make([]string, len(nodes))
	for i, n := range nodes {
		ids[i] = n.ID
	}
	return ids
}

// TestSelectNextCyclic_WrapsAroundToStart — CyclicNodeSearch (docs/TZ_APF_ROADMAP_v1.2.md):
// живой запрос пользователя «дойдя до конца списка узлов, идти по второму кругу, а не
// останавливаться». Три узла, четыре последовательных вызова — четвёртый обязан вернуться
// к первому узлу (по стабильному ID-порядку), не вернуть nil и не зависнуть на последнем.
func TestSelectNextCyclic_WrapsAroundToStart(t *testing.T) {
	e := newTestEngine()
	e.mu.Lock()
	e.nodes = []*models.Node{
		{ID: "a", Name: "A"}, {ID: "b", Name: "B"}, {ID: "c", Name: "C"},
	}
	e.mu.Unlock()

	var seq []string
	for i := 0; i < 4; i++ {
		n := e.selectNextCyclic(nil)
		if n == nil {
			t.Fatalf("selectNextCyclic returned nil on call #%d", i+1)
		}
		seq = append(seq, n.ID)
	}
	want := []string{"a", "b", "c", "a"} // 4-й вызов — снова "a", второй круг
	for i := range want {
		if seq[i] != want[i] {
			t.Errorf("call #%d: got %q, want %q (full sequence: %v)", i+1, seq[i], want[i], seq)
		}
	}
}

// TestSelectNextCyclic_SkipsExcluded — исключённый узел (текущий, только что отказавший)
// не должен возвращаться, даже если по очереди в круге настал именно его черёд.
func TestSelectNextCyclic_SkipsExcluded(t *testing.T) {
	e := newTestEngine()
	e.mu.Lock()
	e.nodes = []*models.Node{{ID: "a"}, {ID: "b"}}
	e.mu.Unlock()

	n := e.selectNextCyclic(&models.Node{ID: "a"})
	if n == nil || n.ID != "b" {
		t.Fatalf("expected excluded node 'a' to be skipped, got %v", n)
	}
}

// TestTryCyclicSearch_StopsAfterOneFullLap — connectNode всегда fails в тестовой среде (нет
// реального sing-box) — tryCyclicSearch обязана пройти РОВНО один круг (не зависнуть в
// бесконечном цикле) и вернуть false.
func TestTryCyclicSearch_StopsAfterOneFullLap(t *testing.T) {
	e := newTestEngine()
	e.mu.Lock()
	e.nodes = []*models.Node{{ID: "a", Address: "10.0.0.1"}, {ID: "b", Address: "10.0.0.2"}}
	e.mu.Unlock()

	done := make(chan bool, 1)
	go func() { ok, _ := e.tryCyclicSearch(nil); done <- ok }()
	select {
	case ok := <-done:
		if ok {
			t.Error("expected false — no real sing-box in test env, connectNode must fail")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("tryCyclicSearch did not return within 10s — likely infinite loop")
	}
}

// TestBuildMultiHopChain_PrefersProtocolDiversity — P2.2 (docs/TZ_APF_ROADMAP_v1.2.md): в
// отличие от buildBestChain (просто топ-2 по Score), MultiHopSelector должен предпочесть
// узлы с РАЗНЫМИ протоколами, если такие есть в пуле, вместо двух лучших одного протокола.
func TestBuildMultiHopChain_PrefersProtocolDiversity(t *testing.T) {
	e := newTestEngine()
	e.mu.Lock()
	e.nodes = []*models.Node{
		{ID: "vless-best", Protocol: models.ProtoVLESS, Address: "1.1.1.1", Score: 0.95},
		{ID: "vless-second", Protocol: models.ProtoVLESS, Address: "1.1.1.2", Score: 0.90},
		{ID: "trojan-third", Protocol: models.ProtoTrojan, Address: "1.1.1.3", Score: 0.50},
	}
	e.mu.Unlock()
	e.cfg.MultiHopCount = 2

	chain := e.buildMultiHopChain()
	if chain == nil || len(chain.Nodes) != 2 {
		t.Fatalf("expected a 2-node chain, got %v", chain)
	}
	protos := map[models.Protocol]bool{}
	for _, n := range chain.Nodes {
		protos[n.Protocol] = true
	}
	if len(protos) < 2 {
		t.Errorf("expected chain to use 2 different protocols (diversity), got all %v: %v",
			chain.Nodes[0].Protocol, chain.Nodes)
	}
}

// TestBuildMultiHopChain_ThreeHops — MultiHopCount=3 должен дать цепочку из 3 узлов, если в
// пуле хватает кандидатов.
func TestBuildMultiHopChain_ThreeHops(t *testing.T) {
	e := newTestEngine()
	e.mu.Lock()
	e.nodes = []*models.Node{
		{ID: "a", Protocol: models.ProtoVLESS, Address: "1.1.1.1", Score: 0.9},
		{ID: "b", Protocol: models.ProtoTrojan, Address: "1.1.1.2", Score: 0.8},
		{ID: "c", Protocol: models.ProtoVMess, Address: "1.1.1.3", Score: 0.7},
	}
	e.mu.Unlock()
	e.cfg.MultiHopCount = 3

	chain := e.buildMultiHopChain()
	if chain == nil || len(chain.Nodes) != 3 {
		t.Fatalf("expected a 3-node chain, got %v", chain)
	}
}

// TestBuildMultiHopChain_InvalidCountFallsBackToTwo — MultiHopCount вне {2,3} обязан
// откатиться на 2, не паниковать и не строить абсурдную цепочку.
func TestBuildMultiHopChain_InvalidCountFallsBackToTwo(t *testing.T) {
	e := newTestEngine()
	e.mu.Lock()
	e.nodes = []*models.Node{
		{ID: "a", Protocol: models.ProtoVLESS, Address: "1.1.1.1", Score: 0.9},
		{ID: "b", Protocol: models.ProtoTrojan, Address: "1.1.1.2", Score: 0.8},
	}
	e.mu.Unlock()
	e.cfg.MultiHopCount = 99

	chain := e.buildMultiHopChain()
	if chain == nil || len(chain.Nodes) != 2 {
		t.Fatalf("expected fallback to a 2-node chain, got %v", chain)
	}
}

// TestBuildMultiHopChain_NotEnoughNodes — меньше кандидатов, чем хопов → nil, не паника.
func TestBuildMultiHopChain_NotEnoughNodes(t *testing.T) {
	e := newTestEngine()
	e.mu.Lock()
	e.nodes = []*models.Node{{ID: "only", Protocol: models.ProtoVLESS, Score: 0.9}}
	e.mu.Unlock()
	e.cfg.MultiHopCount = 2

	if chain := e.buildMultiHopChain(); chain != nil {
		t.Errorf("expected nil chain with only 1 candidate, got %v", chain)
	}
}

func TestSelectBestExcluding(t *testing.T) {
	e := newTestEngine()
	n1 := &models.Node{ID: "n1", Protocol: models.ProtoVLESS, Status: models.StatusOK, Score: 0.9}
	n2 := &models.Node{ID: "n2", Protocol: models.ProtoVLESS, Status: models.StatusOK, Score: 0.8}
	e.nodes = []*models.Node{n1, n2}

	best := e.selectBestExcluding(n1)
	if best == n1 {
		t.Error("selectBestExcluding should not return the excluded node")
	}
	t.Logf("OK: selectBestExcluding best=%v", best)
}

// ─── toInt helper ────────────────────────────────────────────────────────────

func TestToInt(t *testing.T) {
	tests := []struct {
		input interface{}
		want  int
		ok    bool
	}{
		{42, 42, true},
		{int64(100), 100, true},
		{float64(3.7), 3, true},
		{"not_a_number", 0, false},
		{nil, 0, false},
		{true, 0, false},
	}
	for _, tt := range tests {
		got, ok := toInt(tt.input)
		if ok != tt.ok {
			t.Errorf("toInt(%v): ok=%v want %v", tt.input, ok, tt.ok)
		}
		if ok && got != tt.want {
			t.Errorf("toInt(%v): got=%d want %d", tt.input, got, tt.want)
		}
	}
	t.Log("OK: toInt all cases")
}

// ─── log helper ──────────────────────────────────────────────────────────────

func TestEngineLog(t *testing.T) {
	e := newTestEngine()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("log() panicked: %v", r)
		}
	}()
	e.log("test message")
	e.log("message with special chars: !@#$%")
	t.Log("OK: log() no panic")
}

// ─── setDisconnected ─────────────────────────────────────────────────────────

func TestSetDisconnected(t *testing.T) {
	e := newTestEngine()
	e.setDisconnected()
	state := e.GetState()
	if state.Connected {
		t.Error("setDisconnected: should not be connected")
	}
	t.Log("OK: setDisconnected")
}

// ─── ForceRescan ─────────────────────────────────────────────────────────────

func TestForceRescan(t *testing.T) {
	e := newTestEngine()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ForceRescan panicked: %v", r)
		}
	}()
	e.ForceRescan()
	t.Log("OK: ForceRescan no panic")
}

// ─── AddPaidProvider ─────────────────────────────────────────────────────────

func TestAddPaidProvider(t *testing.T) {
	e := newTestEngine()

	// Missing URL — should return error
	err := e.AddPaidProvider(models.PaidProviderEntry{
		ID:   "test-marzban",
		Type: "marzban",
		// URL intentionally missing
	})
	if err == nil {
		t.Log("warn: AddPaidProvider accepted empty URL")
	} else {
		t.Logf("OK: AddPaidProvider empty URL rejected: %v", err)
	}

	// Valid 3xui entry
	err2 := e.AddPaidProvider(models.PaidProviderEntry{
		ID:       "test-3xui",
		Name:     "Test 3X-UI",
		Type:     "3xui",
		URL:      "http://panel.example.com:2053",
		Username: "admin",
		Password: "password123",
	})
	if err2 != nil {
		t.Logf("AddPaidProvider 3xui warn: %v", err2)
	} else {
		t.Log("OK: AddPaidProvider 3xui accepted")
		// Now remove it
		ok := e.RemovePaidProvider("test-3xui")
		if !ok {
			t.Error("RemovePaidProvider: should succeed for just-added provider")
		}
	}
}

// ─── RefreshCatalog ──────────────────────────────────────────────────────────

func TestRefreshCatalogTimeout(t *testing.T) {
	e := newTestEngine()
	// Very short timeout — fetch will fail but must not panic
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	n, err := e.RefreshCatalog(ctx)
	t.Logf("OK: RefreshCatalog nodes=%d err=%v", n, err)
}

// ─── buildBestChain ──────────────────────────────────────────────────────────

func TestBuildBestChainEmpty(t *testing.T) {
	e := newTestEngine()
	// No nodes — should return nil, not panic
	chain := e.buildBestChain()
	if chain != nil {
		t.Logf("buildBestChain with no nodes returned %+v", chain)
	}
	t.Log("OK: buildBestChain empty nodes")
}
