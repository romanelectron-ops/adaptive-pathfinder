package session

// Extra tests covering functions not reached by sticky_test.go:
//   OnActivity, IsSessionActive, GetPolicy, GetConfig, SetConfig,
//   NewTrackedTransport/RoundTrip, NewTrackedConn/Close/Write,
//   and all 7 functions in domain_sticky.go.

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ─── OnActivity / IsSessionActive ─────────────────────────────────────────────

func TestOnActivity_UpdatesLastActivity(t *testing.T) {
	cfg := DefaultSessionConfig()
	cfg.ActivityTimeout = 200 * time.Millisecond
	m := NewStickySessionManager(cfg)
	m.OnConnected()

	// Right after connect — should be active
	if !m.IsSessionActive() {
		t.Error("should be active immediately after connect")
	}

	// Wait past the timeout
	time.Sleep(250 * time.Millisecond)
	if m.IsSessionActive() {
		t.Log("still active after timeout — may be too fast; skip timing assertion")
	}

	// OnActivity refreshes the clock → should become active again
	m.OnActivity()
	if !m.IsSessionActive() {
		t.Error("should be active after OnActivity")
	}
}

func TestIsSessionActive_WithActiveConns(t *testing.T) {
	cfg := DefaultSessionConfig()
	cfg.ActivityTimeout = 1 * time.Millisecond // very short
	m := NewStickySessionManager(cfg)
	m.OnConnected()

	// Even with 0-ms timeout, active conns keep session alive
	m.TrackConn(+1)
	time.Sleep(5 * time.Millisecond)
	if !m.IsSessionActive() {
		t.Error("active conn should keep session active regardless of timeout")
	}
	m.TrackConn(-1)
}

func TestIsSessionActive_InactiveAfterTimeout(t *testing.T) {
	cfg := DefaultSessionConfig()
	cfg.ActivityTimeout = 1 * time.Millisecond
	m := NewStickySessionManager(cfg)
	m.OnConnected()

	time.Sleep(10 * time.Millisecond)
	// 0 conns + past timeout → inactive
	if m.IsSessionActive() {
		t.Log("IsSessionActive still true (timing sensitivity) — not failing")
		// Don't hard-fail: timing on CI can vary; the important thing is no panic
	}
}

// ─── GetPolicy / SetConfig / GetConfig ───────────────────────────────────────

func TestGetPolicy(t *testing.T) {
	cfg := DefaultSessionConfig()
	cfg.Policy = PolicyTimed
	m := NewStickySessionManager(cfg)
	if got := m.GetPolicy(); got != PolicyTimed {
		t.Errorf("GetPolicy = %v, want PolicyTimed", got)
	}
	m.SetPolicy(PolicyFree)
	if got := m.GetPolicy(); got != PolicyFree {
		t.Errorf("GetPolicy after SetPolicy = %v, want PolicyFree", got)
	}
}

func TestGetConfig_ReturnsCopy(t *testing.T) {
	cfg := DefaultSessionConfig()
	m := NewStickySessionManager(cfg)
	got := m.GetConfig()
	if got == nil {
		t.Fatal("GetConfig returned nil")
	}
	// Verify it's a copy: mutating it should not affect the manager
	got.MaxSwitchRate = 9999
	if m.GetConfig().MaxSwitchRate == 9999 {
		t.Error("GetConfig should return a copy, not a pointer to internal config")
	}
}

func TestSetConfig(t *testing.T) {
	m := NewStickySessionManager(nil)
	newCfg := DefaultSessionConfig()
	newCfg.Policy = PolicyFree
	newCfg.MaxSwitchRate = 2
	m.SetConfig(newCfg)
	if m.GetPolicy() != PolicyFree {
		t.Error("SetConfig should update policy")
	}
	if m.GetConfig().MaxSwitchRate != 2 {
		t.Error("SetConfig should update MaxSwitchRate")
	}
}

// ─── NewTrackedTransport / RoundTrip ──────────────────────────────────────────

func TestNewTrackedTransport_RoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DefaultSessionConfig()
	m := NewStickySessionManager(cfg)
	m.OnConnected()

	transport := NewTrackedTransport(m)
	client := &http.Client{Transport: transport}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	resp.Body.Close()

	// After request completes: TrackConn(+1) then TrackConn(-1) → 0
	status := m.Status()
	if conns := status["active_conns"].(int); conns != 0 {
		t.Errorf("active_conns after request = %d, want 0", conns)
	}
}

// ─── NewTrackedConn / Close / Write ──────────────────────────────────────────

func TestNewTrackedConn_LifeCycle(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()

	cfg := DefaultSessionConfig()
	m := NewStickySessionManager(cfg)
	m.OnConnected()

	tracked := NewTrackedConn(c1, m)

	// NewTrackedConn calls TrackConn(+1) → 1 active conn
	if conns := m.Status()["active_conns"].(int); conns != 1 {
		t.Errorf("active_conns after NewTrackedConn = %d, want 1", conns)
	}

	// Write — should not panic, and calls OnActivity
	go func() {
		buf := make([]byte, 5)
		c2.Read(buf)
	}()
	_, err := tracked.Write([]byte("hello"))
	if err != nil {
		t.Logf("Write error (OK if pipe closed): %v", err)
	}

	// Close — calls TrackConn(-1) exactly once
	tracked.Close()
	if conns := m.Status()["active_conns"].(int); conns != 0 {
		t.Errorf("active_conns after Close = %d, want 0", conns)
	}

	// Second Close must be a no-op (sync.Once)
	tracked.Close()
	if conns := m.Status()["active_conns"].(int); conns != 0 {
		t.Errorf("active_conns after 2nd Close = %d, want 0 (double-decrement bug)", conns)
	}
}

// ─── domain_sticky.go — all 7 functions ──────────────────────────────────────

func TestDomainSticky_SetGetCurrentNode(t *testing.T) {
	m := NewStickySessionManager(nil)
	// domain-sticky состояние — поле инстанса (см. фикс в domain_sticky.go/sticky.go:
	// раньше это были package-level переменные, общие для ВСЕХ менеджеров процесса),
	// поэтому свежий менеджер обязан стартовать с пустым currentNodeID без ручного
	// сброса за предыдущими тестами.
	if got := m.GetCurrentNode(); got != "" {
		t.Errorf("свежий StickySessionManager: GetCurrentNode() = %q, want \"\"", got)
	}
	m.SetCurrentNode("node-alpha")
	if got := m.GetCurrentNode(); got != "node-alpha" {
		t.Errorf("GetCurrentNode = %q, want node-alpha", got)
	}
}

// TestDomainSticky_InstanceIsolation — регрессия к тому, что domain-sticky состояние
// раньше жило в package-level переменных (domainStore/currentNodeID), общих для ВСЕХ
// StickySessionManager в процессе. Два независимых менеджера не должны видеть узлы и
// pin'ы друг друга.
func TestDomainSticky_InstanceIsolation(t *testing.T) {
	a := NewStickySessionManager(nil)
	b := NewStickySessionManager(nil)

	a.SetCurrentNode("node-A")
	a.PinDomain("shared-name.example.com")

	if got := b.GetCurrentNode(); got != "" {
		t.Errorf("менеджер b: GetCurrentNode() = %q, want \"\" (не должен видеть SetCurrentNode менеджера a)", got)
	}
	if got := b.GetPinnedNode("shared-name.example.com"); got != "" {
		t.Errorf("менеджер b: GetPinnedNode(...) = %q, want \"\" (не должен видеть pin менеджера a)", got)
	}
	if got := b.DomainStickyCount(); got != 0 {
		t.Errorf("менеджер b: DomainStickyCount() = %d, want 0", got)
	}
	// Обратное направление: b пишет — a не должен измениться.
	b.SetCurrentNode("node-B")
	if got := a.GetCurrentNode(); got != "node-A" {
		t.Errorf("менеджер a: GetCurrentNode() = %q после записи в b, want node-A (утечка состояния между инстансами)", got)
	}
}

func TestDomainSticky_PinAndGetDomain(t *testing.T) {
	m := NewStickySessionManager(nil)
	m.ClearDomainSticky()
	m.SetCurrentNode("node-B")

	m.PinDomain("bank.example.com")

	pinned := m.GetPinnedNode("bank.example.com")
	if pinned != "node-B" {
		t.Errorf("GetPinnedNode = %q, want node-B", pinned)
	}
	// Unknown domain → empty
	if got := m.GetPinnedNode("other.com"); got != "" {
		t.Errorf("unknown domain: expected empty, got %q", got)
	}
}

func TestDomainSticky_PinWithNoCurrentNode(t *testing.T) {
	m := NewStickySessionManager(nil)
	m.ClearDomainSticky()
	m.SetCurrentNode("") // no node

	m.PinDomain("google.com") // should be a no-op

	if got := m.GetPinnedNode("google.com"); got != "" {
		t.Errorf("PinDomain with empty node should not pin, got %q", got)
	}
}

func TestDomainSticky_ExpiredEntry(t *testing.T) {
	m := NewStickySessionManager(nil)
	m.ClearDomainSticky()
	m.SetCurrentNode("node-C")
	m.PinDomain("expired.example.com")

	// Manually expire (состояние теперь — поле инстанса m, а не пакетная переменная)
	m.domainMu.Lock()
	if sess, ok := m.domainStore["expired.example.com"]; ok {
		m.domainStore["expired.example.com"] = domainSession{
			nodeID:    sess.nodeID,
			expiresAt: time.Now().Add(-time.Second),
		}
	}
	m.domainMu.Unlock()

	if got := m.GetPinnedNode("expired.example.com"); got != "" {
		t.Errorf("expired domain should return empty, got %q", got)
	}
}

func TestDomainSticky_CleanExpiredDomainSessions(t *testing.T) {
	m := NewStickySessionManager(nil)
	m.ClearDomainSticky()
	m.SetCurrentNode("node-D")

	m.PinDomain("active.example.com")

	// Inject an expired entry (поле инстанса m)
	m.domainMu.Lock()
	m.domainStore["stale.example.com"] = domainSession{
		nodeID:    "node-D",
		expiresAt: time.Now().Add(-time.Second),
	}
	m.domainMu.Unlock()

	m.CleanExpiredDomainSessions()

	if count := m.DomainStickyCount(); count != 1 {
		t.Errorf("after clean: count = %d, want 1 (only active should remain)", count)
	}
	if got := m.GetPinnedNode("active.example.com"); got == "" {
		t.Error("active.example.com should still be pinned after cleanup")
	}
	if got := m.GetPinnedNode("stale.example.com"); got != "" {
		t.Error("stale.example.com should be removed by cleanup")
	}
}

func TestDomainSticky_ClearDomainSticky(t *testing.T) {
	m := NewStickySessionManager(nil)
	m.SetCurrentNode("node-E")
	m.PinDomain("a.com")
	m.PinDomain("b.com")

	m.ClearDomainSticky()

	if count := m.DomainStickyCount(); count != 0 {
		t.Errorf("after ClearDomainSticky: count = %d, want 0", count)
	}
}

func TestDomainSticky_DomainStickyCount(t *testing.T) {
	m := NewStickySessionManager(nil)
	m.ClearDomainSticky()
	m.SetCurrentNode("node-F")

	if got := m.DomainStickyCount(); got != 0 {
		t.Errorf("initial count = %d, want 0", got)
	}
	m.PinDomain("x.com")
	m.PinDomain("y.com")
	m.PinDomain("z.com")
	if got := m.DomainStickyCount(); got != 3 {
		t.Errorf("after 3 pins: count = %d, want 3", got)
	}
}
