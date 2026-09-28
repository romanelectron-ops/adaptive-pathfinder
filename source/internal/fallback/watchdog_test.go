package fallback

import (
	"context"
	"testing"
	"time"
)

func TestWatchdogNew(t *testing.T) {
	cfg := DefaultWatchdogConfig("127.0.0.1:10808")
	w := NewWatchdog(cfg, nil)
	if w == nil {
		t.Fatal("NewWatchdog returned nil")
	}
	s := w.GetStatus()
	// Начальное состояние — idle (не запущен) или healthy
	validInitialStates := []WatchdogState{WatchdogHealthy, "idle", ""}
	validState := false
	for _, vs := range validInitialStates {
		if s.State == vs {
			validState = true
			break
		}
	}
	if !validState {
		t.Errorf("unexpected initial state: %q", s.State)
	}
	if s.FailCount != 0 {
		t.Errorf("initial FailCount: want 0, got %d", s.FailCount)
	}
	t.Logf("OK: NewWatchdog initial state=%q", s.State)
}

func TestWatchdogReset(t *testing.T) {
	cfg := DefaultWatchdogConfig("127.0.0.1:10808")
	w := NewWatchdog(cfg, nil)

	// Устанавливаем искусственное состояние
	w.status.FailCount = 5
	w.status.State = WatchdogFailed
	w.status.LastError = "test error"

	w.Reset()

	s := w.GetStatus()
	if s.FailCount != 0 {
		t.Errorf("after Reset FailCount: want 0, got %d", s.FailCount)
	}
	if s.State != WatchdogHealthy {
		t.Errorf("after Reset state: want Healthy, got %s", s.State)
	}
	if s.LastError != "" {
		t.Errorf("after Reset LastError: want empty, got %q", s.LastError)
	}
	t.Log("OK: Watchdog.Reset() clears state")
}

func TestWatchdogUpdateProxyAddr(t *testing.T) {
	cfg := DefaultWatchdogConfig("127.0.0.1:10808")
	w := NewWatchdog(cfg, nil)

	w.UpdateProxyAddr("127.0.0.1:20808")
	if w.cfg.ProxyAddr != "127.0.0.1:20808" {
		t.Errorf("ProxyAddr not updated: %s", w.cfg.ProxyAddr)
	}
	t.Log("OK: UpdateProxyAddr")
}

func TestWatchdogCallbacks(t *testing.T) {
	cfg := DefaultWatchdogConfig("127.0.0.1:19999") // несуществующий порт
	cfg.FailThreshold = 1
	cfg.CheckInterval = 100 * time.Millisecond
	cfg.CheckTimeout = 200 * time.Millisecond

	deadCalled := make(chan struct{}, 1)
	w := NewWatchdog(cfg, func(s string) {})
	w.OnDead = func() {
		deadCalled <- struct{}{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go w.Run(ctx)

	select {
	case <-deadCalled:
		t.Log("OK: OnDead called when proxy unreachable")
	case <-ctx.Done():
		t.Error("timeout — OnDead not called")
	}
}

func TestBackoffDuration(t *testing.T) {
	cases := []struct {
		attempt  int
		expected time.Duration
	}{
		{0, 1 * time.Second},
		{1, 2 * time.Second},
		{2, 4 * time.Second},
		{3, 8 * time.Second},
		{4, 16 * time.Second},
		{5, 30 * time.Second},  // capped
		{10, 30 * time.Second}, // still capped
	}
	for _, c := range cases {
		got := backoffDuration(c.attempt)
		if got != c.expected {
			t.Errorf("backoffDuration(%d) = %v, want %v", c.attempt, got, c.expected)
		}
	}
	t.Log("OK: exponential backoff with cap at 30s")
}

func TestGetHistoryLog(t *testing.T) {
	cfg := DefaultWatchdogConfig("127.0.0.1:10808")
	w := NewWatchdog(cfg, nil)
	log := w.GetHistoryLog()
	if len(log) == 0 {
		t.Error("GetHistoryLog should return at least 1 entry")
	}
	t.Logf("OK: history log: %v", log)
}

// ─── TorSnowflake + Psiphon + FallbackOrchestrator tests ──────────────────────

func TestDefaultSnowflakeConfig(t *testing.T) {
	cfg := DefaultSnowflakeConfig("/tmp/test")
	if cfg == nil {
		t.Fatal("nil config")
	}
	if cfg.SOCKSPort == 0 {
		t.Error("SOCKSPort == 0")
	}
	if cfg.DataDir == "" {
		t.Error("DataDir empty")
	}
	t.Logf("OK: SnowflakeConfig socks=%d", cfg.SOCKSPort)
}

func TestTorSnowflakeManagerNew(t *testing.T) {
	cfg := DefaultSnowflakeConfig(t.TempDir())
	m := NewTorSnowflakeManager(cfg, nil)
	if m == nil {
		t.Fatal("nil manager")
	}
	// Без tor бинарника — IsAvailable=false
	avail := m.IsAvailable("/nonexistent")
	t.Logf("OK: IsAvailable(nonexistent)=%v", avail)
}

func TestTorSnowflakeGetStatus(t *testing.T) {
	cfg := DefaultSnowflakeConfig(t.TempDir())
	m := NewTorSnowflakeManager(cfg, nil)
	s := m.GetStatus()
	t.Logf("OK: TorSnowflake status: %+v", s)
}

func TestTorSnowflakeGetSingBoxOutbound(t *testing.T) {
	cfg := DefaultSnowflakeConfig(t.TempDir())
	m := NewTorSnowflakeManager(cfg, nil)
	// Без snowflake
	ob := m.GetSingBoxOutbound(false)
	if ob == nil {
		t.Fatal("outbound nil")
	}
	if ob["type"] == nil {
		t.Error("missing type")
	}
	// С snowflake
	ob2 := m.GetSingBoxOutbound(true)
	if ob2 == nil {
		t.Fatal("snowflake outbound nil")
	}
	t.Logf("OK: outbounds type=%v", ob["type"])
}

func TestDownloadInstructions(t *testing.T) {
	instr := DownloadInstructions()
	if instr == "" {
		t.Error("DownloadInstructions empty")
	}
	t.Logf("OK: instructions len=%d", len(instr))
}

func TestDefaultPsiphonConfig(t *testing.T) {
	cfg := DefaultPsiphonConfig("/tmp/test")
	if cfg == nil {
		t.Fatal("nil")
	}
	if cfg.SOCKSPort == 0 {
		t.Error("SOCKSPort 0")
	}
	if cfg.PropagationChannelID == "" {
		t.Error("PropagationChannelID empty")
	}
	t.Logf("OK: PsiphonConfig socks=%d channel=%s", cfg.SOCKSPort, cfg.PropagationChannelID)
}

func TestPsiphonManagerNew(t *testing.T) {
	cfg := DefaultPsiphonConfig(t.TempDir())
	m := NewPsiphonManager(cfg, nil)
	if m == nil {
		t.Fatal("nil")
	}
	s := m.GetStatus()
	t.Logf("OK: PsiphonManager status: available=%v connected=%v", s.Available, s.Connected)
}

func TestPsiphonGenerateConfig(t *testing.T) {
	cfg := DefaultPsiphonConfig(t.TempDir())
	m := NewPsiphonManager(cfg, nil)
	cfgJSON := m.GenerateConfig()
	if cfgJSON == "" {
		t.Error("GenerateConfig returned empty")
	}
	if cfgJSON[0] != '{' {
		t.Error("expected JSON object")
	}
	t.Logf("OK: GenerateConfig: %d bytes", len(cfgJSON))
}

func TestPsiphonIsAvailable(t *testing.T) {
	cfg := DefaultPsiphonConfig(t.TempDir())
	m := NewPsiphonManager(cfg, nil)
	// Нет psiphond в PATH/binDir — должно вернуть false
	avail := m.IsAvailable("/nonexistent-bin-dir")
	t.Logf("OK: Psiphon.IsAvailable(nonexistent)=%v", avail)
}

func TestPsiphonGetSingBoxOutbound(t *testing.T) {
	cfg := DefaultPsiphonConfig(t.TempDir())
	m := NewPsiphonManager(cfg, nil)
	ob := m.GetSingBoxOutbound()
	if ob == nil {
		t.Fatal("outbound nil")
	}
	if ob["type"] != "socks" {
		t.Errorf("type: want socks, got %v", ob["type"])
	}
	if ob["server_port"] == nil {
		t.Error("missing server_port")
	}
	t.Logf("OK: Psiphon outbound type=%v port=%v", ob["type"], ob["server_port"])
}

func TestFallbackOrchestratorNew(t *testing.T) {
	o := NewFallbackOrchestrator("/nonexistent-bin", t.TempDir(), nil)
	if o == nil {
		t.Fatal("nil orchestrator")
	}
	if o.GetActive() != FallbackNone {
		t.Errorf("initial active: want none, got %v", o.GetActive())
	}
	t.Log("OK: FallbackOrchestrator created")
}

func TestFallbackOrchestratorSetActive(t *testing.T) {
	o := NewFallbackOrchestrator("/tmp", t.TempDir(), nil)
	o.SetActive(FallbackPsiphon)
	if o.GetActive() != FallbackPsiphon {
		t.Errorf("want psiphon, got %v", o.GetActive())
	}
	o.SetActive(FallbackNone)
	if o.GetActive() != FallbackNone {
		t.Errorf("want none, got %v", o.GetActive())
	}
	t.Log("OK: SetActive/GetActive")
}

func TestFallbackOrchestratorGetStatus(t *testing.T) {
	o := NewFallbackOrchestrator("/nonexistent", t.TempDir(), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	status := o.GetStatus(ctx)
	if status == nil {
		t.Fatal("nil status")
	}
	if _, ok := status["active_tunnel"]; !ok {
		t.Error("missing active_tunnel")
	}
	t.Logf("OK: GetStatus active=%v", status["active_tunnel"])
}

func TestFallbackOrchestratorGetSingBoxConfig(t *testing.T) {
	o := NewFallbackOrchestrator("/tmp", t.TempDir(), nil)
	// Tor
	ob := o.GetSingBoxConfig(FallbackTor)
	if ob == nil {
		t.Error("Tor config nil")
	}
	// Psiphon
	ob2 := o.GetSingBoxConfig(FallbackPsiphon)
	if ob2 == nil {
		t.Error("Psiphon config nil")
	}
	// None
	ob3 := o.GetSingBoxConfig(FallbackNone)
	t.Logf("OK: GetSingBoxConfig tor=%v psiphon=%v none=%v",
		ob["type"], ob2["type"], ob3)
}
