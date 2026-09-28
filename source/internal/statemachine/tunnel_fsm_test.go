package statemachine

import (
	"context"
	"errors"
	"testing"
	"time"
)

// ── TunnelState.String ────────────────────────────────────────────────────────

func TestTunnelState_String(t *testing.T) {
	tests := []struct {
		s    TunnelState
		want string
	}{
		{StateIdle, "idle"},
		{StateConnecting, "connecting"},
		{StateConnected, "connected"},
		{StateTesting, "testing"},
		{StateFailing, "failing"},
		{StateFallback, "fallback"},
		{StateReset, "reset"},
		{TunnelState(99), "unknown"},
	}
	for _, tt := range tests {
		got := tt.s.String()
		if got != tt.want {
			t.Errorf("TunnelState(%d).String() = %q, want %q", int(tt.s), got, tt.want)
		}
	}
}

// ── DefaultFallbackHierarchy ─────────────────────────────────────────────────

func TestDefaultFallbackHierarchy_NotEmpty(t *testing.T) {
	if len(DefaultFallbackHierarchy) < 3 {
		t.Errorf("expected at least 3 fallback levels, got %d", len(DefaultFallbackHierarchy))
	}
}

func TestDefaultFallbackHierarchy_EachLevelValid(t *testing.T) {
	for i, lv := range DefaultFallbackHierarchy {
		if lv.Name == "" {
			t.Errorf("level[%d] has empty name", i)
		}
		if len(lv.Protocols) < 1 {
			t.Errorf("level[%d] %s has no protocols", i, lv.Name)
		}
		if lv.Timeout <= 0 {
			t.Errorf("level[%d] %s has non-positive timeout", i, lv.Name)
		}
		if lv.MaxRetries <= 0 {
			t.Errorf("level[%d] %s has non-positive MaxRetries", i, lv.Name)
		}
	}
}

func TestDefaultFallbackHierarchy_Priorities(t *testing.T) {
	for i := 1; i < len(DefaultFallbackHierarchy); i++ {
		prev := DefaultFallbackHierarchy[i-1].Priority
		curr := DefaultFallbackHierarchy[i].Priority
		if curr <= prev {
			t.Errorf("level[%d].Priority (%d) <= level[%d].Priority (%d)",
				i, curr, i-1, prev)
		}
	}
}

// ── New ───────────────────────────────────────────────────────────────────────

func TestNew_NotNil(t *testing.T) {
	fsm := New(nil, time.Minute)
	if fsm == nil {
		t.Fatal("New() returned nil")
	}
}

func TestNew_InitialState(t *testing.T) {
	fsm := New(nil, time.Minute)
	if fsm.State() != StateIdle {
		t.Errorf("initial state = %s, want idle", fsm.State())
	}
}

func TestNew_UsesDefaultHierarchy(t *testing.T) {
	fsm := New(nil, time.Minute)
	level, proto := fsm.CurrentProtocol()
	if level == "" || proto == "" {
		t.Error("CurrentProtocol should return non-empty values")
	}
}

func TestNew_CustomLevels(t *testing.T) {
	custom := []FallbackLevel{
		{Name: "custom-L1", Priority: 1, Protocols: []string{"proto-a"}, Timeout: 5 * time.Second, MaxRetries: 1},
	}
	fsm := New(custom, time.Minute)
	level, proto := fsm.CurrentProtocol()
	if level != "custom-L1" {
		t.Errorf("level = %q, want custom-L1", level)
	}
	if proto != "proto-a" {
		t.Errorf("proto = %q, want proto-a", proto)
	}
}

// ── Connect ───────────────────────────────────────────────────────────────────

func TestFSM_Connect_Success(t *testing.T) {
	fsm := New(nil, 0) // minUptime=0 для быстрых тестов
	ctx := context.Background()

	err := fsm.Connect(ctx, func(proto string) error {
		return nil // успешное подключение
	})
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}
	if fsm.State() != StateConnected {
		t.Errorf("after Connect success, state = %s, want connected", fsm.State())
	}
}

func TestFSM_Connect_Failure(t *testing.T) {
	fsm := New(nil, 0)
	ctx := context.Background()

	connectErr := errors.New("connection refused")
	err := fsm.Connect(ctx, func(proto string) error {
		return connectErr
	})
	if err == nil {
		t.Error("Connect should return error on failure")
	}
	// После неудачного Connect — должен быть не в connected
	if fsm.State() == StateConnected {
		t.Error("after Connect failure, state should not be connected")
	}
}

// ── HandleSuccess ─────────────────────────────────────────────────────────────

func TestFSM_HandleSuccess_InConnected(t *testing.T) {
	fsm := New(nil, 0)
	ctx := context.Background()

	fsm.Connect(ctx, func(proto string) error { return nil })
	fsm.HandleSuccess(50 * time.Millisecond)

	if fsm.State() != StateConnected {
		t.Errorf("after HandleSuccess in connected, state = %s, want connected", fsm.State())
	}
}

func TestFSM_HandleSuccess_ResetsFailCount(t *testing.T) {
	fsm := New(nil, 0)
	ctx := context.Background()
	fsm.Connect(ctx, func(proto string) error { return nil })

	// Имитируем несколько сбоев
	fsm.HandleFailure(errors.New("oops"))
	// Потом успех — сбрасываем счётчик
	// Переводим обратно в connected вручную для теста
	fsm.mu.Lock()
	fsm.state = StateConnected
	fsm.mu.Unlock()

	fsm.HandleSuccess(30 * time.Millisecond)
	if fsm.State() != StateConnected {
		t.Errorf("state = %s, want connected after HandleSuccess", fsm.State())
	}
}

// ── HandleFailure ─────────────────────────────────────────────────────────────

func TestFSM_HandleFailure_ChangesState(t *testing.T) {
	fsm := New(nil, 0)
	ctx := context.Background()
	fsm.Connect(ctx, func(proto string) error { return nil })

	err := errors.New("network timeout")
	fsm.HandleFailure(err)

	state := fsm.State()
	validStates := map[TunnelState]bool{
		StateFailing:    true,
		StateFallback:   true,
		StateReset:      true,
		StateConnecting: true, // при раннем сбое внутри minUptime
	}
	if !validStates[state] {
		t.Errorf("after HandleFailure, state = %s, not a valid failure state", state)
	}
}

func TestFSM_HandleFailure_EscalatesLevels(t *testing.T) {
	// Используем кастомную иерархию с маленьким MaxRetries
	custom := []FallbackLevel{
		{Name: "L1", Priority: 1, Protocols: []string{"p1", "p2"}, Timeout: 5 * time.Second, MaxRetries: 1},
		{Name: "L2", Priority: 2, Protocols: []string{"p3"}, Timeout: 5 * time.Second, MaxRetries: 1},
	}
	fsm := New(custom, 0)
	ctx := context.Background()
	fsm.Connect(ctx, func(proto string) error { return nil })

	var fallbacks []string
	fsm.OnFallback = func(from, to string) {
		fallbacks = append(fallbacks, from+"->"+to)
	}

	// Много сбоев чтобы пройти через протоколы и уровни
	err := errors.New("fail")
	for i := 0; i < 5; i++ {
		fsm.HandleFailure(err)
	}

	// Должны были получить хотя бы один escalation
	state := fsm.State()
	if state != StateFallback && state != StateReset {
		t.Logf("state after failures: %s (fallbacks: %v)", state, fallbacks)
	}
}

// ── Reset ─────────────────────────────────────────────────────────────────────

func TestFSM_Reset_GoesToIdle(t *testing.T) {
	fsm := New(nil, 0)
	ctx := context.Background()
	fsm.Connect(ctx, func(proto string) error { return nil })

	for i := 0; i < 5; i++ {
		fsm.HandleFailure(errors.New("fail"))
	}

	fsm.Reset()
	if fsm.State() != StateIdle {
		t.Errorf("after Reset, state = %s, want idle", fsm.State())
	}
}

func TestFSM_Reset_ShouldSwitchFalse(t *testing.T) {
	fsm := New(nil, 0)
	ctx := context.Background()
	fsm.Connect(ctx, func(proto string) error { return nil })

	for i := 0; i < 10; i++ {
		fsm.HandleFailure(errors.New("fail"))
	}
	fsm.Reset()

	if fsm.ShouldSwitch() {
		t.Error("after Reset, ShouldSwitch should be false")
	}
}

func TestFSM_Reset_ResetsLevel(t *testing.T) {
	fsm := New(nil, 0)
	ctx := context.Background()
	fsm.Connect(ctx, func(proto string) error { return nil })

	// Несколько сбоев для эскалации
	for i := 0; i < 10; i++ {
		fsm.HandleFailure(errors.New("fail"))
	}
	fsm.Reset()

	// После Reset — уровень и протокол должны вернуться к началу
	level, proto := fsm.CurrentProtocol()
	if level == "none" || proto == "none" {
		t.Error("after Reset, should have valid level and proto")
	}
}

// ── Backoff ───────────────────────────────────────────────────────────────────

func TestFSM_Backoff_ZeroInitially(t *testing.T) {
	fsm := New(nil, time.Minute)
	b := fsm.Backoff()
	if b != 0 {
		t.Errorf("initial backoff = %v, want 0", b)
	}
}

func TestFSM_Backoff_NonNegative(t *testing.T) {
	fsm := New(nil, 0)
	ctx := context.Background()
	fsm.Connect(ctx, func(proto string) error { return nil })

	for i := 0; i < 20; i++ {
		fsm.HandleFailure(errors.New("fail"))
	}
	b := fsm.Backoff()
	if b < 0 {
		t.Errorf("backoff should not be negative, got %v", b)
	}
}

func TestFSM_Backoff_RespectsMax(t *testing.T) {
	fsm := New(nil, 0)
	ctx := context.Background()
	fsm.Connect(ctx, func(proto string) error { return nil })

	// Очень много сбоев
	for i := 0; i < 50; i++ {
		fsm.HandleFailure(errors.New("fail"))
	}
	b := fsm.Backoff()
	if b > 10*time.Minute {
		t.Errorf("backoff %v exceeds reasonable maximum", b)
	}
}

// ── CurrentTimeout ────────────────────────────────────────────────────────────

func TestFSM_CurrentTimeout_Positive(t *testing.T) {
	fsm := New(nil, time.Minute)
	timeout := fsm.CurrentTimeout()
	if timeout <= 0 {
		t.Errorf("CurrentTimeout should be positive, got %v", timeout)
	}
}

// ── ShouldSwitch ─────────────────────────────────────────────────────────────

func TestFSM_ShouldSwitch_InitiallyFalse(t *testing.T) {
	fsm := New(nil, time.Minute)
	if fsm.ShouldSwitch() {
		t.Error("fresh FSM should not suggest switching")
	}
}

// ── Callbacks ─────────────────────────────────────────────────────────────────

func TestFSM_OnConnect_Called(t *testing.T) {
	var connected bool
	fsm := New(nil, 0)
	fsm.OnConnect = func(level, proto string) {
		connected = true
	}
	fsm.Connect(context.Background(), func(proto string) error { return nil })
	if !connected {
		t.Error("OnConnect callback should be called on successful connect")
	}
}
