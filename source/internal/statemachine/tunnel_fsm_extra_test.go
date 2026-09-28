package statemachine

import (
	"context"
	"errors"
	"testing"
	"time"
)

// CurrentProtocol — levels empty (direct struct construction)
func TestCurrentProtocol_EmptyLevels(t *testing.T) {
	f := &TunnelFSM{} // no levels
	lv, proto := f.CurrentProtocol()
	if lv != "none" || proto != "none" {
		t.Errorf("expected none/none for empty FSM, got %q/%q", lv, proto)
	}
	t.Log("OK: empty levels -> none/none")
}

// CurrentProtocol — proto index past end of Protocols slice
func TestCurrentProtocol_ProtoExhausted(t *testing.T) {
	f := &TunnelFSM{
		levels: []FallbackLevel{
			{Name: "L1", Protocols: []string{"vless"}},
		},
		currentLevel: 0,
		currentProto: 5, // beyond bounds
	}
	lv, proto := f.CurrentProtocol()
	if lv != "L1" {
		t.Errorf("expected level L1, got %q", lv)
	}
	if proto != "none" {
		t.Errorf("expected proto none when exhausted, got %q", proto)
	}
	t.Log("OK: exhausted proto index -> level/none")
}

// currentProtocolLocked path 1 — level overflow reached via Connect()
func TestCurrentProtocolLocked_LevelOverflow_ViaConnect(t *testing.T) {
	f := &TunnelFSM{
		levels:       []FallbackLevel{{Name: "L1", Protocols: []string{"vless"}, Timeout: time.Second}},
		currentLevel: 99, // past end
		minUptime:    0,
		backoffBase:  time.Millisecond,
		backoffMax:   time.Second,
	}
	// Connect calls currentProtocolLocked; proto will be "none"
	err := f.Connect(context.Background(), func(proto string) error {
		// proto == "none", just return nil
		return nil
	})
	_ = err
	t.Log("OK: currentProtocolLocked level-overflow path reached via Connect")
}

// currentProtocolLocked path 2 — proto overflow reached via Connect()
func TestCurrentProtocolLocked_ProtoOverflow_ViaConnect(t *testing.T) {
	f := &TunnelFSM{
		levels:       []FallbackLevel{{Name: "L1", Protocols: []string{"vless"}, Timeout: time.Second}},
		currentLevel: 0,
		currentProto: 99, // past end of Protocols
		minUptime:    0,
		backoffBase:  time.Millisecond,
		backoffMax:   time.Second,
	}
	err := f.Connect(context.Background(), func(proto string) error {
		return nil
	})
	_ = err
	t.Log("OK: currentProtocolLocked proto-overflow path reached via Connect")
}

// HandleFailure — too soon to switch (minUptime guard)
func TestHandleFailure_TooSoonToSwitch(t *testing.T) {
	f := New([]FallbackLevel{
		{Name: "L1", Protocols: []string{"vless", "trojan"}, Timeout: 10 * time.Second},
	}, 1*time.Hour)
	// Simulate a recent successful connect: set lastSwitch = now
	f.mu.Lock()
	f.lastSwitch = time.Now()
	f.mu.Unlock()

	// First failure while still within minUptime window
	f.HandleFailure(errors.New("timeout"))

	f.mu.RLock()
	state := f.state
	proto := f.currentProto
	f.mu.RUnlock()

	if state != StateConnecting {
		t.Errorf("expected StateConnecting (retry same), got %v", state)
	}
	if proto != 0 {
		t.Errorf("expected proto index 0 (no advance), got %d", proto)
	}
	t.Log("OK: too-soon failure retries same protocol")
}

// calcBackoff — zero count returns zero
func TestCalcBackoff_ZeroBackoffCount(t *testing.T) {
	f := New(nil, 0)
	d := f.Backoff()
	if d != 0 {
		t.Errorf("expected 0 backoff with no failures, got %v", d)
	}
	t.Log("OK: zero backoffCount -> 0 duration")
}

// calcBackoff — backoffCount large enough to exceed backoffMax (hits cap)
func TestCalcBackoff_ExceedsMax(t *testing.T) {
	f := New(nil, 0)
	// backoffBase=2s, backoffMax=120s; 2s * 2^6 = 128s > 120s -> capped
	f.mu.Lock()
	f.backoffCount = 7
	f.mu.Unlock()
	d := f.Backoff()
	if d > f.backoffMax {
		t.Errorf("backoff %v exceeded max %v", d, f.backoffMax)
	}
	if d < f.backoffMax-100*time.Millisecond {
		t.Errorf("backoff %v should be near max %v", d, f.backoffMax)
	}
	t.Log("OK: backoff capped at backoffMax:", d)
}

// log — OnLog callback is invoked when set
func TestLog_OnLogCallback(t *testing.T) {
	f := New(nil, 0)
	var received string
	f.OnLog = func(s string) { received = s }

	// Trigger Connect which calls f.log internally
	_ = f.Connect(nil, func(proto string) error {
		return nil
	})

	if received == "" {
		t.Error("OnLog callback was not called")
	}
	t.Log("OK: OnLog callback receives log message:", received)
}

// CurrentTimeout — level index out of bounds -> fallback 30s
func TestCurrentTimeout_LevelExhausted(t *testing.T) {
	f := &TunnelFSM{
		levels:       []FallbackLevel{{Name: "L1", Protocols: []string{"x"}, Timeout: 5 * time.Second}},
		currentLevel: 99, // way past end
	}
	d := f.CurrentTimeout()
	if d != 30*time.Second {
		t.Errorf("expected 30s fallback timeout, got %v", d)
	}
	t.Log("OK: exhausted level -> 30s fallback timeout")
}

// РЕГРЕССИЯ: HandleFailure паниковал при эскалации на уровень с пустым
// списком протоколов (Protocols[0] на пустом срезе). Кастомная иерархия
// теоретически может содержать такой уровень (например, временно отключённый
// уровень с protocols:[] в конфиге) — FSM не должен падать, а должен
// корректно сообщить "none" в лог и продолжить работу.
func TestHandleFailure_EscalateToLevelWithEmptyProtocols_NoPanic(t *testing.T) {
	custom := []FallbackLevel{
		{Name: "L1", Priority: 1, Protocols: []string{"p1"}, Timeout: time.Second, MaxRetries: 1},
		{Name: "L2-empty", Priority: 2, Protocols: []string{}, Timeout: time.Second, MaxRetries: 1},
	}
	f := New(custom, 0)
	f.Connect(context.Background(), func(proto string) error { return nil })

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("HandleFailure паникует при эскалации на пустой уровень: %v", r)
		}
	}()
	// Первый сбой исчерпывает единственный протокол L1 и переводит на L2-empty.
	f.HandleFailure(errors.New("fail1"))

	lv, proto := f.CurrentProtocol()
	if lv != "L2-empty" {
		t.Errorf("expected escalation to L2-empty, got level %q", lv)
	}
	if proto != "none" {
		t.Errorf("expected proto=none on empty-protocol level, got %q", proto)
	}
	t.Log("OK: escalation to empty-protocol level no longer panics")
}

// currentProtocolLocked — both edge cases via exported CurrentProtocol
func TestCurrentProtocolLocked_BothEdgeCases(t *testing.T) {
	// Edge case 1: no levels
	f1 := &TunnelFSM{}
	lv, proto := f1.CurrentProtocol()
	if lv != "none" || proto != "none" {
		t.Errorf("no levels: expected none/none, got %q/%q", lv, proto)
	}

	// Edge case 2: proto beyond bounds
	f2 := &TunnelFSM{
		levels:       []FallbackLevel{{Name: "X", Protocols: []string{"p1"}}},
		currentProto: 10,
	}
	lv2, proto2 := f2.CurrentProtocol()
	if lv2 != "X" || proto2 != "none" {
		t.Errorf("proto beyond bounds: expected X/none, got %q/%q", lv2, proto2)
	}
	t.Log("OK: currentProtocolLocked edge cases covered")
}

// HandleFailure — полный обход всей иерархии (все уровни и протоколы
// исчерпаны) должен вернуть FSM на level=0/proto=0 и увеличить backoffCount,
// а не остаться "застрявшим" за пределами последнего уровня.
func TestHandleFailure_FullWrapAround_ResetsToLevelZero(t *testing.T) {
	custom := []FallbackLevel{
		{Name: "L1", Protocols: []string{"p1"}, Timeout: time.Second, MaxRetries: 1},
		{Name: "L2", Protocols: []string{"p2"}, Timeout: time.Second, MaxRetries: 1},
	}
	f := New(custom, 0)
	f.Connect(context.Background(), func(proto string) error { return nil })

	// 1-й сбой: L1->L2 (эскалация уровня, единственный протокол в L1 исчерпан).
	f.HandleFailure(errors.New("fail1"))
	// 2-й сбой: L2 тоже единственный протокол исчерпан, уровни закончились ->
	// полный сброс на level=0/proto=0 с backoff.
	f.HandleFailure(errors.New("fail2"))

	if f.State() != StateReset {
		t.Errorf("after exhausting all levels, state = %s, want reset", f.State())
	}
	lv, proto := f.CurrentProtocol()
	if lv != "L1" || proto != "p1" {
		t.Errorf("after full wrap-around expected L1/p1, got %s/%s", lv, proto)
	}
	if f.Backoff() <= 0 {
		t.Error("expected positive backoff after full hierarchy exhaustion")
	}
}
