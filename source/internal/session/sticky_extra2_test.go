package session

import (
	"testing"
	"time"
)

// TrackConn — delta > 0 path (updates lastActivity)
func TestTrackConn_PositiveDelta_UpdatesActivity(t *testing.T) {
	s := NewStickySessionManager(DefaultSessionConfig())
	before := time.Now()
	time.Sleep(1 * time.Millisecond)
	s.TrackConn(1) // delta > 0 -> lastActivity = time.Now()
	s.mu.RLock()
	la := s.lastActivity
	s.mu.RUnlock()
	if !la.After(before) {
		t.Error("lastActivity should be updated when delta > 0")
	}
	t.Log("OK: TrackConn delta>0 updates lastActivity")
}

// TrackConn — negative delta clamps at 0
func TestTrackConn_NegativeClampsZero(t *testing.T) {
	s := NewStickySessionManager(DefaultSessionConfig())
	s.TrackConn(-100)
	s.mu.RLock()
	c := s.activeConns
	s.mu.RUnlock()
	if c != 0 {
		t.Errorf("expected activeConns=0, got %d", c)
	}
	t.Log("OK: negative delta clamped to 0")
}

// CanSwitch — rate limit path with positive retryIn
func TestCanSwitch_RateLimit(t *testing.T) {
	cfg := &SessionConfig{
		Policy:           PolicyFree,
		MaxSwitchRate:    2,
		GraceAfterSwitch: 0,
	}
	s := NewStickySessionManager(cfg)
	// Stuff switchHistory with MaxSwitchRate recent entries
	s.mu.Lock()
	for i := 0; i < cfg.MaxSwitchRate; i++ {
		s.switchHistory = append(s.switchHistory, time.Now())
	}
	s.mu.Unlock()

	dec := s.CanSwitch(false)
	if dec.Allow {
		t.Error("should be denied by rate limit")
	}
	if dec.RetryIn <= 0 {
		t.Error("RetryIn should be positive when rate-limited")
	}
	t.Log("OK: rate limit denial:", dec.Reason)
}

// CanSwitch — rate limit retryIn clamped to 0 (empty history, MaxSwitchRate=0)
func TestCanSwitch_RateLimit_RetryInZero(t *testing.T) {
	cfg := &SessionConfig{
		Policy:           PolicyFree,
		MaxSwitchRate:    0, // 0 >= 0 always triggers rate limit
		GraceAfterSwitch: 0,
	}
	s := NewStickySessionManager(cfg)
	// switchHistory empty -> oldest = zero time -> retryIn < 0 -> clamped to 0

	dec := s.CanSwitch(false)
	if dec.Allow {
		t.Error("should be denied by rate limit (MaxSwitchRate=0)")
	}
	if dec.RetryIn != 0 {
		t.Errorf("RetryIn should be 0 when clamped, got %v", dec.RetryIn)
	}
	t.Log("OK: rate limit retryIn clamped to 0")
}

// CanSwitch — grace period after switch
func TestCanSwitch_GracePeriod(t *testing.T) {
	cfg := &SessionConfig{
		Policy:           PolicyFree,
		MaxSwitchRate:    100,
		GraceAfterSwitch: 5 * time.Minute,
	}
	s := NewStickySessionManager(cfg)
	s.RecordSwitch() // sets lastSwitchAt = now

	dec := s.CanSwitch(false)
	if dec.Allow {
		t.Error("should be denied during grace period")
	}
	t.Log("OK: grace period denial:", dec.Reason)
}

// CanSwitch — PolicySticky with active connections + recent activity
func TestCanSwitch_Sticky_ActiveConns(t *testing.T) {
	cfg := &SessionConfig{
		Policy:           PolicySticky,
		ActivityTimeout:  5 * time.Minute,
		MaxSwitchRate:    100,
		GraceAfterSwitch: 0,
	}
	s := NewStickySessionManager(cfg)
	s.TrackConn(1) // activeConns=1, lastActivity=now

	dec := s.CanSwitch(false)
	if dec.Allow {
		t.Error("sticky: should deny with active connections and recent activity")
	}
	t.Log("OK: sticky + active conns denial:", dec.Reason)
}

// CanSwitch — PolicySticky with young session (< 2 min), no active conns
func TestCanSwitch_Sticky_YoungSession(t *testing.T) {
	cfg := &SessionConfig{
		Policy:           PolicySticky,
		ActivityTimeout:  0, // no active-conn guard
		MaxSwitchRate:    100,
		GraceAfterSwitch: 0,
	}
	s := NewStickySessionManager(cfg)
	s.OnConnected() // connectedAt = now, activeConns = 0

	dec := s.CanSwitch(false)
	if dec.Allow {
		t.Error("sticky: should deny for young session (< 2 min)")
	}
	t.Log("OK: sticky young session denial:", dec.Reason)
}

// CanSwitch — PolicySticky with old session, no active conns -> allow
func TestCanSwitch_Sticky_OldSession_Allow(t *testing.T) {
	cfg := &SessionConfig{
		Policy:           PolicySticky,
		ActivityTimeout:  0,
		MaxSwitchRate:    100,
		GraceAfterSwitch: 0,
	}
	s := NewStickySessionManager(cfg)
	s.mu.Lock()
	s.connectedAt = time.Now().Add(-10 * time.Minute) // old session (> 2 min)
	s.activeConns = 0
	s.mu.Unlock()

	dec := s.CanSwitch(false)
	if !dec.Allow {
		t.Errorf("sticky: old session with no active conns should allow, got: %s", dec.Reason)
	}
	t.Log("OK: sticky old session + no active conns -> allow")
}

// CanSwitch — PolicyTimed, session too short
func TestCanSwitch_Timed_TooShort(t *testing.T) {
	cfg := &SessionConfig{
		Policy:             PolicyTimed,
		MinSessionDuration: 10 * time.Minute,
		MaxSwitchRate:      100,
		GraceAfterSwitch:   0,
	}
	s := NewStickySessionManager(cfg)
	s.OnConnected() // connectedAt = now

	dec := s.CanSwitch(false)
	if dec.Allow {
		t.Error("timed: should deny before MinSessionDuration")
	}
	t.Log("OK: timed too-short denial:", dec.Reason)
}

// CanSwitch — PolicyTimed, session long enough -> allow
func TestCanSwitch_Timed_Expired(t *testing.T) {
	cfg := &SessionConfig{
		Policy:             PolicyTimed,
		MinSessionDuration: 1 * time.Millisecond,
		MaxSwitchRate:      100,
		GraceAfterSwitch:   0,
	}
	s := NewStickySessionManager(cfg)
	s.mu.Lock()
	s.connectedAt = time.Now().Add(-10 * time.Minute)
	s.mu.Unlock()

	dec := s.CanSwitch(false)
	if !dec.Allow {
		t.Errorf("timed: should allow after MinSessionDuration, got: %s", dec.Reason)
	}
	t.Log("OK: timed expired -> allow")
}

// CanSwitch — forced always allows
func TestCanSwitch_Forced_AlwaysAllows(t *testing.T) {
	s := NewStickySessionManager(DefaultSessionConfig())
	if dec := s.CanSwitch(true); !dec.Allow {
		t.Error("forced switch must always be allowed")
	}
	t.Log("OK: forced switch always allowed")
}

// CanSwitch — unknown policy -> default allow
func TestCanSwitch_UnknownPolicy_DefaultAllow(t *testing.T) {
	cfg := &SessionConfig{
		Policy:           StickyPolicy(99), // unknown policy
		MaxSwitchRate:    100,
		GraceAfterSwitch: 0,
	}
	s := NewStickySessionManager(cfg)
	dec := s.CanSwitch(false)
	if !dec.Allow {
		t.Errorf("unknown policy should fall through to default allow, got: %s", dec.Reason)
	}
	t.Log("OK: unknown policy -> default allow:", dec.Reason)
}
