package session

import (
	"testing"
	"time"
)

// SyncFromTraffic — единственный практический источник activeConns/lastActivity в
// продакшене (см. её комментарий: TrackConn/OnActivity рассчитаны на Go-уровневый
// net.Conn-перехват, которого для реального трафика APF не существует).

func TestSyncFromTraffic_SetsAbsoluteCount(t *testing.T) {
	s := NewStickySessionManager(DefaultSessionConfig())
	s.SyncFromTraffic(3, false)
	s.mu.RLock()
	c := s.activeConns
	s.mu.RUnlock()
	if c != 3 {
		t.Errorf("activeConns = %d, want 3", c)
	}

	// Абсолютное значение, не дельта — повторный вызов с меньшим числом должен УМЕНЬШИТЬ
	// счётчик, а не прибавить к нему (в отличие от TrackConn(delta)).
	s.SyncFromTraffic(1, false)
	s.mu.RLock()
	c = s.activeConns
	s.mu.RUnlock()
	if c != 1 {
		t.Errorf("activeConns после второго вызова = %d, want 1 (абсолютное значение, не дельта)", c)
	}
}

func TestSyncFromTraffic_NegativeClampsZero(t *testing.T) {
	s := NewStickySessionManager(DefaultSessionConfig())
	s.SyncFromTraffic(-5, false)
	s.mu.RLock()
	c := s.activeConns
	s.mu.RUnlock()
	if c != 0 {
		t.Errorf("activeConns = %d, want 0 (отрицательное значение зажато)", c)
	}
}

func TestSyncFromTraffic_MovingBytesUpdatesActivity(t *testing.T) {
	s := NewStickySessionManager(DefaultSessionConfig())
	before := time.Now()
	time.Sleep(1 * time.Millisecond)
	s.SyncFromTraffic(1, true)
	s.mu.RLock()
	la := s.lastActivity
	s.mu.RUnlock()
	if !la.After(before) {
		t.Error("lastActivity должна обновиться при movingBytes=true")
	}
}

func TestSyncFromTraffic_NoMovingBytes_DoesNotUpdateActivity(t *testing.T) {
	s := NewStickySessionManager(DefaultSessionConfig())
	s.mu.Lock()
	s.lastActivity = time.Now().Add(-time.Hour)
	fixed := s.lastActivity
	s.mu.Unlock()

	s.SyncFromTraffic(1, false)

	s.mu.RLock()
	la := s.lastActivity
	s.mu.RUnlock()
	if !la.Equal(fixed) {
		t.Error("lastActivity не должна меняться при movingBytes=false (открытое, но простаивающее соединение)")
	}
}

// Интеграционный сценарий: SyncFromTraffic реально управляет CanSwitch() под
// PolicySticky — тот же контракт, что TestCanSwitch_Sticky_ActiveConns проверяет для
// (мёртвого в проде) TrackConn, но через реальный путь.
func TestSyncFromTraffic_DrivesCanSwitch_Sticky(t *testing.T) {
	cfg := &SessionConfig{
		Policy:           PolicySticky,
		ActivityTimeout:  5 * time.Minute,
		MaxSwitchRate:    100,
		GraceAfterSwitch: 0,
	}
	s := NewStickySessionManager(cfg)
	s.SyncFromTraffic(1, true)

	dec := s.CanSwitch(false)
	if dec.Allow {
		t.Error("sticky: должен запретить переключение при активном соединении из SyncFromTraffic")
	}

	// Опрос сообщает, что соединений больше нет — переключение снова разрешено (после
	// того как истечёт защита молодой сессии/ActivityTimeout, здесь оба обнулены выше).
	s.mu.Lock()
	s.connectedAt = time.Now().Add(-10 * time.Minute)
	s.lastActivity = time.Now().Add(-10 * time.Minute)
	s.mu.Unlock()
	s.SyncFromTraffic(0, false)

	dec = s.CanSwitch(false)
	if !dec.Allow {
		t.Errorf("sticky: должен разрешить переключение когда SyncFromTraffic сообщил 0 соединений, получено: %s", dec.Reason)
	}
}
