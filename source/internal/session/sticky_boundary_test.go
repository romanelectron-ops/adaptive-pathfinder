package session

// sticky_boundary_test.go — точные граничные условия CanSwitch()/IsSessionActive() и
// защита от nil-конфигурации, которые sticky_test.go/sticky_extra2_test.go проверяли
// только "с запасом" (минуты вместо миллисекунд у границы) или вовсе не проверяли
// (SetConfig(nil)). Каждый тест здесь целится РОВНО в сравнение (< / >=) в коде
// sticky.go, чтобы будущий рефакторинг, случайно поменявший строгое неравенство на
// нестрогое (или наоборот), был пойман.

import (
	"sync"
	"testing"
	"time"
)

// ── SetConfig(nil) — регрессия найденного бага ────────────────────────────────
//
// NewStickySessionManager(nil) подставляет DefaultSessionConfig(), но до фикса
// SetConfig(nil) сохранял nil буквально: s.cfg = nil. Следующий же вызов
// CanSwitch/IsSessionActive/Status читает s.cfg.* без проверки на nil — паника.
func TestSetConfig_NilFallsBackToDefault(t *testing.T) {
	m := NewStickySessionManager(DefaultSessionConfig())
	m.SetConfig(nil)

	// Не должно паниковать — до фикса паниковало здесь на разыменовании nil.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("SetConfig(nil) должен откатываться на дефолт, а не оставлять nil: паника %v", r)
		}
	}()

	if got := m.GetConfig(); got == nil {
		t.Fatal("GetConfig() вернул nil после SetConfig(nil)")
	}
	if got := m.GetPolicy(); got != PolicySticky {
		t.Errorf("после SetConfig(nil) политика = %v, want PolicySticky (дефолт)", got)
	}
	_ = m.CanSwitch(false)
	_ = m.IsSessionActive()
	_ = m.Status()
}

// ── CanSwitch: GraceAfterSwitch — строгая граница ──────────────────────────────

func TestCanSwitch_GraceAfterSwitch_JustBefore_Denies(t *testing.T) {
	cfg := &SessionConfig{Policy: PolicyFree, MaxSwitchRate: 100, GraceAfterSwitch: 300 * time.Millisecond}
	s := NewStickySessionManager(cfg)
	s.mu.Lock()
	s.lastSwitchAt = time.Now().Add(-250 * time.Millisecond) // 50ms до истечения grace
	s.mu.Unlock()

	dec := s.CanSwitch(false)
	if dec.Allow {
		t.Errorf("за 50ms до конца GraceAfterSwitch переключение должно быть запрещено, reason=%q", dec.Reason)
	}
}

func TestCanSwitch_GraceAfterSwitch_JustAfter_Allows(t *testing.T) {
	cfg := &SessionConfig{Policy: PolicyFree, MaxSwitchRate: 100, GraceAfterSwitch: 300 * time.Millisecond}
	s := NewStickySessionManager(cfg)
	s.mu.Lock()
	s.lastSwitchAt = time.Now().Add(-350 * time.Millisecond) // 50ms после истечения grace
	s.mu.Unlock()

	dec := s.CanSwitch(false)
	if !dec.Allow {
		t.Errorf("через 50ms после конца GraceAfterSwitch переключение должно быть разрешено, reason=%q", dec.Reason)
	}
}

// ── CanSwitch: PolicyTimed / MinSessionDuration — строгая граница ─────────────

func TestCanSwitch_Timed_JustBeforeMinDuration_Denies(t *testing.T) {
	cfg := &SessionConfig{Policy: PolicyTimed, MinSessionDuration: 300 * time.Millisecond, MaxSwitchRate: 100}
	s := NewStickySessionManager(cfg)
	s.mu.Lock()
	s.connectedAt = time.Now().Add(-250 * time.Millisecond)
	s.mu.Unlock()

	dec := s.CanSwitch(false)
	if dec.Allow {
		t.Errorf("за 50ms до MinSessionDuration переключение должно быть запрещено, reason=%q", dec.Reason)
	}
}

func TestCanSwitch_Timed_JustAfterMinDuration_Allows(t *testing.T) {
	cfg := &SessionConfig{Policy: PolicyTimed, MinSessionDuration: 300 * time.Millisecond, MaxSwitchRate: 100}
	s := NewStickySessionManager(cfg)
	s.mu.Lock()
	s.connectedAt = time.Now().Add(-350 * time.Millisecond)
	s.mu.Unlock()

	dec := s.CanSwitch(false)
	if !dec.Allow {
		t.Errorf("через 50ms после MinSessionDuration переключение должно быть разрешено, reason=%q", dec.Reason)
	}
}

// ── CanSwitch: PolicySticky — граница "молодой сессии" (жёстко зашитые 2 минуты) ──

func TestCanSwitch_Sticky_YoungSession_JustBefore2Min_Denies(t *testing.T) {
	cfg := &SessionConfig{Policy: PolicySticky, ActivityTimeout: 0, MaxSwitchRate: 100, GraceAfterSwitch: 0}
	s := NewStickySessionManager(cfg)
	s.mu.Lock()
	s.connectedAt = time.Now().Add(-2*time.Minute + 200*time.Millisecond) // чуть МЕНЬШЕ 2 минут
	s.mu.Unlock()

	dec := s.CanSwitch(false)
	if dec.Allow {
		t.Errorf("за 200ms до истечения 2-минутной защиты молодой сессии переключение должно быть запрещено, reason=%q", dec.Reason)
	}
}

func TestCanSwitch_Sticky_YoungSession_JustAfter2Min_Allows(t *testing.T) {
	cfg := &SessionConfig{Policy: PolicySticky, ActivityTimeout: 0, MaxSwitchRate: 100, GraceAfterSwitch: 0}
	s := NewStickySessionManager(cfg)
	s.mu.Lock()
	s.connectedAt = time.Now().Add(-2*time.Minute - 200*time.Millisecond) // чуть БОЛЬШЕ 2 минут
	s.mu.Unlock()

	dec := s.CanSwitch(false)
	if !dec.Allow {
		t.Errorf("через 200ms после истечения 2-минутной защиты молодой сессии переключение должно быть разрешено, reason=%q", dec.Reason)
	}
}

// ── CanSwitch: PolicySticky — граница ActivityTimeout при активных соединениях ──

func TestCanSwitch_Sticky_ActivityTimeout_JustBefore_Denies(t *testing.T) {
	cfg := &SessionConfig{Policy: PolicySticky, ActivityTimeout: 300 * time.Millisecond, MaxSwitchRate: 100, GraceAfterSwitch: 0}
	s := NewStickySessionManager(cfg)
	s.mu.Lock()
	s.connectedAt = time.Now().Add(-1 * time.Hour) // молодая сессия не мешает
	s.activeConns = 1
	s.lastActivity = time.Now().Add(-250 * time.Millisecond) // idle 250ms < 300ms timeout
	s.mu.Unlock()

	dec := s.CanSwitch(false)
	if dec.Allow {
		t.Errorf("idle 250ms < ActivityTimeout 300ms при активном соединении должно запрещать переключение, reason=%q", dec.Reason)
	}
}

func TestCanSwitch_Sticky_ActivityTimeout_JustAfter_Allows(t *testing.T) {
	cfg := &SessionConfig{Policy: PolicySticky, ActivityTimeout: 300 * time.Millisecond, MaxSwitchRate: 100, GraceAfterSwitch: 0}
	s := NewStickySessionManager(cfg)
	s.mu.Lock()
	s.connectedAt = time.Now().Add(-1 * time.Hour)
	s.activeConns = 1
	s.lastActivity = time.Now().Add(-350 * time.Millisecond) // idle 350ms > 300ms timeout
	s.mu.Unlock()

	dec := s.CanSwitch(false)
	if !dec.Allow {
		t.Errorf("idle 350ms > ActivityTimeout 300ms должно разрешать переключение несмотря на activeConns>0, reason=%q", dec.Reason)
	}
}

// ── IsSessionActive — та же строгая граница ActivityTimeout ───────────────────

func TestIsSessionActive_JustBeforeTimeout_True(t *testing.T) {
	cfg := DefaultSessionConfig()
	cfg.ActivityTimeout = 300 * time.Millisecond
	m := NewStickySessionManager(cfg)
	m.mu.Lock()
	m.lastActivity = time.Now().Add(-250 * time.Millisecond)
	m.mu.Unlock()

	if !m.IsSessionActive() {
		t.Error("idle 250ms < ActivityTimeout 300ms: сессия должна считаться активной")
	}
}

func TestIsSessionActive_JustAfterTimeout_False(t *testing.T) {
	cfg := DefaultSessionConfig()
	cfg.ActivityTimeout = 300 * time.Millisecond
	m := NewStickySessionManager(cfg)
	m.mu.Lock()
	m.lastActivity = time.Now().Add(-350 * time.Millisecond)
	m.mu.Unlock()

	if m.IsSessionActive() {
		t.Error("idle 350ms > ActivityTimeout 300ms: сессия должна считаться неактивной")
	}
}

// ── Rate limit — off-by-one на границе MaxSwitchRate ──────────────────────────
//
// countRecentSwitches(now) >= MaxSwitchRate блокирует. Значит РОВНО MaxSwitchRate
// уже записанных переключений обязаны заблокировать следующее; MaxSwitchRate-1 —
// ещё нет (при условии, что остальные гейты открыты).
func TestCanSwitch_RateLimit_OffByOne(t *testing.T) {
	const limit = 5
	cfg := &SessionConfig{Policy: PolicyFree, MaxSwitchRate: limit, GraceAfterSwitch: 0}
	s := NewStickySessionManager(cfg)

	// limit-1 переключений — рейт-лимит ещё не должен сработать.
	for i := 0; i < limit-1; i++ {
		s.RecordSwitch()
	}
	if dec := s.CanSwitch(false); !dec.Allow {
		t.Fatalf("после %d/%d переключений должно быть разрешено ещё одно, reason=%q", limit-1, limit, dec.Reason)
	}

	// Ещё одно (итого ровно limit) — теперь обязан сработать рейт-лимит.
	s.RecordSwitch()
	dec := s.CanSwitch(false)
	if dec.Allow {
		t.Fatalf("после ровно %d/%d переключений должно быть запрещено, reason=%q", limit, limit, dec.Reason)
	}
	if dec.RetryIn <= 0 {
		t.Error("RetryIn должен быть положительным при активном рейт-лимите")
	}
}

// RecordSwitch должен вычищать записи старше часа — иначе switchHistory растёт
// неограниченно и/или рейт-лимит считает переключения, которых давно не было в
// пределах часового окна.
func TestRecordSwitch_PrunesEntriesOlderThanHour(t *testing.T) {
	s := NewStickySessionManager(DefaultSessionConfig())
	s.mu.Lock()
	s.switchHistory = []time.Time{
		time.Now().Add(-2 * time.Hour),
		time.Now().Add(-90 * time.Minute),
	}
	s.mu.Unlock()

	s.RecordSwitch() // добавляет актуальную запись и должен вычистить старые

	s.mu.RLock()
	history := append([]time.Time(nil), s.switchHistory...)
	s.mu.RUnlock()

	for _, ts := range history {
		if time.Since(ts) > time.Hour {
			t.Errorf("switchHistory содержит запись старше часа после RecordSwitch: %v", ts)
		}
	}
	if len(history) != 1 {
		t.Errorf("switchHistory после чистки = %d записей, want 1 (только что добавленная)", len(history))
	}
}

// ── Конкурентный доступ (-race) ────────────────────────────────────────────────
//
// Реальный путь в проде: SyncFromTraffic вызывается из опроса Clash API (отдельная
// горутина), CanSwitch/Status — из UI-поллинга и из логики автопереключения
// (другие горутины), TrackConn/OnActivity — из потенциальных Go-net.Conn враппепов.
// Явный стресс-тест поверх go test -race controls, что RWMutex действительно
// защищает все поля, а не только те, что задеты остальными тестами по отдельности.
func TestStickySessionManager_ConcurrentAccess_NoRace(t *testing.T) {
	cfg := DefaultSessionConfig()
	cfg.ActivityTimeout = 10 * time.Millisecond
	s := NewStickySessionManager(cfg)

	const workers = 8
	const iterations = 200
	var wg sync.WaitGroup
	wg.Add(workers * 6)

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				s.TrackConn(1)
				s.TrackConn(-1)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				s.SyncFromTraffic(j%3, j%2 == 0)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				s.OnActivity()
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = s.CanSwitch(j%10 == 0)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = s.Status()
				_ = s.IsSessionActive()
			}
		}()
		go func(id int) {
			defer wg.Done()
			node := "node"
			for j := 0; j < iterations; j++ {
				s.SetCurrentNode(node)
				s.PinDomain("example.com")
				_ = s.GetPinnedNode("example.com")
				_ = s.DomainStickyCount()
				if j%20 == 0 {
					s.CleanExpiredDomainSessions()
				}
			}
		}(i)
	}

	wg.Wait()
	// Если дошли сюда без паники/дедлока/находки -race — тест зелёный.
}
