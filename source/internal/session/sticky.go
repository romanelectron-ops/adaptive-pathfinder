// Package session — Sticky Session менеджер для APF.
//
// Проблема: некоторые сайты (банки, стриминг, Google, Cloudflare) отслеживают
// постоянство IP-адреса. Если APF переключает узлы во время активной сессии —
// сайт видит смену IP и блокирует аккаунт или требует повторную авторизацию.
//
// Решение: "Sticky Session" — фиксируем текущий узел на время активных сессий.
// Переключение разрешено только когда нет активных соединений или по явному запросу.
package session

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// StickyPolicy — политика переключения узлов
type StickyPolicy int

const (
	// PolicyFree — переключать свободно (старое поведение, не рекомендуется)
	PolicyFree StickyPolicy = iota

	// PolicySticky — не переключать пока есть активные сессии.
	// Переключение только при реальной потере связи с узлом.
	PolicySticky

	// PolicyTimed — не переключать в течение MinSessionDuration.
	PolicyTimed
)

func (p StickyPolicy) String() string {
	switch p {
	case PolicyFree:
		return "free"
	case PolicySticky:
		return "sticky"
	case PolicyTimed:
		return "timed"
	default:
		return "unknown"
	}
}

// SessionConfig — настройки Sticky Session
type SessionConfig struct {
	Policy             StickyPolicy  `json:"policy"`
	MinSessionDuration time.Duration `json:"min_session_duration"` // для PolicyTimed
	MaxSwitchRate      int           `json:"max_switch_rate_per_hour"`
	GraceAfterSwitch   time.Duration `json:"grace_after_switch"`
	ActivityTimeout    time.Duration `json:"activity_timeout"` // через сколько считать idle
}

// DefaultSessionConfig — рекомендуемые настройки
func DefaultSessionConfig() *SessionConfig {
	return &SessionConfig{
		Policy:             PolicySticky,
		MinSessionDuration: 10 * time.Minute,
		MaxSwitchRate:      6,
		GraceAfterSwitch:   30 * time.Second,
		ActivityTimeout:    45 * time.Second, // 45 сек без трафика = сессия завершена
	}
}

// SwitchDecision — решение о переключении
type SwitchDecision struct {
	Allow   bool
	Reason  string
	RetryIn time.Duration
}

// StickySessionManager управляет политикой переключения узлов.
type StickySessionManager struct {
	mu  sync.RWMutex
	cfg *SessionConfig

	connectedAt   time.Time
	lastSwitchAt  time.Time
	switchHistory []time.Time
	activeConns   int
	lastActivity  time.Time

	// domain-sticky состояние (методы — в domain_sticky.go).
	//
	// РАНЬШЕ это состояние жило в package-level переменных (domainStore/currentNodeID
	// в domain_sticky.go) — методы принимали ресивер *StickySessionManager, но
	// фактически игнорировали его и читали/писали общие для ВСЕХ инстансов пакетные
	// переменные. В проде это было незаметно (engine создаёт ровно один
	// StickySessionManager на процесс — engine.go:424), но ломало базовую
	// инкапсуляцию: второй независимый менеджер (например, в тестах, или в будущем
	// сценарии с несколькими профилями/движками в одном процессе) видел бы чужие
	// domain-pin'ы и currentNodeID. Перенесено в поля структуры — обычная
	// per-instance изоляция, без изменения публичного API.
	domainMu      sync.RWMutex
	domainStore   map[string]domainSession
	currentNodeMu sync.RWMutex
	currentNodeID string
}

// NewStickySessionManager создаёт менеджер
func NewStickySessionManager(cfg *SessionConfig) *StickySessionManager {
	if cfg == nil {
		cfg = DefaultSessionConfig()
	}
	return &StickySessionManager{
		cfg:          cfg,
		lastActivity: time.Now(),
		domainStore:  make(map[string]domainSession),
	}
}

// OnConnected — вызывается когда APF подключился к новому узлу
func (s *StickySessionManager) OnConnected() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connectedAt = time.Now()
	s.lastSwitchAt = time.Now()
	s.activeConns = 0
	s.lastActivity = time.Now()
}

// OnActivity — вызывается при обнаружении трафика через прокси
func (s *StickySessionManager) OnActivity() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastActivity = time.Now()
}

// TrackConn увеличивает/уменьшает счётчик активных соединений
func (s *StickySessionManager) TrackConn(delta int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeConns += delta
	if s.activeConns < 0 {
		s.activeConns = 0
	}
	if delta > 0 {
		s.lastActivity = time.Now()
	}
}

// SyncFromTraffic — реальный источник activeConns/lastActivity в продакшене (аудит:
// "Sticky Session выродился — TrackConn не вызывается"). TrackConn/OnActivity выше
// спроектированы под Go-уровневый перехват (NewTrackedConn/NewTrackedTransport), но
// реальный трафик APF идёт через C-библиотеку sing-box (libbox)/TUN в обход Go net.Conn
// целиком — оборачивать там физически нечего, поэтому TrackConn никогда не вызывался, и
// защита "не переключать при активных соединениях" в CanSwitch() была мертва (activeConns
// всегда 0). Вместо Go-уровневого перехвата — синхронизация с уже существующим опросом
// Clash API sing-box (singbox.TrafficMonitor, опрашивает /connections и /traffic каждые
// 2с, пока движок подключён): count — абсолютное число соединений на этот момент (не
// дельта — опрос может пропустить тик, накопление through TrackConn(delta) разъехалось бы
// с реальностью), movingBytes — true, если мгновенная скорость по /traffic > 0 (реальная
// передача данных, не просто открытый но бездействующий keepalive).
func (s *StickySessionManager) SyncFromTraffic(count int, movingBytes bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if count < 0 {
		count = 0
	}
	s.activeConns = count
	if movingBytes {
		s.lastActivity = time.Now()
	}
}

// IsSessionActive возвращает true если сессия считается активной
func (s *StickySessionManager) IsSessionActive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.activeConns > 0 {
		return true
	}
	// Считаем активной если недавно была активность
	return time.Since(s.lastActivity) < s.cfg.ActivityTimeout
}

// CanSwitch — главный метод: можно ли переключить узел сейчас?
func (s *StickySessionManager) CanSwitch(forced bool) SwitchDecision {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Принудительное переключение (пользователь нажал кнопку) — всегда разрешаем
	if forced {
		return SwitchDecision{Allow: true, Reason: "принудительное переключение"}
	}

	now := time.Now()

	// Rate limit — защита от слишком частых переключений
	recentSwitches := s.countRecentSwitches(now)
	if recentSwitches >= s.cfg.MaxSwitchRate {
		var oldest time.Time
		for _, t := range s.switchHistory {
			if oldest.IsZero() || t.Before(oldest) {
				oldest = t
			}
		}
		retryIn := time.Hour - now.Sub(oldest)
		if retryIn < 0 {
			retryIn = 0
		}
		return SwitchDecision{
			Allow:   false,
			Reason:  fmt.Sprintf("rate limit: %d/%d переключений в час", recentSwitches, s.cfg.MaxSwitchRate),
			RetryIn: retryIn,
		}
	}

	// Grace period после последнего переключения
	sinceSwitch := now.Sub(s.lastSwitchAt)
	if sinceSwitch < s.cfg.GraceAfterSwitch && !s.lastSwitchAt.IsZero() {
		remaining := s.cfg.GraceAfterSwitch - sinceSwitch
		return SwitchDecision{
			Allow:   false,
			Reason:  fmt.Sprintf("пауза после переключения: ещё %v", remaining.Round(time.Second)),
			RetryIn: remaining,
		}
	}

	switch s.cfg.Policy {
	case PolicyFree:
		return SwitchDecision{Allow: true, Reason: "режим: свободный"}

	case PolicySticky:
		// Проверяем активные соединения
		if s.activeConns > 0 {
			idleFor := now.Sub(s.lastActivity)
			if idleFor < s.cfg.ActivityTimeout {
				remaining := s.cfg.ActivityTimeout - idleFor
				return SwitchDecision{
					Allow:   false,
					Reason:  fmt.Sprintf("sticky: %d активных соединений, idle %v (ждём %v)", s.activeConns, idleFor.Round(time.Second), remaining.Round(time.Second)),
					RetryIn: remaining,
				}
			}
		}

		// Защита молодых сессий (< 2 мин после подключения)
		sessionAge := now.Sub(s.connectedAt)
		if sessionAge < 2*time.Minute && !s.connectedAt.IsZero() {
			remaining := 2*time.Minute - sessionAge
			return SwitchDecision{
				Allow:   false,
				Reason:  fmt.Sprintf("sticky: сессия молодая (%v) — защита от смены IP", sessionAge.Round(time.Second)),
				RetryIn: remaining,
			}
		}

		return SwitchDecision{Allow: true, Reason: "sticky: нет активных сессий"}

	case PolicyTimed:
		sessionAge := now.Sub(s.connectedAt)
		if sessionAge < s.cfg.MinSessionDuration && !s.connectedAt.IsZero() {
			remaining := s.cfg.MinSessionDuration - sessionAge
			return SwitchDecision{
				Allow:   false,
				Reason:  fmt.Sprintf("timed: мин. сессия %v не истекла (прошло %v)", s.cfg.MinSessionDuration, sessionAge.Round(time.Second)),
				RetryIn: remaining,
			}
		}
		return SwitchDecision{Allow: true, Reason: "timed: мин. время сессии достигнуто"}
	}

	return SwitchDecision{Allow: true, Reason: "разрешено по умолчанию"}
}

// RecordSwitch — записать факт переключения (для rate limiting)
func (s *StickySessionManager) RecordSwitch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.lastSwitchAt = now
	s.switchHistory = append(s.switchHistory, now)
	// Обрезаем историю — только последний час
	cutoff := now.Add(-time.Hour)
	fresh := s.switchHistory[:0]
	for _, t := range s.switchHistory {
		if t.After(cutoff) {
			fresh = append(fresh, t)
		}
	}
	s.switchHistory = fresh
}

// Status возвращает текущий статус для UI
func (s *StickySessionManager) Status() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	var sessionAgeSec, idleSec, lastSwitchSec float64
	if !s.connectedAt.IsZero() {
		sessionAgeSec = now.Sub(s.connectedAt).Seconds()
	}
	if !s.lastActivity.IsZero() {
		idleSec = now.Sub(s.lastActivity).Seconds()
	}
	if !s.lastSwitchAt.IsZero() {
		lastSwitchSec = now.Sub(s.lastSwitchAt).Seconds()
	}

	return map[string]interface{}{
		"policy":               s.cfg.Policy.String(),
		"session_age_sec":      sessionAgeSec,
		"active_conns":         s.activeConns,
		"idle_for_sec":         idleSec,
		"session_active":       s.activeConns > 0 || idleSec < s.cfg.ActivityTimeout.Seconds(),
		"switches_this_hour":   s.countRecentSwitches(now),
		"max_switch_rate":      s.cfg.MaxSwitchRate,
		"last_switch_ago_sec":  lastSwitchSec,
		"grace_period_sec":     s.cfg.GraceAfterSwitch.Seconds(),
		"min_session_sec":      s.cfg.MinSessionDuration.Seconds(),
		"activity_timeout_sec": s.cfg.ActivityTimeout.Seconds(),
	}
}

// SetPolicy меняет политику на ходу
func (s *StickySessionManager) SetPolicy(policy StickyPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.Policy = policy
}

func (s *StickySessionManager) GetPolicy() StickyPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.Policy
}

func (s *StickySessionManager) GetConfig() *SessionConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := *s.cfg
	return &cp
}

// SetConfig заменяет конфигурацию целиком.
//
// nil трактуется так же, как в NewStickySessionManager — откат на дефолт, а не
// сохранение nil. Без этой проверки следующий же вызов CanSwitch/IsSessionActive/
// Status (все читают поля s.cfg.* без проверки на nil) паниковал бы с nil pointer
// dereference. Конструктор такой защитой уже обладал — сеттер обязан быть с ним
// согласован, иначе граница nil-безопасности пакета не полная.
func (s *StickySessionManager) SetConfig(cfg *SessionConfig) {
	if cfg == nil {
		cfg = DefaultSessionConfig()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg
}

// countRecentSwitches — количество переключений за последний час (без mutex, вызывать под lock)
func (s *StickySessionManager) countRecentSwitches(now time.Time) int {
	cutoff := now.Add(-time.Hour)
	count := 0
	for _, t := range s.switchHistory {
		if t.After(cutoff) {
			count++
		}
	}
	return count
}

// ─── Трекер HTTP-соединений ───────────────────────────────────────────────────

// activityTransport — http.RoundTripper с трекингом активности
type activityTransport struct {
	inner   http.RoundTripper
	manager *StickySessionManager
}

// NewTrackedTransport создаёт транспорт с трекингом активности
func NewTrackedTransport(mgr *StickySessionManager) http.RoundTripper {
	return &activityTransport{
		inner:   http.DefaultTransport,
		manager: mgr,
	}
}

func (t *activityTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.manager.TrackConn(+1)
	t.manager.OnActivity()
	defer t.manager.TrackConn(-1)
	return t.inner.RoundTrip(req)
}

// TrackedConn — обёртка над net.Conn с трекингом соединений
type TrackedConn struct {
	net.Conn
	manager *StickySessionManager
	once    sync.Once
}

// NewTrackedConn оборачивает соединение с трекингом
func NewTrackedConn(conn net.Conn, mgr *StickySessionManager) *TrackedConn {
	mgr.TrackConn(+1)
	mgr.OnActivity()
	return &TrackedConn{Conn: conn, manager: mgr}
}

func (c *TrackedConn) Close() error {
	c.once.Do(func() { c.manager.TrackConn(-1) })
	return c.Conn.Close()
}

func (c *TrackedConn) Write(b []byte) (int, error) {
	if len(b) > 0 {
		c.manager.OnActivity()
	}
	return c.Conn.Write(b)
}
