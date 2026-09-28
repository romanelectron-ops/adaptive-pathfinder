// Package statemachine — конечный автомат управления туннелем APF.
// Реализован по паттернам из tunnel-architect и algorithmist skills.
package statemachine

import (
	"context"
	"fmt"
	"log"
	"math"
	"sync"
	"time"
)

// TunnelState — состояния туннеля
type TunnelState int

const (
	StateIdle       TunnelState = iota // Не запущен
	StateConnecting                    // Устанавливаем соединение
	StateConnected                     // Соединение активно
	StateTesting                       // Проверяем качество
	StateFailing                       // Обнаружены ошибки
	StateFallback                      // Переключаемся на резерв
	StateReset                         // Полный сброс
)

func (s TunnelState) String() string {
	switch s {
	case StateIdle:
		return "idle"
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateTesting:
		return "testing"
	case StateFailing:
		return "failing"
	case StateFallback:
		return "fallback"
	case StateReset:
		return "reset"
	default:
		return "unknown"
	}
}

// FallbackLevel — один уровень иерархии резервных протоколов.
// Из tunnel-architect: минимум 3 уровня, каждый уровень min 2 протокола.
type FallbackLevel struct {
	Name       string
	Priority   int
	Protocols  []string // теги протоколов sing-box
	Timeout    time.Duration
	MaxRetries int
}

// DefaultFallbackHierarchy — 4-уровневая иерархия APF.
// Из tunnel-architect skill + bypass-engineer матрица.
var DefaultFallbackHierarchy = []FallbackLevel{
	{
		Name:       "L1-Reality",
		Priority:   1,
		Protocols:  []string{"vless-reality", "trojan-tls"},
		Timeout:    10 * time.Second,
		MaxRetries: 2,
	},
	{
		Name:       "L2-CDN",
		Priority:   2,
		Protocols:  []string{"vless-ws-cdn", "trojan-cdn"},
		Timeout:    15 * time.Second,
		MaxRetries: 3,
	},
	{
		Name:       "L3-Standard",
		Priority:   3,
		Protocols:  []string{"vmess-ws", "ss-obfs"},
		Timeout:    20 * time.Second,
		MaxRetries: 3,
	},
	{
		Name: "L4-LastResort",
		// C-14 (ТЗ v1.4, FAIL C2): здесь стоял "tor-snowflake" — протокол, которого в этой
		// сборке НЕТ (см. C-6: applyTorFallback строит голый {type:"tor"}, ключи Snowflake из
		// internal/fallback/tor_snowflake.go не совпадают с вендорной схемой). Единственным
		// следствием его присутствия были строки в логе телефона — «escalating to level
		// L4-LastResort (proto: tor-snowflake)» и «switching proto tor-snowflake → direct»:
		// пользователю обещали резерв, которого не существует. Сам уровень не удаляем — на нём
		// стоит direct, настоящий последний резерв.
		Priority:   4,
		Protocols:  []string{"direct"},
		Timeout:    60 * time.Second,
		MaxRetries: 5,
	},
}

// HealthResult — результат проверки соединения
type HealthResult struct {
	OK      bool
	Latency time.Duration
	Error   error
}

// TunnelFSM — конечный автомат управления туннелем APF.
// Реализует паттерн из tunnel-architect skill.
type TunnelFSM struct {
	mu           sync.RWMutex
	state        TunnelState
	levels       []FallbackLevel
	currentLevel int
	currentProto int
	failCount    int
	lastSwitch   time.Time
	minUptime    time.Duration // из настроек SwitchOnlyOnFail

	// Callbacks
	OnConnect    func(level, proto string)
	OnDisconnect func(reason string)
	OnFallback   func(from, to string)
	OnLog        func(string)

	// Exponential backoff (vpn-specialist: reconnect с backoff)
	backoffBase  time.Duration
	backoffMax   time.Duration
	backoffCount int
}

// New создаёт FSM с иерархией fallback
func New(levels []FallbackLevel, minUptime time.Duration) *TunnelFSM {
	if len(levels) == 0 {
		levels = DefaultFallbackHierarchy
	}
	return &TunnelFSM{
		state:       StateIdle,
		levels:      levels,
		minUptime:   minUptime,
		backoffBase: 2 * time.Second,
		backoffMax:  120 * time.Second,
	}
}

// State возвращает текущее состояние
func (f *TunnelFSM) State() TunnelState {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.state
}

// CurrentProtocol возвращает текущий протокол и уровень
func (f *TunnelFSM) CurrentProtocol() (level, proto string) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.currentLevel >= len(f.levels) {
		return "none", "none"
	}
	lv := f.levels[f.currentLevel]
	if f.currentProto >= len(lv.Protocols) {
		return lv.Name, "none"
	}
	return lv.Name, lv.Protocols[f.currentProto]
}

// Connect инициирует подключение через текущий протокол
func (f *TunnelFSM) Connect(ctx context.Context, connectFn func(proto string) error) error {
	f.mu.Lock()
	f.state = StateConnecting
	_, proto := f.currentProtocolLocked()
	f.mu.Unlock()

	f.log(fmt.Sprintf("FSM: connecting via %s", proto))

	if err := connectFn(proto); err != nil {
		f.HandleFailure(err)
		return err
	}

	f.mu.Lock()
	f.state = StateConnected
	f.lastSwitch = time.Now()
	f.failCount = 0
	f.backoffCount = 0
	f.mu.Unlock()

	f.log(fmt.Sprintf("FSM: connected via %s", proto))
	if f.OnConnect != nil {
		lv, pr := f.CurrentProtocol()
		f.OnConnect(lv, pr)
	}
	return nil
}

// HandleFailure обрабатывает сбой соединения.
// Реализует логику из tunnel-architect: пробуем следующий протокол,
// потом следующий уровень, потом начинаем сначала с задержкой.
func (f *TunnelFSM) HandleFailure(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.failCount++
	f.state = StateFailing
	f.log(fmt.Sprintf("FSM: failure #%d — %v", f.failCount, err))

	// Проверяем минимальное время на протоколе
	if time.Since(f.lastSwitch) < f.minUptime && f.failCount < 3 {
		f.log(fmt.Sprintf("FSM: too soon to switch (uptime %v < min %v), retrying same",
			time.Since(f.lastSwitch).Round(time.Second), f.minUptime))
		f.state = StateConnecting
		return
	}

	// Пробуем следующий протокол в текущем уровне
	lv := f.levels[f.currentLevel]
	f.currentProto++

	if f.currentProto < len(lv.Protocols) {
		fromProto := lv.Protocols[f.currentProto-1]
		toProto := lv.Protocols[f.currentProto]
		f.log(fmt.Sprintf("FSM: switching proto %s → %s (same level %s)",
			fromProto, toProto, lv.Name))
		f.state = StateFallback
		if f.OnFallback != nil {
			f.OnFallback(fromProto, toProto)
		}
		return
	}

	// Все протоколы уровня исчерпаны — переходим на следующий уровень
	f.currentProto = 0
	f.currentLevel++

	if f.currentLevel < len(f.levels) {
		nextLevel := f.levels[f.currentLevel]
		// Защита от паники: у кастомной иерархии уровень может быть задан
		// с пустым списком протоколов (баг найден тестом на реальном сценарии
		// "эскалация на уровень без протоколов"). Protocols[0] при пустом
		// срезе паникует — логируем "none" вместо падения FSM.
		nextProto := "none"
		if len(nextLevel.Protocols) > 0 {
			nextProto = nextLevel.Protocols[0]
		}
		f.log(fmt.Sprintf("FSM: escalating to level %s (proto: %s)",
			nextLevel.Name, nextProto))
		f.state = StateFallback
		if f.OnFallback != nil {
			f.OnFallback(lv.Name, nextLevel.Name)
		}
		return
	}

	// Все уровни исчерпаны — начинаем сначала с exponential backoff
	f.currentLevel = 0
	f.currentProto = 0
	f.backoffCount++
	delay := f.calcBackoff()
	f.log(fmt.Sprintf("FSM: all levels exhausted, restarting in %v (attempt #%d)",
		delay, f.backoffCount))
	f.state = StateReset
}

// HandleSuccess обрабатывает успешную проверку соединения
func (f *TunnelFSM) HandleSuccess(latency time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state == StateConnected || f.state == StateTesting {
		f.failCount = 0
		f.state = StateConnected
	}
}

// Reset сбрасывает FSM в начальное состояние
func (f *TunnelFSM) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = StateIdle
	f.currentLevel = 0
	f.currentProto = 0
	f.failCount = 0
	f.backoffCount = 0
}

// Backoff возвращает задержку перед следующей попыткой (exponential backoff)
func (f *TunnelFSM) Backoff() time.Duration {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.calcBackoff()
}

// ShouldSwitch возвращает true если нужно переключить протокол
func (f *TunnelFSM) ShouldSwitch() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.state == StateFallback || f.state == StateReset
}

// ─── Вспомогательные методы ───────────────────────────────────────────────────

func (f *TunnelFSM) currentProtocolLocked() (level, proto string) {
	if f.currentLevel >= len(f.levels) {
		return "none", "none"
	}
	lv := f.levels[f.currentLevel]
	if f.currentProto >= len(lv.Protocols) {
		return lv.Name, "none"
	}
	return lv.Name, lv.Protocols[f.currentProto]
}

// calcBackoff — exponential backoff с jitter.
// Из vpn-specialist: reconnect с exponential backoff.
// Formula: min(base * 2^n + jitter, max)
func (f *TunnelFSM) calcBackoff() time.Duration {
	if f.backoffCount == 0 {
		return 0
	}
	exp := math.Pow(2, float64(f.backoffCount-1))
	delay := time.Duration(float64(f.backoffBase) * exp)
	if delay > f.backoffMax {
		delay = f.backoffMax
	}
	return delay
}

func (f *TunnelFSM) log(msg string) {
	log.Printf("[FSM] %s", msg)
	if f.OnLog != nil {
		f.OnLog(msg)
	}
}

// CurrentTimeout возвращает таймаут для текущего уровня
func (f *TunnelFSM) CurrentTimeout() time.Duration {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.currentLevel >= len(f.levels) {
		return 30 * time.Second
	}
	return f.levels[f.currentLevel].Timeout
}
