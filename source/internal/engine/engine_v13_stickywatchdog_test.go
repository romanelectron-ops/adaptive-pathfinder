// engine_v13_stickywatchdog_test.go — живой отчёт пользователя 2026-09-05 (реальный телефон,
// реальный узел): Watchdog честно объявил тоннель DEAD через настоящие HTTP-проверки шесть раз
// подряд за минуту, но emergencySwitch КАЖДЫЙ раз откладывал переключение сообщением
// «sticky: N активных соединений» — SyncFromTraffic считает канал «активным» по одним лишь
// исходящим байтам, а мёртвый узел получает их бесконечно: приложения телефона продолжают
// открывать новые TCP/TLS-попытки (SYN/ClientHello — тоже «исходящий трафик»), каждая висит
// 5-10с и проваливается, счётчик activeConns никогда не опускается до нуля. Фикс: подтверждённая
// Watchdog'ом смерть (WatchdogFailed) обходит sticky-гейт той же логикой, что neverConfirmedHealthy.
package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/fallback"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// Регрессия: Watchdog подтвердил смерть (WatchdogFailed) — sticky-гейт обязан пропустить
// переключение НЕМЕДЛЕННО, даже если счётчик активных соединений (доживающие ретраи мёртвого
// узла) остаётся положительным и узел когда-то успешно проходил проверки (everSucceeded=true,
// иначе сработал бы уже существующий neverConfirmedHealthy-обход — тест должен проверять
// ИМЕННО новую ветку, а не старую).
func TestEmergencySwitch_WatchdogConfirmedDead_BypassesSticky(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.StickySessionPolicy = "sticky"
	e := New(cfg)

	// everSucceeded=true — узел РАБОТАЛ раньше (изолирует новую ветку от уже покрытой
	// neverConfirmedHealthy).
	e.watchdog.SetHealthConfirmedForTest(true)
	// Watchdog СЕЙЧАС считает канал мёртвым — ровно то состояние, в котором живой телефон
	// застревал минутами.
	e.watchdog.SetStateForTest(fallback.WatchdogFailed, 3)

	e.stateMu.Lock()
	e.state.Connected = true
	e.state.Since = time.Now().Add(-10 * time.Minute) // сессия старая — не «молодая» (see 2-мин гейт)
	e.stateMu.Unlock()

	// Живая картина: доживающие ретраи мёртвого узла держат activeConns > 0 без реальной
	// передачи данных — lastActivity НЕ обновлялась движущимися байтами.
	e.stickySession.OnConnected()
	e.stickySession.SyncFromTraffic(16, false)

	var logs []string
	e.OnLog = func(msg string) { logs = append(logs, msg) }
	e.emergencySwitch()

	for _, l := range logs {
		if strings.Contains(l, "Sticky Session: переключение отложено") {
			t.Fatalf("подтверждённая Watchdog'ом смерть туннеля обязана обходить sticky-гейт, "+
				"а не откладывать переключение: %v", logs)
		}
	}
}

// Контрольный сценарий (не регрессия, а страховка от чрезмерного ослабления): пока Watchdog
// НЕ объявил смерть (State=Healthy/Degraded, ниже FailThreshold) и узел когда-то успешно
// проходил проверки — sticky-гейт обязан по-прежнему защищать активную сессию как раньше.
func TestEmergencySwitch_WatchdogHealthy_StickyStillApplies(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.StickySessionPolicy = "sticky"
	e := New(cfg)

	e.watchdog.SetHealthConfirmedForTest(true)
	e.watchdog.SetStateForTest(fallback.WatchdogDegraded, 1) // ниже FailThreshold — ещё не DEAD

	e.stateMu.Lock()
	e.state.Connected = true
	e.state.Since = time.Now().Add(-10 * time.Minute)
	e.stateMu.Unlock()

	e.stickySession.OnConnected()
	e.stickySession.SyncFromTraffic(5, true) // реальные движущиеся байты — сессия правда активна

	var logs []string
	e.OnLog = func(msg string) { logs = append(logs, msg) }
	e.emergencySwitch()

	found := false
	for _, l := range logs {
		if strings.Contains(l, "Sticky Session: переключение отложено") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("активная сессия на ЖИВОМ (не DEAD) канале должна по-прежнему защищаться sticky: %v", logs)
	}
}
