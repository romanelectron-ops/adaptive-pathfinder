package engine

// Диагностика живого лога ПК 2026-09-09: доп-адреса Kill Switch (участники гонки + bypass-домены)
// резолвились ПОСЛЕДОВАТЕЛЬНО, каждый выжигал полный таймаут DNS (5с) — 15–25 с простоя на КАЖДОМ
// переключении узла (сам Reload туннеля ~1с). resolveKillSwitchExtras теперь резолвит их
// ПАРАЛЛЕЛЬНО под общим бюджетом. Тесты бьют по seam e.ksExtraResolver — без реального DNS/netsh.

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

func ksExtraTestEngine(t *testing.T, race []*models.Node) *Engine {
	t.Helper()
	e := newTestEngine()
	e.bypassManager = nil // изолируем: тест задаёт только участников гонки
	if len(race) > 0 {
		e.mu.Lock()
		e.raceNodes = race
		e.mu.Unlock()
	}
	return e
}

// Параллельность: N медленных резолвов завершаются примерно за ОДИН интервал, а не за N.
// Это и есть суть фикса против «ПК очень долго ищет узел».
func TestResolveKillSwitchExtras_RunsConcurrently(t *testing.T) {
	entry := raceNode("entry", "198.51.100.1", 1.0)
	group := []*models.Node{
		raceNode("a", "domain-a", 0.9),
		raceNode("b", "domain-b", 0.9),
		raceNode("c", "domain-c", 0.9),
		raceNode("d", "domain-d", 0.9),
	}
	e := ksExtraTestEngine(t, group)

	const per = 200 * time.Millisecond
	var calls int32
	e.ksExtraResolver = func(addr string) (string, error) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(per)
		return "203.0.113.9", nil
	}
	ksExtraResolveBudget = 2 * time.Second // заведомо больше одного интервала, но меньше суммы всех
	defer func() { ksExtraResolveBudget = 6 * time.Second }()

	start := time.Now()
	got := e.resolveKillSwitchExtras(entry)
	elapsed := time.Since(start)

	if len(got) != 4 {
		t.Fatalf("ожидалось 4 резолвнутых адреса, получено %d (%v)", len(got), got)
	}
	if elapsed >= per*3 {
		t.Errorf("резолв занял %v — похоже, идёт последовательно (4×%v); ожидалась параллельность (~%v)",
			elapsed, per, per)
	}
	if n := atomic.LoadInt32(&calls); n != 4 {
		t.Errorf("резолвер вызван %d раз, ожидалось 4", n)
	}
}

// Бюджет отсекает зависший резолв; провалившиеся адреса пропускаются, успешные — включаются.
func TestResolveKillSwitchExtras_BudgetCutsHangAndSkipsFailures(t *testing.T) {
	entry := raceNode("entry", "198.51.100.1", 1.0)
	group := []*models.Node{
		raceNode("ok", "good", 0.9),
		raceNode("bad", "bad", 0.9),
		raceNode("slow", "slow", 0.9),
	}
	e := ksExtraTestEngine(t, group)

	e.ksExtraResolver = func(addr string) (string, error) {
		switch addr {
		case "good":
			return "203.0.113.1", nil
		case "bad":
			return "", errors.New("lookup bad: no such host")
		case "slow":
			time.Sleep(3 * time.Second) // дольше бюджета — должен быть отсечён
			return "203.0.113.2", nil
		}
		return "", nil
	}
	ksExtraResolveBudget = 300 * time.Millisecond
	defer func() { ksExtraResolveBudget = 6 * time.Second }()

	start := time.Now()
	got := e.resolveKillSwitchExtras(entry)
	elapsed := time.Since(start)

	if len(got) != 1 || got[0] != "203.0.113.1" {
		t.Fatalf("ожидался только успешный good=203.0.113.1, получено %v", got)
	}
	if elapsed >= 2*time.Second {
		t.Errorf("функция ждала зависший резолв %v — бюджет %v не сработал", elapsed, ksExtraResolveBudget)
	}
}

// Нет доп-адресов (нет гонки, bypass выключен) — резолвить нечего, возвращаем nil без горутин.
func TestResolveKillSwitchExtras_NoExtras(t *testing.T) {
	entry := raceNode("solo", "198.51.100.1", 1.0)
	e := ksExtraTestEngine(t, nil)
	called := false
	e.ksExtraResolver = func(addr string) (string, error) {
		called = true
		return "203.0.113.5", nil
	}
	if got := e.resolveKillSwitchExtras(entry); got != nil {
		t.Errorf("без доп-адресов ожидался nil, получено %v", got)
	}
	if called {
		t.Error("резолвер не должен вызываться, когда доп-адресов нет")
	}
}
