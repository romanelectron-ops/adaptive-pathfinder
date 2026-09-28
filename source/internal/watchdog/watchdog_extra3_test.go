package watchdog

// watchdog_extra3_test.go — сценарии, не покрытые watchdog_test.go/extra/extra2:
//   • GracePeriod реально ИСТЕКАЕТ (а не отменяется ctx) и ПОСЛЕ этого начинается опрос;
//   • Run() не возвращается раньше нескольких тиков PollEvery, пока процесс жив;
//   • ctx отменяется В СЕРЕДИНЕ цикла опроса (не сразу и не во время grace period);
//   • дефолт PollEvery=750ms реально применяется, когда явно не задан (без ожидания
//     750ms — через короткий ctx-таймаут, который обязан истечь раньше первого тика);
//   • isPIDAlive (windows): совпадение по подстроке-PID не даёт ложных срабатываний
//     на "соседних" числах в выводе tasklist (защищает пробельные разделители в коде).

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// GracePeriod должен реально пройти (не быть прерванным ctx), и уже ПОСЛЕ него Run
// обязан приступить к опросу и вернуться, когда процесс уже мёртв.
func TestRun_GracePeriodElapses_ThenDetectsDeath(t *testing.T) {
	origGOOS := watchdogGOOS
	origKill := killCheckFn
	defer func() { watchdogGOOS = origGOOS; killCheckFn = origKill }()

	watchdogGOOS = "linux"
	killCheckFn = func(pid int) error { return errors.New("dead") } // мёртв с самого начала

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := Run(ctx, Config{
		PID:         12345,
		PollEvery:   10 * time.Millisecond,
		GracePeriod: 100 * time.Millisecond,
	})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("ожидался nil (процесс мёртв обнаружен после grace period), получено: %v", err)
	}
	if elapsed < 100*time.Millisecond {
		t.Errorf("Run() вернулся через %v — раньше, чем истёк GracePeriod (100ms); "+
			"опрос не должен начинаться до конца grace period", elapsed)
	}
}

// Пока процесс жив, Run() не должен завершаться раньше нескольких тиков — то есть
// вызывающий действительно ОПРАШИВАЕТ с заданным интервалом, а не выходит по первому
// же тику независимо от результата.
func TestRun_PollsRepeatedly_UntilDeathAfterNTicks(t *testing.T) {
	origGOOS := watchdogGOOS
	origKill := killCheckFn
	defer func() { watchdogGOOS = origGOOS; killCheckFn = origKill }()

	watchdogGOOS = "linux"
	const deathAfterCalls = 5
	var calls int64
	killCheckFn = func(pid int) error {
		n := atomic.AddInt64(&calls, 1)
		if n < deathAfterCalls {
			return nil // жив
		}
		return errors.New("dead") // умер на N-й проверке
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := Run(ctx, Config{
		PID:       999,
		PollEvery: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("expected nil after target dies, got %v", err)
	}
	if got := atomic.LoadInt64(&calls); got < deathAfterCalls {
		t.Errorf("killCheckFn вызван %d раз, ожидалось минимум %d (Run вернулся слишком рано)", got, deathAfterCalls)
	}
}

// ctx отменяется НЕ сразу и не во время grace period, а уже в процессе штатного опроса
// живого процесса — Run обязан вернуть ctx.Err(), а не зависнуть/вернуть nil.
func TestRun_CtxCancelled_DuringPolling(t *testing.T) {
	origGOOS := watchdogGOOS
	origKill := killCheckFn
	defer func() { watchdogGOOS = origGOOS; killCheckFn = origKill }()

	watchdogGOOS = "linux"
	killCheckFn = func(pid int) error { return nil } // всегда жив — Run сам никогда не завершится

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(60 * time.Millisecond) // несколько тиков PollEvery=10ms успеют пройти
		cancel()
	}()

	start := time.Now()
	err := Run(ctx, Config{PID: 1, PollEvery: 10 * time.Millisecond})
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("ожидалась context.Canceled, получено: %v", err)
	}
	if elapsed < 60*time.Millisecond {
		t.Errorf("Run() вернулся через %v раньше отмены ctx (60ms) — вышел не по отмене", elapsed)
	}
}

// Дефолт PollEvery=750ms (PollEvery<=0) обязан реально применяться: если ctx истекает
// раньше первого тика гипотетического короткого интервала, Run не должен успеть
// заметить смерть процесса до истечения ctx. Не ждём реальные 750ms — используем
// заведомо мёртвый PID и короткий ctx-таймаут: если бы дефолт был, скажем, 1ms,
// isPIDAlive успел бы отработать и Run() вернул бы nil ДО истечения ctx.
func TestRun_DefaultPollEvery_NotFaster(t *testing.T) {
	origGOOS := watchdogGOOS
	origKill := killCheckFn
	defer func() { watchdogGOOS = origGOOS; killCheckFn = origKill }()

	watchdogGOOS = "linux"
	killCheckFn = func(pid int) error { return errors.New("dead") } // мёртв, но тикер ещё не сработал

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	err := Run(ctx, Config{PID: 1, PollEvery: 0}) // 0 -> дефолт 750ms
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("при дефолтном PollEvery=750ms короткий ctx (30ms) обязан истечь первым, получено: %v", err)
	}
}

// ── isPIDAlive (windows): совпадение по подстроке PID не ловит "соседей" ──────

func TestIsPIDAlive_Windows_NoFalsePositiveOnAdjacentNumber(t *testing.T) {
	origTasklist := runTasklist
	origGOOS := watchdogGOOS
	defer func() { runTasklist = origTasklist; watchdogGOOS = origGOOS }()

	watchdogGOOS = "windows"
	// Строка содержит "1234" (другой процесс), но НЕ "123" в виде отдельного,
	// окружённого пробелами токена — isPIDAlive(123) обязан вернуть false, а не
	// среагировать на то, что "123" — префикс "1234".
	runTasklist = func(pid int) ([]byte, error) {
		return []byte("Image Name   PID Session Name  Mem Usage\r\n" +
			"other.exe    1234 Console         10,000 K\r\n"), nil
	}

	alive, err := isPIDAlive(123)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alive {
		t.Error("PID 123 не должен считаться живым из-за совпадения с префиксом чужого PID 1234")
	}
}

func TestIsPIDAlive_Windows_ExactMatch(t *testing.T) {
	origTasklist := runTasklist
	origGOOS := watchdogGOOS
	defer func() { runTasklist = origTasklist; watchdogGOOS = origGOOS }()

	watchdogGOOS = "windows"
	runTasklist = func(pid int) ([]byte, error) {
		return []byte("Image Name   PID Session Name  Mem Usage\r\n" +
			"apf.exe      123 Console         10,000 K\r\n"), nil
	}

	alive, err := isPIDAlive(123)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !alive {
		t.Error("PID 123 присутствует в выводе tasklist как отдельный токен — должен считаться живым")
	}
}
