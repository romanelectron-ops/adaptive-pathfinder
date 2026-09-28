package watchdog

// watchdog_checkerr_test.go — P3 (аудит BLACKBOX_2026-09-07, находка A4/B3 #6):
// `Run` отбрасывал ошибку `isPIDAlive` (`alive, _ := isPIDAlive(...)`), из-за чего «проверить
// живость PID НЕ УДАЛОСЬ» схлопывалось в «процесс мёртв». Этот watchdog — отдельный подпроцесс
// (`apf watchdog --pid`), и его возврат nil означает для `cmd/apf/main.go` ровно одно: APF
// упал, пора звать `killswitch.ResetAll()`. Одна неудачная попытка запустить `tasklist`
// (нехватка ресурсов на создание процесса, переходное состояние сессии, временный отказ
// RPC/WMI) снимала защиту с ЖИВОГО APF.
//
// Различаем три исхода, а не два:
//   (a) проверка удалась, процесс жив   → продолжаем опрос;
//   (b) проверка удалась, процесс мёртв → Run возвращает nil (штатный сигнал «делай reset»);
//   (c) проверку выполнить не удалось   → это НЕ (b): логируем и продолжаем, и лишь после
//       MaxCheckErrors ПОДРЯД неудач сдаёмся с отдельной причиной (ErrCheckUnavailable).
//
// Шов для (c) — единственная ветка isPIDAlive, возвращающая ошибку: windows/tasklist
// (`runTasklist` + `watchdogGOOS`, ими же пользуются watchdog_extra_test.go/extra2/extra3).

import (
	"context"
	"errors"
	"io"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// quietLog глушит стандартный логгер на время теста (Run по контракту сообщает о каждой
// неудачной проверке — в выводе тестов эти строки только мешают).
func quietLog(t *testing.T) {
	t.Helper()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
}

// failingTasklist подменяет проверку PID на всегда-падающую и возвращает счётчик вызовов.
func failingTasklist(t *testing.T) *int64 {
	t.Helper()
	origTasklist := runTasklist
	origGOOS := watchdogGOOS
	t.Cleanup(func() { runTasklist = origTasklist; watchdogGOOS = origGOOS })

	var calls int64
	watchdogGOOS = "windows"
	runTasklist = func(pid int) ([]byte, error) {
		atomic.AddInt64(&calls, 1)
		return nil, errors.New("tasklist: не удалось создать процесс")
	}
	return &calls
}

// (c) ≠ (b): ПЕРВАЯ неудачная проверка не имеет права выглядеть как «процесс завершился».
func TestRun_SingleCheckErrorIsNotTreatedAsDeath(t *testing.T) {
	quietLog(t)
	calls := failingTasklist(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := Run(ctx, Config{PID: 4242, PollEvery: 10 * time.Millisecond})

	if err == nil {
		t.Fatal("Run вернул nil — «проверить не удалось» истолковано как «процесс мёртв»: " +
			"вызывающий (cmd/apf/main.go) снимет Kill Switch с ЖИВОГО APF")
	}
	if n := atomic.LoadInt64(calls); n < 2 {
		t.Errorf("проверка вызвана %d раз — опрос прекратился на первой же ошибке, "+
			"вместо того чтобы попробовать ещё раз", n)
	}
}

// Счётчик неудач обязан обнуляться успешной проверкой: чередование «ошибка / жив» — это
// нестабильная среда, а не смерть процесса, и Run не должен завершаться никогда.
func TestRun_CheckErrorsResetOnSuccessfulCheck(t *testing.T) {
	quietLog(t)
	origTasklist := runTasklist
	origGOOS := watchdogGOOS
	defer func() { runTasklist = origTasklist; watchdogGOOS = origGOOS }()

	var calls int64
	watchdogGOOS = "windows"
	runTasklist = func(pid int) ([]byte, error) {
		if atomic.AddInt64(&calls, 1)%2 == 1 {
			return nil, errors.New("tasklist: временный отказ")
		}
		return []byte("Image Name   PID Session Name  Mem Usage\r\n" +
			"apf.exe      4242 Console         10,000 K\r\n"), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	err := Run(ctx, Config{PID: 4242, PollEvery: 5 * time.Millisecond})

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("при чередовании «отказ проверки / процесс жив» Run обязан просто продолжать "+
			"опрос до отмены ctx, получено: %v (вызовов проверки: %d)", err, atomic.LoadInt64(&calls))
	}
	if n := atomic.LoadInt64(&calls); n < 10 {
		t.Errorf("проверка вызвана всего %d раз за 300мс при интервале 5мс — опрос прерывался", n)
	}
}

// После MaxCheckErrors неудач подряд Run обязан вернуться — но с ОТДЕЛЬНОЙ, различимой
// причиной: не nil («мёртв») и не ctx.Err() («свернули снаружи»).
func TestRun_GivesUpAfterConfiguredConsecutiveErrors(t *testing.T) {
	quietLog(t)
	calls := failingTasklist(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := Run(ctx, Config{PID: 4242, PollEvery: time.Millisecond, MaxCheckErrors: 3})

	if !errors.Is(err, ErrCheckUnavailable) {
		t.Fatalf("после 3 неудачных проверок подряд ожидалась ErrCheckUnavailable, получено: %v", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Error("причина неотличима от отмены контекста")
	}
	if n := atomic.LoadInt64(calls); n != 3 {
		t.Errorf("проверка вызвана %d раз, ожидалось ровно MaxCheckErrors=3", n)
	}
}

// Дефолт MaxCheckErrors применяется, когда он не задан явно (0), и он именно
// defaultMaxCheckErrors — не 1 (иначе вернулась бы исходная травма) и не бесконечность.
func TestRun_DefaultMaxCheckErrorsApplied(t *testing.T) {
	quietLog(t)
	calls := failingTasklist(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := Run(ctx, Config{PID: 4242, PollEvery: time.Millisecond}) // MaxCheckErrors не задан

	if !errors.Is(err, ErrCheckUnavailable) {
		t.Fatalf("ожидалась ErrCheckUnavailable по дефолтному порогу, получено: %v", err)
	}
	if n := atomic.LoadInt64(calls); n != int64(defaultMaxCheckErrors) {
		t.Errorf("проверка вызвана %d раз, ожидался дефолтный порог %d", n, defaultMaxCheckErrors)
	}
}

// Каждая неудачная проверка должна быть ВИДНА (иначе «продолжаем опрос» превращается в
// молчаливое проглатывание ошибки — ровно тот дефект, который чинится).
func TestRun_ReportsEveryFailedCheck(t *testing.T) {
	failingTasklist(t)

	var lines []string
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := Run(ctx, Config{
		PID: 4242, PollEvery: time.Millisecond, MaxCheckErrors: 4,
		OnLog: func(s string) { lines = append(lines, s) },
	})
	if !errors.Is(err, ErrCheckUnavailable) {
		t.Fatalf("ожидалась ErrCheckUnavailable, получено: %v", err)
	}
	if len(lines) != 4 {
		t.Fatalf("в лог ушло %d сообщений, ожидалось по одному на каждую из 4 неудач: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], "1/4") || !strings.Contains(lines[3], "4/4") {
		t.Errorf("сообщения не показывают номер попытки: %v", lines)
	}
}

// Возврат к норме после серии неудач тоже должен быть виден, а счётчик — обнулиться.
func TestRun_ReportsRecoveryAfterFailedChecks(t *testing.T) {
	origTasklist := runTasklist
	origGOOS := watchdogGOOS
	defer func() { runTasklist = origTasklist; watchdogGOOS = origGOOS }()

	var calls int64
	watchdogGOOS = "windows"
	runTasklist = func(pid int) ([]byte, error) {
		switch atomic.AddInt64(&calls, 1) {
		case 1, 2:
			return nil, errors.New("tasklist: временный отказ")
		case 3:
			return []byte("apf.exe      4242 Console         10,000 K\r\n"), nil // снова жив
		default:
			return []byte("INFO: No tasks are running which match the specified criteria."), nil
		}
	}

	var lines []string
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := Run(ctx, Config{
		PID: 4242, PollEvery: time.Millisecond, MaxCheckErrors: 3,
		OnLog: func(s string) { lines = append(lines, s) },
	})
	if err != nil {
		t.Fatalf("две неудачи, затем успех, затем подтверждённая смерть ⇒ ожидался nil, получено: %v", err)
	}
	if len(lines) != 3 {
		t.Fatalf("ожидались 2 сообщения о неудачах + 1 о восстановлении, получено %d: %v", len(lines), lines)
	}
	if !strings.Contains(lines[2], "снова выполняется") {
		t.Errorf("восстановление проверки не отражено в логе: %v", lines)
	}
}

// (b) не сломан: подтверждённая смерть процесса по-прежнему возвращает nil — иначе
// cmd/apf/main.go никогда не восстановит сеть после реального краха APF.
func TestRun_ConfirmedDeathStillReturnsNil(t *testing.T) {
	origTasklist := runTasklist
	origGOOS := watchdogGOOS
	defer func() { runTasklist = origTasklist; watchdogGOOS = origGOOS }()

	watchdogGOOS = "windows"
	runTasklist = func(pid int) ([]byte, error) {
		return []byte("INFO: No tasks are running which match the specified criteria."), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := Run(ctx, Config{PID: 4242, PollEvery: 5 * time.Millisecond}); err != nil {
		t.Fatalf("подтверждённая смерть процесса обязана возвращать nil, получено: %v", err)
	}
}
