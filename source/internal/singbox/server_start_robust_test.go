package singbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Живой случай 2026-09-29 (ПК владельца, процессор занят на 100% чужими процессами): порт
// sing-box роли «Выход» открывался от 3 до 48 с, три запуска подряд упирались в срок 30 с;
// причина отказа нигде не писалась (OnLog процесса роли не был подключён), а каждая неудачная
// попытка оставляла в брандмауэре лишнее правило. Тесты фиксируют исправления.

// Срок роли «Выход» больше общего клиентского и не меньше двух минут.
func TestNewWindowsServerRunner_HasLongReadyTimeoutAndLogger(t *testing.T) {
	dir := t.TempDir()
	r := NewWindowsServerRunner(dir, dir).(*windowsServerRunner)
	if r.proc.readyTimeout != serverRoleReadyTimeout {
		t.Errorf("readyTimeout процесса роли = %s, ожидался serverRoleReadyTimeout = %s", r.proc.readyTimeout, serverRoleReadyTimeout)
	}
	if serverRoleReadyTimeout < 2*time.Minute {
		t.Errorf("serverRoleReadyTimeout = %s: меньше двух минут — на загруженном ПК запуск снова будет обрезаться", serverRoleReadyTimeout)
	}
	if serverRoleReadyTimeout <= ReadyTimeout {
		t.Errorf("срок роли (%s) должен быть больше клиентского (%s)", serverRoleReadyTimeout, ReadyTimeout)
	}

	var lines []string
	r.SetLogger(func(s string) { lines = append(lines, s) })
	r.proc.captureOutput("[sing-box] FATAL проба")
	if len(lines) != 1 || !strings.Contains(lines[0], "FATAL проба") {
		t.Errorf("вывод sing-box роли не дошёл до журнала: %v", lines)
	}
}

// Собственный срок процесса перекрывает общий ReadyTimeout — в обе стороны.
func TestAwaitReady_PerProcessTimeoutOverridesGlobal(t *testing.T) {
	restoreProbe, restoreSleep, restoreTimeout, restoreNow := readyProbeFn, startSleepFn, ReadyTimeout, timeNowFn
	defer func() {
		readyProbeFn, startSleepFn, ReadyTimeout, timeNowFn = restoreProbe, restoreSleep, restoreTimeout, restoreNow
	}()
	// Виртуальные часы: каждый вызов sleep двигает время на срок опроса.
	clock := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	timeNowFn = func() time.Time { return clock }
	startSleepFn = func(d time.Duration) { clock = clock.Add(d) }

	// 1) Общий срок огромный, у процесса маленький — процесс сдаётся по своему сроку.
	ReadyTimeout = time.Hour
	readyProbeFn = func(int) error { return errors.New("connection refused") }
	p := &Process{readyPort: 10808, running: true, exitCh: make(chan struct{}), readyTimeout: 500 * time.Millisecond}
	err := p.awaitReady(context.Background())
	if !errors.Is(err, ErrReadyTimeout) {
		t.Fatalf("при собственном сроке 500 мс ожидался ErrReadyTimeout: %v", err)
	}
	if !strings.Contains(err.Error(), "500ms") {
		t.Errorf("в тексте ошибки должен быть собственный срок процесса (500ms): %v", err)
	}
	if !strings.Contains(err.Error(), "антивирус") {
		t.Errorf("в тексте ошибки нет подсказки про нагрузку/антивирус: %v", err)
	}

	// 2) Общий срок крошечный, у процесса большой — порт открывается на 40-й «секунде», и
	// процесс успевает (общий срок его бы обрезал).
	ReadyTimeout = 10 * time.Millisecond
	start := clock
	readyProbeFn = func(int) error {
		if clock.Sub(start) >= 40*time.Second {
			return nil
		}
		return errors.New("connection refused")
	}
	p2 := &Process{readyPort: 10808, running: true, exitCh: make(chan struct{}), readyTimeout: 120 * time.Second}
	if err := p2.awaitReady(context.Background()); err != nil {
		t.Fatalf("процесс со сроком 120 с должен дождаться порта на 40-й секунде: %v", err)
	}
}

func TestLastOutputLine(t *testing.T) {
	if got := lastOutputLine(nil); got != "" {
		t.Errorf("пустой вывод = %q, ожидалась пустая строка", got)
	}
	lines := []string{
		"[sing-box] \x1b[36mINFO\x1b[0m[0000] начало",
		"[sing-box] \x1b[31mFATAL\x1b[0m[0002] initialize inbound[0]: invalid private key",
		"   ",
		"",
	}
	got := lastOutputLine(lines)
	if strings.Contains(got, "\x1b") {
		t.Errorf("остались ANSI-коды: %q", got)
	}
	if !strings.Contains(got, "invalid private key") || !strings.HasPrefix(got, "FATAL") {
		t.Errorf("lastOutputLine = %q, ожидалась последняя непустая строка без префикса [sing-box]", got)
	}
	long := []string{strings.Repeat("я", 500)}
	if r := []rune(lastOutputLine(long)); len(r) > 302 {
		t.Errorf("длинная строка не обрезана: %d рун", len(r))
	}
}

// Сообщение о раннем выходе содержит саму причину (а не отсылку к журналу).
func TestEarlyExit_MessageCarriesReason(t *testing.T) {
	p := &Process{running: true, exitCh: make(chan struct{})}
	p.captureOutput("[sing-box] \x1b[31mFATAL\x1b[0m[0002] initialize inbound[0]: invalid private key")
	err := p.earlyExitLocked()
	if err == nil || !strings.Contains(err.Error(), "invalid private key") {
		t.Fatalf("причина отказа sing-box потерялась в сообщении: %v", err)
	}
	if strings.Contains(err.Error(), "выше по журналу") {
		t.Errorf("осталась отсылка «выше по журналу», которая вела в пустоту: %v", err)
	}
	if !errors.Is(err, ErrConfigRejected) {
		t.Errorf("FATAL про inbound должен классифицироваться как отказ конфигурации: %v", err)
	}
	// Без вывода — прежний общий текст, без паники.
	p2 := &Process{running: true, exitCh: make(chan struct{})}
	if err := p2.earlyExitLocked(); err == nil || !strings.Contains(err.Error(), "завершился сразу после запуска") {
		t.Errorf("без вывода ожидался общий текст: %v", err)
	}
}

// Неудачный Start() не оставляет в брандмауэре правило, заведённое под эту попытку.
func TestWindowsServerRunner_FailedStart_RemovesFirewallRule(t *testing.T) {
	orig := execCommandFn
	var calls []string
	execCommandFn = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		return nil, nil
	}
	t.Cleanup(func() { execCommandFn = orig })

	dir := t.TempDir()
	binName := "sing-box"
	if runtime.GOOS == "windows" {
		binName = "sing-box.exe"
	}
	// «Бинарник» — не исполняемый файл: запуск гарантированно отказывает.
	if err := os.WriteFile(filepath.Join(dir, binName), []byte("stub"), 0755); err != nil {
		t.Fatal(err)
	}
	r := NewWindowsServerRunner(dir, dir)
	if err := r.WriteConfig(BuildServerConfig(testIdentity(t), 28443, "www.microsoft.com")); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	if err := r.Start(context.Background()); err == nil {
		t.Skip("stub-файл неожиданно запустился как процесс — тест неприменим на этой платформе")
	}
	if len(calls) < 2 {
		t.Fatalf("ожидалось add и затем delete правила файрвола, вызовов: %d (%v)", len(calls), calls)
	}
	if !strings.Contains(calls[0], "add") {
		t.Errorf("первый вызов netsh должен заводить правило: %q", calls[0])
	}
	last := calls[len(calls)-1]
	if !strings.Contains(last, "delete") || !strings.Contains(last, serverRoleFirewallRuleName) {
		t.Errorf("после отказа Start() правило не снято: последний вызов %q", last)
	}
}
