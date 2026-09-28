package singbox

// Контракт классов отказа старта sing-box (TZ_SINGBOX_HOTSWITCH_WINDOWS_v1.0 §8, A1/A4/A5).
//
// Что ловится. Движок штрафовал узел за ЛЮБУЮ ошибку старта — в том числе за то, что ОС
// создавала процесс 30 секунд и порт не открылся за срок (живой лог ПК 2026-09-21, шесть
// невиновных узлов подряд). Эти тесты фиксируют, какие отказы Start помечает локальными
// (узел не судим), а какие — отказом конфигурации узла.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestClassifyEarlyExit(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		want  error
	}{
		{"битый outbound узла", []string{
			"[sing-box] FATAL[0000] create service: initialize outbound[2]: parse reality public key: illegal base64",
		}, ErrConfigRejected},
		{"ошибка разбора поля узла", []string{
			"[sing-box] FATAL[0000] decode config at current.json: outbounds[1].uuid: invalid UUID",
		}, ErrConfigRejected},
		{"занятый порт socks", []string{
			"[sing-box] FATAL[0000] start service: start inbound/socks[socks-in]: listen tcp 127.0.0.1:10808: bind: address already in use",
		}, ErrLocalStart},
		{"занятый порт Windows", []string{
			"[sing-box] FATAL[0000] start service: listen tcp 127.0.0.1:10808: Only one usage of each socket address (protocol/network address/port) is normally permitted.",
		}, ErrLocalStart},
		{"не поднялся TUN", []string{
			"[sing-box] FATAL[0000] start service: start inbound/tun[tun-in]: configure tun interface: Cannot create a file when that file already exists.",
		}, ErrLocalStart},
		{"кэш занят другим экземпляром", []string{
			"[sing-box] FATAL[0000] start service: start cache-file: open cache file: timeout",
		}, ErrLocalStart},
		{"FATAL важнее прочих строк", []string{
			"[sing-box] INFO[0000] outbound/vless[proxy]: initialized",
			"[sing-box] FATAL[0000] start service: start inbound/http[http-in]: listen tcp 127.0.0.1:10809: bind: address already in use",
		}, ErrLocalStart},
		{"нераспознанное — отказ узла, а не зависание", []string{
			"[sing-box] FATAL[0000] something entirely new",
		}, ErrConfigRejected},
		{"пустой вывод — отказ узла", nil, ErrConfigRejected},
	}
	for _, c := range cases {
		if got := classifyEarlyExit(c.lines); got != c.want {
			t.Errorf("%s: classifyEarlyExit = %v, ожидалось %v", c.name, got, c.want)
		}
	}
}

// Текст исходной ошибки не меняется — по нему люди читают журнал.
func TestStartError_KeepsMessageAndChain(t *testing.T) {
	cause := fmt.Errorf("запуск sing-box прерван: %w", context.Canceled)
	err := localStartError(cause)
	if err.Error() != cause.Error() {
		t.Errorf("текст изменён: %q, ожидался %q", err.Error(), cause.Error())
	}
	if !errors.Is(err, ErrLocalStart) {
		t.Error("класс потерян")
	}
	if !errors.Is(err, context.Canceled) {
		t.Error("причина потеряна: движок не отличит свою отмену от сбоя машины")
	}
	if errors.Is(err, ErrConfigRejected) {
		t.Error("локальный сбой одновременно помечен отказом конфигурации")
	}
}

func deadProcessWithOutput(lines ...string) *Process {
	exited := make(chan struct{})
	close(exited)
	p := &Process{readyPort: 1, running: true, exitCh: exited}
	for _, l := range lines {
		p.captureOutput(l)
	}
	return p
}

func TestAwaitReady_EarlyExitOnBusyPortIsLocal(t *testing.T) {
	p := deadProcessWithOutput("[sing-box] FATAL[0000] start service: start inbound/socks[socks-in]: " +
		"listen tcp 127.0.0.1:10808: bind: address already in use")
	err := p.awaitReady(context.Background())
	if err == nil {
		t.Fatal("процесс мёртв, а awaitReady вернул успех")
	}
	if !errors.Is(err, ErrLocalStart) {
		t.Errorf("занятый локальный порт не помечен локальным сбоем: %v", err)
	}
	if !strings.Contains(err.Error(), "завершился") {
		t.Errorf("сообщение не называет причину: %v", err)
	}
}

func TestAwaitReady_EarlyExitOnBadOutboundIsConfigRejected(t *testing.T) {
	p := deadProcessWithOutput("[sing-box] FATAL[0000] create service: initialize outbound[0]: unknown cipher")
	err := p.awaitReady(context.Background())
	if !errors.Is(err, ErrConfigRejected) {
		t.Errorf("отвергнутый outbound узла не помечен отказом конфигурации: %v", err)
	}
	if errors.Is(err, ErrLocalStart) {
		t.Errorf("отказ конфигурации узла помечен локальным: %v", err)
	}
}

func TestAwaitReady_TimeoutIsLocal(t *testing.T) {
	restoreProbe, restoreSleep, restoreTimeout := readyProbeFn, startSleepFn, ReadyTimeout
	defer func() {
		readyProbeFn, startSleepFn, ReadyTimeout = restoreProbe, restoreSleep, restoreTimeout
	}()
	readyProbeFn = func(int) error { return errors.New("connection refused") }
	startSleepFn = func(time.Duration) {}
	ReadyTimeout = 10 * time.Millisecond

	p := &Process{readyPort: 10808, running: true, exitCh: make(chan struct{})}
	err := p.awaitReady(context.Background())
	if !errors.Is(err, ErrLocalStart) {
		t.Errorf("порт не открылся за срок — это сбой машины, а не узла: %v", err)
	}
	if !errors.Is(err, ErrReadyTimeout) {
		t.Errorf("таймаут порта не помечен уточнением ErrReadyTimeout (движку нужно для ротации): %v", err)
	}
	if !strings.Contains(err.Error(), "10808") {
		t.Errorf("текст ошибки потерял номер порта: %v", err)
	}
}

// Уточнение ErrReadyTimeout есть ТОЛЬКО у таймаута порта: у прочих локальных сбоев процесс
// конфиг узла не исполнял, ротировать там нечего.
func TestReadyTimeout_OnlyOnPortTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := &Process{readyPort: 10808, running: true, exitCh: make(chan struct{})}
	if err := p.awaitReady(ctx); errors.Is(err, ErrReadyTimeout) {
		t.Errorf("отмена старта помечена как таймаут порта: %v", err)
	}
	busy := deadProcessWithOutput("[sing-box] FATAL[0000] start service: start inbound/socks[socks-in]: bind: address already in use")
	if err := busy.awaitReady(context.Background()); errors.Is(err, ErrReadyTimeout) {
		t.Errorf("занятый порт помечен как таймаут: %v", err)
	}
}

func TestAwaitReady_CancelIsLocalAndKeepsCause(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := &Process{readyPort: 10808, running: true, exitCh: make(chan struct{})}
	err := p.awaitReady(ctx)
	if !errors.Is(err, ErrLocalStart) || !errors.Is(err, context.Canceled) {
		t.Errorf("отмена старта: ожидались ErrLocalStart и context.Canceled в цепочке, получено %v", err)
	}
}

// Без признака готовности (readyPort=0) умерший за паузу процесс — всё равно отказ: раньше
// его ловил отдельный `sing-box check`, снятый этапом A5.
func TestAwaitReady_NoPortStillCatchesDeadProcess(t *testing.T) {
	restore := startSleepFn
	defer func() { startSleepFn = restore }()
	startSleepFn = func(time.Duration) {}

	exited := make(chan struct{})
	close(exited)
	p := &Process{readyPort: 0, running: true, exitCh: exited}
	p.captureOutput("[sing-box] FATAL[0000] create service: initialize outbound[0]: bad key")
	err := p.awaitReady(context.Background())
	if err == nil {
		t.Fatal("процесс мёртв, а awaitReady без порта вернул успех")
	}
	if !errors.Is(err, ErrConfigRejected) {
		t.Errorf("класс отказа потерян: %v", err)
	}
}

func TestStart_NotInstalledIsLocal(t *testing.T) {
	p := NewProcess("/nonexistent_bin_dir_xyz", os.TempDir())
	err := p.Start(context.Background())
	if !errors.Is(err, ErrLocalStart) {
		t.Errorf("отсутствие бинарника — сбой машины, а не узла: %v", err)
	}
}

// Хвост вывода ограничен: долгоживущий процесс не копит журнал в памяти.
func TestCaptureOutput_TailIsBounded(t *testing.T) {
	p := &Process{}
	for i := 0; i < outTailMax*3; i++ {
		p.captureOutput(fmt.Sprintf("line %d", i))
	}
	tail := p.outTailSnapshot()
	if len(tail) != outTailMax {
		t.Fatalf("len(tail) = %d, ожидалось %d", len(tail), outTailMax)
	}
	if tail[len(tail)-1] != fmt.Sprintf("line %d", outTailMax*3-1) {
		t.Errorf("последняя строка потеряна: %q", tail[len(tail)-1])
	}
	p.resetOutTail()
	if len(p.outTailSnapshot()) != 0 {
		t.Error("resetOutTail не очистил хвост прошлого запуска")
	}
}

// A4: срок ожидания порта покрывает медленный, но живой старт с ПК пользователя (8.76 с после
// PID) с запасом. Возврат к 10 с снова резал бы такие запуски ровно на 10.1 с.
func TestReadyTimeout_CoversSlowWindowsStart(t *testing.T) {
	if ReadyTimeout < 30*time.Second {
		t.Errorf("ReadyTimeout = %s — меньше 30 с, медленные живые старты снова будут обрезаться", ReadyTimeout)
	}
}
