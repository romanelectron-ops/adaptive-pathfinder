package main

// S-8/S-9 (ТЗ v1.4, лот L1b-CLI).
//
// S-9: watchdogCmd.RunE выходил по голому `return err` на watchdog.ErrCheckUnavailable, минуя
// writeWatchdogEvent — единственная из четырёх исходных веток, которая молчала (см.
// handleWatchdogRunErr в main.go). Тест-до: TestPre_S9_* — красный ДО извлечения
// handleWatchdogRunErr/добавления записи события (символ handleWatchdogRunErr ещё не
// существовал — компиляция сама по себе была невозможна, тот же приём, что и в L1-WEB для
// полностью нового поведения).
//
// S-8: web.Server.Close() (K2-W) не вызывался владельцем процесса — тест на инжектируемый шов
// stopAPF (webCloser/engineStopper), без реального HTTP-сервера/сигналов ОС (правило лота).

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/watchdog"
)

// withTempDataDir — тесты пишут файлы событий watchdog через config.DataDir(); подменяем на
// временный каталог швом config.SetDataDirOverride, чтобы не трогать реальный %APPDATA%\APF
// машины (правило лота).
func withTempDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	config.SetDataDirOverride(dir)
	t.Cleanup(func() { config.SetDataDirOverride("") })
	return dir
}

func readWatchdogEventFile(t *testing.T, dir string) map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, watchdogEventFile))
	if err != nil {
		t.Fatalf("watchdog_last_event.json не создан: %v", err)
	}
	var event map[string]interface{}
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatalf("watchdog_last_event.json: разбор: %v", err)
	}
	return event
}

// TestS9_ErrCheckUnavailable_WritesCheckUnavailableEvent — S-9: ErrCheckUnavailable обязан
// дать запись event="check_unavailable", reset_done=false, с PID и текстом ошибки (число
// неудачных проверок embedded в тексте internal/watchdog — см. parseConsecutiveCheckErrors).
func TestS9_ErrCheckUnavailable_WritesCheckUnavailableEvent(t *testing.T) {
	dir := withTempDataDir(t)

	simulatedErr := fmt.Errorf("%w: PID %d, %d неудачных проверок подряд, последняя: %v",
		watchdog.ErrCheckUnavailable, 4242, 8, errors.New("exec: \"sh\": executable file not found in $PATH"))

	got := handleWatchdogRunErr(simulatedErr, 4242)
	if !errors.Is(got, watchdog.ErrCheckUnavailable) {
		t.Fatalf("handleWatchdogRunErr обязан вернуть исходную ошибку неизменной, получено: %v", got)
	}

	event := readWatchdogEventFile(t, dir)
	if event["event"] != "check_unavailable" {
		t.Fatalf(`event["event"] = %v, ожидалось "check_unavailable"`, event["event"])
	}
	if resetDone, ok := event["reset_done"].(bool); !ok || resetDone {
		t.Fatalf(`event["reset_done"] = %v, ожидалось false`, event["reset_done"])
	}
	if pid, ok := event["pid"].(float64); !ok || int(pid) != 4242 {
		t.Fatalf(`event["pid"] = %v, ожидалось 4242`, event["pid"])
	}
	errText, _ := event["error"].(string)
	if errText == "" {
		t.Fatal(`event["error"] пуст — текст ошибки (с числом неудачных проверок) потерян`)
	}
	if n, ok := event["consecutive_errors"].(float64); !ok || int(n) != 8 {
		t.Fatalf(`event["consecutive_errors"] = %v, ожидалось 8`, event["consecutive_errors"])
	}
}

// TestS9_NilErr_NoEventWritten — стойкость: nil-ошибка (успешный Run) не должна писать
// событие вообще (это не входит в контракт S-9 — обычные ветки normal_shutdown/
// crash_reset_done/crash_reset_failed пишут события сами в watchdogCmd.RunE).
func TestS9_NilErr_NoEventWritten(t *testing.T) {
	dir := withTempDataDir(t)
	if err := handleWatchdogRunErr(nil, 123); err != nil {
		t.Fatalf("nil на входе обязан вернуть nil, получено: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, watchdogEventFile)); err == nil {
		t.Fatal("handleWatchdogRunErr(nil, ...) не должен создавать файл события")
	}
}

// TestS9_OtherError_NoCheckUnavailableEvent — стойкость: ctx.Canceled или любая другая ошибка
// (не ErrCheckUnavailable) не должна писать событие check_unavailable — у watchdogCmd.RunE
// для неё нет отдельной ветки события вообще (осталось прежним поведением, вне контракта S-9).
func TestS9_OtherError_NoCheckUnavailableEvent(t *testing.T) {
	dir := withTempDataDir(t)
	other := errors.New("контекст отменён")
	got := handleWatchdogRunErr(other, 555)
	if got != other {
		t.Fatalf("ожидалась исходная ошибка неизменной, получено: %v", got)
	}
	if _, err := os.Stat(filepath.Join(dir, watchdogEventFile)); err == nil {
		t.Fatal("посторонняя ошибка не должна писать check_unavailable событие")
	}
}

// TestS9_ParseConsecutiveCheckErrors_UnknownFormat_ReturnsZero — стойкость: если текст ошибки
// когда-нибудь перестанет совпадать с форматом internal/watchdog, парсер не паникует и не
// врёт — 0, а не мусорное число.
func TestS9_ParseConsecutiveCheckErrors_UnknownFormat_ReturnsZero(t *testing.T) {
	if n := parseConsecutiveCheckErrors("совершенно другой текст без чисел"); n != 0 {
		t.Fatalf("ожидалось 0, получено %d", n)
	}
}

// ─── S-8 ────────────────────────────────────────────────────────────────────────────────

type fakeWebCloser struct{ closed bool }

func (f *fakeWebCloser) Close() { f.closed = true }

type fakeEngineStopper struct{ stopped bool }

func (f *fakeEngineStopper) Stop() { f.stopped = true }

// TestS8_StopAPF_ClosesWebThenStopsEngine — путь остановки обязан звать web.Server.Close() и
// engine.Stop() (через инжектируемые швы webCloser/engineStopper).
func TestS8_StopAPF_ClosesWebThenStopsEngine(t *testing.T) {
	fc := &fakeWebCloser{}
	fe := &fakeEngineStopper{}
	stopAPF(fc, fe)
	if !fc.closed {
		t.Fatal("stopAPF не вызвал web.Server.Close()")
	}
	if !fe.stopped {
		t.Fatal("stopAPF не вызвал engine.Stop()")
	}
}

// TestS8_StopAPF_NilWebCloser_NoWebUI — --no-webui: closer нетипизированный nil (см.
// runStartFn), stopAPF не должен паниковать и обязан всё равно остановить движок.
func TestS8_StopAPF_NilWebCloser_NoWebUI(t *testing.T) {
	fe := &fakeEngineStopper{}
	stopAPF(nil, fe)
	if !fe.stopped {
		t.Fatal("stopAPF(nil, eng) должен всё равно остановить движок")
	}
}

func TestS8_StopAPF_BothNil_NoPanic(t *testing.T) {
	stopAPF(nil, nil) // не должен паниковать
}
