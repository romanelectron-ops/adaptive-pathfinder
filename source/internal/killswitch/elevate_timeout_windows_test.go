//go:build windows

package killswitch

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// D-35 · Я-31.3 — ожидание дочернего netsh с ТАЙМАУТОМ (вместо WaitForSingleObject INFINITE).

// (fail-safe) Реальный долгоживущий процесс + крошечный таймаут → ErrElevateTimeout, без вечной блокировки.
func TestWaitNetshProcess_Timeout(t *testing.T) {
	cmd := exec.Command("ping", "-n", "4", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Skip("cannot start helper process:", err)
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()

	h, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.SYNCHRONIZE, false, uint32(cmd.Process.Pid))
	if err != nil {
		t.Skip("OpenProcess failed:", err)
	}
	defer windows.CloseHandle(h) //nolint:errcheck

	origTO := elevateWaitTimeout
	defer func() { elevateWaitTimeout = origTO }()
	elevateWaitTimeout = 50 * time.Millisecond

	start := time.Now()
	err = waitNetshProcess(h)
	if !errors.Is(err, ErrElevateTimeout) {
		t.Fatalf("expected ErrElevateTimeout for hung process, got %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("wait blocked too long (%v) — timeout not honored", d)
	}
}

// B-0403 · R-9 (C-17): по таймауту зависший netsh не просто «отпускается» — его пытаются снять.
// Иначе он мог бы доработать ПОЗЖЕ и применить часть правил уже после отката попытки, нарушив
// семантику D-34 «всё или ничего».
func TestWaitNetshProcess_TimeoutTerminatesChild(t *testing.T) {
	cmd := exec.Command("ping", "-n", "4", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Skip("cannot start helper process:", err)
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()

	h, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.SYNCHRONIZE, false, uint32(cmd.Process.Pid))
	if err != nil {
		t.Skip("OpenProcess failed:", err)
	}
	defer windows.CloseHandle(h) //nolint:errcheck

	origTO, origTerm := elevateWaitTimeout, terminateProcessFn
	defer func() { elevateWaitTimeout, terminateProcessFn = origTO, origTerm }()
	elevateWaitTimeout = 50 * time.Millisecond

	terminated := 0
	terminateProcessFn = func(got windows.Handle) error {
		terminated++
		if got != h {
			t.Errorf("снимается не тот процесс: %v вместо %v", got, h)
		}
		return nil
	}

	if err := waitNetshProcess(h); !errors.Is(err, ErrElevateTimeout) {
		t.Fatalf("expected ErrElevateTimeout, got %v", err)
	}
	if terminated != 1 {
		t.Errorf("TerminateProcess вызван %d раз(а), ожидался 1", terminated)
	}
}

// Неудача снятия (типичный случай на UAC-пути: у родителя нет PROCESS_TERMINATE) не должна
// подменять причину — вызывающий обязан по-прежнему видеть именно таймаут.
func TestWaitNetshProcess_TerminateFailureKeepsTimeoutCause(t *testing.T) {
	cmd := exec.Command("ping", "-n", "4", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Skip("cannot start helper process:", err)
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()

	h, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.SYNCHRONIZE, false, uint32(cmd.Process.Pid))
	if err != nil {
		t.Skip("OpenProcess failed:", err)
	}
	defer windows.CloseHandle(h) //nolint:errcheck

	origTO, origTerm := elevateWaitTimeout, terminateProcessFn
	defer func() { elevateWaitTimeout, terminateProcessFn = origTO, origTerm }()
	elevateWaitTimeout = 50 * time.Millisecond
	terminateProcessFn = func(windows.Handle) error { return errors.New("отказано в доступе") }

	err = waitNetshProcess(h)
	if !errors.Is(err, ErrElevateTimeout) {
		t.Fatalf("причина подменена: %v", err)
	}
	if !strings.Contains(err.Error(), "снять процесс не удалось") {
		t.Errorf("в сообщении нет упоминания неудачного снятия: %v", err)
	}
}

// (wiring) shellExecuteNetsh пробрасывает результат ожидания (таймаут) наружу.
func TestShellExecuteNetsh_TimeoutWiring(t *testing.T) {
	origExec, origWait := shellExecExWFn, waitNetshProcessFn
	defer func() { shellExecExWFn, waitNetshProcessFn = origExec, origWait }()

	shellExecExWFn = func(sei *shellExecuteInfo) (uintptr, uintptr, error) {
		sei.hProcess = 0x1 // ненулевой фиктивный хендл → ветка ожидания процесса
		return 1, 0, nil
	}
	waited := false
	waitNetshProcessFn = func(_ windows.Handle) error { waited = true; return ErrElevateTimeout }

	if err := shellExecuteNetsh("/?"); !errors.Is(err, ErrElevateTimeout) {
		t.Fatalf("expected ErrElevateTimeout propagated, got %v", err)
	}
	if !waited {
		t.Error("wait seam was not invoked")
	}
}
