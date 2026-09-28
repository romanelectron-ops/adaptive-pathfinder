package killswitch

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestSentinel_MarkClearWasActive(t *testing.T) {
	dir := t.TempDir()
	SetSentinelDir(dir)
	defer SetSentinelDir("")

	if WasActive() {
		t.Fatal("маркер не должен существовать изначально")
	}
	markActive()
	if !WasActive() {
		t.Fatal("после markActive маркер должен существовать")
	}
	if _, err := os.Stat(filepath.Join(dir, "killswitch.active")); err != nil {
		t.Fatalf("файл маркера отсутствует: %v", err)
	}
	clearActive()
	if WasActive() {
		t.Fatal("после clearActive маркер должен быть удалён")
	}
}

func TestSentinel_RecoverIfNeeded(t *testing.T) {
	dir := t.TempDir()
	SetSentinelDir(dir)
	defer SetSentinelDir("")

	// ResetAll → no-op (неизвестная платформа), чтобы не дёргать netsh/iptables.
	orig := resetGOOS
	resetGOOS = func() string { return "testnoop" }
	defer func() { resetGOOS = orig }()

	if RecoverIfNeeded() {
		t.Error("без маркера восстановление не должно выполняться")
	}
	markActive()
	if !RecoverIfNeeded() {
		t.Error("при наличии маркера должно выполниться восстановление")
	}
	if WasActive() {
		t.Error("после восстановления маркер должен быть снят")
	}
	if RecoverIfNeeded() {
		t.Error("повторный вызов — восстанавливать нечего")
	}
}

// TestSentinel_RecoverIfNeeded_PreservesMarkerOnResetFailure — сквозной регрессионный
// тест P0-4 (sentinel.go): RecoverIfNeeded() дошёл до реального ResetAll(), которая
// на Windows провалилась (нет прав администратора на критическую netsh-команду).
// До фикса resetWindows() (см. reset.go) эта ошибка терялась, ResetAll() всегда
// возвращал nil, и маркер снимался НЕЗАВИСИМО от исхода — то есть P0-4 не мог
// сработать ни при каких обстоятельствах на боевом пути. Тест ловит именно это.
func TestSentinel_RecoverIfNeeded_PreservesMarkerOnResetFailure(t *testing.T) {
	dir := t.TempDir()
	SetSentinelDir(dir)
	defer SetSentinelDir("")

	origGOOS := resetGOOS
	origExec := execCmdFn
	origShow := showInterfacesFn
	origLog := recoverLogf
	defer func() {
		resetGOOS = origGOOS
		execCmdFn = origExec
		showInterfacesFn = origShow
		recoverLogf = origLog
	}()

	resetGOOS = func() string { return "windows" }
	showInterfacesFn = func() ([]byte, error) { return nil, nil }
	execCmdFn = func(name string, args ...string) error {
		for _, a := range args {
			if a == "firewallpolicy" {
				return errors.New("access is denied")
			}
		}
		return nil
	}

	var loggedMsg string
	recoverLogf = func(format string, args ...interface{}) { loggedMsg = fmt.Sprintf(format, args...) }

	markActive()
	if !WasActive() {
		t.Fatal("подготовка теста: маркер должен быть выставлен")
	}

	RecoverIfNeeded()

	if !WasActive() {
		t.Fatal("P0-4 регрессия: маркер снят несмотря на провал ResetAll() — следующий " +
			"запуск не повторит попытку восстановления сети, пользователь останется без интернета")
	}
	if loggedMsg == "" {
		t.Error("ожидалось диагностическое сообщение о неудачном восстановлении (recoverLogf)")
	}
}

func TestSentinel_NoDirIsNoop(t *testing.T) {
	SetSentinelDir("")
	markActive() // не должно паниковать
	if WasActive() {
		t.Error("WasActive должен быть false, когда каталог не задан")
	}
	clearActive()
	if RecoverIfNeeded() {
		t.Error("RecoverIfNeeded должен быть false, когда каталог не задан")
	}
}
