package singleinstance

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// uniqueName — имя, гарантированно не пересекающееся с настоящим APF-Engine.
// Ловить в тесте реально запущенную службу пользователя недопустимо.
func uniqueName(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("APF-test-%d-%s", os.Getpid(), strings.ReplaceAll(t.Name(), "/", "-"))
}

// Инвариант R-3.1: одновременно не более ОДНОГО держателя; после Close() имя свободно.
func TestAcquire_SecondCaptureIsBusyAndCloseReleases(t *testing.T) {
	name := uniqueName(t)

	first, err := Acquire(name)
	if err != nil {
		t.Fatalf("первый Acquire: %v", err)
	}

	second, err := Acquire(name)
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("второй Acquire: want ErrAlreadyRunning, got (%v, %v)", second, err)
	}
	if second != nil {
		t.Fatal("при занятом имени Lock обязан быть nil — иначе вызывающий закроет чужое владение")
	}

	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	third, err := Acquire(name)
	if err != nil {
		t.Fatalf("Acquire после освобождения: %v", err)
	}
	defer third.Close()
}

func TestLock_CloseIsIdempotent(t *testing.T) {
	lock, err := Acquire(uniqueName(t))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("первый Close: %v", err)
	}
	// Второй Close не должен ни падать, ни закрывать уже переиспользованный ядром handle.
	if err := lock.Close(); err != nil {
		t.Fatalf("повторный Close: %v", err)
	}
}

func TestLock_ScopeAndNameAreReported(t *testing.T) {
	name := uniqueName(t)
	lock, err := Acquire(name)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer lock.Close()

	if !strings.Contains(lock.Name(), name) {
		t.Errorf("Name() = %q, должно содержать %q", lock.Name(), name)
	}
	switch lock.Scope() {
	case ScopeGlobal, ScopeSession, ScopeFile:
	default:
		t.Errorf("Scope() = %q — неизвестная область", lock.Scope())
	}
}

func TestAcquire_EmptyNameRejected(t *testing.T) {
	lock, err := Acquire("")
	if err == nil {
		lock.Close()
		t.Fatal("пустое имя обязано отвергаться: иначе процессы разъедутся по разным пространствам имён")
	}
	if errors.Is(err, ErrAlreadyRunning) {
		t.Fatal("пустое имя — это ошибка вызова, а не «занято»")
	}
}

// Fail-safe: ErrAlreadyRunning отличим от прочих ошибок, иначе main() не сможет
// отличить «второй экземпляр» (режим наблюдателя) от «механизм недоступен» (fail-open).
func TestErrAlreadyRunning_IsDistinguishable(t *testing.T) {
	if errors.Is(errors.New("boom"), ErrAlreadyRunning) {
		t.Fatal("посторонняя ошибка не должна опознаваться как ErrAlreadyRunning")
	}
}

func TestEngineLockName_IsStable(t *testing.T) {
	// Имя — контракт МЕЖДУ бинарями: рассинхрон здесь молча вернёт C-2.
	if EngineLockName != "APF-Engine" {
		t.Fatalf("EngineLockName = %q, want %q", EngineLockName, "APF-Engine")
	}
}
