//go:build windows

package singleinstance

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// fakeWin подменяет ВСЕ три системных шва разом. Частичная подмена — та самая ошибка,
// из-за которой тест sysproxy однажды пробил барьер hostguard и записал реальный реестр.
type fakeWin struct {
	created  []string         // имена, переданные в CreateMutexW, в порядке вызова
	opened   []string         // имена, переданные в OpenMutexW
	closed   []windows.Handle // закрытые handle
	createFn func(string) (windows.Handle, error)
	openFn   func(string) (windows.Handle, error)
}

func installFakeWin(t *testing.T, f *fakeWin) *fakeWin {
	t.Helper()
	oc, oo, ocl := createMutexFn, openMutexFn, closeHandleFn
	t.Cleanup(func() { createMutexFn, openMutexFn, closeHandleFn = oc, oo, ocl })

	createMutexFn = func(name string) (windows.Handle, error) {
		f.created = append(f.created, name)
		if f.createFn == nil {
			return 0, windows.ERROR_INVALID_FUNCTION
		}
		return f.createFn(name)
	}
	openMutexFn = func(name string) (windows.Handle, error) {
		f.opened = append(f.opened, name)
		if f.openFn == nil {
			return 0, windows.ERROR_FILE_NOT_FOUND
		}
		return f.openFn(name)
	}
	closeHandleFn = func(h windows.Handle) error {
		f.closed = append(f.closed, h)
		return nil
	}
	return f
}

// Позитив: Global\ доступен — берём его и в Local\ не лезем.
func TestAcquire_GlobalSucceeds(t *testing.T) {
	f := installFakeWin(t, &fakeWin{
		createFn: func(string) (windows.Handle, error) { return 42, nil },
	})

	lock, err := Acquire("X")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if lock.Scope() != ScopeGlobal {
		t.Errorf("Scope = %q, want %q", lock.Scope(), ScopeGlobal)
	}
	if lock.Name() != `Global\X` {
		t.Errorf("Name = %q, want %q", lock.Name(), `Global\X`)
	}
	if len(f.created) != 1 {
		t.Errorf("CreateMutexW вызван %d раз(а), ожидался 1: %v", len(f.created), f.created)
	}
	if len(f.opened) != 0 {
		t.Errorf("OpenMutexW вызывать не требовалось: %v", f.opened)
	}
}

// Занято своим же аккаунтом: CreateMutexW отдаёт ВАЛИДНЫЙ handle + ERROR_ALREADY_EXISTS.
// Handle обязан быть закрыт, иначе объект переживёт настоящего владельца.
func TestAcquire_GlobalAlreadyExists(t *testing.T) {
	f := installFakeWin(t, &fakeWin{
		createFn: func(string) (windows.Handle, error) { return 77, windows.ERROR_ALREADY_EXISTS },
	})

	lock, err := Acquire("X")
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("want ErrAlreadyRunning, got (%v, %v)", lock, err)
	}
	if lock != nil {
		t.Fatal("Lock обязан быть nil")
	}
	if len(f.closed) != 1 || f.closed[0] != 77 {
		t.Errorf("handle 77 не закрыт: closed=%v", f.closed)
	}
	if len(f.created) != 1 {
		t.Errorf("после «занято» фолбэк в Local\\ недопустим: created=%v", f.created)
	}
}

// ACCESS_DENIED + объект реально существует ⇒ им владеет другой аккаунт (служба под
// SYSTEM). Это ЗАНЯТО, а не «нет привилегии».
func TestAcquire_GlobalAccessDenied_ObjectExists(t *testing.T) {
	f := installFakeWin(t, &fakeWin{
		createFn: func(string) (windows.Handle, error) { return 0, windows.ERROR_ACCESS_DENIED },
		openFn:   func(string) (windows.Handle, error) { return 55, nil },
	})

	lock, err := Acquire("X")
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("want ErrAlreadyRunning, got (%v, %v)", lock, err)
	}
	if len(f.opened) != 1 || f.opened[0] != `Global\X` {
		t.Errorf("OpenMutexW не спросил про Global\\X: %v", f.opened)
	}
	if len(f.closed) != 1 || f.closed[0] != 55 {
		t.Errorf("handle из OpenMutexW не закрыт: %v", f.closed)
	}
}

// ACCESS_DENIED и на CreateMutexW, и на OpenMutexW: объект есть, просто он чужой. Занято.
func TestAcquire_GlobalAccessDenied_OpenAlsoDenied(t *testing.T) {
	installFakeWin(t, &fakeWin{
		createFn: func(string) (windows.Handle, error) { return 0, windows.ERROR_ACCESS_DENIED },
		openFn:   func(string) (windows.Handle, error) { return 0, windows.ERROR_ACCESS_DENIED },
	})

	if _, err := Acquire("X"); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("want ErrAlreadyRunning, got %v", err)
	}
}

// ACCESS_DENIED, но объекта НЕТ ⇒ у процесса просто нет SeCreateGlobalPrivilege.
// Уходим в сессионное пространство имён и честно сообщаем ослабленную область.
func TestAcquire_NoGlobalPrivilege_FallsBackToSession(t *testing.T) {
	f := installFakeWin(t, &fakeWin{
		createFn: func(name string) (windows.Handle, error) {
			if strings.HasPrefix(name, `Global\`) {
				return 0, windows.ERROR_ACCESS_DENIED
			}
			return 9, nil
		},
		openFn: func(string) (windows.Handle, error) { return 0, windows.ERROR_FILE_NOT_FOUND },
	})

	lock, err := Acquire("X")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if lock.Scope() != ScopeSession {
		t.Errorf("Scope = %q, want %q", lock.Scope(), ScopeSession)
	}
	if lock.Name() != `Local\X` {
		t.Errorf("Name = %q, want %q", lock.Name(), `Local\X`)
	}
	if len(f.created) != 2 {
		t.Errorf("ожидались попытки Global\\ и Local\\: %v", f.created)
	}
}

// Непредвиденная ошибка на Global\ — тоже повод попробовать Local\, а не сдаваться.
func TestAcquire_GlobalUnexpectedError_FallsBackToSession(t *testing.T) {
	installFakeWin(t, &fakeWin{
		createFn: func(name string) (windows.Handle, error) {
			if strings.HasPrefix(name, `Global\`) {
				return 0, windows.ERROR_INVALID_HANDLE
			}
			return 9, nil
		},
	})

	lock, err := Acquire("X")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if lock.Scope() != ScopeSession {
		t.Errorf("Scope = %q, want %q", lock.Scope(), ScopeSession)
	}
}

// Занятость, обнаруженная уже на фолбэке, тоже обязана дойти как ErrAlreadyRunning.
func TestAcquire_SessionAlreadyExists(t *testing.T) {
	installFakeWin(t, &fakeWin{
		createFn: func(name string) (windows.Handle, error) {
			if strings.HasPrefix(name, `Global\`) {
				return 0, windows.ERROR_ACCESS_DENIED
			}
			return 5, windows.ERROR_ALREADY_EXISTS
		},
		openFn: func(string) (windows.Handle, error) { return 0, windows.ERROR_FILE_NOT_FOUND },
	})

	if _, err := Acquire("X"); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("want ErrAlreadyRunning, got %v", err)
	}
}

// Fail-safe: обе попытки сорвались по системной причине ⇒ обычная ошибка (fail-open
// на стороне main), а НЕ ErrAlreadyRunning. Текст обязан назвать обе причины.
func TestAcquire_BothNamespacesFail(t *testing.T) {
	installFakeWin(t, &fakeWin{
		createFn: func(name string) (windows.Handle, error) {
			if strings.HasPrefix(name, `Global\`) {
				return 0, windows.ERROR_ACCESS_DENIED
			}
			return 0, windows.ERROR_NOT_ENOUGH_MEMORY
		},
		openFn: func(string) (windows.Handle, error) { return 0, windows.ERROR_FILE_NOT_FOUND },
	})

	lock, err := Acquire("X")
	if err == nil {
		lock.Close()
		t.Fatal("ожидалась ошибка")
	}
	if errors.Is(err, ErrAlreadyRunning) {
		t.Fatal("системный сбой не должен выдаваться за «уже запущен» — main тогда молча не поднимет движок")
	}
	if !strings.Contains(err.Error(), "Global") || !strings.Contains(err.Error(), "Local") {
		t.Errorf("в ошибке нет обеих причин: %v", err)
	}
}

func TestLock_CloseReleasesHandleOnce(t *testing.T) {
	f := installFakeWin(t, &fakeWin{
		createFn: func(string) (windows.Handle, error) { return 42, nil },
	})

	lock, err := Acquire("X")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	_ = lock.Close()
	_ = lock.Close()

	if len(f.closed) != 1 || f.closed[0] != 42 {
		t.Errorf("CloseHandle вызван %d раз(а) (%v), ожидался ровно один", len(f.closed), f.closed)
	}
}
