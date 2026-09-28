//go:build windows

package singleinstance

import (
	"errors"
	"fmt"
	"sync"

	"golang.org/x/sys/windows"
)

// Швы для тестов: все три ветки ниже (объект занят / чужой владелец / нет привилегии)
// иначе невоспроизводимы — они требуют второго процесса под другим аккаунтом.
var (
	createMutexFn = func(name string) (windows.Handle, error) {
		p, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return 0, err
		}
		// initialOwner=false: нам нужен сам факт существования объекта, а не владение
		// мьютексом как примитивом синхронизации. Ждать на нём никто не будет.
		return windows.CreateMutex(nil, false, p)
	}
	openMutexFn = func(name string) (windows.Handle, error) {
		p, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return 0, err
		}
		return windows.OpenMutex(windows.SYNCHRONIZE, false, p)
	}
	closeHandleFn = func(h windows.Handle) error { return windows.CloseHandle(h) }
)

// Lock — удерживаемый handle именованного мьютекса. Освобождается при Close() и,
// как страховка от «зависшего» владения после падения процесса, — ядром Windows
// при завершении процесса (объект исчезает, когда закрыт последний handle).
type Lock struct {
	mu    sync.Mutex
	h     windows.Handle
	name  string
	scope Scope
}

// Name — полное имя объекта вместе с префиксом пространства имён.
func (l *Lock) Name() string { return l.name }

// Scope — область действия фактически захваченного взаимоисключения.
func (l *Lock) Scope() Scope { return l.scope }

// Close — освобождение владения. Идемпотентен.
func (l *Lock) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.h == 0 {
		return nil
	}
	h := l.h
	l.h = 0
	return closeHandleFn(h)
}

// Acquire — захват владения именем name.
func Acquire(name string) (*Lock, error) {
	if name == "" {
		return nil, errors.New("singleinstance: пустое имя ресурса")
	}

	globalName := `Global\` + name
	lock, gerr := tryCreateMutex(globalName, ScopeGlobal)
	if gerr == nil {
		return lock, nil
	}
	if errors.Is(gerr, ErrAlreadyRunning) {
		return nil, gerr
	}

	// ERROR_ACCESS_DENIED двузначен, и различить смыслы обязательно:
	//   а) объект существует, но создан под другим аккаунтом (служба под SYSTEM) — ЗАНЯТО;
	//   б) объекта нет, а у процесса просто нет SeCreateGlobalPrivilege — не занято,
	//      надо уходить в сессионное пространство имён.
	// Различаем через OpenMutex: ERROR_FILE_NOT_FOUND ⇒ объекта нет ⇒ случай (б).
	if errors.Is(gerr, windows.ERROR_ACCESS_DENIED) && mutexExists(globalName) {
		return nil, ErrAlreadyRunning
	}

	// Фолбэк. Он СЛАБЕЕ: взаимоисключение действует только внутри сессии входа, поэтому
	// пара «трей в сессии пользователя + служба в сессии 0» им не покрывается. Область
	// возвращается в Lock.Scope(), чтобы вызывающий мог сказать это вслух в логе.
	lock, lerr := tryCreateMutex(`Local\`+name, ScopeSession)
	if lerr == nil {
		return lock, nil
	}
	if errors.Is(lerr, ErrAlreadyRunning) {
		return nil, lerr
	}
	return nil, fmt.Errorf("singleinstance: не удалось захватить %q (Global: %v; Local: %w)",
		name, gerr, lerr)
}

// tryCreateMutex — одна попытка занять конкретное полное имя.
func tryCreateMutex(fullName string, scope Scope) (*Lock, error) {
	h, err := createMutexFn(fullName)
	switch {
	case err == nil:
		return &Lock{h: h, name: fullName, scope: scope}, nil

	case errors.Is(err, windows.ERROR_ALREADY_EXISTS):
		// CreateMutexW при существующем объекте возвращает ВАЛИДНЫЙ handle вместе с
		// ERROR_ALREADY_EXISTS. Не закрыть его — утечка handle и, что хуже, продление
		// жизни объекта: мьютекс не исчезнет даже после выхода настоящего владельца.
		if h != 0 {
			_ = closeHandleFn(h)
		}
		return nil, ErrAlreadyRunning

	default:
		if h != 0 {
			_ = closeHandleFn(h)
		}
		return nil, err
	}
}

// mutexExists — существует ли объект, пусть даже недоступный нам по DACL.
func mutexExists(fullName string) bool {
	h, err := openMutexFn(fullName)
	if err == nil {
		if h != 0 {
			_ = closeHandleFn(h)
		}
		return true
	}
	// Объект есть, но чужой — это тоже «существует».
	return errors.Is(err, windows.ERROR_ACCESS_DENIED)
}
