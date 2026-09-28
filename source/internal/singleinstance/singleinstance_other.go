//go:build !windows

package singleinstance

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/apf/adaptive-pathfinder/internal/config"
)

// Швы для тестов: занятость лока другим процессом иначе невоспроизводима в unit-тесте.
var (
	lockDirFn  = config.DataDir
	openFileFn = func(path string) (*os.File, error) {
		return os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	}
	flockFn = func(fd int, how int) error { return syscall.Flock(fd, how) }
)

// Lock — удерживаемый flock. Ядро снимает его при закрытии файла и при завершении
// процесса, поэтому «зависшего» владения после падения не остаётся.
type Lock struct {
	mu    sync.Mutex
	f     *os.File
	name  string
	scope Scope
}

// Name — путь к lock-файлу.
func (l *Lock) Name() string { return l.name }

// Scope — область действия фактически захваченного взаимоисключения.
func (l *Lock) Scope() Scope { return l.scope }

// Close — освобождение владения. Идемпотентен.
func (l *Lock) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	f := l.f
	l.f = nil
	_ = flockFn(int(f.Fd()), syscall.LOCK_UN)
	return f.Close()
}

// Acquire — захват владения именем name.
func Acquire(name string) (*Lock, error) {
	if name == "" {
		return nil, errors.New("singleinstance: пустое имя ресурса")
	}

	dir := lockDirFn()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("singleinstance: каталог данных %q: %w", dir, err)
	}
	path := filepath.Join(dir, name+".lock")

	f, err := openFileFn(path)
	if err != nil {
		return nil, fmt.Errorf("singleinstance: lock-файл %q: %w", path, err)
	}

	// flock(2) считает дескрипторы независимыми даже внутри одного процесса, поэтому
	// повторный Acquire в том же процессе честно упирается в EWOULDBLOCK — ровно то
	// поведение, которое проверяет unit-тест.
	if err := flockFn(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrAlreadyRunning
		}
		return nil, fmt.Errorf("singleinstance: flock %q: %w", path, err)
	}
	return &Lock{f: f, name: path, scope: ScopeFile}, nil
}
