package singbox

import (
	"context"
	"errors"
	"testing"
)

// Контракт заглушки ServerRunner (платформы без реализации — Android/Linux, Э-Выход-2/3):
// отказывает ЯВНО (ErrNotImplemented), а не тихо «успевает» — иначе вызывающая сторона
// решит, что сервер поднялся, хотя ничего не запускалось.
func TestStubServerRunner_ExplicitlyNotImplemented(t *testing.T) {
	r := NewServerRunner()

	if r.IsInstalled() {
		t.Error("IsInstalled() = true у заглушки")
	}
	if _, err := r.Version(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Version() err = %v, ожидался ErrNotImplemented", err)
	}
	if _, err := r.GenerateIdentity(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("GenerateIdentity() err = %v, ожидался ErrNotImplemented", err)
	}
	if err := r.WriteConfig(&ServerDoc{}); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("WriteConfig() err = %v, ожидался ErrNotImplemented", err)
	}
	if err := r.Start(context.Background()); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Start() = %v, ожидался ErrNotImplemented", err)
	}
	if err := r.Stop(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Stop() = %v, ожидался ErrNotImplemented", err)
	}
	if r.IsRunning() {
		t.Error("IsRunning() = true у заглушки, ничего не запускалось")
	}
}
