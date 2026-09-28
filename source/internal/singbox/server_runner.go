package singbox

import (
	"context"
	"errors"
)

// ErrNotImplemented — явный отказ вместо тихой заглушки, которая выглядит как успех
// (тот же fail-safe принцип, что и в остальном APF). Возвращается ЛЮБЫМ методом
// stubServerRunner — до тех пор, пока платформенная реализация не заменит заглушку
// (Э-Выход-2 — Android, Э-Выход-3 — Linux; Windows уже заменена, см. NewWindowsServerRunner
// в windows_server_runner.go, Э-Выход-1).
var ErrNotImplemented = errors.New("singbox: ServerRunner ещё не реализован для этой платформы (см. docs/TZ_APF_VHOD_VYHOD_v1.0.md §10)")

// ServerRunner — серверная сторона протокола (роль «Выход»/«Транзит»,
// docs/TZ_APF_VHOD_VYHOD_v1.0.md §1, §2). Симметричен клиентскому Runner (runner.go): тот
// запускает sing-box как ИСХОДЯЩЕЕ подключение к чужому серверу, этот — как ВХОДЯЩЕЕ,
// принимающее чужие подключения. Форма методов зеркалит Runner нарочно (IsInstalled/
// Version/WriteConfig/Start/Stop/IsRunning) — тот же жизненный цикл процесса sing-box,
// другая форма конфигурации (ServerDoc, не Config — см. server_config.go, почему).
//
// Reload у клиента нет аналога: у сервера нет «текущего узла», который нужно менять на
// лету — вместо этого GenerateIdentity, одноразовое действие при первом запуске роли
// (ТЗ §2 — «у каждого звена цепочки свой независимый ключ»), не при каждом подключении.
type ServerRunner interface {
	// IsInstalled сообщает, есть ли чем запускать sing-box.
	IsInstalled() bool
	// Version возвращает версию установленного sing-box.
	Version() (string, error)
	// GenerateIdentity генерирует новый независимый ключ звена (UUID, Reality-keypair,
	// short_id). Одноразовое действие — вызывающая сторона сохраняет результат и передаёт
	// его в BuildServerConfig/BuildServerLink на каждом следующем запуске.
	GenerateIdentity() (ServerIdentity, error)
	// WriteConfig фиксирует конфигурацию для следующего Start.
	WriteConfig(doc *ServerDoc) error
	// Start поднимает sing-box по записанной конфигурации.
	Start(ctx context.Context) error
	// Stop останавливает сервер. Идемпотентен: повторный вызов не ошибка.
	Stop() error
	// IsRunning сообщает текущее состояние.
	IsRunning() bool
}

// stubServerRunner — заглушка для платформ, где ещё нет реализации (Android — Э-Выход-2,
// Linux — Э-Выход-3). IsRunning возвращает false честно (ничего не запускалось), а не
// ошибку — это запрос состояния, а не действие.
type stubServerRunner struct{}

// NewServerRunner возвращает заглушку ServerRunner — плейсхолдер для платформ, для которых
// ещё нет реализации. Windows уже собирается по-настоящему через NewWindowsServerRunner.
func NewServerRunner() ServerRunner { return &stubServerRunner{} }

func (*stubServerRunner) IsInstalled() bool        { return false }
func (*stubServerRunner) Version() (string, error) { return "", ErrNotImplemented }
func (*stubServerRunner) GenerateIdentity() (ServerIdentity, error) {
	return ServerIdentity{}, ErrNotImplemented
}
func (*stubServerRunner) WriteConfig(*ServerDoc) error { return ErrNotImplemented }
func (*stubServerRunner) Start(context.Context) error  { return ErrNotImplemented }
func (*stubServerRunner) Stop() error                  { return ErrNotImplemented }
func (*stubServerRunner) IsRunning() bool              { return false }

var _ ServerRunner = (*stubServerRunner)(nil)
