// Package security — фоновый модуль защиты (docs/TZ_APF_VHOD_VYHOD_v1.0.md §8.2, §10
// Этап 0): периодическая проверка конфигурации на типовые слабые места + обнаружение
// аномалий входящих подключений на ролях «Выход»/«Транзит». НЕ чат-бот и не путь данных —
// работает в собственной горутине (ТЗ §11), результат — рапорт, не автоматическое
// изменение конфигурации (проект запрещает молчаливые изменения состояния).
package security

import (
	"context"
	"errors"
	"time"
)

// ErrNotImplemented — явный отказ вместо тихой заглушки (см. singbox.ErrNotImplemented).
var ErrNotImplemented = errors.New("security: Guard ещё не реализован (см. docs/TZ_APF_VHOD_VYHOD_v1.0.md §10, Этап 0)")

// Severity — простая шкала серьёзности находки (ТЗ §8.2: «не CVSS-жаргон»).
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityCritical
)

// Finding — одна находка проверки уязвимостей или обнаружения вторжения (ТЗ §8.2).
type Finding struct {
	Severity       Severity
	Title          string
	Description    string
	Recommendation string
}

// Report — структурированный рапорт (ТЗ §8.2: «что проверено, что нашли, насколько
// серьёзно, что рекомендуется сделать»), не сырой лог.
type Report struct {
	GeneratedAt time.Time
	Findings    []Finding
}

// Guard — интерфейс фонового модуля защиты. Ни один метод не вызывается с пути данных
// туннеля (ТЗ §11) — оба выполняются в собственной горутине с низким приоритетом.
type Guard interface {
	// ScanConfig проверяет текущую конфигурацию роли на типовые слабые места (устаревший
	// sing-box, предсказуемый short_id/UUID, непроброшенный порт без ограничения источника
	// и т.д.). Периодическая операция, не при каждом подключении (ТЗ §8.2).
	ScanConfig(ctx context.Context) (Report, error)
	// WatchConnections начинает фоновый мониторинг входящих подключений на аномалии
	// (перебор аутентификации, нетиповой профиль, всплеск источников) — только для ролей
	// «Выход»/«Транзит» (ТЗ §8.2: «Вход» ничего не принимает, ему нечего обнаруживать).
	// Возвращает канал находок; закрывается при отмене ctx.
	WatchConnections(ctx context.Context) (<-chan Finding, error)
}

// stubGuard — реализация Этапа 0. Настоящая реализация — Э-ИИ-3 (ScanConfig) и
// Э-ИИ-4 (WatchConnections), см. ТЗ §10.
type stubGuard struct{}

// NewGuard возвращает временную (Этап 0) реализацию Guard.
func NewGuard() Guard { return &stubGuard{} }

func (*stubGuard) ScanConfig(context.Context) (Report, error) {
	return Report{}, ErrNotImplemented
}

func (*stubGuard) WatchConnections(context.Context) (<-chan Finding, error) {
	return nil, ErrNotImplemented
}

var _ Guard = (*stubGuard)(nil)
