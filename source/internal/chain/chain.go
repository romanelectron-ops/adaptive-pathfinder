// Package chain моделирует цепочку звеньев «Вход → Транзит* → Выход»
// (docs/TZ_APF_VHOD_VYHOD_v1.0.md §4, §10 Этап 0). Одиночное подключение (сегодняшний
// APF-клиент) — частный случай цепочки длиной 1, не отдельный код: везде, где принят Chain,
// нет ветвления «а если звено одно».
package chain

import (
	"context"
	"errors"
	"time"
)

// ErrNotImplemented — явный отказ вместо тихой заглушки (см. singbox.ErrNotImplemented).
var ErrNotImplemented = errors.New("chain: диагностика цепочки ещё не реализована (см. docs/TZ_APF_VHOD_VYHOD_v1.0.md §10, Этап 0)")

// Link — одно звено цепочки: ссылка подключения к следующему узлу (ТЗ §4).
type Link struct {
	// Label — «Звено 1: Европа» и т.п., для интерфейса (ТЗ §5.3).
	Label string
	// RawLink — vless://... / wireguard://... — то, что уже понимает parser.ParseLink.
	RawLink string
}

// Chain — упорядоченный список звеньев, ближайшее к «Входу» — первое.
type Chain struct {
	Links []Link
}

// HopDiagnostic — результат проверки одного звена (ТЗ §4: «если любое звено отваливается,
// Вход обязан честно показать, на каком именно», не общее «нет связи»).
type HopDiagnostic struct {
	Index   int
	Label   string
	OK      bool
	Latency time.Duration // 0, если OK == false
	Err     error
}

// Diagnoser проверяет цепочку целиком и возвращает результат по каждому звену.
type Diagnoser interface {
	// Diagnose проверяет все звенья ПАРАЛЛЕЛЬНО (ТЗ §11: «диагностика цепочки —
	// параллельно по всем звеньям, не последовательно» — иначе цепочка из 5 звеньев
	// проверялась бы в 5 раз дольше одного). Порядок результатов соответствует c.Links.
	Diagnose(ctx context.Context, c Chain) ([]HopDiagnostic, error)
}

// stubDiagnoser — реализация Этапа 0. Настоящая реализация — Э-Цепочки-2 (ТЗ §10).
type stubDiagnoser struct{}

// NewDiagnoser возвращает временную (Этап 0) реализацию Diagnoser.
func NewDiagnoser() Diagnoser { return &stubDiagnoser{} }

func (*stubDiagnoser) Diagnose(context.Context, Chain) ([]HopDiagnostic, error) {
	return nil, ErrNotImplemented
}

var _ Diagnoser = (*stubDiagnoser)(nil)
