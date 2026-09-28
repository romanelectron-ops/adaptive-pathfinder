package engine

import (
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// F-30 — honor закреплённого пользователем узла в ОСНОВНОМ пути авто-выбора
// (selectBestForStrategy / ScanAndConnect), а не только при переключении
// (selectBestExcluding, B-08.4). Закрывает «разрыв» из карты связей: ConnectByID
// ставит pin, но авто-скан раньше его игнорировал и мог молча сменить узел.

func engineForStrategy(nodes ...*models.Node) *Engine {
	return &Engine{
		nodes: nodes,
		cfg:   &models.AppConfig{SelectionMode: "balanced"},
		state: &models.ConnectionState{},
	}
}

// (1) Позитив: pinned-узел среди активных кандидатов возвращается, даже если по
// score он хуже другого. Pin-проверка выполняется ДО скоринга → детерминирована.
// ТЗ v1.3 F1.5: узлы тестов помечены проверенными (Status=ok) — непроверенные (IsUnchecked)
// в выбор больше не попадают вовсе.
func TestSelectBestForStrategy_HonorsPin(t *testing.T) {
	fast := &models.Node{ID: "fast", Name: "fast", Latency: 10, Protocol: "vless-reality", Status: models.StatusOK}
	slow := &models.Node{ID: "slow", Name: "slow", Latency: 900, Protocol: "ss", Status: models.StatusOK}
	e := engineForStrategy(fast, slow)

	e.PinNode("slow")
	if got := e.selectBestForStrategy(); got == nil || got.ID != "slow" {
		t.Fatalf("pinned 'slow' must win regardless of score, got %v", got)
	}
}

// (4) Инвариант: pin == "" → поведение прежнее (выбор по score, не nil).
func TestSelectBestForStrategy_NoPin_ReturnsCandidate(t *testing.T) {
	a := &models.Node{ID: "a", Latency: 20, Protocol: "vless-reality", Status: models.StatusOK}
	b := &models.Node{ID: "b", Latency: 50, Protocol: "trojan", Status: models.StatusOK}
	e := engineForStrategy(a, b)
	if got := e.selectBestForStrategy(); got == nil {
		t.Fatal("no-pin path must return a candidate")
	}
}

// (3) Fail-safe: pin указывает на отсутствующий узел → откат к выбору по score
// (не nil при наличии кандидатов, не паника).
func TestSelectBestForStrategy_PinMissing_FallsBack(t *testing.T) {
	a := &models.Node{ID: "a", Latency: 20, Protocol: "vless-reality", Status: models.StatusOK}
	e := engineForStrategy(a)
	e.PinNode("ghost")
	if got := e.selectBestForStrategy(); got == nil {
		t.Fatal("missing pin must fall back to score-based selection")
	}
}

// (3) Fail-safe: пустой пул → nil (не паника).
func TestSelectBestForStrategy_EmptyPool(t *testing.T) {
	e := engineForStrategy()
	if got := e.selectBestForStrategy(); got != nil {
		t.Fatalf("empty pool must return nil, got %v", got)
	}
}
