package engine

import (
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// Status=ok: ТЗ v1.3 F1.5 — непроверенный узел (IsUnchecked) в выбор не попадает, тестовые
// узлы моделируют уже проверенные.
func nodeWithScore(id string, score float64) *models.Node {
	return &models.Node{ID: id, Name: id, Score: score, Status: models.StatusOK}
}

// B-08.4 — авто-выбор предпочитает закреплённый узел, но не «застревает» на нём,
// если он исключён (только что отказал) или недоступен.
func TestSelectBestExcluding_HonorsPin(t *testing.T) {
	low := nodeWithScore("pinned", 0.10)
	high := nodeWithScore("best", 0.90)
	e := &Engine{nodes: []*models.Node{low, high}, state: &models.ConnectionState{}}

	// (1) без закрепления → лучший по score
	if got := e.selectBestExcluding(nil); got != high {
		t.Errorf("no pin → best, got %v", got)
	}

	// (2) закреплён → закреплённый, даже с меньшим score
	e.PinNode("pinned")
	if got := e.selectBestExcluding(nil); got != low {
		t.Errorf("pinned → pinned node, got %v", got)
	}

	// (3) закреплённый исключён (он же только что отказал) → лучший другой
	if got := e.selectBestExcluding(low); got != high {
		t.Errorf("pinned excluded → best other, got %v", got)
	}

	// (4) закреплён несуществующий/недоступный → лучший
	e.PinNode("ghost")
	if got := e.selectBestExcluding(nil); got != high {
		t.Errorf("pinned absent → best, got %v", got)
	}
}
