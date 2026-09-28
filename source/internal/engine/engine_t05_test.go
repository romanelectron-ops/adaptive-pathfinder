package engine

import (
	"context"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// TestConnectionSuperseded проверяет предикат T-05: UAC-горутина не должна
// включать Kill Switch, если подключение откатилось/остановлено.
func TestConnectionSuperseded(t *testing.T) {
	bg, cancel := context.WithCancel(context.Background())
	e := &Engine{
		state:   &models.ConnectionState{Connected: true},
		ctx:     bg,
		connGen: 5,
	}

	if e.connectionSuperseded(5) {
		t.Error("совпадает поколение и подключено — не должно быть superseded")
	}
	if !e.connectionSuperseded(4) {
		t.Error("несовпадение поколения — должно быть superseded")
	}

	e.state.Connected = false
	if !e.connectionSuperseded(5) {
		t.Error("Connected=false — должно быть superseded")
	}

	e.state.Connected = true
	cancel()
	if !e.connectionSuperseded(5) {
		t.Error("ctx отменён — должно быть superseded даже при совпадении поколения")
	}
}
