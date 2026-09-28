package engine

import (
	"sync"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/detector"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// B-26 (дефект D20) — доступ к blockageType из нескольких горутин должен идти ТОЛЬКО
// через потокобезопасные аксессоры getBlockageType/setBlockageType под stateMu.
// Тест запускается под `go test -race`; при «сыром» доступе к полю детектор гонок
// зафиксировал бы DATA RACE.

func TestBlockageType_ConcurrentAccess_NoRace(t *testing.T) {
	e := &Engine{
		state: &models.ConnectionState{},
		cfg:   &models.AppConfig{},
	}

	var wg sync.WaitGroup
	const workers = 8
	const iters = 500

	// писатели: чередуют значения типа блокировки
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				e.setBlockageType(detector.BlockageType((seed + i) % 6))
			}
		}(w)
	}
	// читатели
	for r := 0; r < workers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var sink detector.BlockageType
			for i := 0; i < iters; i++ {
				sink = e.getBlockageType()
			}
			_ = sink
		}()
	}
	wg.Wait()

	// финальное значение валидно (0..5)
	if bt := e.getBlockageType(); bt < 0 || bt > 5 {
		t.Errorf("blockageType вне диапазона: %d", bt)
	}
}

// Базовый функциональный контракт аксессоров: что записали — то и прочитали.
func TestBlockageType_SetGet_RoundTrip(t *testing.T) {
	e := &Engine{state: &models.ConnectionState{}, cfg: &models.AppConfig{}}
	for _, bt := range []detector.BlockageType{0, 1, 2, 3, 4, 5} {
		e.setBlockageType(bt)
		if got := e.getBlockageType(); got != bt {
			t.Errorf("set %d → get %d", bt, got)
		}
	}
}
