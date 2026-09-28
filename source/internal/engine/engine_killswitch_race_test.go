package engine

// engine_killswitch_race_test.go — регресс-тест для находки живого прогона
// 2026-08-19 ([[apf-live-regression-2026-08-19-findings]]): под интенсивной
// параллельной нагрузкой enable_kill_switch терялся из config.json. Причина —
// typed-setter'ы (SetNodeAutoSwitchEnabled, SetCyclicNodeSearch, SetAdBlockProfile,
// SetAntiBlockConfig, AddPaidProvider/RemovePaidProvider) мутировали e.cfg БЕЗ
// e.mu, пока PatchConfig делает marshal(e.cfg)→merge→unmarshal→swap ПОД e.mu —
// классическая гонка lost-update между "мутация на месте" и "снять копию,
// собрать новую, подменить указатель". go test -race обязан поймать это на
// пред-фикс версии кода.

import (
	"sync"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

func TestConcurrentPatchConfigVsTypedSettersPreservesEnableKillSwitch(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	cfg.EnableKillSwitch = true
	e := New(cfg)

	var wg sync.WaitGroup
	const rounds = 200

	wg.Add(4)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			_ = e.PatchConfig(map[string]interface{}{"selection_mode": "balanced"})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			e.SetNodeAutoSwitchEnabled(i%2 == 0)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			e.SetCyclicNodeSearch(i%2 == 0)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			e.SetAntiBlockConfig(i%2 == 0, false, false, "")
		}
	}()
	wg.Wait()

	if got := e.GetConfig().EnableKillSwitch; !got {
		t.Fatalf("EnableKillSwitch lost under concurrent PatchConfig + typed setters: got %v, want true", got)
	}
	t.Log("OK: EnableKillSwitch survives concurrent PatchConfig + typed-setter storm")
}
