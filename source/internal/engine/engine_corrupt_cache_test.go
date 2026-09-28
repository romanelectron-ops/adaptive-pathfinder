package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// P0-9 (аудит 2026-09-01): повреждённый кэш узлов не должен ронять приложение.
//
// `[null]` в nodes_cache.json разбирается в []*models.Node БЕЗ ошибки, давая nil-указатель.
// Раньше loadNodes сразу делал `n.FailCount = 0` — паника. На Android эта паника убивает
// процесс приложения целиком, а loadNodes вызывается из Engine.Start() → androidbridge.Init()
// → APFVpnService.onCreate(): APF падал бы при КАЖДОМ запуске навсегда, до переустановки.
// Дефект самоподдерживающийся — файл пишет сам APF.

func TestLoadNodes_NullEntriesDoNotPanic(t *testing.T) {
	cases := []struct {
		name    string
		content string
		wantOK  int // сколько валидных узлов должно уцелеть
	}{
		{"только null", `[null]`, 0},
		{"null в начале", `[null,{"id":"a","protocol":"vless","address":"1.1.1.1","port":443}]`, 1},
		{"null в конце", `[{"id":"a","protocol":"vless","address":"1.1.1.1","port":443},null]`, 1},
		{"null в середине", `[{"id":"a","protocol":"vless","address":"1.1.1.1","port":443},null,` +
			`{"id":"b","protocol":"vless","address":"2.2.2.2","port":443}]`, 2},
		{"несколько null", `[null,null,null]`, 0},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(config.DataDir(), "nodes_cache.json")
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			if err := os.WriteFile(path, []byte(c.content), 0600); err != nil {
				t.Fatalf("запись кэша: %v", err)
			}
			t.Cleanup(func() { os.Remove(path) })

			cfg := models.DefaultConfig()
			cfg.AutoConnect = false
			cfg.EnableKillSwitch = false
			e := New(cfg)

			// Главное: не паникует.
			if err := e.loadNodes(); err != nil {
				t.Fatalf("loadNodes вернул ошибку на кэше %q: %v", c.content, err)
			}

			e.mu.RLock()
			got := len(e.nodes)
			hasNil := false
			for _, n := range e.nodes {
				if n == nil {
					hasNil = true
				}
			}
			e.mu.RUnlock()

			if hasNil {
				t.Error("после loadNodes в пуле остался nil-узел — паника только отложена")
			}
			if got != c.wantOK {
				t.Errorf("уцелело узлов %d, ожидалось %d — валидные записи не должны теряться "+
					"из-за соседних повреждённых", got, c.wantOK)
			}

			// Потребители, которые раньше падали на nil (в том числе через Android-мост).
			_ = e.GetStats()
			for _, n := range e.GetNodes() {
				if n == nil {
					t.Error("GetNodes вернул nil-элемент — GetNodesJSON на Android упадёт")
				}
			}
		})
	}
}

// P0-9: запись кэша атомарна — прерывание не оставляет усечённый файл.
func TestSaveNodes_IsAtomic(t *testing.T) {
	path := filepath.Join(config.DataDir(), "nodes_cache.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Cleanup(func() { os.Remove(path); os.Remove(path + ".tmp") })

	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	cfg.EnableKillSwitch = false
	e := New(cfg)
	e.mu.Lock()
	// N-5 (ТЗ APF v1.5): saveNodesToDisk теперь фильтрует на запись — удерживаются только
	// proven-fresh/manual/chain-partner/pinned/favorite (nodes_retention.go). Этот тест проверяет
	// АТОМАРНОСТЬ самой записи (temp+rename), а не политику удержания, поэтому фикстура помечена
	// manual (IsUserOwned) — иначе оба узла были бы честно отфильтрованы ДО того, как дошло бы
	// дело до проверки atomicity, и тест сломался бы по причине, к которой не имеет отношения.
	e.nodes = []*models.Node{
		{ID: "a", Protocol: models.ProtoVLESS, Address: "1.1.1.1", Port: 443, Source: "manual"},
		{ID: "b", Protocol: models.ProtoVLESS, Address: "2.2.2.2", Port: 443, Source: "manual"},
	}
	e.mu.Unlock()

	e.saveNodes()

	// Временный файл не должен пережить успешную запись.
	if _, err := os.Stat(path + ".tmp"); err == nil {
		t.Error("после saveNodes остался .tmp — переименование не выполнено")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("чтение кэша: %v", err)
	}
	var back []*models.Node
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("кэш нечитаем после saveNodes: %v", err)
	}
	if len(back) != 2 {
		t.Errorf("в кэше %d узлов, ожидалось 2", len(back))
	}
}
