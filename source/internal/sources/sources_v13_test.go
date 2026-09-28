// sources_v13_test.go — ТЗ v1.3 F4 Stage 0: интервал обновления источника соблюдается и через
// перезапуск/новый менеджер благодаря SourceConfig.LastUpdatedAt.
package sources

import (
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

func TestNeedsUpdate_UsesPersistedTimestamp(t *testing.T) {
	m := New(models.DefaultConfig())
	fresh := models.SourceConfig{ID: "a", AutoUpdate: true, UpdateIntervalHours: 1,
		LastUpdatedAt: time.Now().Add(-10 * time.Minute).Unix()}
	stale := models.SourceConfig{ID: "b", AutoUpdate: true, UpdateIntervalHours: 1,
		LastUpdatedAt: time.Now().Add(-2 * time.Hour).Unix()}
	never := models.SourceConfig{ID: "c", AutoUpdate: true, UpdateIntervalHours: 1}
	zeroInterval := models.SourceConfig{ID: "d", AutoUpdate: true, UpdateIntervalHours: 0,
		LastUpdatedAt: time.Now().Add(-10 * time.Minute).Unix()}
	manual := models.SourceConfig{ID: "e", AutoUpdate: false}

	if m.needsUpdate(fresh) {
		t.Error("свежий (10 мин при интервале 1 ч) не должен обновляться")
	}
	if !m.needsUpdate(stale) {
		t.Error("устаревший (2 ч при интервале 1 ч) должен обновляться")
	}
	if !m.needsUpdate(never) {
		t.Error("никогда не загружавшийся должен обновляться")
	}
	if m.needsUpdate(zeroInterval) {
		t.Error("интервал 0 — не «каждый раз», а минимум 1 ч")
	}
	if m.needsUpdate(manual) {
		t.Error("без auto_update не обновляется")
	}

	// Память менеджера имеет приоритет над персистентным временем.
	m.mu.Lock()
	m.lastUpdate["b"] = time.Now()
	m.mu.Unlock()
	if m.needsUpdate(stale) {
		t.Error("только что загруженный этим менеджером не должен обновляться снова")
	}
	if got := m.LastUpdated(); len(got) != 1 || got["b"].IsZero() {
		t.Errorf("LastUpdated: %v", got)
	}
}
