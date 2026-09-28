package main

import (
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// P1 (аудит 2026-09-01, security-раздел, находка №20б). registerEmergencyHotkey()
// регистрируется в startup() ДО a.engine = engine.New(...) — между ними идут
// go ensureServiceStarted() и singleinstance.AcquireEngine() (файловые операции). Если
// аварийный хоткей сработает в этом узком окне, a.remote и a.engine оба nil — раньше
// EmergencyWipe разыменовывал a.engine напрямую и паниковал в потоке цикла сообщений
// хоткея, роняя весь GUI.
func TestEmergencyWipe_NilEngine_ReturnsErrorNotPanic(t *testing.T) {
	a := &App{cfg: models.DefaultConfig()} // engine и remote оба nil — окно между startup() и engine.New()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("EmergencyWipe с nil-движком запаниковал: %v", r)
		}
	}()

	_, err := a.EmergencyWipe(false, "WIPE")
	if err == nil {
		t.Fatal("EmergencyWipe с nil-движком вернул nil ошибку — ожидался явный отказ")
	}
}
