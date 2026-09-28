package engine

// FU-2 (ТЗ надёжности, живой прогон 09-14) — emergencySwitch ↔ ScanAndConnect как ЦЕЛЬНЫЕ циклы.
//
// Раньше connCycleActive держал только ScanAndConnect, а emergencySwitch — лишь switching; два
// разных single-flight НЕ исключали друг друга, и аварийное переключение могло влезть в окно вне
// connMu (tryPreferredNodesFirst/runPoolScan идущего скана) → взять свободный connMu и переключить
// узел поверх выбора скана: пинг-понг A↔B, лишние реконнекты (тот же класс дефекта, что P0-1).
// Фикс: emergencySwitch берёт тот же connCycleActive в СВОЕЙ commit-точке (после всех skip-гейтов).
//
// Тест — офлайн, без sing-box/сети (барьер hostguard включён): проверяем оркестрацию защёлки, а не
// реальный туннель. Рецепт достижения commit-пути emergencySwitch взят из
// TestEmergencySwitch_ChainPartner_* (активный узел = партнёр цепочки + SwitchOnlyOnFail=false +
// старый state.Since): после гейта путь короткий и ограниченный (ветка повтора на партнёре), без
// ухода в общий пул/tryFallback/сеть.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

func TestEmergencySwitch_SkipsWhileScanCycleActive(t *testing.T) {
	e := newTestEngine()
	e.cfg.SwitchOnlyOnFail = false

	// Активный узел — партнёр цепочки: пройдя гейт, emergencySwitch идёт короткой веткой партнёра
	// (повтор на нём же, connectNode падает офлайн), НЕ уходя в общий пул/tryFallback.
	partner := &models.Node{ID: "partner-1", Name: "МойПартнёр", Address: "203.0.113.9", Port: 1234, IsChainPartner: true}
	e.mu.Lock()
	e.nodes = []*models.Node{partner}
	e.mu.Unlock()
	e.stateMu.Lock()
	e.state.Since = time.Now().Add(-2 * time.Hour)
	e.state.ActiveNode = partner
	e.stateMu.Unlock()

	var logMu sync.Mutex
	var lines []string
	e.OnLog = func(msg string) { logMu.Lock(); lines = append(lines, msg); logMu.Unlock() }
	getLog := func() string { logMu.Lock(); defer logMu.Unlock(); return strings.Join(lines, "\n") }
	resetLog := func() { logMu.Lock(); lines = nil; logMu.Unlock() }

	// ── Фаза 1: цикл ScanAndConnect идёт (тест держит защёлку) ──────────────────
	// emergencySwitch обязан отступить в своей commit-точке, НЕ дойдя до ветки переключения, и НЕ
	// снимая чужую защёлку.
	if !e.connCycleActive.CompareAndSwap(false, true) {
		t.Fatal("защёлка цикла обязана быть свободна в начале теста")
	}
	e.emergencySwitch()

	if !strings.Contains(getLog(), "цикл подключения (скан) уже идёт") {
		t.Fatalf("FU-2: emergencySwitch не отступил перед идущим циклом ScanAndConnect. Лог:\n%s", getLog())
	}
	if strings.Contains(getLog(), "Партнёр цепочки") {
		t.Fatalf("FU-2: emergencySwitch дошёл до ветки переключения, хотя цикл занят. Лог:\n%s", getLog())
	}
	if !e.connCycleActive.Load() {
		t.Fatal("FU-2: emergencySwitch снял ЧУЖУЮ защёлку идущего цикла (обязан лишь провалить CAS и выйти)")
	}

	// ── Фаза 2: цикл завершился (защёлка свободна) ─────────────────────────────
	// emergencySwitch обязан пройти свой гейт, дойти до ветки переключения и на выходе освободить
	// защёлку своим defer. Ctx отменяем и даём короткий — connectNode(partner) падает мгновенно.
	resetLog()
	e.connCycleActive.Store(false)
	e.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	e.ctx = ctx
	e.cancel = cancel
	defer cancel()

	e.emergencySwitch()

	if strings.Contains(getLog(), "цикл подключения (скан) уже идёт") {
		t.Fatalf("FU-2: при свободной защёлке emergencySwitch не должен отступать по гейту цикла. Лог:\n%s", getLog())
	}
	if !strings.Contains(getLog(), "Партнёр цепочки") {
		t.Fatalf("FU-2: при свободной защёлке emergencySwitch должен был дойти до ветки переключения. Лог:\n%s", getLog())
	}
	if e.connCycleActive.Load() {
		t.Error("FU-2: emergencySwitch не освободил защёлку цикла на выходе (defer не сработал)")
	}
}
