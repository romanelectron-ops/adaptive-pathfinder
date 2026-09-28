package androidbridge

import (
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/engine"
)

// Контракт AnyLongOpRunning (2026-09-22, LongOpForegroundService).
//
// Вход:      нет.
// Тело:      OR трёх независимых источников — eng.SweepRunning(), eng.NodeCheckStatus().Running,
// пакетный флаг harvestRunning — читается БЕЗ побочных эффектов (никого не запускает и не
// отменяет).
// Выход:     true, если хотя бы одна из трёх длинных операций идёт прямо сейчас.
// Инвариант: при отсутствующем движке (nil) функция не паникует — отвечает по одному лишь
// harvestRunning. На практике этот флаг взводится только вместе с движком (HarvestNow/
// HarvestFromText сами требуют eng != nil), но функция обязана пережить и рассинхронизированное
// состояние, а не ронять приложение.
//
// Тест НЕ поднимает движок (engine.Start()) и не зовёт ни один package-level StartX — значит не
// оставляет фоновых горутин (не нарушает TestZZZ_NoEngineGoroutineLeak, zz_cleanup_v14_test.go).
func TestAnyLongOpRunning_Contract(t *testing.T) {
	if getEngine() != nil {
		t.Skip("движок уже поднят другим тестом — подмена globalEngine небезопасна")
	}

	t.Run("nil engine, харвест не идёт → false", func(t *testing.T) {
		harvestMu.Lock()
		harvestRunning = false
		harvestMu.Unlock()

		if AnyLongOpRunning() {
			t.Fatal("AnyLongOpRunning() = true при отсутствующем движке и харвесте вне работы")
		}
	})

	t.Run("nil engine, харвест идёт → true (флаг харвеста один держит функцию)", func(t *testing.T) {
		harvestMu.Lock()
		harvestRunning = true
		harvestMu.Unlock()
		t.Cleanup(func() {
			harvestMu.Lock()
			harvestRunning = false
			harvestMu.Unlock()
		})

		if !AnyLongOpRunning() {
			t.Fatal("AnyLongOpRunning() = false при harvestRunning=true — LongOpForegroundService " +
				"остановит себя, пока харвест ещё идёт")
		}
	})

	t.Run("движок поднят, но простаивает (не Start()) → false", func(t *testing.T) {
		harvestMu.Lock()
		harvestRunning = false
		harvestMu.Unlock()

		stub := engine.New(androidConfig())
		globalMu.Lock()
		globalEngine = stub
		globalMu.Unlock()
		t.Cleanup(func() {
			globalMu.Lock()
			globalEngine = nil
			globalMu.Unlock()
		})

		if AnyLongOpRunning() {
			t.Fatal("AnyLongOpRunning() = true у свежесозданного (не Start()) движка — " +
				"SweepRunning()/NodeCheckStatus().Running обязаны быть false по умолчанию")
		}
	})
}
