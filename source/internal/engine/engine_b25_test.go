package engine

import (
	"context"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// B-25 (дефект D20) — post-connect горутины должны учитываться в e.wg и прерывать
// свой стартовый сон по отмене e.ctx, чтобы Stop()/wg.Wait() корректно их дожидался
// и они не переживали движок.

// sleepCtx прерывается отменой ctx (а не висит весь интервал).
func TestSleepCtx_InterruptedByCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{ctx: ctx, cancel: cancel, state: &models.ConnectionState{}, cfg: &models.AppConfig{}}

	cancel() // отменяем заранее
	start := time.Now()
	ok := e.sleepCtx(5 * time.Second)
	elapsed := time.Since(start)

	if ok {
		t.Error("sleepCtx должен вернуть false при отменённом ctx")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("sleepCtx висел %v вместо мгновенного выхода по ctx", elapsed)
	}
}

// sleepCtx досыпает интервал, если ctx не отменён.
func TestSleepCtx_CompletesWhenNotCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := &Engine{ctx: ctx, cancel: cancel, state: &models.ConnectionState{}, cfg: &models.AppConfig{}}

	if !e.sleepCtx(20 * time.Millisecond) {
		t.Error("sleepCtx должен вернуть true, если ctx не отменён")
	}
}

// Главный инвариант B-25: wg-учтённые post-connect горутины завершаются по cancel,
// и wg.Wait() не висит (моделируем реальную остановку движка).
func TestPostConnect_WgTracked_StopDoesNotHang(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{ctx: ctx, cancel: cancel, state: &models.ConnectionState{}, cfg: &models.AppConfig{}}

	// эмулируем запуск post-connect горутин так же, как connectNode: wg.Add + sleepCtx
	for i := 0; i < 3; i++ {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			e.sleepCtx(10 * time.Second) // длинный сон, который должен прерваться
		}()
	}

	cancel() // как Stop()

	done := make(chan struct{})
	go func() { e.wg.Wait(); close(done) }()

	select {
	case <-done:
		// ок: все горутины вышли по ctx, утечки нет
	case <-time.After(2 * time.Second):
		t.Fatal("wg.Wait() завис — post-connect горутины не прервались по ctx (утечка D20)")
	}
}
