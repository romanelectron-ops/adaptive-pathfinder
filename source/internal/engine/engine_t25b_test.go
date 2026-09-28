package engine

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// T-25 (остаток) — goTracked: трекает в wg и НЕ стартует при отменённом ctx.

func TestGoTracked_WaitsForCompletion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{ctx: ctx, cancel: cancel, state: &models.ConnectionState{}, cfg: &models.AppConfig{}}

	var ran int32
	var mu sync.Mutex
	e.goTracked(func() {
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		ran = 1
		mu.Unlock()
	})
	e.wg.Wait() // как Stop() после cancel — но здесь без cancel, ждём завершения
	mu.Lock()
	defer mu.Unlock()
	if ran != 1 {
		t.Error("goTracked-функция не выполнилась")
	}
}

func TestGoTracked_SkipsWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{ctx: ctx, cancel: cancel, state: &models.ConnectionState{}, cfg: &models.AppConfig{}}
	cancel() // ctx уже отменён

	ran := false
	e.goTracked(func() { ran = true })
	e.wg.Wait() // не должно паниковать и не должно висеть
	if ran {
		t.Error("при отменённом ctx goTracked не должен запускать функцию")
	}
}
