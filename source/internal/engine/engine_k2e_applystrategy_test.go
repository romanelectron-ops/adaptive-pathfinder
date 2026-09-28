// engine_k2e_applystrategy_test.go — К2-E П13 (свод C, трек 1 №13; B3 #9, A1 R-1).
//
// Дефект 1 (гонка): applyStrategy писала e.cfg.EnableChain БЕЗ e.mu, тогда как e.cfg читают
// более сотни мест под e.mu.RLock (в том числе applyDPIFromConfig, снимающий копию всей
// структуры). Вызывается applyStrategy из tryFallback L2 — то есть в момент аварийного
// переключения, параллельно с опросом конфигурации интерфейсом.
//
// Дефект 2 (честность): ветки UseReality/UseCDN писали «Strategy: VLESS+Reality (SNI masking)»
// и «Strategy: CDN fronting (IP bypass)», не делая НИЧЕГО — ни одной строки действия за
// логом. Пользователь в логе видит применённую меру, которой не было.
package engine

import (
	"sync"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/detector"
)

// TestK2E_ApplyStrategy_Race — параллельные applyStrategy и чтение конфигурации.
// До фикса: WARNING: DATA RACE на e.cfg.EnableChain. После — чисто.
func TestK2E_ApplyStrategy_Race(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()

	const rounds = 200
	var wg sync.WaitGroup
	wg.Add(3)

	// Писатель — ровно то, что делает tryFallback L2 при смене типа блокировки.
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			e.applyStrategy(detector.Strategy{UseChain: true, Primary: "chain", Fallback: "tor"})
		}
	}()
	// Читатель 1 — продакшн-путь, снимающий копию ВСЕЙ конфигурации под e.mu.RLock.
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			e.mu.RLock()
			cfg := *e.cfg
			e.mu.RUnlock()
			_ = cfg.EnableChain
		}
	}()
	// Читатель 2 — публичный API, которым пользуются все три интерфейса.
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			if c := e.GetConfig(); c == nil {
				t.Error("GetConfig вернул nil")
			}
		}
	}()
	wg.Wait()

	if !e.GetConfig().EnableChain {
		t.Error("applyStrategy(UseChain) не выставила EnableChain — фикс убрал не только гонку")
	}
	t.Log("OK: applyStrategy под e.mu, гонки с читателями конфигурации нет")
}

// TestK2E_ApplyStrategy_HonestLog — ветки без действия не заявляют применение.
func TestK2E_ApplyStrategy_HonestLog(t *testing.T) {
	withTempDataDir(t)

	// UseReality и UseCDN не выполняют НИКАКОГО действия — лог обязан это отражать.
	for _, s := range []detector.Strategy{
		{UseReality: true, Primary: "vless-reality", Fallback: "cdn"},
		{UseCDN: true, Primary: "cdn", Fallback: "tor"},
	} {
		e := newTestEngine()
		lines := captureLog(e)
		before := e.GetConfig().EnableChain
		e.applyStrategy(s)
		if e.GetConfig().EnableChain != before {
			t.Error("ветка без действия изменила конфигурацию")
		}
		var said bool
		for _, l := range lines() {
			if containsAny(l, "зафиксирована", "recorded") {
				said = true
			}
			if containsAny(l, "применена", "applied", "enabling", "включ") {
				t.Errorf("лог заявляет применение меры, которой не было: %q", l)
			}
		}
		if !said {
			t.Errorf("лог не назвал стратегию зафиксированной: %v", lines())
		}
	}

	// UseChain — ветка С действием, её сообщение остаётся утвердительным.
	e := newTestEngine()
	lines := captureLog(e)
	e.applyStrategy(detector.Strategy{UseChain: true, Primary: "chain", Fallback: "tor"})
	if !e.GetConfig().EnableChain {
		t.Fatal("UseChain перестала включать цепочку")
	}
	if len(lines()) == 0 {
		t.Error("UseChain перестала логировать")
	}
	t.Log("OK: лог различает «зафиксировано» и «применено»")
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && len(s) >= len(sub) {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
