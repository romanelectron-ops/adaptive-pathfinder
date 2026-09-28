// checker_checkallwith_defaults_test.go — CheckAllWith: параметры concurrency/pings <= 0
// должны откатываться на разумные дефолты (c.concurrency / PingCount), а не передаваться как
// есть дальше. До этого файла проверялся только явный положительный concurrency
// (TestCheckAllWith_SinglePing_FastAndOK, checker_fast_test.go) — путь по умолчанию не тестировался.
//
// Это не праздная проверка: concurrency=0 без отката превратился бы в
// make(chan struct{}, 0) — небуферизованный канал. Каждая горутина обхода делает
// `sem <- struct{}{}` ПЕРЕД стартом собственной проверки и только СВОЯ ЖЕ (после defer)
// горутина потом читает из sem — то есть отправка размера 0 никогда не разблокируется
// посторонним чтением, и CheckAllWith зависает НАВСЕГДА вместо того чтобы проверить узлы.
// Ровно такой вызов возможен на практике: часть путей движка вызывает CheckAllWith с
// concurrency, вычисленным из конфигурации (0 — вполне достижимое значение по ошибке).
package checker

import (
	"context"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

func TestCheckAllWith_ZeroConcurrency_FallsBackNotHangs(t *testing.T) {
	c := New(3, 5) // конструктор задаёт дефолтный concurrency=3
	c.dialFn = pipeDialer(time.Millisecond)
	nodes := []*models.Node{presetNode("a"), presetNode("b"), presetNode("c"), presetNode("d")}

	done := make(chan []*models.CheckResult, 1)
	go func() { done <- c.CheckAllWith(context.Background(), nodes, 0, 1) }()

	select {
	case results := <-done:
		if len(results) != len(nodes) {
			t.Fatalf("results=%d, want %d", len(results), len(nodes))
		}
		for i, r := range results {
			if r == nil || r.Outcome != models.OutcomeOK {
				t.Errorf("узел %d: %+v", i, r)
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("CheckAllWith(concurrency=0) завис — откат на c.concurrency не сработал")
	}
}

func TestCheckAllWith_NegativeConcurrency_FallsBackNotHangs(t *testing.T) {
	c := New(2, 5)
	c.dialFn = pipeDialer(time.Millisecond)
	nodes := []*models.Node{presetNode("a")}

	done := make(chan []*models.CheckResult, 1)
	go func() { done <- c.CheckAllWith(context.Background(), nodes, -5, 1) }()

	select {
	case results := <-done:
		if len(results) != 1 || results[0].Outcome != models.OutcomeOK {
			t.Fatalf("unexpected results: %+v", results)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("CheckAllWith(concurrency=-5) завис")
	}
}

// pings<=0 откатывается на PingCount (5 проб с паузами) — сравниваем с TestCheckAllWith_SinglePing
// (1 проба, быстро) по числу собранных сэмплов косвенно: при 5 успешных пробах Loss остаётся 0
// и итог занимает заметно дольше одной пробы (межпробные паузы 200мс × 4).
func TestCheckAllWith_ZeroPings_FallsBackToPingCount(t *testing.T) {
	c := New(2, 5)
	c.dialFn = pipeDialer(0)
	node := presetNode("full-series")

	start := time.Now()
	results := c.CheckAllWith(context.Background(), []*models.Node{node}, 2, 0)
	elapsed := time.Since(start)

	if len(results) != 1 || results[0].Outcome != models.OutcomeOK {
		t.Fatalf("unexpected result: %+v", results)
	}
	if node.Loss != 0 {
		t.Errorf("полная серия из PingCount успешных проб должна дать loss=0, got %v", node.Loss)
	}
	// Полная серия (5 проб × 200мс пауз между ними, кроме последней) занимает не меньше ~600мс;
	// одна проба (Stage 1) укладывается в единицы мс. Если откат на PingCount сломан и pings=0
	// уходит как есть в measureLatencyN (там тоже стоит защита pings<=0→PingCount, но проверяем
	// именно контракт CheckAllWith, а не одной внутренней функции), время не будет отличать
	// один случай от другого.
	if elapsed < 500*time.Millisecond {
		t.Errorf("похоже, отработала только 1 проба, а не полная серия PingCount: elapsed=%v", elapsed)
	}
}
