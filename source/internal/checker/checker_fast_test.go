// checker_fast_test.go — ТЗ v1.3 F4 Stage 1: одна проба на узел без межпробных пауз.
package checker

import (
	"context"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

func TestCheckAllWith_SinglePing_FastAndOK(t *testing.T) {
	c := New(2, 5)
	c.dialFn = pipeDialer(time.Millisecond)
	nodes := []*models.Node{presetNode("a"), presetNode("b"), presetNode("c")}
	start := time.Now()
	results := c.CheckAllWith(context.Background(), nodes, 200, 1)
	elapsed := time.Since(start)
	for i, r := range results {
		if r == nil || r.Outcome != models.OutcomeOK || !r.Success || r.Node.Latency < 1 {
			t.Errorf("узел %d: %+v", i, r)
		}
	}
	// Полная серия — 5 проб × 200 мс пауз ≈ 0.8 с на узел; одна проба должна укладываться в сотни мс.
	if elapsed > 700*time.Millisecond {
		t.Errorf("одна проба слишком долгая: %v", elapsed)
	}
	if r := c.CheckOneFast(context.Background(), presetNode("d")); r.Outcome != models.OutcomeOK {
		t.Errorf("CheckOneFast: %+v", r)
	}
}
