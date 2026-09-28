package residential

// Extra tests covering CheckNode, FilterAndRank, BestForStreaming.
// All three used network calls in the original code, so tests
// pre-populate the Selector's internal scores cache to avoid I/O.

import (
	"context"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/iprep"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── CheckNode — cache hit path ───────────────────────────────────────────────

func TestCheckNode_CacheHit(t *testing.T) {
	checker := iprep.NewChecker(nil)
	sel := NewSelector(checker, nil)
	node := &models.Node{ID: "cached-1", Address: "192.168.1.1"}

	// Pre-populate scores cache so no network call is made
	sel.mu.Lock()
	sel.scores["cached-1"] = &NodeScore{
		Node:           node,
		IPInfo:         &iprep.IPInfo{IsResidential: true, RiskScore: 5},
		AntiBlockScore: 120,
		Checked:        true,
	}
	sel.mu.Unlock()

	ns, err := sel.CheckNode(context.Background(), node)
	if err != nil {
		t.Fatalf("CheckNode cache hit: %v", err)
	}
	if ns.AntiBlockScore != 120 {
		t.Errorf("expected cached AntiBlockScore 120, got %.1f", ns.AntiBlockScore)
	}
}

// ─── CheckNode — network-fail path (CheckIP returns synthetic result) ─────────

func TestCheckNode_NetworkFail_ReturnsSyntheticScore(t *testing.T) {
	checker := iprep.NewChecker(nil)
	sel := NewSelector(checker, nil)
	node := &models.Node{ID: "net-fail", Address: "203.0.113.5"} // TEST-NET-3, RFC 5737

	// Use an already-expired context so HTTP calls fail immediately.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	time.Sleep(5 * time.Millisecond) // ensure deadline has passed

	ns, err := sel.CheckNode(ctx, node)
	// CheckIP gracefully handles network failure and returns synthetic IPInfo{Source:"unavailable"}.
	if err != nil {
		t.Fatalf("CheckNode should not error on network fail: %v", err)
	}
	if ns == nil {
		t.Fatal("CheckNode returned nil NodeScore")
	}
	if !ns.Checked {
		t.Error("NodeScore.Checked should be true")
	}
}

// ─── FilterAndRank — with pre-cached scores, no network ──────────────────────

func TestFilterAndRank_SortedByScore(t *testing.T) {
	checker := iprep.NewChecker(nil)
	sel := NewSelector(checker, nil)

	nodes := []*models.Node{
		{ID: "low", Address: "1.1.1.1"},
		{ID: "high", Address: "2.2.2.2"},
		{ID: "mid", Address: "3.3.3.3"},
	}
	sel.mu.Lock()
	sel.scores["low"] = &NodeScore{Node: nodes[0], IPInfo: &iprep.IPInfo{}, AntiBlockScore: -20, Checked: true}
	sel.scores["high"] = &NodeScore{Node: nodes[1], IPInfo: &iprep.IPInfo{IsResidential: true}, AntiBlockScore: 120, Checked: true}
	sel.scores["mid"] = &NodeScore{Node: nodes[2], IPInfo: &iprep.IPInfo{}, AntiBlockScore: 30, Checked: true}
	sel.mu.Unlock()

	result := sel.FilterAndRank(context.Background(), nodes, false)

	if len(result) != 3 {
		t.Fatalf("expected 3 results, got %d", len(result))
	}
	if result[0].ID != "high" {
		t.Errorf("first should be 'high' (score 120), got %q", result[0].ID)
	}
	if result[2].ID != "low" {
		t.Errorf("last should be 'low' (score -20), got %q", result[2].ID)
	}
}

func TestFilterAndRank_RequireResidential_FiltersOut(t *testing.T) {
	checker := iprep.NewChecker(nil)
	sel := NewSelector(checker, nil)

	nodes := []*models.Node{
		{ID: "res", Address: "1.1.1.1"},
		{ID: "dc", Address: "2.2.2.2"},
	}
	sel.mu.Lock()
	sel.scores["res"] = &NodeScore{Node: nodes[0], IPInfo: &iprep.IPInfo{IsResidential: true}, AntiBlockScore: 80, Checked: true}
	sel.scores["dc"] = &NodeScore{Node: nodes[1], IPInfo: &iprep.IPInfo{IsDatacenter: true}, AntiBlockScore: -60, Checked: true}
	sel.mu.Unlock()

	result := sel.FilterAndRank(context.Background(), nodes, true)

	if len(result) != 1 || result[0].ID != "res" {
		t.Errorf("with requireResidential=true, expected [res], got %v", nodeIDs(result))
	}
}

func TestFilterAndRank_RequireResidential_FallbackWhenNoneFound(t *testing.T) {
	checker := iprep.NewChecker(nil)
	sel := NewSelector(checker, nil)

	nodes := []*models.Node{
		{ID: "dc-only", Address: "1.1.1.1"},
	}
	sel.mu.Lock()
	sel.scores["dc-only"] = &NodeScore{Node: nodes[0], IPInfo: &iprep.IPInfo{IsDatacenter: true}, AntiBlockScore: -60, Checked: true}
	sel.mu.Unlock()

	result := sel.FilterAndRank(context.Background(), nodes, true)

	// No residential → falls back to returning the full input list
	if len(result) == 0 {
		t.Error("FilterAndRank should fall back to all nodes when no residential found")
	}
}

// ─── BestForStreaming ─────────────────────────────────────────────────────────

func TestBestForStreaming_PrefersResidential(t *testing.T) {
	checker := iprep.NewChecker(nil)
	sel := NewSelector(checker, nil)

	// dc has higher AntiBlockScore but res is residential
	nodes := []*models.Node{
		{ID: "res", Address: "1.1.1.1"},
		{ID: "dc", Address: "2.2.2.2"},
	}
	sel.mu.Lock()
	sel.scores["res"] = &NodeScore{Node: nodes[0], IPInfo: &iprep.IPInfo{IsResidential: true}, AntiBlockScore: 80, Checked: true}
	sel.scores["dc"] = &NodeScore{Node: nodes[1], IPInfo: &iprep.IPInfo{IsDatacenter: true, IsResidential: false}, AntiBlockScore: 100, Checked: true}
	sel.mu.Unlock()

	best := sel.BestForStreaming(context.Background(), nodes)
	if best == nil {
		t.Fatal("BestForStreaming returned nil")
	}
	if best.ID != "res" {
		t.Errorf("BestForStreaming should prefer residential, got %q", best.ID)
	}
}

func TestBestForStreaming_FallbackToHighestScore(t *testing.T) {
	checker := iprep.NewChecker(nil)
	sel := NewSelector(checker, nil)

	// No residential nodes → fallback to highest AntiBlockScore
	nodes := []*models.Node{
		{ID: "dc-hi", Address: "1.1.1.1"},
		{ID: "dc-lo", Address: "2.2.2.2"},
	}
	sel.mu.Lock()
	sel.scores["dc-hi"] = &NodeScore{Node: nodes[0], IPInfo: &iprep.IPInfo{IsDatacenter: true}, AntiBlockScore: 50, Checked: true}
	sel.scores["dc-lo"] = &NodeScore{Node: nodes[1], IPInfo: &iprep.IPInfo{IsDatacenter: true}, AntiBlockScore: 10, Checked: true}
	sel.mu.Unlock()

	best := sel.BestForStreaming(context.Background(), nodes)
	if best == nil {
		t.Fatal("BestForStreaming returned nil")
	}
	if best.ID != "dc-hi" {
		t.Errorf("no residential: expected dc-hi (highest score), got %q", best.ID)
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func nodeIDs(nodes []*models.Node) []string {
	ids := make([]string, len(nodes))
	for i, n := range nodes {
		ids[i] = n.ID
	}
	return ids
}
