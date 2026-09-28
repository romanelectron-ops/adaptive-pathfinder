package residential

import (
	"context"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/iprep"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// CheckNode — error path: empty address causes CheckIP to return error
func TestCheckNode_EmptyAddress_ReturnsError(t *testing.T) {
	checker := iprep.NewChecker(nil)
	sel := NewSelector(checker, nil)
	node := &models.Node{ID: "empty", Address: ""}
	_, err := sel.CheckNode(context.Background(), node)
	if err == nil {
		t.Error("expected error for node with empty address")
	}
	t.Log("OK: CheckNode with empty address returns error:", err)
}

// FilterAndRank — requireResidential=true, all nodes non-residential → fallback to original list
func TestFilterAndRank_RequireResidential_FallbackToOriginal(t *testing.T) {
	checker := iprep.NewChecker(nil)
	sel := NewSelector(checker, nil)

	nodes := []*models.Node{
		{ID: "n1", Address: "1.2.3.4"},
		{ID: "n2", Address: "5.6.7.8"},
	}

	// Pre-populate cache with non-residential entries so CheckNode uses cache
	sel.mu.Lock()
	for _, n := range nodes {
		sel.scores[n.ID] = &NodeScore{
			Node:           n,
			IPInfo:         &iprep.IPInfo{IsResidential: false, IsDatacenter: true},
			AntiBlockScore: -50,
			Checked:        true,
		}
	}
	sel.mu.Unlock()

	result := sel.FilterAndRank(context.Background(), nodes, true)
	// All datacenter → none pass residential filter → fallback returns original
	if len(result) == 0 {
		t.Error("expected fallback to return original nodes when no residential found")
	}
	t.Log("OK: requireResidential fallback to original list, len=", len(result))
}

// Stats — "default" switch branch: IPInfo is non-nil but no flags set
func TestStats_DefaultIPType(t *testing.T) {
	checker := iprep.NewChecker(nil)
	sel := NewSelector(checker, nil)

	sel.mu.Lock()
	// IPInfo with no flags → hits switch default → counted as "unknown"
	sel.scores["plain"] = &NodeScore{
		Node:    &models.Node{ID: "plain"},
		IPInfo:  &iprep.IPInfo{}, // all flags false
		Checked: true,
	}
	sel.mu.Unlock()

	stats := sel.Stats()
	if stats["unknown"] < 1 {
		t.Errorf("expected unknown >= 1 for plain IPInfo, got %d", stats["unknown"])
	}
	t.Log("OK: plain IPInfo (no flags) counted as unknown in Stats")
}

// BestForStreaming — non-residential nodes in cache → returns best by score (not nil)
func TestBestForStreaming_NonResidential_ReturnsBest(t *testing.T) {
	checker := iprep.NewChecker(nil)
	sel := NewSelector(checker, nil)

	nodes := []*models.Node{
		{ID: "dc1", Address: "1.1.1.1"},
		{ID: "dc2", Address: "2.2.2.2"},
	}

	sel.mu.Lock()
	sel.scores["dc1"] = &NodeScore{
		Node: nodes[0], IPInfo: &iprep.IPInfo{IsDatacenter: true},
		AntiBlockScore: 20, Checked: true,
	}
	sel.scores["dc2"] = &NodeScore{
		Node: nodes[1], IPInfo: &iprep.IPInfo{IsDatacenter: true},
		AntiBlockScore: 10, Checked: true,
	}
	sel.mu.Unlock()

	best := sel.BestForStreaming(context.Background(), nodes)
	if best == nil {
		t.Error("BestForStreaming should return best node even when no residential")
	} else {
		t.Log("OK: BestForStreaming returns", best.ID)
	}
}

// FilterAndRank — CheckNode error path: node with empty address gets neutral score
func TestFilterAndRank_CheckNodeError_NeutralScore(t *testing.T) {
	checker := iprep.NewChecker(nil)
	sel := NewSelector(checker, nil)

	// Node with empty address -> CheckIP("") returns error -> goroutine adds neutral score
	nodes := []*models.Node{
		{ID: "empty-addr", Address: ""},
	}

	// requireResidential=false so error-path node passes through
	result := sel.FilterAndRank(context.Background(), nodes, false)
	if len(result) == 0 {
		t.Error("FilterAndRank should include error-node with neutral score")
	}
	t.Log("OK: CheckNode error -> neutral score appended, result len=", len(result))
}
