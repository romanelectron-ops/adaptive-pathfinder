package residential

import (
	"context"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/iprep"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ── calcAntiBlockScore ────────────────────────────────────────────────────────

func TestCalcAntiBlockScore_Residential(t *testing.T) {
	info := &iprep.IPInfo{
		IsResidential: true,
		IsProxy:       false,
		IsDatacenter:  false,
		RiskScore:     10,
	}
	node := &models.Node{Latency: 50, Score: 8}
	score := calcAntiBlockScore(info, node)
	if score < 80 {
		t.Errorf("residential node should have high anti-block score, got %.1f", score)
	}
}

func TestCalcAntiBlockScore_Datacenter(t *testing.T) {
	info := &iprep.IPInfo{
		IsResidential: false,
		IsDatacenter:  true,
		IsHosting:     true,
		RiskScore:     70,
	}
	node := &models.Node{Latency: 50, Score: 5}
	score := calcAntiBlockScore(info, node)
	if score > 0 {
		t.Errorf("datacenter node should have negative anti-block score, got %.1f", score)
	}
}

func TestCalcAntiBlockScore_ProxyVPN(t *testing.T) {
	info := &iprep.IPInfo{
		IsProxy: true,
		IsVPN:   true,
	}
	node := &models.Node{}
	score := calcAntiBlockScore(info, node)
	if score > -30 {
		t.Errorf("proxy/VPN should have very negative score, got %.1f", score)
	}
}

func TestCalcAntiBlockScore_HostingOrg(t *testing.T) {
	info := &iprep.IPInfo{
		IsResidential: false,
		Org:           "Hetzner Online GmbH",
		ASN:           "AS24940",
		IsDatacenter:  true,
	}
	node := &models.Node{}
	score1 := calcAntiBlockScore(info, node)

	// С "hetzner" в org должен быть штраф
	info2 := &iprep.IPInfo{
		IsResidential: false,
		Org:           "SomeRandomISP",
		IsDatacenter:  true,
	}
	score2 := calcAntiBlockScore(info2, node)

	// Hetzner должен иметь больший штраф
	if score1 >= score2 {
		t.Errorf("known hosting org (hetzner) should have lower score than unknown: %.1f vs %.1f",
			score1, score2)
	}
}

func TestCalcAntiBlockScore_NilInfo(t *testing.T) {
	node := &models.Node{Latency: 100, Score: 5}
	score := calcAntiBlockScore(nil, node)
	// Не должно паниковать, должен вернуть положительный бонус от узла
	if score < 0 {
		t.Errorf("nil info with good node latency should not be very negative, got %.1f", score)
	}
}

func TestCalcAntiBlockScore_NilNode(t *testing.T) {
	info := &iprep.IPInfo{IsResidential: true, RiskScore: 5}
	score := calcAntiBlockScore(info, nil)
	// Не должно паниковать
	if score < 50 {
		t.Errorf("residential with nil node should still have good score, got %.1f", score)
	}
}

// ── NodeScore.Label ───────────────────────────────────────────────────────────

func TestNodeScore_Label(t *testing.T) {
	ns := &NodeScore{
		IPInfo: &iprep.IPInfo{IsResidential: true},
	}
	if ns.Label() != "residential" {
		t.Errorf("Label() = %q, want residential", ns.Label())
	}

	ns2 := &NodeScore{IPInfo: nil}
	if ns2.Label() != "unknown" {
		t.Errorf("nil IPInfo Label() = %q, want unknown", ns2.Label())
	}
}

// ── Selector.Stats ────────────────────────────────────────────────────────────

func TestSelector_Stats_Empty(t *testing.T) {
	checker := iprep.NewChecker(nil)
	sel := NewSelector(checker, nil)
	stats := sel.Stats()
	if stats["total"] != 0 {
		t.Errorf("empty selector should have 0 total, got %d", stats["total"])
	}
}

func TestSelector_Stats_WithData(t *testing.T) {
	checker := iprep.NewChecker(nil)
	sel := NewSelector(checker, nil)

	// Заполняем вручную
	sel.mu.Lock()
	sel.scores["node1"] = &NodeScore{
		Node:    &models.Node{ID: "node1"},
		IPInfo:  &iprep.IPInfo{IsResidential: true},
		Checked: true,
	}
	sel.scores["node2"] = &NodeScore{
		Node:    &models.Node{ID: "node2"},
		IPInfo:  &iprep.IPInfo{IsDatacenter: true},
		Checked: true,
	}
	sel.scores["node3"] = &NodeScore{
		Node:    &models.Node{ID: "node3"},
		IPInfo:  &iprep.IPInfo{IsProxy: true},
		Checked: true,
	}
	sel.scores["node4"] = &NodeScore{
		Node:    &models.Node{ID: "node4"},
		IPInfo:  nil,
		Checked: false,
	}
	sel.mu.Unlock()

	stats := sel.Stats()
	if stats["total"] != 4 {
		t.Errorf("total = %d, want 4", stats["total"])
	}
	if stats["residential"] != 1 {
		t.Errorf("residential = %d, want 1", stats["residential"])
	}
	if stats["datacenter"] != 1 {
		t.Errorf("datacenter = %d, want 1", stats["datacenter"])
	}
	if stats["proxy_vpn"] != 1 {
		t.Errorf("proxy_vpn = %d, want 1", stats["proxy_vpn"])
	}
	if stats["unknown"] != 1 {
		t.Errorf("unknown = %d, want 1", stats["unknown"])
	}
}

// ── Selector.GetScores ────────────────────────────────────────────────────────

func TestSelector_GetScores_SortedByScore(t *testing.T) {
	checker := iprep.NewChecker(nil)
	sel := NewSelector(checker, nil)

	sel.mu.Lock()
	sel.scores["low"] = &NodeScore{
		Node:           &models.Node{ID: "low"},
		AntiBlockScore: -50,
		Checked:        true,
	}
	sel.scores["high"] = &NodeScore{
		Node:           &models.Node{ID: "high"},
		AntiBlockScore: 90,
		Checked:        true,
	}
	sel.scores["mid"] = &NodeScore{
		Node:           &models.Node{ID: "mid"},
		AntiBlockScore: 30,
		Checked:        true,
	}
	sel.mu.Unlock()

	scores := sel.GetScores()
	if len(scores) != 3 {
		t.Fatalf("expected 3 scores, got %d", len(scores))
	}
	// Первый должен быть с наивысшим score
	if scores[0].AntiBlockScore < scores[1].AntiBlockScore {
		t.Error("scores should be sorted descending")
	}
	if scores[1].AntiBlockScore < scores[2].AntiBlockScore {
		t.Error("scores should be sorted descending")
	}
}

// ── Selector.InvalidateNode ───────────────────────────────────────────────────

func TestSelector_InvalidateNode(t *testing.T) {
	checker := iprep.NewChecker(nil)
	sel := NewSelector(checker, nil)

	sel.mu.Lock()
	sel.scores["node1"] = &NodeScore{Node: &models.Node{ID: "node1"}, Checked: true}
	sel.mu.Unlock()

	sel.InvalidateNode("node1")

	sel.mu.RLock()
	_, exists := sel.scores["node1"]
	sel.mu.RUnlock()

	if exists {
		t.Error("node should be removed after InvalidateNode")
	}
}

// ── Selector.FilterAndRank — без сети ─────────────────────────────────────────

func TestSelector_FilterAndRank_EmptyNodes(t *testing.T) {
	checker := iprep.NewChecker(nil)
	sel := NewSelector(checker, nil)

	ctx := context.Background()
	result := sel.FilterAndRank(ctx, nil, false)
	if result != nil {
		t.Error("empty input should return nil")
	}
}

func TestSelector_BestForStreaming_EmptyNodes(t *testing.T) {
	checker := iprep.NewChecker(nil)
	sel := NewSelector(checker, nil)

	ctx := context.Background()
	result := sel.BestForStreaming(ctx, nil)
	if result != nil {
		t.Error("empty input should return nil")
	}
}
