package checker

import (
	"math"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

func TestCalcStats(t *testing.T) {
	// Нормальные данные
	latencies := []int64{100, 110, 95, 105, 0} // 0 = потеря
	avg, jitter, loss := calcStats(latencies)

	if avg < 90 || avg > 115 {
		t.Errorf("avg out of range: %d", avg)
	}
	if loss != 20.0 {
		t.Errorf("expected 20%% loss, got %.1f", loss)
	}
	t.Logf("avg=%dms jitter=%dms loss=%.1f%%", avg, jitter, loss)
}

func TestCalcStatsAllLost(t *testing.T) {
	latencies := []int64{0, 0, 0, 0, 0}
	avg, _, loss := calcStats(latencies)
	if avg != 9999 {
		t.Errorf("all lost: expected 9999ms, got %d", avg)
	}
	if loss != 100.0 {
		t.Errorf("all lost: expected 100%% loss, got %.1f", loss)
	}
}

func TestCalcScore(t *testing.T) {
	// Хороший узел: 50мс, нет потерь, свежий
	score1 := calcScore(50, 5, 0.0, 10.0, 0)
	// Плохой узел: 500мс, 30% потери, старый тест
	score2 := calcScore(500, 50, 30.0, 10.0, 3600)

	if score1 <= score2 {
		t.Errorf("good node score (%.4f) should be > bad node score (%.4f)", score1, score2)
	}

	// Новая формула: latency=50ms → score ≈ 1000/50 = 20
	if score1 < 10.0 {
		t.Errorf("good node score too low: %.4f (expected > 10)", score1)
	}
	t.Logf("good=%.2f bad=%.4f ratio=%.0fx", score1, score2, score1/score2)
}

func TestCalcScoreNormalization(t *testing.T) {
	// При latency=100ms, 0% loss, 0 jitter, fresh → score = 1000/100 = 10.0
	score := calcScore(100, 0, 0.0, 0.0, 0)
	if score < 9.0 || score > 11.0 {
		t.Errorf("expected score ≈ 10.0 for 100ms node, got %.4f", score)
	}
	t.Logf("100ms node score: %.2f", score)
}

func TestCalcScoreAgeFactor(t *testing.T) {
	// Один и тот же узел, разный возраст
	fresh := calcScore(100, 10, 0.0, 5.0, 0)
	old2 := calcScore(100, 10, 0.0, 5.0, 1800) // 30 минут

	if fresh <= old2 {
		t.Errorf("fresh score (%.4f) should be > old score (%.4f)", fresh, old2)
	}
	// AgeFactor(1800) = 1 + 1800/1800 = 2.0 → fresh/old ≈ 2.0
	ratio := fresh / old2
	// Допускаем небольшое отклонение из-за jitter penalty
	if math.Abs(ratio-2.0) > 0.1 {
		t.Errorf("expected ratio ~2.0, got %.3f", ratio)
	}
	t.Logf("fresh=%.4f old=%.4f ratio=%.2f", fresh, old2, ratio)
}

func TestClassifyStatus(t *testing.T) {
	// classifyStatus логика:
	//   lossPct > 50  → blocked
	//   lat > 1000 OR lossPct > 20 → slow
	//   иначе → ok
	tests := []struct {
		lat  int64
		loss float64
		want string
	}{
		{50, 0, "ok"},
		{800, 10, "ok"},      // 800 < 1000 и loss 10 < 20 → ok
		{1500, 5, "slow"},    // lat > 1000 → slow
		{100, 25, "slow"},    // loss > 20 → slow
		{100, 60, "blocked"}, // loss > 50 → blocked
	}
	for _, tt := range tests {
		got := classifyStatus(tt.lat, tt.loss)
		if string(got) != tt.want {
			t.Errorf("lat=%d loss=%.0f: expected %s, got %s", tt.lat, tt.loss, tt.want, got)
		}
	}
}

func TestIsRSTError(t *testing.T) {
	if !isRSTError("connection reset by peer") {
		t.Error("should detect RST")
	}
	if !isRSTError("connection refused") {
		t.Error("should detect refused")
	}
	if isRSTError("i/o timeout") {
		t.Error("timeout is not RST")
	}
}

func TestIsTimeoutError(t *testing.T) {
	if !isTimeoutError("dial tcp: i/o timeout") {
		t.Error("should detect timeout")
	}
	if isTimeoutError("connection reset") {
		t.Error("RST is not timeout")
	}
}

func TestWeightsForMode(t *testing.T) {
	modes := []string{"speed", "stealth", "streaming", "balanced", ""}
	for _, mode := range modes {
		w := WeightsForMode(mode)
		// Сумма весов должна быть ~1.0
		sum := w.Latency + w.Jitter + w.Loss + w.Protocol + w.AntiBlock
		if sum < 0.99 || sum > 1.01 {
			t.Errorf("mode=%q weights sum=%.2f (expected ~1.0)", mode, sum)
		}
	}
	t.Log("OK: all mode weights sum to 1.0")
}

func TestCalcScoreWeightedOrder(t *testing.T) {
	// Reality узел должен получить более высокий stealth score
	// чем обычный WireGuard — даже при том что WG быстрее
	// ТЗ v1.3 F1.4: LastChecked=now — свежая проверка. Раньше тест был зелёным только потому,
	// что у узлов без LastChecked ageFactor≈56 давил base до нуля и решал один protocolScore;
	// с настоящей задержкой (base 10 против 20) plain-latency перевешивала протокол.
	now := time.Now()
	realityNode := &models.Node{
		Protocol:    models.ProtoVLESS,
		Latency:     100,
		Jitter:      10,
		Loss:        0,
		LastChecked: now,
		TLS: &models.TLSConfig{
			Enabled: true,
			Reality: &models.RealityConfig{PublicKey: "test", ShortID: "abc"},
		},
	}
	wgNode := &models.Node{
		Protocol:    models.ProtoWireGuard,
		Latency:     50, // WG быстрее
		Jitter:      5,
		Loss:        0,
		LastChecked: now,
	}

	stealthW := WeightsForMode("stealth")
	realityScore := CalcScoreWeighted(realityNode, stealthW, 0.5)
	wgScore := CalcScoreWeighted(wgNode, stealthW, 0.5)

	if realityScore <= wgScore {
		t.Errorf("stealth mode: Reality score (%.3f) should > WG score (%.3f)", realityScore, wgScore)
	}
	t.Logf("OK: stealth Reality=%.3f > WG=%.3f (protocol matters more than latency)", realityScore, wgScore)

	// В speed режиме с одинаковой латентностью WG должен иметь схожий score
	// (protocolScore 0.25 vs 1.0 для Reality, но в speed режиме protocol вес 0.05)
	speedW := WeightsForMode("speed")
	// Создаём WG с той же латентностью что и Reality — тогда WG выиграет по скорости
	fastWG := &models.Node{
		Protocol:    models.ProtoWireGuard,
		Latency:     100, // одинаковая латентность
		Jitter:      10,
		Loss:        0,
		LastChecked: now,
	}
	realitySpeedScore := CalcScoreWeighted(realityNode, speedW, 0.5)
	wgFastScore := CalcScoreWeighted(fastWG, speedW, 0.5)

	// При одинаковой латентности в speed режиме разница не должна быть огромной
	// (protocol вес только 0.05)
	diff := math.Abs(realitySpeedScore - wgFastScore)
	if diff > 0.15 {
		t.Errorf("speed mode same latency: too large difference Reality=%.3f WG=%.3f diff=%.3f",
			realitySpeedScore, wgFastScore, diff)
	}
	t.Logf("OK: speed mode same latency Reality=%.3f WG=%.3f diff=%.3f", realitySpeedScore, wgFastScore, diff)
}

// TestScoringDeterministic — Gate B: один набор узлов → один порядок каждый раз.
func TestScoringDeterministic(t *testing.T) {
	nodes := []*models.Node{
		{Protocol: models.ProtoVLESS, Latency: 120, Jitter: 15, Loss: 0,
			TLS: &models.TLSConfig{Enabled: true, Reality: &models.RealityConfig{PublicKey: "pk1", ShortID: "s1"}}},
		{Protocol: models.ProtoTrojan, Latency: 80, Jitter: 10, Loss: 1},
		{Protocol: models.ProtoShadowsocks, Latency: 60, Jitter: 5, Loss: 0},
		{Protocol: models.ProtoWireGuard, Latency: 40, Jitter: 3, Loss: 0},
		{Protocol: models.ProtoVMess, Latency: 200, Jitter: 30, Loss: 2},
	}

	weights := WeightsForMode("balanced")

	// Вычисляем scores 3 раза — должны быть одинаковы
	scores := [3][]float64{}
	for run := 0; run < 3; run++ {
		for _, n := range nodes {
			scores[run] = append(scores[run], CalcScoreWeighted(n, weights, 0.5))
		}
	}

	for i := range scores[0] {
		if scores[0][i] != scores[1][i] || scores[1][i] != scores[2][i] {
			t.Errorf("node[%d] non-deterministic: %.4f %.4f %.4f",
				i, scores[0][i], scores[1][i], scores[2][i])
		}
	}

	// Проверяем что порядок стабильный (сортировка даёт один и тот же результат)
	sortByScore := func(ns []*models.Node) []string {
		type pair struct {
			name  string
			score float64
		}
		pairs := make([]pair, len(ns))
		for i, n := range ns {
			pairs[i] = pair{string(n.Protocol), CalcScoreWeighted(n, weights, 0.5)}
		}
		// Простая сортировка
		for i := 0; i < len(pairs); i++ {
			for j := i + 1; j < len(pairs); j++ {
				if pairs[j].score > pairs[i].score {
					pairs[i], pairs[j] = pairs[j], pairs[i]
				}
			}
		}
		result := make([]string, len(pairs))
		for i, p := range pairs {
			result[i] = p.name
		}
		return result
	}

	order1 := sortByScore(nodes)
	order2 := sortByScore(nodes)
	order3 := sortByScore(nodes)

	for i := range order1 {
		if order1[i] != order2[i] || order2[i] != order3[i] {
			t.Errorf("sort non-deterministic at [%d]: %s %s %s", i, order1[i], order2[i], order3[i])
		}
	}

	t.Logf("OK: deterministic ranking: %v", order1)
}

// ─── checker coverage: протокол score, calcStats, safety ─────────────────────

func TestProtocolScore(t *testing.T) {
	cases := []struct {
		name     string
		node     *models.Node
		minScore float64
		maxScore float64
	}{
		{"Reality", &models.Node{
			Protocol: models.ProtoVLESS,
			TLS:      &models.TLSConfig{Reality: &models.RealityConfig{PublicKey: "pk"}},
		}, 0.99, 1.0},
		{"Trojan", &models.Node{Protocol: models.ProtoTrojan}, 0.85, 0.95},
		{"VLESS+TLS", &models.Node{
			Protocol: models.ProtoVLESS,
			TLS:      &models.TLSConfig{Enabled: true},
		}, 0.75, 0.85},
		{"VLESS noTLS", &models.Node{Protocol: models.ProtoVLESS}, 0.45, 0.55},
		{"VMess", &models.Node{Protocol: models.ProtoVMess}, 0.55, 0.65},
		{"SS+transport", &models.Node{
			Protocol:  models.ProtoShadowsocks,
			Transport: &models.TransportConfig{Type: "ws"},
		}, 0.50, 0.60},
		{"SS plain", &models.Node{Protocol: models.ProtoShadowsocks}, 0.35, 0.45},
		{"WireGuard", &models.Node{Protocol: models.ProtoWireGuard}, 0.20, 0.30},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			score := protocolScore(c.node)
			if score < c.minScore || score > c.maxScore {
				t.Errorf("%s: score=%.2f want [%.2f..%.2f]",
					c.name, score, c.minScore, c.maxScore)
			}
			t.Logf("  %s: %.2f ✓", c.name, score)
		})
	}
}

func TestCalcStatsEdgeCases(t *testing.T) {
	// Пустой срез — возвращает sentinel значения (9999, 9999, 100%)
	avg, jitter, loss := calcStats([]int64{})
	t.Logf("empty slice: avg=%d jitter=%d loss=%.1f%%", avg, jitter, loss)
	// Любое поведение ОК — главное не паника

	// Один замер (не 0 — реальный)
	avg, jitter, loss = calcStats([]int64{100})
	if avg != 100 {
		t.Errorf("single real: avg want 100, got %d", avg)
	}
	t.Logf("single real: avg=%d jitter=%d loss=%.1f%%", avg, jitter, loss)

	// Все потери (нули)
	avg, jitter, loss = calcStats([]int64{0, 0, 0})
	if loss != 100.0 {
		t.Errorf("all lost: loss want 100, got %.1f", loss)
	}
	t.Logf("all lost: avg=%d jitter=%d loss=%.1f%%", avg, jitter, loss)

	// Стабильные значения — jitter близок к 0
	avg, jitter, loss = calcStats([]int64{100, 100, 100, 100})
	if avg != 100 {
		t.Errorf("stable: avg want 100, got %d", avg)
	}
	if jitter != 0 {
		t.Errorf("stable: jitter want 0, got %d", jitter)
	}
	t.Logf("stable: avg=%d jitter=%d loss=%.1f%%", avg, jitter, loss)

	t.Log("OK: calcStats edge cases")
}

func TestCalcScoreMonotone(t *testing.T) {
	// Лучший узел (низкая задержка, нет потерь) > худший
	good := calcScore(50, 5, 0, 10, 0)
	bad := calcScore(500, 100, 30, 0, 3600)
	if good <= bad {
		t.Errorf("good score (%.2f) should > bad score (%.2f)", good, bad)
	}
	t.Logf("OK: good=%.3f > bad=%.3f", good, bad)
}

func TestWeightsSum(t *testing.T) {
	for _, mode := range []string{"speed", "stealth", "streaming", "balanced", ""} {
		w := WeightsForMode(mode)
		sum := w.Latency + w.Jitter + w.Loss + w.Protocol + w.AntiBlock
		if sum < 0.99 || sum > 1.01 {
			t.Errorf("mode=%q weights sum=%.4f want 1.0", mode, sum)
		}
	}
	t.Log("OK: all mode weights sum to 1.0")
}

func TestCalcScoreWeightedZeroLatency(t *testing.T) {
	node := &models.Node{
		Protocol:    models.ProtoTrojan,
		Latency:     0, // неизвестная задержка
		LastChecked: time.Now(),
	}
	w := WeightsForMode("balanced")
	score := CalcScoreWeighted(node, w, 0.5)
	// Нулевая задержка нормализуется в худший случай (9999ms)
	if score <= 0 {
		t.Errorf("score should be > 0, got %.4f", score)
	}
	t.Logf("OK: zero latency score=%.4f (treated as 9999ms)", score)
}
