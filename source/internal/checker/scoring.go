// scoring.go
package checker

import (
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ScoreWeights holds per-dimension weights for CalcScoreWeighted.
// The 5 primary weights (Latency+Jitter+Loss+Protocol+AntiBlock) must sum to 1.0.
// Speed and Age are intentionally 0 — calcScore() already folds them into base.
type ScoreWeights struct {
	Latency   float64
	Jitter    float64
	Loss      float64
	Speed     float64
	Protocol  float64
	AntiBlock float64
	Age       float64
}

// WeightsForMode returns ScoreWeights for the given SelectionMode.
// Supported: "speed", "stealth", "streaming", "balanced" (default for "" and unknown).
func WeightsForMode(mode string) ScoreWeights {
	switch mode {
	case "speed", "fast":
		return ScoreWeights{
			Latency:   0.55,
			Jitter:    0.15,
			Loss:      0.20,
			Protocol:  0.07,
			AntiBlock: 0.03,
		}
	case "stealth":
		return ScoreWeights{
			Protocol:  0.40,
			AntiBlock: 0.25,
			Latency:   0.15,
			Loss:      0.12,
			Jitter:    0.08,
		}
	case "streaming":
		return ScoreWeights{
			Latency:   0.25,
			Jitter:    0.30,
			Loss:      0.25,
			Protocol:  0.12,
			AntiBlock: 0.08,
		}
	default: // "balanced", "auto", ""
		return ScoreWeights{
			Latency:   0.40,
			Jitter:    0.15,
			Loss:      0.20,
			Protocol:  0.15,
			AntiBlock: 0.10,
		}
	}
}

// NormalizeBase squashes the raw calcScore base (1000/latency-ish, 0..20+) into [0,1) so it is
// commensurable with protocolScore/antiBlockScore ∈ [0,1].
//
// ТЗ v1.3 F1.4 (консилиум 2026-09-03, BB-2/F-1): раньше base входил в сумму как есть — 100 мс
// давали 10, 50 мс — 20, а бонус протокола не превышал 1.0. Веса режима "stealth"/SNI-блокировки
// (Protocol 0.40-0.60) физически не могли перевесить задержку: plain-VLESS 100 мс (≈5.4)
// обходил VLESS+Reality 200 мс (≈3.2) даже при SNI-блокировке, где Reality — единственное, что
// вообще работает. `TestCalcScoreWeightedOrder` был зелёным только потому, что у тестовых узлов
// LastChecked=0 и ageFactor≈56 давил base до нуля. x/(x+1): 100 мс → 0.5, 50 мс → 0.67,
// 25 мс → 0.8, 1000 мс → 0.09 — монотонно по задержке, ограничено единицей.
func NormalizeBase(base float64) float64 {
	if base <= 0 {
		return 0
	}
	return base / (base + 1)
}

// CalcScoreWeighted computes a weighted score for a node in [0,1].
//
// Единая шкала (F1.4): base из calcScore нормируется через NormalizeBase, поэтому итог всегда
// в [0,1] и сравним между узлами, проверенными в разное время разными путями (CheckOne пишет
// ту же шкалу — см. там). minScore остаётся для совместимости сигнатуры; пол больше НЕ
// поднимает непроверенные узлы: узел, которого не касалась ни одна проверка (IsUnchecked),
// получает 0 — раньше пол 0.5 делал 3800 из 4095 узлов кэша «годными» без единой пробы и
// пропускал их через порог Score > 0.001 в слепое подключение (NL-3/ND-2).
func CalcScoreWeighted(n *models.Node, w ScoreWeights, minScore float64) float64 {
	if n == nil {
		return 0
	}
	if n.UserBanned || n.IsUnchecked() {
		return 0
	}

	// P1-3 (аудит 2026-09-01): узел, чья последняя проверка провалилась, получает 0 —
	// НИЖЕ пола minScore, то есть он гарантированно уступает любому работающему.
	//
	// Без этой ветки обнуление Score в markFail не помогало: selectBestForStrategy
	// пересчитывает Score всем кандидатам через эту функцию, а calcScore считает по
	// СОХРАНЁННЫМ Latency/Jitter/Loss — то есть по последнему УСПЕШНОМУ замеру. У мёртвого
	// узла оставалась отличная старая задержка (50 мс), а возрастной штраф обнулялся свежим
	// LastChecked из markFail, и он получал base = 1000/50 = 20 против 1.25 у живого узла с
	// 800 мс. Мёртвый систематически занимал первое место и выигрывал КАЖДЫЙ выбор, пока не
	// наберёт три отказа для чёрного списка (жалоба «первый „лучший“ узел часто мёртв»).
	//
	// Признак — Status, а не FailCount: статус выставляет и markFail (StatusBlocked при
	// отказе), и classifyStatus (StatusBlocked при потерях > 50 %) — оба случая означают
	// «узел сейчас непригоден». Узлы, которых ещё не проверяли, сюда не попадают: у них
	// статус пустой, и они сохраняют обычную оценку, иначе новые узлы никогда не получили бы
	// шанса (тот самый замкнутый круг, против которого написана getRescanBatch).
	if n.Status == models.StatusBlocked || n.Status == models.StatusBlacklist {
		return 0
	}

	base := NormalizeBase(calcScore(n.Latency, n.Jitter, n.Loss, n.Speed, n.AgeSeconds()))
	protoBonus := protocolScore(n)
	abBonus := antiBlockScore(n.Source)

	// base contributes via the three primary network weights.
	score := base*(w.Latency+w.Jitter+w.Loss) +
		protoBonus*w.Protocol +
		abBonus*w.AntiBlock

	if score < minScore {
		return minScore
	}
	if score > 1 {
		return 1
	}
	return score
}

// protocolScore returns a DPI-resistance score in [0,1] for the node.
// Higher = harder to detect and block.
func protocolScore(n *models.Node) float64 {
	if n == nil {
		return 0.5
	}
	// VLESS + Reality: fingerprints a real TLS server — best DPI evasion.
	if n.TLS != nil && n.TLS.Reality != nil {
		return 1.0
	}
	switch n.Protocol {
	case models.ProtoTrojan:
		// Trojan requires TLS by design — high resistance.
		return 0.9
	case models.ProtoVLESS:
		if n.TLS != nil && n.TLS.Enabled {
			return 0.8 // VLESS + explicit TLS
		}
		return 0.5 // VLESS plain — detectable
	case models.ProtoVMess:
		return 0.6
	case models.ProtoShadowsocks:
		if n.Transport != nil && n.Transport.Type != "" {
			return 0.55 // SS with obfs transport
		}
		return 0.4 // SS plain
	case models.ProtoWireGuard, models.ProtoAmneziaWG:
		return 0.25 // easily fingerprinted UDP
	case models.ProtoTor:
		return 0.15
	default:
		return 0.3
	}
}

// antiBlockScore returns a score in [0,1] based on IP source/reputation.
func antiBlockScore(source string) float64 {
	switch source {
	case "residential":
		return 1.0
	case "paid":
		return 0.75
	default:
		return 1.0 // unknown source: no penalty
	}
}
