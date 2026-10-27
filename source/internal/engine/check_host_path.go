package engine

import (
	"fmt"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// hostPath — как прямо сейчас идёт исходящий TCP самого хоста (apf-svc). Kill Switch режет всё,
// кроме разрешённого, а запущенный TUN уводит ВСЕ пробы в туннель: тогда «не дозвонился» говорит
// о локальной сети, а не об узле.
type hostPath struct {
	ks     bool
	tunnel bool
}

// reliable — прямая TCP-проба с хоста сейчас показывает доступность узла.
func (h hostPath) reliable() bool { return !h.ks && !h.tunnel }

func (e *Engine) currentHostPath() hostPath {
	h := hostPath{ks: e.killSwitchEnabledNow()}
	if e.proc != nil && e.proc.IsRunning() && e.cfg != nil &&
		(e.cfg.ConnectionMode == models.ModeVPN || e.cfg.ConnectionMode == models.ModeHybrid) {
		h.tunnel = true
	}
	return h
}

// failSnapshot — поля узла, которые markFail меняет при отказе пробы.
type failSnapshot struct {
	status           models.NodeStatus
	failCount        int
	successCount     int
	score            float64
	lastChecked      time.Time
	blacklistedUntil time.Time
}

func snapshotFailFields(nodes []*models.Node) map[*models.Node]failSnapshot {
	out := make(map[*models.Node]failSnapshot, len(nodes))
	for _, n := range nodes {
		if n == nil {
			continue
		}
		out[n] = failSnapshot{n.Status, n.FailCount, n.SuccessCount, n.Score, n.LastChecked, n.BlacklistedUntil}
	}
	return out
}

func (s failSnapshot) restore(n *models.Node) {
	n.Status = s.status
	n.FailCount = s.failCount
	n.SuccessCount = s.successCount
	n.Score = s.score
	n.LastChecked = s.lastChecked
	n.BlacklistedUntil = s.blacklistedUntil
}

// guardInconclusiveChecks — отказы TCP-проб, снятые на Windows при активном Kill Switch, при
// запущенном TUN или пока сеть хоста менялась во время самой проверки, НЕ записываются в узлы.
//
// Живой ПК 2026-10-27: «Подключить» запускал фоновый скан пула (Testing 50 nodes) одновременно с
// применением Kill Switch и подъёмом TUN; после него 27 из 70 узлов в кэше получили «blocked»
// (было 1), в том числе проверенный трафиком узел с откликом 255 мс. Это отказ локальной сети, а
// не узлов (тот же класс, что markLocalFailure у подключения). Успешные пробы остаются как есть;
// сам результат проверки вызывающему возвращается без изменений (Success=false — решение «идти ли
// к следующему кандидату» за ним), не пишется только состояние узла (статус, счётчики, Score,
// бан). Не-Windows — поведение прежнее: на Android Kill Switch и туннель — на уровне ОС.
func (e *Engine) guardInconclusiveChecks(nodes []*models.Node, run func() []*models.CheckResult) []*models.CheckResult {
	if e.probeGOOS() != "windows" {
		return run()
	}
	before := e.currentHostPath()
	// Узлы пула читают и пишут под e.mu (AddNodeFromLink, ForceRescan, тумблеры); снимок и откат —
	// тоже под ним. Вызывающие обёртки e.mu не держат (см. комментарий к checkNodeSerialized), а
	// порядок блокировок nodeCheckMu → e.mu нигде не обращён. Сама проверка идёт БЕЗ e.mu.
	e.mu.RLock()
	snaps := snapshotFailFields(nodes)
	e.mu.RUnlock()
	results := run()
	after := e.currentHostPath()
	if before.reliable() && after == before {
		return results
	}
	reverted := 0
	e.mu.Lock()
	for _, r := range results {
		if r == nil || r.Node == nil || r.Outcome != models.OutcomeFail {
			continue
		}
		if s, ok := snaps[r.Node]; ok {
			s.restore(r.Node)
			reverted++
		}
	}
	e.mu.Unlock()
	if reverted > 0 {
		e.log(fmt.Sprintf("Проверка узлов шла при активном Kill Switch или туннеле (либо сеть менялась "+
			"во время неё): %d отказов не записаны — это состояние хоста, а не отказ узлов", reverted))
	}
	return results
}
