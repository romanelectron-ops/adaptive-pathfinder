// sweep.go — ТЗ v1.3 F4 Stage 1 (консилиум 2026-09-03, R2/ND-4/ND-5/UI-A-16): резюмируемый
// обход ВСЕГО пула быстрой TCP-пробой с прогрессом. До этого «сканирование» проверяло 50 узлов
// за раз и никогда не доходило до конца списка (4000+ узлов), а пользователь не видел, что
// вообще происходит («ищет часами, срывается, не проходит весь список»).
//
// Обход: пачки по sweepBatchSize узлов, конкурентность sweepConcurrency, одна проба на узел
// (CheckAllWith). Курсор — ID последнего проверенного узла в стабильном порядке (по ID) —
// пишется в scan_state.json после каждой пачки, поэтому обход, прерванный крахом/остановкой,
// продолжается с места остановки, а не с начала. Отмена контекста не помечает непроверенные
// узлы (F1.1: OutcomeNotChecked → узел не тронут, курсор не двигается).
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ScanProgress — состояние обхода для UI (HTTP /api/scan/progress, событие apf:scan, bridge).
type ScanProgress struct {
	Phase     string `json:"phase"` // idle | running | done | cancelled | error
	Reason    string `json:"reason,omitempty"`
	Done      int    `json:"done"`
	Total     int    `json:"total"`
	Alive     int    `json:"alive"`
	Verified  int    `json:"verified"` // подтверждённых реальным трафиком в пуле (IsProven)
	ETASec    int    `json:"eta_sec"`
	StartedAt int64  `json:"started_at,omitempty"`
	UpdatedAt int64  `json:"updated_at,omitempty"`
	Cursor    string `json:"cursor,omitempty"`
}

var (
	sweepBatchSize   = 200 // var — тесты укорачивают
	sweepConcurrency = 200
	autoSweepDelay   = 5 * time.Second
)

const (
	scanPhaseIdle      = "idle"
	scanPhaseRunning   = "running"
	scanPhaseDone      = "done"
	scanPhaseCancelled = "cancelled"
)

type scanState struct {
	LastID    string `json:"last_id"`
	UpdatedAt int64  `json:"updated_at"`
}

func scanStatePath() string { return filepath.Join(config.DataDir(), "scan_state.json") }

func (e *Engine) loadScanCursor() string {
	data, err := os.ReadFile(scanStatePath())
	if err != nil {
		return ""
	}
	var st scanState
	if json.Unmarshal(data, &st) != nil {
		return ""
	}
	return st.LastID
}

func (e *Engine) saveScanCursor(id string) {
	data, _ := json.Marshal(scanState{LastID: id, UpdatedAt: time.Now().Unix()})
	if err := writeFileAtomic(scanStatePath(), data); err != nil {
		e.log(fmt.Sprintf("Обход пула: курсор не сохранён: %v", err))
	}
}

// GetScanProgress — снимок прогресса (Verified считается по текущему пулу).
func (e *Engine) GetScanProgress() ScanProgress {
	e.sweepMu.Lock()
	p := e.sweepProgress
	e.sweepMu.Unlock()
	if p.Phase == "" {
		p.Phase = scanPhaseIdle
	}
	p.Verified = e.provenCount()
	return p
}

func (e *Engine) provenCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	n := 0
	for _, node := range e.nodes {
		if node != nil && node.IsProven() {
			n++
		}
	}
	return n
}

// StartSweep запускает обход пула в фоне (reason: manual|auto). Ошибка, если обход уже идёт.
func (e *Engine) StartSweep(reason string) error {
	if !e.sweepRunning.CompareAndSwap(false, true) {
		return errors.New("обход пула уже выполняется")
	}
	ctx, cancel := context.WithCancel(e.currentCtx())
	e.sweepMu.Lock()
	e.sweepCancel = cancel
	e.sweepProgress = ScanProgress{Phase: scanPhaseRunning, Reason: reason, StartedAt: time.Now().Unix()}
	e.sweepMu.Unlock()
	e.goTracked(func() {
		defer e.sweepRunning.Store(false)
		defer cancel()
		e.runSweep(ctx, reason)
	})
	return nil
}

// CancelSweep прерывает текущий обход (непроверенные узлы не трогаются, курсор остаётся).
func (e *Engine) CancelSweep() {
	e.sweepMu.Lock()
	cancel := e.sweepCancel
	e.sweepMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// SweepRunning — идёт ли обход.
func (e *Engine) SweepRunning() bool { return e.sweepRunning.Load() }

func (e *Engine) setSweepProgress(mutate func(p *ScanProgress)) ScanProgress {
	e.sweepMu.Lock()
	mutate(&e.sweepProgress)
	e.sweepProgress.UpdatedAt = time.Now().Unix()
	p := e.sweepProgress
	e.sweepMu.Unlock()
	if e.OnScanProgress != nil {
		p.Verified = e.provenCount()
		e.OnScanProgress(p)
	}
	return p
}

// sweepablePool — узлы, участвующие в обходе, в стабильном порядке по ID: не бан пользователя,
// не партнёр цепочки (у него свой путь), не удалённые (их в пуле нет).
func (e *Engine) sweepablePool() []*models.Node {
	e.mu.RLock()
	pool := make([]*models.Node, 0, len(e.nodes))
	for _, n := range e.nodes {
		if n != nil && !n.UserBanned && !n.IsChainPartner {
			pool = append(pool, n)
		}
	}
	e.mu.RUnlock()
	sort.Slice(pool, func(i, j int) bool { return pool[i].ID < pool[j].ID })
	return pool
}

func (e *Engine) runSweep(ctx context.Context, reason string) {
	pool := e.sweepablePool()
	total := len(pool)
	if total == 0 {
		e.setSweepProgress(func(p *ScanProgress) { p.Phase = scanPhaseDone })
		e.log("Обход пула: узлов нет")
		e.log("[diag-N8] stage=runSweep took=0s alive=0 total=0 done=0")
		return
	}
	// Продолжаем после курсора (первый ID строго больше сохранённого); курсор не найден или
	// был последним — с начала. Один полный круг за запуск.
	start := 0
	if cursor := e.loadScanCursor(); cursor != "" {
		for i, n := range pool {
			if n.ID > cursor {
				start = i
				break
			}
		}
	}
	order := make([]*models.Node, 0, total)
	order = append(order, pool[start:]...)
	order = append(order, pool[:start]...)

	e.log(fmt.Sprintf("Обход пула (%s): %d узлов, пачки по %d, с позиции %d", reason, total, sweepBatchSize, start))
	startedAt := time.Now()
	done, alive := 0, 0
	// N-8 (§3 DIAG_N8_PLAN.md, "runSweep +alive/total"): один defer покрывает ВСЕ выходы
	// (нормальное завершение и оба cancel-возврата ниже) — done/alive читаются в момент
	// срабатывания defer, т.е. с итоговыми значениями.
	defer func() {
		e.log(fmt.Sprintf("[diag-N8] stage=runSweep took=%s alive=%d total=%d done=%d",
			time.Since(startedAt).Round(time.Millisecond), alive, total, done))
	}()
	e.setSweepProgress(func(p *ScanProgress) { p.Total = total; p.Done = 0; p.Alive = 0 })
	cb := e.OnNodeUpdated
	for i := 0; i < total; i += sweepBatchSize {
		if ctx.Err() != nil {
			e.finishSweep(scanPhaseCancelled, done, total, alive)
			return
		}
		end := i + sweepBatchSize
		if end > total {
			end = total
		}
		batch := order[i:end]
		results := e.checkNodesWithSerialized(ctx, batch, sweepConcurrency, 1)
		for _, r := range results {
			if r == nil {
				continue
			}
			if r.Outcome == models.OutcomeNotChecked {
				// Отмена посреди пачки: часть узлов не проверена — курсор НЕ двигаем (КТ-10).
				e.finishSweep(scanPhaseCancelled, done, total, alive)
				return
			}
			if r.Success {
				alive++
			}
			if cb != nil && r.Node != nil {
				cb(r.Node)
			}
		}
		done += len(batch)
		e.saveScanCursor(batch[len(batch)-1].ID)
		elapsed := time.Since(startedAt)
		eta := 0
		if done > 0 && done < total {
			eta = int(float64(elapsed) / float64(done) * float64(total-done) / float64(time.Second))
		}
		e.setSweepProgress(func(p *ScanProgress) {
			p.Done, p.Alive, p.ETASec, p.Cursor = done, alive, eta, batch[len(batch)-1].ID
		})
	}
	e.saveNodes()
	e.finishSweep(scanPhaseDone, done, total, alive)
}

func (e *Engine) finishSweep(phase string, done, total, alive int) {
	e.setSweepProgress(func(p *ScanProgress) { p.Phase, p.Done, p.Total, p.Alive, p.ETASec = phase, done, total, alive, 0 })
	switch phase {
	case scanPhaseDone:
		e.log(fmt.Sprintf("Обход пула завершён: живых %d из %d", alive, total))
	case scanPhaseCancelled:
		e.log(fmt.Sprintf("Обход пула прерван: проверено %d из %d (живых %d) — продолжится с этого места", done, total, alive))
	}
}

// maybeAutoSweep — фоновый обход, пока движок простаивает (Start без AutoConnect): к первому
// «Подключить» пул уже прощупан целиком, а не первые 50 узлов. При активном подключении не
// запускается: с Kill Switch прямые пробы к чужим узлам блокируются, в TUN-режиме — идут через
// туннель и меряют не то (V1 R3).
func (e *Engine) maybeAutoSweep() {
	if e.cfg == nil || e.cfg.AutoConnect {
		return
	}
	e.goTracked(func() {
		if !e.sleepCtx(autoSweepDelay) || e.IsConnected() {
			return
		}
		if err := e.StartSweep("auto"); err != nil {
			e.log("Обход пула: " + err.Error())
		}
	})
}
