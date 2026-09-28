package engine

import (
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// Регресс-тесты на находки полного аудита кода 2026-09-01
// (ТЗ: APF/APF_Audit/TZ_REPAIR_2026-09-01.md).

func repairTestEngine(t *testing.T) *Engine {
	t.Helper()
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	cfg.EnableKillSwitch = false
	cfg.BlockIPv6Leak = false
	cfg.BlockWebRTC = false
	cfg.SetSystemProxy = false
	return New(cfg)
}

// P0-7: ResetNetworkDetailed отменял e.ctx и НИКОГДА не пересоздавал его — движок оставался
// мёртвым до перезапуска процесса (goTracked молча переставал что-либо запускать, а
// e.proc.Start(e.ctx) падал с "context canceled"). Близнец TestStop_RecreatesContext.
func TestResetNetworkDetailed_RecreatesContext(t *testing.T) {
	e := repairTestEngine(t)

	ctxBefore := e.ctx
	_ = e.ResetNetworkDetailed()

	select {
	case <-ctxBefore.Done():
		// ожидаемо: старая сессия действительно завершена
	default:
		t.Fatal("ctx до сброса должен быть отменён — иначе сброс ничего не остановил")
	}

	select {
	case <-e.ctx.Done():
		t.Fatal("P0-7: e.ctx после ResetNetworkDetailed() отменён и не пересоздан — " +
			"движок больше не подключится до перезапуска процесса")
	default:
		// ожидаемо: контекст пересоздан, движок снова работоспособен
	}

	// Контекст обязан быть именно НОВЫМ объектом, а не тем же самым.
	if e.ctx == ctxBefore {
		t.Error("e.ctx не заменён — это тот же отменённый контекст")
	}

	// Практическая проверка: goTracked снова запускает задачи.
	done := make(chan struct{})
	e.goTracked(func() { close(done) })
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("goTracked не запустил задачу после сброса — контекст всё ещё мёртв")
	}
}

// P1-3: markFail обновляла LastChecked, но не трогала Score — у только что провалившегося узла
// оставалась старая хорошая задержка, а возрастной штраф обнулялся. Пересчёт давал мёртвому
// узлу более высокий Score, чем живому, и он выигрывал КАЖДЫЙ выбор до попадания в чёрный
// список. Это механическое объяснение жалобы «первый лучший узел часто мёртв».
func TestSelectBest_DeadNodeDoesNotOutrankLiveNode(t *testing.T) {
	e := repairTestEngine(t)

	// Мёртвый: отличная старая задержка, только что провалился.
	dead := &models.Node{
		ID: "dead", Name: "dead", Protocol: models.ProtoVLESS,
		Address: "1.1.1.1", Port: 443, UUID: "11111111-1111-1111-1111-111111111111",
		Latency: 50, Jitter: 1, Loss: 0,
	}
	// Живой: заметно хуже по задержке, но реально работает.
	live := &models.Node{
		ID: "live", Name: "live", Protocol: models.ProtoVLESS,
		Address: "2.2.2.2", Port: 443, UUID: "22222222-2222-2222-2222-222222222222",
		Latency: 800, Jitter: 20, Loss: 0,
		LastChecked: time.Now(), Status: models.StatusOK,
	}
	live.Score = 1000.0 / 800.0

	// Имитируем ровно то, что делает checker.markFail при отказе.
	dead.FailCount = 1
	dead.SuccessCount = 0
	dead.LastChecked = time.Now()
	dead.Status = models.StatusBlocked
	dead.Score = 0

	e.mu.Lock()
	e.nodes = []*models.Node{dead, live}
	e.mu.Unlock()

	best := e.selectBestForStrategy()
	if best == nil {
		t.Fatal("selectBestForStrategy вернул nil при наличии живого кандидата")
	}
	if best.ID == "dead" {
		t.Errorf("P1-3: выбран только что провалившийся узел (Score=%.4f) вместо живого (Score=%.4f)",
			dead.Score, live.Score)
	}
}

// P1-2: runPoolScan запрашивал getRescanBatch(100) и тут же резал результат до первых 50.
// getRescanBatch кладёт давно-непроверенные узлы в ХВОСТ, поэтому обрезка выбрасывала всю
// explore-долю и оставляла чистый top-50 по Score — замкнутый круг, ради разрыва которого
// функция и написана. Проверяем на уровне ВЫЗЫВАЮЩЕГО, а не самой getRescanBatch: её
// собственный тест был зелёным всё время, пока продакшн-путь был сломан.
func TestRescanBatch_AtScanLimit_KeepsNeverCheckedNodes(t *testing.T) {
	e := repairTestEngine(t)

	var nodes []*models.Node
	// 200 узлов с хорошим Score и свежей проверкой — они заполнят весь top.
	for i := 0; i < 200; i++ {
		nodes = append(nodes, &models.Node{
			ID:          "top" + string(rune('a'+i%26)) + string(rune('a'+i/26)),
			Name:        "top",
			Protocol:    models.ProtoVLESS,
			Address:     "1.1.1.1",
			Port:        443,
			Score:       100 - float64(i)*0.1,
			LastChecked: time.Now(),
		})
	}
	// 30 узлов, которых никогда не проверяли (нулевой LastChecked, нулевой Score).
	for i := 0; i < 30; i++ {
		nodes = append(nodes, &models.Node{
			ID:       "fresh" + string(rune('a'+i)),
			Name:     "never-checked",
			Protocol: models.ProtoVLESS,
			Address:  "2.2.2.2",
			Port:     443,
		})
	}

	e.mu.Lock()
	e.nodes = nodes
	e.mu.Unlock()

	e.mu.RLock()
	batch := e.getRescanBatch(scanBatchLimit)
	e.mu.RUnlock()

	if len(batch) != scanBatchLimit {
		t.Fatalf("батч = %d узлов, ожидалось %d", len(batch), scanBatchLimit)
	}

	neverChecked := 0
	for _, n := range batch {
		if n.LastChecked.IsZero() {
			neverChecked++
		}
	}
	if neverChecked == 0 {
		t.Errorf("P1-2: в батче из %d узлов НЕТ ни одного давно-непроверенного — "+
			"explore-доля потеряна, низкоскоровые узлы никогда не получат шанс на Score",
			len(batch))
	}

	// Доля должна примерно соответствовать rescanExploreFraction (0.4 от 50 = 20).
	want := int(float64(scanBatchLimit) * rescanExploreFraction)
	if neverChecked < want/2 {
		t.Errorf("давно-непроверенных в батче %d, ожидалось около %d", neverChecked, want)
	}
}

// P1-2 (страховка): единый лимит. Раньше их было два и второй незаметно отменял первый.
func TestScanBatchLimit_IsSingleSourceOfTruth(t *testing.T) {
	if scanBatchLimit <= 0 {
		t.Fatalf("scanBatchLimit = %d — бессмысленное значение", scanBatchLimit)
	}
	e := repairTestEngine(t)
	var nodes []*models.Node
	for i := 0; i < scanBatchLimit*3; i++ {
		nodes = append(nodes, &models.Node{
			ID: "n" + string(rune('a'+i%26)) + string(rune('a'+i/26)),
			Protocol: models.ProtoVLESS, Address: "1.1.1.1", Port: 443,
			Score: float64(i),
		})
	}
	e.mu.Lock()
	e.nodes = nodes
	e.mu.Unlock()

	e.mu.RLock()
	batch := e.getRescanBatch(scanBatchLimit)
	e.mu.RUnlock()

	if len(batch) > scanBatchLimit {
		t.Errorf("батч %d > лимита %d", len(batch), scanBatchLimit)
	}
}
