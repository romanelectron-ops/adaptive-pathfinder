// engine_k2e_nodecheck_race_test.go — К2-E П1 (свод C, трек 1 №1; B3 #2, A4).
//
// Дефект: четыре пути проверки узлов (runSweep, runPoolScan, tryCyclicSearch, CheckOne из
// AddNode*) работают над ОДНИМИ И ТЕМИ ЖЕ *models.Node без какой-либо сериализации между
// собой. checker.checkOneN/markFail пишут Score, Latency, Jitter, Loss, LastChecked, Status,
// FailCount, BlacklistedUntil прямо в поля узла — без лока. Триггер из свода: engine.go:1403,
// где успешная предпочтительная проверка запускает runPoolScan В ФОНЕ и тут же возвращает
// управление, а фоновый обход пула (StartSweep/maybeAutoSweep) идёт своим чередом.
//
// Наблюдаемое следствие (жалоба владельца): «рабочие узлы пропадают» — рваная запись Score и
// BlacklistedUntil из двух проверок сразу.
package engine

import (
	"net"
	"sync"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// liveLocalNode — узел на живом локальном слушателе: TCP-проба всегда успешна и быстра, узел
// не уходит в чёрный список, поэтому остаётся в выборке обоих путей на всех итерациях.
func liveLocalNode(t *testing.T, id string) *models.Node {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return &models.Node{
		ID:       id,
		Name:     "k2e-" + id,
		Address:  "127.0.0.1",
		Port:     ln.Addr().(*net.TCPAddr).Port,
		Protocol: models.ProtoVLESS,
	}
}

// TestK2E_NodeChecks_Serialized — два ПРОДАКШН-пути проверки над одним узлом одновременно.
// До фикса: WARNING: DATA RACE в checker.checkOneN (запись node.Score/LastChecked/Latency).
// После фикса: обе стороны проходят через одну точку сериализации, гонки нет.
func TestK2E_NodeChecks_Serialized(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	// Источники отключаем: runPoolScan освежает подписки, сеть тесту не нужна.
	e.cfg.Sources = nil

	node := liveLocalNode(t, "k2e-race-node")
	e.mu.Lock()
	e.nodes = []*models.Node{node}
	e.mu.Unlock()

	// Обход пула на одном узле на порядок быстрее скана (одна проба против серии), поэтому
	// «столько же кругов» не пересекались бы по времени: обход крутится, пока идёт скан.
	const rounds = 4
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	// Путь 1 — фоновый доскан пула после успешной предпочтительной проверки (engine.go:1403).
	go func() {
		defer wg.Done()
		defer close(done)
		for i := 0; i < rounds; i++ {
			e.runPoolScan()
		}
	}()
	// Путь 2 — обход всего пула (StartSweep/maybeAutoSweep → runSweep).
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			e.runSweep(e.currentCtx(), "k2e-race")
		}
	}()
	wg.Wait()

	if node.LastChecked.IsZero() {
		t.Fatal("узел так и не был проверен — тест ничего не доказывает")
	}
	t.Logf("OK: %d+%d проверок одного узла двумя путями, Score=%.3f", rounds, rounds, node.Score)
}

// TestK2E_CheckOne_Vs_PoolScan_Serialized — вторая пара из четырёх путей: одиночная проверка
// узла (та, что идёт из AddNode/AddNodeFromLink и из tryPreferredNodesFirst) против скана пула.
func TestK2E_CheckOne_Vs_PoolScan_Serialized(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.Sources = nil

	node := liveLocalNode(t, "k2e-race-node-2")
	e.mu.Lock()
	e.nodes = []*models.Node{node}
	e.mu.Unlock()

	const rounds = 8
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			e.runPoolScan()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			e.checkNodeSerialized(e.currentCtx(), node)
		}
	}()
	wg.Wait()

	if node.LastChecked.IsZero() {
		t.Fatal("узел так и не был проверен — тест ничего не доказывает")
	}
	t.Log("OK: CheckOne и скан пула над одним узлом сериализованы")
}
