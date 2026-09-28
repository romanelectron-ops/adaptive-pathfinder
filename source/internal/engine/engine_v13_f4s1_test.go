// engine_v13_f4s1_test.go — ТЗ v1.3 F4 Stage 1: обход пула резюмируется по курсору, прогресс
// монотонен, отмена не помечает непроверенные узлы (КТ-10), второй запуск отклоняется.
package engine

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// listenerPool — n локальных портов: чётные живые (слушатель держит соединения), нечётные мёртвые.
func listenerPool(t *testing.T, n int) (nodes []*models.Node, closeAll func()) {
	t.Helper()
	var lns []net.Listener
	var held []net.Conn
	var mu sync.Mutex
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		if i%2 == 0 {
			lns = append(lns, ln)
			go func(l net.Listener) {
				for {
					c, err := l.Accept()
					if err != nil {
						return
					}
					mu.Lock()
					held = append(held, c)
					mu.Unlock()
				}
			}(ln)
		} else {
			ln.Close()
		}
		// ID задаём явно в лексикографическом порядке — обход идёт по ID.
		nodes = append(nodes, &models.Node{ID: string(rune('a' + i)), Name: "n" + string(rune('a'+i)),
			Address: "127.0.0.1", Port: port, Protocol: models.ProtoVLESS})
	}
	return nodes, func() {
		for _, l := range lns {
			l.Close()
		}
		mu.Lock()
		for _, c := range held {
			c.Close()
		}
		mu.Unlock()
	}
}

func waitSweep(t *testing.T, e *Engine, timeout time.Duration) ScanProgress {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !e.SweepRunning() {
			return e.GetScanProgress()
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("обход не завершился вовремя")
	return ScanProgress{}
}

func TestSweep_FullPass_ProgressMonotone_AliveCounted(t *testing.T) {
	withTempDataDir(t)
	prev := sweepBatchSize
	sweepBatchSize = 2
	t.Cleanup(func() { sweepBatchSize = prev })

	e := newTestEngine()
	nodes, closeAll := listenerPool(t, 6)
	defer closeAll()
	setNodes(e, nodes...)

	var mu sync.Mutex
	var seen []ScanProgress
	e.OnScanProgress = func(p ScanProgress) { mu.Lock(); seen = append(seen, p); mu.Unlock() }
	if err := e.StartSweep("manual"); err != nil {
		t.Fatal(err)
	}
	if err := e.StartSweep("manual"); err == nil {
		t.Error("второй запуск во время обхода должен отклоняться")
	}
	p := waitSweep(t, e, 20*time.Second)
	if p.Phase != scanPhaseDone || p.Done != 6 || p.Total != 6 || p.Alive != 3 {
		t.Fatalf("итог: %+v", p)
	}
	mu.Lock()
	defer mu.Unlock()
	last := -1
	for _, s := range seen {
		if s.Done < last {
			t.Errorf("прогресс не монотонен: %v", seen)
		}
		last = s.Done
	}
	for _, n := range nodes {
		if n.LastChecked.IsZero() {
			t.Errorf("узел %s должен быть проверен", n.ID)
		}
	}
	if data, err := os.ReadFile(filepath.Join(config.DataDir(), "scan_state.json")); err != nil || !strings.Contains(string(data), `"last_id":"f"`) {
		t.Errorf("курсор должен указывать на последний узел круга: err=%v data=%s", err, data)
	}
}

func TestSweep_CancelKeepsCursor_ResumeContinues(t *testing.T) {
	withTempDataDir(t)
	prev := sweepBatchSize
	sweepBatchSize = 2
	t.Cleanup(func() { sweepBatchSize = prev })

	e := newTestEngine()
	nodes, closeAll := listenerPool(t, 6)
	defer closeAll()
	setNodes(e, nodes...)

	// Отменяем после первой пачки (a,b).
	e.OnScanProgress = func(p ScanProgress) {
		if p.Phase == scanPhaseRunning && p.Done == 2 {
			e.CancelSweep()
		}
	}
	if err := e.StartSweep("manual"); err != nil {
		t.Fatal(err)
	}
	p := waitSweep(t, e, 20*time.Second)
	if p.Phase != scanPhaseCancelled || p.Done < 2 || p.Done >= 6 {
		t.Fatalf("после отмены: %+v", p)
	}
	checkedAfterCancel := p.Done
	if e.loadScanCursor() != nodes[checkedAfterCancel-1].ID {
		t.Errorf("курсор=%q, want %q", e.loadScanCursor(), nodes[checkedAfterCancel-1].ID)
	}
	// КТ-10: узлы после курсора не тронуты.
	for _, n := range nodes[checkedAfterCancel:] {
		if !n.LastChecked.IsZero() || n.Status != "" {
			t.Errorf("узел %s не должен быть помечен после отмены: %+v", n.ID, *n)
		}
	}

	// «Перезапуск»: новый движок продолжает с узла после курсора.
	e2 := newTestEngine()
	setNodes(e2, nodes...)
	var order []string
	var mu sync.Mutex
	e2.OnNodeUpdated = func(n *models.Node) { mu.Lock(); order = append(order, n.ID); mu.Unlock() }
	if err := e2.StartSweep("manual"); err != nil {
		t.Fatal(err)
	}
	p2 := waitSweep(t, e2, 20*time.Second)
	if p2.Phase != scanPhaseDone || p2.Done != 6 {
		t.Fatalf("резюмированный обход: %+v", p2)
	}
	mu.Lock()
	first := ""
	if len(order) > 0 {
		first = order[0]
	}
	mu.Unlock()
	if first != nodes[checkedAfterCancel].ID {
		t.Errorf("обход должен продолжиться с %q, начал с %q (order=%v)", nodes[checkedAfterCancel].ID, first, order)
	}
}

func TestSweep_SkipsBannedAndChainPartner(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	nodes, closeAll := listenerPool(t, 4)
	defer closeAll()
	nodes[0].UserBanned = true
	nodes[1].IsChainPartner = true
	setNodes(e, nodes...)
	if got := len(e.sweepablePool()); got != 2 {
		t.Errorf("sweepablePool=%d want 2", got)
	}
	if p := e.GetScanProgress(); p.Phase != scanPhaseIdle {
		t.Errorf("до запуска phase=%q want idle", p.Phase)
	}
}
