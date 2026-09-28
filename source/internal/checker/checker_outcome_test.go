// checker_outcome_test.go — ТЗ v1.3 F1.1 (консилиум 2026-09-03, BB-1/ND-8): контракт B1 с тремя
// исходами. Инвариант КТ-1: отмена контекста НЕ мутирует ни один узел батча.
package checker

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

func presetNode(id string) *models.Node {
	return &models.Node{
		ID: id, Protocol: models.ProtoVLESS, Address: "10.0.0.1", Port: 443,
		Score: 7.5, Status: models.StatusOK, FailCount: 1, SuccessCount: 4,
		Latency: 120, LastChecked: time.Unix(1_700_000_000, 0),
	}
}

func assertUntouched(t *testing.T, n *models.Node, want *models.Node) {
	t.Helper()
	if n.Score != want.Score || n.Status != want.Status || n.FailCount != want.FailCount ||
		n.SuccessCount != want.SuccessCount || n.Latency != want.Latency ||
		!n.LastChecked.Equal(want.LastChecked) || !n.BlacklistedUntil.Equal(want.BlacklistedUntil) {
		t.Errorf("узел %s мутирован при отмене: got %+v want %+v", n.ID, *n, *want)
	}
}

// Позитив/негатив: Outcome согласован с Success на обоих старых путях.
func TestCheckOne_Outcome_OKAndFail(t *testing.T) {
	c := New(2, 5)
	c.dialFn = pipeDialer(time.Millisecond)
	ok := c.CheckOne(context.Background(), presetNode("ok"))
	if ok.Outcome != models.OutcomeOK || !ok.Success {
		t.Fatalf("OK path: outcome=%q success=%v", ok.Outcome, ok.Success)
	}

	c.dialFn = errDialer("connection refused")
	fail := c.CheckOne(context.Background(), presetNode("fail"))
	if fail.Outcome != models.OutcomeFail || fail.Success {
		t.Fatalf("FAIL path: outcome=%q success=%v", fail.Outcome, fail.Success)
	}
	if fail.Node.Status != models.StatusBlocked {
		t.Errorf("FAIL path должен применить markFail, status=%s", fail.Node.Status)
	}
}

// Регрессия 2026-09-05: dial быстрее 1 мс (loopback/LAN) — успех с latency ≥ 1, а не «потеря»
// (0 — сентинел потери в calcStats; раньше пять мгновенных успехов = all pings failed).
func TestCheckOne_SubMillisecondDial_IsNotLoss(t *testing.T) {
	c := New(2, 5)
	c.dialFn = pipeDialer(0)
	r := c.CheckOne(context.Background(), presetNode("fast"))
	if r.Outcome != models.OutcomeOK || !r.Success {
		t.Fatalf("мгновенный dial должен быть успехом: outcome=%q success=%v err=%v", r.Outcome, r.Success, r.Error)
	}
	if r.Node.Latency < 1 || r.Node.Loss != 0 {
		t.Errorf("latency=%d loss=%.0f, want latency>=1 loss=0", r.Node.Latency, r.Node.Loss)
	}
}

// Fail-safe: контекст отменён ДО пробы → NOT_CHECKED, узел не тронут, dial не вызывался.
func TestCheckOne_CtxCanceledBefore_NotChecked_NoMutation(t *testing.T) {
	c := New(2, 5)
	var dials int32
	c.dialFn = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		atomic.AddInt32(&dials, 1)
		return nil, context.Canceled
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	n := presetNode("a")
	want := *n
	r := c.CheckOne(ctx, n)
	if r.Outcome != models.OutcomeNotChecked || r.Success {
		t.Fatalf("outcome=%q success=%v, want not_checked/false", r.Outcome, r.Success)
	}
	assertUntouched(t, n, &want)
	if atomic.LoadInt32(&dials) != 0 {
		t.Errorf("при отменённом ctx dial не должен вызываться, вызван %d раз", dials)
	}
}

// Fail-safe: отмена ВО ВРЕМЯ пробы (после первого успешного сэмпла) → NOT_CHECKED, без записи
// неполной серии и без markFail.
func TestCheckOne_CtxCanceledDuring_NotChecked_NoMutation(t *testing.T) {
	c := New(2, 5)
	ctx, cancel := context.WithCancel(context.Background())
	c.dialFn = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		cancel() // отмена приходит посреди серии из PingCount проб
		client, server := net.Pipe()
		go server.Close()
		return client, nil
	}
	n := presetNode("b")
	want := *n
	r := c.CheckOne(ctx, n)
	if r.Outcome != models.OutcomeNotChecked {
		t.Fatalf("outcome=%q, want not_checked", r.Outcome)
	}
	assertUntouched(t, n, &want)
}

// Стойкость на уровне ветки (КТ-1): CheckAll с отменой посреди батча — ни один узел не получил
// markFail, узлы в очереди семафора не тронуты. Раньше все они уходили в Status=blocked.
func TestCheckAll_CtxCancelMidway_LeavesUntestedUntouched(t *testing.T) {
	c := New(1, 5) // concurrency 1 → остальные узлы ждут семафора
	ctx, cancel := context.WithCancel(context.Background())
	var dials int32
	c.dialFn = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		if atomic.AddInt32(&dials, 1) == 1 {
			cancel()
		}
		return nil, context.Canceled
	}
	nodes := make([]*models.Node, 0, 8)
	wants := make([]models.Node, 0, 8)
	for i := 0; i < 8; i++ {
		n := presetNode(string(rune('a' + i)))
		nodes = append(nodes, n)
		wants = append(wants, *n)
	}
	results := c.CheckAll(ctx, nodes)
	if len(results) != len(nodes) {
		t.Fatalf("results=%d want %d", len(results), len(nodes))
	}
	for i, r := range results {
		if r == nil || r.Outcome != models.OutcomeNotChecked {
			t.Errorf("узел %d: outcome=%v, want not_checked", i, r)
			continue
		}
		assertUntouched(t, nodes[i], &wants[i])
	}
}
