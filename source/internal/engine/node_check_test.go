// node_check_test.go — N-1 (ТЗ APF v1.5) тесты пробы реального трафика. Всё через fake-шов
// e.probeFn (сеть/процессы/ФС НЕ трогаются) + один guard-тест боевого пути под netguard.UnderTest.
package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/hostguard"
	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/netguard"
)

// tcpAliveNode — узел, «идеальный по TCP» (Status=OK, малая задержка, недавно проверен), но про
// реальный трафик ничего не известно — ровно класс узлов из N-8 (лог ПК 2026-09-09). Такой узел
// переживает rankCandidatesForStrategy → selectableOnly (Score>0.001) и доходит до пробы.
func tcpAliveNode(id string) *models.Node {
	return &models.Node{
		ID:          id,
		Name:        "probe-" + id,
		Address:     "203.0.113.1",
		Port:        443,
		Protocol:    models.ProtoVLESS,
		Source:      "subscription",
		Status:      models.StatusOK,
		Latency:     20,
		LastChecked: time.Now(),
	}
}

func setProbePool(e *Engine, nodes []*models.Node) {
	e.mu.Lock()
	e.nodes = nodes
	e.mu.Unlock()
}

func waitNodeCheckDone(t *testing.T, e *Engine, timeout time.Duration) NodeCheckStatusSnapshot {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s := e.NodeCheckStatus(); !s.Running {
			return s
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("проба не завершилась за %s (status=%+v)", timeout, e.NodeCheckStatus())
	return NodeCheckStatusSnapshot{}
}

// TestNodeCheck_WritesVerifiedOnlyToPassing — фейк-пробер помечает Verified* ТОЛЬКО прошедшим
// узлам; провалившие получают LastFailReason="probe" и НЕ получают подтверждения (§5, AC-1/N-9).
func TestNodeCheck_WritesVerifiedOnlyToPassing(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.Sources = nil

	nodes := []*models.Node{
		tcpAliveNode("a"), tcpAliveNode("b"), tcpAliveNode("c"),
		tcpAliveNode("d"), tcpAliveNode("e"), tcpAliveNode("f"),
	}
	setProbePool(e, nodes)
	pass := map[string]bool{"a": true, "c": true, "e": true}

	e.probeFn = func(ctx context.Context, node *models.Node, slot int) (int64, string, string, error) {
		if pass[node.ID] {
			return 123, "US", "203.0.113.9", nil
		}
		return 0, "", "", errors.New("fake fail")
	}

	// K больше числа узлов → пробуются ВСЕ (порог остановки не достигается).
	if err := e.StartNodeCheck(NodeCheckOptions{TopN: 30, TargetK: 100, Concurrency: 3, PerNode: time.Second}); err != nil {
		t.Fatalf("StartNodeCheck: %v", err)
	}
	st := waitNodeCheckDone(t, e, 5*time.Second)

	if st.Phase != "done" {
		t.Fatalf("phase = %q, want done", st.Phase)
	}
	if st.Probed != 6 || st.Verified != 3 || st.Failed != 3 {
		t.Fatalf("counters: probed=%d verified=%d failed=%d, want 6/3/3", st.Probed, st.Verified, st.Failed)
	}
	for _, n := range nodes {
		if pass[n.ID] {
			if n.LastVerifiedVia != models.VerifiedViaSOCKS {
				t.Errorf("node %s: LastVerifiedVia=%q, want %q", n.ID, n.LastVerifiedVia, models.VerifiedViaSOCKS)
			}
			if n.LastVerifiedAt == 0 || n.VerifiedCount == 0 {
				t.Errorf("node %s: not marked verified (at=%d cnt=%d)", n.ID, n.LastVerifiedAt, n.VerifiedCount)
			}
			if n.LastVerifiedCountry != "US" || n.LastVerifiedExitIP != "203.0.113.9" {
				t.Errorf("node %s: AC-8 country/exit not written (%q/%q)", n.ID, n.LastVerifiedCountry, n.LastVerifiedExitIP)
			}
			if n.LatencyIsThroughTunnel() {
				t.Errorf("node %s: N-9 SOCKS-проба НЕ должна помечаться «через туннель»", n.ID)
			}
		} else {
			if n.LastVerifiedAt != 0 {
				t.Errorf("node %s: провалившийся узел получил подтверждение", n.ID)
			}
			if n.LastFailReason != "probe" {
				t.Errorf("node %s: LastFailReason=%q, want probe", n.ID, n.LastFailReason)
			}
		}
	}
}

// TestNodeCheck_CancelAbortsWithoutPanic — CancelNodeCheck прерывает прогон чисто (фаза
// "cancelled", running=false), без паники; воркеры уважают дочерний ctx (§5).
func TestNodeCheck_CancelAbortsWithoutPanic(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.Sources = nil

	var nodes []*models.Node
	for i := 0; i < 12; i++ {
		nodes = append(nodes, tcpAliveNode(string(rune('a'+i))))
	}
	setProbePool(e, nodes)

	entered := make(chan struct{}, len(nodes))
	e.probeFn = func(ctx context.Context, node *models.Node, slot int) (int64, string, string, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-ctx.Done() // висим, пока прогон не отменят
		return 0, "", "", ctx.Err()
	}

	if err := e.StartNodeCheck(NodeCheckOptions{TopN: 30, TargetK: 100, Concurrency: 3, PerNode: 30 * time.Second}); err != nil {
		t.Fatalf("StartNodeCheck: %v", err)
	}
	<-entered // дождались, что хотя бы один воркер реально зашёл в пробу
	e.CancelNodeCheck()

	st := waitNodeCheckDone(t, e, 5*time.Second)
	if st.Running {
		t.Fatal("после отмены running=true")
	}
	if st.Phase != "cancelled" {
		t.Fatalf("phase = %q, want cancelled", st.Phase)
	}
}

// TestNodeCheck_StopsAtK — при K подтверждённых проба останавливается: probed < N (ранний стоп) и
// probed ≤ N; verified ≥ K (§5). Все узлы «проходят», чтобы K достигался быстро.
func TestNodeCheck_StopsAtK(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.Sources = nil

	const total = 20
	var nodes []*models.Node
	for i := 0; i < total; i++ {
		nodes = append(nodes, tcpAliveNode(nodeID(i)))
	}
	setProbePool(e, nodes)

	e.probeFn = func(ctx context.Context, node *models.Node, slot int) (int64, string, string, error) {
		return 42, "US", "203.0.113.9", nil
	}

	const k, conc = 5, 2
	if err := e.StartNodeCheck(NodeCheckOptions{TopN: total, TargetK: k, Concurrency: conc, PerNode: time.Second}); err != nil {
		t.Fatalf("StartNodeCheck: %v", err)
	}
	st := waitNodeCheckDone(t, e, 5*time.Second)

	if st.Total != total {
		t.Fatalf("total=%d, want %d", st.Total, total)
	}
	if st.Probed > total {
		t.Fatalf("probed=%d > N=%d", st.Probed, total)
	}
	if st.Verified < k {
		t.Fatalf("verified=%d < K=%d", st.Verified, k)
	}
	if st.Probed >= total {
		t.Fatalf("probed=%d — раннего останова не случилось (ждём < %d)", st.Probed, total)
	}
	// Перебор ограничен числом одновременно летящих проб (concurrency).
	if st.Probed > k+conc {
		t.Fatalf("probed=%d — перебор больше K+concurrency=%d", st.Probed, k+conc)
	}
}

// TestNodeCheck_ConcurrencyLimit — одновременных проб не больше opts.Concurrency, а slot-индексы
// лежат в [0, concurrency) (§5, распределитель слотов).
func TestNodeCheck_ConcurrencyLimit(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.Sources = nil

	const total = 24
	var nodes []*models.Node
	for i := 0; i < total; i++ {
		nodes = append(nodes, tcpAliveNode(nodeID(i)))
	}
	setProbePool(e, nodes)

	const conc = 4
	var cur, max, badSlot int32
	var slotMu sync.Mutex
	slotsSeen := map[int]bool{}

	e.probeFn = func(ctx context.Context, node *models.Node, slot int) (int64, string, string, error) {
		if slot < 0 || slot >= conc {
			atomic.AddInt32(&badSlot, 1)
		}
		slotMu.Lock()
		slotsSeen[slot] = true
		slotMu.Unlock()

		c := atomic.AddInt32(&cur, 1)
		for {
			m := atomic.LoadInt32(&max)
			if c <= m || atomic.CompareAndSwapInt32(&max, m, c) {
				break
			}
		}
		time.Sleep(8 * time.Millisecond) // удержание, чтобы форсировать перекрытие
		atomic.AddInt32(&cur, -1)
		return 42, "US", "203.0.113.9", nil
	}

	if err := e.StartNodeCheck(NodeCheckOptions{TopN: total, TargetK: 1000, Concurrency: conc, PerNode: time.Second}); err != nil {
		t.Fatalf("StartNodeCheck: %v", err)
	}
	waitNodeCheckDone(t, e, 10*time.Second)

	if got := atomic.LoadInt32(&max); got > conc {
		t.Fatalf("макс одновременных проб=%d > лимита %d", got, conc)
	}
	if got := atomic.LoadInt32(&max); got < 2 {
		t.Fatalf("параллельность не сработала (max=%d) — тест ничего не доказывает", got)
	}
	if atomic.LoadInt32(&badSlot) != 0 {
		t.Fatalf("slot-индекс вне [0,%d)", conc)
	}
	if len(slotsSeen) > conc {
		t.Fatalf("использовано %d слотов > concurrency=%d", len(slotsSeen), conc)
	}
}

// TestProbeSlotPorts_NoOverlap — распределитель: шаг ровно 3 (≥3, без перекрытия триплетов
// socks/http/clash), и весь блок избегает окна cfg.ListenPort±2 (§5, C5/O4).
func TestProbeSlotPorts_NoOverlap(t *testing.T) {
	cases := []struct{ base, listen, n int }{
		{probePortBase, 10808, 6},  // умолчания — сдвиг не нужен
		{probePortBase, 21205, 6},  // listenPort ВНУТРИ дефолтного блока → сдвиг
		{probePortBase, 21200, 8},  // listenPort ровно на базе
		{probePortBase, 21201, 1},  // один слот у самой базы
		{probePortBase, 30000, 30}, // большой прогон
		{0, 10808, 6},              // невалидная база → нормализуется к probePortBase
	}
	for _, c := range cases {
		ports := probeSlotPorts(c.base, c.listen, c.n)
		if len(ports) != c.n {
			t.Fatalf("listen=%d n=%d: got %d портов", c.listen, c.n, len(ports))
		}
		used := map[int]bool{}
		for i, p := range ports {
			if i > 0 && p-ports[i-1] < 3 {
				t.Fatalf("listen=%d: шаг между слотами %d < 3 (%v)", c.listen, p-ports[i-1], ports)
			}
			// три порта слота: p, p+1, p+2 — ни один не в окне listen±2 и не пересекается с чужими.
			for _, q := range []int{p, p + 1, p + 2} {
				if q >= c.listen-2 && q <= c.listen+2 {
					t.Fatalf("listen=%d: порт %d слота попал в окно listenPort±2", c.listen, q)
				}
				if used[q] {
					t.Fatalf("listen=%d: порт %d используется двумя слотами (%v)", c.listen, q, ports)
				}
				used[q] = true
			}
			if p < 1024 || p+2 > 65535 {
				t.Fatalf("listen=%d: порт %d вне допустимого диапазона", c.listen, p)
			}
		}
	}
}

// TestNodeCheck_GuardNoEgressNoHostMutation — БОЕВОЙ путь (probeFn==nil) под go test не поднимает
// sing-box и не ходит в сеть: netguard.BlockedCount и hostguard.BlockedCount не меняются пробой
// (AC-2). Гейт netguard.UnderTest() в probeNodeReal короткозамыкает до любого egress/ФС.
func TestNodeCheck_GuardNoEgressNoHostMutation(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.Sources = nil
	// probeFn НЕ подменяем: идёт боевой probeNodeReal, гейтящийся netguard.UnderTest().
	if e.probeFn != nil {
		t.Fatal("probeFn должен быть nil для проверки боевого пути")
	}

	nodes := []*models.Node{tcpAliveNode("g1"), tcpAliveNode("g2"), tcpAliveNode("g3")}
	setProbePool(e, nodes)

	netBefore := netguard.BlockedCount()
	hostBefore := hostguard.BlockedCount()

	if err := e.StartNodeCheck(NodeCheckOptions{TopN: 30, TargetK: 100, Concurrency: 2, PerNode: time.Second}); err != nil {
		t.Fatalf("StartNodeCheck: %v", err)
	}
	st := waitNodeCheckDone(t, e, 5*time.Second)

	if got := netguard.BlockedCount(); got != netBefore {
		t.Fatalf("netguard.BlockedCount изменился пробой: %d → %d (egress под go test?)", netBefore, got)
	}
	if got := hostguard.BlockedCount(); got != hostBefore {
		t.Fatalf("hostguard.BlockedCount изменился пробой: %d → %d (проба не должна трогать ОС)", hostBefore, got)
	}
	// Под гейтом каждый узел провалил пробу — ни один не помечен трафиком.
	for _, n := range nodes {
		if n.LastVerifiedAt != 0 {
			t.Errorf("node %s: боевая проба под go test пометила узел (не должна)", n.ID)
		}
	}
	if st.Verified != 0 {
		t.Fatalf("verified=%d, want 0 (боевой путь под go test)", st.Verified)
	}
}

// TestNodeCheck_AndroidSerial — C7: на Android concurrency форсируется в 1.
func TestNodeCheck_AndroidSerial(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.Sources = nil
	e.directProbeGOOS = "android" // probeGOOS() → android

	const total = 6
	var nodes []*models.Node
	for i := 0; i < total; i++ {
		nodes = append(nodes, tcpAliveNode(nodeID(i)))
	}
	setProbePool(e, nodes)

	var cur, max int32
	e.probeFn = func(ctx context.Context, node *models.Node, slot int) (int64, string, string, error) {
		c := atomic.AddInt32(&cur, 1)
		for {
			m := atomic.LoadInt32(&max)
			if c <= m || atomic.CompareAndSwapInt32(&max, m, c) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		atomic.AddInt32(&cur, -1)
		return 42, "US", "203.0.113.9", nil
	}

	// Просим concurrency=6, но Android обязан сжать до 1.
	if err := e.StartNodeCheck(NodeCheckOptions{TopN: total, TargetK: 1000, Concurrency: 6, PerNode: time.Second}); err != nil {
		t.Fatalf("StartNodeCheck: %v", err)
	}
	waitNodeCheckDone(t, e, 5*time.Second)
	if got := atomic.LoadInt32(&max); got != 1 {
		t.Fatalf("Android: макс одновременных проб=%d, want 1 (серийно, C7)", got)
	}
}

// TestNodeCheck_BusyRejectsSecond — один прогон за раз: второй StartNodeCheck возвращает
// ErrNodeCheckBusy.
func TestNodeCheck_BusyRejectsSecond(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.Sources = nil
	setProbePool(e, []*models.Node{tcpAliveNode("a"), tcpAliveNode("b")})

	release := make(chan struct{})
	e.probeFn = func(ctx context.Context, node *models.Node, slot int) (int64, string, string, error) {
		<-release
		return 42, "US", "203.0.113.9", nil
	}
	if err := e.StartNodeCheck(NodeCheckOptions{TopN: 30, TargetK: 100, Concurrency: 1, PerNode: 30 * time.Second}); err != nil {
		t.Fatalf("StartNodeCheck#1: %v", err)
	}
	if err := e.StartNodeCheck(NodeCheckOptions{}); !errors.Is(err, ErrNodeCheckBusy) {
		t.Fatalf("StartNodeCheck#2 err=%v, want ErrNodeCheckBusy", err)
	}
	close(release)
	waitNodeCheckDone(t, e, 5*time.Second)
}

func nodeID(i int) string { return "n" + string(rune('A'+i)) }

// ─── FIX-1 (консилиум L1-ENG-A, CONSILIUM_L1-ENG-A.md п.1) ──────────────────────────────────

// TestNodeCheck_ActiveNodeExcluded — узел, к которому движок СЕЙЧАС подключён, не должен попасть
// в кандидаты пробы. probeNodeReal поднял бы ВТОРУЮ SOCKS-сессию к тому же серверу — провал такой
// пробы (часть протоколов/серверов не переживают параллельную сессию) вызвал бы recordNodeFailure
// и обнулил Score/поднял FailStreak у РАБОЧЕГО активного узла — демотирование живого узла
// собственной же диагностикой (ровно дефект, найденный консилиумом).
func TestNodeCheck_ActiveNodeExcluded(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.Sources = nil

	active := tcpAliveNode("active-node")
	other1 := tcpAliveNode("other-1")
	other2 := tcpAliveNode("other-2")
	nodes := []*models.Node{active, other1, other2}
	setProbePool(e, nodes)

	// Имитируем «движок подключён к active» — тот же эффект на e.state, что и у
	// applySingBoxConfig при успешном подключении (engine.go).
	e.stateMu.Lock()
	e.state.Connected = true
	e.state.ActiveNode = active
	e.stateMu.Unlock()

	var mu sync.Mutex
	var probedIDs []string
	e.probeFn = func(ctx context.Context, node *models.Node, slot int) (int64, string, string, error) {
		mu.Lock()
		probedIDs = append(probedIDs, node.ID)
		mu.Unlock()
		return 42, "US", "203.0.113.9", nil
	}

	if err := e.StartNodeCheck(NodeCheckOptions{TopN: 30, TargetK: 100, Concurrency: 2, PerNode: time.Second}); err != nil {
		t.Fatalf("StartNodeCheck: %v", err)
	}
	st := waitNodeCheckDone(t, e, 5*time.Second)

	for _, id := range probedIDs {
		if id == active.ID {
			t.Fatalf("активный узел %s был пробован — FIX-1 нарушен (пробованы: %v)", active.ID, probedIDs)
		}
	}
	if st.Total != 2 {
		t.Fatalf("total=%d, want 2 (активный узел исключён ДО подсчёта Total)", st.Total)
	}
	if st.Probed != 2 || st.Verified != 2 {
		t.Fatalf("probed=%d verified=%d, want 2/2 (только other-1/other-2)", st.Probed, st.Verified)
	}
	// Проба вообще не должна была коснуться активного узла — ни провалом, ни подтверждением.
	if active.LastFailedAt != 0 || active.LastFailReason != "" {
		t.Errorf("активный узел получил след провала пробы: FailedAt=%d reason=%q", active.LastFailedAt, active.LastFailReason)
	}
	if active.LastVerifiedAt != 0 || active.VerifiedCount != 0 {
		t.Errorf("активный узел получил след подтверждения пробы (не должен — проба его не касалась): at=%d cnt=%d",
			active.LastVerifiedAt, active.VerifiedCount)
	}
}

// TestNodeCheck_NoActiveNodeProbesEverything — контроль: когда движок НЕ подключён
// (e.state.ActiveNode == nil, обычное состояние до первого коннекта / после Disconnect), фильтр
// FIX-1 не должен убирать ничего лишнего.
func TestNodeCheck_NoActiveNodeProbesEverything(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.Sources = nil
	nodes := []*models.Node{tcpAliveNode("x1"), tcpAliveNode("x2"), tcpAliveNode("x3")}
	setProbePool(e, nodes)
	// e.state.ActiveNode остаётся nil (движок не подключён) — поведение по умолчанию newTestEngine.

	e.probeFn = func(ctx context.Context, node *models.Node, slot int) (int64, string, string, error) {
		return 1, "US", "203.0.113.9", nil
	}
	if err := e.StartNodeCheck(NodeCheckOptions{TopN: 30, TargetK: 100, Concurrency: 2, PerNode: time.Second}); err != nil {
		t.Fatalf("StartNodeCheck: %v", err)
	}
	st := waitNodeCheckDone(t, e, 5*time.Second)
	if st.Total != 3 || st.Verified != 3 {
		t.Fatalf("total=%d verified=%d, want 3/3 (нет активного узла — фильтр не должен убирать никого)", st.Total, st.Verified)
	}
}

// ─── FIX-2 (консилиум L1-ENG-A, CONSILIUM_L1-ENG-A.md п.3) ──────────────────────────────────

// TestNodeCheck_BypassesRaceGate — recordNodeVerifiedVia молча пропускает запись, когда
// e.raceNodes != nil (гонка urltest автоподключения, победитель неизвестен) — верно для
// post-connect (ActiveNode может быть инициатором гонки, а не победителем), но НЕ про каталожную
// пробу: probeNodeReal поднимает СВОЙ, ИЗОЛИРОВАННЫЙ SOCKS-инстанс ИМЕННО на этом узле —
// приписывание трафика однозначно, гонки тут физически нет. До FIX-2 воркер звал
// recordNodeVerifiedVia (гейт применился бы) и БЕЗУСЛОВНО bumpNodeCheck(true) — статус показывал
// бы «verified N» при незаписанном узле, и N-5 (удержание) не сохранил бы его при следующей
// записи на диск (рассинхрон статус/реальность).
func TestNodeCheck_BypassesRaceGate(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.Sources = nil

	nodes := []*models.Node{tcpAliveNode("r1"), tcpAliveNode("r2")}
	setProbePool(e, nodes)

	// Гонка узлов автоподключения (buildNodeConfig/BuildRace) идёт ПАРАЛЛЕЛЬНО сборке каталога —
	// независимый механизм, пробуемых узлов не касается.
	e.mu.Lock()
	e.raceNodes = []*models.Node{{ID: "race-a"}, {ID: "race-b"}}
	e.mu.Unlock()

	e.probeFn = func(ctx context.Context, node *models.Node, slot int) (int64, string, string, error) {
		return 55, "DE", "198.51.100.7", nil
	}

	if err := e.StartNodeCheck(NodeCheckOptions{TopN: 30, TargetK: 100, Concurrency: 2, PerNode: time.Second}); err != nil {
		t.Fatalf("StartNodeCheck: %v", err)
	}
	st := waitNodeCheckDone(t, e, 5*time.Second)

	// Счётчик статуса должен отражать РЕАЛЬНОСТЬ: оба узла реально проверены пробой.
	if st.Verified != len(nodes) || st.Failed != 0 {
		t.Fatalf("counters: verified=%d failed=%d, want %d/0 (гонка автоподключения не должна глушить каталожную пробу)",
			st.Verified, st.Failed, len(nodes))
	}
	for _, n := range nodes {
		if n.LastVerifiedAt == 0 || n.VerifiedCount == 0 {
			t.Errorf("node %s: Verified* НЕ проставлен несмотря на успешную пробу (гейт гонки не должен применяться к каталогу)", n.ID)
		}
		if n.LastVerifiedVia != models.VerifiedViaSOCKS {
			t.Errorf("node %s: LastVerifiedVia=%q, want %q", n.ID, n.LastVerifiedVia, models.VerifiedViaSOCKS)
		}
		if n.LastVerifiedCountry != "DE" || n.LastVerifiedExitIP != "198.51.100.7" {
			t.Errorf("node %s: country/exit не записаны: %q/%q", n.ID, n.LastVerifiedCountry, n.LastVerifiedExitIP)
		}
	}
}

// ─── N-2 (ТЗ APF v1.5 §3, C14) ───────────────────────────────────────────────────────────────

// TestNodeCheck_Stage1EmptyPoolGraceful — Stage 1: пустой пул на старте → StartNodeCheck пробует
// updateSources(true) (с cfg.Sources=nil это безопасный no-op без сети, см.
// sources.FetchAll/TestFetchAll_EmptySources) и корректно завершается Total=0/Phase=done — без
// паники и без зависания.
func TestNodeCheck_Stage1EmptyPoolGraceful(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.Sources = nil
	setProbePool(e, nil) // пул пуст с самого начала

	if err := e.StartNodeCheck(NodeCheckOptions{TopN: 30, TargetK: 8, Concurrency: 2, PerNode: time.Second}); err != nil {
		t.Fatalf("StartNodeCheck: %v", err)
	}
	st := waitNodeCheckDone(t, e, 5*time.Second)
	if st.Phase != "done" {
		t.Fatalf("phase=%q, want done (пустой пул без источников не должен зависать/паниковать)", st.Phase)
	}
	if st.Total != 0 || st.Probed != 0 {
		t.Fatalf("total=%d probed=%d, want 0/0", st.Total, st.Probed)
	}
}

// TestNodeCheck_TopNAll_ProbesWholePool — режим «Все рабочие» (config.NodeCheckTopN =
// models.NodeCheckTopNAll, запрос владельца 09-15): StartNodeCheck читает cfg, ставит
// TopN=TargetK=огромное → ranked[:TopN] НЕ срезает пул, а ранний стоп по TargetK недостижим.
// Проверяем оба следствия: Total == размер пула (нет среза) и Probed == размер пула (нет
// раннего стопа), на пуле заведомо больше любого числового пресета.
func TestNodeCheck_TopNAll_ProbesWholePool(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.Sources = nil
	e.cfg.NodeCheckTopN = models.NodeCheckTopNAll // «Все рабочие»

	const poolSize = 40 // больше дефолта (30) и заметно, чтобы срез был бы виден
	var nodes []*models.Node
	for i := 0; i < poolSize; i++ {
		id := fmt.Sprintf("n-%d", i)
		nodes = append(nodes, &models.Node{
			ID: id, Name: id, Address: "203.0.113.1", Port: 443,
			Protocol: models.ProtoVLESS, Source: "subscription",
			// Разная задержка → детерминированное ранжирование; все проходят пробу ниже.
			Status: models.StatusOK, Latency: int64(i + 1), LastChecked: time.Now(),
		})
	}
	setProbePool(e, nodes)

	e.probeFn = func(ctx context.Context, node *models.Node, slot int) (int64, string, string, error) {
		return 55, "US", "203.0.113.9", nil // все узлы «дают трафик»
	}

	// Пустой TopN в opts → StartNodeCheck подставит cfg.NodeCheckTopN (=All).
	if err := e.StartNodeCheck(NodeCheckOptions{Concurrency: 4, PerNode: time.Second}); err != nil {
		t.Fatalf("StartNodeCheck: %v", err)
	}
	st := waitNodeCheckDone(t, e, 15*time.Second)

	if st.Phase != "done" {
		t.Fatalf("phase=%q, want done", st.Phase)
	}
	if st.Total != poolSize {
		t.Fatalf("total=%d, want %d — режим «Все рабочие» не должен срезать пул до числового потолка", st.Total, poolSize)
	}
	if st.Probed != poolSize {
		t.Fatalf("probed=%d, want %d — TargetK при «Все рабочие» не должен рано останавливать пробу", st.Probed, poolSize)
	}
	if st.Verified != poolSize {
		t.Fatalf("verified=%d, want %d — все узлы отдавали трафик", st.Verified, poolSize)
	}
}

// TestNodeCheck_Stage2WidensWindowOnZeroVerified — Stage 2 retry (C14/O15): top-N дал НОЛЬ
// подтверждённых → окно расширяется (nodeCheckWidenFactor×TopN) и пробуются НОВЫЕ кандидаты, а не
// те же самые (recordNodeFailure НЕ выталкивает узел из следующего rankCandidatesForStrategy —
// Score пересчитывается заново на каждом вызове из Latency/Status, поэтому "виджен" в runNodeCheck
// реализован через явное исключение уже пробованных ID — см. комментарий там). Latency разносит
// ранжирование ДЕТЕРМИНИРОВАННО (score = 1000/latency×…, checker/checker.go:calcScore): быстрые
// (провальные) узлы рангуются строго ПЕРЕД медленными (проходными), поэтому top-N первого прохода
// видит только быстрые.
func TestNodeCheck_Stage2WidensWindowOnZeroVerified(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.Sources = nil

	const topN = 5
	var nodes []*models.Node
	failIDs := map[string]bool{}
	for i := 0; i < topN; i++ {
		id := fmt.Sprintf("fail-%d", i)
		failIDs[id] = true
		nodes = append(nodes, &models.Node{
			ID: id, Name: id, Address: "203.0.113.1", Port: 443,
			Protocol: models.ProtoVLESS, Source: "subscription",
			Status: models.StatusOK, Latency: 5, LastChecked: time.Now(),
		})
	}
	const extraCount = 10
	for i := 0; i < extraCount; i++ {
		id := fmt.Sprintf("pass-%d", i)
		nodes = append(nodes, &models.Node{
			ID: id, Name: id, Address: "203.0.113.1", Port: 443,
			Protocol: models.ProtoVLESS, Source: "subscription",
			Status: models.StatusOK, Latency: 5000, LastChecked: time.Now(),
		})
	}
	setProbePool(e, nodes)

	e.probeFn = func(ctx context.Context, node *models.Node, slot int) (int64, string, string, error) {
		if failIDs[node.ID] {
			return 0, "", "", errors.New("fake fail")
		}
		return 77, "US", "203.0.113.9", nil
	}

	if err := e.StartNodeCheck(NodeCheckOptions{TopN: topN, TargetK: 100, Concurrency: 3, PerNode: time.Second}); err != nil {
		t.Fatalf("StartNodeCheck: %v", err)
	}
	st := waitNodeCheckDone(t, e, 5*time.Second)

	if st.Phase != "done" {
		t.Fatalf("phase=%q, want done", st.Phase)
	}
	if st.Total <= topN {
		t.Fatalf("total=%d, want > %d (окно должно было расшириться после нуля подтверждённых)", st.Total, topN)
	}
	if st.Verified == 0 {
		t.Fatalf("verified=0 — Stage 2 retry не нашёл рабочие узлы за окном top-N (виджен не сработал)")
	}
	passed := 0
	for _, n := range nodes {
		if !failIDs[n.ID] && n.LastVerifiedAt != 0 {
			passed++
		}
	}
	if passed == 0 {
		t.Fatal("ни один из «дальних» (за top-N) узлов не подтвердился — расширение окна их не достигло")
	}
	for _, n := range nodes {
		if failIDs[n.ID] && n.LastVerifiedAt != 0 {
			t.Errorf("провальный узел %s внезапно оказался подтверждён", n.ID)
		}
	}
}

// ─── Минор из консилиума L1-ENG-A (CONSILIUM_L1-ENG-A.md п.4) ───────────────────────────────

// TestProbeSlotPorts_ShiftsDownNearPortCeiling — ветка сдвига блока ВНИЗ (node_check.go,
// probeSlotPorts, else-if down>=1024) не была покрыта тестом: она срабатывает, только когда И
// база пересекается с окном listenPort±2, И сдвиг ВВЕРХ сам вышел бы за 60000 — то есть
// listenPort близко к потолку диапазона портов. Считаем ожидаемое базовое значение вручную и
// проверяем его ТОЧНО (а не только «результат валиден»), чтобы доказать, что сработала именно
// ветка вниз, а не вверх/no-op.
func TestProbeSlotPorts_ShiftsDownNearPortCeiling(t *testing.T) {
	const base, listen, n = 59990, 59991, 6
	// overlaps(base): блок [59990,60007] пересекает окно [59989,59993] → сдвиг нужен.
	// up = listen+3 = 59994; up+n*3-1 = 60011 > 60000 → сдвиг ВВЕРХ невозможен.
	// down = listen-2-n*3 = 59971 >= 1024 → сдвиг ВНИЗ.
	wantBase := listen - 2 - n*3
	ports := probeSlotPorts(base, listen, n)
	if len(ports) != n {
		t.Fatalf("got %d ports, want %d", len(ports), n)
	}
	if ports[0] != wantBase {
		t.Fatalf("ports[0]=%d, want %d (ветка сдвига ВНИЗ не сработала — up-shift сам вышел бы за 60000)",
			ports[0], wantBase)
	}
	for i, p := range ports {
		if i > 0 && p-ports[i-1] != 3 {
			t.Fatalf("шаг между слотами %d != 3", p-ports[i-1])
		}
		for _, q := range []int{p, p + 1, p + 2} {
			if q >= listen-2 && q <= listen+2 {
				t.Fatalf("порт %d попал в окно listenPort±2", q)
			}
			if q < 1024 || q > 65535 {
				t.Fatalf("порт %d вне допустимого диапазона", q)
			}
		}
	}
}
