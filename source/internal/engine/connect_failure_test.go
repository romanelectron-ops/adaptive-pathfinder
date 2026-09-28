package engine

// Регресс этапа A ТЗ TZ_SINGBOX_HOTSWITCH_WINDOWS_v1.0 §8: узел судится только за СОБСТВЕННЫЙ
// отказ. Живой лог ПК 2026-09-21: медленный старт sing-box.exe (порт не открылся за срок) шесть
// раз подряд штрафовал разные узлы со score 0.84-0.85 и живым TCP (RCA #2); Stop() посреди пробы
// каталога снял 8 системных фаворитов за 150 мс (RCA #3).

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/singbox"
)

func TestClassifyConnectFailure(t *testing.T) {
	plain := errors.New("x")
	cases := []struct {
		name string
		err  error
		want connectFailureClass
	}{
		{"неклассифицированная — узел (как до этапа A)", plain, failureNode},
		{"отказ конфигурации sing-box — узел", fmt.Errorf("sing-box: %w", singbox.ErrConfigRejected), failureNode},
		{"локальный старт sing-box", fmt.Errorf("sing-box: %w", singbox.ErrLocalStart), failureLocal},
		{"стадия отката помечена локальной", markLocalFailure(plain), failureLocal},
		{"отмена нас самих", fmt.Errorf("x: %w", context.Canceled), failureNoJudgement},
		{"отмена важнее локального класса", fmt.Errorf("sing-box: %w", markLocalFailure(fmt.Errorf("прерван: %w", context.Canceled))), failureNoJudgement},
		{"истёкший срок — не «без суждения»", fmt.Errorf("x: %w", context.DeadlineExceeded), failureNode},
		{"явный отказ узла", markNodeFailure(plain), failureNode},
		{"стадия не перекрашивает отказ узла", markLocalFailure(markNodeFailure(plain)), failureNode},
	}
	for _, c := range cases {
		if got := classifyConnectFailure(c.err); got != c.want {
			t.Errorf("%s: класс = %d, ожидался %d", c.name, got, c.want)
		}
	}
}

// Текст причины не меняется — по нему читают журнал и lastRollback.
func TestClassifiedError_KeepsMessage(t *testing.T) {
	cause := errors.New("порт 10808 занят")
	if got := markLocalFailure(cause).Error(); got != cause.Error() {
		t.Errorf("текст изменён: %q", got)
	}
	if !errors.Is(markLocalFailure(cause), cause) {
		t.Error("исходная причина потеряна из цепочки")
	}
}

func TestClassifyRollbackCause(t *testing.T) {
	plain := errors.New("x")
	for _, stage := range []string{"listen_port", "killswitch", "write_config", "killswitch_tun"} {
		if classifyConnectFailure(classifyRollbackCause(stage, plain)) != failureLocal {
			t.Errorf("стадия %s — сторона машины, ожидался локальный класс", stage)
		}
	}
	if classifyConnectFailure(classifyRollbackCause("apply_runtime", plain)) != failureNode {
		t.Error("apply_runtime без класса от запускателя обязан остаться отказом узла (Android — как было)")
	}
	if classifyConnectFailure(classifyRollbackCause("apply_runtime", fmt.Errorf("sing-box: %w", singbox.ErrLocalStart))) != failureLocal {
		t.Error("apply_runtime с локальным классом запускателя потерял класс")
	}
	nodeErr := markNodeFailure(errors.New("адрес узла не приведён к IP"))
	if classifyConnectFailure(classifyRollbackCause("killswitch", nodeErr)) != failureNode {
		t.Error("неразрешимый адрес узла на стадии Kill Switch перекрашен в локальный сбой")
	}
}

// buildableNode — узел, конфиг которого собирается: connectNode доходит до applySingBoxConfig,
// а там под `go test` срабатывает барьер hostguard — ровно локальный отказ «эта машина не
// запустила sing-box», без единой сетевой операции.
func buildableNode(id string, score float64) *models.Node {
	return &models.Node{ID: id, Name: id, Address: "10.0.0.7", Port: 443, Protocol: models.ProtoVLESS,
		UUID: "11111111-1111-1111-1111-111111111111", Status: models.StatusOK, Score: score}
}

// A1+A2: локальный сбой — узел не штрафуется, следующий кандидат не пробуется.
func TestConnectTopCandidates_LocalFailureStopsWithoutPenalty(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	logs := captureLogs(e)

	nodes := []*models.Node{buildableNode("l1", 0.85), buildableNode("l2", 0.84), buildableNode("l3", 0.83)}
	setNodes(e, nodes...)

	err := e.connectTopCandidates(nodes, "test")
	if err == nil {
		t.Fatal("под go test sing-box не запускается — ожидалась ошибка")
	}
	if classifyConnectFailure(err) != failureLocal {
		t.Fatalf("барьер машины не распознан как локальный сбой: %v\n%v", err, logs.all())
	}
	for _, n := range nodes {
		if n.LastFailReason != "" || n.FailStreak != 0 {
			t.Errorf("узел %s оштрафован за сбой машины: reason=%q streak=%d", n.ID, n.LastFailReason, n.FailStreak)
		}
		if e.isRecentlyFailed(n.ID) {
			t.Errorf("узел %s исключён на 10 мин за сбой машины", n.ID)
		}
	}
	if n := nodes[0]; n.Score != 0.85 {
		t.Errorf("score первого узла изменён: %v", n.Score)
	}
	if logs.has("«l2»") || logs.has("«l3»") {
		t.Errorf("после локального сбоя перебор обязан остановиться: %v", logs.all())
	}
	if !logs.has("сбоя на этой машине") {
		t.Errorf("нет понятного сообщения о локальном сбое: %v", logs.all())
	}
}

// Отказ узла по-прежнему штрафуется и ведёт к следующему кандидату (поведение до этапа A).
func TestConnectTopCandidates_NodeFailureStillPenalizedAndAdvances(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	logs := captureLogs(e)

	bad := badNode("bad", 0.9) // AmneziaWG: конфиг узла не собирается — отказ именно узла
	local := buildableNode("next", 0.8)
	setNodes(e, bad, local)

	_ = e.connectTopCandidates([]*models.Node{bad, local}, "test")
	if bad.LastFailReason != failReasonConnect {
		t.Errorf("отказ узла не записан: reason=%q", bad.LastFailReason)
	}
	if !e.isRecentlyFailed(bad.ID) {
		t.Error("узел с отказом не исключён из ближайшего выбора")
	}
	if !logs.has("«next»") {
		t.Errorf("после отказа узла перебор обязан перейти к следующему кандидату: %v", logs.all())
	}
	if local.LastFailReason != "" {
		t.Errorf("следующий узел оштрафован за сбой машины: %q", local.LastFailReason)
	}
}

// A2: поиск целиком. Локальный сбой → ре-арминг, без резервов; отмена → без ре-арминга;
// отказ узлов → поиск продолжается.
func TestEndSearchOnNonNodeFailure(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()

	if stop, err := e.endSearchOnNonNodeFailure(errors.New("узел")); stop || err != nil {
		t.Errorf("отказ узлов не должен останавливать поиск: stop=%v err=%v", stop, err)
	}
	if stop, _ := e.endSearchOnNonNodeFailure(nil); stop {
		t.Error("nil не должен останавливать поиск")
	}

	canceled := fmt.Errorf("x: %w", context.Canceled)
	stop, err := e.endSearchOnNonNodeFailure(canceled)
	if !stop || !errors.Is(err, context.Canceled) {
		t.Errorf("отмена: stop=%v err=%v", stop, err)
	}
	if e.reArmPending.Load() {
		t.Error("отмена нас самих не должна планировать ре-арминг")
	}

	local := markLocalFailure(errors.New("порт не открылся"))
	stop, err = e.endSearchOnNonNodeFailure(local)
	if !stop || classifyConnectFailure(err) != failureLocal {
		t.Errorf("локальный сбой: stop=%v err=%v", stop, err)
	}
	if !e.reArmPending.Load() {
		t.Error("локальный сбой обязан запланировать повтор (ре-арминг), иначе связь не вернётся")
	}
}

// M2 (консилиум приёмки): таймаут порта — мягкая ротация (исключение в памяти), но без
// стойкого штрафа; прочие локальные сбои узел не трогают вовсе.
func TestRotateAfterStartTimeout(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()

	timedOut := buildableNode("t1", 0.85)
	e.rotateAfterStartTimeout(timedOut, fmt.Errorf("sing-box: %w", errors.Join(singbox.ErrLocalStart, singbox.ErrReadyTimeout)))
	if !e.isRecentlyFailed(timedOut.ID) {
		t.Error("после таймаута порта узел не ушёл из ближайшего выбора — повтор взял бы его снова (риск зацикливания)")
	}
	if timedOut.LastFailReason != "" || timedOut.Score != 0.85 {
		t.Errorf("мягкая ротация превратилась в стойкий штраф: reason=%q score=%v", timedOut.LastFailReason, timedOut.Score)
	}

	busy := buildableNode("t2", 0.84)
	e.rotateAfterStartTimeout(busy, markLocalFailure(errors.New("порт 10808 занят")))
	if e.isRecentlyFailed(busy.ID) {
		t.Error("занятый порт — однозначно сбой машины, узел исключать нельзя")
	}
	e.rotateAfterStartTimeout(nil, singbox.ErrReadyTimeout) // nil-safe
}

// M1 (консилиум приёмки): если ни одна проба не дошла до суждения об узле (все сорвались на
// машине), Stage 2 (обновление источников из сети + расширенное окно) не запускается.
func TestNodeCheck_AllLocalFailuresSkipStage2(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.Sources = nil
	logs := captureLogs(e)

	setProbePool(e, []*models.Node{tcpAliveNode("s1"), tcpAliveNode("s2"), tcpAliveNode("s3")})
	var calls int32
	e.probeFn = func(ctx context.Context, node *models.Node, slot int) (int64, string, string, error) {
		atomic.AddInt32(&calls, 1)
		return 0, "", "", fmt.Errorf("start probe instance: %w", singbox.ErrLocalStart)
	}
	if err := e.StartNodeCheck(NodeCheckOptions{TopN: 2, TargetK: 100, Concurrency: 1, PerNode: time.Second}); err != nil {
		t.Fatalf("StartNodeCheck: %v", err)
	}
	waitNodeCheckDone(t, e, 5*time.Second)

	if logs.has("Stage2 zero-verified") {
		t.Errorf("Stage 2 запущен, хотя ни одна проба не выполнена по причине машины: %v", logs.all())
	}
	if !logs.has("Stage2 пропущен") {
		t.Errorf("нет объяснения, почему Stage 2 пропущен: %v", logs.all())
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Errorf("пробовано %d узлов, ожидалось 2 (только top-N, без расширения окна)", n)
	}
}

// Контроль: настоящие провалы узлов по-прежнему ведут в Stage 2.
func TestNodeCheck_NodeFailuresStillTriggerStage2(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.Sources = nil
	logs := captureLogs(e)

	setProbePool(e, []*models.Node{tcpAliveNode("n1"), tcpAliveNode("n2"), tcpAliveNode("n3")})
	e.probeFn = func(ctx context.Context, node *models.Node, slot int) (int64, string, string, error) {
		return 0, "", "", errors.New("узел не пропустил трафик")
	}
	if err := e.StartNodeCheck(NodeCheckOptions{TopN: 2, TargetK: 100, Concurrency: 1, PerNode: time.Second}); err != nil {
		t.Fatalf("StartNodeCheck: %v", err)
	}
	waitNodeCheckDone(t, e, 5*time.Second)
	if !logs.has("Stage2 zero-verified") {
		t.Errorf("провалы узлов обязаны вести в Stage 2, как до этапа A: %v", logs.all())
	}
}

// A2 в циклическом поиске: локальный сбой обрывает круг без штрафа и возвращает причину.
func TestTryCyclicSearch_LocalFailureStopsLapWithoutPenalty(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	logs := captureLogs(e)

	// Живые по TCP узлы (слушатели на петле), чтобы круг дошёл до connectNode.
	nodes := make([]*models.Node, 0, 3)
	for i := 0; i < 3; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		n := buildableNode(fmt.Sprintf("c%d", i), 0.5)
		n.Address = "127.0.0.1"
		n.Port = ln.Addr().(*net.TCPAddr).Port
		nodes = append(nodes, n)
	}
	setNodes(e, nodes...)

	ok, err := e.tryCyclicSearch(nil)
	if ok {
		t.Fatal("под go test подключение невозможно")
	}
	if classifyConnectFailure(err) != failureLocal {
		t.Fatalf("круг оборван не локальным сбоем: %v\n%v", err, logs.all())
	}
	tried := 0
	for _, l := range logs.all() {
		if strings.Contains(l, "Циклический поиск: пробую") {
			tried++
		}
	}
	if tried != 1 {
		t.Errorf("после локального сбоя круг обязан остановиться на первом узле, пробовано %d", tried)
	}
	for _, n := range nodes {
		if n.LastFailReason != "" || e.isRecentlyFailed(n.ID) {
			t.Errorf("узел %s оштрафован за сбой машины", n.ID)
		}
	}
}

// A3: проба, не выполненная по вине машины, не штрафует узел, не считается провалом и не
// попадает в реконсиляцию избранного.
func TestNodeCheck_LocalProbeFailureDoesNotJudgeNode(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.Sources = nil

	fav := tcpAliveNode("fav")
	fav.VerifiedCount, fav.LastVerifiedAt = 1, time.Now().Add(-72*time.Hour).Unix()
	other := tcpAliveNode("other")
	setProbePool(e, []*models.Node{fav, other})
	if err := e.AddSystemFavorite(fav.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.SetCatalogReviewInterval(models.ReviewIntervalEachScan); err != nil {
		t.Fatal(err)
	}

	e.probeFn = func(ctx context.Context, node *models.Node, slot int) (int64, string, string, error) {
		return 0, "", "", fmt.Errorf("start probe instance: %w", singbox.ErrLocalStart)
	}
	if err := e.StartNodeCheck(NodeCheckOptions{TopN: 30, TargetK: 100, Concurrency: 2, PerNode: time.Second}); err != nil {
		t.Fatalf("StartNodeCheck: %v", err)
	}
	st := waitNodeCheckDone(t, e, 5*time.Second)

	if st.Failed != 0 {
		t.Errorf("локально не выполненные пробы засчитаны провалами узлов: failed=%d", st.Failed)
	}
	for _, n := range []*models.Node{fav, other} {
		if n.LastFailReason != "" {
			t.Errorf("узел %s оштрафован за сбой машины: %q", n.ID, n.LastFailReason)
		}
	}
	if !e.IsFavorite(fav.ID) {
		t.Error("системный фаворит снят по пробе, которую не удалось выполнить на этой машине")
	}
}

// A3: отменённый прогон не снимает системных фаворитов (RCA #3), а реальные успехи сохраняет.
func TestNodeCheck_CancelledRunDoesNotEvictFavorites(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.Sources = nil

	fav := tcpAliveNode("fav")
	fav.VerifiedCount, fav.LastVerifiedAt = 1, time.Now().Add(-72*time.Hour).Unix()
	winner := tcpAliveNode("winner")
	var hang []*models.Node
	for i := 0; i < 6; i++ {
		hang = append(hang, tcpAliveNode(fmt.Sprintf("hang%d", i)))
	}
	setProbePool(e, append([]*models.Node{fav, winner}, hang...))
	if err := e.AddSystemFavorite(fav.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.SetCatalogReviewInterval(models.ReviewIntervalEachScan); err != nil {
		t.Fatal(err)
	}

	settled := make(chan struct{}, 2)
	e.probeFn = func(ctx context.Context, node *models.Node, slot int) (int64, string, string, error) {
		switch node.ID {
		case fav.ID:
			settled <- struct{}{}
			return 0, "", "", errors.New("fake fail") // настоящий провал ДО отмены
		case winner.ID:
			settled <- struct{}{}
			return 10, "US", "203.0.113.9", nil
		}
		<-ctx.Done() // остальные висят до отмены прогона
		return 0, "", "", ctx.Err()
	}
	if err := e.StartNodeCheck(NodeCheckOptions{TopN: 30, TargetK: 100, Concurrency: 8, PerNode: 30 * time.Second}); err != nil {
		t.Fatalf("StartNodeCheck: %v", err)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-settled:
		case <-time.After(5 * time.Second):
			t.Fatal("пробы fav/winner не завершились")
		}
	}
	// Дать воркерам записать исходы fav/winner до отмены.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if st := e.NodeCheckStatus(); st.Probed >= 2 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	e.CancelNodeCheck()
	st := waitNodeCheckDone(t, e, 5*time.Second)
	if st.Phase != "cancelled" {
		t.Fatalf("phase = %q, want cancelled", st.Phase)
	}

	if !e.IsFavorite(fav.ID) {
		t.Error("отменённый прогон снял системного фаворита — «в сомнении — держим» нарушено")
	}
	if !e.IsFavorite(winner.ID) || e.FavoriteOrigin(winner.ID) != models.OriginSystem {
		t.Error("реальный успех отменённого прогона не добавлен в системное избранное")
	}
	for _, n := range hang {
		if n.LastFailReason != "" {
			t.Errorf("узел %s оштрафован за отмену прогона: %q", n.ID, n.LastFailReason)
		}
	}
	if st.Failed != 1 {
		t.Errorf("failed=%d, ожидался 1 (только настоящий провал fav; отменённые — не провалы)", st.Failed)
	}
}
