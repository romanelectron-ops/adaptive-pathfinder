// engine_lot04_verifystate_test.go — «канал подтверждён» обязан гаснуть, когда канал признан
// мёртвым (LOT-04, 2026-09-06).
//
// Симптом, который закрывают эти тесты (жалоба «пишет ВПН подключен, а зайти на сайт не могу»):
// ConnectionState.Verified выставлялся в true один раз, из runPostConnectHealthCheck, и не гас
// НИКОГДА, кроме нового подключения и полного отключения. Смерть туннеля флаг не трогала ни в
// одной из трёх точек обнаружения (Watchdog.OnDead, серия отказов monitor(), провал повторного
// health-check), а переключение (emergencySwitch) имеет семь ранних return — на каждом из них
// сессия оставалась «Connected=true, Verified=true» на заведомо мёртвом канале, и все три UI
// показывали зелёное «Подключено».
package engine

import (
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// deadTestNode — узел, который заведомо не отвечает: петля, порт 1. Никакого выхода в сеть,
// отказ мгновенный (netguard/hostguard не задействованы — QuickPing бьёт напрямую в 127.0.0.1).
func deadTestNode(id string) *models.Node {
	return &models.Node{
		ID: id, Name: id, Protocol: models.ProtoVLESS,
		Address: "127.0.0.1", Port: 1,
	}
}

// newVerifiedEngine — движок в состоянии «подключён и канал подтверждён»: ровно то состояние,
// из которого пользователь наблюдал зелёное «Подключено» на мёртвом туннеле.
// Автопереключение выключено НАМЕРЕННО: состояние обязано стать честным САМО, в точке
// обнаружения смерти, а не как побочный эффект удавшегося переключения (в живых логах
// переключение как раз и не случалось — его срезал один из семи ранних return).
func newVerifiedEngine(t *testing.T, id string) (*Engine, *models.Node) {
	t.Helper()
	withTempDataDir(t)
	cfg := models.DefaultConfig()
	cfg.NodeAutoSwitchEnabled = false
	cfg.SetSystemProxy = false
	cfg.ListenPort = 59991 // никто не слушает: health-check через SOCKS обязан провалиться
	e := New(cfg)
	node := deadTestNode(id)
	setNodes(e, node)
	e.stateMu.Lock()
	e.state.Connected = true
	e.state.Verified = true
	e.state.VerifyState = models.VerifyVerified
	e.state.ActiveNode = node
	e.state.Since = time.Now().Add(-10 * time.Minute) // сессия старая: гейт MinUptimeSec ни при чём
	e.stateMu.Unlock()
	return e, node
}

// assertChannelDead — оба поля контракта погасли и остались тождественны друг другу.
func assertChannelDead(t *testing.T, e *Engine, where string) {
	t.Helper()
	st := e.GetState()
	if st.Verified {
		t.Errorf("%s: канал признан мёртвым, но Verified остался true — UI покажет зелёное "+
			"«Подключено» на неработающем туннеле", where)
	}
	if st.VerifyState != models.VerifyFailed {
		t.Errorf("%s: VerifyState = %q, ожидалось %q", where, st.VerifyState, models.VerifyFailed)
	}
	if st.Verified != (st.VerifyState == models.VerifyVerified) {
		t.Errorf("%s: Verified (%v) разошёлся с VerifyState (%q)", where, st.Verified, st.VerifyState)
	}
}

// waitTracked — дождаться фоновых задач движка (goTracked), но не залипнуть навсегда.
func waitTracked(t *testing.T, e *Engine) {
	t.Helper()
	done := make(chan struct{})
	go func() { e.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Log("фоновые задачи движка не завершились за 10с — продолжаю проверку состояния")
	}
}

// Точка обнаружения смерти №1: Watchdog объявил туннель мёртвым (три HTTP-проверки через
// туннель подряд провалились). Раньше обработчик только записывал сбой в узел и звал
// emergencySwitch — состояние подключения оставалось «подтверждено».
func TestWatchdogOnDead_ClearsVerifiedState(t *testing.T) {
	e, _ := newVerifiedEngine(t, "wd-dead")
	// Отменяем контекст ДО вызова: goTracked(emergencySwitch) тогда не стартует вовсе, и тест
	// проверяет ровно то, что должен — честность состояния БЕЗ участия переключения.
	e.cancel()

	e.watchdog.OnDead()

	assertChannelDead(t, e, "Watchdog.OnDead")
}

// Точка обнаружения смерти №2: monitor() набрал 5 отказов подряд по активному узлу.
func TestMonitorConsistentFailures_ClearsVerifiedState(t *testing.T) {
	e, node := newVerifiedEngine(t, "mon-dead")
	node.FailCount = 4 // следующий отказ — пятый, порог monitor()
	e.cancel()

	e.monitor()

	if node.FailCount < 5 {
		t.Fatalf("предусловие теста не выполнено: monitor() не засчитал отказ (FailCount=%d)",
			node.FailCount)
	}
	assertChannelDead(t, e, "monitor()")
}

// Точка обнаружения смерти №3: провал ПОВТОРНОГО health-check. Его специально запускает
// emergencySwitch из sticky-паузы (единственная перепроверка настоящим HTTP через туннель), и
// именно эта ветка не трогала состояние вовсе.
func TestPostConnectHealthCheckFailure_ClearsVerifiedState(t *testing.T) {
	e, _ := newVerifiedEngine(t, "hc-dead")
	defer waitTracked(t, e)

	e.runPostConnectHealthCheck() // SOCKS на 59991 не поднят — обе пробы провалятся

	assertChannelDead(t, e, "runPostConnectHealthCheck")
}

// ─── Инвариант контракта: Verified ≡ (VerifyState == verified) ────────────────────────────

// assertInvariant — единственное, что обязано выполняться ВСЕГДА и во всех переходах.
func assertInvariant(t *testing.T, e *Engine, after string) {
	t.Helper()
	st := e.GetState()
	if st.Verified != (st.VerifyState == models.VerifyVerified) {
		t.Fatalf("после %s поля разошлись: Verified=%v, VerifyState=%q", after, st.Verified, st.VerifyState)
	}
}

// Обход ВСЕХ переходов состояния подтверждения по очереди. Разойтись поля не вправе ни на одном
// шаге: bool читают старые сборки UI, строку — новые, и расхождение видно пользователю как «два
// места в одном приложении говорят разное про одно подключение».
func TestVerifyState_NeverDivergesFromVerifiedFlag(t *testing.T) {
	withTempDataDir(t)
	cfg := models.DefaultConfig()
	cfg.NodeAutoSwitchEnabled = false
	cfg.SetSystemProxy = false
	e := New(cfg)
	e.cancel() // фоновым задачам здесь делать нечего

	// Свежий движок: ни разу не подключался.
	assertInvariant(t, e, "New()")
	if got := e.GetState().VerifyState; got != models.VerifyIdle {
		t.Errorf("свежий движок: VerifyState=%q, ожидалось %q", got, models.VerifyIdle)
	}

	node := deadTestNode("inv-1")
	setNodes(e, node)

	steps := []struct {
		name string
		do   func()
		want string
	}{
		// «Туннель поднят, проверка впереди» — то, что делает applySingBoxConfig.
		{"подключение (проверка идёт)", func() {
			e.stateMu.Lock()
			e.state.Connected = true
			e.state.ActiveNode = node
			e.setVerifyStateLocked(verifyStateOnApply(e.state.VerifyState, false))
			e.stateMu.Unlock()
		}, models.VerifyChecking},
		// Успех пост-коннект проверки.
		{"канал подтверждён", func() {
			e.stateMu.Lock()
			e.setVerifyStateLocked(models.VerifyVerified)
			e.stateMu.Unlock()
		}, models.VerifyVerified},
		// Смерть канала в любой из трёх точек обнаружения.
		{"канал признан мёртвым", func() { e.markChannelDead("тест") }, models.VerifyFailed},
		// Повторная смерть — идемпотентна, состояние то же.
		{"повторное обнаружение смерти", func() { e.markChannelDead("тест") }, models.VerifyFailed},
		// Самовосстановление без переключения (успешная проверка Watchdog).
		{"канал снова отвечает", func() { e.markChannelAliveAgain() }, models.VerifyVerified},
		// Отключение.
		{"отключение", func() { e.setDisconnected() }, models.VerifyIdle},
		// Смерть на СНЯТОМ туннеле не должна выдумывать «провал проверки» — предмета нет.
		{"смерть после отключения игнорируется", func() { e.markChannelDead("тест") }, models.VerifyIdle},
		// Восстановление на снятом туннеле — тоже.
		{"восстановление после отключения игнорируется", func() { e.markChannelAliveAgain() }, models.VerifyIdle},
	}
	for _, s := range steps {
		s.do()
		assertInvariant(t, e, s.name)
		if got := e.GetState().VerifyState; got != s.want {
			t.Errorf("после «%s»: VerifyState=%q, ожидалось %q", s.name, got, s.want)
		}
	}
}

// ─── Переприменение правил к живому узлу не должно гасить подтверждение ───────────────────

// Решение вынесено в verifyStateOnApply отдельной функцией именно потому, что сама
// applySingBoxConfig под `go test` не проходит дальше барьера hostguard.
func TestVerifyStateOnApply(t *testing.T) {
	cases := []struct {
		name       string
		prev       string
		sameTarget bool
		want       string
	}{
		{"переход на новый узел с подтверждённого", models.VerifyVerified, false, models.VerifyChecking},
		{"переход на новый узел с мёртвого", models.VerifyFailed, false, models.VerifyChecking},
		{"первое подключение", models.VerifyIdle, false, models.VerifyChecking},
		// Главный случай: правка bypass/AdBlock на исправном туннеле. Раньше здесь безусловно
		// вставало «ищу рабочий узел» на несколько секунд — ложная тревога.
		{"переприменение правил к тому же живому узлу", models.VerifyVerified, true, models.VerifyVerified},
		// Переприменение к узлу, который подтверждён НЕ был: подтверждать нечего, честное
		// «проверка идёт» (а не сохранение прежнего «провалилась» — конфигурация-то новая).
		{"переприменение к неподтверждённому узлу", models.VerifyChecking, true, models.VerifyChecking},
		{"переприменение к мёртвому узлу", models.VerifyFailed, true, models.VerifyChecking},
	}
	for _, c := range cases {
		if got := verifyStateOnApply(c.prev, c.sameTarget); got != c.want {
			t.Errorf("%s: verifyStateOnApply(%q, %v) = %q, ожидалось %q",
				c.name, c.prev, c.sameTarget, got, c.want)
		}
	}
}

// Пометка одноразовая и сверяется по указателю: чужое подключение, влезшее между пометкой и
// применением, не должно унаследовать освобождение от сброса.
func TestReapplyTarget_OneShotAndPointerMatched(t *testing.T) {
	withTempDataDir(t)
	e := New(models.DefaultConfig())
	e.cancel()
	node := deadTestNode("reapply-1")
	other := deadTestNode("reapply-2")

	if e.takeReapplyTarget(node, nil) {
		t.Error("без пометки переприменения быть не может")
	}
	e.markReapplyTarget(node, nil)
	if e.takeReapplyTarget(other, nil) {
		t.Error("пометка на один узел не должна опознаваться как переприменение другого")
	}
	if e.takeReapplyTarget(node, nil) {
		t.Error("пометка обязана быть одноразовой: её уже забрало чужое подключение")
	}

	e.markReapplyTarget(node, nil)
	if !e.takeReapplyTarget(node, nil) {
		t.Error("переприменение к тому же узлу не опознано")
	}
	if e.takeReapplyTarget(node, nil) {
		t.Error("пометка не сброшена после того, как её забрали")
	}

	chain := &models.Chain{Nodes: []*models.Node{node}}
	e.markReapplyTarget(nil, chain)
	if !e.takeReapplyTarget(nil, chain) {
		t.Error("переприменение к той же цепочке не опознано")
	}
}

// ─── Свежесть подтверждения: время продлевается, счётчик не раздувается ───────────────────

// Успешные проверки Watchdog идут каждые 15 секунд. Время подтверждения обязано двигаться на
// каждой (иначе ProvenFreshness затухает во время заведомо рабочей сессии), а VerifiedCount —
// нет: он означает «сколько раз канал подтверждён за всю историю» и участвует в ранжировании.
func TestRefreshNodeVerified_ProlongsFreshnessWithoutInflatingCount(t *testing.T) {
	withTempDataDir(t)
	cfg := models.DefaultConfig()
	cfg.SetSystemProxy = false
	e := New(cfg)
	e.cancel()

	node := deadTestNode("fresh-1")
	// Узел уже подтверждался час назад пост-коннект проверкой.
	node.LastVerifiedAt = time.Now().Add(-time.Hour).Unix()
	node.VerifiedCount = 3
	node.FailStreak = 2
	setNodes(e, node)
	e.mu.Lock()
	e.vcBumpNodeID = node.ID
	e.vcBumpAt = time.Now() // счётчик только что рос — окно verifiedCountBumpInterval не истекло
	e.mu.Unlock()

	e.stateMu.Lock()
	e.state.Connected = true
	e.state.ActiveNode = node
	e.state.VerifyState = models.VerifyVerified
	e.state.Verified = true
	e.stateMu.Unlock()

	const checks = 40 // ~10 минут работы сторожа при интервале 15 с
	before := time.Now().Unix()
	for i := 0; i < checks; i++ {
		e.refreshNodeVerified(int64(120 + i))
	}

	e.mu.Lock()
	gotAt, gotCount, gotLat, gotStreak := node.LastVerifiedAt, node.VerifiedCount, node.LastVerifiedLatencyMs, node.FailStreak
	e.mu.Unlock()

	if gotAt < before {
		t.Errorf("свежесть не продлена: LastVerifiedAt=%d, ожидалось не раньше %d", gotAt, before)
	}
	if gotCount != 3 {
		t.Errorf("VerifiedCount раздут: %d за %d успешных проверок подряд, ожидалось 3 "+
			"(окно %v ещё не истекло)", gotCount, checks, verifiedCountBumpInterval)
	}
	if gotLat != int64(120+checks-1) {
		t.Errorf("LastVerifiedLatencyMs не обновлён: %d", gotLat)
	}
	if gotStreak != 0 {
		t.Errorf("FailStreak не сброшен успешной проверкой: %d", gotStreak)
	}
}

// Обратная сторона: окно всё-таки истекло — счётчик обязан вырасти, но ровно на единицу за
// окно, а не на число проверок внутри него.
func TestRefreshNodeVerified_BumpsCountOncePerWindow(t *testing.T) {
	withTempDataDir(t)
	e := New(models.DefaultConfig())
	e.cancel()

	node := deadTestNode("fresh-2")
	node.LastVerifiedAt = time.Now().Add(-2 * time.Hour).Unix()
	node.VerifiedCount = 5
	setNodes(e, node)
	e.mu.Lock()
	e.vcBumpNodeID = node.ID
	e.vcBumpAt = time.Now().Add(-verifiedCountBumpInterval - time.Minute) // окно истекло
	e.mu.Unlock()

	e.stateMu.Lock()
	e.state.Connected = true
	e.state.ActiveNode = node
	e.stateMu.Unlock()

	for i := 0; i < 20; i++ {
		e.refreshNodeVerified(100)
	}

	e.mu.Lock()
	got := node.VerifiedCount
	e.mu.Unlock()
	if got != 6 {
		t.Errorf("VerifiedCount=%d, ожидалось 6: одно окно — один инкремент, "+
			"сколько бы проверок внутрь него ни попало", got)
	}
}

// Узел, который сторож подтвердил первым (пост-коннект проверка не успела или провалилась),
// обязан получить свой первый VerifiedCount — иначе models.Node.IsProven() остаётся false при
// заведомо живом канале, и узел не попадает в «Проверенные».
func TestRefreshNodeVerified_FirstConfirmationCounts(t *testing.T) {
	withTempDataDir(t)
	e := New(models.DefaultConfig())
	e.cancel()

	node := deadTestNode("fresh-3") // VerifiedCount = 0, никогда не подтверждался
	setNodes(e, node)
	e.stateMu.Lock()
	e.state.Connected = true
	e.state.ActiveNode = node
	e.stateMu.Unlock()

	e.refreshNodeVerified(90)
	e.refreshNodeVerified(90)

	e.mu.Lock()
	count, at := node.VerifiedCount, node.LastVerifiedAt
	e.mu.Unlock()
	if count != 1 {
		t.Errorf("VerifiedCount=%d, ожидалось ровно 1 (первое подтверждение засчитано, "+
			"второе — внутри окна)", count)
	}
	if at == 0 {
		t.Error("LastVerifiedAt не записан")
	}
	if !node.IsProven() {
		t.Error("узел с живым подтверждённым каналом обязан считаться проверенным (IsProven)")
	}
}

// Гонка узлов: трафик ведёт победитель группы urltest, а ActiveNode — инициатор. Приписывать
// подтверждение некому — тот же гейт, что у recordNodeVerified (NL-11).
func TestRefreshNodeVerified_SkippedDuringNodeRace(t *testing.T) {
	withTempDataDir(t)
	e := New(models.DefaultConfig())
	e.cancel()

	node := deadTestNode("race-1")
	setNodes(e, node)
	e.stateMu.Lock()
	e.state.Connected = true
	e.state.ActiveNode = node
	e.stateMu.Unlock()
	e.mu.Lock()
	e.raceNodes = []*models.Node{node}
	e.mu.Unlock()

	e.refreshNodeVerified(50)

	e.mu.Lock()
	at, count := node.LastVerifiedAt, node.VerifiedCount
	e.mu.Unlock()
	if at != 0 || count != 0 {
		t.Errorf("при активной гонке узлов подтверждение не должно приписываться инициатору: "+
			"LastVerifiedAt=%d, VerifiedCount=%d", at, count)
	}
}
