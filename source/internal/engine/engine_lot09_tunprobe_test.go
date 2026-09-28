// engine_lot09_tunprobe_test.go — «канал подтверждён» обязано означать «работает тот путь,
// которым реально пользуются приложения» (LOT-09, 2026-09-06).
//
// КОРЕНЬ. runPostConnectHealthCheck подтверждал канал по ОДНОЙ пробе — HTTP через локальный
// SOCKS5 (socks-in sing-box). Браузер и все приложения телефона ходят через TUN-интерфейс
// (tun-in) — это ДРУГОЙ, независимый inbound-путь. Работоспособность одного ничего не
// доказывает про второй, и живой прогон 2026-08-11 ровно это и показал: проверка зелёная,
// Chrome не открывает ни одного сайта. Пользователь видел «ВПН подключен», а сайтов не было.
//
// Сюда же — три находки предыдущего лота, живущие в этой же функции: гейт по Connected для
// VerifyVerified, «зависшая» VerifyChecking и незакрытый reArmPending.
package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/checker"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── Переключатель живой проверки (пункт 3 ТЗ) ────────────────────────────────────────────

// Таблица случаев для directProbePolicy — единственного места, где записано, где прямая проба
// уже вправе рвать подключение, а где пока только наблюдает. Приём тот же, что у
// verifyStateOnApply и sysProxyFailureAborts: боевая ветка (goos=="android", настоящий TUN) под
// `go test` на этой машине недостижима.
func TestDirectProbePolicy_Table(t *testing.T) {
	cases := []struct {
		mode, goos string
		want       tunDirectProbePolicy
		why        string
	}{
		{models.ModeProxy, "android", directProbeSkip,
			"proxy-режим: приложения ходят через локальный SOCKS, прямая проба ушла бы мимо туннеля"},
		{models.ModeProxy, "windows", directProbeSkip, "то же на десктопе"},
		{models.ModeVPN, "android", directProbeEnforce,
			"единственная платформа с живым стендом — здесь провал прямой пробы обязан гасить подтверждение"},
		{models.ModeVPN, "windows", directProbeObserve,
			"Windows-стенда с рабочим TUN нет (wintun-адаптер) — наблюдаем и логируем, но не рвём"},
		{models.ModeVPN, "linux", directProbeObserve, "то же для прочих платформ"},
		{models.ModeVPN, "darwin", directProbeObserve, "то же для прочих платформ"},
		{models.ModeHybrid, "android", directProbeEnforce, "в hybrid приложения тоже идут через TUN"},
		{models.ModeHybrid, "windows", directProbeObserve, "TUN есть, живой проверки нет"},
	}
	for _, tc := range cases {
		if got := directProbePolicy(tc.mode, tc.goos); got != tc.want {
			t.Errorf("directProbePolicy(%q, %q) = %v, ожидалось %v (%s)",
				tc.mode, tc.goos, got, tc.want, tc.why)
		}
	}
}

// ─── Обвязка тестов пост-коннект проверки ─────────────────────────────────────────────────

type probeScript struct {
	socksErr   error
	directErr  error
	socksHits  int
	directHits int
	// onSOCKS — вмешаться в состояние движка ровно в момент пробы (нужно для гейта по Connected).
	onSOCKS func()
}

// newProbeEngine — движок сразу после (пере)подключения: туннель поднят, идёт проверка канала.
// Обе пробы подменены — настоящий SOCKS самого APF под `go test` не поднят, а выход в интернет
// закрыт netguard, поэтому боевую развилку иначе нечем закрепить (см. поля healthProbe* у
// структуры Engine).
func newProbeEngine(t *testing.T, mode, goos string, sc *probeScript) (*Engine, *models.Node) {
	t.Helper()
	withTempDataDir(t)
	cfg := models.DefaultConfig()
	cfg.ConnectionMode = mode
	cfg.NodeAutoSwitchEnabled = false // переключение здесь не предмет проверки
	cfg.SetSystemProxy = false
	cfg.EnableKillSwitch = false
	e := New(cfg)
	e.directProbeGOOS = goos
	e.healthProbeSOCKS = func(ctx context.Context, target string) (checker.HealthInfo, error) {
		sc.socksHits++
		if sc.onSOCKS != nil {
			sc.onSOCKS()
		}
		if sc.socksErr != nil {
			return checker.HealthInfo{}, sc.socksErr
		}
		return checker.HealthInfo{LatencyMs: 42, Country: "NL", ExitIP: "203.0.113.7"}, nil
	}
	e.healthProbeDirect = func(ctx context.Context, target string) (checker.HealthInfo, error) {
		sc.directHits++
		if sc.directErr != nil {
			return checker.HealthInfo{}, sc.directErr
		}
		return checker.HealthInfo{LatencyMs: 51, Country: "NL", ExitIP: "203.0.113.7"}, nil
	}
	node := deadTestNode("lot09-node")
	setNodes(e, node)
	e.stateMu.Lock()
	e.state.Connected = true
	e.state.VerifyState = models.VerifyChecking
	e.state.Verified = false
	e.state.ActiveNode = node
	e.state.Since = time.Now().Add(-10 * time.Minute)
	e.stateMu.Unlock()
	return e, node
}

func assertVerifyState(t *testing.T, e *Engine, want, where string) {
	t.Helper()
	st := e.GetState()
	if st.VerifyState != want {
		t.Errorf("%s: VerifyState = %q, ожидалось %q", where, st.VerifyState, want)
	}
	if st.Verified != (st.VerifyState == models.VerifyVerified) {
		t.Errorf("%s: инвариант нарушен — Verified=%v при VerifyState=%q",
			where, st.Verified, st.VerifyState)
	}
}

// ─── Ядро лота: TUN-режим требует ОБЕИХ проб ──────────────────────────────────────────────

// ЖАЛОБА ПОЛЬЗОВАТЕЛЯ ДОСЛОВНО. Исходящий канал узла работает (SOCKS зелёная), а трафик
// приложений через туннель не проходит (прямая проба красная). До фикса подтверждение
// выставлялось по одной только первой пробе, и UI показывал «Подключено» на канале, через
// который не открывался ни один сайт.
//
// На неисправленном коде тест падает: VerifyState = "verified", ожидалось "failed".
func TestPostConnect_TunMode_SocksGreenDirectRed_NotVerified(t *testing.T) {
	sc := &probeScript{directErr: errors.New("i/o timeout")}
	e, node := newProbeEngine(t, models.ModeVPN, "android", sc)
	defer waitTracked(t, e)

	e.runPostConnectHealthCheck()

	assertVerifyState(t, e, models.VerifyFailed, "SOCKS зелёная + прямая красная")
	if st := e.GetState(); st.Verified {
		t.Error("канал подтверждён при неработающем пути приложений — это и есть жалоба пользователя")
	}
	if sc.directHits == 0 {
		t.Fatal("прямая проба вообще не выполнялась — проверять было нечего")
	}
	if node.LastFailReason != failReasonTunProbe {
		t.Errorf("причина сбоя записана в узел как %q, ожидалось %q — диагноз «узел мёртв» и "+
			"«узел жив, но трафик до него не доходит» различаются", node.LastFailReason, failReasonTunProbe)
	}
	if node.VerifiedCount != 0 {
		t.Errorf("узлу засчитано подтверждение (VerifiedCount=%d), хотя трафик приложений не шёл",
			node.VerifiedCount)
	}
}

// Обе зелёные — канал подтверждён, как и раньше.
func TestPostConnect_TunMode_BothGreen_Verified(t *testing.T) {
	sc := &probeScript{}
	e, node := newProbeEngine(t, models.ModeVPN, "android", sc)
	defer waitTracked(t, e)

	e.runPostConnectHealthCheck()

	assertVerifyState(t, e, models.VerifyVerified, "обе пробы зелёные")
	if sc.socksHits == 0 || sc.directHits == 0 {
		t.Fatalf("в TUN-режиме обязаны выполниться обе пробы: socks=%d direct=%d",
			sc.socksHits, sc.directHits)
	}
	if node.LastVerifiedAt == 0 || node.VerifiedCount != 1 {
		t.Errorf("подтверждение не записано в узел: LastVerifiedAt=%d VerifiedCount=%d",
			node.LastVerifiedAt, node.VerifiedCount)
	}
}

// SOCKS красная — до прямой пробы дело не доходит вовсе (прежнее поведение, точка обнаружения
// смерти №3), и лишнего запроса наружу не делается.
func TestPostConnect_TunMode_SocksRed_ShortCircuits(t *testing.T) {
	sc := &probeScript{socksErr: errors.New("socks5: dial proxy: refused")}
	e, _ := newProbeEngine(t, models.ModeVPN, "android", sc)
	defer waitTracked(t, e)

	e.runPostConnectHealthCheck()

	assertVerifyState(t, e, models.VerifyFailed, "SOCKS красная")
	if sc.directHits != 0 {
		t.Errorf("прямая проба выполнена %d раз, хотя исходящий канал узла уже провалился", sc.directHits)
	}
}

// РЕГРЕССИЯ. В proxy-режиме приложения ходят как раз через локальный SOCKS — прямая проба
// ушла бы МИМО туннеля, в обычный интернет, и не доказала бы ничего. Критерий обязан остаться
// прежним: одна проба через SOCKS.
func TestPostConnect_ProxyMode_DirectProbeNotRunAndIrrelevant(t *testing.T) {
	sc := &probeScript{directErr: errors.New("этой пробы здесь быть не должно")}
	e, _ := newProbeEngine(t, models.ModeProxy, "android", sc)
	defer waitTracked(t, e)

	e.runPostConnectHealthCheck()

	assertVerifyState(t, e, models.VerifyVerified, "proxy-режим, SOCKS зелёная")
	if sc.directHits != 0 {
		t.Errorf("в proxy-режиме прямая проба выполнена %d раз — она проверяет не тот путь "+
			"и не вправе влиять на вердикт", sc.directHits)
	}
}

// Пункт 3 ТЗ: на платформе без живого стенда прямая проба ВЫПОЛНЯЕТСЯ и ЛОГИРУЕТСЯ, но её
// провал подтверждение не блокирует. Переключить — добавить GOOS в directProbePolicy.
func TestPostConnect_TunMode_DesktopObservesButDoesNotBlock(t *testing.T) {
	sc := &probeScript{directErr: errors.New("i/o timeout")}
	e, _ := newProbeEngine(t, models.ModeVPN, "windows", sc)
	var logged bool
	e.OnLog = func(msg string) {
		if strings.Contains(msg, "Прямая (TUN) проба не прошла") {
			logged = true
		}
	}
	defer waitTracked(t, e)

	e.runPostConnectHealthCheck()

	if sc.directHits == 0 {
		t.Fatal("прямая проба обязана выполняться на всех платформах — иначе нечего наблюдать")
	}
	if !logged {
		t.Error("провал прямой пробы не попал в лог — наблюдение без записи бесполезно")
	}
	assertVerifyState(t, e, models.VerifyVerified, "TUN-режим на платформе без живой проверки")
}

// ─── Находка 4.1: гейт по Connected для VerifyVerified ────────────────────────────────────

// Проба живёт до 8 секунд и запускается после двух сон-пауз. За это время сессию могли снять
// (Disconnect/Stop/откат) — и поздно вернувшийся успех воскрешал «канал подтверждён» поверх
// уже снесённого подключения: Connected=false, Verified=true. Такого состояния в контракте
// models.ConnectionState нет вообще. Это был ЕДИНСТВЕННЫЙ переход в VerifyVerified без гейта.
func TestPostConnectVerified_RequiresConnected(t *testing.T) {
	sc := &probeScript{}
	e, _ := newProbeEngine(t, models.ModeProxy, "windows", sc)
	// сессия снимается ровно в момент пробы — как это и происходит живьём
	e.healthProbeSOCKS = func(ctx context.Context, target string) (checker.HealthInfo, error) {
		e.setDisconnected()
		return checker.HealthInfo{LatencyMs: 42, Country: "NL"}, nil
	}
	defer waitTracked(t, e)

	e.runPostConnectHealthCheck()

	st := e.GetState()
	if st.Verified {
		t.Errorf("подтверждение выставлено на снесённой сессии: Connected=%v, Verified=%v",
			st.Connected, st.Verified)
	}
	if st.VerifyState != models.VerifyIdle {
		t.Errorf("VerifyState = %q, ожидалось %q: туннеля нет — предмета проверки тоже",
			st.VerifyState, models.VerifyIdle)
	}
}

// ─── Находка 4.2: «проверка идёт», которая не разрешается ни во что ───────────────────────

// VerifyChecking выставляет ровно одно место (applySingBoxConfig), разрешает ровно одно
// (runPostConnectHealthCheck). Если та вышла по отменённому контексту — а она выходит по любому
// из трёх sleepCtx, — состояние оставалось «проверка идёт» НАВСЕГДА: поднять его обратно не
// умеет никто (markChannelAliveAgain сознательно поднимает только из VerifyFailed). На Android
// клиент через 180 секунд гасит неподтверждённое подключение, то есть снёс бы рабочий туннель.
func TestPostConnectHealthCheck_ResolvesDanglingChecking(t *testing.T) {
	sc := &probeScript{}
	e, _ := newProbeEngine(t, models.ModeProxy, "windows", sc)
	e.cancel() // движок останавливается — первый же sleepCtx вернёт false

	e.runPostConnectHealthCheck()

	if sc.socksHits != 0 {
		t.Fatalf("предусловие теста не выполнено: проба всё-таки выполнялась (%d раз)", sc.socksHits)
	}
	assertVerifyState(t, e, models.VerifyFailed,
		"проверка не состоялась при поднятом туннеле")
}

// Второй вход в ту же дыру: applySingBoxConfig выставляет Connected=true + VerifyChecking и
// запускает проверку через goTracked, а тот НЕ запускает функцию при отменённом контексте.
func TestGoTracked_ReportsDeclineSoCheckingIsNotLost(t *testing.T) {
	sc := &probeScript{}
	e, _ := newProbeEngine(t, models.ModeProxy, "windows", sc)
	e.cancel()

	if started := e.goTracked(func() {}); started {
		t.Fatal("goTracked отрапортовал о старте при отменённом контексте")
	}
	e.resolveDanglingVerifyChecking("тест: движок останавливается")
	assertVerifyState(t, e, models.VerifyFailed, "goTracked отказался запускать проверку")
}

// Обратная сторона того же гейта: на снятой сессии «проверка провалилась» была бы ложью в
// другую сторону — провалилась не проверка, а её предмет.
func TestResolveDanglingChecking_NoopWhenDisconnected(t *testing.T) {
	sc := &probeScript{}
	e, _ := newProbeEngine(t, models.ModeProxy, "windows", sc)
	e.setDisconnected()

	e.resolveDanglingVerifyChecking("тест")

	assertVerifyState(t, e, models.VerifyIdle, "туннеля нет")
}

// И третья сторона: подтверждённое состояние трогать нельзя — резолвер работает ТОЛЬКО из
// VerifyChecking.
func TestResolveDanglingChecking_NoopWhenVerified(t *testing.T) {
	sc := &probeScript{}
	e, _ := newProbeEngine(t, models.ModeProxy, "windows", sc)
	e.stateMu.Lock()
	e.setVerifyStateLocked(models.VerifyVerified)
	e.stateMu.Unlock()

	e.resolveDanglingVerifyChecking("тест")

	assertVerifyState(t, e, models.VerifyVerified, "канал был подтверждён")
}

// ─── Находка 4.3: reArmPending не снимался при отменённом контексте ───────────────────────

// Ре-арминг — единственный механизм, возвращающий пользователя в сеть после исчерпания всех
// кандидатов. Флаг взводился ДО goTracked, а тот при отменённом контексте функцию не запускал —
// и снимать флаг было некому. Последствие переживает саму остановку: Stop() пересоздаёт
// контекст (resetCtx), движок снова работоспособен, но каждый следующий scheduleReArm молча
// выходит на CompareAndSwap. Ре-арминг выключался НАВСЕГДА до перезапуска процесса.
func TestScheduleReArm_ClearsPendingWhenContextCancelled(t *testing.T) {
	sc := &probeScript{}
	e, _ := newProbeEngine(t, models.ModeProxy, "windows", sc)
	e.cancel()

	e.scheduleReArm(errors.New("резервы исчерпаны"))

	if e.reArmPending.Load() {
		t.Fatal("reArmPending остался взведённым — следующий ре-арминг не будет запланирован НИКОГДА")
	}
	// И убеждаемся, что следующий вызов действительно проходит гейт (движок снова живой).
	e.resetCtx()
	e.scheduleReArm(errors.New("вторая попытка"))
	if !e.reArmPending.Load() {
		t.Error("после восстановления контекста ре-арминг всё равно не запланирован")
	}
	e.cancel()
	waitTracked(t, e)
}

// ─── Инвариант контракта на новом пути ────────────────────────────────────────────────────

// Verified ≡ (VerifyState == verified) на КАЖДОМ из новых переходов. bool читают старые сборки
// UI, строку — новые; расхождение пользователь видит как «два места в одном приложении говорят
// разное про одно подключение».
func TestLot09_VerifiedFlagNeverDivergesOnNewPaths(t *testing.T) {
	steps := []struct {
		name      string
		mode      string
		goos      string
		directErr error
	}{
		{"TUN, обе зелёные", models.ModeVPN, "android", nil},
		{"TUN, прямая красная", models.ModeVPN, "android", errors.New("timeout")},
		{"TUN, наблюдение", models.ModeVPN, "windows", errors.New("timeout")},
		{"proxy", models.ModeProxy, "android", errors.New("не важна")},
	}
	for _, s := range steps {
		sc := &probeScript{directErr: s.directErr}
		e, _ := newProbeEngine(t, s.mode, s.goos, sc)
		e.runPostConnectHealthCheck()
		st := e.GetState()
		if st.Verified != (st.VerifyState == models.VerifyVerified) {
			t.Errorf("%s: поля разошлись — Verified=%v, VerifyState=%q",
				s.name, st.Verified, st.VerifyState)
		}
		e.cancel()
		waitTracked(t, e)
	}
}
