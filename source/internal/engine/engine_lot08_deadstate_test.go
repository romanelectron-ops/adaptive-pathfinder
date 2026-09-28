// engine_lot08_deadstate_test.go — дозакрытие точек, где движок УЖЕ знает, что сессия
// нерабочая, а состояние подключения продолжает утверждать обратное (LOT-08, волна 2,
// 2026-09-06). Прямое продолжение LOT-04 (engine_lot04_verifystate_test.go): там закрыты три
// ТОЧКИ ОБНАРУЖЕНИЯ смерти канала, здесь — три оставшиеся точки ОТКАЗА:
//
//  1. rollbackConnectionAttempt — откат неудавшейся попытки подключения;
//  2. scheduleReArm — резервы исчерпаны, рабочего узла нет;
//  3. провал enableSystemProxy при включённом Kill Switch — самая заметная: VerifyVerified
//     к этому моменту уже выставлен, а сессия фактически нерабочая.
//
// Общий контракт (models.ConnectionState): Verified ≡ (VerifyState == VerifyVerified), и
// значения различаются по тому, ПОДНЯТ ЛИ ТУННЕЛЬ: VerifyIdle = «не подключено»,
// VerifyFailed = «туннель поднят, но канал признан неработающим». Именно это различие решает,
// какое состояние правильно в каждой из трёх точек, — см. комментарии у тестов.
package engine

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// newLot08LiveEngine — движок в состоянии «туннель поднят, канал подтверждён»: ровно то
// состояние, из которого пользователь видит зелёное «Подключено». Самодостаточен (не опирается
// на хелперы соседних лотов, кроме давно существующих withTempDataDir/setNodes), чтобы правка
// чужого тестового файла не могла беззвучно изменить смысл этих проверок.
//
// Узел — петля на порт 1: отказ мгновенный, в сеть тест не выходит. ListenPort 59991 не слушает
// никто, поэтому любой health-check через SOCKS обязан провалиться.
func newLot08LiveEngine(t *testing.T, id string) (*Engine, *models.Node) {
	t.Helper()
	withTempDataDir(t)
	cfg := models.DefaultConfig()
	cfg.NodeAutoSwitchEnabled = false // состояние обязано стать честным САМО, без переключения
	cfg.SetSystemProxy = false
	cfg.EnableKillSwitch = false
	cfg.ListenPort = 59991
	e := New(cfg)
	node := &models.Node{ID: id, Name: id, Protocol: models.ProtoVLESS, Address: "127.0.0.1", Port: 1}
	setNodes(e, node)
	e.stateMu.Lock()
	e.state.Connected = true
	e.state.Verified = true
	e.state.VerifyState = models.VerifyVerified
	e.state.ActiveNode = node
	e.state.Since = time.Now().Add(-10 * time.Minute) // гейт MinUptimeSec заведомо ни при чём
	e.stateMu.Unlock()
	return e, node
}

// assertLot08Invariant — единственное, что обязано выполняться после ЛЮБОГО перехода: bool
// читают старые сборки UI, строку — новые, и расхождение пользователь видит как «два места в
// одном приложении говорят разное про одно подключение».
func assertLot08Invariant(t *testing.T, st *models.ConnectionState, after string) {
	t.Helper()
	if st.Verified != (st.VerifyState == models.VerifyVerified) {
		t.Fatalf("после %s поля разошлись: Verified=%v, VerifyState=%q",
			after, st.Verified, st.VerifyState)
	}
}

// assertLot08Dead — «туннель поднят, канал не работает».
func assertLot08Dead(t *testing.T, e *Engine, where string) {
	t.Helper()
	st := e.GetState()
	assertLot08Invariant(t, st, where)
	if st.VerifyState != models.VerifyFailed {
		t.Errorf("%s: VerifyState = %q, ожидалось %q — движок уже знает, что сессия нерабочая, "+
			"а состояние продолжает утверждать обратное", where, st.VerifyState, models.VerifyFailed)
	}
	if st.Verified {
		t.Errorf("%s: Verified остался true — UI покажет зелёное «Подключено» на нерабочей сессии", where)
	}
}

// ─── Точка 1: rollbackConnectionAttempt ──────────────────────────────────────────────────
//
// Почему Failed, а НЕ Idle, и почему в НАЧАЛЕ отката:
//
// Откат вызывается из applySingBoxConfig при wasRunning=true — то есть поверх ЖИВОГО туннеля
// (Reload/ReloadWithFreshTun не удался). В этот момент туннель ещё поднят, а движок уже знает,
// что попытка провалилась: по контракту models.ConnectionState это ровно VerifyFailed
// («туннель поднят, но канал признан неработающим»), не VerifyIdle («не подключено»).
//
// Гасить обязательно в НАЧАЛЕ, а не полагаться на setDisconnected() в конце: между этими двумя
// точками идут ksDisable()/ksReset()/disableSystemProxy() — операции с фаерволом, которые по
// живому инциденту 2026-08-19 умеют висеть на BFE до срабатывания собственного таймаута. Весь
// этот интервал состояние утверждало «канал подтверждён» на заведомо провалившейся попытке.
//
// Отличие от «отключения пользователем»: там предмета проверки нет вовсе, и правильное
// состояние — VerifyIdle. Поэтому ИТОГ отката тоже Idle (setDisconnected в конце снимает
// туннель), а Failed живёт ровно столько, сколько туннель ещё поднят. Оба перехода проверяются
// ниже по последовательности уведомлений UI, а не по конечному снимку: конечный снимок у
// исправленного и неисправленного кода одинаков, разница видна только в том, ЧТО видел
// пользователь во время отката.
func TestRollbackConnectionAttempt_ClearsVerifiedStateAtEntry(t *testing.T) {
	e, _ := newLot08LiveEngine(t, "rollback-live")

	var mu sync.Mutex
	var seen []models.ConnectionState
	e.OnStateChange = func(st *models.ConnectionState) {
		mu.Lock()
		seen = append(seen, *st)
		mu.Unlock()
	}

	cause := errors.New("sing-box: reload failed")
	// wasRunning=true — откат поверх живого туннеля: proc.Stop() не вызывается (см. функцию).
	if err := e.rollbackConnectionAttempt("apply_runtime", cause, true); err != cause {
		t.Fatalf("откат обязан вернуть исходную причину, получено: %v", err)
	}

	mu.Lock()
	got := append([]models.ConnectionState(nil), seen...)
	mu.Unlock()

	if len(got) < 2 {
		t.Fatalf("откат уведомил UI %d раз(а), ожидалось 2 (сначала «канал не работает» на ещё "+
			"поднятом туннеле, затем «отключено»): состояние в начале отката не гасится, и всё "+
			"время снятия Kill Switch/системного прокси UI показывал «Подключено, канал подтверждён»",
			len(got))
	}

	first := got[0]
	assertLot08Invariant(t, &first, "первое уведомление отката")
	if !first.Connected {
		t.Errorf("первое уведомление отката: Connected=false — гашение опоздало и пришло уже "+
			"из setDisconnected(), а не из точки, где движок узнал о провале (VerifyState=%q)",
			first.VerifyState)
	}
	if first.VerifyState != models.VerifyFailed {
		t.Errorf("первое уведомление отката: VerifyState = %q, ожидалось %q",
			first.VerifyState, models.VerifyFailed)
	}
	if first.Verified {
		t.Error("первое уведомление отката: Verified остался true на провалившейся попытке")
	}

	last := got[len(got)-1]
	assertLot08Invariant(t, &last, "последнее уведомление отката")
	if last.Connected {
		t.Error("после отката Connected обязан быть false — туннель снят")
	}
	// Именно Idle, а не Failed: туннеля больше нет, «канал не работает» на отсутствующем канале —
	// та же ложь, только в другую сторону (это и есть разница с «отключением пользователем»).
	if last.VerifyState != models.VerifyIdle {
		t.Errorf("итог отката: VerifyState = %q, ожидалось %q — туннель снят, предмета проверки нет",
			last.VerifyState, models.VerifyIdle)
	}
}

// Холодная попытка (wasRunning=false, туннель ещё не поднимался): гасить нечего — состояние и до
// отката, и после него обязано остаться Idle. Проверка от обратного: фикс точки 1 не имеет права
// выставить «канал не работает» там, где канала никогда не было.
func TestRollbackConnectionAttempt_ColdAttemptStaysIdle(t *testing.T) {
	withTempDataDir(t)
	cfg := models.DefaultConfig()
	cfg.EnableKillSwitch = false
	cfg.SetSystemProxy = false
	e := New(cfg)

	var mu sync.Mutex
	var seen []models.ConnectionState
	e.OnStateChange = func(st *models.ConnectionState) {
		mu.Lock()
		seen = append(seen, *st)
		mu.Unlock()
	}

	cause := errors.New("локальный порт занят")
	// errors.Is: стадия listen_port помечает причину локальным классом (ТЗ HOTSWITCH §8 A1).
	if err := e.rollbackConnectionAttempt("listen_port", cause, false); !errors.Is(err, cause) {
		t.Fatalf("откат обязан вернуть исходную причину, получено: %v", err)
	}

	mu.Lock()
	got := append([]models.ConnectionState(nil), seen...)
	mu.Unlock()
	for i := range got {
		assertLot08Invariant(t, &got[i], "уведомление холодного отката")
		if got[i].VerifyState == models.VerifyFailed {
			t.Errorf("уведомление #%d холодного отката: VerifyState=%q — туннель не поднимался, "+
				"«канал не работает» здесь ложь", i, got[i].VerifyState)
		}
	}
	st := e.GetState()
	assertLot08Invariant(t, st, "холодный откат")
	if st.VerifyState != models.VerifyIdle || st.Verified {
		t.Errorf("холодный откат: VerifyState=%q Verified=%v, ожидалось %q/false",
			st.VerifyState, st.Verified, models.VerifyIdle)
	}
}

// ─── Точка 2: резервы исчерпаны (tryFallback → scheduleReArm) ────────────────────────────
//
// Почему Failed, а НЕ Idle: scheduleReArm — единственная воронка «рабочий узел не найден»
// (её зовут finishScanFailure после трёх исходов ScanAndConnect и emergencySwitch после
// исчерпания tryFallback). Движок в этот момент САМ пишет в лог «Ре-арминг: рабочий узел не
// найден» — и, если туннель при этом всё ещё числится поднятым, одновременно показывает
// «Подключено, канал подтверждён». Два утверждения противоречат друг другу; честное из них —
// «канал не подтверждён», а туннель формально ещё поднят, значит Failed, не Idle.
//
// Idle здесь был бы неверен вдвойне: он означает «не подключено», а Connected никто не снимал.
// Ровно поэтому гашение идёт через markChannelDead — его собственный гейт по Connected сам
// оставляет Idle там, где туннеля нет (проверено отдельным тестом ниже).
func TestScheduleReArm_ClearsVerifiedState(t *testing.T) {
	e, _ := newLot08LiveEngine(t, "rearm-live")
	// Отменяем контекст ДО вызова: goTracked тогда не стартует вовсе, и тест проверяет ровно то,
	// что должен, — честность состояния БЕЗ участия повторного поиска.
	e.cancel()

	e.scheduleReArm(errors.New("Tor недоступен: исполняемый файл tor не найден"))

	assertLot08Dead(t, e, "scheduleReArm (резервы исчерпаны)")
}

// Та же воронка, но через настоящий путь ScanAndConnect: finishScanFailure(err != nil).
func TestFinishScanFailure_ClearsVerifiedState(t *testing.T) {
	e, _ := newLot08LiveEngine(t, "scanfail-live")
	e.cancel()

	cause := errors.New("резервы исчерпаны")
	if err := e.finishScanFailure(cause); err != cause {
		t.Fatalf("finishScanFailure обязан вернуть исходную причину, получено: %v", err)
	}

	assertLot08Dead(t, e, "finishScanFailure (резервы исчерпаны)")
}

// Проверка от обратного №1: успешный поиск (err == nil) в ту же воронку не заходит и гасить
// ничего не имеет права — иначе удачное подключение мигало бы «канал не подтверждён».
func TestFinishScanFailure_SuccessKeepsVerified(t *testing.T) {
	e, _ := newLot08LiveEngine(t, "scanok-live")
	e.cancel()

	if err := e.finishScanFailure(nil); err != nil {
		t.Fatalf("finishScanFailure(nil) обязан вернуть nil, получено: %v", err)
	}

	st := e.GetState()
	assertLot08Invariant(t, st, "finishScanFailure(nil)")
	if st.VerifyState != models.VerifyVerified || !st.Verified {
		t.Errorf("успешный поиск погасил подтверждение: VerifyState=%q Verified=%v",
			st.VerifyState, st.Verified)
	}
}

// ─── Точка 3: системный прокси не включился при включённом Kill Switch ───────────────────
//
// Самая заметная из трёх: к этому моменту runPostConnectHealthCheck УЖЕ выставил VerifyVerified
// (канал sing-box подтверждён настоящим HTTP через SOCKS), а сессия фактически нерабочая —
// Kill Switch без TUN-режима разрешил трафик ТОЛЬКО к текущему узлу в расчёте на системный
// прокси, которого нет. Пользователь получает зелёное «Подключено, канал подтверждён» и
// задушенный трафик всей системы.
//
// Почему Failed, а НЕ Idle: туннель поднят и работает (health-check только что прошёл),
// Connected=true, ActiveNode на месте — сессию никто не снимал, мы уходим в emergencySwitch.
// Это буквальное определение VerifyFailed по контракту models.ConnectionState: «туннель поднят,
// но канал признан неработающим». Idle («не подключено») был бы прямой ложью.
//
// Гасить обязательно ЗДЕСЬ, а не рассчитывать на emergencySwitch: у него семь ранних return
// (автопереключение отключено пользователем, sticky-пауза, гейт MinUptimeSec, «узел уже
// сменился» и т.д.), и на каждом из них сессия оставалась бы «подтверждённой». В тесте
// автопереключение выключено намеренно — ровно этот случай.
func TestSysProxyFailureUnderKillSwitch_ClearsVerifiedState(t *testing.T) {
	e, _ := newLot08LiveEngine(t, "sysproxy-live")
	e.cancel() // goTracked(emergencySwitch) не стартует — проверяем честность состояния без него

	e.abortSessionOnSysProxyFailure(errors.New("targetHive: нет активной консольной сессии"))

	assertLot08Dead(t, e, "провал enableSystemProxy при включённом Kill Switch")
}

// Условие срабатывания ветки не изменено рефакторингом: таблица решений совпадает с прежним
// инлайновым `err != nil && e.cfg.EnableKillSwitch && !e.ksNeedsTunMode()`.
func TestSysProxyFailureAborts_DecisionTable(t *testing.T) {
	boom := errors.New("реестр недоступен")
	cases := []struct {
		name string
		err  error
		ks   bool
		mode string
		want bool
	}{
		{"прокси включился — прерывать нечего", nil, true, models.ModeProxy, false},
		{"провал, но Kill Switch выключен — трафик не задушен", boom, false, models.ModeProxy, false},
		{"провал при Kill Switch в proxy-режиме — прерываем", boom, true, models.ModeProxy, true},
		{"провал в VPN-режиме — трафик идёт через TUN, прокси не нужен", boom, true, models.ModeVPN, false},
		{"провал в hybrid-режиме — TUN есть, прокси не нужен", boom, true, models.ModeHybrid, false},
		{"успех при выключенном Kill Switch", nil, false, models.ModeProxy, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := models.DefaultConfig()
			cfg.EnableKillSwitch = tc.ks
			cfg.ConnectionMode = tc.mode
			e := New(cfg)
			if got := e.sysProxyFailureAborts(tc.err); got != tc.want {
				t.Errorf("sysProxyFailureAborts(err=%v, ks=%v, mode=%s) = %v, ожидалось %v",
					tc.err, tc.ks, tc.mode, got, tc.want)
			}
		})
	}
}

// Проверка от обратного: гашение точки 3 не имеет права сработать на снятой сессии — там
// честное Idle, а «канал не работает» без канала было бы ложью в другую сторону.
func TestSysProxyFailure_DisconnectedStaysIdle(t *testing.T) {
	withTempDataDir(t)
	cfg := models.DefaultConfig()
	cfg.NodeAutoSwitchEnabled = false
	e := New(cfg)
	e.cancel()

	e.abortSessionOnSysProxyFailure(errors.New("реестр недоступен"))

	st := e.GetState()
	assertLot08Invariant(t, st, "провал sysproxy без туннеля")
	if st.VerifyState != models.VerifyIdle || st.Verified {
		t.Errorf("провал sysproxy без туннеля: VerifyState=%q Verified=%v, ожидалось %q/false",
			st.VerifyState, st.Verified, models.VerifyIdle)
	}
}

// Проверка от обратного №2: резервы исчерпаны, когда туннеля и не было. «Канал не работает» на
// отсутствующем канале — ложь в другую сторону, правильное состояние Idle.
func TestScheduleReArm_DisconnectedStaysIdle(t *testing.T) {
	withTempDataDir(t)
	cfg := models.DefaultConfig()
	cfg.NodeAutoSwitchEnabled = false
	e := New(cfg)
	e.cancel()

	e.scheduleReArm(errors.New("узлы не найдены"))

	st := e.GetState()
	assertLot08Invariant(t, st, "scheduleReArm без туннеля")
	if st.VerifyState != models.VerifyIdle || st.Verified {
		t.Errorf("scheduleReArm без туннеля: VerifyState=%q Verified=%v, ожидалось %q/false",
			st.VerifyState, st.Verified, models.VerifyIdle)
	}
}
