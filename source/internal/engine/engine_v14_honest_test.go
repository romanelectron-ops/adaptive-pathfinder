// engine_v14_honest_test.go — лот L1b-ENG2 ТЗ v1.4 (волна W1b): C-15, C-13 (движок), C-3,
// C-5, C-18/V13-4 (ядро), C-20, C-21, C-22.
//
// Каждый тест написан ДО правки и на прежнем коде обязан падать (blackbox-tdd): без падения
// «до» нельзя утверждать, что тест проверяет заявленный дефект, а не фиксирует уже
// существующее поведение.
package engine

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── общие помощники файла ───────────────────────────────────────────────────

// v14HonestEngine — движок на временном каталоге данных, без автоподключения.
func v14HonestEngine(t *testing.T) *Engine {
	t.Helper()
	withTempDataDir(t)
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	return New(cfg)
}

// v14Node — узел, годный к выбору: проверен TCP, ненулевой Score.
func v14Node(id string, score float64) *models.Node {
	return &models.Node{
		ID:          id,
		Name:        id,
		Address:     "185.199.108.153",
		Port:        443,
		Protocol:    models.ProtoVLESS,
		Score:       score,
		Status:      models.StatusOK,
		LastChecked: time.Now(),
	}
}

// v14SetPool кладёт пул в движок и делает первый узел активным.
func v14SetPool(e *Engine, nodes []*models.Node, active *models.Node) {
	e.mu.Lock()
	e.nodes = nodes
	e.mu.Unlock()
	e.stateMu.Lock()
	e.state.ActiveNode = active
	e.state.Connected = active != nil
	e.stateMu.Unlock()
}

// ─── C-15 · «Сменить сервер» не меняет сервер (FAIL D3) ──────────────────────

// TestV14_C15_ThreeForceSwitches_GiveThreeDifferentCandidates — главный тест пункта.
//
// Живой прогон K8-LIVE D3: 7 нажатий подряд, узел не сменился ни разу. ForceSwitchNow
// исключала ТОЛЬКО текущий узел, поэтому кандидат, у которого post-connect только что
// провалился, оставался в выборке, а аварийное переключение возвращало пользователя на
// прежний узел — и следующий клик повторял тот же цикл.
func TestV14_C15_ThreeForceSwitches_GiveThreeDifferentCandidates(t *testing.T) {
	e := v14HonestEngine(t)
	active := v14Node("A", 0.9)
	pool := []*models.Node{active, v14Node("B", 0.8), v14Node("C", 0.7), v14Node("D", 0.6)}
	v14SetPool(e, pool, active)

	seen := map[string]bool{}
	for i := 1; i <= 3; i++ {
		target, exhausted := e.forceSwitchPlan()
		if target == nil {
			t.Fatalf("попытка %d: кандидат не выбран (exhausted=%v) — пул содержит 3 запасных узла", i, exhausted)
		}
		if seen[target.ID] {
			t.Fatalf("попытка %d вернула тот же узел %q: серия ручных переключений топчется на месте", i, target.ID)
		}
		seen[target.ID] = true
	}
	if len(seen) != 3 {
		t.Fatalf("ожидались три РАЗНЫХ кандидата, получено %v", seen)
	}
}

// TestV14_C15_ExhaustedSeries_KeepsActiveNodeAndTellsUser — честный ответ вместо
// молчаливого возврата на тот же сервер (пункт 3 решения C-15).
func TestV14_C15_ExhaustedSeries_KeepsActiveNodeAndTellsUser(t *testing.T) {
	e := v14HonestEngine(t)
	active := v14Node("A", 0.9)
	pool := []*models.Node{active, v14Node("B", 0.8), v14Node("C", 0.7), v14Node("D", 0.6)}
	v14SetPool(e, pool, active)

	for i := 0; i < forceSwitchMaxAttempts; i++ {
		if target, _ := e.forceSwitchPlan(); target == nil {
			t.Fatalf("попытка %d: кандидат не выбран раньше исчерпания серии", i+1)
		}
	}
	target, exhausted := e.forceSwitchPlan()
	if target != nil {
		t.Fatalf("после %d неподтверждённых попыток серия обязана остановиться, а выбран %q",
			forceSwitchMaxAttempts, target.ID)
	}
	if !exhausted {
		t.Fatal("серия исчерпана, но признак exhausted не выставлен — пользователю нечего показать")
	}

	e.ForceSwitchNow()
	st := e.GetState()
	if st.ActiveNode == nil || st.ActiveNode.ID != "A" {
		t.Fatalf("активный узел не должен меняться при исчерпанной серии: %+v", st.ActiveNode)
	}
	if st.SwitchNotice == "" {
		t.Fatal("движок молчит: пользователь видит «сменить сервер» без результата и без объяснения")
	}
}

// TestV14_C15_ExclusionExpiresByTTL — исключение не вечное: через forceSwitchExcludeTTL
// узел снова доступен (риск «слишком агрессивное исключение сузит пул» из ТЗ).
func TestV14_C15_ExclusionExpiresByTTL(t *testing.T) {
	e := v14HonestEngine(t)
	old := forceSwitchExcludeTTL
	forceSwitchExcludeTTL = 40 * time.Millisecond
	defer func() { forceSwitchExcludeTTL = old }()

	active := v14Node("A", 0.9)
	v14SetPool(e, []*models.Node{active, v14Node("B", 0.8)}, active)

	first, _ := e.forceSwitchPlan()
	if first == nil || first.ID != "B" {
		t.Fatalf("первая попытка обязана взять единственный запасной узел B, получено %+v", first)
	}
	if again, exhausted := e.forceSwitchPlan(); again != nil || !exhausted {
		t.Fatalf("второй клик подряд обязан признать серию исчерпанной, получено %+v (exhausted=%v)", again, exhausted)
	}
	time.Sleep(60 * time.Millisecond)
	back, _ := e.forceSwitchPlan()
	if back == nil || back.ID != "B" {
		t.Fatalf("после истечения TTL узел обязан вернуться в выборку, получено %+v", back)
	}
}

// TestV14_C15_VerifiedNodeLeavesExclusion — подтверждённый трафиком узел выходит из
// «отвергнутых» и обнуляет серию: следующий клик начинает заново, а не с исчерпания.
func TestV14_C15_VerifiedNodeLeavesExclusion(t *testing.T) {
	e := v14HonestEngine(t)
	active := v14Node("A", 0.9)
	b := v14Node("B", 0.8)
	v14SetPool(e, []*models.Node{active, b}, active)

	if first, _ := e.forceSwitchPlan(); first == nil || first.ID != "B" {
		t.Fatalf("первая попытка: ожидался B, получено %+v", first)
	}
	// Узел подтвердился реальным трафиком — единственный писатель Verified*-полей.
	e.recordNodeVerified(b, 120, "NL", "193.29.139.147")

	back, exhausted := e.forceSwitchPlan()
	if back == nil || back.ID != "B" {
		t.Fatalf("подтверждённый узел обязан вернуться в выборку, получено %+v (exhausted=%v)", back, exhausted)
	}
}

// TestV14_C15_RelayPenalty_AfterTwoPostConnectFailures — пункт 2 решения C-15: узел роли
// «Выход» (relay-ссылка, apf_relay=1), дважды подряд проваливший post-connect, получает
// recentFailure того же класса, что обычный узел, и перестаёт стоять в топе выборки.
func TestV14_C15_RelayPenalty_AfterTwoPostConnectFailures(t *testing.T) {
	e := v14HonestEngine(t)
	relay := v14Node("RELAY-104.16.174.109-1148", 0.95)
	relay.ExtraParams = map[string]string{"apf_relay": "1"}
	v14SetPool(e, []*models.Node{relay, v14Node("GB", 0.7)}, nil)

	e.recordNodeFailure(relay, failReasonHealthCheck)
	if e.isRecentlyFailed(relay.ID) {
		t.Fatal("один провал не должен выводить relay из выборки — это штраф за ДВА подряд")
	}
	e.recordNodeFailure(relay, failReasonHealthCheck)
	if !e.isRecentlyFailed(relay.ID) {
		t.Fatal("relay на выключенный «Выход» дважды провалил post-connect и всё ещё стоит в выборке: " +
			"ровно этот узел живой прогон D3 выбирал семь раз подряд")
	}
}

// ─── C-13 · тумблеры защиты не персистятся (FAIL B2) + C-3 (Sticky) ──────────

// v14ReloadedConfig — конфиг, прочитанный с диска НОВЫМ движком: ровно то, что увидит
// пользователь после `am force-stop` + запуска (LoadInto поверх дефолтов, как androidbridge).
func v14ReloadedConfig(t *testing.T) *models.AppConfig {
	t.Helper()
	cfg := models.DefaultConfig()
	found, err := config.LoadInto(cfg)
	if err != nil {
		t.Fatalf("config.json не читается: %v", err)
	}
	if !found {
		t.Fatal("config.json не создан: выбор пользователя вообще не сохранён")
	}
	return cfg
}

// TestV14_C13_DisableIPv6Block_SurvivesEngineRecreation — главный тест FAIL B2.
//
// До правки: EnableIPv6Block трогала ТОЛЬКО e.ipv6Guard. В config.json оставалось
// "block_ipv6_leak": true, и после перезапуска приложения защита включалась обратно из
// конфига, которого выбор пользователя не касался.
func TestV14_C13_DisableIPv6Block_SurvivesEngineRecreation(t *testing.T) {
	e := v14HonestEngine(t)
	if !e.GetConfig().BlockIPv6Leak {
		t.Fatal("предусловие: в дефолтном конфиге IPv6 Block включён")
	}
	if err := e.EnableIPv6Block(false); err != nil {
		t.Fatalf("EnableIPv6Block(false): %v", err)
	}
	if e.GetConfig().BlockIPv6Leak {
		t.Fatal("выключение IPv6 Block не дошло до конфига движка: ядро продолжает считать защиту включённой")
	}
	if got := v14ReloadedConfig(t).BlockIPv6Leak; got {
		t.Fatal("после пересоздания движка block_ipv6_leak снова true: выключение не пережило перезапуск (FAIL B2)")
	}
}

// TestV14_C13_DisableWebRTCBlock_SurvivesEngineRecreation — тот же дефект у второго тумблера.
func TestV14_C13_DisableWebRTCBlock_SurvivesEngineRecreation(t *testing.T) {
	e := v14HonestEngine(t)
	if err := e.EnableWebRTCBlock(false); err != nil {
		t.Fatalf("EnableWebRTCBlock(false): %v", err)
	}
	if e.GetConfig().BlockWebRTC {
		t.Fatal("выключение WebRTC Block не дошло до конфига движка")
	}
	if v14ReloadedConfig(t).BlockWebRTC {
		t.Fatal("после пересоздания движка block_webrtc снова true")
	}
}

// TestV14_C13_LeakMonitor_DoesNotReEnableUserDisabledGuard — третий писатель (engine.go
// монитор утечек) сам включал обратно то, что пользователь выключил, не сказав ни слова.
// Истина — конфиг; монитор вправе только предупредить.
func TestV14_C13_LeakMonitor_DoesNotReEnableUserDisabledGuard(t *testing.T) {
	e := v14HonestEngine(t)
	if err := e.EnableIPv6Block(false); err != nil {
		t.Fatalf("EnableIPv6Block(false): %v", err)
	}
	var alerts []string
	e.OnLeakDetected = func(kind, msg string) { alerts = append(alerts, kind+": "+msg) }

	e.handleIPv6Leak("2a00:1450:4010:c07::71")

	if e.GetLeakGuardStatus()["ipv6_guard_enabled"].(bool) {
		t.Fatal("монитор утечек включил защиту обратно вопреки выбору пользователя")
	}
	if e.GetConfig().BlockIPv6Leak {
		t.Fatal("монитор утечек переписал конфиг пользователя")
	}
	if len(alerts) == 0 {
		t.Fatal("монитор промолчал: пользователь не узнал ни об утечке, ни о том, что защита выключена им самим")
	}
}

// TestV14_C3_SetStickyPolicy_SurvivesEngineRecreation — C-3: политика Sticky Session
// (частный случай C-13) жила только в памяти StickySessionManager.
func TestV14_C3_SetStickyPolicy_SurvivesEngineRecreation(t *testing.T) {
	e := v14HonestEngine(t)
	e.SetStickyPolicy("free")
	if got := e.GetConfig().StickySessionPolicy; got != "free" {
		t.Fatalf("политика не дошла до конфига движка: %q", got)
	}
	if got := v14ReloadedConfig(t).StickySessionPolicy; got != "free" {
		t.Fatalf("после пересоздания движка политика снова %q — выбор пользователя потерян (K8-LIVE B3)", got)
	}
}

// TestV14_C13_CyclicSearch_AlreadyPersists — сторож существующего поведения: этот сеттер
// уже писал конфиг, и правка соседних тумблеров не должна его сломать.
func TestV14_C13_CyclicSearch_AlreadyPersists(t *testing.T) {
	e := v14HonestEngine(t)
	e.SetCyclicNodeSearch(true)
	if !v14ReloadedConfig(t).CyclicNodeSearch {
		t.Fatal("cyclic_node_search не сохранён")
	}
}

// ─── C-14 · строки автомата в пользовательском логе (FAIL C2) ────────────────

// TestV14_C14_FSM_DoesNotWriteToUserLog — движок больше не проводит состояния автомата в
// пользовательский лог: автомат не выбирает outbound, его уровни пользователю не адресованы,
// а имена «протоколов» в логе телефона читались как обещание несуществующего резерва.
func TestV14_C14_FSM_DoesNotWriteToUserLog(t *testing.T) {
	e := v14HonestEngine(t)
	var lines []string
	e.OnLog = func(s string) { lines = append(lines, s) }

	for i := 0; i < 40; i++ {
		e.fsm.HandleFailure(errors.New("тестовый сбой"))
	}
	e.fsm.HandleSuccess(10 * time.Millisecond)

	for _, l := range lines {
		low := strings.ToLower(l)
		if strings.Contains(low, "fsm") || strings.Contains(low, "snowflake") {
			t.Fatalf("строка автомата дошла до пользовательского лога: %q", l)
		}
	}
}

// ─── C-5 · мёртвый fsm_state всё ещё отдаётся движком ────────────────────────

func TestV14_C5_Diagnostics_HasNoFSMState(t *testing.T) {
	e := v14HonestEngine(t)
	if _, ok := e.GetDiagnostics()["fsm_state"]; ok {
		t.Fatal("GetDiagnostics всё ещё отдаёт fsm_state: поле никто не читает, а автомат " +
			"не выбирает outbound — показывать его пользователю нечестно")
	}
}

// TestV14_C5_Diagnostics_KeepsHonestFields — сторож: убираем ровно одно поле, остальные
// (их читают три UI) обязаны остаться.
func TestV14_C5_Diagnostics_KeepsHonestFields(t *testing.T) {
	e := v14HonestEngine(t)
	d := e.GetDiagnostics()
	for _, k := range []string{"blockage_type", "strategy_primary", "ipv6_block", "webrtc_block", "last_persist_error"} {
		if _, ok := d[k]; !ok {
			t.Errorf("из диагностики пропало поле %q", k)
		}
	}
}

// ─── C-20 · SOCKS5-замер выдаётся за «через туннель» ─────────────────────────

// TestV14_C20_VerifiedLatency_CarriesItsSource — подтверждение, полученное пробой №1
// (локальный SOCKS5), обязано быть помечено источником: UI на трёх поставках печатал его
// как «N мс через туннель», хотя сам движок в тот же момент писал в лог обратное.
func TestV14_C20_VerifiedLatency_CarriesItsSource(t *testing.T) {
	e := v14HonestEngine(t)
	n := v14Node("N", 0.5)
	e.recordNodeVerified(n, 137, "NL", "193.29.139.147")
	if n.LastVerifiedVia != models.VerifiedViaSOCKS {
		t.Fatalf("замер через локальный SOCKS5 не помечен источником: last_verified_via=%q", n.LastVerifiedVia)
	}
	if n.LatencyIsThroughTunnel() {
		t.Fatal("SOCKS5-замер выдаётся за сквозной через туннель — это и есть жалоба C-20")
	}

	e.recordNodeVerifiedVia(n, 210, "NL", "193.29.139.147", models.VerifiedViaTUN)
	if !n.LatencyIsThroughTunnel() {
		t.Fatal("TUN-bound проба не признаётся сквозной")
	}
}

// ─── C-21 · метка страны узла расходится с фактическим выходом ───────────────

func TestV14_C21_ExitCountryMismatch_IsVisible(t *testing.T) {
	e := v14HonestEngine(t)
	n := v14Node("gb", 0.5)
	n.Name = "🇬🇧GB-82.38.31.179-0124"

	if n.CountryMismatch() {
		t.Fatal("до проверки расхождения быть не может: фактический выход неизвестен")
	}
	if got := n.EffectiveCountry(); got != "GB" {
		t.Fatalf("до проверки страна берётся из метки каталога, получено %q", got)
	}

	e.recordNodeVerified(n, 120, "NL", "193.29.139.147")

	if !n.CountryMismatch() {
		t.Fatal("узел подписан GB, фактический выход NL — расхождение обязано быть видно " +
			"(живой прогон: выбор «страна выхода» ничего не значил)")
	}
	if got := n.EffectiveCountry(); got != "NL" {
		t.Fatalf("когда фактический выход известен, он и есть страна узла, получено %q", got)
	}
	if n.LastVerifiedExitIP != "193.29.139.147" {
		t.Fatalf("IP выхода не сохранён: %q", n.LastVerifiedExitIP)
	}
}

// ─── C-22 (НОВЫЙ пункт) · «Psiphon» молча поднимает Tor ──────────────────────

// TestV14_C22_ActivatePsiphon_DoesNotSilentlyStartTor — та же молчаливая подмена, что у
// Snowflake (C-6): ActivateFallbackTunnel("psiphon") доходила до applyTorFallback, который
// строит {type:"tor"}; SOCKS-выход Psiphon (PsiphonManager.GetSingBoxOutbound) выбрасывался.
func TestV14_C22_ActivatePsiphon_DoesNotSilentlyStartTor(t *testing.T) {
	e := v14HonestEngine(t)
	var lines []string
	e.OnLog = func(s string) { lines = append(lines, s) }

	err := e.ActivateFallbackTunnel("psiphon")
	if err == nil {
		t.Fatal("активация нереализованного резерва завершилась «успехом»")
	}
	if !errors.Is(err, ErrPsiphonNotApplicable) {
		t.Fatalf("отказ не назвал настоящую причину (подмена Psiphon на Tor): %v", err)
	}
	for _, l := range lines {
		if strings.Contains(l, "подключаюсь через psiphon") {
			t.Fatalf("движок объявил подключение через Psiphon, которого не будет: %q", l)
		}
	}
	if st := e.GetFallbackStatus(); st != nil {
		if m, ok := st["fallback"].(map[string]interface{}); ok {
			if m["active_tunnel"] == "psiphon" {
				t.Fatal("статус показывает активным Psiphon, который не запускался")
			}
		}
	}
}

// ─── C-18 / V13-4 · бюджет и стратегия подтверждения пула ────────────────────

// TestV14_C18_PoolCounters_SeparateTCPAliveFromProven — пункт 4 решения: три числа вместо
// одного. Живой прогон D7: «живых 1480 из 5467 · подтверждённых трафиком: 2».
func TestV14_C18_PoolCounters_SeparateTCPAliveFromProven(t *testing.T) {
	e := v14HonestEngine(t)
	tcpOnly := v14Node("tcp", 0.5)
	proven := v14Node("proven", 0.6)
	proven.LastVerifiedAt = time.Now().Unix()
	proven.VerifiedCount = 1
	unchecked := &models.Node{ID: "new", Name: "new", Address: "1.2.3.4", Port: 443}
	v14SetPool(e, []*models.Node{tcpOnly, proven, unchecked}, nil)

	c := e.PoolVerificationCounts()
	if c.Total != 3 {
		t.Errorf("Total=%d, ожидалось 3", c.Total)
	}
	if c.TCPAlive != 2 {
		t.Errorf("TCPAlive=%d, ожидалось 2 (tcp + proven)", c.TCPAlive)
	}
	if c.ProvenTraffic != 1 {
		t.Errorf("ProvenTraffic=%d, ожидалось 1", c.ProvenTraffic)
	}
}

// TestV14_C18_VerifiedGoesStaleByTTL — verified старше TTL переходит в «требует
// переподтверждения» (V13-4 в части фоновой переверификации).
func TestV14_C18_VerifiedGoesStaleByTTL(t *testing.T) {
	now := time.Now().Unix()
	fresh := v14Node("fresh", 0.5)
	fresh.LastVerifiedAt, fresh.VerifiedCount = now-60, 1
	stale := v14Node("stale", 0.5)
	stale.LastVerifiedAt, stale.VerifiedCount = now-int64(models.VerifyStaleAfter.Seconds())-60, 1

	if fresh.VerifyStale(now) {
		t.Error("свежее подтверждение объявлено устаревшим")
	}
	if !stale.VerifyStale(now) {
		t.Errorf("подтверждение старше %v обязано считаться устаревшим", models.VerifyStaleAfter)
	}
}

// TestV14_C18_VerificationBatch_RespectsBudget — бюджет прохода: не больше K узлов за раз,
// иначе рост пула (раздел ИИ) увеличит только непроверяемую массу.
func TestV14_C18_VerificationBatch_RespectsBudget(t *testing.T) {
	e := v14HonestEngine(t)
	var pool []*models.Node
	for i := 0; i < 40; i++ {
		pool = append(pool, v14Node(fmt.Sprintf("n%02d", i), float64(i)/100))
	}
	v14SetPool(e, pool, nil)

	batch := e.NextVerificationBatch(0) // 0 = бюджет по умолчанию
	if len(batch) == 0 {
		t.Fatal("бюджетный отбор не вернул ни одного кандидата на подтверждение")
	}
	if len(batch) > verifyBudgetPerPass {
		t.Fatalf("за один проход отобрано %d узлов при бюджете %d", len(batch), verifyBudgetPerPass)
	}
	if got := e.NextVerificationBatch(3); len(got) > 3 {
		t.Fatalf("явный бюджет 3 не соблюдён: %d", len(got))
	}
}
