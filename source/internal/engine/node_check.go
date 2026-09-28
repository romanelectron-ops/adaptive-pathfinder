// node_check.go — N-1 (ТЗ APF v1.5): проба РЕАЛЬНОГО ТРАФИКА узла для «каталога рабочих узлов».
//
// Стержень (§2 ТЗ): узел считается рабочим ТОЛЬКО после того, как через него реально прошёл HTTP
// GET наружу — не по TCP-задержке. Живой лог ПК 2026-09-09 (N-8): ВСЕ узлы имели latency=1–2ms
// score≈0.95 (TCP-идеал) и 100% провалили post-connect HTTP → движок по кругу менял TCP-идеальные,
// но нерабочие узлы («система очень долго ищет узел»). Проба закрывает именно это.
//
// Механизм (переиспользование, БЕЗ нового билдера, §2/AC-1):
//  1. NewBuilder(probePort, false).BuildSingle(node) — tunMode=false ⇒ SOCKS-only, БЕЗ TUN,
//     БЕЗ sysproxy/маршрутов; не трогает активное подключение.
//  2. Переопределить cfg.Experimental.CacheFile.Path на <DataDir>/probe/slot-N/cache.db (C4/O3:
//     общий cache.db → блокировка bbolt между слотами).
//  3. Поднять инстанс проб-раннером слота (десктоп: singbox.NewProcess(binDir, slotDir)).
//  4. checker.HTTPHealthCheckInfoAt(ctx, "127.0.0.1:probePort", target) — сначала цель по
//     умолчанию (cloudflare/trace), затем HealthCheckFallbackTargets (gstatic), как runProbeAttempts.
//  5. Успех → recordNodeVerifiedVia(..., VerifiedViaSOCKS); провал → recordNodeFailure(..,"probe").
//  6. Погасить инстанс во ВСЕХ ветках (defer), очистить каталог слота.
//
// Изоляция (§3 N-1, plan notes): СВОЙ checkMu (НЕ connMu), дочерний ctx от e.ctx, e.goTracked.
// Тест-безопасность (AC-2, C6): весь per-node путь за швом e.probeFn; в проде nil → probeNodeReal,
// который дополнительно гейтится !netguard.UnderTest() — под `go test` реальный sing-box НЕ
// поднимается и egress НЕ идёт. hostguard НЕ вызывается (проба состояние ОС не меняет).
package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/checker"
	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/netguard"
	"github.com/apf/adaptive-pathfinder/internal/singbox"
)

// nodeProber — тест-шов, покрывающий ВСЮ проверку одного узла: сборка конфига, подъём инстанса,
// HTTP GET наружу и гашение. Возвращает измеренную задержку/страну/exit-IP или ошибку. В проде
// e.probeFn == nil и используется probeNodeReal; тесты подменяют fake-пробером, не трогающим сеть,
// процессы и ФС (AC-2). slot — индекс слота [0..concurrency): по нему боевой путь берёт порт/каталог.
type nodeProber func(ctx context.Context, node *models.Node, slot int) (latencyMs int64, country, exitIP string, err error)

// nodeCheckOutcome/nodeCheckOutcomes — W3 (ТЗ v1.5 §3, TZ_v1.5_NODE_CATALOG_2026-09-14):
// реконсиляция избранного в конце runNodeCheck нуждается в ТОЧНОМ списке "что реально пробовалось
// В ЭТОМ прогоне и с каким исходом" — не в перечитывании Verified*-полей узла (те могли быть
// выставлены более ранним прогоном/другим событием, см. recordNodeVerifiedCore) и не в счётчиках
// NodeCheckStatusSnapshot (те агрегаты, не список ID). probeCandidates наполняет накопитель по
// каждому узлу, которого воркер реально коснулся (успех ИЛИ провал — see-also FIX-2 про landed);
// собственный мьютекс — оба wave (top-N и Stage 2 retry, node_check.go:runNodeCheck) пишут в ОДИН
// общий накопитель конкурентно из нескольких воркеров.
type nodeCheckOutcome struct {
	node   *models.Node
	passed bool
}

type nodeCheckOutcomes struct {
	mu   sync.Mutex
	list []nodeCheckOutcome
}

func (o *nodeCheckOutcomes) add(n *models.Node, passed bool) {
	if o == nil || n == nil {
		return
	}
	o.mu.Lock()
	o.list = append(o.list, nodeCheckOutcome{node: n, passed: passed})
	o.mu.Unlock()
}

func (o *nodeCheckOutcomes) snapshot() []nodeCheckOutcome {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]nodeCheckOutcome(nil), o.list...)
}

// passedOutcomesOnly — только прошедшие пробу (для отменённого прогона: эвикций нет, см. runNodeCheck).
func passedOutcomesOnly(list []nodeCheckOutcome) []nodeCheckOutcome {
	out := make([]nodeCheckOutcome, 0, len(list))
	for _, o := range list {
		if o.passed {
			out = append(out, o)
		}
	}
	return out
}

// NodeCheckOptions — параметры одного прогона пробы. Нули заполняются умолчаниями (withDefaults);
// wave-2 UI/конфиг передаёт сюда пользовательские значения. Держим параметры в opts, а не в схеме
// AppConfig: N-1 схему не меняет (как и N-7), а «в конфиге» из ТЗ обеспечивается тем, что вызывающий
// слой волны 2 подставит значения из настроек.
type NodeCheckOptions struct {
	TopN        int           // сколько верхних по TCP-рангу кандидатов пробовать (умолч. 30)
	TargetK     int           // порог ОСТАНОВКИ: набрали K подтверждённых — стоп (умолч. 8), НЕ потолок удержания
	Concurrency int           // параллельность проб (умолч. 6 десктоп / 1 Android, C7)
	PerNode     time.Duration // таймаут на один узел (умолч. 10 c)
}

// Умолчания — package-level var (тюнятся тестами), тот же стиль, что verifyBudgetPerPass/
// ksExtraResolveBudget. Значения приняты владельцем (ТЗ §6): N=30, K=8, concurrency=6, per-node=10c.
var (
	defaultNodeCheckTopN        = 30
	defaultNodeCheckTargetK     = 8
	defaultNodeCheckConcurrency = 6
	defaultNodeCheckPerNode     = 10 * time.Second
)

// probePortBase — база портов проб-слотов. Далеко от cfg.ListenPort (умолч. 10808) и его соседей,
// чтобы socks/http/clash слотов (порт,+1,+2) не пересекались ни с рабочим инстансом, ни между собой.
var probePortBase = 21200

func (o NodeCheckOptions) withDefaults(goos string) NodeCheckOptions {
	if o.TopN <= 0 {
		o.TopN = defaultNodeCheckTopN
	}
	if o.TargetK <= 0 {
		o.TargetK = defaultNodeCheckTargetK
	}
	if o.Concurrency <= 0 {
		o.Concurrency = defaultNodeCheckConcurrency
	}
	if o.PerNode <= 0 {
		o.PerNode = defaultNodeCheckPerNode
	}
	// C7: Android — один ин-процесс слот, пробы серийно (libbox single-instance + глобали).
	if goos == "android" && o.Concurrency > 1 {
		o.Concurrency = 1
	}
	// K не может превышать N (иначе порог остановки недостижим и это вводит в заблуждение).
	if o.TargetK > o.TopN {
		o.TargetK = o.TopN
	}
	return o
}

// NodeCheckStatusSnapshot — коалесцированный снимок прогресса пробы (за checkMu). JSON-совместим:
// используется NodeCheckStatus() и коллбэком OnNodeCheckBatch (wave 2). «Added» относится к N-2
// (расширение пула из источников) — в N-1 остаётся 0: проба лишь штампует Verified* на уже
// существующих узлах пула, новых не добавляет.
type NodeCheckStatusSnapshot struct {
	Running   bool   `json:"running"`
	Phase     string `json:"phase"` // "" | "probing" | "done" | "cancelled"
	Total     int    `json:"total"` // сколько узлов отобрано на пробу (top-N, ≤ размера пула)
	Probed    int    `json:"probed"`
	Verified  int    `json:"verified"`
	Failed    int    `json:"failed"`
	Added     int    `json:"added"` // N-2 (не пишется в N-1)
	TargetK   int    `json:"target_k"`
	StartedAt int64  `json:"started_at,omitempty"` // unix-секунды

	// KillSwitchWarning — P0-2 (ТЗ v1.6, live-run 09-14, см. память
	// apf-killswitch-blocks-traffic-probe-windows.md): непусто, когда на СТАРТЕ этого прогона
	// Windows Kill Switch реально включён И движок подключён — тогда allow-правило брандмауэра
	// (netsh windowsKS ИЛИ wfpKS, см. killSwitchEnabledNow/computeKillSwitchProbeWarning) сужено
	// до IP АКТИВНОГО узла, и проба сиблингов (probeNodeReal коннектится НАПРЯМУЮ к серверу
	// каждого пробуемого узла) будет ЛОЖНО проваливаться на всех узлах, кроме активного. Чисто
	// диагностическое поле: НЕ останавливает пробу и НЕ трогает KS enforcement — как это показать
	// пользователю, решает UI отдельным лотом (P0-2 отдаёт только честный машиночитаемый сигнал +
	// один e.log, см. StartNodeCheck).
	KillSwitchWarning string `json:"kill_switch_warning,omitempty"`
}

// Сигнальные ошибки драйвера.
var (
	// ErrNodeCheckBusy — проба уже идёт (один прогон за раз).
	ErrNodeCheckBusy = errors.New("проверка узлов уже идёт")
	// ErrEngineStopping — движок останавливается, прогон не запущен.
	ErrEngineStopping = errors.New("движок останавливается — проверка узлов не запущена")
	// errProbeUnderTest — боевой пробер под `go test` (защита от реального egress, AC-2/C6).
	errProbeUnderTest = errors.New("боевая проба узла отключена под go test (netguard.UnderTest)")
)

// killSwitchProbeWarningText — P0-2 (ТЗ v1.6, живой прогон ПК 09-14, см. память
// apf-killswitch-blocks-traffic-probe-windows.md). Текст объясняет ПРИЧИНУ (allow-правило сужено
// до активного узла) и ДЕЙСТВИЕ (отключиться ИЛИ временно выключить KS), не просто «что-то не так».
const killSwitchProbeWarningText = "Kill Switch включён, пока вы подключены — правило файрвола " +
	"разрешает выход только активному узлу, поэтому проба покажет ВСЕ ОСТАЛЬНЫЕ узлы как " +
	"нерабочие, хотя они исправны. Отключитесь (Disconnect) или на время выключите Kill Switch " +
	"и запустите сборку списка заново — тогда проба пойдёт напрямую с хоста и проверит остальные " +
	"узлы честно."

// killSwitchEnabledNow — читает АКТУАЛЬНОЕ состояние используемого сейчас KS-бэкенда для
// детектора предупреждения о пробе (computeKillSwitchProbeWarning). Намеренно НЕ вызывает
// currentKS() (engine.go): та умеет ПЕРЕСОЗДАВАТЬ/ПЕРЕКЛЮЧАТЬ бэкенд (self-heal на подозрении о
// зависшем BFE, локальный↔служебный) — то есть мутирует выбор исполнителя, а не просто читает
// состояние; вызывать эту логику из нового, диагностического call-site — лишний путь к
// NewServiceClient()/новым лог-строкам оттуда, где это не ожидается. Вместо этого — берём
// СЕЙЧАС используемый бэкенд под тем же e.ksMu (тем самым не гонимся с currentKS() за право
// пересоздать e.ks, просто читаем актуальный указатель) и спрашиваем его состояние через уже
// существующий, проверенный самой currentKS() приём — ksIsEnabledWithTimeout (engine.go),
// который защищает ИМЕННО этот вызов от зависшего WFP/BFE (см. её комментарий и
// TestCurrentKS_SelfHealsWhenIsEnabledHangs в engine_r1_r4_test.go): "зависло" здесь не может
// заблокировать StartNodeCheck дольше ksProbeTimeout.
//
// hung трактуется как "не знаю" → false: при реально зависшем KS честнее промолчать, чем
// добавить ложное предупреждение поверх уже сломанного Kill Switch (см. ASSUMPTIONS в result.md
// лота P0-2-KS-PROBE).
//
// e.ks == nil в проде не бывает (New()/NewServiceHost всегда инициализируют его, engine.go:638) —
// проверка ниже только на случай "голого" *Engine{}, собранного вручную в тестах без New();
// тогда падаем на cfg.EnableKillSwitch — тот самый fallback, который ТЗ лота считает допустимым,
// если нет чистого хендла к менеджеру.
func (e *Engine) killSwitchEnabledNow() bool {
	e.ksMu.Lock()
	ks := e.ks
	e.ksMu.Unlock()
	if ks == nil {
		return e.cfg != nil && e.cfg.EnableKillSwitch
	}
	enabled, hung := ksIsEnabledWithTimeout(ks)
	if hung {
		return false
	}
	return enabled
}

// computeKillSwitchProbeWarning — P0-2 (ТЗ v1.6): детектирует условие живого прогона 09-14 ДО
// запуска пробы (см. StartNodeCheck), чтобы самый первый NodeCheckStatus() уже нёс честное
// предупреждение. Условие (все три):
//  1. platform == "windows" — И netsh-бэкенд (proxy-режим), И WFP-бэкенд (VPN/Hybrid) на этой
//     платформе сужают allow ТОЛЬКО до активного узла (killswitch.go:184-191 remoteip=;
//     wfp_windows.go:371-376 guidCondIPRemoteAddress); Android — VpnService-KS, per-endpoint
//     allow не делает вовсе (см. память), поэтому проба сиблингов там не страдает.
//  2. e.IsConnected() — allow-список сужен ИМЕННО ДО ОДНОГО endpoint только пока есть активное
//     подключение; до/после Disconnect проба идёт egress ХОСТА напрямую, KS её не видит.
//  3. killSwitchEnabledNow() — KS не просто "включена настройка", а РЕАЛЬНО применена сейчас
//     (см. её комментарий про currentKS()/cfg fallback).
//
// Чистое чтение: НИКОГДА не трогает connMu/e.proc/e.builder/KS enforcement (Enable/Disable здесь
// не вызываются) — только диагностика.
func (e *Engine) computeKillSwitchProbeWarning() string {
	if e.probeGOOS() != "windows" {
		return ""
	}
	if !e.IsConnected() {
		return ""
	}
	if !e.killSwitchEnabledNow() {
		return ""
	}
	return killSwitchProbeWarningText
}

// StartNodeCheck запускает один прогон пробы реального трафика по top-N кандидатам пула. Возвращает
// сразу; прогресс — через NodeCheckStatus()/OnNodeCheckBatch, отмена — CancelNodeCheck().
func (e *Engine) StartNodeCheck(opts NodeCheckOptions) error {
	// ТЗ v1.7 (PROBE-DEPTH-SETTING), запрос владельца 09-14: дефолт пробует только top-30
	// узлов — владелец хочет находить больше подтверждённых узлов и получил регулируемую
	// глубину пробы в «Параметры» (models.AppConfig.NodeCheckTopN). Подставляем значение из
	// конфига ТОЛЬКО когда вызывающий явно не задал TopN сам (opts.TopN<=0) — программные
	// вызыватели (тесты, будущие точки входа) с явным TopN не переопределяются конфигом.
	// TargetK=TopN сознательно отключает ранний стоп по «набрали K подтверждённых»: цель
	// настройки — проверить КАК МОЖНО БОЛЬШЕ кандидатов, а не остановиться на первых
	// найденных. withDefaults ниже всё равно заполнит TopN=30, если cfgTopN тоже 0.
	if opts.TopN <= 0 {
		e.mu.RLock()
		cfgTopN := 0
		if e.cfg != nil {
			cfgTopN = e.cfg.NodeCheckTopN
		}
		e.mu.RUnlock()
		if cfgTopN > 0 {
			// Режим «Все рабочие» (models.NodeCheckTopNAll, запрос владельца 09-15) — тоже cfgTopN>0
			// и течёт сюда БЕЗ спецкода: TopN=TargetK=огромное → withDefaults не трогает (>0, K≤N),
			// ranked[:TopN] ниже не срезает (len(пула) ≪ значения), ранний стоп по TargetK недостижим.
			opts.TopN = cfgTopN
			opts.TargetK = cfgTopN // проверяем все N (не останавливаемся рано) — цель: найти как можно больше рабочих
		}
	}
	opts = opts.withDefaults(e.probeGOOS())

	// P0-2 (ТЗ v1.6, живой прогон 09-14): вычисляется ДО checkMu и ДО busy-проверки ниже —
	// синхронно и БЕЗ окна гонки, чтобы САМЫЙ ПЕРВЫЙ NodeCheckStatus() после успешного возврата
	// уже нёс предупреждение (нет момента "checkRunning уже true, поле ещё пустое"). Цена:
	// на пути ErrNodeCheckBusy (сканирование уже идёт) эта проба тоже выполняется — лишняя, но
	// дешёвая (ksMu + hang-guarded IsEnabled, максимум ksProbeTimeout в вырожденном случае
	// зависшего KS) и самоизлечивающаяся; вынесена наружу и НЕ залогирована на этом пути (см.
	// ниже), чтобы не путать пользователя предупреждением про сканирование, которое не началось.
	ksWarning := e.computeKillSwitchProbeWarning()

	e.checkMu.Lock()
	if e.checkRunning {
		e.checkMu.Unlock()
		return ErrNodeCheckBusy
	}
	// Дочерний ctx от e.ctx: Stop()/Disconnect() отменяют пробу вместе с движком; CancelNodeCheck
	// отменяет только её. currentCtx() — гонка-безопасное чтение e.ctx.
	ctx, cancel := context.WithCancel(e.currentCtx())
	e.checkRunning = true
	e.checkCancel = cancel
	e.checkStatus = NodeCheckStatusSnapshot{
		Running:           true,
		Phase:             "probing",
		TargetK:           opts.TargetK,
		StartedAt:         time.Now().Unix(),
		KillSwitchWarning: ksWarning,
	}
	e.checkMu.Unlock()

	if ksWarning != "" {
		e.log("[killswitch] " + ksWarning)
	}

	if !e.goTracked(func() { e.runNodeCheck(ctx, opts) }) {
		// e.ctx уже мёртв (движок останавливается) — откатываем заявленное состояние.
		cancel()
		e.finishNodeCheck("cancelled")
		return ErrEngineStopping
	}
	return nil
}

// CancelNodeCheck отменяет текущий прогон (если идёт). Идемпотентна. Воркеры выходят чисто по
// дочернему ctx, без паники; активного подключения проба не касается.
func (e *Engine) CancelNodeCheck() {
	e.checkMu.Lock()
	cancel := e.checkCancel
	e.checkMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// NodeCheckStatus возвращает снимок прогресса (JSON-совместимый).
func (e *Engine) NodeCheckStatus() NodeCheckStatusSnapshot {
	e.checkMu.Lock()
	defer e.checkMu.Unlock()
	return e.checkStatus
}

// nodeCheckWidenFactor — во сколько раз расширить окно top-N при повторе Stage 2 (N-2 §3 C14),
// когда первый проход не подтвердил трафиком НИ ОДНОГО кандидата. var — тюнится тестом, тот же
// стиль, что у defaultNodeCheckTopN и соседей.
var nodeCheckWidenFactor = 2

// excludeActiveNode — FIX-1 (консилиум L1-ENG-A, CONSILIUM_L1-ENG-A.md п.1): убирает из
// кандидатов пробы узел, к которому движок СЕЙЧАС подключён (e.state.ActiveNode). Причина:
// probeNodeReal поднимает ВТОРОЙ, независимый SOCKS-сеанс к ТОМУ ЖЕ серверу — часть
// протоколов/серверов не переживают параллельную сессию с тем же ключом/IP и дают ложный провал;
// провал пробы зовёт recordNodeFailure, который обнуляет Score и растит FailStreak РАБОЧЕГО
// активного узла (демотирование живого узла собственной же диагностикой). Сравнение — по ID
// (как pickPinned/favoritesFirst), не по указателю: узел, пришедший из rankCandidatesForStrategy,
// не обязан быть тем же *Node, что лежит в e.state.ActiveNode, хотя обычно это один объект.
// e.state.ActiveNode == nil, когда движок не подключён (setDisconnected обнуляет его) — тогда
// фильтр не убирает ничего.
func (e *Engine) excludeActiveNode(candidates []*models.Node) []*models.Node {
	e.stateMu.RLock()
	active := e.state.ActiveNode
	e.stateMu.RUnlock()
	if active == nil {
		return candidates
	}
	out := make([]*models.Node, 0, len(candidates))
	for _, n := range candidates {
		if n != nil && n.ID == active.ID {
			continue
		}
		out = append(out, n)
	}
	return out
}

// runNodeCheck — тело прогона (идёт в goTracked-горутине). Изоляция: НИКОГДА не трогает
// connMu/e.proc/e.builder.
//
// N-2 (ТЗ APF v1.5 §3, C14, вариант А, двухступенчатый отбор):
//
//	Stage 1 — пул должен быть заполнен (иначе пробовать нечего, тот же детектор первого запуска,
//	что у loadNodes/runPoolScan, N-6) и должен существовать хоть какой-то TCP-ранг. Второй
//	TCP-скан НЕ пишем безусловно — sweep переиспользуется, ТОЛЬКО если ранжирование
//	действительно вернуло пусто (свежая TCP-проверка реально нужна), не «на всякий случай».
//	Stage 2 — явный цикл: probe top-N кандидатов, пока не наберётся K рабочих (probeCandidates).
//	При НУЛЕ подтверждённых после top-N — расширяем окно И обновляем источники ОДИН раз, затем
//	повторяем (бюджет ретрая = 1 проход, без цикла — C14/O15, но без infinite loop).
func (e *Engine) runNodeCheck(ctx context.Context, opts NodeCheckOptions) {
	t0 := time.Now()
	defer func() { e.logDiagN8("StartNodeCheck", t0) }()

	// Stage 1a: пустой пул — пробовать нечего, синхронно подтягиваем источники (тот же приём,
	// что у runPoolScan, engine.go). С cfg.Sources==nil (нет источников) — быстрый no-op.
	e.mu.RLock()
	poolEmpty := len(e.nodes) == 0
	e.mu.RUnlock()
	if poolEmpty {
		tSrc := time.Now()
		e.updateSources(true)
		e.logDiagN8("updateSources(node-check:pool-empty)", tSrc)
	}

	// FIX-1 применяется на КАЖДОМ ранжировании ниже (Stage 1 и Stage 2 retry) — исключение
	// активного узла не должно "рассосаться" после sweep/updateSources.
	ranked := e.excludeActiveNode(e.rankCandidatesForStrategy())
	if len(ranked) == 0 && !poolEmpty {
		// Пул НЕ пуст, но ранжирование вернуло 0 кандидатов — вот теперь свежий TCP-фильтр
		// ДЕЙСТВИТЕЛЬНО нужен (C14): узлы либо ни разу не проверялись, либо все забанены/только
		// что отказали. Переиспользуем существующий обход (sweep.go), не новый скан.
		tSweep := time.Now()
		e.runSweep(ctx, "node-check")
		ranked = e.excludeActiveNode(e.rankCandidatesForStrategy())
		e.logDiagN8(fmt.Sprintf("runSweep(node-check:stage1-empty-rank) got=%d", len(ranked)), tSweep)
	}

	if len(ranked) > opts.TopN {
		ranked = ranked[:opts.TopN]
	}

	e.checkMu.Lock()
	e.checkStatus.Total = len(ranked)
	snap := e.checkStatus
	e.checkMu.Unlock()
	e.emitNodeCheckStatus(snap)

	if len(ranked) == 0 {
		e.finishNodeCheck("done")
		return
	}

	// W3 (ТЗ v1.5 §3): накопитель "кого реально пробовали и с каким исходом В ЭТОМ прогоне" —
	// обе волны (top-N ниже и Stage 2 retry) пишут в ОДИН outcomes, реконсиляция избранного в
	// конце читает его целиком, одним снимком.
	outcomes := &nodeCheckOutcomes{}
	verified, judged := e.probeCandidates(ctx, ranked, opts, outcomes)

	// Консилиум приёмки этапа A (ТЗ HOTSWITCH §8, правка M1): ни одна проба волны не дошла до
	// суждения об узле — все сорвались на этой машине (слот не поднял sing-box за срок пробы).
	// Расширять окно и обновлять источники из сети бессмысленно: новые кандидаты упрутся в ту же
	// машину, а обновление источников — лишний сетевой проход ради ничего.
	if verified == 0 && judged == 0 && ctx.Err() == nil {
		e.log("[diag-N8] Stage2 пропущен: ни одна проба не выполнена по причине на этой машине " +
			"(sing-box слота не поднялся) — расширение окна не поможет, узлы не судимы")
	}

	// Stage 2 retry (C14/O15): top-N дал НОЛЬ подтверждённых трафиком. Расширяем окно и/или
	// обновляем источники ОДИН раз — бюджет ретрая ровно один проход (bounded, не цикл).
	if verified == 0 && judged > 0 {
		select {
		case <-ctx.Done(): // отмена — ретрай не имеет смысла, ниже phase станет "cancelled"
		default:
			e.log("[diag-N8] Stage2 zero-verified: расширяю окно top-N и обновляю источники (один повтор, N-2 C14)")
			tSrc := time.Now()
			e.updateSources(true)
			e.logDiagN8("updateSources(node-check:stage2-retry)", tSrc)

			// ВАЖНО: recordNodeFailure(node,"probe") ставит Score=0 на структуре узла, но
			// rankCandidatesForStrategy ПЕРЕСЧИТЫВАЕТ Score заново из Latency/Status при каждом
			// вызове (не читает старое значение) — только что провалившие узлы вернутся в
			// ранжировании С ТЕМ ЖЕ рангом, что и до пробы (обычный TCP-скоринг recentFailures их
			// не видит: recordNodeFailure зовёт markNodeFailed только для relay-выходов, §3719).
			// Поэтому «расширить окно» означает ЯВНО исключить уже пробованные ID, а не
			// положиться на то, что ранжирование само их вытолкнет — иначе retry молча
			// повторил бы probeCandidates НАД ТЕМИ ЖЕ узлами вместо новых.
			tried := make(map[string]bool, len(ranked))
			for _, n := range ranked {
				if n != nil {
					tried[n.ID] = true
				}
			}
			widened := opts.TopN * nodeCheckWidenFactor
			fresh := e.excludeActiveNode(e.rankCandidatesForStrategy())
			extra := make([]*models.Node, 0, len(fresh))
			for _, n := range fresh {
				if n == nil || tried[n.ID] {
					continue
				}
				extra = append(extra, n)
				if len(extra) >= widened {
					break
				}
			}
			if len(extra) > 0 {
				e.checkMu.Lock()
				e.checkStatus.Total += len(extra)
				snap := e.checkStatus
				e.checkMu.Unlock()
				e.emitNodeCheckStatus(snap)
				e.probeCandidates(ctx, extra, opts, outcomes)
			}
		}
	}

	// W3 (ТЗ v1.5 §3): реконсиляция избранного — РОВНО ОДИН РАЗ за прогон, ПОСЛЕ обеих волн
	// (top-N и Stage 2 retry). Ручная сборка (StartNodeCheck зовётся только по кнопке
	// пользователя, никакого фонового таймера) — единственный путь, которым каталог меняет
	// избранное.
	//
	// ТЗ HOTSWITCH §8 A3 (RCA #3): у ОТМЕНЁННОГО прогона эвикций нет — «в сомнении — держим»,
	// та же логика, что safeguard'ы W3. Раньше реконсиляция шла и после отмены, и Stop() посреди
	// пробы снимал системных фаворитов пачкой (живой лог 2026-09-21: 8 штук за 150 мс). Реальные
	// успехи отменённого прогона — факт, их добавление в избранное сохраняется.
	probed := outcomes.snapshot()
	if ctx.Err() != nil {
		probed = passedOutcomesOnly(probed)
	}
	e.reconcileFavoritesFromNodeCheck(probed)

	phase := "done"
	select {
	case <-ctx.Done():
		phase = "cancelled"
	default:
	}
	e.finishNodeCheck(phase)
}

// probeCandidates — одна волна параллельной пробы над уже готовым списком кандидатов (отбор и
// исключение активного узла — забота вызывающего). Общее тело Stage 2: worker pool с ограничением
// opts.Concurrency, ранняя остановка при opts.TargetK подтверждённых В ЭТОЙ волне. Возвращает,
// сколько из ЭТИХ кандидатов подтвердились — runNodeCheck трактует 0 как «нужен retry с
// расширенным окном» (N-2 C14). Извлечена из прежнего тела runNodeCheck без изменения логики
// самого пула воркеров — только источник записи результата поменялся (FIX-2, см. ниже).
//
// outcomes — W3: накопитель "узел → прошёл/провалил", которым в конце runNodeCheck пользуется
// reconcileFavoritesFromNodeCheck. nil безопасен (nodeCheckOutcomes.add на nil-получателе —
// no-op) — на случай будущих внутрипакетных вызовов, которым реконсиляция не нужна.
//
// Второе значение — judged: сколько проб дошли до суждения об узле (успех или его собственный
// провал). Пробы, сорванные машиной или отменой, сюда не входят (ТЗ HOTSWITCH §8 A3/M1).
func (e *Engine) probeCandidates(ctx context.Context, candidates []*models.Node, opts NodeCheckOptions, outcomes *nodeCheckOutcomes) (int, int) {
	if len(candidates) == 0 {
		return 0, 0
	}
	// Долг-5 (2026-09-21): под активным Windows Kill Switch проба сиблингов режется default-block
	// (allow сужен до IP активного узла), из-за чего скан во время подключения ложно находил 0
	// рабочих. Открываем узкое временное окно к IP кандидатов ЭТОЙ волны и ГАРАНТИРОВАННО закрываем
	// после (defer). Не Windows / KS выкл / WFP-бэкенд / кандидатов больше потолка → окно не
	// открывается, остаётся честное предупреждение P0-2 (см. openKSProbeWindow). Никогда не трогает
	// базовый KS активного подключения — только аддитивные allow-правила поверх.
	if closeWindow := e.openKSProbeWindow(candidates); closeWindow != nil {
		defer closeWindow()
	}
	ports := probeSlotPorts(probePortBase, e.cfg.ListenPort, opts.Concurrency)

	jobs := make(chan *models.Node)
	stop := make(chan struct{}) // закрывается, когда набрано K подтверждённых В ЭТОЙ волне
	var stopOnce sync.Once
	var verified, judged int32
	var workers sync.WaitGroup

	worker := func(slot int) {
		defer workers.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case node, ok := <-jobs:
				if !ok {
					return
				}
				lat, country, exitIP, err := e.probeOne(ctx, node, slot, ports[slot], opts.PerNode)
				if err != nil {
					// ТЗ HOTSWITCH §8 A3 (RCA #3): судим узел только за его собственный провал.
					// Отменённая проба и сбой машины (слот не поднял sing-box) — не исход узла: ни
					// штрафа, ни записи в outcomes (иначе реконсиляция сняла бы системных фаворитов —
					// живой лог 2026-09-21: Stop() → 8 фаворитов сняты за 150 мс), ни счётчика
					// «провалено» (узел не проверялся).
					if !probeFailureJudgesNode(ctx, err) {
						if ctx.Err() == nil {
							e.log(fmt.Sprintf("Проба «%s»: не выполнена не по вине узла (%v) — узел не судим",
								node.Name, err))
						}
						continue
					}
					atomic.AddInt32(&judged, 1)
					e.recordNodeFailure(node, "probe")
					e.bumpNodeCheck(false)
					outcomes.add(node, false) // W3: реконсиляция избранного читает исход этого прогона
					continue
				}
				// FIX-2 (консилиум L1-ENG-A п.3): каталожная проба однозначна — пишем В ОБХОД
				// гейта гонки узлов (raceNodes), recordNodeVerifiedViaProbe вместо
				// recordNodeVerifiedVia. bumpNodeCheck считает узел подтверждённым ТОЛЬКО если
				// штамп реально лёг (landed) — раньше здесь стояла безусловная bumpNodeCheck(true),
				// и статус мог показать "verified N" при незаписанном узле.
				atomic.AddInt32(&judged, 1)
				landed := e.recordNodeVerifiedViaProbe(node, lat, country, exitIP, models.VerifiedViaSOCKS)
				e.bumpNodeCheck(landed)
				// W3: избранное реконсилируется по РЕАЛЬНОМУ исходу штампа (landed), не по
				// голому факту успешного HTTP GET — незаписанный (гейт гонки где-то ещё)
				// результат не должен продвигать узел в системное избранное.
				outcomes.add(node, landed)
				if landed && int(atomic.AddInt32(&verified, 1)) >= opts.TargetK {
					stopOnce.Do(func() { close(stop) })
				}
			}
		}
	}

	for slot := 0; slot < opts.Concurrency; slot++ {
		slot := slot
		workers.Add(1)
		// goTracked ⇒ воркеры учтены в e.wg (Stop() их дождётся). Если ctx уже мёртв — воркер не
		// запустится, снимаем локальный счётчик вручную, иначе workers.Wait() зависнет.
		if !e.goTracked(func() { worker(slot) }) {
			workers.Done()
		}
	}

	// Подача кандидатов: прекращаем при отмене или достижении K.
feed:
	for _, node := range candidates {
		select {
		case <-ctx.Done():
			break feed
		case <-stop:
			break feed
		case jobs <- node:
		}
	}
	close(jobs)
	workers.Wait()
	return int(atomic.LoadInt32(&verified)), int(atomic.LoadInt32(&judged))
}

// probeFailureJudgesNode — ТЗ HOTSWITCH §8 A3: говорит ли провал пробы что-то об УЗЛЕ.
//
// Нет, если отменён сам прогон (runCtx — ctx прогона, НЕ per-node: истёкший срок пробы одного
// узла — законный провал медленного узла), если слот не поднял sing-box по причине машины
// (singbox.ErrLocalStart: процесс не создан, порт не открылся, запуск прерван) или если шаг
// пробы локальный (каталог слота, запись конфига, барьер тестовой среды). Иначе — да: конфиг
// из данных узла отвергнут либо узел не пропустил реальный трафик.
func probeFailureJudgesNode(runCtx context.Context, err error) bool {
	if runCtx.Err() != nil {
		return false
	}
	return classifyConnectFailure(err) == failureNode && !errors.Is(err, errProbeUnderTest)
}

// probeOne — один узел за швом e.probeFn (тест) либо боевым probeNodeReal. Оборачивает per-node
// таймаутом поверх дочернего ctx прогона.
func (e *Engine) probeOne(ctx context.Context, node *models.Node, slot, socksPort int, perNode time.Duration) (int64, string, string, error) {
	pctx, cancel := context.WithTimeout(ctx, perNode)
	defer cancel()
	if e.probeFn != nil {
		return e.probeFn(pctx, node, slot)
	}
	return e.probeNodeReal(pctx, node, slot, socksPort)
}

// probeNodeReal — БОЕВОЙ пробер (используется, только когда e.probeFn == nil). Поднимает SOCKS-only
// инстанс sing-box для узла, делает реальный HTTP GET наружу, гасит инстанс. Гейт netguard.UnderTest
// — defense-in-depth: даже при nil-шве под `go test` сюда попасть нельзя без реального egress (AC-2).
func (e *Engine) probeNodeReal(ctx context.Context, node *models.Node, slot, socksPort int) (int64, string, string, error) {
	if netguard.UnderTest() {
		return 0, "", "", errProbeUnderTest
	}
	if node == nil {
		return 0, "", "", errors.New("probe: nil node")
	}

	// SOCKS-only конфиг (tunMode=false ⇒ без TUN). Никакого нового билдера — тот же BuildSingle.
	b := singbox.NewBuilder(socksPort, false)
	cfg, err := b.BuildSingle(node)
	if err != nil {
		return 0, "", "", fmt.Errorf("build probe config: %w", err)
	}

	// Каталог слота + свой cache.db (C4/O3: раздельные bbolt-файлы, иначе блокировка).
	slotDir := filepath.Join(config.DataDir(), "probe", fmt.Sprintf("slot-%d", slot))
	if err := os.MkdirAll(slotDir, 0o755); err != nil {
		return 0, "", "", markLocalFailure(fmt.Errorf("probe slot dir: %w", err))
	}
	if cfg.Experimental == nil {
		cfg.Experimental = &singbox.ExperimentalConfig{}
	}
	if cfg.Experimental.CacheFile == nil {
		cfg.Experimental.CacheFile = &singbox.CacheFileConfig{Enabled: true}
	}
	cfg.Experimental.CacheFile.Path = filepath.Join(slotDir, "cache.db")

	// Подъём инстанса проб-раннером слота (десктоп: отдельный процесс на каждый слот; Android:
	// concurrency=1 ⇒ один слот, серийно — см. В-1.5-6 в result.md). Не трогаем e.proc/e.builder.
	proc := singbox.NewProcess(config.BinDir(), slotDir)
	if err := proc.WriteConfig(cfg); err != nil {
		return 0, "", "", markLocalFailure(fmt.Errorf("write probe config: %w", err))
	}
	// Класс отказа старта (singbox.ErrLocalStart / ErrConfigRejected) сохраняется через %w —
	// по нему probeFailureJudgesNode решает, судить ли узел (ТЗ HOTSWITCH §8 A3).
	if err := proc.Start(ctx); err != nil {
		return 0, "", "", fmt.Errorf("start probe instance: %w", err)
	}
	// Гашение во ВСЕХ ветках + уборка каталога слота (C4).
	defer func() {
		_ = proc.Stop()
		_ = os.RemoveAll(slotDir)
	}()

	info, err := e.probeHTTPWithFallback(ctx, fmt.Sprintf("127.0.0.1:%d", socksPort))
	if err != nil {
		return 0, "", "", err
	}
	return info.LatencyMs, info.Country, info.ExitIP, nil
}

// probeHTTPWithFallback — HTTP GET через локальный SOCKS проб-слота: сначала цель по умолчанию,
// затем HealthCheckFallbackTargets — тот же приём, что runProbeAttempts (разная цель на повторе
// отличает «этот внешний адрес недоступен по пути» от «узел не пропускает трафик», инцидент
// 2026-08-27). Первый успех — результат.
func (e *Engine) probeHTTPWithFallback(ctx context.Context, proxyAddr string) (checker.HealthInfo, error) {
	targets := append([]string{checker.DefaultHealthCheckURL()}, checker.HealthCheckFallbackTargets...)
	var lastErr error
	for _, target := range targets {
		select {
		case <-ctx.Done():
			return checker.HealthInfo{}, ctx.Err()
		default:
		}
		info, err := e.checker.HTTPHealthCheckInfoAt(ctx, proxyAddr, target)
		if err == nil {
			return info, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("probe: нет целей проверки")
	}
	return checker.HealthInfo{}, lastErr
}

// reconcileFavoritesFromNodeCheck — W3 (ТЗ v1.5 §3, TZ_v1.5_NODE_CATALOG_2026-09-14): ЕДИНСТВЕННАЯ
// точка, где сборка каталога меняет избранное. Вызывается РОВНО ОДИН РАЗ, в конце runNodeCheck
// (после Stage 2 retry, если он был) — то есть только на РУЧНОЙ сборке (StartNodeCheck запускает
// только явный вызов, никакого фонового таймера нигде в этом пакете нет). Ручная звезда
// пользователя (AddFavorite/RemoveFavorite) сюда не заходит и от этой функции не зависит.
//
//	(a) passed==true в outcomes  → добавить/освежить как СИСТЕМНЫЙ фаворит (addFavoriteWithOrigin
//	    c OriginSystem — идемпотентно, НИКОГДА не понижает уже существующий "user", см. её
//	    комментарий);
//	(b) существующий СИСТЕМНЫЙ фаворит, который был пробован в outcomes и провалился, эвиктится
//	    (evictSystemFavorite), ЕСЛИ давность его последнего подтверждения (Node.LastVerifiedAt)
//	    превысила reviewIntervalDuration(текущая настройка) — при "each_scan" порог 0, эвикшен
//	    без отсрочки. Иначе запись остаётся как есть (безо всякого нового поля "stale" — её
//	    естественная свежесть уже честно видна через Node.VerifyStale/ProvenFreshness);
//	(c) "user"-фавориты НИКОГДА не упоминаются в toEvict ниже (фильтр по EffectiveOrigin==system)
//	    — они не эвиктятся отсюда вообще, каким бы ни был исход их пробы; refresh их proven-
//	    статуса делает recordNodeFailure/recordNodeVerifiedViaProbe САМ, на структуре узла,
//	    независимо от класса избранного;
//	(d) потолок SystemFavoriteCap (enforceSystemFavoriteCap) — В КОНЦЕ, к ИТОГОВОМУ множеству
//	    системных фаворитов (safeguard #2/#6: пин/manual-узлы в этот список не входят и потому
//	    места в потолке не занимают — retainNodeForDisk удержит их на диске своим, независимым
//	    критерием).
//
// Не пробованных в этом прогоне существующих системных фаворитов (не попали в top-N/retry-окно,
// либо исключены как активный узел — FIX-1) эта функция НЕ трогает вообще: отсутствие сигнала —
// не провал, "нет данных" не должно читаться как "нужно вытеснить".
func (e *Engine) reconcileFavoritesFromNodeCheck(outcomes []nodeCheckOutcome) {
	if len(outcomes) == 0 {
		return
	}
	reviewWindow := reviewIntervalDuration(e.CatalogReviewInterval())
	now := time.Now().Unix()

	failedProbedIDs := make(map[string]bool, len(outcomes))
	for _, o := range outcomes {
		if o.node == nil {
			continue
		}
		if o.passed {
			_ = e.addFavoriteWithOrigin(o.node.ID, models.OriginSystem)
			continue
		}
		failedProbedIDs[o.node.ID] = true
	}
	if len(failedProbedIDs) == 0 {
		e.enforceSystemFavoriteCap()
		return
	}

	e.favMu.RLock()
	var candidates []string
	for _, r := range e.favRefs {
		if r.EffectiveOrigin() == models.OriginSystem && failedProbedIDs[r.ID] {
			candidates = append(candidates, r.ID)
		}
	}
	e.favMu.RUnlock()

	if len(candidates) > 0 {
		e.mu.RLock()
		byID := make(map[string]*models.Node, len(e.nodes))
		for _, n := range e.nodes {
			if n != nil {
				byID[n.ID] = n
			}
		}
		e.mu.RUnlock()

		for _, id := range candidates {
			n := byID[id]
			// safeguard "в сомнении — держим дольше": узел исчез из пула между пробой и этой
			// точкой (теоретический край) — нечем измерить давность, эвиктим; иначе эвиктим
			// только если давность ПОСЛЕДНЕГО ПОДТВЕРЖДЕНИЯ (не провала) превысила окно.
			if n != nil && reviewWindow > 0 && now-n.LastVerifiedAt <= int64(reviewWindow.Seconds()) {
				continue
			}
			e.evictSystemFavorite(id)
		}
	}

	e.enforceSystemFavoriteCap()
}

// bumpNodeCheck — атомарно обновляет счётчики прогресса и шлёт коалесцированный снимок.
func (e *Engine) bumpNodeCheck(verified bool) {
	e.checkMu.Lock()
	e.checkStatus.Probed++
	if verified {
		e.checkStatus.Verified++
	} else {
		e.checkStatus.Failed++
	}
	snap := e.checkStatus
	e.checkMu.Unlock()
	e.emitNodeCheckStatus(snap)
}

// clearKillSwitchProbeWarning — долг-5 (2026-09-21): проба открыла временное окно сквозь Windows KS
// (openKSProbeWindow), поэтому ложное предупреждение P0-2 «все прочие узлы покажутся нерабочими»
// больше не верно — снимаем его из статуса текущего прогона и эмитим. No-op, если уже пусто.
func (e *Engine) clearKillSwitchProbeWarning() {
	e.checkMu.Lock()
	if e.checkStatus.KillSwitchWarning == "" {
		e.checkMu.Unlock()
		return
	}
	e.checkStatus.KillSwitchWarning = ""
	snap := e.checkStatus
	e.checkMu.Unlock()
	e.emitNodeCheckStatus(snap)
}

// ensureKillSwitchProbeWarning — долг-5, обратная сторона: окно открыть НЕ удалось (WFP-бэкенд без
// ProbeAllower / кандидатов больше потолка / ошибка netsh) — гарантируем, что честное
// предупреждение P0-2 показано. Актуальный текст и само условие (windows+connected+KS) берём тем
// же детектором, что и на старте (computeKillSwitchProbeWarning) — если KS уже сняли/отключились
// посреди прогона, он вернёт "" и предупреждение не всплывёт зря. No-op, если уже совпадает.
func (e *Engine) ensureKillSwitchProbeWarning() {
	want := e.computeKillSwitchProbeWarning()
	if want == "" {
		return
	}
	e.checkMu.Lock()
	if e.checkStatus.KillSwitchWarning == want {
		e.checkMu.Unlock()
		return
	}
	e.checkStatus.KillSwitchWarning = want
	snap := e.checkStatus
	e.checkMu.Unlock()
	e.emitNodeCheckStatus(snap)
}

// finishNodeCheck переводит прогон в терминальную фазу, снимает running и освобождает cancel.
func (e *Engine) finishNodeCheck(phase string) {
	e.checkMu.Lock()
	if e.checkCancel != nil {
		e.checkCancel()
		e.checkCancel = nil
	}
	e.checkRunning = false
	e.checkStatus.Running = false
	e.checkStatus.Phase = phase
	snap := e.checkStatus
	e.checkMu.Unlock()
	e.emitNodeCheckStatus(snap)
}

func (e *Engine) emitNodeCheckStatus(snap NodeCheckStatusSnapshot) {
	if cb := e.OnNodeCheckBatch; cb != nil {
		cb(snap)
	}
}

// probeSlotPorts — детерминированный распределитель портов проб-слотов. Каждый слот занимает ТРИ
// порта (socks, +1 http, +2 clash — config_builder.go), поэтому шаг между слотами = 3 (C5/O4). Весь
// блок слотов сдвигается целиком, если он накрыл бы окно рабочего инстанса cfg.ListenPort±2.
func probeSlotPorts(base, listenPort, numSlots int) []int {
	if numSlots <= 0 {
		return nil
	}
	if base < 1024 || base > 60000 {
		base = probePortBase
	}
	// Блок слота i: [base+3i, base+3i+2]; весь блок: [base, base+numSlots*3-1].
	overlaps := func(b int) bool {
		lo, hi := b, b+numSlots*3-1
		return lo <= listenPort+2 && listenPort-2 <= hi
	}
	if overlaps(base) {
		if up := listenPort + 3; up+numSlots*3-1 <= 60000 {
			base = up // сразу за окном рабочего инстанса
		} else if down := listenPort - 2 - numSlots*3; down >= 1024 {
			base = down // весь блок ниже окна
		} else {
			base = 1024
		}
	}
	ports := make([]int, numSlots)
	for i := range ports {
		ports[i] = base + i*3
	}
	return ports
}
