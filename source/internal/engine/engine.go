// Package engine — главный оркестратор APF v1.0.7.
// Интегрирует: BlockageDetector, TunnelFSM, SafetyFilter, HTTPHealthCheck.
// Фаза 5: LeakGuard (IPv6/DNS/WebRTC), Crypto (AES-256-GCM), Emergency Wipe.
// Фаза 6: DPI обход (Canary, TrafficPadding, MultiHop, CDN Fronting, ShadowTLS).
// Фаза 7: FallbackOrchestrator (Tor/Snowflake/Psiphon), Watchdog HTTP-монитор.
// Sprint S2: Catalog framework (провайдеры узлов).
// Sprint S4: AdBlock DNS (блокировка рекламы).
// Sprint S6: Anti-VPN-Block (residential IP для стриминговых сервисов и банков).
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/adblock"
	"github.com/apf/adaptive-pathfinder/internal/bypass"
	"github.com/apf/adaptive-pathfinder/internal/catalog"
	"github.com/apf/adaptive-pathfinder/internal/checker"
	"github.com/apf/adaptive-pathfinder/internal/config"
	apfcrypto "github.com/apf/adaptive-pathfinder/internal/crypto"
	"github.com/apf/adaptive-pathfinder/internal/detector"
	"github.com/apf/adaptive-pathfinder/internal/dpi"
	"github.com/apf/adaptive-pathfinder/internal/emergency"
	"github.com/apf/adaptive-pathfinder/internal/fallback"
	"github.com/apf/adaptive-pathfinder/internal/harvester"
	"github.com/apf/adaptive-pathfinder/internal/hostguard"
	"github.com/apf/adaptive-pathfinder/internal/iprep"
	"github.com/apf/adaptive-pathfinder/internal/killswitch"
	"github.com/apf/adaptive-pathfinder/internal/leakguard"
	"github.com/apf/adaptive-pathfinder/internal/logsink"
	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/netutil"
	"github.com/apf/adaptive-pathfinder/internal/parser"
	"github.com/apf/adaptive-pathfinder/internal/relay"
	"github.com/apf/adaptive-pathfinder/internal/residential"
	"github.com/apf/adaptive-pathfinder/internal/session"
	"github.com/apf/adaptive-pathfinder/internal/singbox"
	"github.com/apf/adaptive-pathfinder/internal/sources"
	"github.com/apf/adaptive-pathfinder/internal/statemachine"
	"github.com/apf/adaptive-pathfinder/internal/sysproxy"
	"github.com/apf/adaptive-pathfinder/internal/updater"
	"github.com/apf/adaptive-pathfinder/internal/version"
)

// Engine — ядро APF
type Engine struct {
	cfg   *models.AppConfig
	nodes []*models.Node
	mu    sync.RWMutex

	// saveConfig — куда сохранять cfg при изменениях (PatchConfig и т.п.). По умолчанию
	// config.SaveConfig (пишет в ConfigPath() процесса). apf-svc.exe переопределяет её
	// через SetConfigSavePath, когда работает от SYSTEM: собственный ConfigPath() службы
	// указывает на профиль SYSTEM, а не на профиль реального пользователя (см.
	// docs/TZ_CONFIG_RELOAD_AND_KS_SAFETY_v1.0.md, config.FindInteractiveUserConfigPath) —
	// без этой переопределяемой точки PatchConfig молча писал бы изменения настроек
	// туда, где их никто, кроме самой службы, больше не увидит.
	saveConfig func(cfg *models.AppConfig) error

	checker  *checker.Checker
	safety   *checker.SafetyFilter
	proc     singbox.Runner
	dl       *singbox.Downloader
	ks       killswitch.KillSwitch
	builder  *singbox.Builder
	detector *detector.BlockageDetector
	fsm      *statemachine.TunnelFSM

	// ── Фаза 5: Защита устройства ────────────────────────────────────────────
	ipv6Guard   *leakguard.IPv6Guard     // IPv6 Leak Block
	webrtcGuard *leakguard.WebRTCGuard   // WebRTC Guard
	dnsLeakTest *leakguard.DNSLeakTester // DNS Leak Test
	cryptoStore *apfcrypto.Store         // AES-256-GCM шифрование (nil если не настроено)
	wiper       *emergency.Wiper         // Аварийное удаление

	// ── Фаза 6: DPI обход ────────────────────────────────────────────────────
	canary     *dpi.CanaryTester     // Canary-тест (детект VPN провайдером)
	padder     *dpi.TrafficPadder    // Traffic Padding (jitter + padding)
	multiHop   *dpi.MultiHopSelector // Multi-hop выбор цепочки
	cdnFronter *dpi.CDNFronter       // CDN Fronting (Cloudflare)
	shadowTLS  *dpi.ShadowTLSManager // ShadowTLS v3
	lastCanary *dpi.CanaryResult     // последний результат Canary-теста

	// ── Sticky Session ────────────────────────────────────────────────────────
	stickySession *session.StickySessionManager // защита от смены IP при активной сессии

	// ── Фаза 7: Аварийные туннели + Watchdog ──────────────────────────
	emergencyFallback *fallback.FallbackOrchestrator // Tor/Snowflake/Psiphon
	watchdog          *fallback.Watchdog             // HTTP health monitor

	// ── Sprint S2: Catalog + Sprint S4: AdBlock ───────────────────────
	catalogRegistry *catalog.Registry // реестр провайдеров
	catalogFetcher  *catalog.Fetcher  // агрегатор загрузки
	adBlocker       *adblock.Blocker  // DNS блокировщик рекламы

	// ── Sprint S6: Anti-VPN-Block ─────────────────────────────────
	ipRepChecker  *iprep.Checker        // IP Reputation Checker (ip-api + proxycheck)
	resSelector   *residential.Selector // Отбор residential узлов
	bypassManager *bypass.Manager       // Bypass rules (Netflix, Госуслуги...)

	state   *models.ConnectionState
	stateMu sync.RWMutex
	// BUG-06 fix: WaitGroup tracks background goroutines; startMu prevents concurrent Start()
	wg      sync.WaitGroup
	startMu sync.Mutex
	// connMu (найден живым прогоном на Hyper-V стенде, 2026-08-12) сериализует
	// Stop()/Restart() с applySingBoxConfig(): без него ручной /api/connect (go
	// s.eng.ScanAndConnect(), server.go), горутина AutoConnect и Watchdog-triggered
	// emergencySwitch() могли столкнуться на общем e.ctx/e.proc — ни одна из трёх
	// не отслеживается общим e.wg, поэтому e.wg.Wait() в Stop() их не ждал. Итог:
	// applySingBoxConfig() успевал прочитать e.ctx ровно в узком окне между
	// e.cancel() и пересозданием контекста и падал с "context canceled" на
	// подключении, никак не связанном с тем Stop()/Restart(), что его отменил.
	connMu sync.Mutex
	// builderMu (найдено go test -race 2026-09-05, ТЗ v1.3 F2) сериализует настройку Builder
	// и сборку конфига (connectNode/connectChain: SetAdBlockRules/SetBypassDomains/…/Build*),
	// которые идут ДО connMu в applySingBoxConfig. Два одновременных connectNode (двойной клик
	// «Подключить», ConnectOnce во время emergencySwitch) писали в один Builder без защиты —
	// конфиг одного мог собраться с обёртками/байпасом другого. Leaf-мьютекс: внутри него
	// не берётся ни e.mu, ни connMu.
	builderMu sync.Mutex
	// lastRollback хранит данные о последнем аварийном откате подключения.
	lastRollback *RollbackEvent
	// connGen — поколение подключения; инкрементируется при откате/отключении.
	// Защита T-05: асинхронная UAC-горутина не должна включать Kill Switch для
	// уже отменённого подключения (иначе устройство останется заблокированным без туннеля).
	connGen uint64
	// pinnedNodeID — ID узла, закреплённого пользователем (FR-4). "" — не закреплён.
	// Защищён stateMu.
	pinnedNodeID string
	// ТЗ v1.3 F2: pin временно подавлен («Сменить сервер») до этого момента; pinnedStatus —
	// последний известный статус pin для UI (I3). Оба — под stateMu.
	pinSuppressedUntil time.Time
	pinnedStatus       string
	// F2: избранное — leaf-мьютекс, читается из путей выбора без e.mu (см. favoritesFirst).
	favMu   sync.RWMutex
	favRefs []models.NodeRef
	favIDs  map[string]bool
	// ТЗ v1.3 F4: single-flight emergencySwitch (BB-4), ре-арминг после исчерпания fallback
	// (BB-5), признак «системный прокси выставлен нами» для отката (BB-3).
	switching       atomic.Bool
	reArmPending    atomic.Bool
	reArmAttempts   atomic.Int32
	sysProxyApplied atomic.Bool
	// connCycleActive — P0-1 (ТЗ v1.6): single-flight ВСЕГО цикла ScanAndConnect, а не только
	// applySingBoxConfig (тот сериализует connMu). Живой лог <test-phone> 2026-09-14: две
	// ScanAndConnect-цепочки шли внахлёст — первая поднимала favorite и вставала Connected, а
	// вторая, уже прошедшая свой tryPreferredNodesFirst вне connMu, догоняла connMu и делала
	// РЕДУНДАНТНЫЙ реконнект к тому же узлу (ReloadWithFreshTun поверх только что поднятого
	// инстанса). Reload рестартует sing-box на ТОМ ЖЕ фикс-порту 10808 (tun_runner.go:70-78),
	// и т.к. Stop прежнего инстанса не синхронно освобождает порт, новый Start падал
	// "bind: address already in use", инстанс утекал, а probeListenPort потом ВЕЧНО видел НАШ ЖЕ
	// порт как «второй экземпляр APF». Тот же паттерн, что у switching (BB-4), но для полного
	// цикла подбора+подключения. FU-2 (ТЗ надёжности): теперь тот же флаг берёт и emergencySwitch
	// — в СВОЁЙ commit-точке (после всех skip-гейтов, см. там), делая аварийное переключение и
	// ScanAndConnect взаимоисключающими как цельные циклы (раньше они пересекались в окне вне
	// connMu → пинг-понг A↔B). НЕ затрагивает ручной выбор конкретного узла (ConnectByID),
	// ForceSwitchNow (ручной приоритет пользователя, см. комментарий там) и быстрый путь
	// wasRunning→Reload. Порядок вложенности: switching ⊃ connCycleActive ⊃ connMu.
	connCycleActive atomic.Bool

	// harvestActive — single-flight ручного харвеста (L5-ENG, ТЗ v1.4 §5). Ручной запуск
	// «Обновить узлы (харвест)» может тянуться до Budget.Timeout; двойной клик/повторный вызов
	// из UI не должен запускать второй параллельный проход по тем же источникам. HarvestNow
	// берёт флаг CAS-ом и отпускает через defer. Не связан с connCycleActive: харвест не
	// подключается и не переключает узлы — только читает источники и добавляет в пул через
	// mergeFetchedNodes (границу доверия), поэтому может идти параллельно скану/подключению.
	harvestActive atomic.Bool

	// LOT-09, пост-коннект проверка канала двумя пробами. Все три поля — точки подмены ДЛЯ
	// ТЕСТОВ и только для них: в бою остаются нулевыми, и аксессоры (probeSOCKS/probeDirect/
	// probeGOOS) отдают боевые реализации. Приём тот же, что у verifyStateOnApply и
	// sysProxyFailureAborts — под `go test` настоящий SOCKS самого APF не поднят, выход в
	// интернет закрыт netguard, а runtime.GOOS на этой машине никогда не "android", поэтому
	// боевая ветка иначе недостижима и решение нечем закрепить.
	// Пишутся ДО старта проверок и больше не меняются, поэтому гонки нет.
	healthProbeSOCKS  func(ctx context.Context, targetURL string) (checker.HealthInfo, error)
	healthProbeDirect func(ctx context.Context, targetURL string) (checker.HealthInfo, error)
	directProbeGOOS   string
	// ТЗ v1.3 F5.1: дополнительные получатели строк лога (файл, web-буфер) — OnLog остаётся
	// «главным» (UI), sinks получают копию. Срез copy-on-write под logSinksMu.
	logSinksMu sync.RWMutex
	logSinks   []func(string)
	fileSink   *logsink.FileSink
	// ТЗ v1.3 F3: надгробия удалённых пользователем узлов (см. nodes_manage.go).
	tombs tombstoneSet
	// ТЗ v1.3 F4 Stage 1: обход пула с прогрессом (см. sweep.go).
	sweepMu        sync.Mutex
	sweepProgress  ScanProgress
	sweepCancel    context.CancelFunc
	sweepRunning   atomic.Bool
	OnScanProgress func(ScanProgress)

	// recentFailures — узлы, недавно доказанно нерабочие (emergencySwitch их только что
	// покинул), с меткой времени. Найдено 2026-08-13 живым инцидентом: selectBestExcluding
	// исключает только ТЕКУЩИЙ узел, поэтому при повторных подряд отказах (например узел,
	// технически быстрый, но заблокированный конкретным сайтом — см. Яндекс/DNS 409 в тот же
	// вечер) авто-переключение ping-pong'ит между одними и теми же 1-2 лучшими по Score узлами
	// из всего пула "доступных", а не исследует его шире. recentFailures используется ТОЛЬКО
	// в emergencySwitch (реальный сбой, не обычное подключение) — обычный ScanAndConnect и все
	// существующие тесты selectBestExcluding/selectBestForStrategy не затронуты (пустая карта
	// на свежем движке = прежнее поведение).
	recentFailures   map[string]time.Time
	recentFailuresMu sync.Mutex

	// ── C-15 (ТЗ v1.4, FAIL D3): серия ручных «Сменить сервер» ───────────────────────────
	//
	// Живой прогон K8-LIVE D3: семь нажатий подряд не сменили узел ни разу. Причина —
	// ForceSwitchNow исключала ТОЛЬКО текущий узел (selectBestExcluding(cur)): кандидат,
	// у которого post-connect провалился в рамках этого же клика, к следующему клику снова
	// оказывался лучшим по Score, а аварийное переключение тем временем возвращало
	// пользователя на прежний узел. Внешне — «кнопка не работает».
	//
	// forceSwitchTried — узлы, опробованные ручным переключением и НЕ подтвердившиеся
	// реальным трафиком; исключаются из выборки на forceSwitchExcludeTTL (а не на один клик).
	// forceSwitchStreak — сколько попыток подряд не подтвердилось: после
	// forceSwitchMaxAttempts движок честно говорит «другого рабочего узла не нашлось» вместо
	// молчаливого возврата на тот же сервер.
	//
	// Leaf-мьютекс: внутри forceSwitchMu не берётся ни e.mu, ни stateMu — выборка кандидатов
	// делается ДО его захвата (см. forceSwitchPlan).
	forceSwitchMu     sync.Mutex
	forceSwitchTried  map[string]time.Time
	forceSwitchStreak int

	// raceNodes — состав текущей группы «гонки узлов» (см. buildNodeConfig/BuildRace), либо
	// nil, если подключение обычное, одиночным узлом. Нужен Kill Switch: он обязан разрешить
	// адреса ВСЕХ участников, иначе сам же заблокирует кандидатов и выродит группу в один
	// узел (см. killSwitchAddressesFor). Защищён e.mu — пишется в момент сборки конфига,
	// читается при применении Kill Switch.
	raceNodes []*models.Node

	// vcBumpNodeID/vcBumpAt — когда в последний раз увеличивался Node.VerifiedCount и у какого
	// узла (см. refreshNodeVerified и verifiedCountBumpInterval). Отдельно от самого
	// LastVerifiedAt, потому что время подтверждения продлевается КАЖДОЙ успешной проверкой
	// Watchdog (каждые 15 с), а счётчик — нет: по нему одному нельзя было бы понять, давно ли
	// счётчик рос. Защищены e.mu — там же, где мутируются поля узлов.
	vcBumpNodeID string
	vcBumpAt     time.Time

	// reapplyMu/reapplyNode/reapplyChain — пометка «сейчас идёт ПЕРЕПРИМЕНЕНИЕ правил к тому же
	// живому подключению» (reapplyConfigIfConnected: bypass/AdBlock), а не переход на другой
	// узел. Нужна applySingBoxConfig, чтобы не гасить состояние подтверждения канала на
	// исправном туннеле — см. комментарий там же.
	reapplyMu    sync.Mutex
	reapplyNode  *models.Node
	reapplyChain *models.Chain

	// ─── P2.3 (docs/TZ_APF_ROADMAP_v1.2.md): точка входа роли «Выход» на Windows ──────────
	// Независимый жизненный цикл от клиентского Connect/Disconnect — устройство может быть
	// одновременно «Входом» (обычный VPN-клиент, остальной Engine) и «Выходом» (звеном
	// цепочки), см. server_role.go и комментарий там же (зеркалит уже подключённый Android-
	// путь, mobile/androidbridge/server_role.go).
	serverRoleMu       sync.Mutex
	serverRoleRunner   singbox.ServerRunner
	serverRoleListen   int // публичный порт (тот, что в ссылке) — слушает serverRoleAdmission
	serverRoleInternal int // порт, на котором реально слушает sing-box (эфемерный, TZ_APF_RELAY_v1.0.md §10.2)

	// serverRoleAdmission/serverRoleAdmissionCancel — лимит одновременных «Входов»
	// (docs/TZ_APF_RELAY_v1.0.md §10). Публичный порт слушает ОН, не сам sing-box —
	// работает для прямых подключений И для relay-пути одинаково (ExitClient дозванивается
	// сюда же, не в обход, §10.2).
	serverRoleAdmission       *singbox.AdmissionProxy
	serverRoleAdmissionCancel context.CancelFunc

	// serverRoleExit/serverRoleExitCancel — опциональный relay-fallback (докс §1, §2), когда
	// Reachability не подтвердила прямую доступность и e.cfg.RelayServerAddr задан.
	serverRoleExit       *relay.ExitClient
	serverRoleExitCancel context.CancelFunc
	// serverRoleExitAddr/serverRoleExitFingerprint — relay-адрес и отпечаток TLS-сертификата,
	// на которые сейчас реально настроен serverRoleExit (оба "", если relay-fallback не
	// поднят) — TZ_RELAY_HARDENING_2026-08-29.md кластеры A и B: hot-reload сверяет их с
	// e.cfg.RelayServerAddr/RelayServerFingerprint, чтобы понять, нужно ли пересоздавать
	// ExitClient, а не гасить и поднимать заново при КАЖДОМ hot-reload вне зависимости от
	// того, менялось ли хоть что-то из relay-настроек.
	serverRoleExitAddr        string
	serverRoleExitFingerprint string

	// chainBridges — активные EntryBridge стороны «Вход» для relay-режима партнёров цепочки
	// (AddChainPartnerFromLink), по Node.ID партнёра. [консилиум] Обязательный учёт — без
	// него на каждое переподключение того же партнёра утекает listener-горутина/порт
	// (см. AddChainPartnerFromLink: старый bridge останавливается ПЕРЕД тем, как запомнить
	// новый).
	chainBridgeMu sync.Mutex
	chainBridges  map[string]*relay.EntryBridge

	// manualConnectAt — момент последнего ручного выбора узла (ConnectByID). Пока не истёк
	// manualConnectStickyWindow с этого момента, emergencySwitch() не имеет права перебить
	// выбор пользователя. Живой инцидент 2026-08-19: «при выборе узла вручную подключение
	// не происходит» — код ConnectByID корректен, но если новый узел не проходит первый же
	// health-check мгновенно, безусловный Watchdog/emergencySwitch тут же переключал заново,
	// создавая у пользователя впечатление, что ручной выбор вообще не сработал.
	manualConnectAt time.Time
	manualConnectMu sync.Mutex

	// nodesSaveMu/nodesSavedAt/nodesSaveDirty — дебаунс saveNodes для событий обратной связи
	// (ТЗ v1.3 F1.2, см. saveNodesDebounced). Dirty-флаг сбрасывает Stop() (там saveNodes
	// вызывается безусловно).
	nodesSaveMu    sync.Mutex
	nodesSavedAt   time.Time
	nodesSaveDirty bool
	nodesSaveTimer *time.Timer // отложенный сброс «грязного» кэша (см. flushNodesSave)

	// persistMu/lastPersistErr/lastPersistErrAt — C-4 (ТЗ v1.4, A2): последняя ошибка записи
	// пула узлов на диск.
	//
	// ЗАЧЕМ ОТДЕЛЬНОЕ ПОЛЕ. K2-E П11 убрал из saveNodes fail-open: при отказе шифрования файл
	// НЕ пишется вовсе (плайнтекста на диске не появляется) и наружу возвращается ошибка. Но
	// основной путь записи — фоновый и дебаунсенный (saveNodesDebounced/flushNodesSave), у
	// него нет вызывающего, которому можно вернуть error: он вызывается из health-check и
	// вотчдога как побочный эффект. До этой правки такая ошибка жила ровно одну строку лога, и
	// пользователь с неверным мастер-паролем/переполненным диском продолжал добавлять узлы,
	// не зная, что НИ ОДИН из них не переживёт перезапуск.
	//
	// Собственный мьютекс, а не stateMu: пишется из saveNodes, которая сама вызывается изнутри
	// путей, уже держащих e.mu/stateMu (см. порядок локов в шапке файла) — вложение чужого
	// лока сюда создало бы новое ребро в графе блокировок ради одной строки.
	persistMu        sync.RWMutex
	lastPersistErr   string
	lastPersistErrAt time.Time

	// nodeCheckMu — ЕДИНСТВЕННАЯ точка сериализации всех проверок узлов движком (К2-E П1,
	// свод C трек 1 №1; B3 #2 «самая частая гонка», A4).
	//
	// Первопричина. checker.checkOneN/markFail пишут прямо в поля *models.Node (Score,
	// Latency, Jitter, Loss, LastChecked, Status, FailCount, BlacklistedUntil) БЕЗ какой-либо
	// синхронизации — у пакета checker такого контракта нет и не было. Пока проверку вёл один
	// путь, это было безопасно: внутри CheckAll конкурентность идёт по РАЗНЫМ узлам. Но
	// путей четыре, и они пересекаются на ОДНИХ И ТЕХ ЖЕ указателях узлов:
	//   runSweep         (обход всего пула, sweepConcurrency=200)  — sweep.go
	//   runPoolScan      (скан батча кандидатов, CheckAll)
	//   tryCyclicSearch  (круговой перебор пачками, CheckAll)
	//   CheckOne         (предпочтительный узел, AddNode, AddNodeFromLink)
	// Триггер из свода — engine.go:1403: успешная предпочтительная проверка запускает
	// runPoolScan в ФОНЕ и сразу возвращает управление, дальше фоновый скан идёт параллельно
	// и обходу пула, и следующей одиночной проверке. Наблюдаемое следствие — рваные Score и
	// BlacklistedUntil, то есть жалоба «рабочие узлы пропадают».
	//
	// Раньше этот мьютекс назывался addNodeCheckMu и закрывал только две ветки
	// AddNodeFromLink между собой (найдено go test -race 2026-09-02) — частный случай той же
	// гонки. Теперь через него проходят ВСЕ четыре пути (см. checkNodeSerialized /
	// checkNodesSerialized / checkNodesWithSerialized).
	//
	// Гранулярность — ПАЧКА, а не весь обход: лок берётся вокруг одного вызова checker'а и
	// сразу отпускается. Обход пула из тысяч узлов не запирает одиночную проверку на минуты —
	// максимум на одну пачку (батч ограничен таймаутом пробы), а внутренняя конкурентность
	// CheckAll по разным узлам полностью сохраняется.
	nodeCheckMu sync.Mutex

	// cyclicSearchLastID — id последнего узла, испробованного круговым обходом (см.
	// CyclicNodeSearch/selectNextCyclic). Персистентно в рамках жизни движка (не сбрасывается
	// между отдельными вызовами emergencySwitch), поэтому обход реально идёт по кругу через
	// весь пул со временем, а не начинается заново с первого узла на каждый сбой.
	cyclicSearchMu     sync.Mutex
	cyclicSearchLastID string

	// ksElevated — UAC уже подтверждён пользователем в этой сессии.
	// После первого UAC — не показываем повторно при переключении узлов.
	ksElevated bool
	// vpnEndpoint — IP текущего VPN-сервера для allow-правила Kill Switch.
	// Kill Switch должен разрешить соединение к этому IP, иначе туннель не встанет.
	vpnEndpoint string
	// ksIsService — e.ks указывает на клиента привилегированной службы (Вариант A, D-32/D-33):
	// KS-операции идут по named-pipe в apf-svc (SYSTEM) без UAC. false → локальный бэкенд.
	// B-0403 · R-4.2 (C-7): решение больше НЕ одноразовое — переоценивается в currentKS().
	ksIsService bool
	// ksMu защищает ks/ksIsService/ksProbedAt при ленивой переоценке бэкенда (R-4.2).
	ksMu sync.Mutex
	// ksProbedAt — момент последней пробы доступности службы KS (TTL = ksProbeTTL).
	ksProbedAt time.Time
	// ksSelfService — true, ТОЛЬКО когда этот процесс сам является привилегированной службой
	// apf-svc (SYSTEM) и сам обслуживает \\.\pipe\APF-KS (ставится один раз NewServiceHost,
	// далее неизменно). Живой инцидент 2026-08-19 (docs/TZ_WINDOWS_CONSILIUM_FINDINGS_v1.0.md,
	// P0.1): без этого флага currentKS() того же процесса-службы через ksProbeTTL находит
	// СВОЙ ЖЕ пайп доступным и подменяет уже корректно выбранный локальный бэкенд (обычно
	// WFP — SYSTEM это позволяет) на бэкенд пайпа (ksExec из cmd/apf-svc/main.go, по
	// умолчанию netsh) — self-IPC не пересекает границу привилегий (тот же процесс, тот же
	// SYSTEM-токен), только бессмысленно урезает возможности уже выбранного бэкенда до
	// Capabilities{TunMode:false}, из-за чего applyKillSwitch() fail-closed отказывает КАЖДОЙ
	// попытке VPN-подключения. Пока ksSelfService=true — currentKS() никогда не пробует
	// killswitch.NewServiceClient().
	ksSelfService bool

	// B-0403 · R-8: кэш ЕДИНСТВЕННОГО резолва адреса узла входа на попытку подключения.
	endpointMu     sync.Mutex
	endpointFor    string // адрес, для которого получен ответ
	endpointAll    string // все адреса (транспортная форма для Kill Switch)
	endpointPinned string // один адрес для конфигурации sing-box
	// ksExtraResolver — тест-seam: резолвер ДОП-адресов Kill Switch (участники гонки +
	// bypass-домены). В проде nil → resolveKillSwitchExtras идёт через resolveEndpointOnce
	// (killswitch DNS с внутренним таймаутом 5с). Тесты подменяют его, чтобы проверить
	// параллельность/бюджет без реального DNS.
	ksExtraResolver func(addr string) (ip string, err error)
	// ksDeclinedThisSession — пользователь отклонил UAC в ЭТОЙ сессии (R-2.2/C-6).
	// Сессионный флаг вместо записи EnableKillSwitch=false в конфиг: настройку пользователя
	// изменяет только пользователь. Защищён stateMu.
	ksDeclinedThisSession bool
	// allowConnectWithoutKS — разовое разрешение подключиться БЕЗ защиты (escape hatch к
	// fail-closed, D-2/R-2.1). Выставляется только явным действием пользователя и НЕ персистится.
	// Защищён stateMu.
	allowConnectWithoutKS bool

	// Sprint 6: Auto-update
	appUpdater *updater.Updater

	// Sprint 8: Traffic monitoring через sing-box Clash API
	trafficMonitor *singbox.TrafficMonitor

	// Тип блокировки — определяется при старте
	blockageType detector.BlockageType
	strategy     detector.Strategy

	ctx    context.Context
	cancel context.CancelFunc
	// ctxMu (аудит: ~30 нелоченых чтений e.ctx против трёх точек пересоздания в
	// Stop/Restart/ResetNetworkDetailed) защищает ТОЛЬКО саму пару полей ctx/cancel —
	// не путать с connMu, который сериализует ЦЕЛЫЕ операции (попытки подключения
	// против Stop/Restart). Лист-мьютекс: берётся кратко вокруг чтения/записи поля,
	// никогда не удерживается при вызове другого кода — не участвует в deadlock с
	// connMu/e.mu/stateMu. См. currentCtx/cancelCurrentCtx/resetCtx ниже.
	ctxMu sync.RWMutex

	// ── N-1 (ТЗ APF v1.5): проба реального трафика узла (каталог рабочих узлов) ──
	// Полностью изолирована от активного подключения: СВОЙ checkMu (НЕ connMu/e.mu),
	// дочерний ctx от e.ctx, горутины через goTracked (в e.wg). Проба НИКОГДА не трогает
	// e.proc/e.builder/connMu — не мешает активному VPN-подключению (plan notes / §3 N-1).
	checkMu      sync.Mutex
	checkRunning bool
	checkCancel  context.CancelFunc
	checkStatus  NodeCheckStatusSnapshot
	// probeFn — тест-seam, покрывающий ВСЮ проверку одного узла (сборка cfg + подъём инстанса +
	// HTTP GET + гашение). В проде nil → probeNodeReal (боевой путь, дополнительно гейтится
	// !netguard.UnderTest()). Тесты подменяют фейком, не трогающим сеть/процессы/ФС — так под
	// `go test` реальный sing-box не поднимается и egress не идёт (AC-2, C6/O5/O6).
	probeFn nodeProber

	OnStateChange  func(*models.ConnectionState)
	OnNodeUpdated  func(*models.Node)
	OnLog          func(string)
	OnProgress     func(pct int, msg string)
	OnLeakDetected func(leakType string, details string) // Фаза 5: уведомление об утечке
	// OnNodeCheckBatch — коалесцированный прогресс пробы для UI (N-3, wave 2). nil в бэкенде/тестах.
	OnNodeCheckBatch func(NodeCheckStatusSnapshot)
	// OnHarvestProgress — прогресс ручного харвеста источников (L5-ENG, ТЗ v1.4 §5). nil ⇒ не транслируется.
	OnHarvestProgress func(harvester.Progress)
}

// NetworkResetResult — детальный результат восстановления сети.
type NetworkResetResult struct {
	Success    bool     `json:"success"`
	DurationMs int64    `json:"duration_ms"`
	Warnings   []string `json:"warnings"`
	Error      string   `json:"error,omitempty"`
}

// RollbackEvent — информация о последнем rollback при подключении.
type RollbackEvent struct {
	At         time.Time `json:"at"`
	Stage      string    `json:"stage"`
	Reason     string    `json:"reason"`
	WasRunning bool      `json:"was_running"`
}

// New создаёт Engine
func New(cfg *models.AppConfig) *Engine {
	// Живой инцидент 2026-08-13: пользователь сообщил про перманентную потерю интернета
	// на реальной машине (пережила перезагрузки, ни одного процесса APF не найдено) —
	// ровно тот риск, о котором предупреждает комментарий в sysproxy_windows.go:
	// SetHTTPProxy пишет прокси прямо в реестр HKCU и не снимается сам при крахе/
	// принудительном завершении процесса. RecoverStale — самолечение при каждом старте
	// движка, до любого действия пользователя: если прошлая сессия САМА включила
	// системный прокси и не успела его снять (метка, см. internal/sysproxy/marker.go),
	// откатывает его — но только если текущее значение в реестре всё ещё совпадает с
	// тем, что записала метка (пользователь мог сам перенастроить прокси в промежутке —
	// это не наше состояние, не трогаем). No-op на Android/там, где SetHTTPProxy и так
	// no-op.
	sysproxy.RecoverStale()

	ctx, cancel := context.WithCancel(context.Background())
	dataDir := config.DataDir()
	binDir := config.BinDir()

	proc := singbox.NewProcess(binDir, dataDir)
	dl := singbox.NewDownloader(binDir)
	// Вариант A (D-32/D-33): если поднята привилегированная служба APF — KS-операции делегируем ей
	// (без UAC, switch без реэлевации, recovery на службе). Иначе — локальный KS (путь одного UAC).
	// R-4.2 (C-7): это лишь ПЕРВИЧНЫЙ выбор; дальше бэкенд переоценивается в currentKS(), поэтому
	// поздний старт службы подхватывается без рестарта APF, а её крах — без «мёртвого» клиента.
	needTun := cfg.ConnectionMode == models.ModeVPN || cfg.ConnectionMode == models.ModeHybrid
	ks := killswitch.NewLocalBackend(needTun)
	ksIsService := false
	if svc, ok := killswitch.NewServiceClient(); ok {
		ks = svc
		ksIsService = true
	}
	killswitch.SetSentinelDir(dataDir)
	// Sprint 2: TUN mode включается через ConnectionMode
	tunMode := cfg.ConnectionMode == models.ModeVPN || cfg.ConnectionMode == models.ModeHybrid
	builder := singbox.NewBuilder(cfg.ListenPort, tunMode)
	// B-0403 · R-6.2 (C-11): защита от IPv6-утечки означает «v6 идёт В ТУННЕЛЬ». Если пользователь
	// её отключил — возвращаем прежнее поведение (v6 мимо туннеля), но уже осознанно с его стороны.
	builder.SetTunIPv6(cfg.BlockIPv6Leak)
	det := detector.New()
	safety := checker.NewSafetyFilter()

	minUptime := time.Duration(cfg.MinUptimeSec) * time.Second
	if minUptime == 0 {
		minUptime = 120 * time.Second
	}
	fsm := statemachine.New(nil, minUptime)

	// Фаза 5+6: создаём компоненты защиты устройства
	socksAddr := fmt.Sprintf("127.0.0.1:%d", cfg.ListenPort)

	e := &Engine{
		cfg: cfg, checker: checker.New(20, 5),
		safety: safety, proc: proc, dl: dl,
		ks: ks, ksIsService: ksIsService, ksProbedAt: time.Now(), builder: builder,
		detector: det, fsm: fsm,
		// VerifyIdle, а не пустая строка: поле с `omitempty` просто не попало бы в JSON, и
		// новые экраны UI не смогли бы отличить «движок ещё не подключался» от «сборка
		// движка старая и поля вовсе не знает». Verified при этом false — тождество
		// Verified == (VerifyState == VerifyVerified) соблюдено с первой секунды.
		state:      &models.ConnectionState{VerifyState: models.VerifyIdle},
		saveConfig: func(cfg *models.AppConfig) error { return config.SaveConfig(cfg) },
		ctx:        ctx, cancel: cancel,
		recentFailures:   make(map[string]time.Time),
		forceSwitchTried: make(map[string]time.Time),
		favIDs:           make(map[string]bool),

		// Фаза 5
		ipv6Guard:   leakguard.NewIPv6Guard(),
		webrtcGuard: leakguard.NewWebRTCGuard(),
		dnsLeakTest: leakguard.NewDNSLeakTester(socksAddr),
		wiper:       emergency.New(),

		// Фаза 6: DPI обход
		canary:     dpi.NewCanaryTester(socksAddr),
		padder:     dpi.NewTrafficPadder(dpi.DefaultPaddingConfig()),
		multiHop:   dpi.NewMultiHopSelector(),
		cdnFronter: dpi.NewCDNFronter(dpi.DefaultCDNConfig()),
		shadowTLS:  dpi.NewShadowTLSManager(dpi.DefaultShadowTLSConfig()),

		// Sticky Session: защита от смены IP при активных сессиях
		stickySession: session.NewStickySessionManager(session.DefaultSessionConfig()),

		// Фаза 7: аварийные туннели. Сторож собирается ниже, через e.newWatchdog():
		// здесь ещё нет ни e.log, ни предиката активности (дефект D-A25).
		emergencyFallback: fallback.NewFallbackOrchestrator(binDir, dataDir, nil),

		// Sprint S2: Catalog framework
		catalogRegistry: catalog.NewRegistry(),

		// Sprint S4: AdBlock DNS
		adBlocker: adblock.NewBlocker(nil),
	}

	// Сторож — сразу с логом, обработчиками и предикатом активности (дефект D-A25).
	e.watchdog = e.newWatchdog()

	// Пробрасываем логи
	proc.OnLog = e.log
	dl.OnLog = e.log
	dl.OnProgress = func(pct int, msg string) {
		if e.OnProgress != nil {
			e.OnProgress(pct, msg)
		}
	}
	// C-14 (ТЗ v1.4, FAIL C2): проводки fsm.OnLog/OnFallback/OnConnect в ПОЛЬЗОВАТЕЛЬСКИЙ лог
	// здесь БОЛЬШЕ НЕТ, и возвращать её не надо.
	//
	// Автомат жив (HandleSuccess/HandleFailure зовутся из движка, состояние настоящее — см.
	// возражение O-33 консилиума v1.4), но он НЕ выбирает outbound: имена его уровней и
	// «протоколов» — внутренняя лестница эскалации, а не то, чем реально подключается
	// пользователь. В логе телефона это читалось как обещание резерва, которого нет
	// («escalating to level L4-LastResort (proto: tor-snowflake)»), и как подмена протокола,
	// которой не было («switching proto tor-snowflake → direct»). Технический канал у автомата
	// остаётся: TunnelFSM.log пишет через стандартный log.Printf("[FSM] …"), который в
	// пользовательский лог и в его экспорт не попадает.

	// Пробрасываем лог в adBlocker и catalog
	e.adBlocker = adblock.NewBlocker(e.log)
	// P1-6 (аудит 2026-09-01): восстанавливаем белый список из конфигурации. Профиль AdBlock
	// применяется отдельно (SetAdBlockProfile при старте), а исключения к нему до этого
	// нигде не восстанавливались — см. models.AppConfig.AdBlockAllowlist.
	if len(cfg.AdBlockAllowlist) > 0 {
		e.adBlocker.SetAllowlist(cfg.AdBlockAllowlist)
	}
	e.catalogFetcher = catalog.NewFetcher(e.catalogRegistry)

	// Sprint S6: инициализация Anti-VPN-Block компонентов
	e.ipRepChecker = iprep.NewChecker(e.log)
	if cfg.AntiBlockAPIKey != "" {
		e.ipRepChecker.SetAPIKey(cfg.AntiBlockAPIKey)
	}
	e.resSelector = residential.NewSelector(e.ipRepChecker, e.log)
	e.bypassManager = bypass.NewManager(config.DataDir())

	// Sprint 6: Auto-update
	e.appUpdater = updater.New(version.Version)
	e.appUpdater.OnLog = e.log
	e.appUpdater.OnUpdateAvailable = func(status *updater.UpdateStatus) {
		e.log(fmt.Sprintf("🆕 Доступно обновление APF v%s → v%s",
			status.CurrentVersion, status.LatestVersion))
	}

	// Sprint 8: Traffic monitor (clashAPIPort = socksPort+2)
	e.trafficMonitor = singbox.NewTrafficMonitor(cfg.ListenPort + 2)
	e.wireTrafficMonitorStats()

	return e
}

// wireTrafficMonitorStats подключает StickySessionManager к уже существующему опросу
// Clash API (TrafficMonitor.poll, каждые 2с, пока движок подключён) — см. комментарий у
// session.SyncFromTraffic про то, почему это единственный практический источник
// активности для трафика, идущего через libbox/TUN в обход Go net.Conn. Вызывается и из
// конструктора, и из PatchConfig (там trafficMonitor пересоздаётся при смене порта —
// колбэк нужно навешивать заново на новый экземпляр).
func (e *Engine) wireTrafficMonitorStats() {
	if e.trafficMonitor == nil || e.stickySession == nil {
		return
	}
	e.trafficMonitor.OnStats = func(st singbox.TrafficStats) {
		e.stickySession.SyncFromTraffic(st.Conns, st.UpSpeed > 0 || st.DownSpeed > 0)
	}
}

// NewServiceHost создаёт Engine для процесса, который САМ является привилегированной службой
// apf-svc (SYSTEM) и сам обслуживает \\.\pipe\APF-KS (killswitch.ServePipe в cmd/apf-svc/main.go).
// В отличие от New(), гарантированно использует только локальный KS-бэкенд — currentKS() этого
// движка никогда не дозванивается до своего же пайпа (см. комментарий у поля ksSelfService).
// Владельцы пайпа-НЕ-владельцы движка (GUI/трей/CLI без прав) по-прежнему создаются через New()
// и легитимно ходят в пайп через currentKS() как раньше.
func NewServiceHost(cfg *models.AppConfig) *Engine {
	e := New(cfg)
	e.ksSelfService = true
	e.ksMu.Lock()
	e.ks, e.ksIsService = killswitch.NewLocalBackend(e.ksNeedsTunMode()), false
	e.ksProbedAt = time.Now()
	e.ksMu.Unlock()
	return e
}

// SetConfigSavePath переопределяет, куда PatchConfig/SaveConfig-подобные операции
// пишут изменённый cfg — по умолчанию используется config.SaveConfig (ConfigPath()
// текущего процесса). Нужна процессам, чей ConfigPath() не совпадает с профилем
// реального пользователя (Windows-служба apf-svc.exe под LocalSystem, см.
// docs/TZ_CONFIG_RELOAD_AND_KS_SAFETY_v1.0.md, config.FindInteractiveUserConfigPath) —
// без переопределения PatchConfig молча писал бы изменения настроек в профиль SYSTEM,
// где их не увидит ни пользователь, ни следующий перезапуск GUI/трея/CLI.
func (e *Engine) SetConfigSavePath(path string) {
	e.saveConfig = func(cfg *models.AppConfig) error {
		return config.SaveConfigTo(path, cfg)
	}
}

// SetRunner подменяет запускатель sing-box (этап Э-4, Ш-3).
//
// Вход:      альтернативная реализация singbox.Runner — например, singbox-в-процессе для
// Android VPN-режима вместо singbox.Process (внешний процесс, действует по умолчанию).
// Тело:      прямая замена поля.
// Выход:     нет.
// Fail-safe: не проверяет, идёт ли сейчас подключение — вызывающая сторона обязана
// вызывать SetRunner ДО первого Start()/ScanAndConnect() в сеансе, не во время него.
// Обычный путь sing-box отдельным процессом (десктоп, Android proxy-режим) SetRunner
// вообще не вызывает — e.mu здесь не по требованию гонок, а ради единообразия с
// остальными сеттерами конфигурации движка.
// Инвариант: остальной engine.go (подбор узла, watchdog, аварийное переключение) не
// различает, какая реализация Runner активна — весь код продолжает звать
// Start/Stop/WriteConfig/Reload/IsRunning как прежде.
func (e *Engine) SetRunner(r singbox.Runner) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.proc = r
}

// SetTunMode переключает построение tun-inbound в конфигурациях, которые движок будет
// строить дальше (этап Э-4, Ш-3). Тот же caveat, что у SetRunner: вызывать до
// Start()/ScanAndConnect() текущего сеанса, не во время него.
func (e *Engine) SetTunMode(enabled bool, mtu int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.builder.SetTunMode(enabled)
	e.builder.SetTunMTU(mtu)
}

// SetMasterPassword устанавливает мастер-пароль для шифрования хранилища.
// Фаза 5: после установки nodes_cache.json будет зашифрован AES-256-GCM.
// Если password == "" — шифрование отключается.
func (e *Engine) SetMasterPassword(password string) {
	if password == "" {
		e.cryptoStore = nil
		e.log("Crypto: encryption disabled")
		return
	}
	e.cryptoStore = apfcrypto.New(password)
	e.log("Crypto: AES-256-GCM encryption enabled")
}

// ─── Жизненный цикл ──────────────────────────────────────────────────────────

// Start запускает оркестратор
func (e *Engine) Start() error {
	// BUG-06 fix: prevent concurrent Start() calls
	e.startMu.Lock()
	defer e.startMu.Unlock()
	config.EnsureDirs()
	e.openFileLog() // ТЗ v1.3 F5.1: до первой строки, чтобы старт тоже попал в файл
	e.log("APF Engine " + version.Label() + " starting...")

	// P0-4 fix: при старте всегда чистим мусор от предыдущих запусков.
	// Если приложение крашнулось — могли остаться правила Kill Switch APF.
	// При старте: если прошлая сессия завершилась аварийно с активным Kill Switch
	// (kill/BSOD/питание) — выполняем полный откат сети (ResetAll, включая DNS).
	if killswitch.RecoverIfNeeded() {
		e.log("Kill Switch: обнаружен аварийный выход прошлой сессии — выполнен полный сброс сети")
	}
	// killswitch.QuickReset() безопасен: не трогает WiFi, не обрывает соединения.
	// R-4.1: через e.ksReset() — тем же маршрутом, что и применение (служба/локальный бэкенд).
	e.ksReset()
	e.log("Startup: cleaned up any leftover APF firewall rules")

	// Живой прогон 2026-09-22 (Android): Restart() зовёт Start() ВТОРОЙ раз в рамках уже
	// живого процесса — на Android так устроен ЛЮБОЙ Disconnect в VPN-режиме (StopTun →
	// restartEngine → Restart() → Start(), см. комментарий у Restart()), на Windows-службе
	// так же устроен svc.Continue после Pause. e.nodes к этому моменту уже полон: между
	// прошлым Start() и этим вызовом его никто не опустошал. Безусловный loadNodes() затирал
	// e.nodes отфильтрованным ДЛЯ ДИСКА подмножеством (см. N-5 у saveNodesToDisk — файл
	// осознанно держит только избранное/закреплённое/недавнее, полный пул живёт только в
	// памяти) — на телефоне пул на глазах проседал с 4042 узлов до 17 сразу после «Отключить»,
	// хотя PID процесса не менялся ни разу (не рестарт процесса, а именно эта перезагрузка
	// внутри Start()). loadNodes() нужен ТОЛЬКО на настоящем холодном старте, когда e.nodes
	// ещё пуст — на тёплом перезапуске в памяти уже есть более полная и свежая картина пула,
	// чем на диске, и её нельзя перезаписывать.
	e.mu.RLock()
	coldStart := len(e.nodes) == 0
	e.mu.RUnlock()
	if coldStart {
		if err := e.loadNodes(); err != nil {
			e.log(fmt.Sprintf("No saved nodes: %v", err))
		}
		e.log(fmt.Sprintf("Loaded %d nodes from cache", len(e.nodes)))
	} else {
		e.log(fmt.Sprintf("Warm restart: keeping %d nodes already in memory", len(e.nodes)))
	}
	e.loadTombstones() // ТЗ v1.3 F3: до первого updateSources
	// ТЗ v1.3 F2 I2: закрепление/избранное из config.json — после загрузки пула, чтобы
	// переразрешить ссылки по адресу, если ID узлов изменились (миграция схемы в loadNodes).
	e.restorePinAndFavorites()
	e.maybeAutoSweep() // ТЗ v1.3 F4 Stage 1: фоновый обход пула в простое

	// Загружаем настройки DPI из персистентного конфига
	e.applyDPIFromConfig()

	// Загружаем AdBlock профиль если включён
	if e.cfg.AdBlockProfile != "" && e.cfg.AdBlockProfile != "disabled" {
		e.log(fmt.Sprintf("AdBlock: loading profile '%s' from config...", e.cfg.AdBlockProfile))
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			if err := e.adBlocker.SetProfile(ctx, adblock.Profile(e.cfg.AdBlockProfile)); err != nil {
				e.log(fmt.Sprintf("AdBlock: init error: %v", err))
			}
		}()
	}

	// Пробрасываем лог в Watchdog и аварийные туннели
	e.watchdog = e.newWatchdog()
	e.emergencyFallback = fallback.NewFallbackOrchestrator(
		config.BinDir(), config.DataDir(), e.log,
	)

	// BUG-06 fix: track goroutines so Stop() can wait for clean shutdown
	e.wg.Add(3)
	go func() { defer e.wg.Done(); e.ensureSingBox() }()
	go func() { defer e.wg.Done(); e.monitorLoop() }()
	go func() { defer e.wg.Done(); e.sourceUpdateLoop() }()

	// Sprint 6: регистрируем платные провайдеры из конфига
	e.registerPaidProviders()

	// Sprint 6: запускаем фоновую проверку обновлений
	if e.appUpdater != nil {
		e.appUpdater.StartAutoCheck(e.currentCtx())
	}

	// Фаза 7: запускаем Watchdog в фоне
	if e.watchdog != nil {
		e.wg.Add(1)
		go func() { defer e.wg.Done(); e.watchdog.Run(e.currentCtx()) }()
	}

	// Фаза 5: включаем защиту устройства при старте
	e.wg.Add(1)
	go func() { defer e.wg.Done(); e.enableDeviceProtection() }()

	if e.cfg.AutoConnect {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			time.Sleep(2 * time.Second)
			// Диагностика блокировки перед подключением
			e.log("Diagnosing network blockage type...")
			bt, strategy, report := e.detector.DiagnoseAndRecommend(e.currentCtx())
			e.stateMu.Lock()
			e.blockageType = bt
			e.strategy = strategy
			e.stateMu.Unlock()
			e.log(fmt.Sprintf("Blockage: %s | %s", bt, report))

			e.applyStrategy(strategy)

			if err := e.ScanAndConnect(); err != nil {
				e.log(fmt.Sprintf("Auto-connect failed: %v", err))
			}
		}()
	}
	return nil
}

// enableDeviceProtection включает защиту устройства (Фаза 5).
// vpn-specialist: IPv6 блокируем до подключения VPN, чтобы не было окна утечки.
func (e *Engine) enableDeviceProtection() {
	// IPv6 Leak Block
	if e.cfg.BlockIPv6Leak {
		if err := e.ipv6Guard.Enable("apf0"); err != nil {
			e.log(fmt.Sprintf("IPv6 Guard warning: %v", err))
		} else {
			e.log("IPv6 Leak Block: enabled")
		}
	}

	// WebRTC Guard
	if e.cfg.BlockWebRTC {
		if err := e.webrtcGuard.Enable(); err != nil {
			e.log(fmt.Sprintf("WebRTC Guard warning: %v", err))
		} else {
			e.log("WebRTC Guard: включён (частично — применяйте браузерные инструкции, см. /api/leakguard/browser-instructions)")
		}
	}

	// DNS Leak Quick Check перед подключением
	leaking, serverIP := e.dnsLeakTest.QuickCheck(context.Background())
	if leaking {
		e.log(fmt.Sprintf("⚠️ DNS Leak detected before VPN: server=%s", serverIP))
		if e.OnLeakDetected != nil {
			e.OnLeakDetected("dns_pre_vpn", fmt.Sprintf("DNS сервер %s виден до VPN", serverIP))
		}
	}
}

// currentCtx — гонка-безопасное чтение e.ctx (см. ctxMu у поля). Возвращает снимок на
// момент вызова — тот же контракт, что был у прямого e.ctx: вызывающий код либо
// использует его немедленно, либо порождает производный через context.With*, никогда не
// перечитывает поле повторно в расчёте на «свежее» значение.
func (e *Engine) currentCtx() context.Context {
	e.ctxMu.RLock()
	defer e.ctxMu.RUnlock()
	return e.ctx
}

// cancelCurrentCtx — гонка-безопасный вызов e.cancel(). Сам cancel() выполняется ВНЕ
// лока (функция снята под RLock, вызвана после RUnlock) — cancel() закрывает Done()-канал
// у потенциально многих производных контекстов, держать ctxMu на это время незачем.
func (e *Engine) cancelCurrentCtx() {
	e.ctxMu.RLock()
	cancel := e.cancel
	e.ctxMu.RUnlock()
	if cancel != nil {
		cancel()
	}
}

// resetCtx — гонка-безопасное пересоздание ctx/cancel. Единственные три вызывающих
// (Stop/Restart/ResetNetworkDetailed) уже держат connMu в этот момент — ctxMu вложен
// ВНУТРИ connMu, тот же порядок, что уже устоялся в файле (см. Restart(): e.mu внутри
// connMu).
func (e *Engine) resetCtx() {
	e.ctxMu.Lock()
	e.ctx, e.cancel = context.WithCancel(context.Background())
	e.ctxMu.Unlock()
}

// Stop останавливает всё
func (e *Engine) Stop() {
	e.log("Stopping...")
	e.cancelCurrentCtx() // не под connMu — должен прервать попытку подключения немедленно, а не ждать её
	// BUG-06 fix: ждём фоновые горутины, но не бесконечно — см. комментарий у wgWaitTimeout
	// (живой инцидент 2026-08-25: зависшая goTracked-горутина держала процесс неубиваемым).
	if !waitGroupWithTimeout(&e.wg, wgWaitTimeout) {
		e.log(fmt.Sprintf("Stop(): не все фоновые задачи завершились за %v — продолжаю закрытие без них", wgWaitTimeout))
	}

	// connMu: ОБЯЗАТЕЛЬНО после wg.Wait(), не до. emergencySwitch() (Watchdog) сам
	// зовёт applySingBoxConfig() → connMu.Lock() и отслеживается тем же e.wg (через
	// goTracked) — если взять connMu здесь раньше wg.Wait(), Stop() будет ждать
	// завершения этой горутины в wg.Wait(), а та горутина будет ждать connMu,
	// который держит Stop() — гарантированный deadlock (поймано go test). После
	// wg.Wait() ВСЕ e.wg-отслеживаемые попытки подключения уже точно освободили
	// connMu на выходе (см. applySingBoxConfig) — здесь мы дожидаемся только
	// НЕотслеживаемых (ручной /api/connect: `go s.eng.ScanAndConnect()` в
	// server.go не входит в e.wg), прежде чем пересоздавать контекст ниже.
	e.connMu.Lock()
	defer e.connMu.Unlock()

	// BUG-Win-TUN-3 (найден живым прогоном на Hyper-V стенде, 2026-08-12): Stop() отменял
	// e.ctx и НИКОГДА не пересоздавал его — тем же паттерном, что и BUG-06 (см. Restart()
	// ниже), только для другого вызывающего пути. /api/disconnect зовёт Stop() напрямую
	// (не Restart()+Start(), которые пересоздают контекст, но и автоматически
	// переподключаются — не то, что нужно для «Отключить»), поэтому ЛЮБОЙ следующий
	// /api/connect (ScanAndConnect → connectNode → applySingBoxConfig → e.proc.Start(e.ctx))
	// подставлял уже мёртвый контекст — sing-box падал на самом старте с "context canceled"
	// НАВСЕГДА, до перезапуска процесса. Пересоздаём контекст здесь же, без вызова Start(),
	// чтобы Disconnect оставлял движок в honestly-idle, но подключаемом состоянии.
	e.resetCtx()

	// Фаза 5: снимаем защиту устройства
	if e.ipv6Guard.IsEnabled() {
		e.ipv6Guard.Disable()
	}
	if e.webrtcGuard.IsEnabled() {
		e.webrtcGuard.Disable()
	}

	if e.cfg.EnableKillSwitch {
		_ = e.ksDisable() // R-4.1: единый маршрут KS-операций
	}
	e.ksReset() // R-4.1: единый маршрут KS-операций
	e.proc.Stop()
	e.saveNodes()
	e.setDisconnected()
	e.fsm.Reset()
	e.FlushLog() // ТЗ v1.3 F5.1: хвост лога — на диск до выхода процесса

	// P1-4: снимаем системный прокси при отключении.
	//
	// СИНХРОННО, а не в отсоединённой горутине (находка аудита 2026-09-01, security #8).
	// Раньше здесь стояло `go func(){...}()`: gui.shutdown() зовёт Stop(), затем закрывает
	// lock и хоткей, затем Wails завершает процесс — горутину никто не дожидался. Между её
	// стартом и записью в реестр стоят svc.IsWindowsService, WTSGetActiveConsoleSessionId,
	// WTSQueryUserToken, GetTokenUser, RegOpenKeyEx; на нагруженной машине процесс успевал
	// умереть раньше. Итог: ШТАТНОЕ закрытие приложения оставляло в HKCU прокси на мёртвый
	// порт — то же состояние, что после краха (инцидент 2026-08-13). Операция занимает
	// единицы миллисекунд, ждать её дешевле, чем чинить потерянный интернет.
	if err := e.disableSystemProxy(); err != nil {
		e.log(fmt.Sprintf("SysProxy disable warning: %v", err))
	}

	// P0-4: сбрасываем флаг elevated — при следующем Start() нужен новый UAC
	// (на случай если пользователь перезапускает приложение)
	e.setKSElevated(false)
}

// Restart полностью перезапускает движок без потери конфигурации.
// Исправляет BUG-06: после Stop() контекст отменён и повторный Start() не работает.
// После Stop() → Restart() → новый контекст → новый Start().
func (e *Engine) Restart() error {
	e.log("Engine restart initiated...")

	// Останавливаем текущую сессию
	e.cancelCurrentCtx() // не под connMu — должен прервать попытку подключения немедленно
	// BUG-06 fix: ждём горутины перед пересозданием контекста, но не бесконечно —
	// см. комментарий у wgWaitTimeout (тот же живой инцидент 2026-08-25, что и в Stop()).
	if !waitGroupWithTimeout(&e.wg, wgWaitTimeout) {
		e.log(fmt.Sprintf("Restart(): не все фоновые задачи завершились за %v — продолжаю без них", wgWaitTimeout))
	}

	// connMu: ОБЯЗАТЕЛЬНО после wg.Wait() — та же причина, что в Stop() (см. её
	// комментарий и комментарий у поля connMu): emergencySwitch()/AutoConnect
	// отслеживаются через e.wg и сами берут connMu внутри applySingBoxConfig();
	// взять connMu раньше wg.Wait() — гарантированный deadlock. Start() в конце
	// этой функции лишь запускает горутины и не блокируется на connMu сам — если
	// он тут же запустит AutoConnect, та горутина корректно подождёт наш Unlock.
	e.connMu.Lock()
	defer e.connMu.Unlock()
	if e.proc.IsRunning() {
		e.proc.Stop()
		// Ждём освобождения портов sing-box
	}

	// Снимаем все сетевые изменения APF
	if e.cfg.EnableKillSwitch {
		_ = e.ksDisable() // R-4.1: единый маршрут KS-операций
	}
	e.ksReset() // R-4.1: единый маршрут KS-операций
	e.disableSystemProxy()

	// Restart() — единственный путь Android между VPN- и proxy-сессиями (StopTun/
	// Disconnect в mobile/androidbridge оба идут через него, см. restartEngine в
	// bridge.go); на десктопе не вызывается вовсе (переключение режима идёт через
	// PatchConfig, который сам синхронизирует builder.SetTunMode). Без сброса тут
	// builder.tunMode оставался true после VPN-сессии: следующий обычный Connect()
	// в режиме "прокси" (Android startProxy(), без какого-либо fd) всё равно строил
	// tun-inbound и падал на "query tun name: ... bad file descriptor" — живой баг,
	// найден QA на телефоне 2026-08-20. StartTun/StartTunToNode сами включают режим
	// явным SetTunMode(true, mtu) СРАЗУ после Restart() (см. prepareTun в tun.go),
	// так что безусловный сброс здесь не мешает следующей VPN-сессии. Короткий e.mu
	// нужен только на сами два поля builder'а (та же дисциплина, что у публичного
	// Engine.SetTunMode) — Restart() уже держит connMu, а вложенный короткий e.mu
	// внутри connMu — обычный для этого файла порядок (см. selectBestForStrategy).
	e.mu.Lock()
	e.builder.SetTunMode(false)
	e.builder.SetTunMTU(0)
	e.mu.Unlock()

	// Создаём новый контекст для следующей сессии
	e.resetCtx()

	// Сбрасываем состояние
	e.fsm.Reset()
	e.setDisconnected()
	e.setKSElevated(false)
	e.vpnEndpoint = ""

	// Пересоздаём watchdog с новым контекстом
	e.watchdog = e.newWatchdog()

	e.log("Engine restarted, starting fresh session...")
	return e.Start()
}

// disableSystemProxy снимает системный прокси (Sprint 2, P1-4).
// proxy-specialist: при отключении APF браузер не должен пытаться
// подключиться к несуществующему прокси APF.
func (e *Engine) disableSystemProxy() error {
	e.sysProxyApplied.Store(false)
	if !e.cfg.SetSystemProxy {
		return nil
	}
	return sysproxy.Disable()
}

// enableSystemProxy устанавливает системный HTTP прокси (Sprint 2, P1-4).
// Вызывается после успешного подключения в Proxy/Hybrid режиме.
//
// Возвращает error (P0.2, Слой 3, docs/TZ_WINDOWS_CONSILIUM_FINDINGS_v1.0.md) — раньше ошибка
// записи только логировалась, и вызывающий код продолжал считать сессию рабочей. После фикса
// targetHive() (internal/sysproxy) запись под службой без активной консольной сессии пользователя
// теперь честно возвращает ошибку вместо тихой записи в чужой куст реестра — и эта ошибка
// обязана дойти до вызывающего: если Kill Switch включён без TUN-режима, он уже разрешил трафик
// ТОЛЬКО к текущему узлу в расчёте на то, что системный прокси направит туда обычные приложения
// (см. applyKillSwitch, engine.go:1518-1523) — без реальной записи в реестр Kill Switch душит
// весь трафик системы, а UI показывает «Подключено».
func (e *Engine) enableSystemProxy() error {
	if !e.cfg.SetSystemProxy {
		return nil
	}
	httpPort := e.cfg.ListenPort + 1 // HTTP proxy на socksPort+1
	if err := sysproxy.SetHTTPProxy("127.0.0.1", httpPort); err != nil {
		e.log(fmt.Sprintf("SysProxy: warning: %v", err))
		return err
	}
	e.sysProxyApplied.Store(true)
	e.log(fmt.Sprintf("SysProxy: HTTP proxy set → 127.0.0.1:%d", httpPort))
	return nil
}

// ResetNetwork — полный откат сетевых изменений
func (e *Engine) ResetNetwork() error {
	res := e.ResetNetworkDetailed()
	if !res.Success {
		if res.Error != "" {
			// errors.New, а не fmt.Errorf: res.Error — это данные, а не строка формата.
			// Знак «%» внутри сообщения (например «сброшено 50%») превратил бы текст
			// в «%!s(MISSING)» и скрыл настоящую причину отказа сетевого отката.
			return errors.New(res.Error)
		}
		return errors.New("network reset failed")
	}
	return nil
}

// ResetNetworkDetailed выполняет полный сетевой откат и возвращает подробный статус.
func (e *Engine) ResetNetworkDetailed() *NetworkResetResult {
	started := time.Now()
	result := &NetworkResetResult{}

	e.log("Full network reset...")
	e.cancelCurrentCtx()

	// Фаза 5: снимаем все защиты
	if err := e.ipv6Guard.Disable(); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("ipv6 guard disable: %v", err))
	}
	if err := e.webrtcGuard.Disable(); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("webrtc guard disable: %v", err))
	}

	if e.cfg.EnableKillSwitch {
		if err := e.ksDisable(); err != nil { // R-4.1: единый маршрут KS-операций
			result.Warnings = append(result.Warnings, fmt.Sprintf("kill switch disable: %v", err))
		}
	}
	e.proc.Stop()

	// P0-5 (аудит 2026-09-01): системный прокси СНИМАЕТСЯ ЗДЕСЬ.
	// Раньше «Восстановить сеть» его не трогала — а это самая частая причина, по которой
	// пользователь эту кнопку и нажимает («после APF пропал интернет» = в HKCU остался
	// прокси на мёртвый порт, инцидент 2026-08-13). Кнопка спасения не чинила основной
	// сценарий, ради которого существует.
	if err := e.disableSystemProxy(); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("system proxy disable: %v", err))
	}

	err := e.ksResetAll() // R-4.1: через выбранный бэкенд (служба выполнит своими правами)
	if err != nil {
		e.log(fmt.Sprintf("Reset warning: %v", err))
		result.Error = err.Error()
	}
	e.setDisconnected()

	// P0-7 (аудит 2026-09-01): пересоздаём контекст — тот же дефект BUG-Win-TUN-3, который
	// уже чинили в Stop(), но во втором входе он остался. Без этого после нажатия
	// «Восстановить сеть» goTracked() молча переставал запускать что-либо (ForceRescan,
	// ConnectByID, ForceSwitchNow, emergencySwitch), а e.proc.Start(e.ctx) падал с
	// "context canceled" — движок оставался мёртвым до перезапуска процесса, без единой
	// ошибки в UI. connMu держим по тому же соображению, что и в Stop().
	e.connMu.Lock()
	e.resetCtx()
	e.connMu.Unlock()

	e.log("Network reset complete.")
	result.DurationMs = time.Since(started).Milliseconds()
	result.Success = err == nil
	if result.Success && len(result.Warnings) > 0 {
		e.log(fmt.Sprintf("Network reset completed with warnings: %d", len(result.Warnings)))
	}
	return result
}

// EmergencyWipe — аварийное удаление данных APF (Фаза 5).
// Вызывается по горячей клавише или кнопке в UI.
// wipeAll=true — удалить и sing-box бинарник.
func (e *Engine) EmergencyWipe(wipeAll bool) *emergency.WipeResult {
	e.log("⚠️ EMERGENCY WIPE INITIATED")

	// Сначала останавливаем всё
	e.cancelCurrentCtx()
	e.proc.Stop()
	_ = e.ksDisable() // R-4.1: единый маршрут KS-операций
	e.ipv6Guard.Disable()
	e.webrtcGuard.Disable()
	e.ksReset() // R-4.1: единый маршрут KS-операций

	// P0-5 (аудит 2026-09-01): системный прокси снимается ДО стирания — обязательно в этом
	// порядке. Wipe() удаляет весь DataDir, включая sysproxy_active.marker — единственный
	// признак, по которому sysproxy.RecoverStale() при следующем запуске понимает, что прокси
	// остался от APF, и чинит его. Раньше EmergencyWipe не снимал прокси и при этом уничтожал
	// маркер: пользователь оставался без интернета НАВСЕГДА, причём именно штатная аварийная
	// функция приводила к состоянию инцидента 2026-08-13.
	if err := e.disableSystemProxy(); err != nil {
		e.log(fmt.Sprintf("Wipe: не удалось снять системный прокси: %v", err))
	}

	return e.wiper.Wipe(config.DataDir(), config.BinDir(), emergency.WipeOptions{
		WipeSelf:    wipeAll,
		WipeSingBox: wipeAll,
		ShredPasses: 1,
		ExtraFiles:  e.wipeExtraFiles(wipeAll),
		OnProgress: func(step, total int, msg string) {
			e.log(fmt.Sprintf("Wipe [%d/%d]: %s", step, total, msg))
		},
	})
}

// wipeExtraFiles — P1 (аудит 2026-09-01, security-раздел, находка №17 «улики»): файлы, которые
// Wipe() не видит, потому что они лежат ВНЕ DataDir/BinDir, но выдают факт использования APF
// (или конкретный VPN-узел) не хуже самого DataDir. Отсутствие любого из них — не ошибка, см.
// WipeOptions.ExtraFiles.
//
//   - apf_killswitch.netsh (%TEMP%) — временный скрипт UAC-пути Kill Switch, содержит IP
//     VPN-узла в remoteip=. killswitch.EnableWithUAC сам его удаляет через defer при штатном
//     завершении — переживает только крах процесса ДО этого defer (см. её doc-comment).
//     Путь ЛИТЕРАЛЬНО дублирует internal/killswitch/killswitch_uac_windows.go — этот пакет
//     кросс-платформенный (Linux-сборка тоже проходит через EmergencyWipe), а сам файл нужен
//     только на Windows; вводить сюда build-тег ради одной строки — цена больше пользы,
//     несуществующий путь на других ОС безвреден (ExtraFiles тут же отбрасывает отсутствующее).
//   - webui_port.txt (%ProgramData%, config.PortFilePath) — публикует РЕАЛЬНЫЙ порт, на
//     котором поднялся Web UI; сам по себе не секрет, но подтверждает, что APF запускался на
//     этой машине, ровно как и остальное, что Wipe стирает.
//   - при wipeAll (пользователь явно попросил стереть и бинарники) — сам исполняемый файл и
//     трей-компаньон рядом с ним. Раньше WipeSelf стирал только BinDir (<exe>/bin/), а сам
//     apf.exe уровнем выше не трогал вовсе — "стереть всё" оставляло приложение установленным.
//     Попытка удалить СВОЙ ЖЕ запущенный exe — best-effort: Windows в норме это разрешает
//     (файл помечается на удаление и физически исчезает, когда закрывается последний хендл
//     при завершении процесса), но гарантии нет — отказ здесь не отличается от любого другого
//     res.Errors и не прерывает остальное стирание.
func (e *Engine) wipeExtraFiles(wipeAll bool) []string {
	extra := []string{
		filepath.Join(os.TempDir(), "apf_killswitch.netsh"),
		config.PortFilePath(),
	}
	if wipeAll {
		if exe, err := os.Executable(); err == nil {
			if resolved, err2 := filepath.EvalSymlinks(exe); err2 == nil {
				exe = resolved
			}
			extra = append(extra, exe, filepath.Join(filepath.Dir(exe), "apf-tray.exe"))
		}
	}
	return extra
}

// applyStrategy фиксирует выбранную стратегию обхода.
//
// Вход:      рекомендация детектора блокировки.
// Тело:      единственное реальное действие — включение режима цепочки (UseChain);
//
//	остальные ветки только записывают выбор в лог.
//
// Выход:     нет.
// Fail-safe: запись в конфигурацию идёт под e.mu — тем же локом, под которым конфигурацию
//
//	читают все остальные (в том числе applyDPIFromConfig, снимающий копию структуры).
//
// К2-E П13 (свод C трек 1 №13; B3 #9, A1 R-1), два разных дефекта в семи строках:
//
//  1. ГОНКА. `e.cfg.EnableChain = true` писалось без лока, а e.cfg читают ~105 мест под
//     e.mu.RLock. Вызывается applyStrategy из tryFallback L2 — в момент аварийного
//     переключения, ровно тогда, когда интерфейс опрашивает состояние чаще всего.
//
//  2. ЛОЖЬ В ЛОГЕ. Ветки UseReality и UseCDN писали «Strategy: VLESS+Reality (SNI masking)» и
//     «Strategy: CDN fronting (IP bypass)», не выполняя НИ ОДНОГО действия. Предпочтение
//     Reality реализовано совсем в другом месте — при выборе узла по типу блокировки
//     (selectBestForStrategy + scoring), а CDN-фронтинг требует инфраструктуры пользователя и
//     по умолчанию выключен. Формулировка изменена на «зафиксирована»: движок записал выбор,
//     а сработает он (или нет) при выборе узла.
func (e *Engine) applyStrategy(s detector.Strategy) {
	switch {
	case s.UseReality:
		e.log("Strategy: стратегия зафиксирована — предпочтение VLESS+Reality " +
			"(сработает при выборе узла, если Reality-узлы есть в пуле)")
	case s.UseCDN:
		e.log("Strategy: стратегия зафиксирована — CDN fronting " +
			"(настраивается отдельно и требует своего CDN-воркера)")
	case s.UseChain:
		e.log("Strategy: chain tunneling (DPI bypass)")
		e.mu.Lock()
		e.cfg.EnableChain = true
		e.mu.Unlock()
	}
	e.log(fmt.Sprintf("Primary: %s | Fallback: %s", s.Primary, s.Fallback))
}

// ─── Подключение ─────────────────────────────────────────────────────────────

// ScanAndConnect — диагностика + сканирование + подключение
func (e *Engine) ScanAndConnect() (err error) {
	// P0-1 (ТЗ v1.6): single-flight всего цикла. Второй одновременный ScanAndConnect не
	// начинает собственный подбор+подключение поверх идущего — иначе он делает редундантный
	// реконнект к уже поднимаемому/поднятому узлу и утекает фикс-порт входа (см. поле
	// connCycleActive и корень P0-1). Дубликат — не ошибка: цикл, что уже идёт, обслуживает то
	// же намерение «подключиться», поэтому возвращаем nil (успешный no-op для вызывающего).
	if !e.connCycleActive.CompareAndSwap(false, true) {
		e.log("Подключение уже идёт — дублирующий вызов ScanAndConnect пропущен")
		return nil
	}
	defer e.connCycleActive.Store(false)

	// N-8 (§3 DIAG_N8_PLAN.md): "start→first working" — полное время от старта скана до
	// возврата (успех = найден и поднят рабочий узел; провал — до исчерпания резервов).
	// defer покрывает ВСЕ точки return разом, включая ранние (§3.1 таблица).
	t0 := time.Now()
	defer func() {
		outcome := "failed"
		if err == nil {
			outcome = "connected"
		}
		e.log(fmt.Sprintf("[diag-N8] stage=ScanAndConnect took=%s outcome=%s", time.Since(t0).Round(time.Millisecond), outcome))
	}()
	e.log("Starting scan...")

	// §3, докс PLAN_2026-08-28_stubs_and_realfunc.md (плавающий приоритет, запрос
	// пользователя): узел, который в прошлый раз реально подтвердил рабочий канал,
	// пробуется ПЕРВЫМ, до полного скана пула. При успехе — подключаемся сразу (секунды
	// вместо 25-30с полного скана), а полный скан пула запускается фоном, не блокируя уже
	// установленное соединение.
	if node := e.tryPreferredNodesFirst(); node != nil {
		err := e.connectNode(node)
		if err == nil {
			return nil
		}
		// ТЗ HOTSWITCH §8 A1/A2: судим узел только за его собственный отказ. Сбой машины (порт,
		// Kill Switch, старт процесса) не повод ни штрафовать узел, ни идти по пулу — весь пул
		// упал бы так же, а резервы (Tor) сверху ещё и эскалировали бы тип блокировки.
		switch classifyConnectFailure(err) {
		case failureNoJudgement:
			return err
		case failureLocal:
			e.log(fmt.Sprintf("Приоритет: «%s» не подключён из-за сбоя на этой машине, а не узла (%v) — "+
				"узел не штрафуется", node.Name, err))
			e.rotateAfterStartTimeout(node, err)
			return e.finishScanFailure(err)
		}
		// Предпочтительный узел ответил на TCP, но подключение не собралось — это не повод
		// вернуть ошибку: идём обычным путём по пулу (F2 I7: автофоллбэк по порядку выбора).
		e.log(fmt.Sprintf("Приоритет: подключение к «%s» не удалось (%v) — обычный путь", node.Name, err))
		e.recordNodeFailure(node, failReasonConnect)
		e.markNodeFailed(node.ID)
	}

	if !e.runPoolScan() {
		return e.finishScanFailure(e.tryFallback())
	}

	ranked := e.rankCandidatesForStrategy()
	if len(ranked) == 0 {
		return e.finishScanFailure(e.tryFallback())
	}
	// ТЗ v1.3 F4 (ND-6): не одна попытка по «лучшему», а цикл по top-K с бюджетом времени.
	err = e.connectTopCandidates(ranked, "Best")
	if err == nil {
		return nil
	}
	if stop, stopErr := e.endSearchOnNonNodeFailure(err); stop {
		return stopErr
	}
	if e.cfg.CyclicNodeSearch {
		ok, cycErr := e.tryCyclicSearch(nil)
		if ok {
			return nil
		}
		if stop, stopErr := e.endSearchOnNonNodeFailure(cycErr); stop {
			return stopErr
		}
	}
	return e.finishScanFailure(e.tryFallback())
}

// endSearchOnNonNodeFailure — ТЗ HOTSWITCH §8 A2: прекращать ли поиск целиком после отказа
// перебора кандидатов. Локальный сбой — да, с ре-армингом (следующий кандидат и резервы вроде
// Tor упали бы так же, а повторная диагностика в tryFallback по ложным провалам ещё и
// эскалировала бы тип блокировки — гипотеза h2 ТЗ). Отмена нас самих — да, без ре-арминга
// (движок останавливают). Отказ узлов — нет: (false, nil), поиск идёт дальше.
func (e *Engine) endSearchOnNonNodeFailure(err error) (bool, error) {
	if err == nil {
		return false, nil
	}
	switch classifyConnectFailure(err) {
	case failureNoJudgement:
		return true, err
	case failureLocal:
		return true, e.finishScanFailure(err)
	}
	return false, nil
}

// finishScanFailure — единая точка «поиск провалился целиком» (ТЗ v1.3 F4 BB-5): планирует
// ре-арминг, чтобы движок не остался «без узлов» до ручного вмешательства.
func (e *Engine) finishScanFailure(err error) error {
	if err != nil {
		e.scheduleReArm(err)
	}
	return err
}

// connectTopK / connectBudget — сколько лучших кандидатов и за какое время пробует
// connectTopCandidates, прежде чем перейти к циклическому поиску/резервам (ТЗ v1.3 F4 ND-6).
// reArmMinDelay / reArmMaxDelay — окно ре-арминга после исчерпания резервов (BB-5):
// 30 с → 1 м → 2 м → 4 м → 5 м (экспоненциально, с потолком).
// var, а не const — тест скорости поиска/подключения (2026-09-05) подменяет эти значения
// на маленькие, чтобы проверить сам механизм тайм-бюджета/лимита без ожидания реальных 60 с
// (тот же приём, что у scanBatchLimit/sweepBatchSize/nodesSaveDebounce/autoSweepDelay).
var (
	connectTopK   = 5
	connectBudget = 60 * time.Second
	reArmMinDelay = 30 * time.Second
	reArmMaxDelay = 5 * time.Minute
)

// connectTopCandidates пробует подключиться к первым connectTopK узлам списка в его порядке,
// не дольше connectBudget. Ошибка подключения (не сбой канала — тот ловит health-check)
// пишется в узел (connect_error) и в recentFailures, чтобы следующий выбор его не повторил —
// но только если это отказ САМОГО узла (ТЗ HOTSWITCH §8 A1). Сбой машины или отмена обрывают
// перебор сразу и возвращаются как есть (A2): вызывающий по классу решает, что дальше.
func (e *Engine) connectTopCandidates(ranked []*models.Node, why string) error {
	deadline := time.Now().Add(connectBudget)
	lastErr := errors.New("no connectable candidates")
	for i, n := range ranked {
		if i >= connectTopK {
			break
		}
		if time.Now().After(deadline) {
			e.log(fmt.Sprintf("%s: бюджет %v на попытки подключения исчерпан", why, connectBudget))
			break
		}
		if err := e.currentCtx().Err(); err != nil {
			return err
		}
		e.log(fmt.Sprintf("%s: %s | score=%.3f latency=%dms protocol=%s",
			why, n.Name, n.Score, n.Latency, n.Protocol))
		// N-8 (§3 DIAG_N8_PLAN.md): per-candidate raise/reload — connectNode = build+apply
		// (одноузловой аналог "raise/reload" из таблицы §3.1); post-connect health-check —
		// отдельная асинхронная стадия, её тайминг снят отдельно в runPostConnectHealthCheck
		// (time-to-first-verified).
		tCand := time.Now()
		err := e.connectNode(n)
		e.logDiagN8(fmt.Sprintf("connectTopCandidates:%s", n.ID), tCand)
		if err == nil {
			e.fsm.HandleSuccess(time.Duration(n.Latency) * time.Millisecond)
			return nil
		}
		lastErr = err
		switch classifyConnectFailure(err) {
		case failureNoJudgement:
			return err
		case failureLocal:
			e.log(fmt.Sprintf("Подключение к «%s» не удалось из-за сбоя на этой машине, а не узла: %v — "+
				"узел не штрафуется, перебор остановлен (следующий кандидат упал бы так же)", n.Name, err))
			e.rotateAfterStartTimeout(n, err)
			return err
		}
		e.log(fmt.Sprintf("Подключение к «%s» не удалось: %v — следующий кандидат", n.Name, err))
		e.recordNodeFailure(n, failReasonConnect)
		e.markNodeFailed(n.ID)
	}
	return lastErr
}

// reArmDelay — пауза перед attempt-й попыткой ре-арминга: 30 с, 1 м, 2 м, 4 м, далее 5 м.
func reArmDelay(attempt int32) time.Duration {
	delay := reArmMinDelay
	for i := int32(1); i < attempt && delay < reArmMaxDelay; i++ {
		delay *= 2
	}
	if delay > reArmMaxDelay {
		delay = reArmMaxDelay
	}
	return delay
}

// scheduleReArm — ТЗ v1.3 F4 (BB-5, R5): после исчерпания всех кандидатов и резервов движок
// раньше просто останавливался «без узлов» до ручного вмешательства. Теперь полный поиск
// повторяется по экспоненциальной паузе (reArmMinDelay…reArmMaxDelay) с уважением к
// NodeAutoSwitchEnabled, отмене контекста (Disconnect/Stop — sleepCtx), уже установленному
// соединению и смене поколения подключения (пользователь вмешался вручную). Одновременно
// висит не больше одного ре-арминга (reArmPending).
func (e *Engine) scheduleReArm(cause error) {
	// LOT-08, точка отказа №2. Единственная воронка «рабочий узел не найден»: сюда приходят
	// finishScanFailure (все три исхода ScanAndConnect) и emergencySwitch после исчерпания
	// tryFallback. Движок в этот момент сам пишет в лог «рабочий узел не найден» — и, если
	// туннель при этом всё ещё числится поднятым, одновременно показывает «Подключено, канал
	// подтверждён». Два утверждения об одной сессии противоречат друг другу, и честное из них
	// — второе: подтверждения у нас нет.
	//
	// Почему VerifyFailed, а не VerifyIdle: Connected здесь никто не снимал, туннель формально
	// поднят, а Idle означает «не подключено». Гейт по Connected внутри markChannelDead сам
	// оставит Idle там, где туннеля нет (обычный случай: все попытки подключения уже откатились
	// через rollbackConnectionAttempt → setDisconnected).
	//
	// Гасим ДО CompareAndSwap: «резервы исчерпаны» — факт о сессии, он верен независимо от
	// того, висит ли уже один запланированный ре-арминг.
	//
	// Сознательный размен (риск ложного гашения): сюда можно прийти и с живым туннелем — если
	// поиск нового узла провалился, ничего не тронув (ForceRescan/ForceSwitchNow при пустом
	// пуле и недоступном Tor). Тогда подтверждение снимается с работающего канала — но не
	// дольше чем до первой успешной проверки Watchdog (≤15 с, markChannelAliveAgain вернёт
	// VerifyVerified). Обратная ошибка — «подтверждено» на мёртвом канале — не лечится вообще
	// ничем, кроме ручного переподключения; поэтому размен именно такой, тот же, что принят
	// LOT-04 для monitor().
	// ТЗ HOTSWITCH §8 A2: при локальном сбое «рабочий узел не найден» — неправда (узлы никто не
	// судил), и человек по журналу пошёл бы искать другие узлы вместо причины на своей машине.
	reason := "рабочий узел не найден"
	if classifyConnectFailure(cause) == failureLocal {
		reason = "подключение сорвалось на этой машине, узлы не виноваты"
	}
	e.markChannelDead(fmt.Sprintf("резервы исчерпаны, %s: %v", reason, cause))
	if !e.reArmPending.CompareAndSwap(false, true) {
		return
	}
	attempt := e.reArmAttempts.Add(1)
	delay := reArmDelay(attempt)
	e.stateMu.RLock()
	gen := e.connGen
	e.stateMu.RUnlock()
	e.log(fmt.Sprintf("Ре-арминг: %s (%v) — повторю полный поиск через %v (попытка %d)",
		reason, cause, delay.Round(time.Second), attempt))
	// LOT-09, находка 4.3: если e.ctx уже отменён, goTracked НЕ запускает функцию — и флаг,
	// взведённый CompareAndSwap выше, не снимал никто. Внутри самой горутины отмена учтена
	// (обе ветки вокруг sleepCtx делают Store(false)), а вот отказ ЗАПУСТИТЬСЯ не был учтён
	// вовсе. Последствие переживает саму остановку: Stop() пересоздаёт контекст (resetCtx),
	// движок снова работоспособен, но reArmPending остался true — и каждый следующий
	// scheduleReArm молча выходит на CompareAndSwap. То есть после одного неудачного момента
	// ре-арминг выключается НАВСЕГДА до перезапуска процесса, а это единственный механизм,
	// возвращающий пользователя в сеть после исчерпания всех кандидатов.
	if !e.goTracked(func() {
		if !e.sleepCtx(delay) {
			e.reArmPending.Store(false)
			return
		}
		e.reArmPending.Store(false)
		if !e.cfg.NodeAutoSwitchEnabled {
			e.log("Ре-арминг: автопереключение отключено пользователем — не повторяю поиск")
			return
		}
		if e.IsConnected() {
			e.log("Ре-арминг: соединение уже установлено — отменяю")
			return
		}
		e.stateMu.RLock()
		curGen := e.connGen
		e.stateMu.RUnlock()
		if curGen != gen {
			e.log("Ре-арминг: состояние подключения менялось вручную — отменяю")
			return
		}
		e.log("Ре-арминг: повторный поиск рабочего узла")
		if err := e.ScanAndConnect(); err != nil {
			e.log(fmt.Sprintf("Ре-арминг: поиск снова не удался: %v", err))
			return // ScanAndConnect сам планирует следующий ре-арминг (finishScanFailure)
		}
		e.reArmAttempts.Store(0)
	}) {
		e.reArmPending.Store(false)
		e.log("Ре-арминг: движок останавливается — повторный поиск не запланирован")
	}
}

// preferredTryLimit — сколько предпочтительных узлов пробуется до полного скана (ТЗ v1.3 F2).
const preferredTryLimit = 5

type preferredCand struct {
	node *models.Node
	why  string
}

// preferredCandidates — упорядоченный список узлов, которые стоит попробовать ДО полного
// скана пула (порядок выбора F2, инвариант I6): 1) закреплённый (если не подавлен и без
// свежего сбоя), 2) избранные по Score, 3) LastActiveNodeID — только если pin пуст или
// совпадает (раньше «плавающий приоритет» молча обходил pin — R4), 4) подтверждённые реальным
// трафиком по свежести. Исключаются чёрный список, бан пользователя и партнёры цепочки.
// Не более preferredTryLimit.
func (e *Engine) preferredCandidates() []preferredCand {
	pid := e.PinnedNodeID()
	suppressed := pid != "" && e.pinSuppressed()
	favIDs := e.FavoriteIDs()

	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.cfg == nil {
		return nil
	}
	lastID := e.cfg.LastActiveNodeID
	byID := make(map[string]*models.Node, len(e.nodes))
	for _, n := range e.nodes {
		if n != nil {
			byID[n.ID] = n
		}
	}
	usable := func(n *models.Node) bool {
		return n != nil && !n.IsBlacklisted() && !n.IsChainPartner && !n.UserBanned
	}
	out := make([]preferredCand, 0, preferredTryLimit)
	seen := make(map[string]bool, preferredTryLimit)
	add := func(n *models.Node, why string) {
		if !usable(n) || seen[n.ID] || len(out) >= preferredTryLimit {
			return
		}
		seen[n.ID] = true
		out = append(out, preferredCand{node: n, why: why})
	}

	if pid != "" {
		switch pinned := byID[pid]; {
		case pinned == nil:
			e.setPinnedStatus(pinStatusUnreachable)
		case suppressed:
			// статус уже suppressed (suppressPin)
		case pinFreshFailure(pinned):
			e.setPinnedStatus(pinStatusUnreachable)
		default:
			add(pinned, "закреплён")
		}
	}
	favs := make([]*models.Node, 0, len(favIDs))
	for _, id := range favIDs {
		if n := byID[id]; usable(n) {
			favs = append(favs, n)
		}
	}
	sort.SliceStable(favs, func(i, j int) bool { return favs[i].Score > favs[j].Score })
	for _, n := range favs {
		add(n, "избранное")
	}
	if lastID != "" && (pid == "" || pid == lastID) {
		add(byID[lastID], "последний рабочий")
	}
	proven := make([]*models.Node, 0, 8)
	for _, n := range e.nodes {
		if usable(n) && n.IsProven() && !n.LastOutcomeIsFailure() && !seen[n.ID] {
			proven = append(proven, n)
		}
	}
	sortCandidatesProvenFirst(proven, time.Now().Unix())
	for _, n := range proven {
		add(n, "подтверждён ранее")
	}
	return out
}

// tryPreferredNodesFirst — см. ScanAndConnect. Пробует preferredCandidates по очереди быстрой
// проверкой CheckOne; первый живой возвращается для немедленного connectNode (секунды вместо
// полного скана), полный скан пула запускается фоном. nil — приоритетов нет, никто не ответил
// или контекст отменён (тогда вызывающая сторона идёт обычным путём). Раньше здесь был только
// LastActiveNodeID (tryLastActiveNodeFirst), и он обходил закреплённый узел.
func (e *Engine) tryPreferredNodesFirst() *models.Node {
	cands := e.preferredCandidates()
	if len(cands) == 0 {
		return nil
	}
	for _, c := range cands {
		e.log(fmt.Sprintf("Приоритет: пробую «%s» (%s) первым...", c.node.Name, c.why))
		result := e.checkNodeSerialized(e.currentCtx(), c.node)
		if result == nil || result.Outcome == models.OutcomeNotChecked {
			return nil // отмена/остановка — не «недоступен»
		}
		if !result.Success {
			e.log(fmt.Sprintf("Приоритет: «%s» недоступен (%s)", c.node.Name, result.Error))
			if c.node.ID == e.PinnedNodeID() {
				e.setPinnedStatus(pinStatusUnreachable)
			}
			continue
		}
		e.log(fmt.Sprintf("Приоритет: «%s» жив (%dms) — подключаюсь сразу, "+
			"полный скан пула — фоном", c.node.Name, c.node.Latency))
		e.goTracked(func() { e.runPoolScan() })
		return c.node
	}
	e.log("Приоритет: ни один из предпочтительных узлов не ответил — обычный полный скан")
	return nil
}

// runPoolScan — измеряет метрики пакета кандидатов пула (CheckAll) и уведомляет
// подписчиков (OnNodeUpdated), обновляя Score для будущего выбора. Общая часть между
// ScanAndConnect (блокирующий путь, при провале — tryFallback) и фоновым досканом после
// успешного tryLastActiveNodeFirst (§3 — НЕ блокирует уже установленное подключение, провал
// здесь просто означает «Score пула не обновился в этот раз», а не что-либо, требующее
// tryFallback). Возвращает true, если хотя бы один кандидат был протестирован.
func (e *Engine) runPoolScan() bool {
	// ТЗ v1.3 F4 Stage 0: подключение НЕ ждёт загрузки подписок. Раньше updateSources(false)
	// здесь выполнялась синхронно и (из-за пересоздаваемого на каждый вызов менеджера — см.
	// SourceConfig.LastUpdatedAt) перекачивала ВСЕ подписки перед каждой проверкой пула:
	// секунды-минуты до первой TCP-пробы (ND-3). Теперь: пустой пул — загружаем синхронно
	// (иначе проверять нечего); иначе — освежаем в фоне по интервалам, скан идёт по тому,
	// что уже есть.
	e.mu.RLock()
	poolEmpty := len(e.nodes) == 0
	e.mu.RUnlock()
	if poolEmpty {
		e.updateSources(true)
	} else {
		e.goTracked(func() { e.updateSources(false) })
	}

	// P1-2 (аудит 2026-09-01): батч запрашивается СРАЗУ нужного размера.
	//
	// Раньше здесь стояло getRescanBatch(100), а ниже — `candidates[:50]`. getRescanBatch
	// кладёт давно-непроверенные узлы в ХВОСТ батча (60 top ++ 40 stale), поэтому слепая
	// обрезка до первых 50 выбрасывала ВСЮ explore-долю целиком и оставляла чистый top-50 по
	// Score. То есть замкнутый круг, ради разрыва которого getRescanBatch и написана
	// («5314 узлов, реально используются 1-2», QA v1.0 §1), воспроизводился дословно, а
	// собственный тест функции оставался зелёным — он дёргает её напрямую, минуя вызывающего.
	//
	// Единый лимит вместо двух: сколько узлов собираемся проверить, столько и запрашиваем.
	e.mu.RLock()
	all := e.getRescanBatch(scanBatchLimit)
	e.mu.RUnlock()

	var candidates []*models.Node
	if e.cfg.SafetyFilter {
		candidates = e.safety.FilterSafe(all)
		if len(candidates) == 0 {
			candidates = all
		}
	} else {
		candidates = all
	}

	if len(candidates) == 0 {
		e.log("No candidates, forcing source update...")
		e.updateSources(true)
		e.mu.RLock()
		candidates = e.getRescanBatch(scanBatchLimit)
		e.mu.RUnlock()
	}
	if len(candidates) == 0 {
		return false
	}

	e.log(fmt.Sprintf("Testing %d nodes (safety filter: %v)...",
		len(candidates), e.cfg.SafetyFilter))

	results := e.checkNodesSerialized(e.currentCtx(), candidates)
	// P0.3 (docs/TZ_WINDOWS_CONSILIUM_FINDINGS_v1.0.md): раньше e.mu.Lock() держался на все
	// до-50 вызовов OnNodeUpdated подряд. Тело цикла не мутирует e.nodes — только читает
	// указатель на колбэк, который не меняется чаще, чем раз за весь запуск приложения — лок
	// здесь ничего не защищал, а лишь блокировал GetNodes()/GetStats()/PatchConfig() (те же
	// e.mu), которыми защищены и клики по тумблерам Kill Switch/системного прокси/режима VPN:
	// во время скана они казались не отвечающими на несколько секунд.
	cb := e.OnNodeUpdated
	for _, r := range results {
		if r != nil && cb != nil {
			cb(r.Node)
		}
	}
	return true
}

// selectBestForStrategy выбирает лучший узел с учётом типа блокировки и режима выбора.
// algorithmist: взвешенный scoring по SelectionMode из конфига.
// tunnel-architect: при SNI-блокировке приоритет Reality-узлам.
func (e *Engine) selectBestForStrategy() *models.Node {
	ranked := e.rankCandidatesForStrategy()
	if len(ranked) == 0 {
		return nil
	}
	return ranked[0]
}

// rankCandidatesForStrategy — тело selectBestForStrategy, возвращающее ВЕСЬ упорядоченный
// список годных к подключению кандидатов (ТЗ v1.3 F4: ScanAndConnect идёт по top-K, а не
// по одному «лучшему»). Порядок: закреплённый (если прошёл фильтры) → избранные → подтверждённые
// реальным трафиком → остальные по Score.
func (e *Engine) rankCandidatesForStrategy() []*models.Node {
	// getActiveCandidates читает e.nodes без своего лока (см. её комментарий) — раньше
	// ScanAndConnect/tryFallback звали её здесь тоже без лока: гонка с параллельными
	// писателями пула (updateSources по тикеру, AddNodeFromLink) реальна и потенциально
	// паникует на рассогласованном срезе (тот же класс находки, что и у emergencySwitch,
	// 2026-08-24). ТОЛЬКО вокруг самого чтения: ниже по функции лок берётся СНОВА (для
	// записи Score, см. комментарий там) — держать его непрерывно нельзя, RWMutex не
	// реентерабелен, и e.mu.RLock() здесь + e.mu.Lock() там на одной горутине — гарантированный
	// самозаклин (живой прогон 2026-09-02: ровно так и поймано, TestScanAndConnect_SafetyFilter
	// зависала на этом).
	e.mu.RLock()
	candidates := e.getActiveCandidates(0)
	e.mu.RUnlock()
	if len(candidates) == 0 {
		return nil
	}

	// Получаем веса для текущего режима выбора
	selMode := e.cfg.SelectionMode
	if selMode == "" {
		selMode = "balanced"
	}
	weights := checker.WeightsForMode(selMode)

	curBlockage := e.getBlockageType()

	// При SNI/DPI блокировке — усиливаем вес протокола (bypass-engineer)
	if curBlockage == detector.BlockageSNI || curBlockage == detector.BlockageDeep {
		weights.Protocol = 0.60
		weights.Latency = 0.15
		weights.AntiBlock = 0.10
		e.log(fmt.Sprintf("Strategy: boosting protocol weight for %s blockage", curBlockage))
	}

	// При IP блокировке — усиливаем вес AntiBlock (нужен другой IP)
	if curBlockage == detector.BlockageIP {
		weights.AntiBlock = 0.40
		weights.Protocol = 0.20
		weights.Latency = 0.25
	}

	// Пересчитываем Score для всех кандидатов с новыми весами.
	// F-34: запись n.Score идёт под e.mu, т.к. узлы из e.nodes параллельно читаются
	// (GetNodes/JSON-сериализация в HTTP). Лок берётся здесь локально — вызывающие
	// (ScanAndConnect/tryFallback) к этому моменту уже отпустили e.mu.
	// ТЗ v1.3 F1.4/F1.5: пол 0.5 отменён (minScore=0) — непроверенный узел получает 0 и через
	// порог Score > 0.001 ниже не проходит; годными считаются только узлы с реальной пробой.
	e.mu.Lock()
	for _, n := range candidates {
		n.Score = checker.CalcScoreWeighted(n, weights, 0)
	}
	e.mu.Unlock()

	// F1.5: проверенные реальным трафиком — впереди (по свежести подтверждения и задержке
	// через туннель), затем остальные по Score; забаненные и недавно отказавшие — вон.
	candidates = e.filterSelectable(candidates, nil)
	sortCandidatesProvenFirst(candidates, time.Now().Unix())
	candidates = e.favoritesFirst(candidates) // F2: избранное — перед остальным пулом

	// Годные к подключению: с ненулевым Score или подтверждённые реальным трафиком (их
	// последняя TCP-проба могла быть давно — подтверждение туннеля весомее TCP-connect).
	ranked := selectableOnly(candidates)

	// FR-4 (F-30, расширение B-08.4): закреплённый пользователем узел имеет приоритет и в
	// ОСНОВНОМ пути авто-выбора (ScanAndConnect), а не только при переключении
	// (selectBestExcluding). ТЗ v1.3 PIN-5: проверка идёт ПОСЛЕ фильтров — раньше pin возвращался
	// до них, и забаненный/только что отказавший закреплённый узел выбирался вслепую.
	if pid := e.PinnedNodeID(); pid != "" {
		if pinned := e.pickPinned(candidates, pid); pinned != nil {
			ranked = moveToFront(ranked, pinned)
		}
	}

	// Логируем топ-3 для диагностики
	top := ranked
	if len(top) > 3 {
		top = top[:3]
	}
	for i, n := range top {
		e.log(fmt.Sprintf("  [%d] %s score=%.3f lat=%dms proto=%s",
			i+1, n.Name, n.Score, n.Latency, n.Protocol))
	}
	return ranked
}

// selectableOnly оставляет узлы, годные к подключению (см. firstSelectable), сохраняя порядок.
func selectableOnly(sorted []*models.Node) []*models.Node {
	out := make([]*models.Node, 0, len(sorted))
	for _, n := range sorted {
		if n.Score > 0.001 || n.IsProven() {
			out = append(out, n)
		}
	}
	return out
}

// moveToFront ставит n первым (добавляя, если его нет в списке), порядок остальных сохраняется.
func moveToFront(list []*models.Node, n *models.Node) []*models.Node {
	out := make([]*models.Node, 0, len(list)+1)
	out = append(out, n)
	for _, x := range list {
		if x != n {
			out = append(out, x)
		}
	}
	return out
}

func (e *Engine) connectNode(node *models.Node) error {
	cfg, err := e.buildNodeConfigWithSetup(node)
	if err != nil {
		return fmt.Errorf("build config: %w", err)
	}
	return e.applySingBoxConfig(cfg, node, nil)
}

// buildNodeConfigWithSetup — настройка Builder под текущее состояние движка + сборка конфига
// узла, целиком под builderMu (см. поле).
func (e *Engine) buildNodeConfigWithSetup(node *models.Node) (*singbox.Config, error) {
	e.builderMu.Lock()
	defer e.builderMu.Unlock()
	// Sprint S4: перед билдом подцепляем текущие AdBlock правила в Builder
	if e.adBlocker != nil {
		e.builder.SetAdBlockRules(e.adBlocker.GetSingBoxDNSRules())
	}
	// Прямой маршрут (реальный сплит-туннелинг, см. память apf-bypass-feature-broken /
	// docs/TZ_APF_QA_AND_BACKLOG_v1.0.md §2): раньше пользовательский bypass_list.json
	// никогда не попадал в Builder.bypass (захардкожен на localhost) — байпас-домены не
	// маршрутизировались напрямую ни на одной платформе.
	if e.bypassManager != nil {
		e.builder.SetBypassDomains(e.bypassManager.DirectRouteDomains())
	}
	// Приложения вне VPN. На Windows это имена процессов и решается правилом маршрутизации
	// по process_name (работает только в TUN-режиме); на Android то же самое делается на
	// уровне ОС через VpnService.Builder.addDisallowedApplication и сюда не попадает —
	// см. models.AppConfig.DisallowedApps.
	if runtime.GOOS != "android" {
		e.builder.SetDirectProcesses(e.cfg.DisallowedApps)
	}
	// R-6.2: настройка защиты от IPv6-утечки могла измениться через PatchConfig после New().
	e.builder.SetTunIPv6(e.cfg.BlockIPv6Leak)
	// Задача #18: пользовательский тумблер "IPv6 Block" (EnableIPv6Block/ipv6Guard) — раньше
	// на Android ничего не делал, теперь реально форсирует ipv4_only на DNS-уровне.
	e.builder.SetBlockIPv6(e.ipv6Guard.IsEnabled())
	// R-8: резолвим адрес узла ОДИН раз и закрепляем IP в конфигурации, чтобы sing-box не
	// резолвил домен сам через внешний резолвер мимо туннеля.
	e.prepareEndpoint(node.Address)
	// T-18: при включённом ShadowTLS оборачиваем outbound в итоговом конфиге.
	if e.shadowTLS != nil && e.shadowTLS.IsEnabled() {
		e.builder.SetShadowTLS(&singbox.ShadowTLSParams{
			Server:   e.shadowTLS.ServerHost(),
			Port:     e.shadowTLS.ServerPort(),
			Version:  e.shadowTLS.Version(),
			Password: e.shadowTLS.Password(),
			SNI:      e.shadowTLS.SNI(),
		})
	} else {
		e.builder.SetShadowTLS(nil)
	}
	// T-18(CDN): при включённом CDN-fronting фронтим outbound через CDN (TLS+ws).
	if e.cdnFronter != nil && e.cdnFronter.IsEnabled() {
		if p := e.cdnFronter.BuildFrontedOutbound(); p != nil {
			e.builder.SetCDNFronting(&singbox.CDNParams{
				Server: p.Server, Port: p.ServerPort, SNI: p.SNI,
				WSPath: p.WSPath, WSHost: p.WSHost,
			})
		}
	} else {
		e.builder.SetCDNFronting(nil)
	}
	return e.buildNodeConfig(node)
}

// raceGroupSize — сколько узлов участвует в гонке. Больше — выше шанс сразу попасть на
// рабочий, но каждый кандидат держит собственную пробу и соединение; 6 — компромисс,
// подтверждённый тем, что в живом логе рабочий узел находился в пределах первых нескольких
// кандидатов по score.
const raceGroupSize = 6

// buildNodeConfig собирает конфиг для подключения к узлу — одиночный либо «гонку»
// нескольких кандидатов (см. singbox.Builder.BuildRace и NodeRaceEnabled).
//
// Гонка сознательно НЕ применяется, когда узел задан жёстко: при ручном выборе и при
// закреплённом узле пользователь ожидает подключения именно к нему, а urltest мог бы увести
// трафик на соседний кандидат — это выглядело бы как «ручной выбор не работает» (ровно та
// жалоба, из-за которой появилось sticky-окно manualConnectStickyWindow). Также гонка
// несовместима с ShadowTLS/CDN-обёртками — там теги outbound'ов заняты обёрткой.
func (e *Engine) buildNodeConfig(node *models.Node) (*singbox.Config, error) {
	// Состав группы обязан быть сброшен на КАЖДОМ построении конфига, до всех ранних
	// возвратов: иначе Kill Switch продолжил бы разрешать адреса прошлой группы после
	// перехода на одиночный узел — разрешения пережили бы то, ради чего выдавались.
	e.setRaceNodes(nil)

	if !e.shouldRaceNodes(node) {
		return e.builder.BuildSingle(node)
	}
	candidates := e.raceCandidates(node, raceGroupSize)
	if len(candidates) < 2 {
		return e.builder.BuildSingle(node)
	}
	// Резолвим адреса участников ЗАРАНЕЕ и передаём в конфиг закреплёнными (инвариант R-8).
	// Иначе доменные имена всех кандидатов ушли бы в открытый DNS с реального адреса
	// пользователя — то есть весь список его узлов, — а Kill Switch разрешил бы не те IP,
	// которые в итоге выберет sing-box.
	pinned := make(map[string]string, len(candidates))
	for _, c := range candidates {
		if ip, _, rerr := e.resolveEndpointOnce(c.Address); rerr == nil && ip != "" {
			pinned[c.Address] = ip
		}
	}
	e.builder.SetRacePinnedIPs(pinned)

	cfg, err := e.builder.BuildRace(candidates)
	if err != nil {
		// Любая причина отказа (несовместимость с обёрткой, мало пригодных кандидатов) —
		// не повод не подключиться вовсе: откатываемся на обычный одиночный конфиг.
		e.log(fmt.Sprintf("Гонка узлов недоступна (%v) — подключаюсь одиночным узлом", err))
		return e.builder.BuildSingle(node)
	}
	// Запоминаем состав ДО применения конфига: applyKillSwitch читает его, чтобы разрешить
	// адреса всех участников (см. killSwitchAddressesFor).
	e.setRaceNodes(candidates)
	names := make([]string, 0, len(candidates))
	for _, c := range candidates {
		names = append(names, c.Name)
	}
	e.log(fmt.Sprintf("Гонка узлов: проверяю %d кандидатов одновременно, трафик пойдёт через "+
		"первый ответивший — %s", len(candidates), strings.Join(names, " | ")))
	return cfg, nil
}

// setRaceNodes запоминает состав текущей группы гонки (или сбрасывает его при nil).
// Читается applyKillSwitch через killSwitchAddressesFor.
func (e *Engine) setRaceNodes(nodes []*models.Node) {
	e.mu.Lock()
	e.raceNodes = nodes
	e.mu.Unlock()
}

// shouldRaceNodes — уместна ли гонка для этого подключения.
func (e *Engine) shouldRaceNodes(node *models.Node) bool {
	if node == nil || !e.cfg.NodeRaceEnabled {
		return false
	}
	// Узел выбран пользователем явно — уважаем выбор, не подменяем его группой.
	if pid := e.PinnedNodeID(); pid != "" && pid == node.ID {
		return false
	}
	if e.withinManualConnectSticky() {
		return false
	}
	// Обёртки занимают теги outbound'ов — см. BuildRace.
	if e.shadowTLS != nil && e.shadowTLS.IsEnabled() {
		return false
	}
	if e.cdnFronter != nil && e.cdnFronter.IsEnabled() {
		return false
	}
	return true
}

// raceCandidates выбирает участников гонки: сам узел плюс лучшие из активных кандидатов.
// Узел-инициатор всегда идёт первым — он победитель обычного отбора по score, и если он
// действительно рабочий, urltest выберет именно его.
func (e *Engine) raceCandidates(node *models.Node, limit int) []*models.Node {
	out := []*models.Node{node}
	seen := map[string]bool{node.ID: true}
	// getActiveCandidates итерируется по e.nodes и сортирует по Score БЕЗ собственного лока —
	// её контракт требует, чтобы лок держал вызывающий (так и делают ScanAndConnect,
	// emergencySwitch, ForceSwitchNow). Путь connectNode → buildNodeConfig лока не берёт,
	// поэтому берём его здесь: параллельные писатели пула реальны и живут в других
	// горутинах (updateSources по тикеру, AddNodeFromLink из HTTP-обработчика и JNI-потока,
	// loadNodes). Без лока это гарантированный data race и потенциальная паника на
	// рассогласованном срезе (найдено ревью 2026-08-24).
	e.mu.RLock()
	candidates := e.getActiveCandidates(limit * 2)
	e.mu.RUnlock()
	for _, c := range candidates {
		if len(out) >= limit {
			break
		}
		if c == nil || seen[c.ID] {
			continue
		}
		// Узлы, только что доказанно подведшие, в гонку не берём — иначе серия
		// переключений раз за разом тащила бы за собой один и тот же мёртвый набор.
		if e.isRecentlyFailed(c.ID) {
			continue
		}
		seen[c.ID] = true
		out = append(out, c)
	}
	return out
}

func (e *Engine) connectChain(chain *models.Chain) error {
	cfg, err := e.buildChainConfigWithSetup(chain)
	if err != nil {
		return fmt.Errorf("build chain: %w", err)
	}
	return e.applySingBoxConfig(cfg, nil, chain)
}

// buildChainConfigWithSetup — то же, что buildNodeConfigWithSetup, для цепочки (под builderMu).
func (e *Engine) buildChainConfigWithSetup(chain *models.Chain) (*singbox.Config, error) {
	e.builderMu.Lock()
	defer e.builderMu.Unlock()
	// Sprint S4: перед билдом подцепляем текущие AdBlock правила в Builder
	if e.adBlocker != nil {
		e.builder.SetAdBlockRules(e.adBlocker.GetSingBoxDNSRules())
	}
	// Прямой маршрут — см. комментарий в connectNode.
	if e.bypassManager != nil {
		e.builder.SetBypassDomains(e.bypassManager.DirectRouteDomains())
	}
	// Приложения вне VPN. На Windows это имена процессов и решается правилом маршрутизации
	// по process_name (работает только в TUN-режиме); на Android то же самое делается на
	// уровне ОС через VpnService.Builder.addDisallowedApplication и сюда не попадает —
	// см. models.AppConfig.DisallowedApps.
	if runtime.GOOS != "android" {
		e.builder.SetDirectProcesses(e.cfg.DisallowedApps)
	}
	// R-6.2: то же и для цепочки — иначе v6 утекал бы мимо туннеля именно в multi-hop.
	e.builder.SetTunIPv6(e.cfg.BlockIPv6Leak)
	// Задача #18: то же самое для цепочки — см. комментарий в connectNode.
	e.builder.SetBlockIPv6(e.ipv6Guard.IsEnabled())
	// R-8: у цепочки закрепляется адрес ТОЧКИ ВХОДА — только к ней подключается хост.
	if entry := singbox.ChainEntryNode(chain); entry != nil {
		e.prepareEndpoint(entry.Address)
	} else {
		e.builder.SetServerIP("")
	}
	return e.builder.BuildChain(chain)
}

// listenProbeFn — шов: в тестах занятость порта иначе воспроизводится только реальным сокетом.
var listenProbeFn = func(addr string) (net.Listener, error) { return net.Listen("tcp", addr) }

// probeListenPort — B-0403 · R-3.2 (C-2). Проверяет, что локальные порты входа свободны,
// ДО того как мы тронем фаервол и запустим sing-box.
//
//	Вход:      e.cfg.ListenPort (SOCKS5) и ListenPort+1 (HTTP) — оба занимает sing-box.
//	Тело:      пробный net.Listen на 127.0.0.1 по каждому порту, сразу же закрывается.
//	Выход:     nil либо ошибка с именем конкретного занятого порта.
//	Fail-safe: ListenPort<=0 (Android, где вход не публикуется) — проверка пропускается.
//	Инвариант: подключение не начинается, если порт уже занят чужим процессом.
//
// Перебора портов здесь сознательно НЕТ, в отличие от Web UI. Web UI никто, кроме человека,
// не ищет, а ListenPort прошит в сборке конфигурации sing-box и в системном прокси
// (ListenPort+1). Тихо уехать на соседний порт значило бы поднять туннель, мимо которого
// пойдёт весь трафик браузера, — то есть утечка под видом успеха.
//
// Гонка TOCTOU (порт освободился/занялся между пробой и стартом sing-box) неустранима без
// передачи сокета внутрь sing-box. Проба остаётся диагностикой: она превращает невнятный
// сбой процесса в понятное сообщение и отсекает 99% случая «второй экземпляр APF».
func (e *Engine) probeListenPort() error {
	base := e.cfg.ListenPort
	if base <= 0 {
		return nil
	}
	for _, port := range []int{base, base + 1} {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		ln, err := listenProbeFn(addr)
		if err != nil {
			return fmt.Errorf("локальный порт %d занят другим процессом (возможно, уже запущен "+
				"второй экземпляр APF или посторонний sing-box): %w", port, err)
		}
		_ = ln.Close()
	}
	return nil
}

// portReleaseTimeout / portReleasePoll — окно ожидания РЕАЛЬНОГО освобождения локального порта
// входа нашим же прежним инстансом sing-box. var, а не const: тесты подменяют на короткие
// значения, чтобы проверять механизм без ожидания секунд (тот же приём, что у connectBudget и
// reArmMinDelay выше).
var (
	portReleaseTimeout = 3 * time.Second
	portReleasePoll    = 100 * time.Millisecond
)

// ensureListenPortFree — P0-1 (ТЗ v1.6). Холодный старт (wasRunning==false) требует свободных
// портов входа. probeListenPort даёт мгновенный ответ, НО на реконнекте порт может ещё держать
// НАШ ЖЕ прежний инстанс: ни одна из реализаций proc не гарантирует СИНХРОННОГО освобождения
// ОС-порта на Stop/Close.
//
//	Android: InProcessRunner.IsRunning()==server.Instance()!=nil расходится с реальным
//	         состоянием listener'а/serviceStatus (inprocess_runner.go:171-179) — Close не
//	         обязательно уже снял bind.
//	Windows: Process.IsRunning()==p.running мгновенно=false на Stop(), а Process.Kill()
//	         освобождает порт асинхронно (process.go). Reload это гасит Sleep 500ms, холодный
//	         probeListenPort — нет.
//
// Прежний код трактовал такой висящий НАШ порт как «второй экземпляр APF» и отказывался
// подключаться навсегда (живой лог телефона 2026-09-14, порт 10808 — узел исправен, заклинена
// оркестрация). Теперь: пробуем вернуть порт себе (best-effort Stop нашего runner'а) и ждём
// РЕАЛЬНОГО освобождения поллингом listenProbe до таймаута. «Второй экземпляр» объявляем ТОЛЬКО
// если порт не освободился и после этого — тогда его действительно держит кто-то, кем мы не
// управляем. Ожидание уважает отмену контекста (Disconnect/Stop).
//
// Инвариант: probeListenPort больше не даёт ложный «второй экземпляр» на НАШ же зависший инстанс.
// Замечание: proc.Stop() достаёт лишь инстанс, которым runner владеет СЕЙЧАС; уже подменённый
// (ReloadWithFreshTun) и утёкший инстанс отсюда недостижим — от такого утёка защищает
// connCycleActive (single-flight цикла), не давая наложению создать утёк вовсе.
func (e *Engine) ensureListenPortFree() error {
	err := e.probeListenPort()
	if err == nil {
		return nil
	}
	e.log(fmt.Sprintf("Порт входа занят на холодном старте (%v) — проверяю, не наш ли это "+
		"прежний инстанс, и жду освобождения…", err))
	// Best-effort возврат порта себе. На холодном пути (IsRunning==false) это, как правило,
	// no-op у обеих реализаций — реальный механизм ниже — поллинг; Stop здесь на случай
	// десинхрона IsRunning в другую сторону (инстанс жив, но флаг соврал).
	if e.proc != nil {
		_ = e.proc.Stop()
	}
	deadline := time.Now().Add(portReleaseTimeout)
	for {
		if perr := e.probeListenPort(); perr == nil {
			e.log("Порт входа освобождён — продолжаю холодный старт")
			return nil
		} else {
			err = perr
		}
		if !time.Now().Before(deadline) {
			break
		}
		if !e.sleepCtx(portReleasePoll) {
			return fmt.Errorf("ожидание освобождения порта входа прервано остановкой движка: %w", err)
		}
	}
	return fmt.Errorf("локальный порт входа не освободился за %v — вероятно, его держит "+
		"посторонний процесс (второй экземпляр APF или чужой sing-box): %w", portReleaseTimeout, err)
}

func (e *Engine) applySingBoxConfig(cfg *singbox.Config, node *models.Node, chain *models.Chain) error {
	// connMu: сериализует эту попытку подключения со Stop()/Restart() (см. комментарий
	// у поля connMu) — без этого e.proc.Start(e.ctx)/Reload(e.ctx) ниже мог прочитать
	// e.ctx ровно в узком окне между отменой и пересозданием контекста и падать с
	// "context canceled" на попытке, не имеющей отношения к тому, что его отменило.
	e.connMu.Lock()
	defer e.connMu.Unlock()

	// Пометку забираем ОДИН раз и здесь, до всех ранних return ниже: иначе неудавшаяся попытка
	// оставила бы её висеть и следующее, ни с чем не связанное подключение приняло бы себя за
	// переприменение правил. См. takeReapplyTarget.
	reapplyMarked := e.takeReapplyTarget(node, chain)

	// БАРЬЕР hostguard. Здесь встречаются НАСТОЯЩИЙ бинарник sing-box и НАСТОЯЩИЙ TUN-конфиг
	// (apf0, AutoRoute:true) — то есть отсюда стартует полноценный перехват системной маршрутизации.
	//
	// Под `go test` это недопустимо, и «тесты же без прав администратора» тут не спасает:
	// BinDir() = каталог рядом с исполняемым файлом, а у тестового бинарника это временный каталог
	// go-build. Прогон реально скачивал туда 29 МБ sing-box.exe с GitHub, после чего IsInstalled()
	// становился true и следующий же вызов поднимал туннель. Инцидент 2026-07-28.
	// Оба отказа ниже — про эту машину, не про узел (ТЗ HOTSWITCH §8 A1): штрафовать узел за
	// отсутствующий бинарник или барьер тестовой среды нельзя.
	if !hostguard.Allow("engine.applySingBoxConfig") {
		return markLocalFailure(fmt.Errorf("engine: загрузка и запуск sing-box заблокированы барьером hostguard " +
			"(`go test`); для рантайм-испытаний используйте изолированный стенд, tools/sandbox/README.md"))
	}
	if !e.proc.IsInstalled() {
		e.log("Downloading sing-box...")
		if err := e.dl.Download(e.currentCtx()); err != nil {
			return markLocalFailure(fmt.Errorf("sing-box unavailable: %w", err))
		}
	}
	wasRunning := e.proc.IsRunning()

	// R-3.2 (C-2): порт проверяем только на холодном старте — при Reload порт держит наш же
	// sing-box, и проба дала бы ложное «занято». Стоит ДО Kill Switch: незачем перекраивать
	// фаервол ради подключения, которое всё равно не поднимется.
	// P0-1 (ТЗ v1.6): не голая проба, а ensureListenPortFree — она сперва пытается вернуть себе
	// НАШ же зависший порт (Stop+поллинг до реального release), и лишь затем объявляет «второй
	// экземпляр». Прежняя голая probeListenPort заклинивала реконнект навсегда на собственном
	// зомби-инстансе (живой лог 2026-09-14).
	if !wasRunning {
		if err := e.ensureListenPortFree(); err != nil {
			return e.rollbackConnectionAttempt("listen_port", err, wasRunning)
		}
	}

	// B-0403 · R-2.1 (C-4): FAIL-CLOSED. Если пользователь включил Kill Switch, то любая
	// невозможность его применить (нет capability под режим, не резолвится узел, ошибка apply,
	// отказ UAC) ПРЕРЫВАЕТ подключение. Прежнее поведение — «лучше подняться без KS, чем без сети» —
	// и было дефектом: функция предотвращения утечки молча отключалась, а UI показывал «Connected».
	if e.cfg.EnableKillSwitch {
		if err := e.applyKillSwitch(node, chain); err != nil {
			if !e.isAllowConnectWithoutKS() {
				return e.rollbackConnectionAttempt("killswitch", err, wasRunning)
			}
			// Escape hatch (разовый, не персистится): пользователь явно согласился без защиты.
			e.log(fmt.Sprintf("⚠ KillSwitch НЕ применён (%v) — подключение продолжено по явному "+
				"разрешению пользователя. Защиты от утечки НЕТ.", err))
		}
	}
	if err := e.proc.WriteConfig(cfg); err != nil {
		return e.rollbackConnectionAttempt("write_config", err, wasRunning)
	}

	// Диагностика задачи #11 (2026-08-13, живая находка): после серии быстрых
	// emergencySwitch-переключений в logcat одновременно видны ДВА разных outbound с тегом
	// "proxy" (напр. shadowsocks И vmess) — то есть где-то остаётся жить старый инстанс
	// sing-box. connMu здесь уже держит эту функцию целиком, так что два ЭТИХ вызова
	// Reload/Start в принципе не могут выполняться параллельно — если проблема всё же
	// воспроизводится, значит быстрые последовательные вызовы (connMu их только
	// сериализует, не гарантирует что oldInstance.Close() внутри sing-box действительно
	// синхронно освобождает ВСЕ его горутины/TUN-путь) либо сам StartOrReloadService
	// (vendor/.../daemon/started_service.go) — источник, не наш вызывающий код. Логи ниже
	// — единственный способ отличить один случай от другого на реальном устройстве, не
	// гадая по исходнику vendor.
	targetName := "?"
	if node != nil {
		targetName = node.Name
	} else if chain != nil {
		targetName = "chain"
	}
	// Задача #11, вариант 2 (2026-08-17, решение пользователя после исчерпания вариантов
	// внутри нашего кода — см. память apf-overlapping-singbox-instances): если запущенный
	// Runner умеет ReloadWithFreshTun (сейчас — только androidbridge.tunRunner на Android
	// в TUN-режиме), используем его вместо обычного Reload при каждой перезагрузке поверх
	// уже работающего инстанса. Обычный Start (первое подключение сеанса) не отличается —
	// свежий TUN-интерфейс и так создаётся один раз, пересоздавать нечего.
	tunReloader, freshTun := e.proc.(singbox.TunReloader)
	applyKind := "Start"
	if wasRunning {
		if freshTun {
			applyKind = "ReloadWithFreshTun"
		} else {
			applyKind = "Reload"
		}
	}
	applyStarted := time.Now()
	e.log(fmt.Sprintf("[diag-11] sing-box %s begin: target=%s", applyKind, targetName))

	var err error
	if wasRunning {
		if freshTun {
			err = tunReloader.ReloadWithFreshTun(e.currentCtx(), cfg)
		} else {
			err = e.proc.Reload(e.currentCtx(), cfg)
		}
	} else {
		err = e.proc.Start(e.currentCtx())
	}
	e.log(fmt.Sprintf("[diag-11] sing-box %s end: target=%s took=%v err=%v",
		applyKind, targetName, time.Since(applyStarted), err))
	if err != nil {
		return e.rollbackConnectionAttempt("apply_runtime", fmt.Errorf("sing-box: %w", err), wasRunning)
	}

	// R-6.1 (C-10): TUN поднимается только сейчас, ПОСЛЕ старта sing-box, поэтому permit-правило
	// «разрешить трафик через apf0» невозможно было поставить в момент Enable — LUID ещё не
	// существовал. Досоздаём его сейчас; без него WFP заблокировал бы весь трафик приложений.
	if err := e.ensureTunPermit(); err != nil {
		if !e.isAllowConnectWithoutKS() {
			return e.rollbackConnectionAttempt("killswitch_tun", err, wasRunning)
		}
		e.log(fmt.Sprintf("⚠ KillSwitch: permit для TUN не поставлен (%v) — продолжено по явному "+
			"разрешению пользователя.", err))
	}

	e.stateMu.Lock()
	e.state.Connected = true
	// Состояние подтверждения канала сбрасывается на КАЖДОМ (пере)подключении, включая
	// emergencySwitch — узел новый, его канал ещё не проверен, поэтому VerifyChecking («проверка
	// идёт»), а не «подтверждён». В VerifyVerified его переведёт runPostConnectHealthCheck,
	// только после успешной verifyTunnelHealthCheck.
	//
	// Исключение — переприменение правил к ТОМУ ЖЕ живому подключению (см. verifyStateOnApply и
	// reapplyConfigIfConnected). Цель сверяется по указателю: пометку ставит сам путь
	// переприменения, а активный узел не должен был смениться, пока мы шли сюда.
	sameLiveTarget := reapplyMarked &&
		((node != nil && e.state.ActiveNode == node) || (chain != nil && e.state.ActiveChain == chain))
	e.setVerifyStateLocked(verifyStateOnApply(e.state.VerifyState, sameLiveTarget))
	e.state.ActiveNode = node
	e.state.ActiveChain = chain
	if node != nil {
		e.state.Mode = string(node.Protocol)
	} else {
		e.state.Mode = "chain"
	}
	e.state.Since = time.Now()
	e.stateMu.Unlock()

	// Уведомляем Sticky Session о новом подключении
	e.stickySession.OnConnected()
	e.stickySession.RecordSwitch()
	// Sprint 4: обновляем текущий nodeID для domain sticky
	if node != nil {
		e.stickySession.SetCurrentNode(node.ID)
	}
	// vpn-specialist: в VPN режиме системный прокси не нужен — TUN перехватывает всё.
	// В Proxy режиме — включается ниже, ПОСЛЕ runPostConnectHealthCheck (см. её комментарий
	// и инцидент 2026-08-19: включение здесь же, сразу после старта sing-box, ставило системный
	// прокси на узел, чья доступность подтверждена только TCP-пробой checker.CheckOne — открытый
	// порт, не рабочий VPN-протокол. Мёртвый-но-открытый узел мгновенно рвал интернет всей системе
	// на весь Watchdog-цикл (до ~45с), а не только при уже установленных, потом умерших соединениях.

	// Sprint 8: запускаем мониторинг трафика через Clash API
	if e.trafficMonitor != nil {
		e.trafficMonitor.Reset()
		e.trafficMonitor.Start(e.currentCtx())
	}

	if e.OnStateChange != nil {
		e.OnStateChange(e.GetState())
	}
	e.log(fmt.Sprintf("Connected! SOCKS5→127.0.0.1:%d  HTTP→127.0.0.1:%d",
		e.cfg.ListenPort, e.cfg.ListenPort+1))

	// P0-8 (аудит 2026-09-01): все четыре post-connect задачи запускаются ЧЕРЕЗ goTracked.
	//
	// Раньше здесь стояли голые `e.wg.Add(1)` — единственные во всём файле, обходившие
	// goTracked (см. её комментарий: она специально проверяет отменённость e.ctx, «иначе
	// wg.Add во время wg.Wait() даёт панику»). Сценарий: «Подключить» (горутина из
	// web/server.go НЕ отслеживается e.wg), через секунду «Отключить» → Stop() отменяет
	// контекст и паркуется в waitGroupWithTimeout; фоновые горутины выходят, счётчик доходит
	// до нуля, Wait ещё не разбужен — и здесь Add(1) даёт
	// panic("sync: WaitGroup misuse: Add called concurrently with Wait") с падением процесса,
	// в том числе службы apf-svc под SYSTEM.
	//
	// Фаза 5: DNS Leak Test после подключения (через 3 сек — дать туннелю встать)
	e.goTracked(e.runPostConnectLeakTest)
	// Фаза 6: Canary-тест (после DNS через 4 сек)
	e.goTracked(e.runPostConnectCanary)
	// Sprint S6: Anti-Block проверка IP
	e.goTracked(func() { e.runPostConnectAntiBlock(node) })
	// T-01/LOT-09: верификация РЕАЛЬНОГО прохождения трафика ЧЕРЕЗ туннель — HTTP через
	// локальный SOCKS5 плюс, в TUN-режиме, прямая проба тем путём, которым ходят приложения.
	// Если движок уже останавливается, goTracked её не запустит — и «проверка идёт»,
	// выставленная строкой 1973 вместе с Connected=true, не разрешилась бы никогда.
	if !e.goTracked(e.runPostConnectHealthCheck) {
		e.resolveDanglingVerifyChecking("движок останавливается — проверка не стартовала")
	}
	// Фаза 7: запускаем Watchdog если ещё не запущен
	if e.watchdog != nil {
		e.watchdog.UpdateProxyAddr(fmt.Sprintf("127.0.0.1:%d", e.cfg.ListenPort))
		e.watchdog.Reset()
	}

	return nil
}

// enableKillSwitchWithUAC — ONE UAC запрос на всю сессию.
//
// bypass-engineer: один диалог Windows вместо четырёх.
// Генерируем PowerShell batch-скрипт со всеми netsh командами
// и запускаем его ОДНИМ вызовом с elevation.
//
// После первого подтверждения ksElevated=true — повторный UAC
// при переключении узлов НЕ показывается.
func (e *Engine) enableKillSwitchWithUAC(node *models.Node, gen uint64) {
	ks := e.currentKS()
	vpnIP := ""
	if node != nil {
		// D-36: в netsh remoteip= уходит IP, не домен. Резолв не удался → KS не включаем.
		ip, err := killswitch.NormalizeEndpointIP(node.Address)
		if err != nil {
			e.abortForKSFailure(gen, fmt.Errorf("адрес узла %q не приведён к IP: %w", node.Address, err))
			return
		}
		vpnIP = ip
	}

	// Windows: используем одиночный UAC через netsh-скрипт
	if wks, ok := ks.(interface {
		EnableWithUAC(string, int) error
	}); ok {
		// ksCall: см. её комментарий — эта горутина отслеживается в e.wg, и повисший здесь
		// WFP-вызов застопорил бы e.wg.Wait() внутри Stop() навсегда.
		err := e.ksCall("EnableWithUAC", ks, func() error { return wks.EnableWithUAC(vpnIP, e.cfg.ListenPort) })
		if err != nil {
			if err == killswitch.ErrUACCancelled {
				// R-2.2 (C-6): НЕ трогаем cfg.EnableKillSwitch и НЕ пишем конфиг — иначе отказ в
				// одном диалоге тихо отключал бы защиту во ВСЕХ будущих сессиях. Помечаем сессию.
				e.setKSDeclinedThisSession(true)
				e.abortForKSFailure(gen, fmt.Errorf("пользователь отклонил запрос прав администратора (UAC)"))
				return
			}
			e.abortForKSFailure(gen, err)
			return
		}
		// T-05: пока ждали подтверждения UAC, подключение могло откатиться или
		// движок — остановиться. Если так, снимаем только что включённый Kill Switch,
		// иначе устройство останется полностью заблокированным без активного туннеля.
		if e.connectionSuperseded(gen) {
			// e.ksCall, не ks.Disable() напрямую (независимая находка аудита 2026-08-19 —
			// эта горутина отслеживается в e.wg через goTracked; повисший здесь WFP-вызов
			// заблокировал бы e.wg.Wait() внутри Stop() навсегда, тем же классом бага, который
			// весь остальной фикс самолечения (ksCall/currentKS) должен был закрыть целиком).
			//
			// S-1 (ТЗ v1.4): ошибка Disable здесь ГЛУШИТСЯ ОСОЗНАННО и это не тот же дефект,
			// что был на пути SetVPNEndpoint. Разница в том, какое состояние безопасно: там
			// движок собирался ВКЛЮЧИТЬ защиту вслепую (без адреса узла в allow-списке) и
			// обязан был отказаться; здесь он уже находится в откате и обязан довести откат до
			// конца — прерваться на первой ошибке значило бы оставить фаервол включённым без
			// туннеля, то есть ровно ту «машину без интернета», от которой откат и спасает.
			// Ошибку не выбрасываем молча: она уходит в лог, чтобы отказ Disable был виден.
			if derr := e.ksCall("Disable", ks, ks.Disable); derr != nil {
				e.log(fmt.Sprintf("KillSwitch: Disable при откате после UAC не удался (%v) — "+
					"продолжаю откат через ksReset, снятие правил обязано дойти до конца", derr))
			}
			e.ksReset()
			e.log("KillSwitch: подключение отменено во время ожидания UAC — Kill Switch снят (защита от блокировки без туннеля)")
			return
		}
		e.setKSElevated(true)
		e.log("✓ KillSwitch: активирован (UAC подтверждён, сессия защищена)")
		// R-6.1: туннель к этому моменту уже поднят — досоздаём permit для apf0.
		if err := e.ensureTunPermit(); err != nil {
			e.abortForKSFailure(gen, err)
		}
		return
	}

	// Linux/Android: нет UAC, применяем напрямую. e.ksCall — та же причина, что и в
	// UAC-ветке выше: единая точка вызова обязана оставаться единой на ВСЕХ платформах,
	// не только там, где сегодня воспроизвёлся живой инцидент (Windows/WFP).
	if err := e.ksCall("Enable", ks, func() error {
		return ks.Enable("apf0", []int{e.cfg.ListenPort})
	}); err != nil {
		e.abortForKSFailure(gen, err)
		return
	}
	if e.connectionSuperseded(gen) {
		// S-1 (ТЗ v1.4): глушение осознанное — см. комментарий у такого же отката в UAC-ветке
		// выше. Откат обязан доработать до конца; ошибка идёт в лог, а не наружу.
		if derr := e.ksCall("Disable", ks, ks.Disable); derr != nil {
			e.log(fmt.Sprintf("KillSwitch: Disable при откате не удался (%v) — "+
				"продолжаю откат через ksReset", derr))
		}
		e.ksReset()
		e.log("KillSwitch: подключение отменено — Kill Switch снят")
		return
	}
	e.setKSElevated(true)
}

// abortForKSFailure реализует fail-closed для АСИНХРОННОГО пути применения KS (R-2.1/D-2).
//
// Синхронный путь возвращает ошибку в applySingBoxConfig и там же откатывается. UAC-путь работает
// в горутине уже после старта туннеля, поэтому обязан снять подключение сам — иначе получалось
// ровно то состояние, которое консилиум назвал худшим: «Connected + пользователь уверен, что KS
// включён + KS фактически выключен» (C-4).
//
// Fail-safe: если подключение уже неактуально (gen устарел) — ничего не трогаем.
// Escape hatch: разовое разрешение пользователя оставляет туннель, но громко и видимо.
func (e *Engine) abortForKSFailure(gen uint64, cause error) {
	if e.connectionSuperseded(gen) {
		e.log(fmt.Sprintf("KillSwitch: %v (подключение уже неактуально — ничего не делаем)", cause))
		return
	}
	if e.isAllowConnectWithoutKS() {
		e.log(fmt.Sprintf("⚠ KillSwitch НЕ применён (%v) — подключение оставлено по явному "+
			"разрешению пользователя. Защиты от утечки НЕТ.", cause))
		return
	}
	e.log(fmt.Sprintf("KillSwitch не применён (%v) — подключение отменяется (fail-closed). "+
		"Разрешить подключение без защиты можно явной кнопкой в UI.", cause))
	e.proc.Stop()
	e.ksReset()
	e.setLastRollback("killswitch_uac", cause, false)
	e.setDisconnected()
	if e.OnStateChange != nil {
		e.OnStateChange(e.GetState())
	}
}

// connectionSuperseded сообщает, что подключение поколения gen больше не актуально:
// движок остановлен (ctx отменён), либо произошёл откат/отключение (connGen изменился),
// либо состояние уже «не подключено». Используется асинхронной UAC-горутиной (T-05),
// чтобы не включать Kill Switch для уже несуществующего туннеля.
func (e *Engine) connectionSuperseded(gen uint64) bool {
	if ctx := e.currentCtx(); ctx != nil && ctx.Err() != nil {
		return true
	}
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()
	return gen != e.connGen || !e.state.Connected
}

// setKSElevated / isKSElevated — потокобезопасный доступ к флагу ksElevated (DEF-06).
// Поле читается/пишется из Stop(), Restart() и асинхронной UAC-горутины; защищаем stateMu,
// как и задекларировано в описании поля (см. struct Engine).
func (e *Engine) setKSElevated(v bool) {
	e.stateMu.Lock()
	e.ksElevated = v
	e.stateMu.Unlock()
}

func (e *Engine) isKSElevated() bool {
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()
	return e.ksElevated
}

// ─── R-2.2 / R-2.1: сессионные флаги Kill Switch (НЕ персистятся) ─────────────

// setKSDeclinedThisSession помечает, что пользователь отклонил UAC в этой сессии (C-6).
// Заменяет прежнюю запись cfg.EnableKillSwitch=false в конфиг: настройку пользователя
// изменяет ТОЛЬКО пользователь, а отказ действует до перезапуска приложения.
func (e *Engine) setKSDeclinedThisSession(v bool) {
	e.stateMu.Lock()
	e.ksDeclinedThisSession = v
	e.stateMu.Unlock()
}

func (e *Engine) isKSDeclinedThisSession() bool {
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()
	return e.ksDeclinedThisSession
}

// SetAllowConnectWithoutKS — escape hatch к fail-closed (D-2/R-2.1): разовое явное разрешение
// подключиться БЕЗ Kill Switch. Вызывается только по прямому действию пользователя в UI.
// НЕ персистится: после перезапуска APF снова действует fail-closed.
func (e *Engine) SetAllowConnectWithoutKS(v bool) {
	e.stateMu.Lock()
	e.allowConnectWithoutKS = v
	e.stateMu.Unlock()
	if v {
		e.log("⚠ Разрешено подключение БЕЗ Kill Switch (только для этой сессии)")
	}
}

func (e *Engine) isAllowConnectWithoutKS() bool {
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()
	return e.allowConnectWithoutKS
}

// KSStatus — наблюдаемое состояние защиты для UI/трея (чтобы отказ KS был ВИДЕН, а не только в логе).
type KSStatus struct {
	Requested        bool   `json:"requested"`          // пользователь включил Kill Switch
	Active           bool   `json:"active"`             // защита реально применена
	Backend          string `json:"backend"`            // "service" | "local"
	SupportsMode     bool   `json:"supports_mode"`      // бэкенд покрывает текущий режим
	Mode             string `json:"mode"`               // текущий режим подключения
	DeclinedUAC      bool   `json:"declined_uac"`       // UAC отклонён в этой сессии
	AllowedWithoutKS bool   `json:"allowed_without_ks"` // действует разовое разрешение без защиты
}

// KillSwitchStatus возвращает наблюдаемое состояние Kill Switch (R-2.1: отказ обязан быть виден).
func (e *Engine) KillSwitchStatus() KSStatus {
	ks := e.currentKS()
	e.ksMu.Lock()
	isSvc := e.ksIsService
	e.ksMu.Unlock()
	backend := "local"
	if isSvc {
		backend = "service"
	}
	// ksIsEnabledWithTimeout, не ks.IsEnabled() напрямую: этот статус читает UI-поллинг
	// (GetState/дашборд) КАЖДУЮ секунду — currentKS() выше уже лечит зависший бэкенд, но
	// только раз в ksProbeTTL; в промежутке кэшированный e.ks мог зависнуть уже ПОСЛЕ
	// последней проверки, и без защиты здесь сам опрос статуса подвесил бы поллинг GUI.
	active, hung := ksIsEnabledWithTimeout(ks)
	if hung {
		e.log("KillSwitch: статус недоступен (бэкенд не отвечает) — считаю неактивным до следующей проверки")
	}
	return KSStatus{
		Requested:        e.cfg.EnableKillSwitch,
		Active:           active,
		Backend:          backend,
		SupportsMode:     ks.Capabilities().SupportsMode(e.cfg.ConnectionMode),
		Mode:             e.ksModeLabel(),
		DeclinedUAC:      e.isKSDeclinedThisSession(),
		AllowedWithoutKS: e.isAllowConnectWithoutKS(),
	}
}

// ─── B-0403 · R-8 (C-14): ОДИН резолв адреса узла на попытку подключения ─────

// resolveEndpointOnce резолвит адрес узла ровно один раз за попытку подключения и запоминает
// результат.
//
//	Вход:      address — домен или IP узла входа.
//	Тело:      killswitch.NormalizeEndpointIPs → все адреса (для правил KS) + один закрепляемый.
//	Выход:     (all — транспортная форма для KS, pinned — один IP для конфигурации sing-box, err).
//	Fail-safe: пустой адрес → ("", "", nil); ошибка резолва → ("", "", err), кэш не обновляется.
//	Инвариант: конфигурация sing-box и правила Kill Switch построены по ОДНОМУ И ТОМУ ЖЕ ответу
//	           резолвера. Два независимых резолва домена с round-robin/GeoDNS могли дать разные
//	           адреса — KS разрешил бы один, а sing-box пошёл бы на другой и был бы заблокирован.
func (e *Engine) resolveEndpointOnce(address string) (all string, pinned string, err error) {
	if address == "" {
		return "", "", nil
	}
	e.endpointMu.Lock()
	if e.endpointFor == address && e.endpointAll != "" {
		all, pinned = e.endpointAll, e.endpointPinned
		e.endpointMu.Unlock()
		return all, pinned, nil
	}
	e.endpointMu.Unlock()

	v4, v6, err := killswitch.NormalizeEndpointIPs(address)
	if err != nil {
		return "", "", err
	}
	joined := append(append([]string{}, v4...), v6...)
	all = strings.Join(joined, ",")
	// Закрепляем IPv4, если он есть: стратегия DNS в конфигурации — prefer_ipv4, и у узлов
	// без v6-связности AAAA-запись может существовать, но не работать.
	if len(v4) > 0 {
		pinned = v4[0]
	} else if len(v6) > 0 {
		pinned = v6[0]
	}

	e.endpointMu.Lock()
	e.endpointFor, e.endpointAll, e.endpointPinned = address, all, pinned
	e.endpointMu.Unlock()
	return all, pinned, nil
}

// prepareEndpoint резолвит адрес узла входа и закрепляет его в билдере ДО сборки конфигурации.
// Ошибка резолва здесь не фатальна: при включённом Kill Switch подключение всё равно будет
// остановлено в applyKillSwitch (fail-closed), а при выключенном — прежнее поведение, когда
// домен резолвит сам sing-box.
func (e *Engine) prepareEndpoint(address string) {
	if address == "" {
		e.builder.SetServerIP("")
		return
	}
	_, pinned, err := e.resolveEndpointOnce(address)
	if err != nil {
		e.builder.SetServerIP("")
		e.log(fmt.Sprintf("Адрес узла %q не резолвится (%v) — IP не закреплён в конфигурации", address, err))
		return
	}
	e.builder.SetServerIP(pinned)
}

// errKSEndpointNotApplied — S-1 (ТЗ v1.4, первоисточник B3): Kill Switch НЕ принял адрес узла в
// список разрешений.
//
// Почему это отдельная ошибка, а не «не удалось резолвить». Резолв и передача адреса бэкенду —
// два разных отказа с разными последствиями. Неразрешимый адрес означает «подключаться некуда»;
// непринятый бэкендом адрес означает «подключаться есть куда, но фаервол об этом не знает» — и
// если поверх этого включить защиту, она заблокирует В ТОМ ЧИСЛЕ сам туннель. Это и есть живой
// инцидент 2026-08-19: WFP-вызов повис на BFE (ksCall сдался по таймауту), ошибка отбрасывалась
// присваиванием в `_`, а routeKillSwitchEnable спокойно включал Kill Switch — «интернета нет
// совсем» до переустановки приложения. Вызывающий обязан отличать эти два случая, поэтому
// маркер, а не просто текст.
var errKSEndpointNotApplied = errors.New("Kill Switch не принял адрес узла в список разрешений")

// setVPNEndpointForKS передаёт в Kill Switch адреса узла (D-36), взятые из ЕДИНОГО резолва (R-8).
// vpn-specialist: Kill Switch должен разрешить трафик к VPN endpoint, иначе заблокирует само
// подключение к туннелю.
//
// Выход: нормализованный адрес и ошибка. Ошибка бывает двух видов и вызывающий обязан их
// различать (errors.Is по errKSEndpointNotApplied): адрес не резолвится либо бэкенд не принял
// адрес. Приоритет у резолва: без IP передавать бэкенду нечего в принципе.
// R-2.3: семейства разделяет бэкенд (splitVPNIPs) — через границу идёт транспортная форма.
func (e *Engine) setVPNEndpointForKS(address string) (string, error) {
	ip, _, err := e.resolveEndpointOnce(address)
	ks := e.currentKS()
	if wks, ok := ks.(interface {
		SetVPNEndpoint(string, int)
	}); ok {
		// ksCall: тот же риск зависшего WFP-вызова, что у Enable/Disable (см. её комментарий) —
		// эта функция вызывается под connMu (applyKillSwitch → applySingBoxConfig), повисший
		// здесь syscall застопорил бы ЛЮБОЕ последующее подключение/переключение узла.
		//
		// S-1: результат ksCall БОЛЬШЕ НЕ выбрасывается. Единственный источник ошибки здесь —
		// таймаут ksCall (сама SetVPNEndpoint значения не возвращает), то есть ровно сценарий
		// зависшего BFE из инцидента 2026-08-19.
		if kerr := e.ksCall("SetVPNEndpoint", ks, func() error {
			wks.SetVPNEndpoint(ip, e.cfg.ListenPort)
			return nil
		}); kerr != nil && err == nil {
			err = fmt.Errorf("%w: %w", errKSEndpointNotApplied, kerr)
		}
	}
	return ip, err
}

// ─── B-0403 · R-1.2 / R-2.1 / R-4.2: маршрутизация Kill Switch ────────────────

// ksProbeTTL — период переоценки доступности служебного KS-канала (R-4.2/C-7).
// Достаточно мал, чтобы поздний старт службы (DelayedAutoStart) подхватился за секунды, и
// достаточно велик, чтобы не дёргать named-pipe на каждый вызов.
const ksProbeTTL = 5 * time.Second

// ksNeedsTunMode сообщает, уходит ли трафик приложений через TUN (режимы VPN/Hybrid).
func (e *Engine) ksNeedsTunMode() bool {
	return e.cfg.ConnectionMode == models.ModeVPN || e.cfg.ConnectionMode == models.ModeHybrid
}

// currentKS возвращает актуальный бэкенд Kill Switch, лениво переоценивая выбор (R-4.2/C-7).
//
// Тело: не чаще раза в ksProbeTTL пробуем служебный канал.
//   - АКТИВНЫЙ KS никогда не подменяется: иначе уже поставленные правила остались бы бесхозными,
//     а Disable ушёл бы «не туда» (это и есть класс дефекта C-3).
//   - служба появилась → переходим на неё; служба умерла → откатываемся на локальный бэкенд;
//   - локальный бэкенд пересоздаётся, только если он не покрывает текущий режим подключения
//     (например, пользователь переключил proxy → VPN, а выбран был netsh).
//
// Инвариант: движок никогда не остаётся с клиентом мёртвой службы.
func (e *Engine) currentKS() killswitch.KillSwitch {
	e.ksMu.Lock()
	defer e.ksMu.Unlock()
	if e.ks != nil && time.Since(e.ksProbedAt) < ksProbeTTL {
		return e.ks
	}
	e.ksProbedAt = time.Now()
	if e.ks != nil {
		// Живой инцидент 2026-08-19 (второй раунд, после ksCallWithTimeout): IsEnabled() тоже
		// берёт k.mu бэкенда (wfp_windows.go) — если предыдущий Enable()/SetVPNEndpoint() на
		// ЭТОМ ЖЕ бэкенде завис на BFE (см. комментарий у ksCallTimeout), k.mu остаётся
		// захвачен НАВСЕГДА брошенной горутиной. Обычный вызов IsEnabled() здесь застрял бы
		// вместе с ним — а поскольку currentKS() держит e.ksMu на всё своё тело, это заодно
		// подвесило бы e.ksMu для ЛЮБОГО другого вызывающего (ksDisable/ksReset/PatchConfig и
		// т.п. тоже проходят через currentKS()) — то есть один зависший WFP-вызов глушил бы
		// ВЕСЬ Kill Switch навсегда, а не только текущую попытку. inlineKSTimeout здесь короче
		// основного ksCallTimeout (это лёгкая проверка, не боевая операция) — не пересоздаём
		// бэкенд ПОД АКТИВНЫМ подключением зря, но и не ждём долго.
		enabled, hung := ksIsEnabledWithTimeout(e.ks)
		if hung {
			e.log("KillSwitch: бэкенд не отвечает (похоже, зависла системная служба фильтрации " +
				"BFE) — пересоздаю, не дожидаясь и не трогая зависшую попытку")
			e.ks, e.ksIsService = killswitch.NewLocalBackend(e.ksNeedsTunMode()), false
			return e.ks
		}
		if enabled {
			return e.ks // KS активен — менять исполнителя нельзя
		}
	}
	// ksSelfService: этот процесс сам обслуживает \\.\pipe\APF-KS — не звоним в свой же пайп
	// (см. комментарий у поля ksSelfService; инцидент 2026-08-19, P0.1 в
	// docs/TZ_WINDOWS_CONSILIUM_FINDINGS_v1.0.md).
	if !e.ksSelfService {
		if svc, ok := killswitch.NewServiceClient(); ok {
			if !e.ksIsService {
				e.log("KillSwitch: обнаружена служба APF — операции выполняются через неё (без UAC)")
			}
			e.ks, e.ksIsService = svc, true
			return e.ks
		}
	}
	if e.ksIsService {
		e.log("KillSwitch: служба APF недоступна — переключаюсь на локальный бэкенд")
	} else if e.ks != nil && e.ks.Capabilities().SupportsMode(e.cfg.ConnectionMode) {
		return e.ks // локальный бэкенд уже подходит под режим — не пересоздаём
	}
	e.ks, e.ksIsService = killswitch.NewLocalBackend(e.ksNeedsTunMode()), false
	return e.ks
}

// applyKillSwitch — единственная точка применения Kill Switch при подключении (R-1.2 + R-2.1).
//
// Вход:  node — узел подключения (nil для цепочки).
// Тело:  1) capability-gate: бэкенд обязан уметь защитить ТЕКУЩИЙ режим (иначе C-1: netsh в
//
//	VPN-режиме «работает», но блокирует весь трафик пользователя);
//	2) резолв адреса узла в IP (D-36);
//	3) применение по привилегированному пути (служба → admin → один UAC).
//
// Выход: nil — защита применена (или заявлена и подтверждается асинхронно на UAC-пути);
//
//	error — защиту применить НЕЛЬЗЯ; вызывающий обязан отменить подключение (fail-closed).
//
// killSwitchUnsupportedModeHint — платформенно-зависимое объяснение к капабилити-гейту Kill
// Switch (ТЗ v1.3, живой отчёт пользователя 2026-09-05): раньше это была одна строка про
// «WFP/службу APF/администратора» на ВСЕ платформы разом — Android-пользователь, у которого
// не включена системная Always-on VPN защита, вместо понятной причины видел упоминание
// Windows-службы и прав администратора, к его телефону не имеющих отношения.
func killSwitchUnsupportedModeHint() string {
	switch runtime.GOOS {
	case "android":
		return "на Android эту защиту даёт только системная настройка «Always-on VPN» + " +
			"«Блокировать соединения без VPN» (Настройки → Сеть → VPN); сейчас она выключена " +
			"или не покрывает этот режим подключения — приложение включить её само не может"
	case "windows":
		return "нужен WFP: установите службу APF или запустите от администратора. " +
			"Подробности: netsh не умеет разрешать трафик по интерфейсу туннеля"
	case "linux":
		return "нужны права на управление iptables/nftables (обычно root)"
	default:
		return "этот бэкенд Kill Switch не поддерживает выбранный режим на данной платформе"
	}
}

// ksExtraResolveBudget — общий бюджет на ПАРАЛЛЕЛЬНЫЙ резолв ДОП-адресов Kill Switch (участники
// гонки + bypass-домены). Чуть больше внутреннего таймаута net-резолвера
// (killswitch.lookupDNSTimeout = 5с), чтобы захватить укладывающиеся в него резолвы и залогировать
// каждый провал поимённо, но не ждать зависших дольше. var, а не const — тесты вправе укоротить.
// Диагностика живого лога ПК 2026-09-09: последовательный резолв доп-адресов давал 15–25 с простоя
// на КАЖДОМ переключении узла (сам Reload туннеля ~1с), снаружи — «система очень долго ищет узел».
var ksExtraResolveBudget = 6 * time.Second

// resolveKillSwitchExtras резолвит ДОП-адреса Kill Switch для entry — адреса остальных участников
// гонки узлов И bypass-домены с прямым маршрутом (оба уже собраны и дедуплицированы в
// killSwitchAddressesFor) — и возвращает успешно резолвнутые IP.
//
// Эти адреса «по возможности»: не резолвнулись — конкретный кандидат/обход не участвует, но
// подключение к точке входа не срывается (fail-safe). Раньше их резолвили ДВА последовательных
// цикла (гонка, затем bypass), причём bypass-домены — дважды, а неуспешный резолв не кэшируется
// (resolveEndpointOnce выходит с ошибкой ДО записи кэша). При недоступном DNS — ровно когда его и
// ждёшь недоступным (рабочего узла нет, автопереключение перебирает кандидатов) — каждый адрес
// выжигал полный таймаут резолвера ПОСЛЕДОВАТЕЛЬНО. Теперь все резолвы идут ПАРАЛЛЕЛЬНО под общим
// бюджетом ksExtraResolveBudget: суммарно ~один таймаут вместо N.
//
// Живой инцидент 2026-08-25 (bypass): домены с DirectRoute (Госуслуги/банки — bypass.Manager)
// sing-box матчит на route(direct) и уводит В ОБХОД туннеля, но при включённом Kill Switch каждая
// такая попытка падала "connectex: forbidden by access permissions" — KS разрешал только адреса
// узла (+участников гонки), а DirectRoute-домен стучится на другой IP. Поэтому его адрес тоже
// вносим в allow-список. Ограничение: резолвим один раз, тем же upstream (8.8.8.8), что и sing-box;
// сайт за CDN/GeoDNS может позже ответить IP вне списка.
func (e *Engine) resolveKillSwitchExtras(entry *models.Node) []string {
	extras := e.killSwitchAddressesFor(entry)
	if len(extras) <= 1 {
		return nil
	}
	extras = extras[1:] // [0] — адрес точки входа: резолвится отдельно и обязателен

	bypassSet := make(map[string]bool)
	if e.bypassManager != nil {
		for _, d := range e.bypassManager.DirectRouteDomains() {
			bypassSet[d] = true
		}
	}

	resolve := e.ksExtraResolver
	if resolve == nil {
		resolve = func(addr string) (string, error) {
			ip, _, err := e.resolveEndpointOnce(addr)
			return ip, err
		}
	}

	type ksResolve struct {
		addr string
		ip   string
		err  error
	}
	// Буфер на весь список: каждая запущенная горутина шлёт ровно один результат и не блокируется,
	// даже если мы перестали читать после срабатывания бюджета (зависшая горутина завершится сама
	// в пределах внутреннего таймаута резолвера и учтена в e.wg).
	results := make(chan ksResolve, len(extras))
	pending := 0
	for _, addr := range extras {
		addr := addr
		if e.goTracked(func() {
			ip, err := resolve(addr)
			results <- ksResolve{addr: addr, ip: ip, err: err}
		}) {
			pending++
		}
	}

	var out []string
	budget := time.NewTimer(ksExtraResolveBudget)
	defer budget.Stop()
	for pending > 0 {
		select {
		case r := <-results:
			pending--
			if r.err != nil || r.ip == "" {
				if bypassSet[r.addr] {
					e.log(fmt.Sprintf("Kill Switch: bypass-домен %q не резолвится (%v) — "+
						"обход для него не будет разрешён", r.addr, r.err))
				} else {
					e.log(fmt.Sprintf("Kill Switch: адрес участника гонки %q не резолвится (%v) — "+
						"кандидат не будет разрешён", r.addr, r.err))
				}
				continue
			}
			out = append(out, r.ip)
		case <-budget.C:
			e.log(fmt.Sprintf("Kill Switch: резолв доп-адресов не уложился в %s — разрешено %d "+
				"(остальные добавятся при следующем применении)", ksExtraResolveBudget, len(out)))
			return out
		}
	}
	return out
}

// Инвариант: не существует состояния «KS применён бэкендом, не поддерживающим текущий режим».
func (e *Engine) applyKillSwitch(node *models.Node, chain *models.Chain) error {
	// N-8 (§3 DIAG_N8_PLAN.md): главный индикатор KS-фикса — ожидаем ~1с (было 15-25с до
	// resolveKillSwitchExtras, см. §1.2). defer покрывает все ранние return (S-1 отказы и успех).
	t0 := time.Now()
	defer func() { e.logDiagN8("applyKillSwitch", t0) }()
	ks := e.currentKS()
	caps := ks.Capabilities()
	if !caps.SupportsMode(e.cfg.ConnectionMode) {
		return fmt.Errorf("Kill Switch не может защитить режим %q этим бэкендом (%s)",
			e.ksModeLabel(), killSwitchUnsupportedModeHint())
	}
	// Расширение того же инварианта (R-1.1/R-2.1) на ещё один случай, найденный
	// инцидентом 2026-08-19 (docs/TZ_CONFIG_RELOAD_AND_KS_SAFETY_v1.0.md, причина B):
	// в proxy-режиме netsh-бэкенд защищает трафик фильтрацией по адресу назначения
	// (allow только к IP узла), а ПОСЛЕДНЕЙ командой ставит глобальную политику
	// blockinbound,blockoutbound для ВСЕХ процессов. Это безопасно только если ОС
	// реально направляет трафик приложений через локальный SOCKS/HTTP прокси —
	// иначе Kill Switch не защищает НИЧЕГО (туннель ничего не тянет), а рвёт вообще
	// весь интернет системы, независимо от того, поднимется ли сам туннель. Поэтому
	// в proxy-режиме без системного прокси Kill Switch тоже трактуется как «этот
	// бэкенд не может честно защитить текущую конфигурацию» — отказ, а не тихая
	// блокировка без пользы.
	//
	// НЕ на Android (живой отчёт пользователя 2026-09-05): «Системный прокси» — понятие
	// netsh-бэкенда (Windows), androidKS.Enable() вообще не фильтрует пакеты сам и не
	// зависит от того, направлена ли через SOCKS обычная система — его Capabilities() уже
	// целиком отражают реальную защиту (Always-on VPN + lockdown), проверенную гейтом выше.
	// Требовать несуществующую на телефоне настройку «Системный прокси» означало бы
	// заблокировать подключение пользователю, у которого защита и так честно есть.
	if runtime.GOOS != "android" && !e.ksNeedsTunMode() && !e.cfg.SetSystemProxy {
		return fmt.Errorf("Kill Switch в режиме прокси без включённого системного прокси " +
			"заблокирует ВЕСЬ трафик системы, а не только цель (обычные приложения идут " +
			"напрямую, минуя туннель, и не попадают в список разрешений firewall) — включите " +
			"«Системный прокси» в настройках или выключите Kill Switch")
	}
	// R-8: для цепочки хост физически подключается только к ТОЧКЕ ВХОДА. Раньше сюда приходил
	// node==nil, разрешающее правило не создавалось вовсе, и при default-block-outbound цепочка
	// не могла подняться в принципе — «Kill Switch включён» означало «связи нет».
	entry := node
	if entry == nil {
		entry = singbox.ChainEntryNode(chain)
	}
	if entry != nil {
		// Адрес точки входа обязателен: если он не резолвится, подключаться некуда.
		// Адреса остальных участников гонки — «по возможности»: их отсутствие означает лишь
		// то, что конкретный кандидат не поучаствует, а не провал всего подключения.
		ip, err := e.setVPNEndpointForKS(entry.Address)
		if err != nil {
			// S-1 (ТЗ v1.4): два разных отказа — два разных объяснения пользователю.
			// «Бэкенд не принял адрес» — это НЕ повод включить защиту всё равно: fail-closed
			// здесь означает «не трогать сеть» (интернет остаётся живым, защиты нет и об этом
			// сказано), а не «заблокировать всё» — именно вторая трактовка и дала инцидент
			// 2026-08-19, когда Kill Switch включался поверх пустого allow-списка.
			if errors.Is(err, errKSEndpointNotApplied) {
				return fmt.Errorf("Kill Switch не включён: адрес узла %q не удалось внести в "+
					"список разрешений (%w) — включение защиты поверх пустого списка отрезало "+
					"бы весь трафик, включая сам туннель", entry.Address, err)
			}
			// Адрес узла не резолвится — отказ именно этого узла (ТЗ HOTSWITCH §8 A1): узлы с
			// другими адресами подключиться могут, перебор должен идти дальше.
			return markNodeFailure(fmt.Errorf("адрес узла %q не приведён к IP: %w", entry.Address, err))
		}
		ips := []string{ip}
		// Резолв ДОП-адресов (участники гонки + bypass-домены) вынесен в
		// resolveKillSwitchExtras: теперь ПАРАЛЛЕЛЬНО и с общим бюджетом. Прежние два
		// последовательных цикла на реальном ПК давали 15–25 с простоя перед reload на
		// каждом переключении узла (диагностика живого лога 2026-09-09).
		ips = append(ips, e.resolveKillSwitchExtras(entry)...)
		joined := strings.Join(ips, ",")
		if len(ips) > 1 {
			// Передаём весь список одной строкой: бэкенд Kill Switch уже умеет её разбирать
			// (killswitch.splitVPNIPs делит по запятой и раскладывает по семействам).
			if _, err := e.setVPNEndpointForKSList(joined); err != nil {
				return fmt.Errorf("не удалось разрешить адреса группы: %w", err)
			}
		}
		e.vpnEndpoint = joined
	}
	return e.routeKillSwitchEnable(entry)
}

// setVPNEndpointForKSList — то же, что setVPNEndpointForKS, но принимает уже готовый
// список IP через запятую (адреса всех участников гонки), без повторного резолва.
//
// S-1 (ТЗ v1.4): результат ksCall тоже возвращается наружу, а не выбрасывается в `_`. Раньше
// функция объявляла возвращаемую ошибку и ВСЕГДА отдавала nil — вызывающий (applyKillSwitch)
// проверял её добросовестно, но проверять было нечего.
func (e *Engine) setVPNEndpointForKSList(ips string) (string, error) {
	ks := e.currentKS()
	if wks, ok := ks.(interface {
		SetVPNEndpoint(string, int)
	}); ok {
		if err := e.ksCall("SetVPNEndpoint", ks, func() error {
			wks.SetVPNEndpoint(ips, e.cfg.ListenPort)
			return nil
		}); err != nil {
			return ips, fmt.Errorf("%w: %w", errKSEndpointNotApplied, err)
		}
	}
	return ips, nil
}

// maxProbeAllowIPs — потолок числа IP кандидатов, для которых открывается временное probe-окно
// сквозь Windows KS (долг-5). Одно netsh-правило кодирует адреса в remoteip=<CSV>; тысячи IP
// (режим «Все рабочие», models.NodeCheckTopNAll) вышли бы за лимит длины команды и правило бы не
// встало (см. дизайн-ограничение в docs/TZ_WINDOWS_CONSILIUM_FINDINGS_v1.0.md §454-498). Если
// кандидатов волны больше потолка — окно НЕ открываем, оставляя честное предупреждение P0-2
// (отключиться и пересканировать), а не тихо проваливаем «хвост». 256 IPv4 ≈ 4 КБ CSV — с
// запасом внутри ~8 КБ лимита строки netsh; покрывает все числовые пресеты глубины (≤300 всё
// равно почти всегда IPv4 и укладывается, а «Все рабочие» сознательно уходит в деградацию).
const maxProbeAllowIPs = 256

// openKSProbeWindow — долг-5 (2026-09-21): открыть на время ОДНОЙ волны трафик-пробы скана
// временное окно сквозь активный Windows Kill Switch к IP кандидатов и вернуть функцию-снятие
// (для defer в probeCandidates) ИЛИ nil, если окно открывать не нужно/нельзя. При УСПЕХЕ снимает
// ложное предупреждение P0-2 (проба пойдёт честно с хоста); при невозможности — гарантирует, что
// честное предупреждение показано (отключиться/выключить KS). Каждая волна вызывает сама за себя →
// последняя волна оставляет предупреждение в состоянии, соответствующем реальности.
//
// Почему безопасно (вердикт консилиума ACCEPT-WITH-FIXES): аддитивные узкие allow-правила ТОЛЬКО
// к IP узлов-кандидатов (которые пользователь и так тестирует); базовый allow-list и blockoutbound
// НЕ трогаются; снятие гарантируется defer'ом + суффиксы -allow-probe* входят в windowsRuleSuffixes
// (их снимет любая очистка/аварийный сброс KS, если defer почему-то не отработал). Windows-
// специфично: Android-KS — OS-level (Always-on VPN), per-endpoint allow там нет, проба не
// блокируется; WFP-бэкенд (VPN/Hybrid) ProbeAllower пока НЕ реализует → окно не открывается,
// честное предупреждение остаётся (ТЗ §480-483 явно санкционирует деградацию).
func (e *Engine) openKSProbeWindow(candidates []*models.Node) func() {
	if e.probeGOOS() != "windows" || !e.killSwitchEnabledNow() {
		return nil // KS не в игре — проба и так идёт egress хоста напрямую, предупреждения нет
	}
	ks := e.currentKS()
	pa, ok := ks.(killswitch.ProbeAllower)
	if !ok || len(candidates) == 0 || len(candidates) > maxProbeAllowIPs {
		// Дешёвая отсечка ДО резолва адресов: бэкенд без ProbeAllower (WFP/VPN) ИЛИ кандидатов
		// волны больше потолка (режим «Все рабочие», тысячи узлов) — окно не открываем, остаётся
		// честное предупреждение P0-2 (отключиться и пересканировать).
		e.ensureKillSwitchProbeWarning()
		return nil
	}
	ips := probeCandidateIPs(candidates)
	if len(ips) == 0 || len(ips) > maxProbeAllowIPs {
		// Ни один адрес не привёлся к IP (напр. хостнеймы не резолвятся под активным KS), либо
		// после резолва dual-stack адресов их стало больше потолка — оставляем предупреждение.
		e.ensureKillSwitchProbeWarning()
		return nil
	}
	if err := e.ksCall("AllowProbeTargets", ks, func() error { return pa.AllowProbeTargets(ips) }); err != nil {
		e.log("[killswitch] не удалось открыть окно пробы сквозь Kill Switch: " + err.Error() +
			" — оставляю предупреждение, часть узлов может показаться нерабочей")
		_ = e.ksCall("ClearProbeTargets", ks, func() error { return pa.ClearProbeTargets() }) // откат частичного
		e.ensureKillSwitchProbeWarning()
		return nil
	}
	// Окно открыто — проба сиблингов пойдёт честно, ложное предупреждение больше не верно.
	e.clearKillSwitchProbeWarning()
	return func() {
		_ = e.ksCall("ClearProbeTargets", ks, func() error { return pa.ClearProbeTargets() })
	}
}

// probeCandidateIPs — уникальные IP, к которым probe-правило KS должно разрешить исходящее, из
// адресов кандидатов. Node.Address — это ХОСТ (порт отдельным полем Node.Port), может быть голым
// IP или хостнеймом. Приводим тем же примитивом, что базовый KS (killswitch.NormalizeEndpointIPs
// через resolveEndpointOnce): голый IP отдаётся без сети, хостнейм резолвится в IP (обе семьи).
// Не привёлся (хостнейм не резолвится — в т.ч. если DNS сам режется активным KS) — узел просто не
// попадёт в окно (проба его покажет нерабочим, как и без фикса; честнее, чем врать про allow).
// Резолв последовательный: вызывается только когда кандидатов ≤ maxProbeAllowIPs (см.
// openKSProbeWindow), в пуле подавляющее большинство — голые IP (сети не требуют).
func probeCandidateIPs(candidates []*models.Node) []string {
	seen := make(map[string]bool, len(candidates))
	out := make([]string, 0, len(candidates))
	for _, n := range candidates {
		if n == nil {
			continue
		}
		v4, v6, err := killswitch.NormalizeEndpointIPs(strings.TrimSpace(n.Address))
		if err != nil {
			continue
		}
		for _, ip := range append(append([]string{}, v4...), v6...) {
			if ip == "" || seen[ip] {
				continue
			}
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out
}

// killSwitchAddressesFor — какие адреса Kill Switch обязан разрешить для этого подключения.
//
// Обычно это ровно один узел. Но при включённой «гонке узлов» sing-box держит соединения
// СО ВСЕМИ участниками группы (см. singbox.Builder.BuildRace), и если разрешить только
// один адрес, остальные кандидаты будут заблокированы самим Kill Switch: их пробы
// провалятся, группа выродится в один узел — а если именно он и окажется мёртвым, связи не
// будет вовсе. То есть без этого учёта включённый Kill Switch делал бы «гонку» не просто
// бесполезной, а ХУДШЕ обычного режима.
//
// Список остаётся закрытым (разрешены только адреса участников группы) — это не ослабление
// Kill Switch, а приведение его разрешений в соответствие с тем, куда движок реально ходит.
func (e *Engine) killSwitchAddressesFor(entry *models.Node) []string {
	if entry == nil {
		return nil
	}
	addrs := []string{entry.Address}
	e.mu.RLock()
	race := e.raceNodes
	e.mu.RUnlock()
	seen := map[string]bool{entry.Address: true}
	for _, n := range race {
		if n == nil || seen[n.Address] {
			continue
		}
		seen[n.Address] = true
		addrs = append(addrs, n.Address)
	}

	// Домены, которые пользователь сознательно вывел из-под VPN (bypass с прямым маршрутом).
	//
	// Без этого включённое правило «прямой маршрут» при включённом Kill Switch давало
	// результат, ПРОТИВОПОЛОЖНЫЙ ожидаемому: трафик к домену уходит с физического интерфейса,
	// не совпадает ни с одним разрешением (разрешены только loopback, локальная сеть и адрес
	// узла), и терминальное правило «блокировать всё» его глушит. То есть сайт, ради которого
	// правило и включали, переставал открываться ВООБЩЕ — ни через VPN, ни напрямую, и молча
	// (найдено ревью 2026-08-24).
	//
	// Ограничение честное: разрешаются адреса, известные на момент подключения. Домены с
	// CDN/GeoDNS могут отвечать другими адресами позже — тогда часть запросов всё же упрётся
	// в Kill Switch. Полное решение требует отслеживания DNS-ответов на лету.
	if e.bypassManager != nil {
		for _, d := range e.bypassManager.DirectRouteDomains() {
			if d == "" || seen[d] {
				continue
			}
			seen[d] = true
			addrs = append(addrs, d)
		}
	}
	return addrs
}

// ksModeLabel — человекочитаемое имя режима для сообщений.
func (e *Engine) ksModeLabel() string {
	if e.cfg.ConnectionMode == "" {
		return models.ModeProxy
	}
	return e.cfg.ConnectionMode
}

// ensureTunPermit досоздаёт permit-правило для TUN после старта sing-box (R-6.1/C-10).
//
// Тело: только для TUN-режимов и только если KS включён. Интерфейс apf0 появляется не мгновенно,
// поэтому пробуем несколько раз с паузой. Бэкенды без allow-by-interface сюда не попадают —
// их отсекает capability-gate в applyKillSwitch.
// Выход: nil — permit-tun гарантированно есть либо не требуется; error — VPN-трафик заблокирован.
func (e *Engine) ensureTunPermit() error {
	if !e.cfg.EnableKillSwitch || !e.ksNeedsTunMode() {
		return nil
	}
	ks := e.currentKS()
	ensurer, ok := ks.(interface{ EnsureTunPermit(string) error })
	if !ok {
		return nil // бэкенд не нуждается в отдельном permit (linux: правило по имени интерфейса)
	}
	// ksIsEnabledWithTimeout, не ks.IsEnabled() напрямую: тот же риск зависшего WFP-вызова —
	// эта проверка вне currentKS(), её никто больше не защищает.
	enabled, hung := ksIsEnabledWithTimeout(ks)
	if hung {
		return fmt.Errorf("killswitch: IsEnabled не ответил за %s — бэкенд, похоже, завис", ksProbeTimeout)
	}
	if !enabled {
		return nil // KS ещё применяется асинхронно (UAC-путь) — permit поставит сам путь
	}
	var last error
	for i := 0; i < tunPermitAttempts; i++ {
		// ksCall: тот же риск, что и у Enable/Disable (см. её комментарий) — сам WFP-вызов
		// внутри EnsureTunPermit может зависнуть на BFE, а без внешнего таймаута это
		// застопорило бы весь retry-цикл на первой же попытке, а не просто одну попытку.
		if last = e.ksCall("EnsureTunPermit", ks, func() error { return ensurer.EnsureTunPermit("apf0") }); last == nil {
			return nil
		}
		select {
		case <-e.currentCtx().Done():
			return last
		case <-time.After(tunPermitRetryPause):
		}
	}
	return fmt.Errorf("permit для TUN не поставлен: %w", last)
}

// Параметры ожидания появления apf0 (интерфейс создаётся sing-box уже после старта процесса).
var (
	tunPermitAttempts   = 10
	tunPermitRetryPause = time.Second
)

// routeKillSwitchEnable выбирает привилегированный путь применения Kill Switch (D-32):
//   - служба (Вариант A): по named-pipe, без UAC, работает и на switch узла, recovery — на службе;
//   - процесс admin: применяем напрямую;
//   - не admin, первый раз: один UAC асинхронно (goTracked, T-25/D-35);
//   - не admin, уже элевировались, службы нет: честная деградация.
//
// R-2.1: любой отказ теперь возвращается ошибкой (fail-closed), а не пишется в лог как warning.
func (e *Engine) routeKillSwitchEnable(node *models.Node) error {
	ks := e.currentKS()
	if e.ksIsService {
		if err := e.ksCall("Enable", ks, func() error {
			return ks.Enable("apf0", []int{e.cfg.ListenPort})
		}); err != nil {
			return fmt.Errorf("служба APF не применила Kill Switch: %w", err)
		}
		e.setKSElevated(true)
		return nil
	}
	if killswitch.IsAdmin() {
		if err := e.ksCall("Enable", ks, func() error {
			return ks.Enable("apf0", []int{e.cfg.ListenPort})
		}); err != nil {
			return fmt.Errorf("Kill Switch не применён: %w", err)
		}
		e.setKSElevated(true)
		return nil
	}
	if e.isKSDeclinedThisSession() {
		// R-2.2 (C-6): пользователь уже отказал в UAC в этой сессии — не спрашиваем повторно,
		// но и НЕ делаем вид, что защита есть.
		return fmt.Errorf("Kill Switch требует прав администратора, а UAC был отклонён в этой сессии")
	}
	if !e.isKSElevated() {
		// Первый раз — запрашиваем UAC асинхронно (ОДИН раз за сессию). При отказе/сбое
		// горутина обязана снять подключение (R-2.1), а не просто залогировать.
		e.log("KillSwitch: запрашиваю права администратора (UAC)...")
		e.stateMu.RLock()
		gen := e.connGen
		e.stateMu.RUnlock()
		// D-35: отслеживаемая горутина (учтена в e.wg, не стартует при отменённом ctx).
		nodeCopy := node
		e.goTracked(func() { e.enableKillSwitchWithUAC(nodeCopy, gen) })
		return nil
	}
	// D-32 честная деградация: элевировались ранее, но процесс не admin и службы APF нет.
	return fmt.Errorf("смена узла без прав администратора и без службы APF: правила Kill Switch " +
		"нельзя обновить для нового IP (установите службу apf-svc)")
}

// ksReset — единая точка быстрого сброса правил APF (R-4.1/C-3).
//
// Раньше движок звал killswitch.QuickReset() напрямую из 7 мест: на служебном пути это выполняло
// netsh ВНУТРИ неадминского процесса (молча падало), а админский трей мог снести правила живой
// службы. Теперь сброс идёт тем же маршрутом, что и применение.
// Инвариант: не существует пути, изменяющего фаервол в обход выбранного бэкенда.
// ksCallTimeout — сколько максимум Stop()/Connect() ждут ОДНУ операцию KS-бэкенда (Enable/
// Disable/Reset/ResetAll), прежде чем сдаться и продолжить без неё.
//
// Живой инцидент 2026-08-19 (docs/TZ_WINDOWS_CONSILIUM_FINDINGS_v1.0.md): это первый раунд, где
// WFP-бэкенд реально заработал (P0.1 — раньше self-dial подменял его на netsh ещё до старта).
// FwpmEngineOpen0/FwpmTransactionBegin0 и другие WFP-вызовы (wfp_windows.go) — синхронные
// системные вызовы к BFE (Base Filtering Engine) через RPC, БЕЗ таймаута на уровне Go: если BFE
// подвисает (перегружен, застрял на прошлой сессии и т.п.), наш код блокируется вместе с ним —
// НАВСЕГДА, поскольку Go не умеет прервать уже начавшийся синхронный syscall.
//
// ВТОРОЙ РАУНД того же инцидента (позже в тот же день): первая версия этого таймаута просто
// СДАВАЛАСЬ ЖДАТЬ, не трогая сам зависший бэкенд — а зависшая горутина внутри fn держит
// wfpKS.mu (wfp_windows.go) НАВСЕГДА. Любой следующий вызов к ТОМУ ЖЕ бэкенду (в т.ч. просто
// IsEnabled() внутри currentKS()) тоже блокируется на этом mu — то есть каждая ПОСЛЕДУЮЩАЯ
// попытка пользователя переподключиться тоже виснет (или тоже сдаётся через 8с, но результат
// всё равно «не работает, повторно запустить не смог») — единственным способом освободить
// систему по-прежнему оставалось полное удаление приложения (убивает процесс → dynamic-сессия
// WFP закрывается сама). Таймаут БЕЗ самолечения не восстанавливает работоспособность, только
// делает зависание видимым раз, а не бесконечным.
//
// Поэтому теперь при таймауте бэкенд не просто «бросается» — он немедленно ЗАМЕНЯЕТСЯ свежим
// (e.ks) под e.ksMu, если с момента вызова его никто не заменил раньше нас. Старая, зависшая
// горутина внутри fn остаётся жить сама по себе (Go не может её прервать) вместе со своим
// mu — но её больше никто не спрашивает: все будущие операции идут через новый, чистый
// бэкенд/новую WFP-сессию. Это единственный доступный вариант самолечения без падения процесса.
//
// var, не const: тесты укорачивают её (test-seam, тот же паттерн, что osUserHomeDirFn и
// подобные в internal/config) — иначе проверка реального таймаута ждала бы настоящие 8с.
var ksCallTimeout = 8 * time.Second

// wgWaitTimeout — сколько максимум Stop()/Restart() ждут e.wg.Wait() (все goTracked-горутины:
// emergencySwitch, enableKillSwitchWithUAC и т.п.), прежде чем сдаться и продолжить закрытие
// движка без них.
//
// Живой инцидент 2026-08-25: пользователь сообщил, что apf-svc.exe не убивается ни при
// удалении, ни при переустановке (NSIS `net stop APFService` отрабатывает, `Sleep 1000`,
// но файл всё равно занят — Task Manager показывает процесс живым, 0% CPU, то есть не
// зависший в busy-loop, а именно ЗАБЛОКИРОВАННЫЙ). Корень — ksCall/ksIsEnabledWithTimeout
// защищают ОДНУ операцию KS-бэкенда (см. её комментарий), но САМ e.wg.Wait() в Stop()/
// Restart() вызывался БЕЗ какого-либо таймаута: если goTracked-горутина (emergencySwitch от
// Watchdog, сработавший за часы непрерывной работы службы, или enableKillSwitchWithUAC) сама
// зависла на чём-то, что не входит в защиту ksCall (сетевой вызов без учёта ctx, ожидание UAC,
// которое никто не подтвердит на службе без интерактивного пользователя, и т.п.) —
// svc.Handler.Execute() в cmd/apf-svc НИКОГДА не доходил до `resp <- svc.Status{State:
// svc.Stopped}`, SCM никогда не видел Stopped, `net stop` не мог довести дело до конца, и
// процесс оставался держать файл apf-svc.exe открытым бесконечно. Тот же класс бага, для
// которого уже был сделан ksCall (Go не может прервать чужой синхронный вызов) — но на
// уровень выше: сдаться и продолжить закрытие, а не ждать вечно.
var wgWaitTimeout = 15 * time.Second

// waitGroupWithTimeout ждёт wg не дольше timeout. Возвращает true, если группа завершилась
// сама (все горутины вышли), false — если сдались по таймауту (недожатые горутины продолжают
// жить сами по себе, ровно как зависшая горутина внутри ksCall, — вызывающий код обязан
// считать движок остановленным в любом случае, не блокировать закрытие приложения/службы ими).
func waitGroupWithTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// ksCall — единая точка вызова операции КОНКРЕТНОГО экземпляра KS-бэкенда (ks — то, что вернул
// currentKS() непосредственно перед этим вызовом) с защитой от зависания и самолечением (см.
// комментарий у ksCallTimeout). ks передаётся явно (не берётся заново из e.ks), чтобы после
// таймаута можно было сравнить «это ещё тот же бэкенд, что мы вызывали, или его уже кто-то
// успел заменить» и не затереть чужую свежую замену повторно.
func (e *Engine) ksCall(op string, ks killswitch.KillSwitch, fn func() error) error {
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(ksCallTimeout):
		e.ksMu.Lock()
		if e.ks == ks {
			e.log(fmt.Sprintf("KillSwitch: %s не завершился за %s — похоже, зависла системная "+
				"служба фильтрации (BFE); пересоздаю бэкенд, не дожидаясь зависшей попытки",
				op, ksCallTimeout))
			e.ks, e.ksIsService = killswitch.NewLocalBackend(e.ksNeedsTunMode()), false
			e.ksProbedAt = time.Now()
		}
		e.ksMu.Unlock()
		return fmt.Errorf("killswitch: %s не завершился за %s — бэкенд пересоздан, "+
			"повторите попытку", op, ksCallTimeout)
	}
}

// ksIsEnabledWithTimeout — то же самолечение, что ksCall, но для проверки IsEnabled() ВНУТРИ
// currentKS(), которая уже держит e.ksMu на всё своё тело — ksCall (сам берущий e.ksMu на
// таймауте) сюда не годится, вызывающий сам решает, что делать при hung=true. Более короткий
// таймаут: это лёгкая проверка состояния, а не боевая сетевая операция.
var ksProbeTimeout = 3 * time.Second

func ksIsEnabledWithTimeout(ks killswitch.KillSwitch) (enabled bool, hung bool) {
	done := make(chan bool, 1)
	go func() { done <- ks.IsEnabled() }()
	select {
	case v := <-done:
		return v, false
	case <-time.After(ksProbeTimeout):
		return false, true
	}
}

// manualConnectStickyWindow — см. комментарий у поля manualConnectAt. var, не const —
// тот же test-seam приём, что у ksCallTimeout/ksProbeTimeout (тесты укорачивают окно).
var manualConnectStickyWindow = 20 * time.Second

// withinManualConnectSticky — true, пока не истёк manualConnectStickyWindow с последнего
// ручного ConnectByID. emergencySwitch() обязан это проверить ПЕРВЫМ делом, до любых прочих
// anti-flap проверок (SwitchOnlyOnFail/Sticky Session — те защищают от флаппинга вообще,
// это отдельная защита именно от гонки с только что сделанным пользователем выбором).
func (e *Engine) withinManualConnectSticky() bool {
	e.manualConnectMu.Lock()
	defer e.manualConnectMu.Unlock()
	return !e.manualConnectAt.IsZero() && time.Since(e.manualConnectAt) < manualConnectStickyWindow
}

func (e *Engine) ksReset() {
	ks := e.currentKS()
	if r, ok := ks.(interface{ Reset() error }); ok {
		if err := e.ksCall("Reset", ks, r.Reset); err != nil {
			e.log(fmt.Sprintf("KillSwitch reset: %v", err))
		}
		return
	}
	// Локальный бэкенд без отдельного Reset: снимаем правила напрямую (мы и есть исполнитель).
	//
	// S-1 (ТЗ v1.4): единственное глушение, где ошибки не может быть ПО ПОСТРОЕНИЮ —
	// killswitch.QuickReset() ничего не возвращает, замыкание всегда отдаёт nil, и остаётся
	// лишь таймаут ksCall. Он и так уже залогирован самой ksCall («не завершился за …,
	// бэкенд пересоздан»), а ksReset вызывается только на путях отката, где прерываться
	// нельзя (см. комментарий у откатного Disable в enableKillSwitchWithUAC).
	_ = e.ksCall("QuickReset", ks, func() error { killswitch.QuickReset(); return nil })
}

// ksDisable — единая точка снятия Kill Switch (R-4.1/C-3).
//
// Прямые e.ks.Disable() оставались последними обходными путями к фаерволу: поле e.ks могло
// указывать на бэкенд, выбранный несколько минут назад (мёртвый клиент службы) или вовсе быть
// nil. currentKS() при этом безопасен: АКТИВНЫЙ бэкенд он не подменяет, а неактивный снимать
// нечего. Выход: ошибка бэкенда, если снять не удалось.
func (e *Engine) ksDisable() error {
	ks := e.currentKS()
	return e.ksCall("Disable", ks, ks.Disable)
}

// ksResetAll — полный откат сетевых изменений APF (включая DNS) тем же маршрутом (R-4.1/C-3).
func (e *Engine) ksResetAll() error {
	ks := e.currentKS()
	if r, ok := ks.(interface{ ResetAll() error }); ok {
		return e.ksCall("ResetAll", ks, r.ResetAll)
	}
	return e.ksCall("ResetAll", ks, killswitch.ResetAll)
}

// rollbackConnectionAttempt откатывает сетевые изменения при ошибке подключения.
// Цель: не оставить пользователя без интернета из-за частично применённых правил.
func (e *Engine) rollbackConnectionAttempt(stage string, cause error, wasRunning bool) error {
	e.log(fmt.Sprintf("Connection rollback at stage=%s: %v", stage, cause))
	e.setLastRollback(stage, cause, wasRunning)

	// LOT-08, точка отказа №1. Гасим подтверждение ЗДЕСЬ, в начале отката, а не полагаемся на
	// setDisconnected() в самом конце функции.
	//
	// Почему в начале: между этой строкой и setDisconnected() идут ksDisable()/ksReset()/
	// disableSystemProxy() — операции с фаерволом и реестром, которые по живому инциденту
	// 2026-08-19 умеют висеть на BFE до срабатывания собственного таймаута ksCall. Весь этот
	// интервал состояние продолжало утверждать «канал подтверждён» на попытке, которая уже
	// заведомо провалилась.
	//
	// Почему VerifyFailed, а не VerifyIdle: откат при wasRunning=true идёт поверх ЕЩЁ ПОДНЯТОГО
	// туннеля (не удался Reload/ReloadWithFreshTun) — по контракту models.ConnectionState это
	// ровно «туннель поднят, но канал признан неработающим». Это НЕ «отключение пользователем»:
	// там предмета проверки нет, и правильное состояние — Idle. Итог отката тоже Idle, его
	// ставит setDisconnected() ниже, когда туннеля уже нет; Failed живёт ровно столько, сколько
	// туннель ещё числится поднятым. На холодной попытке (wasRunning=false, Connected ещё false)
	// собственный гейт markChannelDead делает вызов no-op — канала не было, гасить нечего.
	e.markChannelDead(fmt.Sprintf("откат подключения на стадии %s", stage))

	if e.cfg.EnableKillSwitch {
		if err := e.ksDisable(); err != nil { // R-4.1: единый маршрут KS-операций
			e.log(fmt.Sprintf("Rollback warning (kill switch disable): %v", err))
		}
	}

	// Всегда снимаем блокирующие firewall-правила APF как fail-safe.
	e.ksReset() // R-4.1: единый маршрут KS-операций

	// ТЗ v1.3 F4 (BB-3): системный прокси, выставленный НАМИ на этот сеанс, после отката
	// указывал бы на порт, который никто не слушает — браузеры без интернета «навсегда»
	// (инцидент 2026-08-17 с застрявшим sysproxy). Снимаем только то, что ставили сами.
	if e.sysProxyApplied.Load() {
		if err := e.disableSystemProxy(); err != nil {
			e.log(fmt.Sprintf("Rollback warning (system proxy disable): %v", err))
		}
	}

	// Если процесса до попытки не было, останавливаем возможный частичный запуск.
	if !wasRunning {
		e.proc.Stop()
	}

	e.setDisconnected()
	return classifyRollbackCause(stage, cause)
}

// classifyRollbackCause — класс отказа по стадии отката (ТЗ HOTSWITCH §8 A1). Все стадии, кроме
// apply_runtime, — про эту машину: порт (listen_port), фаервол (killswitch, killswitch_tun),
// запись файла (write_config). Исключение внутри killswitch — неразрешимый адрес узла: он уже
// помечен отказом узла в applyKillSwitch, и markLocalFailure его не перекрашивает. Для
// apply_runtime класс несёт сама ошибка запускателя (singbox.ErrLocalStart/ErrConfigRejected);
// неклассифицированная (in-process запускатель Android) остаётся отказом узла — как до этапа A.
func classifyRollbackCause(stage string, cause error) error {
	if stage == "apply_runtime" {
		return cause
	}
	return markLocalFailure(cause)
}

func (e *Engine) setLastRollback(stage string, cause error, wasRunning bool) {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	e.lastRollback = &RollbackEvent{
		At:         time.Now(),
		Stage:      stage,
		Reason:     cause.Error(),
		WasRunning: wasRunning,
	}
}

// runPostConnectLeakTest проверяет утечки после успешного подключения.
// vpn-specialist: проверяем что DNS идёт через туннель, а не мимо.
func (e *Engine) runPostConnectLeakTest() {
	if !e.sleepCtx(3 * time.Second) {
		return // движок останавливается — не выполняем post-connect работу
	}
	// e.ctx — см. комментарий у runPostConnectHealthCheck (иначе Stop() ждёт до 15с этого
	// таймаута даже после явного Disconnect).
	ctx, cancel := context.WithTimeout(e.currentCtx(), 15*time.Second)
	defer cancel()

	result, err := e.dnsLeakTest.Test(ctx)
	if err != nil {
		e.log(fmt.Sprintf("DNS leak test error: %v", err))
		return
	}

	e.log(fmt.Sprintf("DNS Leak Test: %s", result.Diagnosis))

	if result.Leaked {
		e.log("⚠️ " + result.Recommendation)
		if e.OnLeakDetected != nil {
			e.OnLeakDetected("dns", result.Diagnosis)
		}
	}

	// Проверяем IPv6 утечку
	if leaked, addr := leakguard.TestIPv6Leak(); leaked {
		e.handleIPv6Leak(addr)
	}
}

// handleIPv6Leak — реакция монитора на обнаруженную утечку IPv6.
//
// Вынесено из runLeakTests отдельной функцией, чтобы поведение можно было проверить, не
// поднимая монитор и не трогая сеть машины (тот же приём, что у androidConfig в мосту).
func (e *Engine) handleIPv6Leak(addr string) {
	e.log(fmt.Sprintf("⚠️ IPv6 Leak detected: %s", addr))
	if e.OnLeakDetected != nil {
		e.OnLeakDetected("ipv6", fmt.Sprintf("IPv6 соединение работает мимо VPN: %s", addr))
	}
	// C-13 (ТЗ v1.4): монитор БОЛЬШЕ НЕ включает то, что пользователь выключил. Раньше здесь
	// стоял безусловный Enable — третий писатель тумблера, из-за которого выбор пользователя
	// отменялся молча и «сам собой». Истина — конфиг: если защита выключена пользователем,
	// монитор вправе только предупредить (OnLeakDetected выше уже сработал).
	e.mu.RLock()
	wanted := e.cfg.BlockIPv6Leak
	e.mu.RUnlock()
	if !wanted {
		e.log("IPv6 Guard: утечка обнаружена, но защита выключена пользователем — включать не буду")
		return
	}
	if !e.ipv6Guard.IsEnabled() {
		e.ipv6Guard.Enable("apf0")
		e.log("IPv6 Guard: auto-enabled after leak detection")
	}
}

// runPostConnectHealthCheck (T-01): после подъёма туннеля проверяет, что исходящий канал
// sing-box (outbound к узлу) реально пропускает HTTP-трафик — запрос к trace-эндпоинту через
// локальный SOCKS5 (RFC 1928). Подтверждает, что сам sing-box/узел рабочие, и определяет
// страну выхода. Пост-коннект задача: учтена в e.wg, прерывается через sleepCtx.
//
// Находка 2026-08-11 (живой прогон): в VPN-режиме ОДНА ЭТА проверка НЕ подтверждает, что
// системный трафик СТОРОННИХ приложений реально идёт через TUN-интерфейс — только что
// исходящий канал sing-box (SOCKS5→узел) сам по себе работает. Наблюдалось расхождение:
// проверка зелёная, а Chrome не мог открыть ни одного сайта (см. FULL_RUN_RESULTS_2026-08-10.md,
// TZ_VPN_TUN_REAL_TRAFFIC_2026-08-11.md) — TUN/SOCKS5 внутри sing-box два независимых
// inbound-пути, работоспособность одного не гарантирует работоспособность другого.
//
// ЗАКРЫТО LOT-09 (2026-09-06): в TUN-несущих режимах (vpn/hybrid) после успеха пробы через
// SOCKS выполняется ВТОРАЯ, прямая проба — тот же запрос без SOCKS-диалера
// (checker.HTTPHealthCheckDirectInfoAt). Её сокет никем не protect'ится и потому уходит в
// TUN — ровно тем путём, которым ходит браузер. Подтверждение канала требует УСПЕХА ОБЕИХ;
// «SOCKS зелёная, прямая красная» — это и есть жалоба пользователя, и она обязана давать
// VerifyFailed, а не «Подключено». Где провал прямой пробы уже вправе рвать подключение, а
// где пока только логируется — см. directProbePolicy (переключатель живой проверки).
// Инцидент 2026-08-19: раньше системный прокси включался СРАЗУ после старта sing-box (см.
// applySingBoxConfig), до того как эта проверка вообще стартовала. Предподключенный TCP-проб
// (checker.CheckOne) подтверждает только открытый порт узла, не рабочий VPN-протокол —
// «живой но не пропускающий трафик» узел мгновенно рвал интернет всей системе, а исправление
// ждало отдельного Watchdog-цикла (до ~45с). Теперь единственная точка включения системного
// прокси — успех ЭТОЙ проверки; на неудаче прокси не включается вовсе, а переключение
// запускается немедленно, не дожидаясь, пока Watchdog наберёт свои 3 провала подряд.
// postConnectProbeAttempts — сколько раз пробуем подтвердить канал, прежде чем признать
// узел негодным.
//
// Одной попытки мало (найдено ревью 2026-08-24). Verified выставляется РОВНО здесь, а на
// Android состояние «не подтверждён» через 180 секунд приводит к принудительной остановке
// туннеля. При этом первая проба идёт через считанные секунды после подключения, когда
// туннель ещё «прогревается» (DNS, первые соединения, рейт-лимиты) — единичный сбой не
// доказывает, что узел нерабочий. Хуже: при выключенном автопереключении и в sticky-окне
// после ручного выбора emergencySwitch не запускается, повторной проверки не было ни от
// кого, и узел оставался неподтверждённым НАВСЕГДА — то есть рабочее подключение
// детерминированно сносилось.
// Ровно две попытки — сознательный баланс. Больше повторов защищают от единичного сбоя, но
// прямо удлиняют время, которое пользователь сидит без интернета на мёртвом узле (та самая
// жалоба из России). Основную защиту рабочего туннеля даёт не число повторов, а то, что
// клиент больше НЕ рвёт неподтверждённое подключение (см. ConnectOutcome.UNVERIFIED в
// APFVpnService.kt); повтор здесь закрывает лишь транзиентный сбой первой пробы.
const postConnectProbeAttempts = 2

// tunTrafficDeadReason — причина, с которой гасится подтверждение, когда исходящий канал узла
// работает, а путь приложений (TUN) — нет. Именно этот текст видит пользователь в логе вместо
// прежнего «Подключено»: разница между «узел мёртв» и «узел жив, но трафик до него не доходит»
// определяет, что человеку делать дальше (сменить узел или разбираться с TUN/правами VPN).
const tunTrafficDeadReason = "исходящий канал узла работает, но трафик приложений через туннель не проходит"

// tunDirectProbePolicy — что делать с прямой (TUN-bound) пробой в текущем режиме и на текущей
// платформе.
type tunDirectProbePolicy int

const (
	// directProbeSkip — прямая проба не нужна и не запускается.
	directProbeSkip tunDirectProbePolicy = iota
	// directProbeObserve — прямая проба выполняется и логируется, но её провал НЕ мешает
	// подтвердить канал.
	directProbeObserve
	// directProbeEnforce — прямая проба выполняется, и её провал означает «канал не подтверждён».
	directProbeEnforce
)

// directProbePolicy — ПЕРЕКЛЮЧАТЕЛЬ ЖИВОЙ ПРОВЕРКИ (LOT-09, пункт 3). Одна точка, в которой
// записано, где прямая проба уже вправе рвать подключение, а где она пока только наблюдает.
//
// Почему не «везде enforce». Провал прямой пробы гасит подтверждение и запускает переключение
// узла. Цена ошибочного провала — пользователь теряет рабочее подключение, поэтому включать
// enforcement на платформе, где поведение ни разу не проверено живьём, нельзя. На сегодня
// (2026-09-06) живой стенд есть только для Android (телефон <test-phone>); рабочего Windows-стенда
// с TUN нет — известная нерешённая проблема с wintun-адаптером в госте Hyper-V
// (см. apf-windows-tun-wintun-adapter-timeout).
//
// КАК ПЕРЕВЕСТИ ПОСЛЕ ЖИВОЙ ПРОВЕРКИ: добавить нужный GOOS в case ниже — больше ничего.
// Таблица случаев зафиксирована в TestDirectProbePolicy_Table.
//
// Отдельная чистая функция ровно по той же причине, что verifyStateOnApply и
// sysProxyFailureAborts: боевая ветка (goos=="android", настоящий TUN) под `go test` на этой
// машине недостижима, и решение иначе нечем закрепить.
func directProbePolicy(mode, goos string) tunDirectProbePolicy {
	// Приложения идут через TUN только в этих двух режимах (тот же предикат, что
	// ksNeedsTunMode). В proxy-режиме они идут через локальный SOCKS — его и проверяет
	// проба №1, а прямая проба ушла бы мимо туннеля и ничего бы не доказала.
	if mode != models.ModeVPN && mode != models.ModeHybrid {
		return directProbeSkip
	}
	switch goos {
	case "android":
		// Единственная платформа с живым стендом. Здесь же и подтверждён механизм:
		// VpnService.protect() применяется только к сокетам самого sing-box
		// (AutoDetectInterfaceControl), а не ко всему процессу, поэтому обычный HTTP-запрос
		// из Go-кода приложения захватывается VpnService и уходит в TUN — тем же путём, что
		// трафик браузера.
		return directProbeEnforce
	default:
		return directProbeObserve
	}
}

// probeGOOS — платформа для directProbePolicy. См. directProbeGOOS у структуры.
func (e *Engine) probeGOOS() string {
	if e.directProbeGOOS != "" {
		return e.directProbeGOOS
	}
	return runtime.GOOS
}

// probeSOCKS — проба №1: HTTP через локальный SOCKS5 самого APF (исходящий канал sing-box).
func (e *Engine) probeSOCKS(ctx context.Context, targetURL string) (checker.HealthInfo, error) {
	if e.healthProbeSOCKS != nil {
		return e.healthProbeSOCKS(ctx, targetURL)
	}
	return e.verifyTunnelHealthInfo(ctx, targetURL)
}

// probeDirect — проба №2: тот же запрос БЕЗ SOCKS-диалера, то есть тем путём, которым ходят
// приложения (в TUN-режиме он и есть TUN). См. checker.HTTPHealthCheckDirectInfoAt.
func (e *Engine) probeDirect(ctx context.Context, targetURL string) (checker.HealthInfo, error) {
	if e.healthProbeDirect != nil {
		return e.healthProbeDirect(ctx, targetURL)
	}
	if targetURL == "" {
		targetURL = checker.DefaultHealthCheckURL()
	}
	return e.checker.HTTPHealthCheckDirectInfoAt(ctx, targetURL)
}

// watchdogTunProbeTimeout — бюджет ОДНОЙ прямой (TUN-несущей) пробы сторожа (долг-6). var — тюнится тестом.
var watchdogTunProbeTimeout = 6 * time.Second

// watchdogTunProbeAttempts — сколько раз подряд прямая проба должна провалиться, чтобы сторож счёл
// путь приложений (TUN) мёртвым. >1 гасит редкий флап одиночной пробы (та же осторожность, что
// FailThreshold у SOCKS-проверки сторожа), не откладывая честность бэйджа надолго.
const watchdogTunProbeAttempts = 2

// watchdogTunVerdict — долг-6 (2026-09-21, см. apf-healthcheck-checks-socks-not-tun /
// apf-connected-vs-verified-lies): успешная проверка сторожа доказывает лишь, что жив SOCKS-in
// sing-box, а НЕ что жив путь приложений (TUN). На платформе, где прямая (TUN-несущая) проба
// проверена живьём и вправе выносить вердикт (directProbeEnforce — сегодня только Android, тот же
// переключатель, что у пост-коннект пробы), подтверждаем бэйдж «Подтверждено» ТОЛЬКО когда и TUN
// отвечает; иначе честно гасим его («зелёная галка, а сайта нет»). Возвращает (healthy, decided):
//
//	decided=false — TUN-вердикт неприменим (не enforce-платформа ИЛИ идёт пост-коннект проба
//	                VerifyChecking, которая авторитетнее): вызывающий действует как раньше (по SOCKS).
//	decided=true  — прямая проба вынесла вердикт: healthy=true (TUN жив) / false (SOCKS жив, TUN нет).
//
// НАМЕРЕННО не запускает переключение узла: эскалацию оставляем SOCKS-логике сторожа (OnDead) —
// цена ложной прямой пробы на живом канале это потеря рабочего подключения (та же осторожность, что
// в directProbePolicy). Здесь только честность бэйджа; если TUN действительно мёртв, SOCKS вскоре
// тоже отвалится и сработает штатный OnDead→emergencySwitch.
func (e *Engine) watchdogTunVerdict() (healthy bool, decided bool) {
	if directProbePolicy(e.cfg.ConnectionMode, e.probeGOOS()) != directProbeEnforce {
		return true, false // не enforce — прежнее SOCKS-поведение, TUN-вердикт не выносим
	}
	e.stateMu.RLock()
	vs := e.state.VerifyState
	e.stateMu.RUnlock()
	// Вмешиваемся только когда канал числится подтверждённым или уже помечен неработающим — не
	// трогаем VerifyChecking (там авторитетна пост-коннект проба нового узла; сторож мог ещё бить
	// через старый outbound — та же осторожность, что в markChannelAliveAgain/resolveDanglingVerifyChecking).
	if vs != models.VerifyVerified && vs != models.VerifyFailed {
		return true, false
	}
	var lastErr error
	for attempt := 1; attempt <= watchdogTunProbeAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(e.currentCtx(), watchdogTunProbeTimeout)
		_, err := e.probeDirect(ctx, "")
		cancel()
		if err == nil {
			return true, true
		}
		lastErr = err
	}
	if lastErr != nil {
		e.log("[watchdog] прямая (TUN) проба не прошла, хотя SOCKS отвечает: " + lastErr.Error())
	}
	return false, true
}

// runProbeAttempts — общая обвязка повторов для обеих проб пост-коннект проверки.
// Возвращает (результат последней удачной попытки, «движок останавливается», ошибка).
func (e *Engine) runProbeAttempts(what string, probe func(context.Context, string) (checker.HealthInfo, error)) (checker.HealthInfo, bool, error) {
	var lastErr error
	var okInfo checker.HealthInfo
	for attempt := 1; attempt <= postConnectProbeAttempts; attempt++ {
		// e.ctx (не context.Background()): иначе Stop()/Disconnect() вынужден ждать
		// e.wg.Wait() до собственного таймаута этой проверки, даже когда движок уже
		// остановлен — живой симптом «отключение выполняется через ~30 секунд».
		ctx, cancel := context.WithTimeout(e.currentCtx(), 8*time.Second)
		// target пустой на первой попытке (проба бьёт в cfTraceURL по умолчанию); со второй —
		// берём ИЗ ДРУГОГО пула (checker.HealthCheckFallbackTargets).
		// Живой инцидент 2026-08-27: повтор в тот же самый 1.1.1.1, который и не прошёл
		// первую попытку, ничего не проверяет заново — если именно этот адрес недоступен
		// по пути (а не узел/протокол сломан), обе попытки провалятся идентично. Разная
		// цель на второй попытке отличает «этот конкретный внешний адрес недоступен» от
		// «канал реально не пропускает трафик».
		target := ""
		if attempt > 1 && len(checker.HealthCheckFallbackTargets) > 0 {
			target = checker.HealthCheckFallbackTargets[(attempt-2)%len(checker.HealthCheckFallbackTargets)]
		}
		// ТЗ v1.3 F1.2: результат больше не выбрасывается (`_, _, lastErr` — NL-1) — задержка/
		// страна/exit-IP записываются в узел через recordNodeVerified.
		info, err := probe(ctx, target)
		lastErr = err
		cancel()
		if lastErr == nil {
			okInfo = info
			return okInfo, false, nil
		}
		if attempt < postConnectProbeAttempts {
			e.log(fmt.Sprintf("Проверка %s не прошла (попытка %d из %d) — повторяю",
				what, attempt, postConnectProbeAttempts))
			if !e.sleepCtx(2 * time.Second) {
				return okInfo, true, lastErr // движок останавливается
			}
		}
	}
	return okInfo, false, lastErr
}

func (e *Engine) runPostConnectHealthCheck() {
	// N-8 (§3 DIAG_N8_PLAN.md): "time-to-first-verified" — от входа сюда (сразу после raise)
	// до момента, когда канал реально подтверждён трафиком (см. точку ниже, где VerifyVerified
	// выставляется). Ранние return (движок останавливается) этот лог не пишут намеренно —
	// подтверждения не случилось, измерять нечего.
	t0 := time.Now()
	// LOT-09, находка 4.2: «проверка идёт» обязана разрешиться ХОТЬ ВО ЧТО-ТО. Ранние
	// return'ы ниже (движок останавливается на любом из трёх sleepCtx) не трогали состояние
	// вовсе, а поднять его обратно из VerifyChecking не умеет никто: markChannelAliveAgain
	// сознательно поднимает только из VerifyFailed. Подробнее — у самой функции.
	defer e.resolveDanglingVerifyChecking("проверка канала не была доведена до конца")

	// Первая проба быстрее прежних 5 секунд: чем раньше обнаружен мёртвый узел, тем меньше
	// пользователь сидит без интернета (живой лог из России — десятки секунд ожидания).
	if !e.sleepCtx(2 * time.Second) {
		return // движок останавливается — пропускаем post-connect работу
	}

	// ── Проба №1: исходящий канал sing-box (SOCKS5 на петле → узел) ──────────────────────
	verifiedInfo, aborted, lastErr := e.runProbeAttempts("канала", e.probeSOCKS)
	if aborted {
		return // движок останавливается
	}
	if lastErr != nil {
		e.log("⚠ Post-connect health check провален — узел не подтвердил рабочий канал, переключаюсь")
		// Точка обнаружения смерти №3. Отдельно от первого подключения важна ПОВТОРНАЯ
		// проверка: emergencySwitch специально запускает её из sticky-паузы (см. там же), и до
		// 2026-09-06 эта ветка не трогала состояние вовсе — канал уже был признан мёртвым
		// настоящим HTTP через туннель, а UI продолжал показывать «Подключено».
		e.markChannelDead("post-connect health check")
		// F1.2: реальный сбой — в узел (Score=0, FailStreak++, LastFailReason), а не только в
		// recentFailures на 10 минут (ND-1).
		e.stateMu.RLock()
		failed := e.state.ActiveNode
		e.stateMu.RUnlock()
		e.recordNodeFailure(failed, failReasonHealthCheck)
		e.goTracked(e.emergencySwitch)
		return
	}

	// ── Проба №2: путь, которым реально ходят приложения (LOT-09) ────────────────────────
	//
	// Корень жалобы «ВПН подключен, а сайт не открывается»: до сих пор подтверждение
	// выставлялось прямо здесь, по одной только пробе выше. Она проверяет socks-in, а браузер
	// и все приложения телефона идут через tun-in — в sing-box это ДВА независимых
	// inbound-пути, и работоспособность одного ничего не доказывает про второй (живой прогон
	// 2026-08-11: проверка зелёная, Chrome не открывает ничего; см. FULL_RUN_RESULTS_2026-08-10.md
	// и TZ_VPN_TUN_REAL_TRAFFIC_2026-08-11.md, а также комментарий у самой функции).
	// C-20 (ТЗ v1.4): если прямая (TUN-bound) проба пройдёт, именно её величина — та самая
	// «задержка через туннель», а не SOCKS5-замер пробы №1.
	var tunInfo *checker.HealthInfo
	policy := directProbePolicy(e.cfg.ConnectionMode, e.probeGOOS())
	switch policy {
	case directProbeSkip:
		// proxy-режим: приложения ходят как раз через локальный SOCKS, который проба №1 и
		// проверила. Прямая проба здесь ушла бы МИМО туннеля, в обычный интернет, и не
		// доказала бы ничего ни в одну, ни в другую сторону — критерий остаётся прежним.
	case directProbeObserve, directProbeEnforce:
		enforce := policy == directProbeEnforce
		// Тот же повтор с ДРУГОЙ целью, что у пробы №1, и по той же причине (инцидент
		// 2026-08-27): единственный внешний адрес — единая точка отказа самой диагностики, а
		// здесь провал ещё и рвёт подключение пользователя.
		directInfo, dAborted, derr := e.runProbeAttempts("трафика приложений через туннель", e.probeDirect)
		if dAborted {
			return // движок останавливается
		}
		if derr == nil {
			e.log(fmt.Sprintf("✓ Трафик приложений проходит через туннель (%dms, выход: %s) — "+
				"прямая проба мимо SOCKS, тот же путь, что у браузера",
				directInfo.LatencyMs, directInfo.Country))
			di := directInfo
			tunInfo = &di
			break
		}
		e.log(fmt.Sprintf("⚠ Прямая (TUN) проба не прошла: %v — исходящий канал узла работает, "+
			"но трафик приложений через туннель не проходит", derr))
		if !enforce {
			// Пункт 3 ТЗ LOT-09: наблюдаем и логируем везде, но блокируем подтверждение
			// только там, где вердикт проверен живьём (см. directProbePolicy).
			e.log("Прямая проба на этой платформе пока не влияет на вердикт (нет живой проверки) — " +
				"подтверждение выставляется по исходящему каналу")
			break
		}
		e.markChannelDead(tunTrafficDeadReason)
		e.stateMu.RLock()
		failed := e.state.ActiveNode
		e.stateMu.RUnlock()
		e.recordNodeFailure(failed, failReasonTunProbe)
		e.goTracked(e.emergencySwitch)
		return
	}

	// Канал подтверждён реальным трафиком — только теперь UI вправе показать "подключено"
	// вместо "ищу рабочий узел" (см. Verified в models.ConnectionState).
	e.stateMu.Lock()
	// LOT-09, находка 4.1: гейт по Connected. Это был ЕДИНСТВЕННЫЙ переход в VerifyVerified
	// без него (у markChannelDead, markChannelAliveAgain и setDisconnected он есть). Проба
	// живёт до 8 секунд и запускается ещё дважды по 2 секунды сна — за это время сессию могли
	// снять (Disconnect/Stop/откат), и поздно вернувшийся успех воскрешал «канал подтверждён»
	// поверх уже снесённого подключения: Connected=false, Verified=true — состояние, которого
	// в контракте нет вообще.
	if !e.state.Connected {
		e.stateMu.Unlock()
		e.log("Проверка канала вернулась успехом, но туннеля уже нет — подтверждение не выставляю")
		return
	}
	e.setVerifyStateLocked(models.VerifyVerified)
	active := e.state.ActiveNode
	e.stateMu.Unlock()
	// N-8 (§3 DIAG_N8_PLAN.md): индикатор успеха N-1/N-2 — сколько реально заняло получить
	// первое подтверждение трафиком после подъёма узла.
	e.logDiagN8("time-to-first-verified", t0)
	// F1.2: подтверждение реальным трафиком — в узел (LastVerifiedAt/VerifiedCount/задержка/
	// страна/exit-IP). Это единственный источник списка «Проверенные» и приоритета выбора.
	if tunInfo != nil {
		e.recordNodeVerifiedVia(active, tunInfo.LatencyMs, tunInfo.Country, tunInfo.ExitIP, models.VerifiedViaTUN)
	} else {
		e.recordNodeVerifiedVia(active, verifiedInfo.LatencyMs, verifiedInfo.Country, verifiedInfo.ExitIP,
			models.VerifiedViaSOCKS)
	}
	// §3 (плавающий приоритет): запоминаем именно ЗДЕСЬ, а не в connectNode — там узел
	// только подключился, канал ещё не подтверждён реальным трафиком (ровно то различие,
	// ради которого существует Verified). Узел, который лишь открыл сокет, но ни разу не
	// прошёл health-check, не заслуживает приоритета на следующем холодном старте.
	if active != nil {
		e.recordLastActiveNode(active.ID)
	}
	if e.OnStateChange != nil {
		e.OnStateChange(e.GetState())
	}
	if e.cfg.ConnectionMode != models.ModeVPN {
		if err := e.enableSystemProxy(); e.sysProxyFailureAborts(err) {
			e.abortSessionOnSysProxyFailure(err)
			return
		}
	}
}

// sysProxyFailureAborts — обязан ли провал включения системного прокси прервать сессию.
//
// P0.2, Слой 3 (docs/TZ_WINDOWS_CONSILIUM_FINDINGS_v1.0.md): Kill Switch без TUN-режима
// разрешает трафик ТОЛЬКО к текущему узлу в расчёте на то, что системный прокси перенаправит
// туда обычные приложения (applyKillSwitch, engine.go:~1518). Если запись реестра не удалась
// (например, служба не смогла определить активную консольную сессию пользователя —
// internal/sysproxy targetHive), оставлять сессию «Подключено» означает душить весь трафик
// системы без единой рабочей цели.
//
// Вынесено в отдельную функцию вместе с abortSessionOnSysProxyFailure по той же причине, что и
// verifyStateOnApply (LOT-04): под `go test` sysproxy.SetHTTPProxy — no-op барьера hostguard и
// НИКОГДА не возвращает ошибку, поэтому боевая ветка изнутри runPostConnectHealthCheck тестом
// недостижима, и решение иначе нечем закрепить.
func (e *Engine) sysProxyFailureAborts(err error) bool {
	return err != nil && e.cfg.EnableKillSwitch && !e.ksNeedsTunMode()
}

// abortSessionOnSysProxyFailure — реакция на невключившийся системный прокси при включённом
// Kill Switch: состояние гасится ЗДЕСЬ, и только потом запускается переключение.
//
// LOT-08, точка отказа №3 (самая заметная из трёх). К этому моменту runPostConnectHealthCheck
// уже выставил VerifyVerified — канал sing-box действительно подтверждён настоящим HTTP через
// SOCKS. Но обычные приложения в эту дырку не попадают: системный прокси не встал, а Kill
// Switch пропускает трафик только к узлу. Сессия нерабочая, а состояние утверждает обратное —
// пользователь видит зелёное «Подключено» и задушенный трафик всей системы.
//
// Почему VerifyFailed, а не VerifyIdle: туннель поднят, Connected=true, ActiveNode на месте —
// сессию никто не снимал. По контракту models.ConnectionState это буквально «туннель поднят, но
// канал признан неработающим»; Idle означает «не подключено» и был бы прямой ложью.
//
// Почему здесь, а не внутри emergencySwitch: у переключения семь ранних return (отключённое
// пользователем автопереключение, sticky-пауза, гейт MinUptimeSec, «узел уже сменился» и т.д.),
// и на каждом из них сессия осталась бы «подтверждённой» — ровно та дыра, которую LOT-04
// закрыл для трёх точек ОБНАРУЖЕНИЯ смерти, гася состояние в месте знания, а не переключения.
func (e *Engine) abortSessionOnSysProxyFailure(cause error) {
	e.log(fmt.Sprintf("⚠ SysProxy не применён (%v), а Kill Switch требует его в proxy-режиме — переключаюсь", cause))
	e.markChannelDead("системный прокси не применён при включённом Kill Switch")
	e.goTracked(e.emergencySwitch)
}

// verifyTunnelHealthCheck проверяет исходящий SOCKS5-канал sing-box (checker.HTTPHealthCheck →
// dialViaSOCKS5), НЕ системный TUN-путь (см. находку 2026-08-11 у runPostConnectHealthCheck
// выше). Возвращает (latency, country, err) для пост-коннект проверки и для тестов. Контракт:
// при недоступном SOCKS5-прокси — ошибка без паники; при успехе — латентность и страна выхода.
// Закрывает «висячий» T-01: раньше HTTPHealthCheck/dialViaSOCKS5 вызывались только из тестов и
// не работали в боевом потоке.
func (e *Engine) verifyTunnelHealthCheck(ctx context.Context, targetURL string) (int64, string, error) {
	info, err := e.verifyTunnelHealthInfo(ctx, targetURL)
	return info.LatencyMs, info.Country, err
}

// verifyTunnelHealthInfo — то же, что verifyTunnelHealthCheck, но с exit-IP (ТЗ v1.3 F1.2):
// результат идёт в Node.LastVerified* через recordNodeVerified, а не выбрасывается.
func (e *Engine) verifyTunnelHealthInfo(ctx context.Context, targetURL string) (checker.HealthInfo, error) {
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", e.cfg.ListenPort)
	if targetURL == "" {
		targetURL = checker.DefaultHealthCheckURL()
	}
	info, err := e.checker.HTTPHealthCheckInfoAt(ctx, proxyAddr, targetURL)
	if err != nil {
		e.log(fmt.Sprintf("Проверка исходящего канала узла не прошла: %v", err))
		return info, err
	}
	e.log(fmt.Sprintf("✓ Исходящий канал узла отвечает (%dms, выход: %s) — SOCKS5, "+
		"не подтверждает системный TUN-путь для сторонних приложений", info.LatencyMs, info.Country))
	return info, nil
}

// ─── ТЗ v1.3 F1.2: обратная связь реального трафика в узел ───────────────────────────────

// verifiedFailReason* — значения Node.LastFailReason (F1.2).
const (
	failReasonHealthCheck = "health_check"
	failReasonWatchdog    = "watchdog"
	failReasonMonitor     = "monitor"
	failReasonConnect     = "connect_error"
	// failReasonTunProbe — узел ответил по исходящему каналу, но трафик приложений через TUN
	// не прошёл (LOT-09). Отдельно от failReasonHealthCheck намеренно: диагноз другой, и по
	// логам узла потом видно, какая именно половина пути не работала.
	failReasonTunProbe = "tun_probe"
)

// recordNodeVerified — единственный писатель Verified*-полей узла (консилиум 2026-09-03, NL-1/
// ND-1: раньше результат HTTP-проверки через туннель выбрасывался, и в узле не оставалось ни
// одного следа того, что он реально пропускал трафик). Гейт гонки узлов (NL-11): при активной
// группе urltest трафик идёт через победителя, а ActiveNode — инициатор, поэтому при
// raceNodes != nil подтверждение НЕ приписывается никому (снимок raceNodes — под e.mu).
func (e *Engine) recordNodeVerified(node *models.Node, latencyMs int64, country, exitIP string) {
	// C-20 (ТЗ v1.4): по умолчанию подтверждение приходит от пробы №1 — локального SOCKS5.
	e.recordNodeVerifiedVia(node, latencyMs, country, exitIP, models.VerifiedViaSOCKS)
}

// recordNodeVerifiedVia — то же, но с явным источником замера (C-20). «Через туннель» вправе
// называться только результат прямой (TUN-bound) пробы probeDirect; всё остальное — замер
// исходящего канала узла через локальный SOCKS5, и UI обязан говорить об этом другими словами.
func (e *Engine) recordNodeVerifiedVia(node *models.Node, latencyMs int64, country, exitIP, via string) {
	e.recordNodeVerifiedCore(node, latencyMs, country, exitIP, via, false)
}

// recordNodeVerifiedViaProbe — FIX-2 (консилиум L1-ENG-A, CONSILIUM_L1-ENG-A.md п.3): вариант
// recordNodeVerifiedVia для каталожной пробы N-1 (node_check.go). Разница — bypassRaceGate=true:
// probeNodeReal поднимает СВОЙ ИЗОЛИРОВАННЫЙ SOCKS-инстанс РОВНО для узла node и делает HTTP GET
// через него — приписывание трафика узлу тут физически однозначно, гонка urltest (e.raceNodes,
// см. recordNodeVerifiedCore) к этому пути вообще не относится: она существует для post-connect
// случая, где активный трафик мог пойти через ПОБЕДИТЕЛЯ группы, а не через e.state.ActiveNode
// (инициатора). Раньше воркер node_check.go звал recordNodeVerifiedVia (гейт гонки применялся) и
// БЕЗУСЛОВНО bumpNodeCheck(true) — если гейт молча отказывал (гонка автоподключения шла
// параллельно со сборкой каталога), статус показывал «verified N», а узел не получал НИ ОДНОГО
// поля Verified* → N-5 (удержание) не сохранил бы его при следующей записи на диск. Возвращает
// true, если штамп РЕАЛЬНО лёг на узел — вызывающий обязан звать bumpNodeCheck именно с этим
// значением, а не с константой true.
func (e *Engine) recordNodeVerifiedViaProbe(node *models.Node, latencyMs int64, country, exitIP, via string) bool {
	return e.recordNodeVerifiedCore(node, latencyMs, country, exitIP, via, true)
}

// recordNodeVerifiedCore — общее тело recordNodeVerifiedVia/recordNodeVerifiedViaProbe.
// bypassRaceGate=false — прежнее поведение (гейт e.raceNodes применяется, см. комментарий у
// recordNodeVerified выше); bypassRaceGate=true — каталожная проба (FIX-2), гейт гонки не
// применяется, потому что он не про эту ситуацию. Возвращает true, если штамп лёг на узел.
func (e *Engine) recordNodeVerifiedCore(node *models.Node, latencyMs int64, country, exitIP, via string, bypassRaceGate bool) bool {
	if node == nil {
		return false
	}
	now := time.Now().Unix()
	e.mu.Lock()
	if !bypassRaceGate && e.raceNodes != nil {
		e.mu.Unlock()
		e.log("Подтверждение канала не приписано узлу: активна гонка узлов, победитель неизвестен")
		return false
	}
	// Разрешение — секунды: подтверждение в ту же секунду, что и предыдущий сбой, обязано
	// считаться ПОЗЖЕ него (последнее событие побеждает), иначе LastOutcomeIsFailure залипает.
	if now <= node.LastFailedAt {
		now = node.LastFailedAt + 1
	}
	node.LastVerifiedAt = now
	node.VerifiedCount++
	// Отмечаем инкремент, чтобы refreshNodeVerified (успешные проверки Watchdog каждые 15 с)
	// не добавил второй в ту же минуту — см. verifiedCountBumpInterval.
	e.vcBumpNodeID = node.ID
	e.vcBumpAt = time.Now()
	node.LastVerifiedLatencyMs = latencyMs
	if via != "" {
		node.LastVerifiedVia = via
	}
	if country != "" {
		node.LastVerifiedCountry = country
	}
	if exitIP != "" {
		node.LastVerifiedExitIP = exitIP
	}
	node.FailStreak = 0
	id := node.ID
	e.mu.Unlock()
	// C-15: узел доказал, что работает — серия ручных переключений закончена успехом.
	e.noteForceSwitchOutcome(id)
	e.saveNodesDebounced()
	return true
}

// recordNodeFailure — единственный писатель LastFailed*/FailStreak (F1.2): реальный сбой
// (health-check, Watchdog, monitor, ошибка подключения), НЕ TCP-проба checker'а. Score
// обнуляется здесь же, чтобы узел не выигрывал следующий выбор по старой хорошей задержке
// (ND-1: selectBestForStrategy не смотрит recentFailures, только Score).
func (e *Engine) recordNodeFailure(node *models.Node, reason string) {
	if node == nil {
		return
	}
	now := time.Now().Unix()
	e.mu.Lock()
	if now <= node.LastVerifiedAt { // та же секунда, что и подтверждение — сбой позже (см. recordNodeVerified)
		now = node.LastVerifiedAt + 1
	}
	node.LastFailedAt = now
	node.LastFailReason = reason
	node.FailStreak++
	node.Score = 0
	streak := node.FailStreak
	relay := isRelayExitNode(node)
	id := node.ID
	e.mu.Unlock()
	// C-15 пункт 2 (ТЗ v1.4): узел роли «Выход» на выключенном компьютере проваливает
	// post-connect гарантированно, а Score у него обнуляется только до следующего скана —
	// после двух провалов подряд он получает recentFailure того же класса, что обычный узел,
	// и перестаёт выигрывать выбор кликом за кликом (живой прогон D3).
	if relay && streak >= 2 {
		e.markNodeFailed(id)
	}
	e.saveNodesDebounced()
}

// ─── C-18 / V13-4 (ТЗ v1.4): бюджет и стратегия подтверждения пула ───────────────────────
//
// Живой прогон K8-LIVE D7: «Обход завершён: живых 1480 из 5467 · подтверждённых трафиком: 2».
// 99,96 % пула не подтверждено ни разу — и это не дефект счётчика, а честная арифметика:
// единственный критерий «рабочий» (VerifyState=verified после пробы) требует ПОДКЛЮЧЕНИЯ к
// узлу, то есть делается по одному узлу за раз. Раздел ИИ пул увеличит; без бюджета это
// увеличит только непроверяемую массу.

// verifyBudgetPerPass — сколько узлов один проход (в том числе будущий ИИ-харвестер, §5)
// вправе поставить в очередь на подтверждение трафиком. var — настраивается и проверяется
// тестом границы.
var verifyBudgetPerPass = 10

// PoolCounts — три честных числа о пуле вместо одного (C-18 п.4). «Отвечает по TCP» и
// «подтверждён трафиком» — РАЗНЫЕ величины, и смешивать их в одно «живых N» нельзя.
type PoolCounts struct {
	Total         int `json:"total"`          // всего узлов в пуле
	TCPAlive      int `json:"tcp_alive"`      // порт отвечает (checker), про трафик ничего не известно
	ProvenTraffic int `json:"proven_traffic"` // хотя бы раз реально пропустил трафик
	VerifyStale   int `json:"verify_stale"`   // подтверждался, но подтверждение старше VerifyStaleAfter
}

// PoolVerificationCounts — счётчики пула для UI и отчётов харвестера.
func (e *Engine) PoolVerificationCounts() PoolCounts {
	now := time.Now().Unix()
	var c PoolCounts
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, n := range e.nodes {
		if n == nil {
			continue
		}
		c.Total++
		if n.Status == models.StatusOK || n.Status == models.StatusSlow {
			c.TCPAlive++
		}
		if n.IsProven() {
			c.ProvenTraffic++
			if n.VerifyStale(now) {
				c.VerifyStale++
			}
		}
	}
	return c
}

// NextVerificationBatch — не более budget узлов, которым подтверждение нужнее всего.
//
// Вход:      budget (<=0 — verifyBudgetPerPass).
// Тело:      сначала узлы с УСТАРЕВШИМ подтверждением (их переподтвердит следующее реальное
//
//	подключение к ним — отдельных подключений ради проверки не делаем, чтобы не рвать
//	сессию пользователя), затем отвечающие по TCP, но ни разу не подтверждённые; внутри
//	групп — по убыванию Score.
//
// Игнорирует: забаненные пользователем, в чёрном списке, ни разу не проверенные (о них
//
//	нечего утверждать), партнёров цепочки (они не взаимозаменяемы).
//
// Выход:     срез длиной не больше budget.
func (e *Engine) NextVerificationBatch(budget int) []*models.Node {
	if budget <= 0 {
		budget = verifyBudgetPerPass
	}
	now := time.Now().Unix()
	e.mu.RLock()
	all := e.getActiveCandidates(0)
	e.mu.RUnlock()

	var stale, neverProven []*models.Node
	for _, n := range all {
		if n == nil || n.IsUnchecked() {
			continue
		}
		switch {
		case n.VerifyStale(now):
			stale = append(stale, n)
		case !n.IsProven() && (n.Status == models.StatusOK || n.Status == models.StatusSlow):
			neverProven = append(neverProven, n)
		}
	}
	out := append(stale, neverProven...)
	if len(out) > budget {
		out = out[:budget]
	}
	return out
}

// ─── Состояние проверки канала: Verified и VerifyState ───────────────────────────────────
//
// Общий контракт с UI (см. models.ConnectionState): Verified обязан быть ТОЖДЕСТВЕН
// VerifyState == models.VerifyVerified. Поля читают разные потребители — старые сборки
// Web/Wails/Kotlin смотрят на bool, новые экраны на строку с различением «ещё проверяю» и
// «проверка провалилась». Любое расхождение пользователь видит как «два места в одном
// приложении говорят разное про одно и то же подключение», поэтому оба поля меняются только
// парой и только через setVerifyStateLocked.

// setVerifyStateLocked — вызывается ПОД e.stateMu.Lock(). true, если состояние действительно
// изменилось: уведомлять UI одинаковым состоянием незачем (Watchdog бьёт каждые 15 секунд).
func (e *Engine) setVerifyStateLocked(s string) bool {
	if e.state.VerifyState == s && e.state.Verified == (s == models.VerifyVerified) {
		return false
	}
	e.state.VerifyState = s
	e.state.Verified = s == models.VerifyVerified
	return true
}

// markChannelDead — канал признан НЕработающим в ТОЧКЕ ОБНАРУЖЕНИЯ смерти: обработчик
// Watchdog.OnDead, серия отказов monitor(), провал повторного health-check.
//
// Симптом, который это закрывает (жалоба «пишет ВПН подключен, а зайти на сайт не могу»):
// Verified выставлялся в true один раз и не гас НИКОГДА, кроме нового подключения и полного
// отключения. Смерть туннеля флаг не трогала нигде, а переключение (emergencySwitch) имеет семь
// ранних return — отключённое пользователем автопереключение, sticky-пауза, гейт MinUptimeSec,
// «узел уже сменился» и т.д. На каждом из них сессия оставалась «Connected=true, Verified=true»
// на заведомо мёртвом канале, и все три UI показывали зелёное «Подключено».
//
// Гасим ИМЕННО здесь, а не внутри emergencySwitch: к моменту входа в переключение состояние уже
// честное, поэтому ни один из семи ранних return больше не может оставить ложное «подтверждено».
// Это же означает, что фикс не зависит от того, разрешено ли автопереключение вообще.
func (e *Engine) markChannelDead(reason string) {
	e.stateMu.Lock()
	if !e.state.Connected {
		// Туннеля уже нет — там честное idle (setDisconnected). «Проверка провалилась» поверх
		// отключения была бы ложью в другую сторону: провалилась не проверка, а предмет проверки.
		e.stateMu.Unlock()
		return
	}
	changed := e.setVerifyStateLocked(models.VerifyFailed)
	e.stateMu.Unlock()
	if !changed {
		return
	}
	e.log(fmt.Sprintf("Канал признан неработающим (%s) — подтверждение снято, "+
		"UI больше не показывает «Подключено» на мёртвом туннеле", reason))
	if e.OnStateChange != nil {
		e.OnStateChange(e.GetState())
	}
}

// markChannelAliveAgain — успешная проверка Watchdog (настоящий HTTP через туннель) поднимает
// состояние обратно из VerifyFailed.
//
// Зачем: markChannelDead гасит подтверждение независимо от того, состоялось ли переключение, а
// оно как раз может НЕ состояться — автопереключение выключено пользователем, партнёр цепочки
// Вход-Выход не подменяется, резервы исчерпаны. Без обратного перехода честно погашенный флаг
// залипал бы в «failed» до ручного переподключения, даже когда канал сам восстановился
// (типичный случай: временная недоступность одной проверочной цели, см. FallbackCheckURLs).
//
// Поднимаем ТОЛЬКО из VerifyFailed. Из VerifyChecking — нет: там прямо сейчас идёт пост-коннект
// проба нового узла, её вывод точнее и придёт через считанные секунды; иначе Watchdog, ещё
// бивший через старый outbound, мог бы объявить подтверждённым узел, к которому мы только что
// переключились и о котором ничего не знаем.
func (e *Engine) markChannelAliveAgain() {
	e.stateMu.Lock()
	if !e.state.Connected || e.state.VerifyState != models.VerifyFailed {
		e.stateMu.Unlock()
		return
	}
	e.setVerifyStateLocked(models.VerifyVerified)
	e.stateMu.Unlock()
	e.log("Канал снова отвечает через туннель — подтверждение восстановлено")
	if e.OnStateChange != nil {
		e.OnStateChange(e.GetState())
	}
}

// resolveDanglingVerifyChecking — закрывает «зависшую проверку» (LOT-09, находка 4.2).
//
// ЧТО ЗАВИСАЛО. VerifyChecking выставляет ровно одно место — applySingBoxConfig
// (verifyStateOnApply), а разрешить его умеет тоже ровно одно — runPostConnectHealthCheck.
// Между ними две дыры, и обе молчаливые:
//
//  1. applySingBoxConfig зовёт проверку через goTracked, а тот НЕ запускает функцию, если
//     e.ctx уже отменён. Connected=true и VerifyChecking при этом уже выставлены строкой выше;
//  2. сама runPostConnectHealthCheck выходит по любому из трёх sleepCtx, не трогая состояние.
//
// Поднять состояние обратно не может никто: markChannelAliveAgain сознательно поднимает
// ТОЛЬКО из VerifyFailed (иначе Watchdog, ещё бьющий через старый outbound, объявил бы
// подтверждённым узел, о котором ничего не известно). То есть «проверка идёт» становилась
// терминальной — а на Android клиент через 180 секунд гасит неподтверждённое подключение,
// то есть детерминированно сносил бы РАБОЧИЙ туннель.
//
// Почему VerifyFailed, а не VerifyIdle: гейт по Connected ниже уже отсёк случай «туннеля нет»
// (там честное idle ставит setDisconnected). Если туннель числится поднятым, а проверка не
// состоялась, честное утверждение ровно одно: подтверждения у нас нет. Ошибка возможна только
// в сторону осторожности — первая же успешная проверка Watchdog вернёт VerifyVerified через
// markChannelAliveAgain (≤15 с), тогда как обратная ошибка не лечится ничем.
func (e *Engine) resolveDanglingVerifyChecking(reason string) {
	e.stateMu.Lock()
	if !e.state.Connected || e.state.VerifyState != models.VerifyChecking {
		e.stateMu.Unlock()
		return
	}
	e.setVerifyStateLocked(models.VerifyFailed)
	e.stateMu.Unlock()
	e.log(fmt.Sprintf("Проверка канала осталась незавершённой (%s) — состояние переведено в "+
		"«не подтверждено»; «проверка идёт» иначе залипала навсегда", reason))
	if e.OnStateChange != nil {
		e.OnStateChange(e.GetState())
	}
}

// verifyStateOnApply — какое состояние подтверждения обязано остаться у подключения после
// применения конфигурации sing-box (см. вызов в applySingBoxConfig).
//
// Отдельная функция, потому что сама applySingBoxConfig под `go test` дальше барьера hostguard
// не проходит (там встречаются настоящий бинарник sing-box и настоящий TUN), и решение внутри
// неё иначе нечем закрепить тестом.
func verifyStateOnApply(prev string, sameLiveTarget bool) string {
	// Переприменение правил (bypass/AdBlock) к ТОМУ ЖЕ живому узлу: узел не менялся, канал
	// только что был подтверждён — гасить нечего. Раньше здесь безусловно ставился false, и
	// правка белого списка на исправном туннеле на несколько секунд роняла UI в «ищу рабочий
	// узел»: ложная тревога, а не честное состояние.
	if sameLiveTarget && prev == models.VerifyVerified {
		return models.VerifyVerified
	}
	// Обычный (пере)коннект: узел новый, его канал ещё не проверен. Именно «проверка идёт», а
	// не «провалилась» — провал имеет отдельный смысл и отдельный текст в UI.
	return models.VerifyChecking
}

// markReapplyTarget/takeReapplyTarget — пометка для verifyStateOnApply выше: цель, к которой
// reapplyConfigIfConnected сейчас переприменяет правила. Одноразовая — её забирает первый же
// применяющий конфиг. Если это оказался не тот путь (параллельное настоящее подключение),
// сверка целей по указателю в applySingBoxConfig не совпадёт, и состояние честно погаснет:
// ошибка возможна только в сторону лишней осторожности.
func (e *Engine) markReapplyTarget(node *models.Node, chain *models.Chain) {
	e.reapplyMu.Lock()
	e.reapplyNode, e.reapplyChain = node, chain
	e.reapplyMu.Unlock()
}

func (e *Engine) takeReapplyTarget(node *models.Node, chain *models.Chain) bool {
	e.reapplyMu.Lock()
	n, c := e.reapplyNode, e.reapplyChain
	e.reapplyNode, e.reapplyChain = nil, nil
	e.reapplyMu.Unlock()
	if node != nil {
		return n != nil && n == node
	}
	if chain != nil {
		return c != nil && c == chain
	}
	return false
}

// verifiedCountBumpInterval — как часто успешная проверка Watchdog вправе увеличить
// Node.VerifiedCount (см. refreshNodeVerified).
//
// Watchdog бьёт каждые 15 секунд — 240 проверок в час. Инкремент на каждой за сутки стабильной
// сессии дал бы +5760 к счётчику, который означает «сколько раз канал подтверждён за всю
// историю» и участвует в ранжировании узлов: один узел, на котором пользователь просидел
// выходные, навсегда перевесил бы весь остальной пул, то есть счётчик перестал бы означать то,
// что он означает. 15 минут — не более 4 инкрементов в час: долгая рабочая сессия всё ещё
// отличается от одного удачного коннекта, но порядок узлов не искажается на порядки.
const verifiedCountBumpInterval = 15 * time.Minute

// refreshNodeVerified — успешная проверка Watchdog продлевает свежесть подтверждения активного
// узла.
//
// Находка 2026-09-06: единственным писателем LastVerifiedAt был recordNodeVerified, вызываемый
// только из runPostConnectHealthCheck — то есть один раз на подключение. Watchdog при этом
// каждые 15 секунд честно доказывал HTTP-запросом через туннель, что канал жив, и выбрасывал
// это знание. В результате Node.ProvenFreshness затухала по экспоненте (полураспад ~24 ч) прямо
// во время стабильной многочасовой сессии, когда трафик заведомо шёл через этот узел, и после
// перезапуска узел выглядел «давно не подтверждался».
//
// Гейт гонки узлов — тот же, что у recordNodeVerified (NL-11): при активной группе urltest
// трафик ведёт победитель, а ActiveNode — инициатор, приписывать подтверждение некому.
func (e *Engine) refreshNodeVerified(latencyMs int64) {
	e.stateMu.RLock()
	connected, active := e.state.Connected, e.state.ActiveNode
	e.stateMu.RUnlock()
	if !connected || active == nil {
		return
	}
	now := time.Now().Unix()
	e.mu.Lock()
	if e.raceNodes != nil {
		e.mu.Unlock()
		return
	}
	// Та же семантика «последнее событие побеждает», что в recordNodeVerified: подтверждение в
	// ту же секунду, что и предыдущий сбой, обязано считаться позже него.
	if now <= active.LastFailedAt {
		now = active.LastFailedAt + 1
	}
	active.LastVerifiedAt = now
	if latencyMs > 0 {
		active.LastVerifiedLatencyMs = latencyMs
	}
	active.FailStreak = 0
	// VerifiedCount — по расписанию (см. verifiedCountBumpInterval). Исключения: узел ещё ни
	// разу не считался подтверждённым (иначе IsProven() остался бы false при живом канале) и
	// смена узла (для нового узла это первое подтверждение вотчдогом).
	if active.VerifiedCount == 0 || e.vcBumpNodeID != active.ID ||
		time.Since(e.vcBumpAt) >= verifiedCountBumpInterval {
		active.VerifiedCount++
		e.vcBumpNodeID = active.ID
		e.vcBumpAt = time.Now()
	}
	e.mu.Unlock()
	e.saveNodesDebounced()
}

// saveNodesDebounced — не чаще раза в nodesSaveDebounce: verified/failure-события приходят
// сериями (health-check каждые секунды на долгой сессии), а nodes_cache.json — 2.5 МБ.
func (e *Engine) saveNodesDebounced() {
	e.nodesSaveMu.Lock()
	if since := time.Since(e.nodesSavedAt); since < nodesSaveDebounce {
		e.nodesSaveDirty = true
		if e.nodesSaveTimer == nil {
			e.nodesSaveTimer = time.AfterFunc(nodesSaveDebounce-since, e.flushNodesSave)
		}
		e.nodesSaveMu.Unlock()
		return
	}
	e.nodesSavedAt = time.Now()
	e.nodesSaveDirty = false
	e.nodesSaveMu.Unlock()
	e.saveNodes()
}

// flushNodesSave — отложенный сброс по таймеру debounce. Без него сбой, записанный через
// 10 с после последнего сохранения, лежал бы в памяти до следующего события или Stop() и
// терялся при убийстве процесса (Android штатно убивает под давлением памяти).
func (e *Engine) flushNodesSave() {
	e.nodesSaveMu.Lock()
	e.nodesSaveTimer = nil
	if !e.nodesSaveDirty {
		e.nodesSaveMu.Unlock()
		return
	}
	e.nodesSavedAt = time.Now()
	e.nodesSaveDirty = false
	e.nodesSaveMu.Unlock()
	e.saveNodes()
}

// nodesSaveDebounce — переменная, а не константа: тесты укорачивают окно.
var nodesSaveDebounce = 60 * time.Second

// recordLastActiveNode персистирует §3 (плавающий приоритет): узел id только что подтвердил
// реально рабочий канал. Пишется в config.json через тот же e.saveConfig, что и PatchConfig —
// переживает перезапуск процесса (nodes_cache.json тоже переживает, но там узел нужно ещё
// найти и отличить от тысяч остальных; отдельное поле в конфиге — самый дешёвый способ). Не
// пишет на диск при отсутствии изменений (частый случай — тот же узел подтверждается снова
// и снова при каждом health-check в рамках одной долгой сессии).
func (e *Engine) recordLastActiveNode(id string) {
	if id == "" {
		return
	}
	e.mu.Lock()
	if e.cfg.LastActiveNodeID == id {
		e.mu.Unlock()
		return
	}
	e.cfg.LastActiveNodeID = id
	cfg := e.cfg
	e.mu.Unlock()
	if err := e.saveConfig(cfg); err != nil {
		e.log(fmt.Sprintf("LastActiveNodeID: ошибка сохранения: %v", err))
	}
}

// ─── Переключение (tunnel-architect FSM) ─────────────────────────────────────

// chainPartnerUnreachableMessage — текст лога «партнёр цепочки Вход-Выход недоступен».
//
// Живой инцидент 2026-09-29: партнёр «Выход» отдал ссылку на свой приватный адрес 10.x.x.x
// (внутри его Wi-Fi), а телефон-«Вход» сидел в ДРУГОЙ сети — каждая попытка кончалась
// dial tcp ...: i/o timeout, и этот лог повторялся бесконечно, ни словом не объясняя, ПОЧЕМУ
// партнёр недостижим: приватный адрес снаружи своей сети недостижим в принципе. Если адрес узла
// приватный/loopback/CGNAT (netutil.LinkHostWarning), дописываем причину — пользователь видит её
// сразу в журнале и в статусе Android, а не гадает про «сломанный sing-box». Для публичного адреса
// и имени хоста текст прежний (предупреждать не о чем: недоступность там — вопрос файрвола/NAT
// партнёра, а не топологии сети). Вынесено в чистую функцию, чтобы проверяться без движка.
func chainPartnerUnreachableMessage(name, address string) string {
	msg := fmt.Sprintf("⚠ Партнёр цепочки Вход-Выход «%s» недоступен — жду восстановления, "+
		"не подменяю случайным узлом из общего пула", name)
	if w := netutil.LinkHostWarning(address); w != "" {
		msg += fmt.Sprintf(". Возможная причина — адрес партнёра «%s»: %s", address, w)
	}
	return msg
}

func (e *Engine) emergencySwitch() {
	// ТЗ v1.3 F4 (BB-4): single-flight. Watchdog (level-trigger), post-connect health-check и
	// monitor могут дёрнуть переключение одновременно; второй вызов раньше начинал ВТОРОЙ
	// выбор/подключение поверх первого (два outbound, пинг-понг A↔B). Первый доводит дело до
	// конца, остальные выходят; Watchdog повторит вызов, если после этого туннель всё ещё мёртв.
	if !e.switching.CompareAndSwap(false, true) {
		e.log("Emergency switch: переключение уже выполняется — повторный вызов пропущен")
		return
	}
	defer e.switching.Store(false)
	e.log("Emergency switch initiated...")

	// Единая точка гейта для ВСЕХ вызывающих (Watchdog, post-connect health check, Monitor —
	// см. комментарий у поля NodeAutoSwitchEnabled в models.AppConfig). Проверяем раньше
	// любых прочих anti-flap механизмов ниже: пользователь явно попросил не переключать
	// узлы вообще, это не то же самое, что "переключать реже".
	if !e.cfg.NodeAutoSwitchEnabled {
		e.log("🛑 Автопереключение узлов отключено пользователем — остаюсь на текущем узле (Настройки → «Не переключать узлы автоматически»)")
		return
	}
	// Защита от гонки с только что сделанным ручным выбором (ConnectByID) — см. комментарий
	// у withinManualConnectSticky. Действует независимо от NodeAutoSwitchEnabled: даже когда
	// автопереключение в целом разрешено, оно не должно тут же перебивать пользователя.
	if e.withinManualConnectSticky() {
		e.log("Emergency switch: пропускаю — пользователь только что выбрал узел вручную, даю ему время подняться")
		return
	}

	e.stateMu.RLock()
	cur := e.state.ActiveNode
	sinceConn := time.Since(e.state.Since)
	e.stateMu.RUnlock()

	// Живой инцидент 2026-08-12 (Android, реальный узел): бесплатный публичный узел
	// отвечал HTTP 409 на КАЖДОЕ соединение с момента подключения — watchdog это видел
	// (FailCount рос без остановки), но обе grace-паузы ниже (MinUptimeSec и sticky
	// «молодая сессия») отсчитываются от момента ПОДКЛЮЧЕНИЯ, а не от момента, когда узел
	// последний раз реально работал. Для узла, который не прошёл НИ ОДНОЙ проверки с
	// момента коннекта, это не защита от флаппинга — это гарантированный простой минимум
	// на MinUptimeSec (у пользователя было дольше: FailCount дошёл до 8, сайты не
	// грузились несколько минут). Если узел хоть раз подтвердился рабочим и потом
	// деградировал — grace всё ещё уместна (не флапаем на переходных сбоях); поэтому
	// bypass только для «ни разу не подтверждён» случая, не для «был жив, умер».
	neverConfirmedHealthy := e.watchdog != nil && !e.watchdog.HasEverSucceeded()

	// Живой отчёт пользователя 2026-09-05 (телефон, реальный узел): Watchdog добросовестно
	// объявил "DEAD (3-6 failures)" через настоящие HTTP-проверки ЧЕРЕЗ ТУННЕЛЬ шесть раз
	// подряд за минуту, но КАЖДЫЙ раз Sticky Session откладывал переключение сообщением
	// "sticky: 16-17 активных соединений" — потому что SyncFromTraffic (см. её комментарий,
	// wireTrafficMonitorStats) считает канал "активным", как только sing-box сообщил
	// ненулевую исходящую скорость: приложения на телефоне продолжают ОТКРЫВАТЬ новые
	// TCP/TLS-попытки к мёртвому узлу (SYN/ClientHello — это тоже "исходящий трафик"),
	// каждая висит 5-10с и проваливается, а на смену ей тут же открывается следующая —
	// счётчик activeConns никогда не опускается до нуля, и sticky-защита длится бесконечно
	// вокруг узла, который уже НИЧЕГО не пропускает. Sticky Session существует, чтобы не
	// спугнуть РЕАЛЬНО работающую сессию — а такой сессии за мёртвым узлом нет: Watchdog
	// не TCP-пингует, а честно ждёт HTTP-ответ через туннель, и три провала подряд с разных
	// целей (FallbackCheckURLs) — куда более сильный сигнал смерти, чем безусловный
	// activeConns>0 из одних лишь исходящих байт. Поэтому подтверждённая Watchdog'ом смерть
	// туннеля обходит sticky-гейт той же логикой, что уже применена для neverConfirmedHealthy
	// чуть выше: защищать активность, которой не существует, не входит в задачу sticky.
	watchdogConfirmedDead := e.watchdog != nil && e.watchdog.GetStatus().State == fallback.WatchdogFailed

	minUptime := time.Duration(e.cfg.MinUptimeSec) * time.Second
	if e.cfg.SwitchOnlyOnFail && sinceConn < minUptime && !neverConfirmedHealthy {
		e.log(fmt.Sprintf("Too early to switch (uptime %v < %v), monitoring...",
			sinceConn.Round(time.Second), minUptime))
		return
	}
	if neverConfirmedHealthy && sinceConn < minUptime {
		e.log("Node never confirmed healthy since connect — bypassing anti-flap grace period")
	}

	// ── Sticky Session: проверяем можно ли переключаться сейчас ──────────────
	// При аварийном переключении (реальный сбой) — не форсируем немедленно,
	// но и не блокируем навсегда. Если сессия активна — пробуем ещё раз позже.
	// forced=true при neverConfirmedHealthy: sticky-защита существует чтобы не спугнуть
	// активную сессию сменой IP — а узел, который ни разу не пропустил трафик, не мог
	// открыть никакой сессии, защищать нечего. То же — при watchdogConfirmedDead (см. её
	// комментарий): подтверждённая HTTP-проверками смерть туннеля сильнее сырого счётчика
	// activeConns, который доживающие ретраи мёртвого узла держат искусственно ненулевым.
	decision := e.stickySession.CanSwitch(neverConfirmedHealthy || watchdogConfirmedDead)
	if !decision.Allow {
		e.log(fmt.Sprintf("Sticky Session: переключение отложено (%s), повтор через %v",
			decision.Reason, decision.RetryIn.Round(time.Second)))
		// Планируем повторную попытку
		e.goTracked(func() {
			wait := decision.RetryIn
			if wait <= 0 || wait > 5*time.Minute {
				wait = 60 * time.Second
			}
			if !e.sleepCtx(wait) {
				return // движок останавливается — не перепроверяем
			}
			// ТЗ v1.3 F4 (ND-10/G-B8): перепроверка — настоящим HTTP health-check через туннель,
			// а не TCP-пингом monitor(): TCP до узла проходит и у мёртвого канала (R1).
			e.runPostConnectHealthCheck()
		})
		return
	}

	// FU-2 (ТЗ надёжности, живой прогон 09-14): аварийное переключение — это ПОЛНОЦЕННЫЙ цикл
	// выбора+подключения, ровно как ScanAndConnect. Раньше они сериализовались только через
	// connMu (применение ОДНОГО sing-box-конфига), но НЕ как цельные циклы: ScanAndConnect
	// держит connCycleActive, однако его tryPreferredNodesFirst/runPoolScan идут ВНЕ connMu —
	// в это окно сюда мог влезть emergencySwitch, взять свободный connMu и переключить узел.
	// Итог — два конкурирующих выбора, пинг-понг A↔B и лишние реконнекты (тот же класс дефекта,
	// что P0-1). Берём тот же single-flight ЦИКЛА: если ScanAndConnect уже идёт, он сам подберёт
	// и поднимет рабочий узел — аварийное переключение поверх него не нужно и вредно (Watchdog
	// level-триггерный: если после скана туннель всё ещё мёртв, monitor/health вызовут нас снова,
	// а к тому моменту connCycleActive уже свободен — между ре-армами scheduleReArm флаг НЕ
	// держится). Берём ПОСЛЕ всех skip-гейтов (auto-switch/manual-sticky/uptime/sticky-session),
	// чтобы быстрый ранний выход не блокировал параллельный ScanAndConnect и не создавал «оба
	// no-op». switching (выше) дедупит emergencySwitch сам с собой; connCycleActive добавляет
	// взаимное исключение со ScanAndConnect. Порядок вложенности: switching ⊃ connCycleActive ⊃
	// connMu — един во всём файле, цикла блокировок нет. ForceSwitchNow сознательно НЕ участвует:
	// это ручное «Сменить сервер», у него приоритет пользователя (заставить его пропускать цикл
	// вернуло бы жалобу C-15 «кнопка ничего не делает»); connMu там по-прежнему защищает от
	// повреждения состояния.
	if !e.connCycleActive.CompareAndSwap(false, true) {
		e.log("Emergency switch: цикл подключения (скан) уже идёт — переключение не требуется, его обслужит текущий цикл")
		return
	}
	defer e.connCycleActive.Store(false)

	// BB-4: после гейтов перепроверяем, что активный узел всё тот же — иначе кто-то уже
	// переключил (ConnectOnce/ScanAndConnect), и «сбой» относится к прошлому узлу.
	e.stateMu.RLock()
	nowActive := e.state.ActiveNode
	e.stateMu.RUnlock()
	if cur != nil && nowActive != nil && nowActive.ID != cur.ID {
		e.log(fmt.Sprintf("Emergency switch: активный узел уже сменился (%s → %s) — переключение не требуется",
			cur.Name, nowActive.Name))
		return
	}

	e.fsm.HandleFailure(fmt.Errorf("monitor detected failure"))

	// Реальный сбой подтверждён (мы дошли до этой точки не через "too early"/sticky-паузу) —
	// запоминаем узел как недавно отказавший, см. поле recentFailures.
	if cur != nil {
		e.markNodeFailed(cur.ID)
	}

	// §4 (докс PLAN_2026-08-28_stubs_and_realfunc.md, наблюдение пользователя): партнёр
	// цепочки Вход-Выход — единственный в своём роде, не взаимозаменяем с публичными
	// узлами. При его сбое НЕ уходим в общий пул (getActiveCandidates и так больше не
	// вернёт публичный узел вместо него — но с публичным сбоем это выглядело бы как
	// внезапная незапрошенная подмена связи с конкретным человеком на случайный VPN).
	// Вместо этого просто повторяем попытку подключения именно к нему; следующий тик
	// monitor()/Watchdog вызовет emergencySwitch снова, если партнёр всё ещё недоступен —
	// естественный периодический ретрай без отдельного цикла.
	if cur != nil && cur.IsChainPartner {
		e.log(chainPartnerUnreachableMessage(cur.Name, cur.Address))
		if err := e.connectNode(cur); err == nil {
			e.fsm.HandleSuccess(time.Duration(cur.Latency) * time.Millisecond)
		} else if classifyConnectFailure(err) == failureNode {
			e.markNodeFailed(cur.ID) // ТЗ HOTSWITCH §8 A1: сбой машины партнёру не вменяем
		}
		return
	}

	e.mu.RLock()
	ranked := e.selectCandidatesExcluding(cur)
	e.mu.RUnlock()

	// ТЗ v1.3 F4 (ND-6): цикл по top-K кандидатам с бюджетом, а не одна попытка по «лучшему».
	if len(ranked) > 0 {
		err := e.connectTopCandidates(ranked, "Switching to")
		if err == nil {
			return
		}
		// ТЗ HOTSWITCH §8 A2: сбой машины — не идём ни по кругу, ни в Tor; повтор ре-армингом.
		if stop, _ := e.endSearchOnNonNodeFailure(err); stop {
			return
		}
	}

	// CyclicNodeSearch (docs/TZ_APF_ROADMAP_v1.2.md): обычный Score-based выбор исчерпан —
	// либо selectBestExcluding не нашёл ни одного кандидата с подтверждённым Score, либо
	// найденный узел не подключился. Раньше это означало прямой переход на tryFallback()
	// (Tor/Snowflake/Psiphon), даже если в пуле ещё остаются непроверенные/низкоскоровые
	// узлы, которые ни разу не пробовались, — с точки зрения пользователя выглядело как
	// «дошёл до конца списка и остановился». При включённом тумблере обходим весь пул по
	// кругу, прежде чем сдаться на аварийные туннели.
	if e.cfg.CyclicNodeSearch {
		ok, cycErr := e.tryCyclicSearch(cur)
		if ok {
			return
		}
		if stop, _ := e.endSearchOnNonNodeFailure(cycErr); stop {
			return
		}
	}

	// BB-5: резервы исчерпаны — не «остаёмся без узлов навсегда», а планируем повтор.
	if err := e.tryFallback(); err != nil {
		e.scheduleReArm(err)
	}
}

// tryCyclicSearch — см. CyclicNodeSearch. Проходит до одного полного круга по пулу
// (selectNextCyclic использует персистентный курсор — сама помнит, где остановилась в
// прошлый раз), пытаясь подключиться к каждому кандидату по очереди. true при первом
// успешном подключении; false, если полный круг пройден и ни один узел не заработал.
//
// Ошибка — только когда круг оборван не отказом узлов (ТЗ HOTSWITCH §8 A2): локальный сбой
// подключения или отмена нас самих. Вызывающий по её классу решает, идти ли в резервы.
func (e *Engine) tryCyclicSearch(ex *models.Node) (bool, error) {
	e.mu.RLock()
	total := len(e.nodes)
	e.mu.RUnlock()
	if total == 0 {
		return false, nil
	}
	// ТЗ v1.3 F4 (G-B9): круг идёт ПАЧКАМИ с TCP-предпроверкой (CheckAll, конкурентно) и
	// бюджетом времени. Раньше каждый узел круга подключался ВСЛЕПУЮ — старт sing-box,
	// health-check, откат — по 10-30 с на заведомо мёртвый узел, тысячи узлов → «ищет часами»
	// (R2). Теперь мёртвые отсеиваются TCP-пробой за секунды, подключаемся только к живым, по
	// возрастанию задержки.
	deadline := time.Now().Add(cyclicSearchBudget)
	seen := make(map[string]bool, total)
	checked := 0
	for checked < total {
		// Живой инцидент 2026-08-26/27: без этой проверки цикл слепо идёт до конца пула
		// (тысячи узлов) даже после Restart()/Stop() — e.wg.Wait() в Restart() ждёт максимум
		// wgWaitTimeout=15s и потом ПРОДОЛЖАЕТ, не убив эту горутину, а сам цикл не смотрит
		// ни на что, кроме "сколько узлов ещё осталось". Внешне выглядело как «после
		// закрытия и повторного открытия не пересоздаёт туннель»: новая сессия успешно
		// стартовала, но лог (и CPU) оставался забит этим осиротевшим циклом, без единого
		// шанса когда-либо завершиться раньше конца списка.
		select {
		case <-e.currentCtx().Done():
			return false, e.currentCtx().Err()
		default:
		}
		if time.Now().After(deadline) {
			e.log(fmt.Sprintf("Циклический поиск: бюджет %v исчерпан (%d/%d узлов проверено)",
				cyclicSearchBudget, checked, total))
			return false, nil
		}
		batch := make([]*models.Node, 0, cyclicBatchSize)
		for len(batch) < cyclicBatchSize && checked+len(batch) < total {
			n := e.selectNextCyclic(ex)
			if n == nil || seen[n.ID] {
				break // круг замкнулся
			}
			seen[n.ID] = true
			batch = append(batch, n)
		}
		if len(batch) == 0 {
			break
		}
		checked += len(batch)
		e.log(fmt.Sprintf("Циклический поиск (%d/%d): TCP-проверка пачки из %d узлов", checked, total, len(batch)))
		results := e.checkNodesSerialized(e.currentCtx(), batch)
		alive := make([]*models.Node, 0, 8)
		for _, r := range results {
			if r == nil {
				continue
			}
			if r.Outcome == models.OutcomeNotChecked {
				return false, e.currentCtx().Err() // отмена контекста — не «мёртвые узлы»
			}
			if r.Success && r.Node != nil {
				alive = append(alive, r.Node)
			}
		}
		sort.SliceStable(alive, func(i, j int) bool { return alive[i].Latency < alive[j].Latency })
		for _, n := range alive {
			if time.Now().After(deadline) {
				e.log("Циклический поиск: бюджет времени исчерпан на этапе подключения")
				return false, nil
			}
			e.log(fmt.Sprintf("Циклический поиск: пробую %s (%dms)", n.Name, n.Latency))
			err := e.connectNode(n)
			if err == nil {
				e.fsm.HandleSuccess(time.Duration(n.Latency) * time.Millisecond)
				return true, nil
			}
			// ТЗ HOTSWITCH §8 A1/A2: сбой машины или отмена — не вина узла и повод прекратить круг.
			if classifyConnectFailure(err) != failureNode {
				e.log(fmt.Sprintf("Циклический поиск: «%s» не подключён не по вине узла (%v) — круг прерван, "+
					"узел не штрафуется", n.Name, err))
				e.rotateAfterStartTimeout(n, err)
				return false, err
			}
			e.recordNodeFailure(n, failReasonConnect)
			e.markNodeFailed(n.ID)
		}
	}
	e.log("Циклический поиск: полный круг пройден, рабочий узел не найден")
	return false, nil
}

// cyclicSearchBudget / cyclicBatchSize — бюджет времени одного круга и размер пачки
// TCP-предпроверки (ТЗ v1.3 F4 G-B9). var, а не const — см. комментарий у connectTopK.
var (
	cyclicSearchBudget = 4 * time.Minute
	cyclicBatchSize    = 100
)

// selectNextCyclic возвращает следующий узел в стабильном (по ID) порядке обхода после
// cyclicSearchLastID, с оборачиванием в начало списка по достижении конца — собственно
// «второй круг», о котором просил пользователь. ex — узел, который заведомо не годится
// (только что отказавший), пропускается независимо от места в очереди. Курсор
// (cyclicSearchLastID) обновляется на каждый вызов, поэтому последовательные вызовы внутри
// одного tryCyclicSearch каждый раз получают РАЗНЫЙ узел, а не зависают на одном.
func (e *Engine) selectNextCyclic(ex *models.Node) *models.Node {
	e.mu.RLock()
	cands := append([]*models.Node(nil), e.nodes...)
	e.mu.RUnlock()
	if len(cands) == 0 {
		return nil
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].ID < cands[j].ID })

	e.cyclicSearchMu.Lock()
	lastID := e.cyclicSearchLastID
	e.cyclicSearchMu.Unlock()

	startIdx := 0
	if lastID != "" {
		for i, n := range cands {
			if n.ID == lastID {
				startIdx = (i + 1) % len(cands)
				break
			}
		}
	}
	for i := 0; i < len(cands); i++ {
		idx := (startIdx + i) % len(cands)
		n := cands[idx]
		if ex != nil && n.ID == ex.ID {
			continue
		}
		if n.IsBlacklisted() || n.UserBanned || n.IsChainPartner {
			continue // F3: бан пользователя; §4: партнёр цепочки не взаимозаменяем с публичными
		}
		e.cyclicSearchMu.Lock()
		e.cyclicSearchLastID = n.ID
		e.cyclicSearchMu.Unlock()
		return n
	}
	return nil
}

// tryFallback — 4-уровневый fallback из tunnel-architect + Фаза 7
func (e *Engine) tryFallback() error {
	e.log("Trying fallback hierarchy...")

	curBT := e.getBlockageType()

	if e.cfg.EnableChain || curBT == detector.BlockageDeep {
		e.log("Fallback L1: chain mode (VPN→Proxy)...")
		// P2.2 (docs/TZ_APF_ROADMAP_v1.2.md): MultiHopEnabled уточняет, КАК цепочка выбирает
		// узлы (протокол-разнообразная выборка через MultiHopSelector), не отдельный режим —
		// EnableChain/BlockageDeep по-прежнему решают, строить ли цепочку вообще.
		var chain *models.Chain
		if e.cfg.MultiHopEnabled {
			chain = e.buildMultiHopChain()
		} else {
			chain = e.buildBestChain()
		}
		if chain != nil {
			if err := e.connectChain(chain); err == nil {
				return nil
			}
		}
	}

	e.log("Fallback L2: re-diagnosing and adapting strategy...")
	bt, strategy, _ := e.detector.DiagnoseAndRecommend(e.currentCtx())
	if bt != curBT {
		e.log(fmt.Sprintf("Blockage type changed: %s → %s", curBT, bt))
		e.stateMu.Lock()
		e.blockageType = bt
		e.strategy = strategy
		e.stateMu.Unlock()
		e.applyStrategy(strategy)
		if best := e.selectBestForStrategy(); best != nil {
			if err := e.connectNode(best); err == nil {
				return nil
			}
		}
	}

	// Фаза 7: Tor/Snowflake/Psiphon — автовыбор лучшего аварийного туннеля
	if e.emergencyFallback != nil {
		e.log("Fallback L3: selecting emergency tunnel (Tor/Snowflake/Psiphon)...")
		ctx, cancel := context.WithTimeout(e.currentCtx(), 15*time.Second)
		bestTunnel := e.emergencyFallback.SelectBest(ctx)
		cancel()

		switch bestTunnel {
		case fallback.FallbackTor:
			e.log("Fallback L3: Tor direct")
			if err := e.applyTorFallback("tor", "Tor"); err == nil {
				return nil
			}
		case fallback.FallbackSnowflake:
			// К2-E П7(б). Раньше здесь стояло «Fallback L3: Tor + Snowflake», а узел
			// назывался «Tor Snowflake» — и то и другое неправда: applyTorFallback строит
			// голый {type:"tor"}, Snowflake не применяется никогда (см.
			// fallback.ErrSnowflakeNotApplicable). Причём SelectBest выбирает Snowflake
			// ИМЕННО когда прямой Tor не отвечает, то есть подменял его на заведомо
			// нерабочий вариант и сообщал об успехе.
			e.log("Fallback L3: прямой Tor (Snowflake применить нечем — " +
				"нет поддержки pluggable transport)")
			if err := e.applyTorFallback("tor", "Tor"); err == nil {
				return nil
			}
		case fallback.FallbackPsiphon:
			// T-16(б): Psiphon требует запущенного psiphond (реального SDK сейчас нет).
			// Не маскируем подмену под «Psiphon»: честно сообщаем и используем явный Tor.
			e.log("Fallback L3: Psiphon недоступен (нет psiphond) — переключаюсь на Tor")
			if err := e.applyTorFallback("tor", "Tor (Psiphon недоступен)"); err == nil {
				return nil
			}
		}
	}

	// L4: последний резерв — чистый Tor.
	// К2-E П7(б): отображаемое имя узла было «Tor Snowflake» при том, что комментарий строкой
	// выше сам говорит «чистый Tor». Имя узла видно пользователю в интерфейсе — это была та же
	// ложь, что и в логе L3.
	e.log("Fallback L4: Tor last resort")
	return e.applyTorFallback("tor", "Tor")
}

// ErrTorUnavailable — Tor нечем исполнить на этой системе (дефект D-A29).
//
// Формулировка обращена к человеку и называет причину, а не следствие: до этой правки
// пользователь видел падение sing-box и решал, что у него сломалась сеть.
var ErrTorUnavailable = errors.New(
	"Tor недоступен: исполняемый файл tor не найден ни в системе, ни в каталоге APF. " +
		"sing-box запускает Tor внешним процессом (встроенного Tor в официальных сборках нет), " +
		"поэтому конфигурация с outbound type:\"tor\" не стартует вовсе. " +
		"На Android бинарника tor нет — аварийный туннель через Tor там пока недоступен")

// ErrPsiphonNotApplicable — C-22 (НОВЫЙ пункт ТЗ v1.4).
//
// Формулировка построена по образцу fallback.ErrSnowflakeNotApplicable и по той же причине:
// молчаливая подмена резерва прямым Tor — худший исход. Пользователь включает «Psiphon»,
// получает ровно тот Tor, который у него, скорее всего, и заблокирован, и не понимает, почему
// «резерв» не помог. Отказ обязан быть один и узнаваться через errors.Is.
var ErrPsiphonNotApplicable = errors.New(
	"Резервный туннель Psiphon недоступен: APF не умеет передать его SOCKS-выход в sing-box — " +
		"все ветки резервного подключения строят конфигурацию Tor. Включение Psiphon сейчас " +
		"означало бы обычный прямой Tor — выберите его явно, если он у вас не заблокирован")

// applyTorFallback — единственная точка, где применяется конфигурация с Tor (дефект D-A29).
//
// Вход:      идентификатор и отображаемое имя аварийного узла.
// Тело:      проверка исполнимости → сборка конфигурации → применение.
// Выход:     nil при успехе, ErrTorUnavailable, если Tor запускать нечем.
// Fail-safe: при отсутствии оркестратора считаем Tor недоступным.
// Инвариант: конфигурация с outbound type:"tor" не применяется, пока не найден файл tor.
//
// Раньше таких мест было четыре (три ветки L3 и «последний резерв» L4), и все они строили
// конфигурацию вслепую. На Android это давало вот такую цепочку: подключение к обычному
// узлу не поднялось → фаллбэк → sing-box падает с «exec: tor: executable file not found»
// → движок откатывается на стадии apply_runtime. Пользователь узнавал только последнее
// звено и не мог понять, что причина — отсутствующий бинарник, а не блокировка.
func (e *Engine) applyTorFallback(id, name string) error {
	if e.emergencyFallback == nil || !e.emergencyFallback.TorAvailable() {
		e.log("Fallback: " + ErrTorUnavailable.Error())
		return ErrTorUnavailable
	}
	e.builderMu.Lock()
	cfg := e.builder.BuildTor()
	e.builderMu.Unlock()
	node := &models.Node{ID: id, Name: name, Protocol: models.ProtoTor}
	return e.applySingBoxConfig(cfg, node, nil)
}

func (e *Engine) buildBestChain() *models.Chain {
	// См. тот же комментарий у selectBestForStrategy — getActiveCandidates не лочит сама,
	// раньше tryFallback звал её отсюда тоже без лока.
	e.mu.RLock()
	cands := e.getActiveCandidates(0)
	e.mu.RUnlock()
	if len(cands) < 2 {
		return nil
	}
	var chain []*models.Node
	seen := map[string]bool{}
	for _, n := range cands {
		if !seen[n.Address] && n.Score > 0 {
			chain = append(chain, n)
			seen[n.Address] = true
		}
		if len(chain) == 2 {
			break
		}
	}
	if len(chain) < 2 {
		return nil
	}
	return &models.Chain{Nodes: chain}
}

// buildMultiHopChain — P2.2 (docs/TZ_APF_ROADMAP_v1.2.md): та же роль в tryFallback L1, что
// и buildBestChain, но выбор узлов идёт через MultiHopSelector.SelectBestChain
// (internal/dpi/multihop.go) — предпочитает узлы с РАЗНЫМИ протоколами на каждом хопе, не
// просто два самых высокоскоровых. dpi.Hop уже размечает роли по тому же соглашению, что
// singbox.Builder.BuildChain ожидает от models.Chain.Nodes (индекс 0 — точка входа, куда
// подключается клиент напрямую; последний — точка выхода в интернет) — прямое отображение
// без переупорядочивания. Собственный MultiHopBuilder (multihop.go) сознательно НЕ
// используется: у него свой отдельный *singbox.Builder, отдельный от e.builder, и он
// (вместе с BuildViaProxy/BuildThreeHop) нигде не тестировался живым подключением — здесь
// нужна только его СЕЛЕКЦИЯ узлов, построение конфигурации идёт уже проверенным connectChain.
func (e *Engine) buildMultiHopChain() *models.Chain {
	hops := e.cfg.MultiHopCount
	if hops != 2 && hops != 3 {
		hops = 2
	}
	// См. тот же комментарий у selectBestForStrategy — getActiveCandidates не лочит сама.
	e.mu.RLock()
	cands := e.getActiveCandidates(0)
	e.mu.RUnlock()
	mhChain := e.multiHop.SelectBestChain(cands, hops)
	if mhChain == nil || len(mhChain.Hops) < 2 {
		return nil
	}
	nodes := make([]*models.Node, len(mhChain.Hops))
	for i, h := range mhChain.Hops {
		nodes[i] = h.Node
	}
	return &models.Chain{Nodes: nodes}
}

// ─── Мониторинг ──────────────────────────────────────────────────────────────

func (e *Engine) monitorLoop() {
	e.mu.RLock()
	checkInterval := e.cfg.CheckInterval
	e.mu.RUnlock()
	if checkInterval <= 0 {
		checkInterval = 30
	}
	ticker := time.NewTicker(time.Duration(checkInterval) * time.Second)
	// Sprint 4: очищаем истёкшие domain sticky сессии раз в час
	cleanTicker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	defer cleanTicker.Stop()
	// ТЗ v1.3 F5.5 (GAP-25): периодическая проверка DNS/IPv6-утечки по DNSLeakTestInterval
	// (секунды; 0 — выключено). Настройка существовала с Фазы 5 (дефолт 300), но никем не
	// читалась — единственная проверка шла один раз после подключения. Минимум 60 с: чаще —
	// лишний трафик наружу через туннель без пользы. nil-канал в select блокируется вечно.
	e.mu.RLock()
	leakInterval := e.cfg.DNSLeakTestInterval
	e.mu.RUnlock()
	var leakC <-chan time.Time
	if leakInterval > 0 {
		if leakInterval < 60 {
			leakInterval = 60
		}
		leakTicker := time.NewTicker(time.Duration(leakInterval) * time.Second)
		defer leakTicker.Stop()
		leakC = leakTicker.C
	}
	for {
		select {
		case <-e.currentCtx().Done():
			return
		case <-ticker.C:
			e.monitor()
		case <-leakC:
			if e.IsConnected() {
				e.goTracked(e.runPostConnectLeakTest)
			}
		case <-cleanTicker.C:
			e.stickySession.CleanExpiredDomainSessions()
			e.log(fmt.Sprintf("Domain sticky: cleaned (active: %d)", e.stickySession.DomainStickyCount()))
		}
	}
}

// Инцидент 2026-08-19 (второй раунд, живой прогон): monitor() пингует e.state.ActiveNode
// напрямую TCP-сокетом (checker.QuickPing) в обход туннеля. applyKillSwitch() внутри
// applySingBoxConfig переключает разрешённый Kill Switch IP на НОВЫЙ узел РАНЬШЕ, чем
// e.state.ActiveNode обновляется на тот же узел — обновление стейта происходит только
// ПОСЛЕ успешного Reload/Start (~1с по логам «took=918ms»). Если monitorLoop-тикер
// срабатывает именно в этом окне, он пингует СТАРЫЙ узел (state ещё не обновился) через
// УЖЕ переключённый на новый IP Kill Switch — получает настоящий WFP-отказ («connectex:
// forbidden by its access permissions», НЕ проблема сети/узла) и засчитывает старому,
// рабочему узлу ложный провал. Серия ложных провалов доводит FailCount до порога и
// вызывает emergencySwitch() — ненужное переключение, спровоцированное самим APF, а не
// реальной проблемой узла (подтверждено логами: узел только что прошёл health-check и
// DNS-тест, затем «Monitor FAIL» на нём же в первую же секунду после начала нового скана).
// connMu сериализует все реальные попытки подключения/переключения (applySingBoxConfig) —
// если она СЕЙЧАС занята, переключение уже идёт, и проверять «старый» активный узел
// бессмысленно: он либо уже не активен, либо вот-вот перестанет быть им.
func (e *Engine) monitor() {
	e.stateMu.RLock()
	connected, active := e.state.Connected, e.state.ActiveNode
	e.stateMu.RUnlock()
	if !connected || active == nil {
		return
	}
	if !e.connMu.TryLock() {
		return // переключение уже в процессе — пропускаем тик, не мешаем и не гоняемся
	}
	defer e.connMu.Unlock()

	lat, err := e.checker.QuickPing(e.currentCtx(), active)
	if err != nil {
		active.FailCount++
		e.log(fmt.Sprintf("Monitor FAIL #%d: %s", active.FailCount, err))
		if active.FailCount >= 5 {
			e.log("Monitor: consistent failures, switching...")
			// Точка обнаружения смерти №2: пять отказов подряд по активному узлу. Состояние
			// обязано стать честным здесь, а не «если переключение вдруг состоится» — см.
			// markChannelDead про семь ранних return в emergencySwitch.
			e.markChannelDead("monitor: 5 отказов подряд")
			e.recordNodeFailure(active, failReasonMonitor) // F1.2: реальный сбой — в узел
			e.goTracked(e.emergencySwitch)
		}
		return
	}
	active.Latency = lat
	active.FailCount = 0
	e.fsm.HandleSuccess(time.Duration(lat) * time.Millisecond)
}

func (e *Engine) sourceUpdateLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-e.currentCtx().Done():
			return
		case <-ticker.C:
			e.updateSources(false)
		}
	}
}

// isUnsupportedProtocol — P1.2 (docs/TZ_APF_ROADMAP_v1.2.md): WireGuard/AmneziaWG узлы
// парсятся и скорятся нормально, но buildOutbound() (internal/singbox/config_builder.go)
// безусловно отказывает на любой реальной попытке подключения — sing-box 1.13.16 (закреплённая
// версия проекта) убрал outbound-тип "wireguard". Раньше такие узлы всё равно попадали в пул,
// проходили health-check цикл за циклом и никогда не работали — впустую тратили место и циклы
// скоринга. Фильтруем на входе в пул (не в parser.ParseLink — та просто конвертирует ссылку в
// Node, решение "годится ли протокол для ЭТОЙ сборки" — забота движка, не парсера).
func isUnsupportedProtocol(p models.Protocol) bool {
	return p == models.ProtoWireGuard || p == models.ProtoAmneziaWG
}

// sourceTunnelProxy — адрес локального SOCKS движка для загрузки источников через туннель
// (C-7). Возвращает ("", false), когда тянуть надо напрямую.
//
// Условий два, и оба обязательны:
//   - подключение активно (иначе SOCKS движка попросту никто не слушает);
//   - режим «прокси» (в VPN/TUN весь трафик и так в туннеле — второй заворот только удлинил
//     бы путь и добавил точку отказа; пункт 3 решения C-7).
func (e *Engine) sourceTunnelProxy() (string, bool) {
	if !e.IsConnected() {
		return "", false
	}
	e.mu.RLock()
	mode := e.cfg.ConnectionMode
	port := e.cfg.ListenPort
	e.mu.RUnlock()
	if mode != models.ModeProxy || port <= 0 {
		return "", false
	}
	return fmt.Sprintf("127.0.0.1:%d", port), true
}

func (e *Engine) updateSources(force bool) {
	// N-8 (§3 DIAG_N8_PLAN.md): ожидание после KS-фикса ~1-3с (параллельная загрузка подписок).
	t0 := time.Now()
	defer func() { e.logDiagN8("updateSources", t0) }()
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()
	src := sources.New(cfg)
	// C-7 (ТЗ v1.4, B3 #7): при активном подключении в proxy-режиме источники узлов идут
	// ЧЕРЕЗ туннель. Раньше подписки тянулись мимо него всегда — то есть ровно в «худший
	// день», когда пул мёртв и обновить его неоткуда, запрос шёл по заблокированному пути.
	src.OnLog = e.log
	src.SetTunnelProxy(e.sourceTunnelProxy)
	newNodes, err := src.FetchAll(e.currentCtx(), force)
	// ТЗ v1.3 F4 Stage 0: время загрузки — в SourceConfig.LastUpdatedAt (персистентно), иначе
	// следующий менеджер снова считает все источники «никогда не загруженными».
	e.persistSourceTimestamps(src.LastUpdated())
	if err != nil || len(newNodes) == 0 {
		return
	}
	// ТЗ v1.3 F3/NL-9/NL-10: единая точка слияния — надгробия, ValidateNode, дедуп внутри выдачи.
	e.mergeFetchedNodes(newNodes, "Sources")
}

// persistSourceTimestamps переносит время последней загрузки источников в cfg.Sources[i].
// LastUpdatedAt и сохраняет config.json, если что-то изменилось (ТЗ v1.3 F4 Stage 0).
func (e *Engine) persistSourceTimestamps(updated map[string]time.Time) {
	if len(updated) == 0 {
		return
	}
	e.mu.Lock()
	changed := false
	for i := range e.cfg.Sources {
		t, ok := updated[e.cfg.Sources[i].ID]
		if !ok {
			continue
		}
		if ts := t.Unix(); ts > e.cfg.Sources[i].LastUpdatedAt {
			e.cfg.Sources[i].LastUpdatedAt = ts
			changed = true
		}
	}
	var err error
	if changed && e.saveConfig != nil {
		err = e.saveConfig(e.cfg)
	}
	e.mu.Unlock()
	if err != nil {
		e.log(fmt.Sprintf("Sources: ошибка сохранения времени обновления: %v", err))
	}
}

func (e *Engine) ensureSingBox() {
	if e.proc.IsInstalled() {
		ver, _ := e.proc.Version()
		e.log(fmt.Sprintf("sing-box: %s", ver))
		return
	}
	e.log("Downloading sing-box automatically...")
	if err := e.dl.Download(e.currentCtx()); err != nil {
		e.log(fmt.Sprintf("Download failed: %v", err))
		e.log("Manual install: https://github.com/SagerNet/sing-box/releases")
	}
}

// ─── Выбор узла ──────────────────────────────────────────────────────────────

func (e *Engine) selectBest() *models.Node { return e.selectBestExcluding(nil) }

func (e *Engine) selectBestExcluding(ex *models.Node) *models.Node {
	ranked := e.selectCandidatesExcluding(ex)
	if len(ranked) == 0 {
		return nil
	}
	return ranked[0]
}

// selectCandidatesExcluding — упорядоченный список кандидатов на переключение без ex
// (ТЗ v1.3 F4: emergencySwitch идёт по top-K, а не по одному). Вызывающие держат e.mu.RLock.
func (e *Engine) selectCandidatesExcluding(ex *models.Node) []*models.Node {
	all := e.getActiveCandidates(0)
	// ТЗ v1.3 F1.5/F2 (консилиум 2026-09-03, PIN-5/PIN-6): фильтры — ДО pin-ветки. Раньше
	// закреплённый узел возвращался раньше проверки recentFailures и порога Score — при
	// хронически плохом pin движок пинг-понгал A↔B. Пропуск pin теперь виден в логе (I3).
	cands := e.filterSelectable(all, ex)
	var pinned *models.Node
	if pid := e.PinnedNodeID(); pid != "" {
		pinned = e.pickPinned(cands, pid)
	}
	now := time.Now().Unix()
	sortCandidatesProvenFirst(cands, now)
	cands = e.favoritesFirst(cands) // F2: избранное — перед остальным пулом
	ranked := selectableOnly(cands)
	if len(ranked) == 0 {
		// Все годные узлы недавно отказали (recentFailures) — это не повод остаться без кандидата
		// и свалиться в Tor/Psiphon: берём отказавших по порядку (прежний контракт
		// TestSelectBestExcluding_FallsBackIfAllRecentlyFailed). Бан пользователя и «ни разу не
		// проверен» смягчению не подлежат.
		lenient := e.filterCandidates(all, ex, false)
		sortCandidatesProvenFirst(lenient, now)
		lenient = e.favoritesFirst(lenient)
		ranked = selectableOnly(lenient)
	}
	if pinned != nil {
		ranked = moveToFront(ranked, pinned)
	}
	return ranked
}

// firstSelectable — первый годный к подключению узел отсортированного списка: с ненулевым
// Score или подтверждённый реальным трафиком (его TCP-Score мог устареть, но подтверждение
// туннеля весомее).
func firstSelectable(sorted []*models.Node) *models.Node {
	for _, n := range sorted {
		if n.Score > 0.001 || n.IsProven() {
			return n
		}
	}
	return nil
}

// recentFailureTTL — сколько помнить, что узел только что доказанно подвёл (см. поле
// recentFailures). Того же порядка, что MinUptimeSec по умолчанию (2 мин) — не годами, но
// достаточно, чтобы серия подряд идущих emergencySwitch не зациклилась на одних и тех же 1-2
// топовых по Score узлах.
const recentFailureTTL = 10 * time.Minute

// markNodeFailed отмечает узел как только что доказанно нерабочий (зовётся из
// emergencySwitch непосредственно перед выбором замены). Заодно чистит устаревшие записи —
// карта не растёт неограниченно на долгоживущем движке.
func (e *Engine) markNodeFailed(id string) {
	if id == "" {
		return
	}
	now := time.Now()
	e.recentFailuresMu.Lock()
	defer e.recentFailuresMu.Unlock()
	e.recentFailures[id] = now
	for k, t := range e.recentFailures {
		if now.Sub(t) > recentFailureTTL {
			delete(e.recentFailures, k)
		}
	}
}

// isRecentlyFailed сообщает, отмечался ли узел как отказавший в последние recentFailureTTL.
func (e *Engine) isRecentlyFailed(id string) bool {
	e.recentFailuresMu.Lock()
	defer e.recentFailuresMu.Unlock()
	t, ok := e.recentFailures[id]
	if !ok {
		return false
	}
	return time.Since(t) <= recentFailureTTL
}

// filterSelectable — общий фильтр годности кандидата для ПОДКЛЮЧЕНИЯ (ТЗ v1.3 F1.5):
// не ex, не UserBanned (F3), не IsUnchecked (слепые подключения запрещены — ND-2; такие узлы
// получают шанс только через обход Stage 1/getRescanBatch), не в recentFailures. Не берёт e.mu
// (вызывающие selectBestExcluding уже держат RLock — V3 п.4).
func (e *Engine) filterSelectable(cands []*models.Node, ex *models.Node) []*models.Node {
	return e.filterCandidates(cands, ex, true)
}

// filterCandidates — тело filterSelectable; skipRecentlyFailed=false даёт «мягкий» проход для
// случая, когда ВСЕ годные узлы недавно отказали (см. selectBestExcluding).
func (e *Engine) filterCandidates(cands []*models.Node, ex *models.Node, skipRecentlyFailed bool) []*models.Node {
	// F2: подавленный после «Сменить сервер» pin исключается из кандидатов ЦЕЛИКОМ (не только
	// из pin-ветки) — иначе он тут же выиграл бы общий отбор по Score, и переключение не
	// состоялось бы (I5).
	suppressedID := ""
	if e.pinSuppressed() {
		suppressedID = e.PinnedNodeID()
	}
	out := cands[:0:0]
	for _, n := range cands {
		if n == nil || (ex != nil && n.ID == ex.ID) {
			continue
		}
		if n.UserBanned || n.IsUnchecked() || (suppressedID != "" && n.ID == suppressedID) {
			continue
		}
		if skipRecentlyFailed && e.isRecentlyFailed(n.ID) {
			continue
		}
		out = append(out, n)
	}
	return out
}

// pickPinned — закреплённый узел из уже отфильтрованных кандидатов; если он не прошёл фильтры
// (бан/недавний отказ/не в пуле) или последнее реальное событие по нему — сбой, пропуск
// логируется с причиной (F2 I3/I5), а не происходит молча (PIN-6).
func (e *Engine) pickPinned(filtered []*models.Node, pid string) *models.Node {
	// F2: после «Сменить сервер» pin подавлен на recentFailureTTL (suppressPin) — иначе выбор
	// тут же вернулся бы на него (I5). Статус suppressed уже выставлен suppressPin.
	if e.pinSuppressed() {
		e.log("📌 Закреплённый узел пропущен: подавлен после ручного переключения")
		return nil
	}
	for _, n := range filtered {
		if n.ID != pid {
			continue
		}
		// Окно пропуска — см. pinFreshFailure: recentFailureTTL от момента сбоя, а не «навсегда».
		if pinFreshFailure(n) {
			e.log(fmt.Sprintf("📌 Закреплённый узел «%s» пропущен: последнее событие по нему — сбой (%s)", n.Name, n.LastFailReason))
			e.setPinnedStatus(pinStatusUnreachable)
			return nil
		}
		return n
	}
	e.log("📌 Закреплённый узел пропущен: недоступен для выбора (нет в пуле, забанен или недавно отказал)")
	e.setPinnedStatus(pinStatusUnreachable)
	return nil
}

// sortCandidatesProvenFirst — порядок выбора F1.5: сначала узлы, подтверждённые реальным
// трафиком (свежие подтверждения раньше, при равной свежести — меньшая задержка через
// туннель), у которых последнее событие не сбой; затем все остальные по Score убыв.
func sortCandidatesProvenFirst(cands []*models.Node, nowUnix int64) {
	rank := func(n *models.Node) (int, float64) {
		if n.IsProven() && !n.LastOutcomeIsFailure() {
			lat := n.LastVerifiedLatencyMs
			if lat < 50 {
				lat = 50
			}
			return 0, n.ProvenFreshness(nowUnix) * (1000.0 / float64(lat))
		}
		return 1, n.Score
	}
	sort.SliceStable(cands, func(i, j int) bool {
		bi, ki := rank(cands[i])
		bj, kj := rank(cands[j])
		if bi != bj {
			return bi < bj
		}
		return ki > kj
	})
}

// mergeNodeHistory — слияние истории двух записей одного узла (F1.3): kept получает максимум
// подтверждений/сбоев и объединённые пользовательские флаги.
func mergeNodeHistory(kept, dup *models.Node) {
	if dup.VerifiedCount > kept.VerifiedCount {
		kept.VerifiedCount = dup.VerifiedCount
	}
	if dup.LastVerifiedAt > kept.LastVerifiedAt {
		kept.LastVerifiedAt = dup.LastVerifiedAt
		kept.LastVerifiedLatencyMs = dup.LastVerifiedLatencyMs
		kept.LastVerifiedCountry = dup.LastVerifiedCountry
		kept.LastVerifiedExitIP = dup.LastVerifiedExitIP
	}
	if dup.LastFailedAt > kept.LastFailedAt {
		kept.LastFailedAt = dup.LastFailedAt
		kept.LastFailReason = dup.LastFailReason
	}
	if dup.FailStreak > kept.FailStreak {
		kept.FailStreak = dup.FailStreak
	}
	kept.UserBanned = kept.UserBanned || dup.UserBanned
	if kept.UserNote == "" {
		kept.UserNote = dup.UserNote
	}
	if kept.LastChecked.IsZero() && !dup.LastChecked.IsZero() {
		kept.LastChecked, kept.Score, kept.Status = dup.LastChecked, dup.Score, dup.Status
		kept.Latency, kept.Jitter, kept.Loss = dup.Latency, dup.Jitter, dup.Loss
	}
}

func (e *Engine) getActiveCandidates(limit int) []*models.Node {
	var result []*models.Node
	for _, n := range e.nodes {
		// §4 (docs/PLAN_2026-08-28_stubs_and_realfunc.md): партнёр цепочки Вход-Выход не
		// взаимозаменяем ни с одним публичным узлом — не конкурирует за авто-выбор и не
		// попадает в батч пересканирования (getRescanBatch строится поверх этой же
		// функции). Подключение К НЕМУ идёт другим путём (AddChainPartnerFromLink/
		// ConnectByID/emergencySwitch-спецветка), не через этот общий пул.
		// ТЗ v1.3 F3: ручной бан пользователя — вон из ЛЮБОГО отбора (в т.ч. цепочки/гонка).
		if n != nil && !n.IsBlacklisted() && !n.IsChainPartner && !n.UserBanned {
			result = append(result, n)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Score > result[j].Score })
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result
}

// rescanExploreFraction — доля батча перепроверки, отданная под давно-непроверенные узлы
// (см. getRescanBatch). var, не const — test-seam, тот же приём, что у ksCallTimeout.
var rescanExploreFraction = 0.4

// scanBatchLimit — сколько узлов проверяет один проход runPoolScan. Единственный лимит на
// этом пути: раньше их было два (запрос батча на 100 + слепая обрезка до 50), и вторая
// операция срезала весь explore-хвост первой — см. комментарий в runPoolScan (P1-2).
var scanBatchLimit = 50

// canaryAutoRunEnabled — запускать ли Canary-тест автоматически после каждого подключения.
//
// false с 2026-09-01 (P2 аудита): зонды теста идут мимо туннеля к сервису
// TLS-фингерпринтинга и демаскируют пользователя, а его вердикт при этом недостижим по
// построению. Подробности — в комментарии runPostConnectCanary. var, а не const: тест может
// включить автоматику, чтобы проверить сам путь.
var canaryAutoRunEnabled = false

// getRescanBatch — кандидаты для батча ПЕРЕТЕСТИРОВАНИЯ сети (ScanAndConnect), НЕ то же
// самое, что getActiveCandidates(limit): та функция — чистый top-N по Score, корректный для
// ВЫБОРА (selectBestForStrategy, SelectMultiHopChain — там действительно нужны именно лучшие).
// Для ПЕРЕПРОВЕРКИ чистый top-N — самоусиливающееся узкое место (QA v1.0 §1, живой инцидент:
// у пользователя из 5314 узлов пула реально использовались только 1-2 — низкоскоровые/никогда
// не проверенные узлы просто никогда не попадали в батч перепроверки, чтобы получить шанс на
// Score, и поэтому никогда не могли туда попасть — замкнутый круг). Решение из плана QA v1.0:
// смешивать часть лимита с давно-непроверенными узлами вместо чистого топа.
func (e *Engine) getRescanBatch(limit int) []*models.Node {
	all := e.getActiveCandidates(0) // весь активный пул, уже отсортирован по Score убыв.
	if limit <= 0 || len(all) <= limit {
		return all
	}

	exploreCount := int(float64(limit) * rescanExploreFraction)
	topCount := limit - exploreCount

	top := all[:topCount]
	// all[topCount:] по построению не пересекается с top — отдельная проверка на дубликаты
	// не нужна.
	stale := append([]*models.Node(nil), all[topCount:]...)
	// LastChecked по возрастанию: узлы, которых ещё не коснулись (нулевое время), и давно не
	// перепроверявшиеся — первыми.
	sort.Slice(stale, func(i, j int) bool { return stale[i].LastChecked.Before(stale[j].LastChecked) })
	if len(stale) > exploreCount {
		stale = stale[:exploreCount]
	}

	batch := make([]*models.Node, 0, len(top)+len(stale))
	batch = append(batch, top...)
	batch = append(batch, stale...)
	return batch
}

// ─── Сериализация проверок узлов (К2-E П1) ────────────────────────────────────
//
// Три обёртки ниже — ЕДИНСТВЕННЫЙ разрешённый способ позвать checker из движка по путям
// runSweep / runPoolScan / tryCyclicSearch / CheckOne. Прямой вызов e.checker.Check* с этих
// путей возвращает гонку из комментария к nodeCheckMu.
//
// Вход:      контекст и узел (узлы) для проверки.
// Тело:      захват nodeCheckMu → один вызов checker'а → освобождение.
// Выход:     ровно то, что вернул checker (обёртки ничего не интерпретируют).
// Fail-safe: лок держится строго на время вызова; ни подключение, ни обновление источников,
//
//	ни колбэки OnNodeUpdated под ним не выполняются — взаимная блокировка невозможна.
//
// Не покрыты сознательно: QuickPing (watchdog, latency активного узла — не пишет поля пула)
// и HTTPHealthCheck* (проверка канала, а не узла).
func (e *Engine) checkNodeSerialized(ctx context.Context, node *models.Node) *models.CheckResult {
	e.nodeCheckMu.Lock()
	defer e.nodeCheckMu.Unlock()
	return e.checker.CheckOne(ctx, node)
}

func (e *Engine) checkNodesSerialized(ctx context.Context, nodes []*models.Node) []*models.CheckResult {
	e.nodeCheckMu.Lock()
	defer e.nodeCheckMu.Unlock()
	return e.checker.CheckAll(ctx, nodes)
}

func (e *Engine) checkNodesWithSerialized(ctx context.Context, nodes []*models.Node, concurrency, pings int) []*models.CheckResult {
	e.nodeCheckMu.Lock()
	defer e.nodeCheckMu.Unlock()
	return e.checker.CheckAllWith(ctx, nodes, concurrency, pings)
}

// ─── Публичный API ────────────────────────────────────────────────────────────

// Найдено ревью (см. память apf-host-watchdog-and-review-findings): раньше «голый» go
// не отслеживался через e.wg — Stop() мог вернуться раньше этой горутины и получить
// тихий реконнект сразу после явного Disconnect. goTracked() (уже используется для
// emergencySwitch/enableKillSwitchWithUAC) закрывает и это, и заодно не стартует
// горутину вовсе, если e.ctx уже отменён (Stop() идёт прямо сейчас).
func (e *Engine) ForceRescan() {
	e.goTracked(func() {
		e.mu.Lock()
		for _, n := range e.nodes {
			n.LastChecked = time.Time{}
			n.Score = 0
		}
		e.mu.Unlock()
		e.log("Force rescan: re-diagnosing blockage...")
		bt, strategy, report := e.detector.DiagnoseAndRecommend(e.currentCtx())
		e.stateMu.Lock()
		e.blockageType = bt
		e.strategy = strategy
		e.stateMu.Unlock()
		e.log(report)
		e.applyStrategy(strategy)
		e.updateSources(true)
		e.ScanAndConnect()
	})
}

func (e *Engine) AddNodeFromLink(link string) error {
	node, err := parser.ParseLink(link)
	if err != nil {
		return err
	}
	// B-29: не допускаем заведомо некорректный узел в пул (молча падал бы при проверке).
	if err := models.ValidateNode(node); err != nil {
		return err
	}
	// P1.2 (docs/TZ_APF_ROADMAP_v1.2.md): см. комментарий у isUnsupportedProtocol — явный
	// отказ сразу, а не «добавился, но никогда не подключится» после N бесплодных попыток.
	if isUnsupportedProtocol(node.Protocol) {
		return fmt.Errorf("протокол %s не поддерживается этой сборкой sing-box (outbound-тип "+
			"удалён в 1.13.0) — узел не добавлен", node.Protocol)
	}
	node.Source = "manual"
	e.clearTombstone(node.ID) // F3: явное добавление пользователем сильнее прошлого удаления
	e.mu.Lock()
	for _, existing := range e.nodes {
		if existing.ID != node.ID {
			continue
		}
		// Полный дубликат — это НЕ повод отказать. Пользователь, вручную вставляющий ссылку,
		// которую он только что где-то взял, сообщает нам ровно одно: «я знаю, что этот узел
		// рабочий». Прежний ответ «already exists» выглядел как отказ добавить, при том что
		// узел мог лежать в пуле зачернённым после серии неудач и больше никогда не
		// пробоваться. Поэтому вместо ошибки — «оживляем» запись.
		//
		// И ОБЯЗАТЕЛЬНО переносим параметры подключения из свежеразобранной ссылки. Иначе
		// правка вырождается в ловушку: пользователь вставляет ссылку с ИСПРАВЛЕННЫМИ
		// параметрами (сменился Reality-ключ, SNI, ws-путь, flow), получает «успех» — а в
		// пуле остаётся старая нерабочая конфигурация, и узел по-прежнему не подключается.
		// Ровно та жалоба, которую эта ветка и должна закрывать (найдено ревью 2026-08-24).
		existing.TLS = node.TLS
		existing.Transport = node.Transport
		existing.Flow = node.Flow
		existing.AltID = node.AltID
		if node.Name != "" {
			existing.Name = node.Name
		}
		existing.FailCount = 0
		existing.BlacklistedUntil = time.Now().Add(-time.Second)
		existing.Score = 0
		existing.LastChecked = time.Time{}
		existing.Source = "manual"
		revived := existing
		e.mu.Unlock()
		e.saveNodes()
		e.log(fmt.Sprintf("Узел уже был в списке — сброшен и будет проверен заново: %s", revived.Name))
		go func() {
			r := e.checkNodeSerialized(e.currentCtx(), revived)
			if e.OnNodeUpdated != nil {
				e.OnNodeUpdated(revived)
			}
			if r.Success {
				e.log(fmt.Sprintf("Node OK: %s (%dms)", revived.Name, r.Latency))
			}
		}()
		return nil
	}
	e.nodes = append(e.nodes, node)
	e.mu.Unlock()
	e.saveNodes()
	go func() {
		r := e.checkNodeSerialized(e.currentCtx(), node)
		if e.OnNodeUpdated != nil {
			e.OnNodeUpdated(node)
		}
		if r.Success {
			e.log(fmt.Sprintf("Node OK: %s (%dms)", node.Name, r.Latency))
		}
	}()
	return nil
}

// AddChainPartnerFromLink — точка входа роли «Вход»: пользователь вставляет ссылку,
// полученную от партнёра в роли «Выход» (BuildServerRoleLink), и сразу подключается к нему.
//
// Отличие от обычного AddNodeFromLink (§4, docs/PLAN_2026-08-28_stubs_and_realfunc.md):
// партнёр по цепочке — не взаимозаменяем с публичными VPN-узлами (единственный в своём
// роде, конкретная связь "точка-точка" с конкретным человеком, а не «ещё один узел в
// пуле»). Помечаем IsChainPartner=true, чтобы:
//   - обычный автовыбор/пересканирование (getActiveCandidates) никогда не подменял его
//     случайным публичным узлом и не тратил на него бюджет батча пересканирования;
//   - при сбое emergencySwitch повторял попытку подключения именно к нему, а не уходил в
//     общий пул (см. спецветку в emergencySwitch).
//
// В отличие от AddNodeFromLink — подключается СРАЗУ (не ждёт следующего ScanAndConnect):
// пользователь только что вручную вставил конкретную ссылку от конкретного партнёра,
// ожидание планового скана здесь неуместно, это не «ещё один кандидат в пул».
func (e *Engine) AddChainPartnerFromLink(link string) (*models.Node, error) {
	node, err := parser.ParseLink(link)
	if err != nil {
		return nil, err
	}
	if err := models.ValidateNode(node); err != nil {
		return nil, err
	}
	if isUnsupportedProtocol(node.Protocol) {
		return nil, fmt.Errorf("протокол %s не поддерживается этой сборкой sing-box — узел не добавлен", node.Protocol)
	}
	node.Source = "chain_partner"
	node.IsChainPartner = true
	if node.Name == "" || node.Name == string(node.Protocol) {
		node.Name = fmt.Sprintf("Партнёр Вход-Выход %s:%d", node.Address, node.Port)
	}

	// [консилиум] node.ID уже вычислен parser.ParseLink от ИСХОДНЫХ Address/Port (в
	// relay-режиме — это адрес RelayServer из ссылки, docs/TZ_APF_RELAY_v1.0.md §3, НЕ адрес
	// устройства «Выход» напрямую) — стабилен независимо от того, что чуть ниже Address/Port
	// подменяются на локальный адрес EntryBridge. Пересчитывать ID ПОСЛЕ подмены было бы
	// ошибкой: у локального моста новый эфемерный порт при КАЖДОМ переподключении, и дедуп
	// (`existing.ID == node.ID` ниже) перестал бы находить старую запись — пул засорялся бы
	// узлами-призраками одного и того же партнёра.
	var newBridge *relay.EntryBridge
	if node.ExtraParams["apf_relay"] == "1" {
		exitID := node.ExtraParams["apf_exitid"]
		if exitID == "" {
			return nil, fmt.Errorf("relay-ссылка без apf_exitid — повреждена")
		}
		// [TZ_RELAY_HARDENING_2026-08-29.md кластер B] Отпечаток TLS-сертификата relay —
		// обязателен: без него EntryBridge не сможет подключиться (fail-closed, см.
		// internal/relay/tunnel_tls.go) — честная ошибка здесь понятнее, чем непонятный
		// отказ dial'а внутри уже поднятого моста.
		relayFingerprint := node.ExtraParams["apf_relayfp"]
		if relayFingerprint == "" {
			return nil, fmt.Errorf("relay-ссылка без apf_relayfp (отпечаток TLS-сертификата relay) — повреждена или собрана старой версией")
		}
		relayAddr := fmt.Sprintf("%s:%d", node.Address, node.Port)
		newBridge = relay.NewEntryBridge(relayAddr, exitID, relayFingerprint)
		newBridge.OnLog = e.log
		localAddr, err := newBridge.Start(e.currentCtx())
		if err != nil {
			return nil, fmt.Errorf("relay: не удалось поднять локальный мост: %w", err)
		}
		localHost, localPortStr, err := net.SplitHostPort(localAddr)
		if err != nil {
			newBridge.Stop()
			return nil, fmt.Errorf("relay: неверный локальный адрес моста %q: %w", localAddr, err)
		}
		localPort, _ := strconv.Atoi(localPortStr)
		node.Address = localHost
		node.Port = localPort
		e.log(fmt.Sprintf("Вход-Выход: relay-мост для партнёра «%s» поднят на %s", node.Name, localAddr))
	}

	e.clearTombstone(node.ID) // F3: партнёра добавляет сам пользователь
	e.mu.Lock()
	replaced := false
	for i, existing := range e.nodes {
		if existing.ID == node.ID {
			// Тот же партнёр переподключается по (возможно, обновлённой) ссылке — обычная
			// история "у него сменился IP/порт/ключ", не ошибка.
			node.AddedAt = existing.AddedAt
			e.nodes[i] = node
			replaced = true
			break
		}
	}
	if !replaced {
		node.AddedAt = time.Now()
		e.nodes = append(e.nodes, node)
	}
	e.mu.Unlock()
	e.saveNodes()

	// [консилиум, HIGH] Останавливаем СТАРЫЙ мост этого партнёра (если был) ПЕРЕД тем, как
	// запомнить новый — без этого на каждое переподключение утекает listener-горутина и порт.
	e.chainBridgeMu.Lock()
	if old, ok := e.chainBridges[node.ID]; ok {
		old.Stop()
	}
	if newBridge != nil {
		if e.chainBridges == nil {
			e.chainBridges = make(map[string]*relay.EntryBridge)
		}
		e.chainBridges[node.ID] = newBridge
	} else {
		delete(e.chainBridges, node.ID)
	}
	e.chainBridgeMu.Unlock()

	e.log(fmt.Sprintf("Вход-Выход: подключаюсь к партнёру «%s» (%s:%d)...", node.Name, node.Address, node.Port))
	if err := e.connectNode(node); err != nil {
		// [консилиум, UX, docs/TZ_APF_RELAY_v1.0.md §10.2 п.5] Быстрый провал сразу после
		// попытки подключения к chain-partner-узлу неотличим для пользователя от «партнёр
		// оффлайн» и «у партнёра исчерпан лимит подключений» (admission-control обрывает TCP
		// ДО VLESS/Reality-хендшейка — вставить туда текстовое сообщение невозможно). Честная
		// подсказка вместо голой сетевой ошибки.
		return node, fmt.Errorf("партнёр недоступен или у него исчерпан лимит одновременных "+
			"подключений — попробуйте позже (%w)", err)
	}
	return node, nil
}

// AddNodeManual добавляет узел, собранный вручную в редакторе продвинутых полей (B-29):
// Reality public_key/short_id, transport ws/grpc и т.п. Узел валидируется тем же
// ValidateNode, дедуплицируется по ID и сохраняется. Контракт: невалидный узел → ошибка
// без побочных эффектов; дубликат → ошибка; успех → узел в пуле + фоновая проверка.
func (e *Engine) AddNodeManual(node *models.Node) error {
	if err := models.ValidateNode(node); err != nil {
		return err
	}
	// P3 (аудит 2026-09-01): тот же отказ, что и в AddNodeFromLink. Три из четырёх путей в пул
	// (updateSources, AddNodeFromLink, платные провайдеры) отсеивали WireGuard/AmneziaWG, а
	// редактор продвинутых полей — нет. Узел с неподдерживаемым протоколом попадал в пул и
	// молча не подключался никогда: buildOutbound() отказывает, но пользователь видел только
	// «узел добавлен» и бесконечно красный статус без объяснения причины.
	if isUnsupportedProtocol(node.Protocol) {
		return fmt.Errorf("протокол %s не поддерживается этой сборкой sing-box (outbound-тип "+
			"удалён в 1.13.0) — узел не добавлен", node.Protocol)
	}
	node.Source = "manual"
	if node.ID == "" {
		node.ID = parser.GenerateNodeID(node)
	}
	if node.Name == "" {
		node.Name = fmt.Sprintf("%s %s:%d", node.Protocol, node.Address, node.Port)
	}
	e.clearTombstone(node.ID) // F3: явное добавление пользователем сильнее прошлого удаления
	e.mu.Lock()
	for _, existing := range e.nodes {
		if existing.ID == node.ID {
			e.mu.Unlock()
			return fmt.Errorf("already exists: %s", node.Name)
		}
	}
	e.nodes = append(e.nodes, node)
	e.mu.Unlock()
	e.saveNodes()
	go func() {
		r := e.checkNodeSerialized(e.currentCtx(), node)
		if e.OnNodeUpdated != nil {
			e.OnNodeUpdated(node)
		}
		if r.Success {
			e.log(fmt.Sprintf("Node OK: %s (%dms)", node.Name, r.Latency))
		}
	}()
	return nil
}

func (e *Engine) GetNodes() []*models.Node {
	e.mu.RLock()
	defer e.mu.RUnlock()
	// F-34: возвращаем СНИМКИ узлов (копии по значению), а не живые указатели.
	// Иначе HTTP-слой сериализует n.Score в JSON одновременно с тем, как
	// selectBestForStrategy его пересчитывает (n.Score = …) — гонка данных (ловится -race).
	// Поля-указатели (TLS/Transport) после парсинга неизменяемы, поэтому их можно
	// разделять; гонка была только на скалярных полях (Score), которые копия защищает.
	//
	// P0-9 (аудит 2026-09-01): собираем через append, а НЕ по индексу в срез фиксированной
	// длины. Раньше было `out := make(..., len(e.nodes))` + `out[i] = &cp`, и при nil-элементе
	// ветка `continue` оставляла в результате nil-ДЫРУ. Веб-путь это переживал (json.Marshal
	// пишет null), а Android — нет: GetNodesJSON разыменовывает элементы при сортировке, и
	// паника в Go, вызванном из Kotlin, убивает процесс приложения целиком.
	out := make([]*models.Node, 0, len(e.nodes))
	for _, n := range e.nodes {
		if n == nil {
			continue
		}
		cp := *n
		out = append(out, &cp)
	}
	return out
}

func (e *Engine) GetState() *models.ConnectionState {
	e.stateMu.RLock()
	s := *e.state
	s.PinnedNodeID = e.pinnedNodeID
	// ТЗ v1.3 F2 I3: статус pin — «active» считается живьём по ActiveNode, остальное — из
	// последнего решения путей выбора (setPinnedStatus). Только stateMu: GetState зовётся и из
	// мест, где удерживается e.mu.
	if s.PinnedNodeID != "" {
		switch {
		case s.Connected && s.ActiveNode != nil && s.ActiveNode.ID == s.PinnedNodeID:
			s.PinnedStatus = pinStatusActive
		case time.Now().Before(e.pinSuppressedUntil):
			s.PinnedStatus = pinStatusSuppressed
		case e.pinnedStatus != "":
			s.PinnedStatus = e.pinnedStatus
		default:
			s.PinnedStatus = pinStatusStandby
		}
	}
	e.stateMu.RUnlock()
	// Запросы лота L1b-SEC2 и L1-SEC: предупреждения, которые обязаны дойти до UI, но живут
	// вне состояния. Оба читаются ПОСЛЕ снятия stateMu — их источники берут собственные
	// мьютексы (config.SecretsState — RWMutex пакета config; LastPersistError — persistMu).
	if reason, warned := e.SecretsWarning(); warned {
		s.SecretsWarning = reason
	}
	s.LastPersistError = e.LastPersistError()
	s.FavoriteIDs = e.FavoriteIDs()
	return &s
}

// newWatchdog собирает сторожа со ВСЕМИ обработчиками и предикатом активности.
//
// Вход:      настройки движка.
// Тело:      конструктор + OnDead/OnRecover + ShouldCheck.
// Выход:     готовый к запуску сторож.
// Инвариант: не существует экземпляра сторожа, у которого набор обработчиков отличается.
//
// Раньше сторож собирался в трёх местах (конструктор, Start, Restart), и наборы обработчиков
// уже разошлись: в конструкторе не было ни OnDead, ни OnRecover, ни лога. Предикат
// ShouldCheck (дефект D-A25) разошёлся бы точно так же, поэтому сборка сведена в одну точку.
func (e *Engine) newWatchdog() *fallback.Watchdog {
	w := fallback.NewWatchdog(
		fallback.DefaultWatchdogConfig(fmt.Sprintf("127.0.0.1:%d", e.cfg.ListenPort)),
		e.log,
	)
	// Дефект D-A25: сторож судит о здоровье туннеля, а не о его отсутствии.
	w.ShouldCheck = e.IsConnected
	w.OnDead = func() {
		// Живой инцидент 2026-08-19 (docs/TZ_CONFIG_RELOAD_AND_KS_SAFETY_v1.0.md):
		// enableSystemProxy() включается СРАЗУ после старта sing-box-процесса (см. вызов
		// в applySingBoxConfig), задолго до того, как watchdog вообще успевает заметить,
		// что узел не работает (3 провала подряд, ~30-45 сек по умолчанию). Пока весь
		// системный HTTP-трафик указывает на прокси мёртвого узла, обычный браузинг
		// реально стоит — не Kill Switch, а именно системный прокси в никуда. При
		// переборе НЕСКОЛЬКИХ подряд плохих бесплатных узлов (типичная ситуация для
		// публичных агрегаторов) простои копятся, а не ограничиваются одним циклом
		// детекта. Симметрично: enableSystemProxy() уже вызывается заново при каждом
		// успешном applySingBoxConfig (в т.ч. после emergencySwitch/Reload), так что явный
		// re-enable здесь не нужен — как только новый узел реально поднимется, прокси
		// вернётся сам.
		if err := e.disableSystemProxy(); err != nil {
			e.log(fmt.Sprintf("SysProxy: не удалось снять на время переключения: %v", err))
		}
		e.log("⚠️ Watchdog: tunnel dead, initiating emergency switch")
		// Точка обнаружения смерти №1 — и самая частая. Сторож только что трижды подряд не смог
		// получить HTTP-ответ ЧЕРЕЗ туннель: сильнее доказательства смерти канала у движка нет.
		// Гасим состояние здесь, до вызова переключения: emergencySwitch ниже может не
		// состояться совсем (см. markChannelDead), и до 2026-09-06 ровно это оставляло
		// пользователя с зелёным «Подключено» на канале, который сторож уже похоронил.
		e.markChannelDead("watchdog: туннель не отвечает")
		// F1.2: реальный сбой пишется в узел (Score=0, FailStreak++) — раньше Watchdog оставлял
		// след только в recentFailures на 10 минут, и мёртвый узел с хорошей TCP-задержкой
		// возвращался в топ выбора (ND-1).
		e.stateMu.RLock()
		dead := e.state.ActiveNode
		e.stateMu.RUnlock()
		e.recordNodeFailure(dead, failReasonWatchdog)
		e.goTracked(e.emergencySwitch)
	}
	// OnHealthy — КАЖДАЯ успешная проверка сторожа (в отличие от OnRecover ниже, который
	// срабатывает только на переходе «был провал → снова жив»).
	w.OnHealthy = func(latencyMs int64) {
		// Долг-6 (2026-09-21): успех сторожа доказывает лишь живой SOCKS-in, а не путь приложений
		// (TUN). Там, где прямая (TUN) проба вправе выносить вердикт (directProbeEnforce — сегодня
		// Android), если SOCKS отвечает, а TUN — нет («зелёная галка, сайта нет»), ЧЕСТНО гасим
		// бэйдж, НЕ продлеваем свежесть и НЕ переключаемся (эскалацию оставляем SOCKS-логике,
		// см. watchdogTunVerdict). На прочих платформах/режимах поведение прежнее.
		if healthy, decided := e.watchdogTunVerdict(); decided && !healthy {
			e.markChannelDead("watchdog: SOCKS отвечает, но путь приложений (TUN) не отвечает")
			return
		}
		// Продлеваем свежесть подтверждения активного узла: до 2026-09-06 это знание
		// выбрасывалось, и «проверенность» узла затухала прямо во время стабильной сессии,
		// когда трафик заведомо шёл (см. refreshNodeVerified).
		e.refreshNodeVerified(latencyMs)
		// И это же — единственный путь обратно из «канал не работает», когда переключение так и
		// не состоялось (см. markChannelAliveAgain).
		e.markChannelAliveAgain()
	}
	w.OnRecover = func() {
		e.log("✅ Watchdog: tunnel recovered")
		// P1-5: ResetCounters, а НЕ полный Reset — последний стирает everSucceeded, то есть
		// сигнал «узел уже подтверждал работоспособность», ровно в момент подтверждения.
		// Подробнее — комментарий у Watchdog.ResetCounters.
		w.ResetCounters()
	}
	return w
}

// IsConnected — считает ли движок туннель поднятым (дефект D-A25).
//
// Отдельный дешёвый предикат, а не GetState().Connected, потому что его дёргает сторож
// каждые 15 секунд: копировать ради одного логического значения всю структуру состояния
// вместе со срезами незачем.
func (e *Engine) IsConnected() bool {
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()
	return e.state.Connected
}

// IsVerified — прошёл ли активный узел post-connect health check (см. Verified в
// models.ConnectionState). false сразу после подключения и на каждом emergencySwitch,
// пока узел не подтвердит реальный сквозной трафик — UI использует это, чтобы не
// показывать "подключено" раньше времени.
func (e *Engine) IsVerified() bool {
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()
	return e.state.Verified
}

// ─── FR-4: ручной выбор узла (manual selection / pinning) ─────────────────────

// ErrEmptyNodeID возвращается при пустом ID узла.
var ErrEmptyNodeID = fmt.Errorf("node id is empty")

// findNodeByID возвращает узел из пула по ID (B-08.1). Чистый поиск под e.mu,
// пул не мутируется. Пустой ID → ErrEmptyNodeID; не найден → ошибка с указанием ID.
func (e *Engine) findNodeByID(id string) (*models.Node, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, ErrEmptyNodeID
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, n := range e.nodes {
		if n.ID == id {
			return n, nil
		}
	}
	return nil, fmt.Errorf("node not found: %s", id)
}

// ─── ТЗ v1.3 F2: закрепление и избранное (персистентные, консилиум 2026-09-03 R4/PIN) ───

// Статусы закреплённого узла (models.ConnectionState.PinnedStatus, I3).
const (
	pinStatusActive      = "active"
	pinStatusStandby     = "standby"
	pinStatusUnreachable = "unreachable"
	pinStatusSuppressed  = "suppressed"
	pinStatusMissing     = "missing"
)

// Pin закрепляет узел с валидацией (контракт B-08.3 пересмотрен ТЗ v1.3): неизвестный ID —
// ошибка БЕЗ побочных эффектов. Закрепление пишется в config.json (I1/I2).
func (e *Engine) Pin(id string) error {
	node, err := e.findNodeByID(id)
	if err != nil {
		return err
	}
	e.PinNode(node.ID)
	return nil
}

// PinNode закрепляет узел по ID без валидации (B-08.3; совместимость с web/gui/bridge и
// тестами). Снимает подавление pin и персистирует через persistPinAndFavorites.
func (e *Engine) PinNode(id string) {
	id = strings.TrimSpace(id)
	e.stateMu.Lock()
	changed := e.pinnedNodeID != id
	e.pinnedNodeID = id
	e.pinSuppressedUntil = time.Time{}
	e.pinnedStatus = ""
	if id != "" {
		e.pinnedStatus = pinStatusStandby
	}
	e.stateMu.Unlock()
	if changed {
		e.persistPinAndFavorites()
	}
}

// Unpin снимает закрепление (алиас UnpinNode, имя по ТЗ v1.3 F2).
func (e *Engine) Unpin() { e.UnpinNode() }

// UnpinNode снимает закрепление узла (B-08.3) и персистирует.
func (e *Engine) UnpinNode() {
	e.stateMu.Lock()
	changed := e.pinnedNodeID != ""
	e.pinnedNodeID = ""
	e.pinSuppressedUntil = time.Time{}
	e.pinnedStatus = ""
	e.stateMu.Unlock()
	if changed {
		e.persistPinAndFavorites()
	}
}

// IsPinned сообщает, закреплён ли узел пользователем (B-08.3).
func (e *Engine) IsPinned() bool {
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()
	return e.pinnedNodeID != ""
}

// PinnedNodeID возвращает ID закреплённого узла ("" — не закреплён) (B-08.3).
func (e *Engine) PinnedNodeID() string {
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()
	return e.pinnedNodeID
}

// suppressPin временно исключает закреплённый узел из авто-выбора (после «Сменить сервер»):
// pin при этом НЕ снимается (B-08.4 пересмотрен — раньше ForceSwitchNow звал UnpinNode, и
// выбор пользователя терялся). Возврат на pin — при следующем событии выбора после окна (I4).
func (e *Engine) suppressPin(d time.Duration) {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	if e.pinnedNodeID == "" {
		return
	}
	e.pinSuppressedUntil = time.Now().Add(d)
	e.pinnedStatus = pinStatusSuppressed
}

func (e *Engine) pinSuppressed() bool {
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()
	return time.Now().Before(e.pinSuppressedUntil)
}

// setPinnedStatus запоминает причину последнего решения по pin для UI (I3). Только stateMu —
// вызывается из путей выбора, где может удерживаться e.mu.RLock.
func (e *Engine) setPinnedStatus(status string) {
	e.stateMu.Lock()
	if e.pinnedNodeID != "" {
		e.pinnedStatus = status
	}
	e.stateMu.Unlock()
}

// pinFreshFailure — последнее реальное событие по узлу — сбой, и он свежее recentFailureTTL.
// Окно, а не «навсегда»: иначе закреплённый узел после единственного сбоя никогда не получил
// бы шанса подтвердиться заново (его верифицирует только реальное подключение). По
// LastFailedAt, а не по карте recentFailures — переживает перезапуск.
func pinFreshFailure(n *models.Node) bool {
	return n.LastOutcomeIsFailure() && !n.IsBlacklisted() &&
		time.Since(time.Unix(n.LastFailedAt, 0)) < recentFailureTTL
}

// AddFavorite добавляет узел в ПОЛЬЗОВАТЕЛЬСКОЕ избранное (валидация как у Pin); идемпотентно.
// W3 (ТЗ v1.5 §2, TZ_v1.5_NODE_CATALOG_2026-09-14): звезда пользователя — единственный писатель
// класса OriginUser. Если узел уже был СИСТЕМНЫМ фаворитом (добавлен сборкой каталога,
// AddSystemFavorite), клик по звезде ПОВЫШАЕТ его до "user" (safeguard #3 — sticky promotion):
// после этого его не может снова убрать реконсиляция runNodeCheck, только сам пользователь через
// RemoveFavorite.
func (e *Engine) AddFavorite(id string) error {
	if _, err := e.findNodeByID(id); err != nil {
		return err
	}
	return e.addFavoriteWithOrigin(id, models.OriginUser)
}

// AddSystemFavorite — то же самое, но класс OriginSystem: пишет ТОЛЬКО реконсиляция каталога
// (reconcileFavoritesFromNodeCheck, node_check.go) для узла, только что прошедшего пробу
// реального трафика. Публичная — понадобится тестам и будущим UI-лотам (просмотр/ручной запуск
// сборки). НИКОГДА не понижает уже существующий "user" — если узел уже избранное любого класса,
// это no-op (см. addFavoriteWithOrigin): каталог не имеет права отобрать у записи статус "user".
func (e *Engine) AddSystemFavorite(id string) error {
	if _, err := e.findNodeByID(id); err != nil {
		return err
	}
	return e.addFavoriteWithOrigin(id, models.OriginSystem)
}

// addFavoriteWithOrigin — общее тело AddFavorite/AddSystemFavorite (W3). Мутация favRefs/favIDs
// — ПОД favMu, короткая секция: safeguard #3 консилиума (star↔evict race) полагается именно на
// то, что и промоушен звездой, и эвикшен системного класса (evictSystemFavorite) берут один и тот
// же мьютекс и каждый пере-проверяет класс/наличие записи ПРЯМО ПЕРЕД мутацией — какой бы из двух
// ни выиграл гонку за лок, второй увидит уже актуальное состояние и не затрёт его вслепую.
func (e *Engine) addFavoriteWithOrigin(id string, origin string) error {
	node, err := e.findNodeByID(id)
	if err != nil {
		return err
	}
	e.favMu.Lock()
	if e.favIDs == nil {
		e.favIDs = make(map[string]bool)
	}
	if e.favIDs[node.ID] {
		if origin != models.OriginUser {
			e.favMu.Unlock()
			return nil // AddSystemFavorite на уже избранном (любого класса) — идемпотентный no-op
		}
		promoted := false
		for i := range e.favRefs {
			if e.favRefs[i].ID == node.ID && e.favRefs[i].EffectiveOrigin() == models.OriginSystem {
				e.favRefs[i].Origin = models.OriginUser
				promoted = true
				break
			}
		}
		e.favMu.Unlock()
		if promoted {
			e.log(fmt.Sprintf("⭐ Системный фаворит повышен пользователем: %s", node.Name))
			e.persistPinAndFavorites()
		}
		return nil
	}
	e.favIDs[node.ID] = true
	ref := models.NodeRefOf(node)
	ref.Origin = origin
	e.favRefs = append(e.favRefs, ref)
	e.favMu.Unlock()
	if origin == models.OriginUser {
		e.log(fmt.Sprintf("⭐ В избранное: %s", node.Name))
	}
	e.persistPinAndFavorites()
	return nil
}

// RemoveFavorite убирает узел из избранного; неизвестный/не избранный ID — не ошибка.
func (e *Engine) RemoveFavorite(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("empty node id")
	}
	e.favMu.Lock()
	if !e.favIDs[id] {
		e.favMu.Unlock()
		return nil
	}
	delete(e.favIDs, id)
	kept := e.favRefs[:0]
	for _, r := range e.favRefs {
		if r.ID != id {
			kept = append(kept, r)
		}
	}
	e.favRefs = kept
	e.favMu.Unlock()
	e.persistPinAndFavorites()
	return nil
}

// FavoriteIDs — ID избранных узлов в порядке добавления.
func (e *Engine) FavoriteIDs() []string {
	e.favMu.RLock()
	defer e.favMu.RUnlock()
	out := make([]string, 0, len(e.favRefs))
	for _, r := range e.favRefs {
		out = append(out, r.ID)
	}
	return out
}

// IsFavorite — узел в избранном (любого класса).
func (e *Engine) IsFavorite(id string) bool {
	e.favMu.RLock()
	defer e.favMu.RUnlock()
	return e.favIDs[id]
}

// FavoriteRefs — снимок ВСЕГО избранного С классом (NodeRef.Origin включён). W3: для
// потребителей, которым класс важен (filterNodesForRetention/потолок системного класса на
// запись). FavoriteIDs() выше остаётся как есть для потребителей, которым класс не нужен —
// сигнатура/контракт того метода не меняются.
func (e *Engine) FavoriteRefs() []models.NodeRef {
	e.favMu.RLock()
	defer e.favMu.RUnlock()
	return append([]models.NodeRef(nil), e.favRefs...)
}

// FavoriteOrigin — класс избранного узла: models.OriginUser/OriginSystem, или "" — узел вообще
// не в избранном. W3, для UI-лотов (какую звёздочку/бейдж показать).
func (e *Engine) FavoriteOrigin(id string) string {
	e.favMu.RLock()
	defer e.favMu.RUnlock()
	for _, r := range e.favRefs {
		if r.ID == id {
			return r.EffectiveOrigin()
		}
	}
	return ""
}

// favoriteIDsByOrigin — общее тело UserFavoriteIDs/SystemFavoriteIDs.
func (e *Engine) favoriteIDsByOrigin(origin string) []string {
	e.favMu.RLock()
	defer e.favMu.RUnlock()
	out := make([]string, 0, len(e.favRefs))
	for _, r := range e.favRefs {
		if r.EffectiveOrigin() == origin {
			out = append(out, r.ID)
		}
	}
	return out
}

// UserFavoriteIDs — ID пользовательских фаворитов (звезда), в порядке добавления. W3, для
// UI-лотов, которым нужно показать "Мои"/"Каталог" раздельно.
func (e *Engine) UserFavoriteIDs() []string { return e.favoriteIDsByOrigin(models.OriginUser) }

// SystemFavoriteIDs — ID системных фаворитов (сборка каталога), в порядке добавления. Не более
// SystemFavoriteCap элементов сразу после реконсиляции (enforceSystemFavoriteCap) — но между
// сборками может временно быть меньше, никогда — искусственно урезано здесь.
func (e *Engine) SystemFavoriteIDs() []string { return e.favoriteIDsByOrigin(models.OriginSystem) }

// favoritesFirst — устойчиво переставляет избранные узлы вперёд (порядок выбора F2: pinned →
// favorites → остальное). Leaf-лок favMu — безопасно из путей выбора под e.mu.RLock.
func (e *Engine) favoritesFirst(cands []*models.Node) []*models.Node {
	e.favMu.RLock()
	defer e.favMu.RUnlock()
	if len(e.favIDs) == 0 || len(cands) < 2 {
		return cands
	}
	sort.SliceStable(cands, func(i, j int) bool {
		return e.favIDs[cands[i].ID] && !e.favIDs[cands[j].ID]
	})
	return cands
}

// persistPinAndFavorites — единственный писатель cfg.PinnedNode/cfg.Favorites (I1/I2).
// Ссылки берутся из текущего пула (адрес/порт/протокол — для переразрешения после миграции ID).
func (e *Engine) persistPinAndFavorites() {
	if e.saveConfig == nil {
		return // голый Engine в тестах
	}
	e.stateMu.RLock()
	pid := e.pinnedNodeID
	e.stateMu.RUnlock()
	e.favMu.RLock()
	favs := append([]models.NodeRef(nil), e.favRefs...)
	e.favMu.RUnlock()

	e.mu.Lock()
	if e.cfg == nil {
		e.mu.Unlock()
		return
	}
	if pid == "" {
		e.cfg.PinnedNode = nil
	} else {
		ref := models.NodeRef{ID: pid}
		for _, n := range e.nodes {
			if n != nil && n.ID == pid {
				ref = models.NodeRefOf(n)
				break
			}
		}
		e.cfg.PinnedNode = &ref
	}
	e.cfg.Favorites = favs
	err := e.saveConfig(e.cfg)
	e.mu.Unlock()
	if err != nil {
		e.log(fmt.Sprintf("Pin/избранное: ошибка сохранения config.json: %v", err))
	}
}

// evictSystemFavorite — W3: снимает избранное с узла, но ТОЛЬКО если это ещё системный класс на
// момент удаления (safeguard #3/#5 консилиума TZ_v1.5_NODE_CATALOG_2026-09-14). Повторная
// проверка класса ПРЯМО ПЕРЕД удалением, под тем же favMu, что и addFavoriteWithOrigin: если
// пользователь успел нажать звезду (промоушен до "user") между тем, как реконсиляция решила
// вытеснить эту запись, и этим вызовом, звезда побеждает — запись остаётся. НЕ трогает
// Node/пул/бан (safeguard #5 — эвикшен НЕ бан: узел просто перестаёт быть избранным, может
// вернуться в избранное позже, обычным путём). Не найдено/уже не системный — тихий no-op.
func (e *Engine) evictSystemFavorite(id string) {
	e.favMu.Lock()
	idx := -1
	for i, r := range e.favRefs {
		if r.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 || e.favRefs[idx].EffectiveOrigin() != models.OriginSystem {
		e.favMu.Unlock()
		return
	}
	name := e.favRefs[idx].Name
	e.favRefs = append(e.favRefs[:idx], e.favRefs[idx+1:]...)
	delete(e.favIDs, id)
	e.favMu.Unlock()
	if name == "" {
		name = id
	}
	e.log(fmt.Sprintf("Каталог: системный фаворит снят (проба не прошла, интервал пересмотра истёк): %s", name))
	e.persistPinAndFavorites()
}

// enforceSystemFavoriteCap — W3 §2/§4/safeguard #2/#6: потолок SystemFavoriteCap применяется
// ТОЛЬКО к Origin==system (снимок sysIDs ниже уже отфильтрован по классу — пользовательские
// записи сюда не попадают ни при каких обстоятельствах, и узлы, удерживаемые по ДРУГОМУ
// критерию — pin/manual/chain-partner — не входят в этот список и потому не занимают место в
// потолке просто по факту существования). Снимок системных фаворитов — под favMu (RLock),
// Score/latency для сортировки — под e.mu (RLock), НИКОГДА одновременно (см. порядок локов у
// saveNodesToDisk) — мутация конкретной записи идёт через evictSystemFavorite, которая сама берёт
// favMu и повторно проверяет класс (safeguard #3).
func (e *Engine) enforceSystemFavoriteCap() {
	e.favMu.RLock()
	sysIDs := make([]string, 0, len(e.favRefs))
	for _, r := range e.favRefs {
		if r.EffectiveOrigin() == models.OriginSystem {
			sysIDs = append(sysIDs, r.ID)
		}
	}
	e.favMu.RUnlock()
	if len(sysIDs) <= SystemFavoriteCap {
		return
	}

	e.mu.RLock()
	byID := make(map[string]*models.Node, len(e.nodes))
	for _, n := range e.nodes {
		if n != nil {
			byID[n.ID] = n
		}
	}
	e.mu.RUnlock()

	sortSystemFavoriteIDsByQuality(sysIDs, byID)
	for _, id := range sysIDs[SystemFavoriteCap:] {
		e.evictSystemFavorite(id)
	}
}

// restorePinAndFavorites восстанавливает pin/избранное из cfg (New и Start после loadNodes):
// ссылки переразрешаются по адресу, если ID узла изменился. Не найденный pin остаётся
// закреплённым со статусом missing — подписка может вернуть узел позже.
func (e *Engine) restorePinAndFavorites() {
	e.mu.RLock()
	cfg := e.cfg
	if cfg == nil {
		e.mu.RUnlock()
		return
	}
	resolve := func(ref models.NodeRef) (models.NodeRef, bool) {
		for _, n := range e.nodes {
			if n != nil && ref.Matches(n) {
				return models.NodeRefOf(n), true
			}
		}
		return ref, false
	}
	var pid, pinName string
	pinMissing := false
	if cfg.PinnedNode != nil && cfg.PinnedNode.ID != "" {
		r, ok := resolve(*cfg.PinnedNode)
		pid, pinName, pinMissing = r.ID, r.Name, !ok
	}
	favs := make([]models.NodeRef, 0, len(cfg.Favorites))
	for _, ref := range cfg.Favorites {
		if ref.ID == "" && ref.Address == "" {
			continue
		}
		// W3 safeguard #1 (data-loss blocker, TZ_v1.5_NODE_CATALOG_2026-09-14): нормализуем
		// класс из СОХРАНЁННОЙ ссылки (EffectiveOrigin — Origin=="" читается как "user") ДО
		// resolve, и переносим его на СВЕЖУЮ ссылку — resolve возвращает models.NodeRefOf(n)
		// заново с нуля (адрес/имя/протокол актуальны после миграции ID), что БЕЗ этой строки
		// молча стёрло бы класс на каждом restart/loadNodes. Раз нормализованное здесь "user"
		// (в т.ч. для записей без Origin, сделанных до W3) больше никогда не станет "system"
		// само по себе — только явный AddSystemFavorite мог бы, а он не понижает существующее.
		origin := ref.EffectiveOrigin()
		r, _ := resolve(ref)
		r.Origin = origin
		favs = append(favs, r)
	}
	e.mu.RUnlock()

	e.stateMu.Lock()
	e.pinnedNodeID = pid
	e.pinnedStatus = ""
	if pid != "" {
		e.pinnedStatus = pinStatusStandby
		if pinMissing {
			e.pinnedStatus = pinStatusMissing
		}
	}
	e.stateMu.Unlock()

	e.favMu.Lock()
	e.favRefs = favs
	e.favIDs = make(map[string]bool, len(favs))
	for _, r := range favs {
		e.favIDs[r.ID] = true
	}
	e.favMu.Unlock()

	if pid != "" {
		if pinMissing {
			e.log(fmt.Sprintf("📌 Закреплённый узел %s не найден в пуле — остаётся закреплённым (статус missing)", pid))
		} else {
			e.log(fmt.Sprintf("📌 Закреплённый узел восстановлен: %s", pinName))
		}
	}
}

// ConnectOnce подключается к узлу, НЕ меняя закрепление (F2, PIN-8): «▶ Подключить» в списке
// узлов и тап по узлу на Android. Ставит manualConnectAt (защита от гонки с авто-выбором).
// Инвариант: пустой/неизвестный ID — ошибка без побочных эффектов.
func (e *Engine) ConnectOnce(nodeID string) error {
	node, err := e.findNodeByID(nodeID)
	if err != nil {
		return err
	}
	e.manualConnectMu.Lock()
	e.manualConnectAt = time.Now()
	e.manualConnectMu.Unlock()
	e.log(fmt.Sprintf("Manual connect: %s", node.Name))
	// См. комментарий у ForceRescan — goTracked вместо голого go закрывает окно
	// «тихий реконнект переживает Stop()».
	e.goTracked(func() {
		if err := e.connectNode(node); err != nil {
			e.log(fmt.Sprintf("Manual connect failed: %v", err))
			if classifyConnectFailure(err) == failureNode { // ТЗ HOTSWITCH §8 A1
				e.recordNodeFailure(node, failReasonConnect)
			}
		}
	})
	return nil
}

// ConnectAndPin = Pin + ConnectOnce (F2): подключиться к конкретному узлу и закрепить его.
func (e *Engine) ConnectAndPin(nodeID string) error {
	if err := e.Pin(nodeID); err != nil {
		return err
	}
	return e.ConnectOnce(nodeID)
}

// ConnectByID — алиас ConnectAndPin (B-08.2, FR-4; прежнее имя для web/gui/bridge).
// Инвариант: при пустом/неизвестном ID возвращает ошибку БЕЗ побочных эффектов
// (закрепление не ставится, подключение не запускается).
func (e *Engine) ConnectByID(nodeID string) error { return e.ConnectAndPin(nodeID) }

func (e *Engine) GetStats() map[string]int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	stats := map[string]int{"total": len(e.nodes)}
	proven := 0
	for _, n := range e.nodes {
		// P0-9: nil-элемент возможен при повреждённом кэше — см. loadNodes.
		if n == nil {
			continue
		}
		stats[string(n.Status)]++
		// ТЗ v1.7 (десктоп verified-UX): счётчик узлов с подтверждённым трафиком для карточки
		// «Узлов с трафиком» на Dashboard (Web/Wails). IsProven() читает поля самого узла без
		// блокировок движка — безопасно под уже взятым e.mu.RLock (в отличие от provenCount(),
		// который сам берёт e.mu.RLock и вложенно повесил бы RWMutex этой же горутины).
		if n.IsProven() {
			proven++
		}
	}
	stats["proven"] = proven
	return stats
}

// GetTrafficStats возвращает статистику трафика в реальном времени (Sprint 8).
func (e *Engine) GetTrafficStats() map[string]interface{} {
	if e.trafficMonitor == nil {
		return map[string]interface{}{
			"up_bytes": 0, "down_bytes": 0,
			"up_speed": 0, "down_speed": 0,
			"up_speed_str": "0 B/s", "down_speed_str": "0 B/s",
			"up_total_str": "0 B", "down_total_str": "0 B",
		}
	}
	ts := e.trafficMonitor.GetStats()
	return map[string]interface{}{
		"up_bytes":       ts.UpBytes,
		"down_bytes":     ts.DownBytes,
		"up_speed":       ts.UpSpeed,
		"down_speed":     ts.DownSpeed,
		"up_speed_str":   singbox.FormatSpeed(ts.UpSpeed),
		"down_speed_str": singbox.FormatSpeed(ts.DownSpeed),
		"up_total_str":   singbox.FormatBytes(ts.UpBytes),
		"down_total_str": singbox.FormatBytes(ts.DownBytes),
	}
}

func (e *Engine) GetSingBoxInfo() map[string]interface{} {
	info := map[string]interface{}{
		"installed": e.proc.IsInstalled(),
		"running":   e.proc.IsRunning(),
	}
	if e.proc.IsInstalled() {
		ver, _ := e.proc.Version()
		info["version"] = ver
	}
	return info
}

// ResetBlockageCache сбрасывает кэш диагностики блокировки (Sprint 3).
// Вызывать при смене сети или по кнопке в UI.
func (e *Engine) ResetBlockageCache() {
	e.detector.InvalidateCache()
	e.log("Blockage detection cache reset")
}

// getBlockageType / setBlockageType — единые потокобезопасные точки доступа к полю
// blockageType (B-26 / дефект D20). Поле читается из нескольких горутин (Start,
// selectBestForStrategy, tryFallback, GetDiagnostics, applyDPICounterMeasures), поэтому
// весь доступ идёт через эти аксессоры под stateMu — никаких «сырых» обращений к полю.
// goTracked запускает фоновую функцию, отслеживаемую e.wg, чтобы Stop()/wg.Wait()
// гарантированно её дожидался (T-25). Использовать вместо «голого» go для операций,
// которые не должны переживать движок (emergencySwitch и т.п.).
// Если ctx уже отменён (идёт Stop), функция НЕ запускается — иначе wg.Add во время
// wg.Wait() даёт панику «WaitGroup is reused». Это безопасно: при остановке движка
// фоновую работу всё равно не нужно начинать.
//
// Возвращает, СТАРТОВАЛА ли задача (LOT-09). Отказ был молчаливым, и два вызывающих кода на
// этом ломались: scheduleReArm оставлял навсегда взведённым reArmPending (следующий ре-арминг
// не планировался НИКОГДА), а applySingBoxConfig оставлял навсегда «проверка канала идёт» —
// её единственный разрешающий (runPostConnectHealthCheck) просто не стартовал. Возвращаемое
// значение можно игнорировать: остальные вызовы — «запусти, если движок жив», и там отказ
// действительно ничего не значит.
func (e *Engine) goTracked(fn func()) bool {
	select {
	case <-e.currentCtx().Done():
		return false
	default:
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		fn()
	}()
	return true
}

// sleepCtx спит d или прерывается при отмене ctx. Возвращает false, если прерван.
// B-25: post-connect горутины раньше спали time.Sleep() глухо и не реагировали на
// e.ctx — при Stop() они переживали движок. Теперь сон прерываемый, а сами горутины
// учтены в e.wg, поэтому Stop()/wg.Wait() их корректно дожидается.
func (e *Engine) sleepCtx(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-e.currentCtx().Done():
		return false
	case <-t.C:
		return true
	}
}

func (e *Engine) getBlockageType() detector.BlockageType {
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()
	return e.blockageType
}

func (e *Engine) setBlockageType(bt detector.BlockageType) {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	e.blockageType = bt
}

// ─── Sprint 6: Paid Providers ─────────────────────────────────────────────────

// registerPaidProviders читает PaidProviders из конфига и регистрирует в каталоге.
func (e *Engine) registerPaidProviders() {
	if e.catalogRegistry == nil || len(e.cfg.PaidProviders) == 0 {
		return
	}
	for _, entry := range e.cfg.PaidProviders {
		if !entry.Enabled {
			continue
		}
		cfg := catalog.PaidProviderConfig{
			ID:              entry.ID,
			Name:            entry.Name,
			Type:            entry.Type,
			URL:             entry.URL,
			Username:        entry.Username,
			Password:        entry.Password,
			Token:           entry.Token,
			SubscriptionURL: entry.SubscriptionURL,
			Enabled:         entry.Enabled,
			InsecureTLS:     entry.InsecureTLS,
		}
		p, err := catalog.NewPaidProvider(cfg)
		if err != nil {
			e.log(fmt.Sprintf("Paid provider [%s]: init error: %v", entry.Name, err))
			continue
		}
		e.catalogRegistry.Register(p)
		e.log(fmt.Sprintf("Paid provider registered: %s (%s)", entry.Name, entry.Type))
	}
}

// AddPaidProvider добавляет новый платный провайдер и сохраняет в конфиг.
func (e *Engine) AddPaidProvider(entry models.PaidProviderEntry) error {
	// Генерируем ID если не задан
	if entry.ID == "" {
		entry.ID = fmt.Sprintf("paid-%d", len(e.cfg.PaidProviders)+1)
	}

	// Проверяем что ID уникален
	for _, existing := range e.cfg.PaidProviders {
		if existing.ID == entry.ID {
			return fmt.Errorf("provider with id %q already exists", entry.ID)
		}
	}

	// Создаём и проверяем провайдер
	cfg := catalog.PaidProviderConfig{
		ID:              entry.ID,
		Name:            entry.Name,
		Type:            entry.Type,
		URL:             entry.URL,
		Username:        entry.Username,
		Password:        entry.Password,
		Token:           entry.Token,
		SubscriptionURL: entry.SubscriptionURL,
		Enabled:         true,
		InsecureTLS:     entry.InsecureTLS,
	}
	p, err := catalog.NewPaidProvider(cfg)
	if err != nil {
		return fmt.Errorf("create provider: %w", err)
	}

	// Тестируем подключение
	e.log(fmt.Sprintf("Paid provider [%s]: testing connection...", entry.Name))
	ctx, cancel := context.WithTimeout(e.currentCtx(), 15*time.Second)
	defer cancel()
	nodes, err := p.Fetch(ctx)
	if err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	e.log(fmt.Sprintf("Paid provider [%s]: connected, got %d nodes", entry.Name, len(nodes)))

	// Регистрируем и сохраняем
	e.catalogRegistry.Register(p)
	e.mu.Lock()
	e.cfg.PaidProviders = append(e.cfg.PaidProviders, entry)
	e.saveConfig(e.cfg)
	e.mu.Unlock()

	// Добавляем узлы в пул
	if len(nodes) > 0 {
		e.mu.Lock()
		existing := make(map[string]bool, len(e.nodes))
		for _, n := range e.nodes {
			existing[n.ID] = true
		}
		added := 0
		for _, n := range nodes {
			if !existing[n.ID] && !e.isTombstoned(n.ID) { // F3: удалённое пользователем не воскрешаем
				existing[n.ID] = true
				e.nodes = append(e.nodes, n)
				added++
			}
		}
		e.mu.Unlock()
		if added > 0 {
			e.saveNodes()
			e.log(fmt.Sprintf("Paid provider [%s]: added %d nodes", entry.Name, added))
		}
	}
	return nil
}

// GetPaidProviders — [TZ_TAILS_HARDENING_2026-08-31.md кластер C] список сохранённых платных
// провайдеров. Windows GUI получает этот же список другим путём (App.GetConfig().PaidProviders
// — общий конфиг уже гоняется туда-обратно через Wails), но у Android-моста (gomobile)
// общего "отдать весь конфиг" вызова нет — нужен отдельный узкий геттер именно под список
// провайдеров для экрана «Платные провайдеры» (кластер C, mobile/androidbridge).
func (e *Engine) GetPaidProviders() []models.PaidProviderEntry {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]models.PaidProviderEntry, len(e.cfg.PaidProviders))
	copy(out, e.cfg.PaidProviders)
	return out
}

// RemovePaidProvider удаляет платного провайдера по ID.
func (e *Engine) RemovePaidProvider(id string) bool {
	e.mu.Lock()
	found := false
	newList := e.cfg.PaidProviders[:0]
	for _, entry := range e.cfg.PaidProviders {
		if entry.ID == id {
			found = true
			e.log(fmt.Sprintf("Paid provider removed: %s", entry.Name))
		} else {
			newList = append(newList, entry)
		}
	}
	if found {
		e.cfg.PaidProviders = newList
		e.saveConfig(e.cfg)
	}
	e.mu.Unlock()
	if found {
		// P1-7 (аудит 2026-09-01): провайдер убирается ИЗ РЕЕСТРА.
		// Раньше этого не делалось (метода Unregister не существовало), и удалённый
		// провайдер продолжал опрашиваться при каждом RefreshCatalog с сохранёнными
		// учётными данными — до перезапуска процесса.
		if e.catalogRegistry != nil {
			e.catalogRegistry.Unregister(id)
		}

		// Удаляем узлы этого провайдера из пула.
		// Тег берётся из catalog.PaidSourceTag — единственного источника истины: раньше
		// здесь была своя строка "paid:"+id, а провайдеры проставляли Source по трём другим
		// конвенциям (имя панели / голый ID), поэтому фильтр не совпадал НИКОГДА и узлы
		// удалённого провайдера оставались в пуле навсегда.
		source := catalog.PaidSourceTag(id)
		e.mu.Lock()
		filtered := e.nodes[:0]
		for _, n := range e.nodes {
			if n == nil {
				continue
			}
			if n.Source != source {
				filtered = append(filtered, n)
			}
		}
		e.nodes = filtered
		e.mu.Unlock()
		e.saveNodes()
	}
	return found
}

// TestPaidProvider тестирует подключение к провайдеру без сохранения.
func (e *Engine) TestPaidProvider(entry models.PaidProviderEntry) (int, error) {
	cfg := catalog.PaidProviderConfig{
		ID:              entry.ID,
		Name:            entry.Name,
		Type:            entry.Type,
		URL:             entry.URL,
		Username:        entry.Username,
		Password:        entry.Password,
		Token:           entry.Token,
		SubscriptionURL: entry.SubscriptionURL, // fix: was missing, asymmetry with AddPaidProvider
		Enabled:         true,
		InsecureTLS:     entry.InsecureTLS,
	}
	p, err := catalog.NewPaidProvider(cfg)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(e.currentCtx(), 20*time.Second)
	defer cancel()
	nodes, err := p.Fetch(ctx)
	if err != nil {
		return 0, err
	}
	return len(nodes), nil
}

// ─── Sprint 6: Auto-update API ────────────────────────────────────────────────

// CheckForUpdate вручную запускает проверку обновлений.
func (e *Engine) CheckForUpdate(ctx context.Context) (*updater.UpdateStatus, error) {
	if e.appUpdater == nil {
		return nil, fmt.Errorf("updater not initialized")
	}
	return e.appUpdater.CheckForUpdate(ctx)
}

// GetUpdateStatus возвращает последний статус проверки обновлений.
func (e *Engine) GetUpdateStatus() *updater.UpdateStatus {
	if e.appUpdater == nil {
		return &updater.UpdateStatus{CurrentVersion: version.Version}
	}
	return e.appUpdater.GetLastStatus()
}

// updateApplyEnabled — S-UPD (2026-09-15, security). Применение обновлений (замена
// собственного APF.exe на скачанный бинарник) ВЫКЛЮЧЕНО по умолчанию — fail-closed.
//
// Причина (перепроверено по коду 09-15, находка аудита 2026-09-01 подтверждена живой): у канала
// релизов НЕТ криптоподписи, а ожидаемая SHA-256 берётся из checksums.txt ТОГО ЖЕ релиза
// (updater.fetchChecksum) — один и тот же владелец релиза контролирует и бинарник, и его сумму,
// поэтому сумма подтверждает лишь целостность в канале, а НЕ подлинность издателя. Цель обновления
// api.github.com/repos/apf/adaptive-pathfinder на момент правки не существует → имя org
// СКВОТТИРУЕМО: кто угодно, зарегистрировав его, публикует «релиз» с бОльшей версией и вредоносным
// APF.exe с совпадающей суммой; ApplyUpdate → updater.DownloadAndApply сделал бы os.Rename поверх
// работающего файла, а служба apf-svc.exe исполняется под LocalSystem → это supply-chain RCE под
// SYSTEM, спровоцированный одним кликом пользователя по «доступно обновление».
//
// Проверка/уведомление (CheckForUpdate, StartAutoCheck) НЕ трогаются — они лишь читают версию и не
// заменяют файл; обезврежен именно единственный путь записи. var (не const): когда появится
// ПОДПИСАННЫЙ канал (ed25519 с вшитым pubkey) либо org apf будет занят и защищён владельцем —
// флаг снимается здесь одной правкой, вся логика скачивания/сверки в updater цела и протестирована.
//
// 2026-09-29: канал проверки перенаправлен на настоящий репозиторий владельца
// (romanelectron-ops/adaptive-pathfinder, см. updater.githubAPI) — сквоттинг org apf больше не
// влияет. Но подписи у релизов по-прежнему нет, поэтому применение остаётся выключенным.
var updateApplyEnabled = false

// ApplyUpdate скачивает и применяет обновление.
//
// S-UPD (2026-09-15): fail-closed — пока канал релизов не подписан, применение отклоняется до
// любой сетевой активности (см. updateApplyEnabled). Обновление — только вручную с официального
// источника.
//
// P1 (аудит 2026-09-01, security-раздел, находка №3): контрольная сумма (если релиз её
// публикует) берётся из последнего результата CheckForUpdate — но ТОЛЬКО если downloadURL
// совпадает с тем, что было в этом результате. Вызывающая сторона обязана сперва вызвать
// CheckForUpdate и передать сюда ровно тот же DownloadURL — несовпадение (например, кто-то
// подставил свой URL) не даёт ложно применить чужую сумму к чужому файлу; в этом случае
// DownloadAndApply получит пустую сумму и честно предупредит, а не проверит не то.
func (e *Engine) ApplyUpdate(ctx context.Context, downloadURL string, onProgress func(int)) error {
	if !updateApplyEnabled {
		e.log("Обновление: применение отклонено — канал релизов APF не подписан; обновитесь " +
			"вручную с официального источника (защита от подмены обновления)")
		return fmt.Errorf("применение обновлений отключено: канал релизов не подписан; " +
			"обновитесь вручную с официального источника")
	}
	if e.appUpdater == nil {
		return fmt.Errorf("updater not initialized")
	}
	var expectedSHA256 string
	if st := e.appUpdater.GetLastStatus(); st != nil && st.DownloadURL == downloadURL {
		expectedSHA256 = st.SHA256
	}
	return e.appUpdater.DownloadAndApply(ctx, downloadURL, expectedSHA256, onProgress)
}

// GetConfig возвращает текущую конфигурацию.
func (e *Engine) GetConfig() *models.AppConfig {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg
}

// GetDiagnostics возвращает расширенную диагностику (Фаза 5: + leak status)
func (e *Engine) GetDiagnostics() map[string]interface{} {
	var rb map[string]interface{}
	e.stateMu.RLock()
	if e.lastRollback != nil {
		rb = map[string]interface{}{
			"at":          e.lastRollback.At,
			"stage":       e.lastRollback.Stage,
			"reason":      e.lastRollback.Reason,
			"was_running": e.lastRollback.WasRunning,
		}
	}
	// BUG-FIX: was duplicate RLock(); now reads diagBT/diagStrat under the existing lock.
	diagBT := e.blockageType
	diagStrat := e.strategy
	e.stateMu.RUnlock()

	return map[string]interface{}{
		"blockage_type":    diagBT.String(),
		"strategy_primary": diagStrat.Primary,
		"strategy_reason":  diagStrat.Reason,
		"use_reality":      diagStrat.UseReality,
		"use_cdn":          diagStrat.UseCDN,
		"use_chain":        diagStrat.UseChain,
		// C-5 (ТЗ v1.4): здесь стояло "fsm_state": e.fsm.State().String(). Автомат ЖИВ (его
		// двигают HandleSuccess/HandleFailure, см. возражение O-33), но он не выбирает
		// outbound, а Android и Web перестали это поле читать. Отдавать пользователю
		// внутреннее состояние, по которому ничего не решается, — та же нечестность, что и
		// строки FSM в логе (C-14). Диагностика автомата — в техническом канале log.Printf.
		// Фаза 5
		"ipv6_block":     e.ipv6Guard.IsEnabled(),
		"webrtc_block":   e.webrtcGuard.IsEnabled(),
		"crypto_enabled": e.cryptoStore != nil,
		"last_rollback":  rb,
		// C-4 (ТЗ v1.4): "" — последняя запись пула узлов прошла. Непустая строка означает,
		// что nodes_cache.json НЕ обновлён (fail-closed при отказе шифрования, K2-E П11, или
		// ошибка записи) и добавленные узлы не переживут перезапуск. Показ — за UI-лотами
		// (U-17); движок обязан лишь перестать молчать. models.ConnectionState полем не
		// расширялся сознательно: пакет models вне владения этого лота (см. result.md).
		"last_persist_error":    e.LastPersistError(),
		"last_persist_error_at": e.LastPersistErrorAt(),
		// ТЗ v1.3 F5.1: где лежит постоянный лог и сколько он весит
		"log_file":       e.LogFilePath(),
		"log_size_bytes": e.logFileSize(),
		// Sprint 7: версии
		"apf_version":      version.Version,
		"sing_box_version": singbox.SingBoxVersion,
	}
}

// GetLeakGuardStatus возвращает статус всех защит (Фаза 5)
func (e *Engine) GetLeakGuardStatus() map[string]interface{} {
	return map[string]interface{}{
		"ipv6_guard_enabled":   e.ipv6Guard.IsEnabled(),
		"webrtc_guard_enabled": e.webrtcGuard.IsEnabled(),
		// T-13b: честный статус WebRTC ("partial"/"none", никогда "full"). Раньше Status()
		// существовал и тестировался, но наружу не отдавался — UI получал лишь bool.
		"webrtc_status": e.webrtcGuard.Status(),
		// P1 (аудит 2026-09-01, security-раздел, находка №16): тот же принцип для IPv6 —
		// Status() существовал, но не отдавался наружу, и до этой правки не проверял, реально
		// ли действует Kill Switch (единственный механизм, который на Windows хоть что-то
		// делает для этой защиты). KillSwitchStatus().Active — тот же полинг-безопасный путь,
		// что уже читает дашборд каждую секунду (см. комментарий у KillSwitchStatus).
		"ipv6_status":          e.ipv6Guard.Status(e.KillSwitchStatus().Active),
		"crypto_enabled":       e.cryptoStore != nil,
		"browser_instructions": leakguard.GetBrowserInstructions(),
		"firefox_user_js":      leakguard.GenerateFirefoxUserJS(),
	}
}

// RunDNSLeakTest запускает полную проверку DNS-утечки (Фаза 5).
// Возвращает результат для отображения в UI.
func (e *Engine) RunDNSLeakTest(ctx context.Context) (*leakguard.DNSLeakResult, error) {
	e.log("Running DNS leak test...")
	result, err := e.dnsLeakTest.Test(ctx)
	if err != nil {
		return nil, err
	}
	e.log(fmt.Sprintf("DNS Leak Test result: leaked=%v diagnosis=%s",
		result.Leaked, result.Diagnosis))
	return result, nil
}

// EnableIPv6Block включает/выключает IPv6 блокировку (Фаза 5).
//
// C-13 (ТЗ v1.4, FAIL B2): до 2026-09-08 функция трогала ТОЛЬКО e.ipv6Guard. В config.json
// оставалось "block_ipv6_leak": true, и выбор пользователя жил ровно до следующего
// подключения (enableDeviceProtection читает КОНФИГ) или до перезапуска приложения. Живой
// прогон видел это как «тумблер выключен, Диагностика показывает включено». Истина —
// конфиг; guard — исполнитель, поэтому пишем оба и в таком порядке: сначала исполнитель
// (может отказать), потом истина.
func (e *Engine) EnableIPv6Block(enable bool) error {
	var err error
	if enable {
		err = e.ipv6Guard.Enable("apf0")
	} else {
		err = e.ipv6Guard.Disable()
	}
	if err != nil {
		return err
	}
	e.persistToggle(func(cfg *models.AppConfig) { cfg.BlockIPv6Leak = enable })
	if enable {
		e.log("IPv6 Leak Block: enabled by user")
	} else {
		e.log("IPv6 Leak Block: disabled by user")
	}
	return nil
}

// EnableWebRTCBlock включает/выключает WebRTC защиту (Фаза 5). Персист — см. EnableIPv6Block.
func (e *Engine) EnableWebRTCBlock(enable bool) error {
	var err error
	if enable {
		err = e.webrtcGuard.Enable()
	} else {
		err = e.webrtcGuard.Disable()
	}
	if err != nil {
		return err
	}
	e.persistToggle(func(cfg *models.AppConfig) { cfg.BlockWebRTC = enable })
	if enable {
		e.log("WebRTC Guard: enabled by user")
	} else {
		e.log("WebRTC Guard: disabled by user")
	}
	return nil
}

// persistToggle — общий путь сохранения тумблера защиты (C-13/C-3): изменение поля e.cfg под
// e.mu и запись конфига тем же способом, что у SetCyclicNodeSearch. Отдельная функция, чтобы
// у всех тумблеров был ОДИН писатель: разнобой в этом месте и породил FAIL B2.
func (e *Engine) persistToggle(apply func(cfg *models.AppConfig)) {
	e.mu.Lock()
	apply(e.cfg)
	var err error
	if e.saveConfig != nil {
		err = e.saveConfig(e.cfg)
	}
	e.mu.Unlock()
	if err != nil {
		e.log(fmt.Sprintf("Настройка не сохранена в config.json: %v", err))
	}
}

// PatchConfig применяет частичное обновление конфигурации.
// Все изменения валидируются перед применением.
// Sprint 8: добавлена валидация для предотвращения невалидных состояний.
// Sprint 9+: защищён мьютексом для безопасного конкурентного доступа.
func (e *Engine) PatchConfig(patch map[string]interface{}) error {
	_, err := e.PatchConfigDetailed(patch)
	return err
}

// dpiPatchKeys — ключи, после изменения которых нужно переприменить DPI/Session-настройки
// (applyDPIFromConfig), и ключи, требующие перезапуска процесса (needsRestart).
var (
	// К2-E П9: ключи traffic_padding_enabled / traffic_padding_aggressive убраны из этого
	// списка. Список означает «после изменения этого ключа нужно ПЕРЕПРИМЕНИТЬ настройку» —
	// для padding'а переприменять нечего: он не участвует в обработке трафика (см.
	// padding_enabled в GetDPIStatus). Значение по-прежнему сохраняется в конфигурации
	// обычным путём применения патча; лишним остаётся только обещание, что оно что-то
	// изменит прямо сейчас.
	dpiPatchKeys = map[string]bool{
		"cdn_worker_domain": true,
		"shadowtls_enabled": true, "shadowtls_sni": true, "shadowtls_password": true,
		"shadowtls_server_addr": true, "sticky_session_policy": true,
	}
	restartPatchKeys = map[string]bool{"listen_port": true, "webui_port": true}
)

// PatchConfigDetailed — ТЗ v1.3 F5.4 (консилиум 2026-09-03, GAP-25/V2): применение патча
// разделено на часть под e.mu (applyPatchLocked) и пост-применение ПОСЛЕ Unlock
// (applyDPIFromConfig → SetShadowTLSConfig сам берёт e.mu — под локом это deadlock).
// Живой инцидент 2026-09-02: /api/save-config {shadowtls_enabled:false} менял только файл, а
// DPI-менеджер оставался включённым до перезапуска — каждый outbound по-прежнему шёл в
// заглушку 5.6.7.8. Возвращает ключи, требующие перезапуска (listen_port/webui_port), чтобы UI
// показал тост «нужен перезапуск», а не молчал.
func (e *Engine) PatchConfigDetailed(patch map[string]interface{}) (needsRestart []string, err error) {
	if len(patch) == 0 {
		return nil, fmt.Errorf("patch is empty")
	}

	// Валидация входящих значений (до захвата мьютекса)
	if err := validatePatch(patch); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	needsRestart, dpiChanged, err := e.applyPatchLocked(patch)
	if err != nil {
		return nil, err
	}
	if dpiChanged {
		e.applyDPIFromConfig()
	}
	return needsRestart, nil
}

// applyPatchLocked — часть PatchConfig под e.mu: слияние, нормализация, сохранение.
func (e *Engine) applyPatchLocked(patch map[string]interface{}) (needsRestart []string, dpiChanged bool, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Находка Э-Win-TUN-2 (docs/TZ_WINDOWS_TUN_VPN_v1.0.md): connection_mode решает,
	// строит ли builder tun-inbound и какой backend берёт killswitch.NewLocalBackend —
	// оба вычисляются ОДИН РАЗ в New() и не пересобираются здесь. Смена connection_mode
	// на уже подключённом движке молча оставила бы builder/killswitch от СТАРОГО режима
	// (например, VPN→proxy: TUN-инбаунд и WFP-бэкенд остались бы висеть, хотя cfg уже
	// говорит "proxy") — в отличие от прочих полей patch (порт и т.п.), это не просто
	// «неудобно после перезапуска», а рассинхрон killswitch-защиты с фактическим
	// режимом. Поэтому именно это поле — явный отказ, а не тихое применение.
	if newMode, ok := patch["connection_mode"]; ok {
		if s, ok := newMode.(string); ok && s != e.cfg.ConnectionMode && e.IsConnected() {
			return nil, false, fmt.Errorf("connection_mode: нельзя сменить режим при активном подключении — сначала отключитесь")
		}
	}

	data, err := json.Marshal(e.cfg)
	if err != nil {
		return nil, false, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, false, err
	}
	for k, v := range patch {
		m[k] = v
	}
	data, err = json.Marshal(m)
	if err != nil {
		return nil, false, err
	}
	var newCfg models.AppConfig
	if err := json.Unmarshal(data, &newCfg); err != nil {
		return nil, false, err
	}

	// ТЗ v1.3 F5.2: те же правила, что на всех точках входа (раньше здесь были свои клампы,
	// расходившиеся с validatePatch/DefaultConfig — check_interval 10 против 5 и т.п.).
	// WebUIPort=0 — «выключено» — не для патча из UI: держим прежнее поведение (→ дефолт).
	if newCfg.WebUIPort == 0 {
		newCfg.WebUIPort = 9090
	}
	for _, w := range newCfg.Normalize() {
		e.log("Config: " + w)
	}
	for k := range patch {
		if restartPatchKeys[k] {
			needsRestart = append(needsRestart, k)
		}
		if dpiPatchKeys[k] {
			dpiChanged = true
		}
	}
	sort.Strings(needsRestart)

	// Находка Э-Win-TUN-4 (docs/TZ_WINDOWS_TUN_VPN_v1.0.md): отказ на «сменить режим при
	// подключении» выше защищает killswitch (currentKS() сам переоценивает бэкенд по
	// e.cfg.ConnectionMode при следующем вызове — переживает эту функцию без доп. кода),
	// но e.builder.tunMode — отдельное закэшированное поле (SetTunMode/SetTunMTU), которое
	// НИКТО кроме этой функции больше не синхронизирует с e.cfg после New(). Без явного
	// вызова тут смена режима из GUI (Э-Win-TUN-4) молча не подействовала бы до перезапуска
	// всего процесса — тот самый «повисает молча», от которого отказ выше защищает только
	// половину состояния. e.builder уже под тем же e.mu — SetTunMode(Engine) взял бы его
	// повторно и, в отличие от sync.RWMutex, sync.Mutex не реентерабелен: вызвали бы напрямую
	// методы Builder, а не Engine.SetTunMode.
	modeChanged := newCfg.ConnectionMode != e.cfg.ConnectionMode
	e.cfg = &newCfg
	if modeChanged {
		needTun := newCfg.ConnectionMode == models.ModeVPN || newCfg.ConnectionMode == models.ModeHybrid
		e.builder.SetTunMode(needTun)
		// mtu=0: «умолчание sing-box» — верно для десктопа, где TUN создаёт внешний
		// процесс sing-box сам и сам выбирает MTU (см. Builder.SetTunMTU, отличие от
		// Android, где интерфейс создаёт VpnService.Builder и MTU обязателен явно).
		e.builder.SetTunMTU(0)
	}

	// Обновляем trafficMonitor если порт изменился
	if e.trafficMonitor != nil {
		e.trafficMonitor = singbox.NewTrafficMonitor(newCfg.ListenPort + 2)
		e.wireTrafficMonitorStats()
	}

	return needsRestart, dpiChanged, e.saveConfig(e.cfg)
}

// ─── S-7 (ТЗ v1.4): белый список ключей конфиг-патча ─────────────────────────

// patchAllowedKeys — какие ключи вообще разрешено менять через PatchConfig/`/api/save-config`,
// и какого Go-типа поле за каждым из них стоит.
//
// ЗАЧЕМ. Раньше validatePatch была switch-ом по ШЕСТИ ключам без ветки default: всё, чего в
// switch нет, проходило без единой проверки. Практический итог (B1, находка S-7): HTTP-патч мог
// поставить `enable_kill_switch`, `set_system_proxy`, `disallowed_apps`, `relay_server_addr`
// любым значением любого типа, а посторонний ключ («опечатка в имени поля», «ключ из чужой
// версии UI») принимался, отвечал 200 и молча исчезал при разборе в models.AppConfig —
// пользователь видел успех там, где не изменилось НИЧЕГО.
//
// ПОЧЕМУ СПИСОК СТРОИТСЯ ОТРАЖЕНИЕМ, А НЕ РУКАМИ. Риск белого списка ровно один: случайно
// запретить ключ, которым пользуется свой же интерфейс (ТЗ, раздел «Риск» S-7). Список,
// выведенный из json-тегов models.AppConfig, не может от неё отстать: новое поле конфига
// разрешено в тот же момент, когда появилось, а удалённое перестаёт приниматься само.
// Проверено grep-ом по трём фронтам (web `/api/save-config`, Wails `App.PatchConfig`,
// androidbridge): все ключи, которые они шлют, — поля AppConfig, посторонних нет.
var patchAllowedKeys = buildPatchAllowedKeys()

// patchReadOnlyKeys — поля конфига, у которых есть собственный владелец-API; через патч они
// read-only (ТЗ v1.3 F2 I1, сохраняется без изменений).
var patchReadOnlyKeys = map[string]string{
	"pinned_node": "use the pin/favorites API",
	"favorites":   "use the pin/favorites API",
}

func buildPatchAllowedKeys() map[string]reflect.Kind {
	out := map[string]reflect.Kind{}
	t := reflect.TypeOf(models.AppConfig{})
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			continue
		}
		out[name] = t.Field(i).Type.Kind()
	}
	return out
}

// patchKindOK — грубая проверка «значение хотя бы того рода, что и поле».
//
// Намеренно грубая: задача — отсечь мусор (строка в bool-поле, число в строковом), а не
// повторить разбор encoding/json. Значение nil (JSON null) пропускается: для не-указательных
// полей json.Unmarshal трактует его как «ничего не менять», и это безопасный no-op.
// Составные поля (sources, paid_providers, pinned_node) проверяются только на «это вообще
// массив/объект» — их внутреннюю схему разбирает сам json.Unmarshal в applyPatchLocked.
func patchKindOK(kind reflect.Kind, val interface{}) bool {
	if val == nil {
		return true
	}
	switch kind {
	case reflect.Bool:
		_, ok := val.(bool)
		return ok
	case reflect.String:
		_, ok := val.(string)
		return ok
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		_, ok := toInt(val)
		return ok
	case reflect.Float32, reflect.Float64:
		switch val.(type) {
		case float64, int, int64, json.Number:
			return true
		}
		return false
	case reflect.Slice:
		_, ok := val.([]interface{})
		return ok
	case reflect.Map, reflect.Struct, reflect.Ptr, reflect.Interface:
		return true
	}
	return true
}

// patchStringSliceOK — дополнительная проверка для списков строк (disallowed_apps, bypass_list,
// force_list, adblock_allowlist): элемент не той природы уронил бы json.Unmarshal целиком, и
// патч отвергался бы с невнятным «cannot unmarshal number into Go value of type string».
func patchStringSliceOK(val interface{}) bool {
	if val == nil {
		return true
	}
	arr, ok := val.([]interface{})
	if !ok {
		return false
	}
	for _, v := range arr {
		if _, ok := v.(string); !ok {
			return false
		}
	}
	return true
}

// stringSliceConfigKeys — ключи AppConfig, за которыми стоит []string (см. patchStringSliceOK).
var stringSliceConfigKeys = map[string]bool{
	"disallowed_apps":   true,
	"bypass_list":       true,
	"force_list":        true,
	"adblock_allowlist": true,
}

// validatePatch проверяет значения перед применением к конфигу.
//
// Порядок проверок (S-7): 1) ключ вообще существует в models.AppConfig; 2) ключ не read-only;
// 3) значение хотя бы того рода, что и поле; 4) диапазоны для полей, у которых они есть.
// Любой отказ называет ключ поимённо — вызывающий (web-слой) отдаёт это текстом в 400.
func validatePatch(patch map[string]interface{}) error {
	for key, val := range patch {
		if reason, ro := patchReadOnlyKeys[key]; ro {
			return fmt.Errorf("field %s: read-only via config patch — %s", key, reason)
		}
		kind, known := patchAllowedKeys[key]
		if !known {
			return fmt.Errorf("field %s: unknown config key — not a field of AppConfig", key)
		}
		if !patchKindOK(kind, val) {
			return fmt.Errorf("field %s: wrong type %T for %s field", key, val, kind)
		}
		if stringSliceConfigKeys[key] && !patchStringSliceOK(val) {
			return fmt.Errorf("field %s: must be a list of strings, got %T", key, val)
		}
		switch key {
		case "listen_port", "webui_port":
			port, ok := toInt(val)
			if !ok || port < 1024 || port > 65530 {
				return fmt.Errorf("field %s: must be 1024–65530, got %v", key, val)
			}
		case "check_interval_sec":
			n, ok := toInt(val)
			if !ok || n < 5 || n > 3600 {
				return fmt.Errorf("check_interval_sec: must be 5–3600, got %v", val)
			}
		case "max_latency_ms":
			n, ok := toInt(val)
			if !ok || n < 100 {
				return fmt.Errorf("max_latency_ms: must be >= 100, got %v", val)
			}
		case "connection_mode":
			s, ok := val.(string)
			if !ok || (s != "proxy" && s != "vpn" && s != "hybrid") {
				return fmt.Errorf("connection_mode: must be proxy|vpn|hybrid, got %v", val)
			}
		case "selection_mode":
			s, ok := val.(string)
			if !ok || (s != "balanced" && s != "speed" && s != "stealth" && s != "streaming") {
				return fmt.Errorf("selection_mode: must be balanced|speed|stealth|streaming, got %v", val)
			}
		case "node_check_top_n":
			// ТЗ v1.7 (PROBE-DEPTH-SETTING): 0 = встроенный дефолт движка (30, см.
			// node_check.go defaultNodeCheckTopN); иначе 10–300, тот же диапазон, что
			// models.Normalize клампит для значений из config.json на диске.
			// Плюс режим «Все рабочие» (запрос владельца 09-15): точное значение
			// models.NodeCheckTopNAll пропускаем как сигнал «весь пул без среза» —
			// тот же спецкейс, что и в models.Normalize.
			n, ok := toInt(val)
			if !ok || (n != 0 && n != models.NodeCheckTopNAll && (n < 10 || n > 300)) {
				return fmt.Errorf("node_check_top_n: must be 0, 10–300, or %d (all), got %v", models.NodeCheckTopNAll, val)
			}
		}
		// ТЗ v1.3 F2 I1 (pinned_node/favorites): единственный писатель —
		// Pin/Unpin/AddFavorite/RemoveFavorite; через PatchConfig эти ключи менять нельзя
		// (иначе UI-патч «всего конфига» молча стирал бы закрепление, а движок не узнал бы об
		// изменении). Запрет переехал наверх, в patchReadOnlyKeys, чтобы отказ по read-only
		// проверялся ПЕРЕД проверкой типа и не зависел от порядка веток switch.
	}
	return nil
}

// toInt пытается привести interface{} к int.
func toInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	}
	return 0, false
}

// ─── Персистентность (Фаза 5: с шифрованием) ─────────────────────────────────

// saveNodes сохраняет пул узлов в nodes_cache.json (при заданном мастер-пароле — шифрованным).
//
// Вход:      текущий e.nodes.
// Тело:      сериализация → (шифрование) → атомарная запись.
// Выход:     nil при успехе, иначе ошибка записи/шифрования.
// Fail-safe: FAIL-CLOSED. Не удалось зашифровать — файл НЕ пишется вовсе и прошлый кэш
//
//	остаётся нетронутым; ошибка поднимается наверх.
//
// К2-E П11 (свод C трек 1 №11; B1 #2, A3). Раньше здесь стоял fail-open: при ошибке Encrypt
// пул писался ПЛАЙНТЕКСТОМ («Fallback: сохраняем без шифрования»). Пользователь задаёт
// мастер-пароль ровно затем, чтобы адреса, UUID и пароли протоколов не лежали на диске
// открытыми; одна ошибка шифрования — и предыдущий шифртекст затирался открытым текстом, а
// наружу не уходило ничего, кроме строки в логе. Молчаливое понижение уровня защиты — худший
// из возможных исходов: состояние выглядит нормальным, а секреты уже на диске.
//
// Возвращаемое значение можно игнорировать там, где сохранение — побочный эффект удачной
// операции (фон, дебаунс): вызывающему важно, что плайнтекст не появился, а не что запись
// удалась. Явно проверяют её те, кто обязан сообщить пользователю (см. Stop/Flush).
// C-4 (ТЗ v1.4): saveNodes — тонкая обёртка, единственная задача которой в том, чтобы исход
// записи попал в состояние движка, КАКИМ БЫ путём запись ни была вызвана. Вариант «записывать
// только в saveNodesDebounced» отвергнут: saveNodes зовут ещё полтора десятка мест
// (nodes_manage.go, sweep.go, Stop), и половина из них тоже игнорирует возвращаемое значение —
// обёртка покрывает их все разом и не может рассинхронизироваться с новыми вызовами.
func (e *Engine) saveNodes() error {
	err := e.saveNodesToDisk()
	e.recordPersistResult(err)
	return err
}

// recordPersistResult запоминает исход последней записи пула: ошибку — с текстом и временем,
// успех — очищает поле (проблема была временной: диск освободился, пароль исправлен).
func (e *Engine) recordPersistResult(err error) {
	e.persistMu.Lock()
	if err != nil {
		e.lastPersistErr = err.Error()
		e.lastPersistErrAt = time.Now()
	} else {
		e.lastPersistErr = ""
		e.lastPersistErrAt = time.Time{}
	}
	e.persistMu.Unlock()
}

// LastPersistError — текст последней неудачи сохранения пула узлов ("" — последняя запись
// прошла). C-4 (=U-17): три интерфейса показывают это рядом со списком узлов
// («узлы не сохранены: <причина>»), потому что молчаливая потеря пула при перезапуске
// неотличима для пользователя от «приложение всё забыло само».
func (e *Engine) LastPersistError() string {
	e.persistMu.RLock()
	defer e.persistMu.RUnlock()
	return e.lastPersistErr
}

// LastPersistErrorAt — когда именно запись не удалась (нулевое время, если ошибки нет).
func (e *Engine) LastPersistErrorAt() time.Time {
	e.persistMu.RLock()
	defer e.persistMu.RUnlock()
	return e.lastPersistErrAt
}

func (e *Engine) saveNodesToDisk() error {
	path := filepath.Join(config.DataDir(), "nodes_cache.json")
	// N-5 (ТЗ APF v1.5 §3, C9/C10/C11, DATA-LOSS-CRITICAL): фильтр — ТОЛЬКО на запись. Строим
	// ОТФИЛЬТРОВАННУЮ КОПИЮ, e.nodes в памяти остаётся ПОЛНЫМ (сканирование/выбор его не теряют).
	// pinnedID/favRefs читаются СВОИМИ leaf-локами (stateMu/favMu) ДО e.mu.RLock — оба
	// безопасны под ним (см. комментарии у PinnedNodeID/FavoriteRefs), но проще и надёжнее взять
	// их заранее и не держать три лока одновременно. FavoriteRefs() (не FavoriteIDs()) — W3:
	// filterNodesForRetention нужен класс (NodeRef.Origin) для потолка системного избранного.
	pinnedID := e.PinnedNodeID()
	favRefs := e.FavoriteRefs()
	now := time.Now().Unix()
	e.mu.RLock()
	retained := filterNodesForRetention(e.nodes, now, pinnedID, favRefs)
	data, _ := json.MarshalIndent(retained, "", "  ")
	e.mu.RUnlock()
	os.MkdirAll(filepath.Dir(path), 0700)

	// Фаза 5: шифруем если установлен мастер-пароль
	if e.cryptoStore != nil {
		encrypted, err := e.cryptoStore.Encrypt(data)
		if err != nil {
			e.log(fmt.Sprintf("Crypto: encrypt error: %v — кэш узлов НЕ сохранён "+
				"(незашифрованная запись запрещена)", err))
			return fmt.Errorf("кэш узлов не сохранён: шифрование не удалось: %w", err)
		}
		if err := writeFileAtomic(path, encrypted); err != nil {
			e.log(fmt.Sprintf("Cache: write encrypted error: %v", err))
			return err
		}
		return nil
	}

	if err := writeFileAtomic(path, data); err != nil {
		e.log(fmt.Sprintf("Cache: write error: %v", err))
		return err
	}
	return nil
}

// writeFileAtomic пишет файл через временный + Rename, чтобы прерывание записи не оставляло
// усечённый файл.
//
// P0-9 (аудит 2026-09-01). Раньше saveNodes звал os.WriteFile напрямую (O_TRUNC + Write):
// убийство процесса между усечением и завершением записи оставляло битый JSON, и следующий
// loadNodes возвращал ошибку разбора — весь пул узлов пользователя (включая добавленные
// вручную и партнёров цепочки) терялся молча. На Android это не гипотетика: система штатно
// убивает процесс под давлением памяти, причём saveNodes вызывается именно из Stop().
//
// Rename в пределах одного каталога атомарен и на POSIX, и на Windows (MoveFileEx с
// заменой) — читатель видит либо старый файл целиком, либо новый целиком.
func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp) // не оставляем мусор, если переименование не удалось
		return err
	}
	return nil
}

func (e *Engine) loadNodes() error {
	path := filepath.Join(config.DataDir(), "nodes_cache.json")
	rawData, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Фаза 5: расшифровываем если файл зашифрован
	var data []byte
	if apfcrypto.IsEncrypted(rawData) {
		if e.cryptoStore == nil {
			return fmt.Errorf("nodes cache is encrypted but no master password set")
		}
		data, err = e.cryptoStore.Decrypt(rawData)
		if err != nil {
			return fmt.Errorf("decrypt nodes cache: %w", err)
		}
		e.log("Crypto: nodes_cache.json decrypted successfully")
	} else {
		data = rawData
	}

	var nodes []*models.Node
	if err := json.Unmarshal(data, &nodes); err != nil {
		return err
	}
	now := time.Now()
	seen := make(map[string]*models.Node, len(nodes))
	migrated := make([]*models.Node, 0, len(nodes))
	dropped := 0
	nulls := 0
	for _, n := range nodes {
		// P0-9 (аудит 2026-09-01): элемент может быть nil.
		//
		// JSON `[null]` или `[{...},null]` разбирается БЕЗ ошибки в []*models.Node, давая
		// nil-указатель. Дальше `n.FailCount = 0` — паника, а loadNodes вызывается из
		// Engine.Start() → androidbridge.Init() → APFVpnService.onCreate(). На Android паника
		// в Go убивает процесс приложения целиком: APF падал бы при КАЖДОМ запуске навсегда,
		// до переустановки. Дефект самоподдерживающийся — файл пишет сам APF (saveNodes).
		if n == nil {
			nulls++
			continue
		}
		// ТЗ v1.3 F1.3 (консилиум 2026-09-03, NL-4/ND-4): история узла ПЕРЕЖИВАЕТ перезапуск.
		// Раньше здесь безусловно обнулялись FailCount/Score/LastChecked и снимался чёрный список —
		// каждый старт превращал 4000 узлов в «никогда не проверенные», при этом устаревший Status
		// (blocked/blacklist) оставался: в живом кэше 118 узлов с fail_count>0 и нулевым
		// last_checked, 39 «blacklist» с давно истёкшим сроком. Первый батч скана после этого —
		// просто позиции 0..49 файла. Теперь: истёкший бан снимаем и чиним Status, счётчик TCP-
		// отказов сбрасываем (сессионная величина), а Score/LastChecked/Verified*/FailStreak —
		// оставляем: возраст проверки штрафует ageFactor в calcScore, ради этого он и существует.
		n.FailCount = 0
		if !n.BlacklistedUntil.IsZero() && !now.Before(n.BlacklistedUntil) {
			n.BlacklistedUntil = time.Time{}
			if n.Status == models.StatusBlacklist {
				n.Status = models.StatusUnknown
			}
		}
		// Миграция схемы ID (2026-08-24, см. parser.generateID): раньше ID считался только по
		// protocol:address:port, теперь в хеш входят и учётные данные. Пересчитываем ID КАЖДОМУ
		// узлу из кеша, иначе старые записи и свежеразобранные ссылки жили бы под разными ID
		// и дедупликация в updateSources/AddNodeFromLink удвоила бы пул. Пересчёт идемпотентен:
		// второй запуск уже застаёт новые ID и ничего не меняет.
		n.ID = parser.GenerateNodeID(n)
		// Схлопываем настоящие дубликаты (полностью совпадающая конфигурация подключения),
		// которые до миграции могли лежать в кеше под разными ID — например, добавленные
		// разными путями. Молча выбрасывать записи из пользовательского кеша нельзя: если
		// схема ID когда-нибудь окажется недостаточно различающей, потеря узлов пройдёт
		// незаметно — а именно так и выглядела исходная жалоба. Поэтому считаем и логируем.
		if kept := seen[n.ID]; kept != nil {
			// ТЗ v1.3 F1.3: при схлопывании дубликатов история подтверждений СЛИВАЕТСЯ, а не
			// теряется вместе с отброшенной записью (max VerifiedCount/LastVerifiedAt/
			// LastFailedAt, OR UserBanned, непустая заметка) — иначе переезд схемы ID стирал бы
			// «проверенные» узлы (V3 к NL §4.6).
			mergeNodeHistory(kept, n)
			dropped++
			continue
		}
		seen[n.ID] = n
		migrated = append(migrated, n)
	}
	if dropped > 0 {
		e.log(fmt.Sprintf("Кеш узлов: схлопнуто %d дубликат(ов) из %d записей", dropped, len(nodes)))
	}
	if nulls > 0 {
		e.log(fmt.Sprintf("Кеш узлов: пропущено %d пустых записей (повреждённый файл) — "+
			"остальные %d узлов сохранены", nulls, len(migrated)))
	}
	e.mu.Lock()
	e.nodes = migrated
	e.mu.Unlock()
	return nil
}

func (e *Engine) setDisconnected() {
	e.stateMu.Lock()
	e.state.Connected = false
	// Не «провалилась», а «нет предмета проверки»: туннель снят намеренно (Disconnect/Stop/
	// откат), и показывать «канал не работает» на отсутствующем канале — та же ложь, что и
	// «подтверждён» на мёртвом, только в другую сторону.
	e.setVerifyStateLocked(models.VerifyIdle)
	e.connGen++ // T-05: помечаем подключение устаревшим для асинхронной UAC-горутины
	e.state.ActiveNode = nil
	e.state.ActiveChain = nil
	e.stateMu.Unlock()
	if e.OnStateChange != nil {
		e.OnStateChange(e.GetState())
	}
}

// logDiagN8 — единый формат точек инструментации N-8 (ТЗ APF v1.5 §3 N-8, DIAG_N8_PLAN.md §3):
// "[diag-N8] stage=<name> took=<dur>". Один паттерн — можно грепать свежий apf.log по
// "[diag-N8]" и сверять с таблицей §3.1 (ScanAndConnect/updateSources/runSweep/
// connectTopCandidates/applyKillSwitch/time-to-first-verified) без досочинения формата вручную.
func (e *Engine) logDiagN8(stage string, since time.Time) {
	e.log(fmt.Sprintf("[diag-N8] stage=%s took=%s", stage, time.Since(since).Round(time.Millisecond)))
}

func (e *Engine) log(msg string) {
	if e.OnLog != nil {
		e.OnLog(msg)
	} else {
		// Fallback: если OnLog не задан — пишем сами
		log.Printf("[ENGINE] %s", msg)
	}
	e.logSinksMu.RLock()
	sinks := e.logSinks
	e.logSinksMu.RUnlock()
	for _, s := range sinks {
		s(msg)
	}
}

// AddLogSink — ТЗ v1.3 F5.1: добавить получателя строк лога, не перезаписывая OnLog (раньше
// web.New делал `eng.OnLog = …` и молча отбирал лог у владельца — GAP-37).
func (e *Engine) AddLogSink(fn func(string)) {
	if fn == nil {
		return
	}
	e.logSinksMu.Lock()
	next := make([]func(string), 0, len(e.logSinks)+1)
	next = append(next, e.logSinks...)
	e.logSinks = append(next, fn)
	e.logSinksMu.Unlock()
}

// openFileLog открывает постоянный лог-файл (config.LogPath(): ротация 5×2 МБ, 72 ч, фильтр
// секретов) и подписывает его на строки лога. Не на Android — там свой ApfFileLogger (Kotlin).
func (e *Engine) openFileLog() {
	if runtime.GOOS == "android" || e.fileSink != nil {
		return
	}
	fs, err := logsink.NewFileSink(config.LogPath(), logsink.Options{})
	if err != nil {
		e.log(fmt.Sprintf("Лог-файл не открыт (%v) — лог только в памяти", err))
		return
	}
	e.fileSink = fs
	e.AddLogSink(fs.Write)
	e.log("Лог-файл: " + fs.Path())
}

// LogFilePath — путь постоянного лог-файла ("" — не ведётся: Android/ошибка открытия).
func (e *Engine) LogFilePath() string {
	if e.fileSink == nil {
		return ""
	}
	return e.fileSink.Path()
}

// FlushLog сбрасывает буфер лог-файла на диск (перед экспортом/остановкой).
func (e *Engine) FlushLog() {
	if e.fileSink != nil {
		_ = e.fileSink.Flush()
	}
}

func (e *Engine) logFileSize() int64 {
	if e.fileSink == nil {
		return 0
	}
	return e.fileSink.Size()
}

// ─── Фаза 6: DPI обход ───────────────────────────────────────────────────────

// RunCanaryTest запускает Canary-тест и применяет counter-measures если нужно.
// bypass-engineer: автоматически включаем padding/reality при детекции VPN.
func (e *Engine) RunCanaryTest(ctx context.Context) (*dpi.CanaryResult, error) {
	e.log("Running Canary test (VPN detectability check)...")
	result, err := e.canary.Test(ctx)
	if err != nil {
		return nil, err
	}

	e.stateMu.Lock()
	e.lastCanary = result
	e.stateMu.Unlock()

	e.log(fmt.Sprintf("Canary: score=%d detectable=%v — %s",
		result.Score, result.VPNDetectable, result.CounterMeasure))

	// Автоматически применяем counter-measures
	if result.VPNDetectable {
		e.applyDPICounterMeasures(result)
	}

	return result, nil
}

// applyDPICounterMeasures применяет меры противодействия DPI на основе Canary.
// bypass-engineer: выбираем measure по типу детекции.
func (e *Engine) applyDPICounterMeasures(r *dpi.CanaryResult) {
	switch r.CounterMeasure {
	case "reality+utls":
		// К2-E П9: РЕАЛЬНОЕ действие этой ветки — предпочтение Reality при SNI-блокировке
		// (единственный слой маскировки, который в APF действительно работает, вердикт B3).
		// Строка «enabling aggressive traffic padding» и вызов padder.Enable(true) отсюда
		// убраны: padding не применяется к данным нигде (см. GetDPIStatus), и сообщение
		// создавало у пользователя впечатление принятой контрмеры.
		e.log("DPI Counter-measure: приоритет Reality (маскировка SNI)")
		e.setBlockageType(detector.BlockageSNI) // Reality-first при детекте DPI

	case "traffic_padding+websocket":
		// Та же причина: предложить нечего — padding в APF неисполним, а websocket-транспорт
		// задаётся самим узлом, не контрмерой. Честно фиксируем детект, ничего не обещая.
		e.log("DPI Counter-measure: обнаружен DPI; traffic padding в APF не применяется — " +
			"помогает только смена узла/протокола")

	case "utls":
		e.log("DPI Counter-measure: uTLS already active via sing-box")
		// uTLS управляется через sing-box конфиг — ничего не делаем

	default:
		// score < 25 — всё ок
	}
}

// GetDPIStatus возвращает статус всех DPI-защит (Фаза 6)
func (e *Engine) GetDPIStatus(ctx context.Context) map[string]interface{} {
	e.stateMu.RLock()
	canary := e.lastCanary
	e.stateMu.RUnlock()

	var canaryData interface{}
	if canary != nil {
		canaryData = map[string]interface{}{
			"score":           canary.Score,
			"vpn_detectable":  canary.VPNDetectable,
			"diagnosis":       canary.Diagnosis,
			"counter_measure": canary.CounterMeasure,
			"duration_ms":     canary.Duration,
			"tested_at":       canary.TestedAt,
			"score_label":     dpi.FormatScore(canary.Score),
		}
	}

	return map[string]interface{}{
		// Canary
		"canary": canaryData,
		// Traffic Padding — К2-E П9 (свод C трек 1 №9; B1 #5, B3 #4, D6).
		//
		// ВСЕГДА false, и это не заглушка «пока не готово», а единственный честный ответ:
		// методы данных padding'а (dpi.TrafficPadder.WrapConn, .JitteredDial,
		// dpi.NewPaddedConn) не вызываются НИ ОДНОЙ строкой продакшн-кода — трафик через них
		// не проходит, задержки не вносятся, размеры пакетов не меняются. Раньше здесь стояло
		// e.padder.IsEnabled(), то есть состояние внутреннего флага, который ни на что не
		// влияет: пользователь видел «маскировка включена» ровно там, где её нет.
		//
		// Чинить padding по-настоящему нельзя без патча sing-box (вердикт консилиума: «не
		// делать»), поэтому правда — здесь, а не в попытке подключить его на живом трафике.
		// Инвариант держит TestK2E_PaddingDataPath_StillUnused: если методы данных начнут
		// вызываться, тест покраснеет и потребует вернуть сюда настоящее состояние.
		"padding_enabled": false,
		// padding_config убран намеренно (аудит 2026-09-21): он отражал изменяемый флаг e.padder,
		// который после прямого вызова EnableTrafficPadding мог показать enabled=true и тем самым
		// противоречить padding_enabled=false выше. Ни один UI его не читал (только докстринг
		// ApfCore.kt перечислял ключ). Единственная честная величина padding'а — padding_enabled=false.
		// Multi-hop — [консилиум, TZ_TAILS_HARDENING_2026-08-31.md кластер A, находка №1]
		// раньше здесь ошибочно читался EnableChain (управляет самим фактом сборки цепочки в
		// tryFallback) вместо MultiHopEnabled (управляет ТЕМ, КАК цепочка собирается —
		// см. buildMultiHopChain) — разные поля разной семантики, статус-API врал о состоянии
		// тумблера «Многохоповая цепочка» в UI.
		"multihop_enabled": e.cfg.MultiHopEnabled,
		// CDN Fronting
		"cdn_status": e.cdnFronter.GetStatus(ctx),
		// ShadowTLS
		"shadowtls_status": e.shadowTLS.GetStatus(ctx),
	}
}

// EnableTrafficPadding переключает флаг Traffic Padding (Фаза 6).
//
// К2-E П9: флаг переключается (настройка пользователя не теряется), но НИКАКОГО эффекта на
// трафик не имеет и больше не сообщает об обратном — см. развёрнутое обоснование у ключа
// padding_enabled в GetDPIStatus. Тумблер в интерфейсах снимают другие лоты трека 1.
func (e *Engine) EnableTrafficPadding(enable bool, aggressive bool) {
	if enable {
		e.padder.Enable(aggressive)
		e.log("Traffic Padding: отмечен включённым в настройках, но к трафику не применяется " +
			"(нет точки применения в APF)")
	} else {
		e.padder.Disable()
		e.log("Traffic Padding: выключен")
	}
}

// SetCDNConfig настраивает CDN Fronting (Фаза 6)
func (e *Engine) SetCDNConfig(workerDomain, backendHost string, backendPort int) {
	// ТЗ v1.3 F5.3: домен-заглушка (example.*, *.test, localhost, IP из документационных сетей)
	// не включает фронтинг — иначе весь трафик уходил бы в несуществующий воркер.
	if workerDomain != "" {
		if err := netutil.ValidateRemoteHost(workerDomain); err != nil {
			e.log(fmt.Sprintf("CDN Fronting: домен воркера отклонён — %v; фронтинг выключен", err))
			if e.OnLeakDetected != nil {
				e.OnLeakDetected("config", "CDN Fronting выключен: "+err.Error())
			}
			workerDomain = ""
		}
	}
	cfg := dpi.DefaultCDNConfig()
	cfg.Enabled = workerDomain != ""
	cfg.WorkerDomain = workerDomain
	cfg.BackendHost = backendHost
	cfg.BackendPort = backendPort
	e.cdnFronter = dpi.NewCDNFronter(cfg)
	if cfg.Enabled {
		e.log(fmt.Sprintf("CDN Fronting: configured via %s", workerDomain))
	} else {
		e.log("CDN Fronting: disabled")
	}
}

// GetCDNWorkerScript возвращает JavaScript код Cloudflare Worker (Фаза 6)
func (e *Engine) GetCDNWorkerScript() string {
	cfg := e.cdnFronter.GetStatus(context.Background())
	_ = cfg
	// Используем адрес текущего активного узла если есть
	e.stateMu.RLock()
	node := e.state.ActiveNode
	e.stateMu.RUnlock()

	host := "your-vpn-server.example.com"
	port := 443
	if node != nil {
		host = node.Address
		port = node.Port
	}
	return dpi.WorkerSetupInstructions(host, port)
}

// SetShadowTLSConfig настраивает ShadowTLS v3 (Фаза 6).
//
// Найдено QA 2026-08-17: UI (Android "СОХРАНИТЬ", тот же путь у desktop) принимал и
// сохранял полностью пустой конфиг (без пароля) с тостом успеха. SNI/Server безопасно
// откатываются на дефолт (www.bing.com) при пустом вводе — но Password такого отката не
// имеет и не может: пустой HMAC-ключ гарантированно не совпадёт с настройками сервера,
// т.е. включённый ShadowTLS с пустым паролем ГАРАНТИРОВАННО не поднимется. Отклоняем
// это здесь же, чтобы ошибка была видна в момент сохранения, а не как непонятный отказ
// подключения позже.
//
// Найдено QA 2026-08-18 (задача #29): GetStatus() намеренно НЕ возвращает пароль (секрет,
// не эхо в UI) — значит honest UI, подставляющий сохранённые SNI/Server/enabled при
// повторном открытии диалога, физически не может подставить и пароль. Без этой оговорки
// пользователь, открывший диалог заново и просто поправивший SNI, наткнулся бы на отказ
// "пароль обязателен" из-за пустого поля — хотя пароль реально уже настроен на сервере и
// сохранён. Пустой пароль отклоняется, ТОЛЬКО если ShadowTLS ещё не был включён с непустым
// паролем ранее; иначе пустое поле трактуется как «не меняю», прежний пароль сохраняется.
//
// P1-1 (аудит 2026-09-01): новый параметр serverAddr — адрес РЕАЛЬНОГО сервера ShadowTLS
// (host:port). handshakeServer (параметр server) описывает только маскировку — сайт,
// который должен увидеть DPI в TLS ClientHello — и трафик туда никогда не идёт; без
// serverAddr клиенту физически некуда подключаться, поэтому при enabled=true он обязателен
// той же логикой, что и пароль: пустое значение при уже включённом ShadowTLS с непустым
// serverAddr — «не меняю», иначе — отказ.
//
// P1-1: та же правка добавила персистенцию — раньше вызов ничего не писал в e.cfg/на диск,
// и любое изменение (включая Enabled/Password/SNI) терялось при следующем перезапуске,
// хотя AppConfig.ShadowTLSPassword/SNI существуют именно для этого и читаются при
// применении сохранённого конфига (см. applyDPIFromConfig).
func (e *Engine) SetShadowTLSConfig(enabled bool, password, sni, server, serverAddr string) error {
	if enabled && password == "" {
		existing := e.shadowTLS.GetConfig()
		if !existing.Enabled || existing.Password == "" {
			return fmt.Errorf("ShadowTLS: пароль обязателен при включении (должен совпадать с сервером)")
		}
		password = existing.Password
	}
	if enabled && serverAddr == "" {
		existing := e.shadowTLS.GetConfig()
		if !existing.Enabled || existing.ServerAddr == "" {
			return fmt.Errorf("ShadowTLS: адрес реального сервера обязателен при включении " +
				"(host:port — НЕ маскировочный SNI-сайт, а сервер, где поднят shadow-tls daemon)")
		}
		serverAddr = existing.ServerAddr
	}
	// ТЗ v1.3 F5.3 (GAP-43): адрес настоящего сервера не может быть заглушкой — инцидент
	// 2026-09-02: example.com/5.6.7.8:8443 из плейсхолдера остались включёнными, и каждый
	// outbound заворачивался в несуществующий сервер. RFC1918/CGNAT разрешены (свой сервер).
	if enabled {
		if err := netutil.ValidateRemoteTarget(serverAddr); err != nil {
			return fmt.Errorf("ShadowTLS: адрес сервера отклонён — %v", err)
		}
	}
	cfg := dpi.DefaultShadowTLSConfig()
	cfg.Enabled = enabled
	cfg.Password = password
	if sni != "" {
		cfg.HandshakeSNI = sni
	}
	if server != "" {
		cfg.HandshakeServer = server
	}
	if serverAddr != "" {
		cfg.ServerAddr = serverAddr
	}
	e.shadowTLS.SetConfig(cfg)
	if enabled {
		e.log(fmt.Sprintf("ShadowTLS v3: enabled (SNI: %s, server: %s)", cfg.HandshakeSNI, cfg.ServerAddr))
	} else {
		e.log("ShadowTLS v3: disabled")
	}

	e.mu.Lock()
	e.cfg.ShadowTLSEnabled = cfg.Enabled
	e.cfg.ShadowTLSSNI = cfg.HandshakeSNI
	e.cfg.ShadowTLSPassword = cfg.Password
	e.cfg.ShadowTLSServerAddr = cfg.ServerAddr
	e.saveConfig(e.cfg)
	e.mu.Unlock()
	return nil
}

// AutoSelectShadowTLSSNI автоматически выбирает лучший SNI для ShadowTLS
func (e *Engine) AutoSelectShadowTLSSNI(ctx context.Context) (string, error) {
	sni, server, latency, err := e.shadowTLS.AutoSelectSNI(ctx)
	if err != nil {
		return "", err
	}
	e.log(fmt.Sprintf("ShadowTLS: auto-selected SNI=%s latency=%dms", sni, latency))
	// Применяем выбранный SNI
	cfg := e.shadowTLS.GetConfig()
	cfg.HandshakeSNI = sni
	cfg.HandshakeServer = server
	e.shadowTLS.SetConfig(cfg)
	return sni, nil
}

// runPostConnectCanary запускает Canary-тест после успешного подключения.
// bypass-engineer: проверяем маскировку ПОСЛЕ установки туннеля.
func (e *Engine) runPostConnectCanary() {
	// P2 (аудит 2026-09-01): АВТОМАТИЧЕСКИЙ прогон Canary отключён.
	//
	// Две независимые причины, каждой достаточно.
	//
	// 1) Тест демаскирует пользователя. Его зонды сознательно идут МИМО туннеля (rawClient в
	//    dpi/canary.go), и запускался он на КАЖДОМ успешном подключении. То есть через 4
	//    секунды после установления VPN приложение с реального IP обращалось к
	//    tls.peet.ws — сервису TLS-фингерпринтинга, которым пользуются почти исключительно
	//    разработчики обходных инструментов. Наблюдатель на канале провайдера видел связку
	//    «TLS к неизвестному узлу → сразу прямой запрос к tls.peet.ws», то есть сильный
	//    маркер ровно того, что APF пытается скрыть.
	//
	// 2) Результат предопределён. Максимально достижимая сумма — 45 при пороге
	//    VPNDetectable = 50: одна проверка всегда возвращает false, другая всегда true
	//    (проверяет собственный SOCKS), третья ищет подстроку, которой в ответе сервиса нет,
	//    четвёртая меряет задержку мимо туннеля. Предупреждение не могло сработать никогда.
	//
	// Ручной запуск (RunCanaryTest через кнопку в UI) СОХРАНЁН: там пользователь сам решает
	// заплатить эту цену за диагностику. Убрана только автоматика, о которой он не знает.
	if !canaryAutoRunEnabled {
		return
	}

	if !e.sleepCtx(4 * time.Second) { // даём туннелю полностью встать
		return
	}
	// e.ctx — см. комментарий у runPostConnectHealthCheck.
	ctx, cancel := context.WithTimeout(e.currentCtx(), 20*time.Second)
	defer cancel()

	result, err := e.RunCanaryTest(ctx)
	if err != nil {
		e.log(fmt.Sprintf("Canary test error: %v", err))
		return
	}

	if result.VPNDetectable {
		e.log(fmt.Sprintf("⚠️ Canary: VPN detectable (score=%d) — applying counter-measures",
			result.Score))
		if e.OnLeakDetected != nil {
			e.OnLeakDetected("dpi", fmt.Sprintf("VPN обнаруживается провайдером (score=%d). %s",
				result.Score, result.Recommendation))
		}
	}
}

// SelectMultiHopChain выбирает оптимальную multi-hop цепочку из пула узлов.
func (e *Engine) SelectMultiHopChain(hops int) *dpi.MultiHopChain {
	e.mu.RLock()
	nodes := e.getActiveCandidates(30)
	e.mu.RUnlock()
	return e.multiHop.SelectBestChain(nodes, hops)
}

// applyDPIFromConfig — загружает DPI/Session настройки из персистентного конфига.
// Вызывается при старте Engine и после PatchConfig.
//
// ТЗ v1.3 F5.4: НЕ вызывать под e.mu (SetShadowTLSConfig берёт e.mu сам). Симметрично: настройка,
// выключенная в конфиге, реально выключает менеджер — раньше функция умела только включать, и
// PatchConfig {shadowtls_enabled:false} оставлял ShadowTLS активным до перезапуска.
func (e *Engine) applyDPIFromConfig() {
	e.mu.RLock()
	cfg := *e.cfg // снимок: ниже e.mu отпущен, а сеттеры берут его сами
	e.mu.RUnlock()

	// Traffic Padding — К2-E П9: состояние флага переносится из конфигурации, но «включено»
	// больше не заявляется (padding не применяется к данным, см. GetDPIStatus).
	if cfg.TrafficPaddingEnabled {
		e.padder.Enable(cfg.TrafficPaddingAggressive)
		e.log("Config: Traffic Padding отмечен в настройках, но к трафику не применяется")
	} else if e.padder != nil && e.padder.IsEnabled() {
		e.padder.Disable()
		e.log("Config: Traffic Padding выключен")
	}

	// CDN Fronting
	if cfg.CDNWorkerDomain != "" {
		// F5.3: домен-заглушка не включает фронтинг (SetCDNConfig сам отвергнет и залогирует).
		e.SetCDNConfig(cfg.CDNWorkerDomain, "", 443)
	} else if e.cdnFronter != nil && e.cdnFronter.IsEnabled() {
		e.SetCDNConfig("", "", 443)
	}

	// ShadowTLS
	if cfg.ShadowTLSEnabled {
		// P1-1 (аудит 2026-09-01): ошибка теперь проверяется. Сохранённый конфиг с
		// Enabled=true, но без ShadowTLSServerAddr (старый конфиг, созданный до этого
		// поля, либо руками отредактированный файл) раньше молча "включал" ShadowTLS,
		// который на самом деле никогда бы не заработал — пользователь видел тумблер
		// "включено" и не подозревал, что реального эффекта это не даёт.
		// F5.3: адрес-заглушка (example.com/5.6.7.8/203.0.113.x) — та же ветка: не включаем,
		// WARN в лог и уведомление в UI (инцидент 2026-09-02).
		if err := e.SetShadowTLSConfig(true, cfg.ShadowTLSPassword, cfg.ShadowTLSSNI,
			cfg.ShadowTLSSNI+":443", cfg.ShadowTLSServerAddr); err != nil {
			e.log(fmt.Sprintf("Config: ShadowTLS v3 НЕ включён — %v", err))
			e.disableShadowTLSKeepSecrets()
			if e.OnLeakDetected != nil {
				e.OnLeakDetected("config", "ShadowTLS выключен: "+err.Error())
			}
		} else {
			e.log(fmt.Sprintf("Config: ShadowTLS v3 enabled (SNI: %s)", cfg.ShadowTLSSNI))
		}
	} else if e.shadowTLS != nil && e.shadowTLS.IsEnabled() {
		e.disableShadowTLSKeepSecrets()
		e.log("Config: ShadowTLS v3 disabled")
	}

	// Sticky Session Policy
	if cfg.StickySessionPolicy != "" {
		e.SetStickyPolicy(cfg.StickySessionPolicy)
		e.log(fmt.Sprintf("Config: Sticky Session policy: %s", cfg.StickySessionPolicy))
	}
}

// disableShadowTLSKeepSecrets выключает менеджер ShadowTLS, НЕ стирая сохранённые пароль/адрес
// (в отличие от SetShadowTLSConfig(false, "", …), который записал бы пустой пароль в e.cfg —
// и повторное включение из UI потребовало бы вводить его заново, см. QA 2026-08-18 #29).
func (e *Engine) disableShadowTLSKeepSecrets() {
	if e.shadowTLS == nil {
		return
	}
	c := *e.shadowTLS.GetConfig()
	c.Enabled = false
	e.shadowTLS.SetConfig(&c)
}

// ─── Фаза 7: Аварийные туннели + Watchdog ─────────────────────────────────

// GetFallbackStatus — статус всех аварийных туннелей (Фаза 7)
func (e *Engine) GetFallbackStatus() map[string]interface{} {
	result := map[string]interface{}{}
	if e.emergencyFallback != nil {
		result["fallback"] = e.emergencyFallback.GetStatus(e.currentCtx())
	}
	if e.watchdog != nil {
		result["watchdog"] = e.watchdog.GetStatus()
	}
	return result
}

// ActivateFallbackTunnel — ручная активация аварийного туннеля (Фаза 7)
// tunnel: "tor", "tor_snowflake", "psiphon"
//
// К2-E П7(а) (свод C трек 1 №7; B3 #3): "tor_snowflake" отвергается ЧЕСТНОЙ ошибкой на всех
// платформах. Раньше вызов проходил тот же путь, что и обычный Tor: SetActive(Snowflake),
// сообщение «подключаюсь через tor_snowflake», а применялся голый {type:"tor"} — Snowflake не
// доходит до sing-box ни на одной платформе (см. fallback.ErrSnowflakeNotApplicable), на
// Android его нет и структурно. Отказ идёт ДО SetActive, чтобы статус резервов не показывал
// активным туннель, который не запускался.
func (e *Engine) ActivateFallbackTunnel(tunnel string) error {
	if e.emergencyFallback == nil {
		return fmt.Errorf("fallback orchestrator not initialized")
	}
	var ft fallback.FallbackTunnel
	switch tunnel {
	case "tor":
		ft = fallback.FallbackTor
	case "tor_snowflake":
		if !e.emergencyFallback.SnowflakeApplicable() {
			err := error(fallback.ErrSnowflakeNotApplicable)
			// Если вдобавок нечем запустить и обычный Tor — говорим и это: обе причины
			// верны одновременно, и ворота D-A29 (ручная кнопка проходит ту же проверку,
			// что и автоматический фаллбэк) остаются закрытыми, а не подменяются.
			if !e.emergencyFallback.TorAvailable() {
				err = fmt.Errorf("%w. Кроме того: %w", fallback.ErrSnowflakeNotApplicable, ErrTorUnavailable)
			}
			e.log("Фаллбэк: " + err.Error())
			return err
		}
		ft = fallback.FallbackSnowflake
	case "psiphon":
		ft = fallback.FallbackPsiphon
	default:
		return fmt.Errorf("unknown fallback tunnel: %s", tunnel)
	}

	e.log(fmt.Sprintf("Фаллбэк: активация %s...", tunnel))
	// C-4/C-6 (ТЗ v1.4): запоминаем прежний активный резерв. `active` — не служебный флажок,
	// а то, что три интерфейса показывают полем "active_tunnel" (GetFallbackStatus →
	// FallbackOrchestrator.GetStatus). Раньше он выставлялся ДО единственной попытки поднять
	// туннель и не откатывался при её провале: неудачная активация Tor оставляла в статусе
	// «активен Tor», хотя не запускалось вообще ничего.
	prevActive := e.emergencyFallback.GetActive()
	e.emergencyFallback.SetActive(ft)

	// C-6 (ТЗ v1.4): контракт «конфигурация + признак применимости» вместо голой nil-проверки.
	if _, supported := e.emergencyOutboundFor(ft); !supported {
		e.emergencyFallback.SetActive(prevActive)
		err := e.emergencyUnsupportedErr(ft, tunnel)
		e.log("Фаллбэк: " + err.Error())
		return err
	}

	// Для Tor/Snowflake — sing-box сам прокидывает кировый выход;
	// для Psiphon — проксируем через SOCKS5 psiphond.
	// Ручная активация проходит ту же проверку исполнимости, что и автоматическая
	// (дефект D-A29): кнопка в интерфейсе не должна уметь то, чего не умеет движок.
	e.log(fmt.Sprintf("Фаллбэк: подключаюсь через %s...", tunnel))
	if err := e.applyTorFallback("emergency-"+tunnel, "Emergency: "+tunnel); err != nil {
		e.emergencyFallback.SetActive(prevActive)
		return err
	}
	return nil
}

// emergencyOutboundFor — контракт C-6 (ТЗ v1.4): «конфигурация резервного туннеля И признак,
// применима ли она», вместо прежнего `outbound := GetSingBoxConfig(ft)`, чей результат
// использовался ТОЛЬКО как nil-проверка и тут же выбрасывался.
//
// ПОЧЕМУ ЗНАЧЕНИЕ ВСЁ РАВНО НЕ ПРИМЕНЯЕТСЯ. Карта, которую строит fallback-пакет, НЕ является
// вендорной схемой sing-box: под ключом "options" там лежат опции torrc
// (ClientTransportPlugin/UseBridges/Bridge — см. комментарий у fallback.ErrSnowflakeNotApplicable),
// тогда как vendor option/tor.go ждёт ключ "torrc". Подставить такую карту в конфигурацию
// нельзя — sing-box её не разберёт. Поэтому применимую конфигурацию Tor движок строит сам,
// вендорным путём: singbox.Builder.BuildTor() (голый outbound {type:"tor"}), а карта отсюда
// служит ровно одному: сказать, есть ли у резерва хоть какая-то реализация.
//
// ПОЧЕМУ КОНТРАКТ ЖИВЁТ В ДВИЖКЕ, А НЕ В fallback. ТЗ предлагает сменить сигнатуру
// GetSingBoxConfig на (map, bool); пакет internal/fallback этим лотом не владеется (правка
// пошла бы поверх чужого файла), а наблюдаемое поведение — честный отказ вместо молчаливой
// подмены — от места объявления не зависит. Расхождение зафиксировано в result.md.
//
// Snowflake — единственный неприменимый резерв (Н-6: не оживлять). Tor и Psiphon применимы в
// том смысле, что у движка есть чем их поднять; исполнимость проверяет уже applyTorFallback
// (ErrTorUnavailable, ворота D-A29).
func (e *Engine) emergencyOutboundFor(ft fallback.FallbackTunnel) (map[string]interface{}, bool) {
	if e.emergencyFallback == nil {
		return nil, false
	}
	outbound := e.emergencyFallback.GetSingBoxConfig(ft)
	if outbound == nil {
		return nil, false
	}
	if ft == fallback.FallbackSnowflake {
		return outbound, false
	}
	// C-22 (НОВЫЙ пункт ТЗ v1.4, найден лотом L1b-ENG2): та же молчаливая подмена, что у
	// Snowflake. PsiphonManager.GetSingBoxOutbound возвращает нормальный SOCKS-outbound на
	// 127.0.0.1:<SOCKSPort> psiphond, но ни одна ветка движка его НЕ применяет: и ручная
	// активация, и авто-фаллбэк идут в applyTorFallback, который строит {type:"tor"}.
	// Пользователь, выбравший «Psiphon», получал прямой Tor и сообщение об успехе.
	if ft == fallback.FallbackPsiphon {
		return outbound, false
	}
	return outbound, true
}

// emergencyUnsupportedErr — текст отказа для неприменимого резерва. Для Snowflake это ровно та
// же ошибка, что отдаёт ранний гейт SnowflakeApplicable(): отказ обязан быть ОДИН и узнаваться
// через errors.Is, откуда бы он ни пришёл.
func (e *Engine) emergencyUnsupportedErr(ft fallback.FallbackTunnel, tunnel string) error {
	if ft == fallback.FallbackSnowflake {
		return fallback.ErrSnowflakeNotApplicable
	}
	if ft == fallback.FallbackPsiphon {
		// Тот же приём, что у раннего гейта Snowflake (см. ActivateFallbackTunnel): когда
		// вдобавок нечем запустить и обычный Tor, обе причины верны ОДНОВРЕМЕННО, и ворота
		// D-A29 («ручная кнопка проходит ту же проверку, что автоматический фаллбэк»)
		// остаются закрытыми, а не подменяются. errors.Is находит и ту, и другую.
		if e.emergencyFallback != nil && !e.emergencyFallback.TorAvailable() {
			return fmt.Errorf("%w. Кроме того: %w", ErrPsiphonNotApplicable, ErrTorUnavailable)
		}
		return ErrPsiphonNotApplicable
	}
	return fmt.Errorf("резервный туннель %q не реализован: APF не умеет передать его "+
		"конфигурацию в sing-box", tunnel)
}

// AutoSelectFallback — автоматически выбирает лучший аварийный туннель
func (e *Engine) AutoSelectFallback() string {
	if e.emergencyFallback == nil {
		return string(fallback.FallbackNone)
	}
	ctx, cancel := context.WithTimeout(e.currentCtx(), 15*time.Second)
	defer cancel()
	best := e.emergencyFallback.SelectBest(ctx)
	e.log(fmt.Sprintf("Авто-фаллбэк: выбран %s", best))
	return string(best)
}

// GetWatchdogStatus — статус watchdog для UI
func (e *Engine) GetWatchdogStatus() map[string]interface{} {
	if e.watchdog == nil {
		return map[string]interface{}{"state": "disabled"}
	}
	s := e.watchdog.GetStatus()
	return map[string]interface{}{
		"state":        string(s.State),
		"fail_count":   s.FailCount,
		"latency_ms":   s.LatencyMs,
		"last_error":   s.LastError,
		"total_checks": s.TotalChecks,
		"total_fails":  s.TotalFails,
		"last_check":   s.LastCheckAt,
	}
}

// SetNodeAutoSwitchEnabled включает/выключает автопереключение узлов при сбое (см. комментарий
// у models.AppConfig.NodeAutoSwitchEnabled). Отдельный типизированный метод, не через общий
// PatchConfig — Android-мост (mobile/androidbridge) собирается gomobile bind, который не умеет
// в map[string]interface{} через границу FFI, поэтому у Android свои typed setter-функции
// (см. SetAntiBlockConfig выше) в отличие от desktop GUI, где то же самое идёт через
// App.PatchConfig({node_auto_switch_enabled: ...}).
func (e *Engine) SetNodeAutoSwitchEnabled(enabled bool) {
	e.mu.Lock()
	e.cfg.NodeAutoSwitchEnabled = enabled
	e.saveConfig(e.cfg)
	e.mu.Unlock()
	if enabled {
		e.log("Автопереключение узлов: включено")
	} else {
		e.log("Автопереключение узлов: выключено пользователем")
	}
}

// IsNodeAutoSwitchEnabled — текущее состояние тумблера (для инициализации UI).
func (e *Engine) IsNodeAutoSwitchEnabled() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg.NodeAutoSwitchEnabled
}

// SetCyclicNodeSearch включает/выключает круговой обход пула при исчерпании обычного
// Score-based выбора (см. комментарий у models.AppConfig.CyclicNodeSearch). Тот же
// typed-setter приём, что и SetNodeAutoSwitchEnabled — Android-мост не умеет в generic
// PatchConfig через границу gomobile.
func (e *Engine) SetCyclicNodeSearch(enabled bool) {
	e.mu.Lock()
	e.cfg.CyclicNodeSearch = enabled
	e.saveConfig(e.cfg)
	e.mu.Unlock()
	if enabled {
		e.log("Циклический поиск узла: включён")
	} else {
		e.log("Циклический поиск узла: выключен")
	}
}

// IsCyclicNodeSearchEnabled — текущее состояние тумблера (для инициализации UI).
func (e *Engine) IsCyclicNodeSearchEnabled() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg.CyclicNodeSearch
}

// SetChainMode включает/выключает режим цепочки VPN → Proxy (см. models.AppConfig.EnableChain
// и её комментарий). На Android до этой правки настройки не было вовсе — тот же typed-setter
// приём, что и SetCyclicNodeSearch: Android-мост не умеет в generic PatchConfig через границу
// gomobile, а Web/Wails ходят через App.PatchConfig({enable_chain: ...}) напрямую.
func (e *Engine) SetChainMode(enabled bool) {
	e.mu.Lock()
	e.cfg.EnableChain = enabled
	e.saveConfig(e.cfg)
	e.mu.Unlock()
	if enabled {
		e.log("Режим цепочки: включён")
	} else {
		e.log("Режим цепочки: выключен")
	}
}

// IsChainModeEnabled — текущее состояние тумблера (для инициализации UI).
func (e *Engine) IsChainModeEnabled() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg.EnableChain
}

// SetMultihopEnabled включает/выключает выбор узлов РАЗНЫХ протоколов на каждом звене
// цепочки (см. models.AppConfig.MultiHopEnabled) — уточняет SetChainMode и без него (или без
// автоматической эскалации при глубокой блокировке) эффекта не даёт. Тот же typed-setter приём.
func (e *Engine) SetMultihopEnabled(enabled bool) {
	e.mu.Lock()
	e.cfg.MultiHopEnabled = enabled
	e.saveConfig(e.cfg)
	e.mu.Unlock()
	if enabled {
		e.log("Многохоповая цепочка: включена")
	} else {
		e.log("Многохоповая цепочка: выключена")
	}
}

// IsMultihopEnabled — текущее состояние тумблера (для инициализации UI).
func (e *Engine) IsMultihopEnabled() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg.MultiHopEnabled
}

// SetMultihopCount задаёт число хопов многохоповой цепочки. Допустимы только 2 и 3 (см.
// models.AppConfig.MultiHopCount) — как и Normalize() при загрузке конфига, любое другое
// значение откатывается на 2 здесь же, а не молча уходит в конфиг с недопустимым числом.
func (e *Engine) SetMultihopCount(n int) {
	if n != 2 && n != 3 {
		n = 2
	}
	e.mu.Lock()
	e.cfg.MultiHopCount = n
	e.saveConfig(e.cfg)
	e.mu.Unlock()
	e.log(fmt.Sprintf("Число хопов в цепочке: %d", n))
}

// GetMultihopCount — текущее число хопов (для инициализации UI). 0 (ещё не задано) отдаёт
// дефолт 2, а не 0 — 0 хопов бессмысленно показывать в спиннере с вариантами {2, 3}.
func (e *Engine) GetMultihopCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cfg.MultiHopCount == 0 {
		return 2
	}
	return e.cfg.MultiHopCount
}

// ─── W3 (ТЗ v1.5 §5): интервал пересмотра каталога ──────────────────────────────────────

// isKnownReviewInterval — единственное место, перечисляющее допустимые значения
// AppConfig.CatalogReviewInterval (держим ЗДЕСЬ, а не в models/config_normalize.go — тот файл
// вне зоны этого лота).
func isKnownReviewInterval(v string) bool {
	switch v {
	case models.ReviewIntervalEachScan, models.ReviewIntervalDaily, models.ReviewIntervalWeekly, models.ReviewIntervalMonthly:
		return true
	default:
		return false
	}
}

// CatalogReviewInterval — текущий интервал пересмотра каталога (W3 §5): ГЕЙТ ДАВНОСТИ, после
// которого проваленная проба на СЛЕДУЮЩЕЙ ручной сборке вправе снять узел из системного
// избранного — НЕ триггер автозапуска сборки (сканирование остаётся только по кнопке
// пользователя, owner-декрет консилиума TZ_v1.5_NODE_CATALOG_2026-09-14). Пустое/неизвестное
// значение в cfg (руками отредактированный/устаревший config.json — этот файл сознательно не
// проходит через models.AppConfig.Normalize, которая вне зоны этого лота) читается как
// ReviewIntervalEachScan, а не падает и не паникует.
func (e *Engine) CatalogReviewInterval() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cfg == nil || !isKnownReviewInterval(e.cfg.CatalogReviewInterval) {
		return models.ReviewIntervalEachScan
	}
	return e.cfg.CatalogReviewInterval
}

// SetCatalogReviewInterval сохраняет интервал пересмотра каталога (leaf-локed через
// persistToggle — тот же единственный-писатель приём, что у остальных enum-настроек, см.
// SetStickyPolicy/SetAdBlockProfile). В отличие от загрузки старого конфига (которая всегда
// откатывается на дефолт БЕЗ ошибки — см. CatalogReviewInterval), здесь неизвестное значение —
// ОШИБКА без побочных эффектов: это явный пользовательский ввод, ему нужно сообщить, что значение
// не подошло, а не молча подменить его.
func (e *Engine) SetCatalogReviewInterval(v string) error {
	v = strings.ToLower(strings.TrimSpace(v))
	if !isKnownReviewInterval(v) {
		return fmt.Errorf("неизвестный интервал пересмотра каталога: %q", v)
	}
	e.persistToggle(func(cfg *models.AppConfig) { cfg.CatalogReviewInterval = v })
	e.log(fmt.Sprintf("Каталог: интервал пересмотра установлен на %s", v))
	return nil
}

// reviewIntervalDuration — переводит настройку интервала пересмотра в порог давности последнего
// ПОДТВЕРЖДЕНИЯ (Node.LastVerifiedAt), после которого проваленная проба вправе вытеснить системный
// фаворит (W3 §3/§5, reconcileFavoritesFromNodeCheck в node_check.go). "each_scan" и любое
// нераспознанное значение → 0 (эвикшен без отсрочки — честный провал виден сразу, а не
// "each_scan" молча превращается в "никогда"). LastVerifiedAt — unix-секунды, не календарная
// дата, поэтому day/week/month — фиксированные приближения (24ч/7сут/30сут), не календарные.
func reviewIntervalDuration(v string) time.Duration {
	switch v {
	case models.ReviewIntervalDaily:
		return 24 * time.Hour
	case models.ReviewIntervalWeekly:
		return 7 * 24 * time.Hour
	case models.ReviewIntervalMonthly:
		return 30 * 24 * time.Hour
	default:
		return 0
	}
}

// ─── Sticky Session API ─────────────────────────────────────────────────────────

// GetStickySessionStatus — статус Sticky Session для Web UI
func (e *Engine) GetStickySessionStatus() map[string]interface{} {
	status := e.stickySession.Status()
	// Добавляем решение о текущем состоянии
	decision := e.stickySession.CanSwitch(false)
	status["can_switch"] = decision.Allow
	status["switch_blocked_reason"] = decision.Reason
	status["retry_in_sec"] = decision.RetryIn.Seconds()
	return status
}

// SetStickyPolicy — меняем политику Sticky Session
func (e *Engine) SetStickyPolicy(policy string) {
	// Неизвестное значение = дефолт "sticky" (тот же список, что в models.Config.Normalize).
	// Имя нормализуется здесь же: в конфиг обязано попасть ровно то, что движок применил, —
	// иначе после перезапуска пользователь получил бы третью, никем не выбранную политику.
	p, name := session.PolicySticky, "sticky"
	switch policy {
	case "free":
		p, name = session.PolicyFree, "free"
	case "timed":
		p, name = session.PolicyTimed, "timed"
	}
	e.stickySession.SetPolicy(p)
	// C-3 (ТЗ v1.4, K8-LIVE B3): поле StickySessionPolicy в конфиге существовало и ЧИТАЛОСЬ
	// при применении конфига, но обратной записи не было — выбор «Свободно менять» жил только
	// в памяти менеджера и умирал вместе с процессом. Частный случай C-13, решается тем же
	// единственным писателем.
	e.persistToggle(func(cfg *models.AppConfig) { cfg.StickySessionPolicy = name })
	e.log(fmt.Sprintf("Sticky Session: policy set to %s", name))
}

// ─── C-15 (ТЗ v1.4): серия ручных «Сменить сервер» ───────────────────────────────

// forceSwitchExcludeTTL — сколько узел, опробованный ручным переключением и не подтвердившийся
// реальным трафиком, не предлагается снова. Того же порядка, что recentFailureTTL: достаточно,
// чтобы серия кликов исследовала пул, и недостаточно, чтобы пул сузился надолго.
// var, а не const — граница проверяется тестом (риск из ТЗ: «слишком агрессивное исключение»).
var forceSwitchExcludeTTL = 10 * time.Minute

// forceSwitchMaxAttempts — сколько кандидатов подряд движок пробует по кнопке «Сменить сервер»,
// прежде чем сказать пользователю правду вместо молчаливого возврата на прежний узел.
var forceSwitchMaxAttempts = 3

// switchNoticeNoOtherNode — текст для UI и лога, когда серия исчерпана.
const switchNoticeNoOtherNode = "Не удалось найти другой рабочий узел — оставлен прежний"

// setSwitchNotice кладёт краткое объяснение результата ручного переключения в состояние
// (models.ConnectionState.SwitchNotice). "" очищает.
func (e *Engine) setSwitchNotice(msg string) {
	e.stateMu.Lock()
	e.state.SwitchNotice = msg
	e.stateMu.Unlock()
}

// purgeForceSwitchTriedLocked чистит истёкшие исключения. Вызывается ПОД forceSwitchMu.
// Когда не осталось ни одного исключения, серия считается завершённой и счётчик обнуляется:
// иначе кнопка осталась бы «исчерпанной» навсегда.
func (e *Engine) purgeForceSwitchTriedLocked() {
	now := time.Now()
	for id, at := range e.forceSwitchTried {
		if now.Sub(at) > forceSwitchExcludeTTL {
			delete(e.forceSwitchTried, id)
		}
	}
	if len(e.forceSwitchTried) == 0 {
		e.forceSwitchStreak = 0
	}
}

// forceSwitchPlan — решение одного нажатия «Сменить сервер».
//
// Вход:      состояние движка (активный узел, пул, исключения серии).
// Выход:     (узел для попытки, false) — пробуем этот узел; (nil, true) — серия исчерпана,
//
//	пользователю говорим правду и остаёмся на прежнем узле; (nil, false) — кандидатов
//	нет вообще (свежий пул без Score) — вызывающий уходит в пересканирование, как раньше.
//
// Игнорирует: узлы, опробованные этой же серией и не подтвердившиеся (TTL), — ровно то, чего
//
//	не хватало живому прогону D3, где один и тот же relay выигрывал выбор каждый клик.
//
// Порядок мьютексов: выборка кандидатов делается под e.mu.RLock и завершается ДО захвата
// forceSwitchMu — тот остаётся листом.
func (e *Engine) forceSwitchPlan() (*models.Node, bool) {
	e.stateMu.RLock()
	cur := e.state.ActiveNode
	e.stateMu.RUnlock()

	e.mu.RLock()
	ranked := e.selectCandidatesExcluding(cur)
	e.mu.RUnlock()

	e.forceSwitchMu.Lock()
	defer e.forceSwitchMu.Unlock()
	e.purgeForceSwitchTriedLocked()

	if e.forceSwitchStreak >= forceSwitchMaxAttempts {
		return nil, true
	}
	for _, n := range ranked {
		if n == nil {
			continue
		}
		if _, tried := e.forceSwitchTried[n.ID]; tried {
			continue
		}
		// Исключаем СРАЗУ, а не по факту провала: post-connect проверка асинхронна, а
		// следующий клик пользователя приходит раньше её вердикта (живой прогон: семь кликов
		// подряд). Подтверждение трафиком снимает исключение — см. noteForceSwitchOutcome.
		e.forceSwitchTried[n.ID] = time.Now()
		e.forceSwitchStreak++
		return n, false
	}
	return nil, len(e.forceSwitchTried) > 0
}

// noteForceSwitchOutcome снимает исключение с узла, который ПОДТВЕРДИЛСЯ реальным трафиком,
// и обнуляет серию: следующее нажатие начинает отсчёт заново, а не с исчерпания.
// Зовётся из recordNodeVerified — единственного писателя Verified*-полей.
func (e *Engine) noteForceSwitchOutcome(nodeID string) {
	if nodeID == "" {
		return
	}
	e.forceSwitchMu.Lock()
	delete(e.forceSwitchTried, nodeID)
	e.forceSwitchStreak = 0
	e.forceSwitchMu.Unlock()
}

// isRelayExitNode — узел роли «Выход» цепочки Вход-Выход: ссылка relay (apf_relay=1,
// см. connectNode) или явно добавленный партнёр цепочки. Такие узлы указывают на конкретный
// чужой компьютер: когда он выключен, health check валится ГАРАНТИРОВАННО, а Score у них
// высокий (CDN-фронт отвечает мгновенно) — в живом прогоне D3 они выигрывали выбор каждый раз.
func isRelayExitNode(n *models.Node) bool {
	if n == nil {
		return false
	}
	return n.IsChainPartner || n.ExtraParams["apf_relay"] == "1"
}

// ForceSwitchNow — принудительное переключение несмотря на Sticky Session.
// Для кнопки "Сменить сервер" в UI.
func (e *Engine) ForceSwitchNow() {
	decision := e.stickySession.CanSwitch(true) // forced=true
	if !decision.Allow {
		e.log("Force switch: not allowed even with force flag")
		return
	}
	e.log("Force switch: bypassing Sticky Session")
	// ТЗ v1.3 F2 (B-08.4 пересмотрен): «Сменить сервер» pin НЕ снимает — раньше здесь стоял
	// UnpinNode(), и один клик молча стирал выбор пользователя («сбрасывается избранный»).
	// Закреплённый узел лишь подавляется на recentFailureTTL, чтобы выбор не вернулся на него
	// тут же (I5, нет пинг-понга); возврат — при следующем событии выбора после окна (I4).
	e.suppressPin(recentFailureTTL)
	// Sprint 4: очищаем domain sticky при принудительном переключении
	e.stickySession.ClearDomainSticky()
	// НЕ e.fsm.HandleFailure(). Найдено 2026-08-24 живым тестированием пользователя:
	// «переключение → нет узлов», «обновить подключение → бесконечный поиск», «после ошибки
	// больше не находит серверов» — все три симптома сходятся к одной причине.
	//
	// HandleFailure — эскалационный автомат для НАСТОЯЩИХ сбоев соединения: он двигает
	// внутренний уровень (протокол → протокол → следующий уровень → ... → Tor/Snowflake/
	// Psiphon) и НЕ откатывается сам по себе — сброс только на полном Stop()/Restart()
	// (см. engine.go, оба места с fsm.Reset()). Ручное «Сменить сервер» — это осознанный
	// выбор пользователя попробовать другой узел, а не признак того, что текущий протокол
	// не работает. Раньше каждый клик двигал автомат ровно как настоящий сбой: через
	// несколько ручных переключений подряд (обычное поведение при тестировании — нажать
	// пару раз, посмотреть на результат) движок реально доходил до попыток Tor/Psiphon,
	// которых в этой сборке физически нет (нет tor/psiphond) — и застревал там: следующие
	// клики продолжали эскалацию оттуда же, а не начинали заново с обычного пула узлов.
	// Внешне это выглядело как «нет узлов»/«бесконечный поиск» — на деле пул был цел,
	// просто выбор узла для него больше не вызывался, вызывался Tor-путь.
	//
	// Если что и нужно fsm при ручном переключении — то явный Reset (пользователь начинает
	// заново), а не эскалация; но и это не требуется: ниже уже есть безопасный fallback на
	// tryFallback(), который и без FSM корректно проходит все уровни при пустом selectBest.
	// C-15 (ТЗ v1.4, FAIL D3): выбор идёт не по «лучшему кроме текущего», а по плану серии —
	// узлы, уже опробованные этой серией и не подтвердившиеся, исключаются на
	// forceSwitchExcludeTTL, а после forceSwitchMaxAttempts серия честно останавливается.
	e.setSwitchNotice("")
	best, exhausted := e.forceSwitchPlan()
	// См. комментарий у ForceRescan — goTracked вместо голого go закрывает окно
	// «тихий реконнект переживает Stop()».
	if best != nil {
		e.log(fmt.Sprintf("Сменить сервер: пробую узел «%s»", best.Name))
		e.goTracked(func() {
			if err := e.connectNode(best); err != nil {
				e.log(fmt.Sprintf("Force switch failed: %v", err))
			}
		})
		return
	}
	if exhausted {
		// Пункт 3 решения C-15: молчаливый возврат на тот же сервер — это и есть жалоба
		// «кнопка не работает». Говорим прямо и оставляем прежний узел (он хотя бы жив).
		e.log(switchNoticeNoOtherNode)
		e.setSwitchNotice(switchNoticeNoOtherNode)
		return
	}
	// selectBestExcluding не нашла НИ ОДНОГО кандидата со Score>0 — это не значит, что узлов
	// нет: свежезагруженный/только что "оживлённый" узел (AddNodeFromLink) имеет Score=0,
	// пока его не проверит сканирование. Раньше отсюда сразу уходили в tryFallback()
	// (Tor/Psiphon-тупик), даже когда пул был полон непроверенных, но потенциально рабочих
	// узлов. Сначала — быстрое сканирование части пула, и только если ОНО тоже не даёт ни
	// одного рабочего кандидата, тогда уже аварийные туннели.
	e.log("Force switch: нет проверенных кандидатов — пересканирую пул перед аварийным туннелем")
	e.goTracked(func() {
		if err := e.ScanAndConnect(); err != nil {
			e.log(fmt.Sprintf("Force switch: пересканирование не помогло (%v), пробую аварийные туннели", err))
			_ = e.tryFallback()
		}
	})
}

// ─── Sprint S2: Catalog API ───────────────────────────────────────────────────

// GetCatalogStatus возвращает статус всех провайдеров для Web UI.
//
// node_count в Registry.Status() — это ProviderMeta.NodeCount, счётчик из ПОСЛЕДНЕГО
// живого Fetch() этого провайдера в ЭТОМ процессе (providers.go). У большинства
// пользователей пул на старте загружается из nodes_cache.json, а не живым Fetch —
// поэтому без этой правки диалог «Каталог серверов» показывал «0 узлов» у каждого
// источника, даже когда в пуле реально лежали тысячи узлов с этим Source (найдено
// живым QA на телефоне 2026-08-20). Пересчитываем node_count из фактического e.nodes,
// сгруппированного по Source — это то же самое поле, что providers.go проставляет
// узлам при Fetch (n.Source = p.id), поэтому ключи совпадают.
func (e *Engine) GetCatalogStatus() []map[string]interface{} {
	if e.catalogRegistry == nil {
		return nil
	}
	e.mu.Lock()
	counts := make(map[string]int, len(e.nodes))
	for _, n := range e.nodes {
		counts[n.Source]++
	}
	e.mu.Unlock()

	status := e.catalogRegistry.Status()
	for _, s := range status {
		if id, ok := s["id"].(string); ok {
			s["node_count"] = counts[id]
		}
	}
	return status
}

// RefreshCatalog принудительно обновляет узлы из всех активных провайдеров.
// Результаты добавляются в пул узлов engine (без дублей).
func (e *Engine) RefreshCatalog(ctx context.Context) (int, error) {
	if e.catalogFetcher == nil {
		return 0, fmt.Errorf("catalog fetcher not initialized")
	}
	e.log("Catalog: refreshing all providers...")
	newNodes, results := e.catalogFetcher.FetchAll(ctx)

	// Логируем результаты по провайдерам
	for _, r := range results {
		if r.Error != nil {
			e.log(fmt.Sprintf("Catalog: provider %s FAILED (%v): %v", r.ProviderID, r.Duration.Round(time.Millisecond), r.Error))
		} else {
			e.log(fmt.Sprintf("Catalog: provider %s OK — %d nodes (%v)", r.ProviderID, len(r.Nodes), r.Duration.Round(time.Millisecond)))
		}
	}

	if len(newNodes) == 0 {
		return 0, nil
	}

	// Добавляем новые узлы в пул
	e.mu.Lock()
	existing := make(map[string]bool, len(e.nodes))
	for _, n := range e.nodes {
		existing[n.ID] = true
	}
	added := 0
	for _, n := range newNodes {
		if !existing[n.ID] && !e.isTombstoned(n.ID) { // F3: удалённое пользователем не воскрешаем
			existing[n.ID] = true
			e.nodes = append(e.nodes, n)
			added++
		}
	}
	e.mu.Unlock()

	if added > 0 {
		e.log(fmt.Sprintf("Catalog: added %d new nodes (total: %d)", added, len(e.nodes)))
		e.saveNodes()
	}
	return added, nil
}

// SetProviderEnabled включает/выключает провайдера каталога по ID.
func (e *Engine) SetProviderEnabled(id string, enabled bool) bool {
	if e.catalogRegistry == nil {
		return false
	}
	ok := e.catalogRegistry.SetEnabled(id, enabled)
	if ok {
		e.log(fmt.Sprintf("Catalog: provider %s enabled=%v", id, enabled))
	}
	return ok
}

// ─── Sprint S4: AdBlock API ───────────────────────────────────────────────────

// GetAdBlockStatus возвращает статус AdBlock для Web UI.
func (e *Engine) GetAdBlockStatus() map[string]interface{} {
	if e.adBlocker == nil {
		return map[string]interface{}{"profile": "disabled", "total_domains": 0}
	}
	s := e.adBlocker.GetStats()
	return map[string]interface{}{
		"profile":            string(e.adBlocker.GetProfile()),
		"total_domains":      s.TotalDomains,
		"allowlist_size":     s.AllowlistSize,
		"last_updated":       s.LastUpdated,
		"update_duration_ms": s.UpdateDuration,
		"sources_loaded":     s.SourcesLoaded,
		"sources_failed":     s.SourcesFailed,
		"allowlist":          e.adBlocker.GetAllowlist(),
	}
}

// SetAdBlockProfile устанавливает профиль AdBlock и загружает блок-листы.
// profile: "disabled", "light", "standard", "strict"
func (e *Engine) SetAdBlockProfile(profile string) error {
	if e.adBlocker == nil {
		return fmt.Errorf("adblock not initialized")
	}
	p := adblock.Profile(profile)
	switch p {
	case adblock.ProfileDisabled, adblock.ProfileLight, adblock.ProfileStandard, adblock.ProfileStrict:
		// ok
	default:
		return fmt.Errorf("unknown adblock profile: %s", profile)
	}
	e.log(fmt.Sprintf("AdBlock: setting profile to '%s'...", profile))
	// Обновление листов запускаем асинхронно чтобы не блокировать HTTP handler
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := e.adBlocker.SetProfile(ctx, p); err != nil {
			e.log(fmt.Sprintf("AdBlock: profile update error: %v", err))
		}
	}()
	// Сохраняем в конфиг
	e.mu.Lock()
	e.cfg.AdBlockProfile = profile
	e.saveConfig(e.cfg)
	e.mu.Unlock()
	return nil
}

// AdBlockToggleAllowlist добавляет или удаляет домен из белого списка AdBlock.
//
// P1-6 (аудит 2026-09-01). Раньше метод делал ровно один шаг — правил map в памяти
// блокировщика — и на этом останавливался. Не хватало трёх вещей, без которых пользователь
// не получал обещанного результата:
//
//  1. сохранения — список терялся при перезапуске (см. AppConfig.AdBlockAllowlist);
//  2. применения к активному подключению — правила уезжали в sing-box только при следующем
//     коннекте, то есть «разрешил домен, а сайт всё равно не грузится» до переподключения;
//  3. отклика на некорректный ввод — мусор молча ложился в список (см. normalizeDomain).
//
// Возвращает true, если состояние действительно изменилось. false означает «ничего не
// произошло» — вызывающая сторона обязана сообщить об этом пользователю, а не рисовать успех.
func (e *Engine) AdBlockToggleAllowlist(domain string, add bool) bool {
	if e.adBlocker == nil {
		return false
	}
	changed := false
	if add {
		changed = e.adBlocker.AddToAllowlist(domain)
		if changed {
			e.log(fmt.Sprintf("AdBlock: allowlist +%s", domain))
		}
	} else {
		changed = e.adBlocker.RemoveFromAllowlist(domain)
		if changed {
			e.log(fmt.Sprintf("AdBlock: allowlist -%s", domain))
		}
	}
	if !changed {
		// Ввод не изменил состояние: либо не домен, либо уже был (не было) в списке.
		// Молчать нельзя — иначе UI показывает «применено», а не применилось ничего.
		e.log(fmt.Sprintf("AdBlock: allowlist без изменений (%q)", domain))
		return false
	}

	list := e.adBlocker.GetAllowlist()
	e.mu.Lock()
	e.cfg.AdBlockAllowlist = list
	e.saveConfig(e.cfg)
	e.mu.Unlock()

	// Пересобрать конфигурацию имеет смысл только если AdBlock вообще включён: при
	// профиле "disabled" GetSingBoxDNSRules() возвращает nil и переподключение ничего не
	// изменило бы, а разрыв активного соединения пользователь бы заметил.
	if e.adBlocker.GetProfile() != adblock.ProfileDisabled {
		e.reapplyConfigIfConnected("AdBlock")
	}
	return true
}

// ─── Sprint S6: Anti-VPN-Block API ─────────────────────────────────────────────

// GetAntiBlockStatus — статус Anti-VPN-Block для Web UI.
// Возвращает: включён ли режим, качество IP текущего узла, статистику пула.
func (e *Engine) GetAntiBlockStatus() map[string]interface{} {
	status := map[string]interface{}{
		"enabled":          e.cfg.AntiBlockEnabled,
		"residential_only": e.cfg.AntiBlockResidentialOnly,
		"auto_switch":      e.cfg.AntiBlockAutoSwitch,
		"cache_size":       0,
		"current_ip_info":  nil,
		"pool_stats":       map[string]int{},
		"bypass_rules":     0,
	}

	if e.ipRepChecker != nil {
		status["cache_size"] = e.ipRepChecker.CacheSize()
	}
	if e.resSelector != nil {
		status["pool_stats"] = e.resSelector.Stats()
	}
	if e.bypassManager != nil {
		status["bypass_rules"] = len(e.bypassManager.Rules())
	}

	// Проверяем IP текущего узла если подключены
	e.stateMu.RLock()
	activeNode := e.state.ActiveNode
	e.stateMu.RUnlock()

	if activeNode != nil && e.ipRepChecker != nil {
		cached := e.ipRepChecker.GetCached(activeNode.Address)
		if cached != nil {
			status["current_ip_info"] = map[string]interface{}{
				"ip":             cached.IP,
				"label":          cached.Label(),
				"is_residential": cached.IsResidential,
				"is_datacenter":  cached.IsDatacenter,
				"is_proxy":       cached.IsProxy,
				"risk_score":     cached.RiskScore,
				"isp":            cached.ISP,
				"asn":            cached.ASN,
				"country":        cached.Country,
				"source":         cached.Source,
				"good_streaming": cached.IsGoodForStreaming(),
			}
		}
	}

	return status
}

// CheckNodeIP проверяет IP-репутацию узла по ID.
// Использует кэш если есть, иначе делает запрос к API.
func (e *Engine) CheckNodeIP(ctx context.Context, nodeID string) (map[string]interface{}, error) {
	if e.ipRepChecker == nil {
		return nil, fmt.Errorf("anti-block not initialized")
	}

	// Находим узел по ID
	e.mu.RLock()
	var targetNode *models.Node
	for _, n := range e.nodes {
		if n.ID == nodeID {
			targetNode = n
			break
		}
	}
	e.mu.RUnlock()

	if targetNode == nil {
		return nil, fmt.Errorf("node not found: %s", nodeID)
	}

	e.log(fmt.Sprintf("Anti-Block: checking IP for node %s (%s)", targetNode.Name, targetNode.Address))
	info, err := e.ipRepChecker.CheckIP(ctx, targetNode.Address)
	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{
		"node_id":        nodeID,
		"node_name":      targetNode.Name,
		"ip":             info.IP,
		"label":          info.Label(),
		"is_residential": info.IsResidential,
		"is_datacenter":  info.IsDatacenter,
		"is_proxy":       info.IsProxy,
		"is_vpn":         info.IsVPN,
		"risk_score":     info.RiskScore,
		"isp":            info.ISP,
		"org":            info.Org,
		"asn":            info.ASN,
		"country":        info.Country,
		"source":         info.Source,
		"good_streaming": info.IsGoodForStreaming(),
	}
	return result, nil
}

// CheckCurrentIP проверяет репутацию IP текущего активного узла.
func (e *Engine) CheckCurrentIP(ctx context.Context) (map[string]interface{}, error) {
	if e.ipRepChecker == nil {
		return nil, fmt.Errorf("anti-block not initialized")
	}
	e.stateMu.RLock()
	activeNode := e.state.ActiveNode
	e.stateMu.RUnlock()

	if activeNode == nil {
		return nil, fmt.Errorf("not connected")
	}
	return e.CheckNodeIP(ctx, activeNode.ID)
}

// CheckCurrentIPByAddr проверяет репутацию произвольного IP-адреса.
// Используется для тестирования любого IP через Web UI.
func (e *Engine) CheckCurrentIPByAddr(ctx context.Context, ip string) (map[string]interface{}, error) {
	if e.ipRepChecker == nil {
		return nil, fmt.Errorf("anti-block not initialized")
	}
	if ip == "" {
		return nil, fmt.Errorf("empty IP")
	}
	info, err := e.ipRepChecker.CheckIP(ctx, ip)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"ip":             info.IP,
		"label":          info.Label(),
		"is_residential": info.IsResidential,
		"is_datacenter":  info.IsDatacenter,
		"is_proxy":       info.IsProxy,
		"is_vpn":         info.IsVPN,
		"risk_score":     info.RiskScore,
		"isp":            info.ISP,
		"org":            info.Org,
		"asn":            info.ASN,
		"country":        info.Country,
		"source":         info.Source,
		"good_streaming": info.IsGoodForStreaming(),
	}, nil
}

// SetAntiBlockConfig устанавливает настройки Anti-VPN-Block.
func (e *Engine) SetAntiBlockConfig(enabled, residentialOnly, autoSwitch bool, apiKey string) {
	e.mu.Lock()
	e.cfg.AntiBlockEnabled = enabled
	e.cfg.AntiBlockResidentialOnly = residentialOnly
	e.cfg.AntiBlockAutoSwitch = autoSwitch
	if apiKey != "" {
		e.cfg.AntiBlockAPIKey = apiKey
	}
	e.saveConfig(e.cfg)
	e.mu.Unlock()
	if apiKey != "" && e.ipRepChecker != nil {
		e.ipRepChecker.SetAPIKey(apiKey)
	}

	if enabled {
		e.log(fmt.Sprintf("Anti-Block: enabled (residential_only=%v, auto_switch=%v)",
			residentialOnly, autoSwitch))
	} else {
		e.log("Anti-Block: disabled")
	}
}

// GetBypassRules возвращает все bypass-правила для Web UI.
func (e *Engine) GetBypassRules() []map[string]interface{} {
	if e.bypassManager == nil {
		return nil
	}
	rules := e.bypassManager.Rules()
	result := make([]map[string]interface{}, len(rules))
	for i, r := range rules {
		result[i] = map[string]interface{}{
			"id":                  r.ID,
			"name":                r.Name,
			"domains":             r.Domains,
			"require_residential": r.RequireResidential,
			"direct_route":        r.DirectRoute,
			"prefer_country":      r.PreferCountry,
			"notes":               r.Notes,
			"enabled":             r.Enabled,
			"builtin":             r.Builtin,
		}
	}
	return result
}

// reapplyBypassIfConnected — задача #25, живой QA 2026-08-18: CRUD над bypass-правилами менял
// только bypassManager (persisted список) — в реально запущенный sing-box новые правила
// попадали лишь при СЛЕДУЮЩЕМ connectNode/connectChain (переподключение), не сразу. Живьём
// подтверждено логкатом: curl к домену с "прямой маршрут" шёл через outbound/shadowsocks[proxy]
// сразу после Add, и только outbound/direct[direct] после ручного disconnect/reconnect — при
// этом UI никак не сообщал пользователю о необходимости переподключиться.
//
// Переиспользует уже закалённый живыми прогонами путь коннекта (тот же connectNode/connectChain,
// что и обычное подключение/переключение узла, включая Android TunReloader из задачи #11), а не
// изобретает отдельный «частичный» reload — тот же connMu (внутри applySingBoxConfig)
// сериализует это с любым другим одновременным подключением, так что гонки с ручным
// disconnect/switch исключены тем же механизмом, что уже проверен для остальных путей.
func (e *Engine) reapplyBypassIfConnected() { e.reapplyConfigIfConnected("Bypass") }

// reapplyConfigIfConnected — общий механизм из комментария выше. Параметр label — только для
// строк лога, поведение от него не зависит.
//
// P1-6 (аудит 2026-09-01): вынесено из reapplyBypassIfConnected, потому что ровно та же
// проблема была у белого списка AdBlock — правила уезжают в sing-box только при следующем
// коннекте. Переиспользуем закалённый путь, а не заводим второй такой же.
func (e *Engine) reapplyConfigIfConnected(label string) {
	if !e.IsConnected() {
		return
	}
	e.stateMu.RLock()
	node := e.state.ActiveNode
	chain := e.state.ActiveChain
	e.stateMu.RUnlock()
	// Помечаем цель ДО подключения: applySingBoxConfig обязана отличить «переприменение правил к
	// тому же живому узлу» от «переход на другой узел» — иначе она безусловно гасит состояние
	// подтверждения, и исправный туннель на секунды уходит в «ищу рабочий узел» просто потому,
	// что пользователь поправил bypass-список. См. verifyStateOnApply.
	if chain != nil {
		e.log(label + ": изменение применяется к активному подключению (цепочка)...")
		e.markReapplyTarget(nil, chain)
		e.goTracked(func() {
			if err := e.connectChain(chain); err != nil {
				e.log(fmt.Sprintf("%s: применение к активной цепочке не удалось: %v", label, err))
			}
		})
		return
	}
	if node != nil {
		e.log(label + ": изменение применяется к активному подключению...")
		e.markReapplyTarget(node, nil)
		e.goTracked(func() {
			if err := e.connectNode(node); err != nil {
				e.log(fmt.Sprintf("%s: применение к активному узлу не удалось: %v", label, err))
			}
		})
	}
}

// SetBypassRule включает/выключает bypass-правило по ID.
func (e *Engine) SetBypassRule(id string, enabled bool) bool {
	if e.bypassManager == nil {
		return false
	}
	ok := e.bypassManager.SetRuleEnabled(id, enabled)
	if ok {
		e.log(fmt.Sprintf("Anti-Block bypass: rule %s enabled=%v", id, enabled))
		e.reapplyBypassIfConnected()
	}
	return ok
}

// AddBypassDomain добавляет пользовательское bypass-правило. directRoute=true — домен идёт
// НАПРЯМУЮ, в обход VPN целиком (не защищён VPN); requireResidential — домен идёт через VPN,
// но предпочтителен residential-узел. Оба флага независимы (можно оба false/true).
func (e *Engine) AddBypassDomain(domain, name string, requireResidential, directRoute bool) bool {
	if e.bypassManager == nil {
		return false
	}
	// К2-E П12: причина отказа больше не теряется. Раньше на любой некорректный ввод сюда
	// возвращался просто nil, интерфейс показывал безмолвное «не получилось», и пользователь
	// не понимал, что именно не так с его доменом.
	r, err := e.bypassManager.AddUserRuleChecked(domain, name, requireResidential, directRoute)
	if err != nil {
		e.log(fmt.Sprintf("Bypass: домен %q отклонён — %v", domain, err))
		return false
	}
	if r != nil {
		e.log(fmt.Sprintf("Bypass: added domain %s (residential=%v, direct_route=%v)",
			r.Domains[0], requireResidential, directRoute))
		e.reapplyBypassIfConnected()
		return true
	}
	return false
}

// UpdateBypassDomain редактирует пользовательское bypass-правило (builtin — нельзя).
func (e *Engine) UpdateBypassDomain(id, domain, name string, requireResidential, directRoute bool) bool {
	if e.bypassManager == nil {
		return false
	}
	ok := e.bypassManager.UpdateUserRule(id, domain, name, requireResidential, directRoute)
	if ok {
		e.log(fmt.Sprintf("Bypass: updated rule %s (domain=%s, residential=%v, direct_route=%v)",
			id, domain, requireResidential, directRoute))
		e.reapplyBypassIfConnected()
	}
	return ok
}

// RemoveBypassDomain удаляет пользовательское bypass-правило.
func (e *Engine) RemoveBypassDomain(id string) bool {
	if e.bypassManager == nil {
		return false
	}
	ok := e.bypassManager.RemoveUserRule(id)
	if ok {
		e.log(fmt.Sprintf("Bypass: removed rule %s", id))
		e.reapplyBypassIfConnected()
	}
	return ok
}

// ─── Приложения вне VPN (Android per-app split tunneling) ─────────────────────
//
// См. models.AppConfig.DisallowedApps: механизм ОС-уровня, дополняющий bypass-домены.
// Хранение здесь (а не только в Kotlin) даёт единый источник истины и переживает
// переустановку вместе с остальным config.json.

// DisallowedApps возвращает копию списка пакетов, исключённых из VPN.
func (e *Engine) DisallowedApps() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]string, len(e.cfg.DisallowedApps))
	copy(out, e.cfg.DisallowedApps)
	return out
}

// SetDisallowedApps заменяет список пакетов, исключённых из VPN, и сохраняет конфиг.
//
// Применение к УЖЕ активному соединению — забота вызывающей стороны на Android: список
// читает Kotlin в момент сборки VpnService.Builder, а пересобрать интерфейс можно только
// пересозданием TUN (тот же путь, что у задачи #11 — ReloadWithFreshTun). Здесь мы
// сознательно НЕ дёргаем reapplyBypassIfConnected: он переприменяет конфиг sing-box, а
// список исключённых приложений живёт не в конфиге sing-box, а в самом VPN-интерфейсе.
func (e *Engine) SetDisallowedApps(pkgs []string) {
	cleaned := make([]string, 0, len(pkgs))
	seen := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		cleaned = append(cleaned, p)
	}
	e.mu.Lock()
	e.cfg.DisallowedApps = cleaned
	e.mu.Unlock()
	// Логируем ТОЛЬКО количество. Перечень пакетов — чувствительные данные (это список
	// банковских, платёжных и государственных приложений пользователя), а e.log уходит в
	// постоянный файловый журнал с ротацией 72 часа, который пользователь может выгрузить и
	// переслать через «Поделиться». Kotlin-половина этой же фичи осознанно пишет в журнал
	// только счётчик — здесь была единственная точка утечки (найдено ревью 2026-08-24).
	e.log(fmt.Sprintf("Вне VPN: приложений в списке — %d", len(cleaned)))
	if err := config.SaveConfig(e.cfg); err != nil {
		e.log(fmt.Sprintf("Вне VPN: не удалось сохранить список: %v", err))
	}
}

// runPostConnectAntiBlock проверяет IP после подключения и при необходимости переключается.
// Вызывается асинхронно из applySingBoxConfig если AntiBlockAutoSwitch=true.
func (e *Engine) runPostConnectAntiBlock(node *models.Node) {
	if !e.cfg.AntiBlockEnabled || !e.cfg.AntiBlockAutoSwitch {
		return
	}
	if node == nil || e.ipRepChecker == nil {
		return
	}

	// Даём узлу 2с встать
	if !e.sleepCtx(2 * time.Second) {
		return
	}
	// e.ctx — см. комментарий у runPostConnectHealthCheck.
	ctx, cancel := context.WithTimeout(e.currentCtx(), 8*time.Second)
	defer cancel()

	info, err := e.ipRepChecker.CheckIP(ctx, node.Address)
	if err != nil {
		e.log(fmt.Sprintf("Anti-Block: IP check failed for %s: %v", node.Address, err))
		return
	}

	e.log(fmt.Sprintf("Anti-Block: node %s IP=%s label=%s risk=%d streaming=%v",
		node.Name, info.IP, info.Label(), info.RiskScore, info.IsGoodForStreaming()))

	if info.IsGoodForStreaming() {
		return // всё ок
	}

	// IP плохой — ищем residential альтернативу
	e.log(fmt.Sprintf("⚠️ Anti-Block: datacenter IP обнаружен (%s), ищу residential узел...", info.Label()))

	if e.OnLeakDetected != nil {
		e.OnLeakDetected("anti_block",
			fmt.Sprintf("Текущий IP (%s) %s — Netflix/банки могут заблокировать. Переключаюсь...",
				info.IP, info.Label()))
	}

	e.mu.RLock()
	candidates := e.getActiveCandidates(0)
	e.mu.RUnlock()

	ctx2, cancel2 := context.WithTimeout(e.currentCtx(), 15*time.Second)
	defer cancel2()

	best := e.resSelector.BestForStreaming(ctx2, candidates)
	if best == nil || best.ID == node.ID {
		e.log("Anti-Block: нет residential альтернативы")
		return
	}

	e.log(fmt.Sprintf("Anti-Block: переключаюсь на %s", best.Name))
	// runPostConnectAntiBlock САМА уже отслеживается через e.wg (см. вызов в
	// applySingBoxConfig), но этот ВЛОЖЕННЫЙ go — нет: раньше wg.Wait() в Stop()
	// возвращался, как только тело runPostConnectAntiBlock заканчивалось (сразу после
	// запуска этой горутины), не дожидаясь самого connectNode. goTracked закрывает
	// именно эту вложенную утечку.
	e.goTracked(func() {
		if err := e.connectNode(best); err != nil {
			e.log(fmt.Sprintf("Anti-Block: switch failed: %v", err))
		}
	})
}
