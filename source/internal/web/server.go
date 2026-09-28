package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/engine"
	"github.com/apf/adaptive-pathfinder/internal/harvester"
	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/netguard"
	"github.com/apf/adaptive-pathfinder/internal/singbox"
	"github.com/apf/adaptive-pathfinder/internal/version"
)

// Injection hooks for testing hard-to-reach branches.
var (
	// httpServeFn wraps http.Serve so tests can prevent Start() from blocking.
	httpServeFn = func(ln net.Listener, handler http.Handler) error {
		return http.Serve(ln, handler)
	}
	// connectivityHTTPClientFn creates the HTTP client used by apiConnectivityCheck.
	connectivityHTTPClientFn = func() *http.Client {
		// netguard: под `go test` выход за пределы петли отвергается (Т-5).
		return netguard.Client(5 * time.Second)
	}
	// connectivityDNSLookupFn resolves hostnames in apiConnectivityCheck.
	connectivityDNSLookupFn = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return net.DefaultResolver.LookupIPAddr(ctx, host)
	}

	// engEnableIPv6BlockFn / engEnableWebRTCBlockFn / engAutoSelectSNIFn allow
	// error injection in tests without touching the engine package.
	engEnableIPv6BlockFn   = func(eng *engine.Engine, enabled bool) error { return eng.EnableIPv6Block(enabled) }
	engEnableWebRTCBlockFn = func(eng *engine.Engine, enabled bool) error { return eng.EnableWebRTCBlock(enabled) }
	engAutoSelectSNIFn     = func(eng *engine.Engine, ctx context.Context) (string, error) {
		return eng.AutoSelectShadowTLSSNI(ctx)
	}
	// catalogRefreshFn allows tests to inject a fake RefreshCatalog (e.g. one that blocks on
	// ctx.Done()) without touching the engine package — see П18, apiCatalogRefresh below.
	catalogRefreshFn = func(eng *engine.Engine, ctx context.Context) (int, error) {
		return eng.RefreshCatalog(ctx)
	}
)

type Server struct {
	eng  *engine.Engine
	port int
	// portMu защищает port: Start() выбирает фактический порт в своей горутине, а трей
	// читает его из другой, чтобы подписать пункт меню «Открыть Web UI».
	portMu sync.RWMutex
	mux    *http.ServeMux
	logs   []string
	logsMu sync.Mutex
	// ctx/cancel — П18 (аудит 2026-09-07): у Server раньше не было ни одного способа
	// сигнализировать собственным фоновым горутинам об остановке. apiCatalogRefresh запускал
	// голую `go func(){...}()` с context.Background() — такая горутина переживала конец
	// теста и (в проде) остановку сервера. engine.Engine прячет для этого случая приватный
	// goTracked (не экспортирован — расширять публичную поверхность engine не в периметре
	// этого лота, см. result.md open_questions), поэтому здесь минимальный локальный аналог:
	// ctx отменяется в Close(), wg даёт дождаться завершения фоновых задач.
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// ── S-2 (ТЗ v1.4, консилиум CONSILIUM_v1.4.md O-2): аутентификация локального API ──
	//
	// authToken — постоянный 32-байтовый токен, сгенерированный в New() и живущий весь
	// процесс. requireAuth() принимает его либо в "Authorization: Bearer <token>", либо
	// в cookie apf_ui — сравнение ПОСТОЯННОГО времени (isAuthorized), чтобы сам барьер не
	// стал новым каналом утечки токена. Пустая строка (генерация не удалась — истощение
	// crypto/rand) трактуется как fail-closed: доступ закрыт всем, а не открыт всем.
	authToken string

	// handoffKeys — S-2 п.4: одноразовые ключи для обмена на cookie apf_ui браузерным
	// клиентом (кнопка "Открыть Web UI" в трее/GUI). Только в памяти, TTL 10с,
	// инвалидируются при первом предъявлении независимо от исхода (см. consumeHandoffKey).
	handoffMu   sync.Mutex
	handoffKeys map[string]time.Time

	// secLogLast — S-13: не чаще одной записи в секунду НА ПРИЧИНУ отказа (origin/auth),
	// иначе шторм отказов вытесняет из 300-строчного s.logs (appendLog) всё остальное.
	secLogMu   sync.Mutex
	secLogLast map[string]time.Time

	// ── L5-WEB (ТЗ v1.4 §5): ручной харвест источников ──
	// engine.HarvestNow синхронный и может тянуться до бюджета (10 мин по умолчанию), поэтому веб
	// запускает его в фоновой горутине (trackedGo) и отдаёт прогресс/итог по опросу
	// /api/nodes/harvest-status — тот же паттерн, что у пробы узлов. harvestMu защищает поля ниже.
	// В отчёт наружу идут ТОЛЬКО счётчики (не сырые URL/содержимое) — анти-XSS и анти-утечка
	// секретов (те же соображения, что у harvester.SanitizeForLog и RejectedItem без сырья).
	harvestMu       sync.Mutex
	harvestRunning  bool
	harvestDone     bool
	harvestErr      string
	harvestProgress harvester.Progress
	harvestResult   *engine.HarvestResult
}

// Port — фактический порт, на котором сервер поднялся. До успешного Start() возвращает
// запрошенный при New(); Start() перебирает диапазон и может остановиться на другом.
func (s *Server) Port() int {
	s.portMu.RLock()
	defer s.portMu.RUnlock()
	return s.port
}

// trackedGo запускает fn в горутине, зарегистрированной в s.wg, и передаёт ей s.ctx —
// используется вместо голого `go func(){...}()` для фоновой работы, которая должна прекратиться
// вместе с сервером (П18). Close() отменяет s.ctx и дожидается s.wg.
func (s *Server) trackedGo(fn func(ctx context.Context)) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		fn(s.ctx)
	}()
}

// Close отменяет контекст фоновых задач сервера (см. trackedGo) и дожидается их завершения.
// У Server раньше не было метода остановки вообще; Start() не имеет graceful shutdown, и это
// не добавляется здесь — Close() только даёт зарегистрированным через trackedGo горутинам
// (сейчас — apiCatalogRefresh) шанс не пережить сервер. Вызывающий код (cmd/apf-tray,
// gui/app.go — вне владения этого лота) должен звать Close() при остановке сервера, чтобы
// эффект был виден в проде, а не только в тестах.
func (s *Server) Close() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
}

func New(eng *engine.Engine, port int) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{eng: eng, port: port, mux: http.NewServeMux(), ctx: ctx, cancel: cancel}
	// ТЗ v1.3 F5.1 (GAP-37): ОБОРАЧИВАЕМ OnLog владельца, а не перезаписываем — apf-svc/cmd/apf
	// ставят свой обработчик до web.New и раньше молча его теряли. Без прежнего обработчика —
	// консольный принтер, как и раньше (headless-режим).
	prevLog := eng.OnLog
	eng.OnLog = func(msg string) {
		if prevLog != nil {
			prevLog(msg)
		} else {
			log.Printf("[ENGINE] %s", msg)
		}
		s.logsMu.Lock()
		s.logs = append(s.logs, msg)
		if len(s.logs) > 300 {
			s.logs = s.logs[len(s.logs)-300:]
		}
		s.logsMu.Unlock()
	}
	// Фаза 5: уведомления об утечках пишем в лог с пометкой (прежний обработчик — сохраняем).
	prevLeak := eng.OnLeakDetected
	eng.OnLeakDetected = func(leakType string, details string) {
		msg := fmt.Sprintf("⚠️ LEAK [%s]: %s", leakType, details)
		log.Printf("[ENGINE] %s", msg)
		s.logsMu.Lock()
		s.logs = append(s.logs, msg)
		s.logsMu.Unlock()
		if prevLeak != nil {
			prevLeak(leakType, details)
		}
	}
	// S-2: токен генерируется здесь (не в Start()) — доступен как только Server существует,
	// и не-браузерный клиент (gui/webclient.go, после L1b-CLI) может прочитать файл сразу
	// после того, как engine.New()/web.New() вернули управление владельцу процесса.
	if tok, err := generateAuthToken(); err != nil {
		// Fail-closed (isAuthorized) — не fail-open: см. комментарий у поля authToken.
		log.Printf("[Web] не удалось сгенерировать токен аутентификации: %v", err)
	} else {
		s.authToken = tok
		if werr := writeAuthTokenFile(tok); werr != nil {
			log.Printf("[Web] не удалось опубликовать файл токена для наблюдателей: %v", werr)
		}
	}
	s.routes()
	return s
}

// ─── S-2 (ТЗ v1.4, O-2): токен постоянной аутентификации ─────────────────────────────
//
// Проблема (аудит B1 + консилиум O-2): web.Server слушает 127.0.0.1 без аутентификации —
// ЛЮБОЙ локальный процесс любой учётной записи (служба apf-svc.exe создаётся под
// LocalSystem, cmd/apf-svc/main.go) мог снять Kill Switch, прочитать приватный ключ Reality
// (S-3), стереть данные. guardCrossOrigin (ниже, S-18) закрывает межсайтовые запросы
// БРАУЗЕРА, но не защищает от произвольного локального процесса вовсе.
//
// Черновик предлагал печатать токен в теле HTML-страницы "/" — консилиум (O-2) это
// отклонил: страница "/" тогда отдавалась БЕЗ проверки происхождения на GET (см. S-18),
// то есть тот же самый локальный процесс получил бы токен запросом GET "/" — дыра
// осталась бы на месте. Решение FINAL: токен НИКОГДА не попадает в тело страницы;
// браузерный вход — через одноразовый handoff-ключ (см. apiUIHandoffKey/apiUIHandoff).

func generateAuthToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("web: генерация токена аутентификации: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// authTokenFilePath — %APPDATA%\APF\webui_token (config.DataDir(), НЕ SharedDataDir/
// %ProgramData%: в отличие от webui_port.txt (S-4, лот L1-KS), который обязан читать
// наблюдатель под ДРУГОЙ учётной записью, токен-файл не должен быть читаем произвольной
// другой учёткой на той же машине — см. restrictTokenFileACL).
func authTokenFilePath() string {
	return filepath.Join(config.DataDir(), "webui_token")
}

// writeAuthTokenFile — best-effort, как config.WritePortFile: ошибка записи не должна
// ронять уже поднятый сервер, только оставить не-браузерных клиентов (gui/webclient.go,
// после L1b-CLI) без способа аутентифицироваться — понятная ошибка "токен не найден по
// пути X" вместо аварийного выключателя (Н-17 — обходной механизм не вводится).
func writeAuthTokenFile(token string) error {
	path := authTokenFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("web: создание каталога токена: %w", err)
	}
	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		return fmt.Errorf("web: запись файла токена: %w", err)
	}
	restrictTokenFileACL(path)
	return nil
}

// aclRestricted — не повторять icacls для одного и того же пути на каждый New() (в
// тестах пакета web DataDir изолирован ОДИН раз на весь прогон — testmain_isolation_test.go,
// то есть путь токен-файла один и тот же для всех тестов; в проде Server создаётся один
// раз за жизнь процесса — но защититься от повторных вызовов дёшево и не вредит).
var aclRestricted sync.Map

// restrictTokenFileACL — os.WriteFile(…, 0600) на Windows НЕ ограничивает доступ (Windows
// не смотрит на POSIX-биты режима), поэтому явно снимаем наследование и оставляем только
// текущего пользователя через icacls (тот же инструмент, что уже упомянут как план для
// singbox-бинарника — internal/singbox/process.go:239). Не заводим отдельный
// internal/config-хелпер и не используем golang.org/x/sys/windows напрямую — оба варианта
// вне периметра владения этого лота (только internal/web/server.go) или ломают
// кросс-компиляцию на не-Windows (internal/killswitch/reset.go — прямое доказательство,
// что go test ./... для этого репозитория гоняется и на Linux). Best-effort и намеренно
// тихий: узкий ACL — защита в глубину поверх requireAuth (сам токен всё равно нужен),
// отказ icacls (например, файл на не-NTFS-разделе) не должен мешать работе сервера.
func restrictTokenFileACL(path string) {
	if runtime.GOOS != "windows" {
		return
	}
	if _, already := aclRestricted.LoadOrStore(path, struct{}{}); already {
		return
	}
	user := os.Getenv("USERNAME")
	if user == "" {
		return
	}
	if domain := os.Getenv("USERDOMAIN"); domain != "" {
		user = domain + "\\" + user
	}
	_ = exec.Command("icacls", path, "/inheritance:r", "/grant:r", user+":F").Run()
}

// portRange — сколько последовательных портов, начиная с настроенного, перебирает
// Start(), прежде чем сдаться. Расширен с 10 до 100 — живой инцидент 2026-08-25: на
// реальной машине пользователя, кроме APF, крутится произвольный набор чужого софта
// (Docker Desktop/WSL и т.п.), который тоже опортунистически занимает свободные
// локальные порты. Пользователь не будет и не должен разбираться, что закрыть, чтобы
// APF запустился — единственный воспроизводимый способ не зависеть от того, что ещё
// установлено на машине, это пережить занятость МНОГИХ портов подряд, а не только
// соседнего десятка.
const portRange = 100

func (s *Server) Start() error {
	base := s.Port()
	for port := base; port < base+portRange; port++ {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Printf("[Web] Port %d busy, trying next...", port)
			continue
		}
		// Живой инцидент 2026-09-03: base=0 (испорченный/неинициализированный
		// webui_port в config.json) — "127.0.0.1:0" для net.Listen ЗАКОННЫЙ адрес
		// ("любой свободный порт", ОС тут же успешно слушает), но это НЕ значит, что
		// реальный порт равен 0 — раньше здесь сохранялась голая переменная цикла
		// port (буквально 0), а не порт, на котором сокет РЕАЛЬНО поднялся. Сервер
		// продолжал честно работать (см. апстрим лог "Ready: http://localhost:0"),
		// но и лог, и webui_port.txt (см. WritePortFile ниже) публиковали 0 —
		// GUI/трей-наблюдатель читает именно этот файл, чтобы достучаться до
		// владельца, и на порт 0 достучаться нельзя. Внешне выглядело как «ни один
		// тумблер не переключается»: сам движок работал, только сообщал о себе не
		// туда. ln.Addr() — единственный источник истины после Listen, не входной
		// port.
		if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok {
			port = tcpAddr.Port
		}
		s.portMu.Lock()
		s.port = port
		s.portMu.Unlock()
		// Публикуем фактический порт для сторонних наблюдателей (gui/app.go,
		// cmd/apf-tray в режиме наблюдателя) — см. config.WritePortFile. Best-effort:
		// ошибка записи не должна ронять уже поднятый сервер, только оставить
		// наблюдателей без подсказки (откатятся на настроенный порт, как раньше).
		if werr := config.WritePortFile(port); werr != nil {
			log.Printf("[Web] не удалось опубликовать фактический порт для наблюдателей: %v", werr)
		}
		log.Printf("[Web] Ready: http://localhost:%d", port)
		// P0-2/S-2/S-13: барьер оборачивает ВЕСЬ mux, а не отдельные обработчики — новый
		// маршрут защищён автоматически, забыть его нельзя. Handler() — единая точка
		// сборки цепочки, см. её комментарий; тесты (server_v14_auth_test.go) проходят
		// через ту же функцию, чтобы не разойтись с боевым порядком проверок.
		return httpServeFn(ln, s.Handler())
	}
	return fmt.Errorf("web: no free port in range %d-%d", base, base+portRange)
}

// Handler — полная цепочка middleware, в которой в бою (Start()) обслуживается mux.
// Порядок ФИКСИРОВАН и проверен тестом (S-18: "сначала происхождение, потом
// аутентификация — оба отказа журналируются"):
//
//  1. logSecurityDenials (S-13) — снаружи всех: видит итоговый код ответа, чтобы
//     журналировать И отказ происхождения (403), И отказ аутентификации (401), откуда бы
//     он ни пришёл.
//  2. guardCrossOrigin (P0-2, S-18) — проверка происхождения для ЛЮБОГО метода, кроме
//     GET "/" и GET "/ui".
//  3. requireAuth (S-2) — Bearer-токен или cookie apf_ui для ЛЮБОГО метода на "/api/*"
//     (и на всём остальном, кроме тех же двух исключений).
//  4. s.mux — сами обработчики.
func (s *Server) Handler() http.Handler {
	return s.logSecurityDenials(guardCrossOrigin(s.requireAuth(s.mux)))
}

func (s *Server) routes() {
	// Существующие эндпоинты
	s.mux.HandleFunc("/api/state", s.apiState)
	s.mux.HandleFunc("/api/nodes", s.apiNodes)
	s.mux.HandleFunc("/api/stats", s.apiStats)
	s.mux.HandleFunc("/api/singbox", s.apiSingBox)
	s.mux.HandleFunc("/api/logs", s.apiLogs)
	s.mux.HandleFunc("/api/logs/export", s.apiLogsExport)
	s.mux.HandleFunc("/api/domain-check", s.apiDomainCheck)
	s.mux.HandleFunc("/api/config", s.apiConfig)
	s.mux.HandleFunc("/api/connect", s.apiConnect)
	s.mux.HandleFunc("/api/disconnect", s.apiDisconnect)
	s.mux.HandleFunc("/api/scan", s.apiScan)
	s.mux.HandleFunc("/api/rescan", s.apiRescan)
	s.mux.HandleFunc("/api/add-node", s.apiAddNode)
	s.mux.HandleFunc("/api/add-node-manual", s.apiAddNodeManual)
	s.mux.HandleFunc("/api/chain-partner/connect", s.apiConnectChainPartner)
	s.mux.HandleFunc("/api/connect-node", s.apiConnectNode)
	s.mux.HandleFunc("/api/connect-once", s.apiConnectOnce)
	s.mux.HandleFunc("/api/pin", s.apiPin)
	s.mux.HandleFunc("/api/pinned-node", s.apiPinnedNode)
	s.mux.HandleFunc("/api/favorite", s.apiFavorite)
	s.mux.HandleFunc("/api/favorites", s.apiFavorites)
	// W3 (ТЗ v1.5 §5, TZ_v1.5_NODE_CATALOG_2026-09-14, лот L2-WEB-B): гейт давности для
	// авто-вытеснения СИСТЕМНОГО избранного на следующей РУЧНОЙ сборке — не расписание
	// автоскана (его нет, owner-декрет консилиума). GET/POST на одном маршруте, см.
	// apiCatalogReviewInterval.
	s.mux.HandleFunc("/api/catalog-review-interval", s.apiCatalogReviewInterval)
	// ТЗ v1.3 F3: управление узлами
	s.mux.HandleFunc("/api/node/remove", s.apiNodeRemove)
	s.mux.HandleFunc("/api/node/ban", s.apiNodeBan)
	s.mux.HandleFunc("/api/node/update", s.apiNodeUpdate)
	s.mux.HandleFunc("/api/node/reset", s.apiNodeReset)
	s.mux.HandleFunc("/api/nodes/restore-removed", s.apiNodesRestoreRemoved)
	// ТЗ v1.3 F4 Stage 1: обход пула с прогрессом
	s.mux.HandleFunc("/api/scan/progress", s.apiScanProgress)
	s.mux.HandleFunc("/api/scan/start", s.apiScanStart)
	s.mux.HandleFunc("/api/scan/cancel", s.apiScanCancel)
	// ТЗ v1.5 N-1/N-3 (L2-WEB): «Собрать список рабочих узлов» — проба РЕАЛЬНОГО трафика (не
	// TCP) через SOCKS-only инстанс на узел. Имена по C13/O13: НЕ "catalog" — префикс занят
	// провайдерами подписок (/api/catalog/*, см. ниже).
	s.mux.HandleFunc("/api/nodes/check-all", s.apiNodeCheckStart)
	s.mux.HandleFunc("/api/nodes/check-cancel", s.apiNodeCheckCancel)
	s.mux.HandleFunc("/api/nodes/check-status", s.apiNodeCheckStatus)
	// L5-WEB (ТЗ v1.4 §5): ручной харвест узлов из настроенных источников.
	s.mux.HandleFunc("/api/nodes/harvest", s.apiHarvestStart)
	s.mux.HandleFunc("/api/nodes/harvest-status", s.apiHarvestStatus)
	// Извлечение узлов из вставленного пользователем текста (много ссылок/дамп/подписка): тот же
	// детерминированный харвестер, но тело приносит сам пользователь, а не источник.
	s.mux.HandleFunc("/api/nodes/harvest-text", s.apiHarvestTextStart)
	s.mux.HandleFunc("/api/reset-network", s.apiResetNetwork)
	s.mux.HandleFunc("/api/connectivity-check", s.apiConnectivityCheck)
	s.mux.HandleFunc("/api/save-config", s.apiSaveConfig)
	s.mux.HandleFunc("/api/diagnostics", s.apiDiagnostics)

	// P2.3 (docs/TZ_APF_ROADMAP_v1.2.md): точка входа роли «Выход»/«Транзит» на Windows —
	// internal/engine/server_role.go был готов и протестирован, не хватало HTTP-роутов
	// (паритет с mobile/androidbridge/server_role.go на Android).
	s.mux.HandleFunc("/api/server-role/status", s.apiServerRoleStatus)
	s.mux.HandleFunc("/api/server-role/identity", s.apiServerRoleIdentity)
	// S-3 (ТЗ v1.4): приватный ключ Reality — только явным POST с подтверждением, под
	// токеном, с записью в журнал (см. apiServerRoleIdentityExport). GET identity выше
	// больше не отдаёт приватный ключ вообще.
	s.mux.HandleFunc("/api/server-role/identity/export", s.apiServerRoleIdentityExport)
	s.mux.HandleFunc("/api/server-role/generate-identity", s.apiServerRoleGenerateIdentity)
	s.mux.HandleFunc("/api/server-role/build-link", s.apiServerRoleBuildLink)
	s.mux.HandleFunc("/api/server-role/start", s.apiServerRoleStart)
	s.mux.HandleFunc("/api/server-role/stop", s.apiServerRoleStop)

	// P2.1 (docs/TZ_APF_ROADMAP_v1.2.md): каталог платных провайдеров (3x-ui/Marzban/
	// Hiddify/generic) — Engine.AddPaidProvider/RemovePaidProvider/TestPaidProvider были
	// готовы и протестированы, не хватало HTTP-роутов. Список существующих провайдеров —
	// через уже существующий /api/config (models.AppConfig.PaidProviders), отдельный GET
	// не нужен.
	s.mux.HandleFunc("/api/paid-providers/add", s.apiPaidProviderAdd)
	s.mux.HandleFunc("/api/paid-providers/remove", s.apiPaidProviderRemove)
	s.mux.HandleFunc("/api/paid-providers/test", s.apiPaidProviderTest)

	// ── Фаза 5: Защита устройства ──────────────────────────────────────
	s.mux.HandleFunc("/api/leakguard/status", s.apiLeakGuardStatus)
	s.mux.HandleFunc("/api/leakguard/dns-test", s.apiDNSLeakTest)
	s.mux.HandleFunc("/api/leakguard/ipv6", s.apiIPv6Block)
	s.mux.HandleFunc("/api/leakguard/webrtc", s.apiWebRTCBlock)
	s.mux.HandleFunc("/api/leakguard/browser-instructions", s.apiBrowserInstructions)
	s.mux.HandleFunc("/api/crypto/set-password", s.apiSetPassword)
	s.mux.HandleFunc("/api/emergency/wipe", s.apiEmergencyWipe)

	s.mux.HandleFunc("/api/dpi/status", s.apiDPIStatus)
	s.mux.HandleFunc("/api/dpi/canary-test", s.apiCanaryTest)
	s.mux.HandleFunc("/api/dpi/padding", s.apiTrafficPadding)
	s.mux.HandleFunc("/api/dpi/cdn", s.apiCDNFronting)
	s.mux.HandleFunc("/api/dpi/cdn-worker-script", s.apiCDNWorkerScript)
	s.mux.HandleFunc("/api/dpi/shadowtls", s.apiShadowTLS)
	s.mux.HandleFunc("/api/dpi/shadowtls-auto-sni", s.apiShadowTLSAutoSNI)

	s.mux.HandleFunc("/api/session/status", s.apiSessionStatus)
	s.mux.HandleFunc("/api/session/policy", s.apiSessionPolicy)
	s.mux.HandleFunc("/api/session/force-switch", s.apiForceSwitch)

	// Фаза 7: аварийные туннели + watchdog
	s.mux.HandleFunc("/api/fallback/status", s.apiFallbackStatus)
	s.mux.HandleFunc("/api/fallback/activate", s.apiFallbackActivate)
	s.mux.HandleFunc("/api/fallback/auto-select", s.apiFallbackAutoSelect)
	s.mux.HandleFunc("/api/watchdog/status", s.apiWatchdogStatus)
	s.mux.HandleFunc("/api/watchdog/history", s.apiWatchdogHistory)

	// Sprint S2: Catalog
	s.mux.HandleFunc("/api/catalog/status", s.apiCatalogStatus)
	s.mux.HandleFunc("/api/catalog/refresh", s.apiCatalogRefresh)
	s.mux.HandleFunc("/api/catalog/provider", s.apiCatalogProvider)

	// Sprint S4: AdBlock
	s.mux.HandleFunc("/api/adblock/status", s.apiAdBlockStatus)
	s.mux.HandleFunc("/api/adblock/profile", s.apiAdBlockProfile)
	s.mux.HandleFunc("/api/adblock/allowlist", s.apiAdBlockAllowlist)

	// Sprint S6: Anti-VPN-Block
	s.mux.HandleFunc("/api/antiblock/status", s.apiAntiBlockStatus)
	s.mux.HandleFunc("/api/antiblock/check-ip", s.apiAntiBlockCheckIP)
	s.mux.HandleFunc("/api/antiblock/check-node", s.apiAntiBlockCheckNode)
	s.mux.HandleFunc("/api/antiblock/config", s.apiAntiBlockConfig)
	s.mux.HandleFunc("/api/antiblock/bypass-list", s.apiAntiBlockBypassList)
	s.mux.HandleFunc("/api/antiblock/bypass-domain", s.apiAntiBlockBypassDomain)

	// S-2 (ТЗ v1.4): браузерный вход по одноразовому handoff-ключу — см. Handler()/
	// requireAuth и комментарий у apiUIHandoff. Оба пути — публичные точки входа
	// (isPublicEntryPoint), исключённые и из guardCrossOrigin (S-18), и из requireAuth.
	s.mux.HandleFunc("/api/ui/handoff", s.apiUIHandoffKey)
	s.mux.HandleFunc("/ui", s.apiUIHandoff)

	s.mux.HandleFunc("/", s.apiUI)
}

// ── Существующие хэндлеры ─────────────────────────────────────────────────────

func (s *Server) apiState(w http.ResponseWriter, r *http.Request) {
	cors(w)
	json.NewEncoder(w).Encode(s.eng.GetState())
}

func (s *Server) apiStats(w http.ResponseWriter, r *http.Request) {
	cors(w)
	json.NewEncoder(w).Encode(s.eng.GetStats())
}

// apiPinnedNode — GET: id закреплённого узла (""  — не закреплён), без побочных эффектов.
// §4.4 ТЗ v2.0 (docs/TZ_APF_QA_AND_BACKLOG_v2.0.md): до этой правки единственный способ узнать
// PinnedNodeID через HTTP был apiPin (POST /api/pin) — сам мутирующий вызов, непригодный для
// observer-режима desktop GUI (webClient), которому нужно просто ОТОБРАЗИТЬ текущее
// закрепление в таблице узлов, не меняя его.
func (s *Server) apiPinnedNode(w http.ResponseWriter, r *http.Request) {
	cors(w)
	st := s.eng.GetState()
	json.NewEncoder(w).Encode(map[string]string{
		"pinned_node_id": st.PinnedNodeID,
		"pinned_status":  st.PinnedStatus, // ТЗ v1.3 F2 I3
	})
}

func (s *Server) apiSingBox(w http.ResponseWriter, r *http.Request) {
	cors(w)
	json.NewEncoder(w).Encode(s.eng.GetSingBoxInfo())
}

func (s *Server) apiConfig(w http.ResponseWriter, r *http.Request) {
	cors(w)
	json.NewEncoder(w).Encode(s.eng.GetConfig())
}

func (s *Server) apiLogs(w http.ResponseWriter, r *http.Request) {
	cors(w)
	s.logsMu.Lock()
	logs := make([]string, len(s.logs))
	copy(logs, s.logs)
	s.logsMu.Unlock()
	json.NewEncoder(w).Encode(logs)
}

// apiLogsExport — GET /api/logs/export: полный лог-файл как вложение (ТЗ v1.3 F5.1). Если файл
// не ведётся (Android/ошибка открытия) — отдаём буфер последних строк.
func (s *Server) apiLogsExport(w http.ResponseWriter, r *http.Request) {
	cors(w)
	name := "apf-log-" + time.Now().Format("2006-01-02_15-04") + ".txt"
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	if path := s.eng.LogFilePath(); path != "" {
		s.eng.FlushLog()
		if f, err := os.Open(path); err == nil {
			defer f.Close()
			io.Copy(w, f)
			return
		}
	}
	s.logsMu.Lock()
	logs := make([]string, len(s.logs))
	copy(logs, s.logs)
	s.logsMu.Unlock()
	for _, l := range logs {
		io.WriteString(w, l+"\n")
	}
}

// apiDomainCheck — GET /api/domain-check?q=подстрока
//
// Отвечает на вопрос «сайт всё ещё видит VPN, хотя я включил обход — что реально идёт
// через туннель?» без ручного чтения лога. Живой инцидент 2026-08-25: правило Госуслуг
// сработало для gosuslugi.ru, но сайт продолжал детектить VPN — причина оказалась в
// непокрытом поддомене gu-st.ru, найденном только ручным чтением лога. Эта ручная работа
// теперь делает checkDomainRouting() (см. её комментарий про метод корреляции).
//
// q пустой — вернуть все домены, что видел роутер за время буфера логов (последние 300
// строк, тот же буфер, что и apiLogs). Непустой q — только домены, содержащие подстроку
// (без учёта регистра) — так пользователь ищет по имени интересующего его сайта.
func (s *Server) apiDomainCheck(w http.ResponseWriter, r *http.Request) {
	cors(w)
	q := r.URL.Query().Get("q")
	s.logsMu.Lock()
	logs := make([]string, len(s.logs))
	copy(logs, s.logs)
	s.logsMu.Unlock()
	json.NewEncoder(w).Encode(CheckDomainRouting(logs, q))
}

// nodeWithBadge — узел плюс значок проверенности трафиком, отдаваемый /api/nodes вместе с
// остальными полями узла. VerifyBadge (models.Node.VerifyBadge) — МЕТОД, сам по себе в JSON
// не попадает; вычисляем его здесь один раз и добавляем полем verify_badge. Источник истины
// один — этот метод, JS его логику не повторяет (общий контракт трёх UI: Web/Wails/Android
// обязаны показывать один и тот же значок для одного и того же узла, см. models/node.go).
type nodeWithBadge struct {
	*models.Node
	Badge string `json:"verify_badge"`
	// C-21-ui (ТЗ v1.4): метка каталога (из имени узла) против фактического выхода
	// (LastVerifiedCountry, заполняет L1b-ENG2 после успешной проверки). Методы уже существуют
	// на *models.Node (CatalogCountry/ExitCountry/CountryMismatch, node.go) — сами по себе в
	// JSON не попадают (методы, не поля), UI-лот только вызывает их и добавляет вычисленный
	// результат, как уже сделано для Badge выше. Если LastVerifiedCountry ещё не заполнен
	// (L1b-ENG2 не успел/сам движок ещё не проверял узел) — ExitCountry пустой, JS не рисует
	// вторую метку (условно, см. renderNodes).
	CatalogCountry  string `json:"catalog_country,omitempty"`
	ExitCountry     string `json:"exit_country,omitempty"`
	CountryMismatch bool   `json:"country_mismatch,omitempty"`
}

// attachVerifyBadges — оборачивает срез узлов вычисленным значком и меткой страны (C-21-ui).
// Вынесено отдельной функцией (не инлайн в apiNodes), чтобы её можно было прогнать юнит-тестом
// на всех шести состояниях значка без обращения к движку: AddNodeManual/AddNodeFromLink
// запускают фоновую TCP-проверку узла, которая гоняется за полями, выставленными тестом до
// вставки, и делает результат недетерминированным (см. server_verify_badge_test.go).
func attachVerifyBadges(nodes []*models.Node, nowUnix int64) []nodeWithBadge {
	out := make([]nodeWithBadge, len(nodes))
	for i, n := range nodes {
		out[i] = nodeWithBadge{
			Node:            n,
			Badge:           n.VerifyBadge(nowUnix),
			CatalogCountry:  n.CatalogCountry(),
			ExitCountry:     n.ExitCountry(),
			CountryMismatch: n.CountryMismatch(),
		}
	}
	return out
}

func (s *Server) apiNodes(w http.ResponseWriter, r *http.Request) {
	cors(w)
	// P1.1 (docs/TZ_WINDOWS_CONSILIUM_FINDINGS_v1.0.md): раньше s.eng.GetNodes() звался ДВАЖДЫ
	// (для nodes и отдельно для total) — лишний O(n) RLock+копирование всего пула, и
	// потенциальный рассинхрон между total и len(nodes), если updateSources() дописал узлы
	// между двумя вызовами. Один снимок на весь ответ.
	// ТЗ v1.3 F3: представления all|proven|manual|banned|favorites|removed.
	view := r.URL.Query().Get("view")
	if view == engine.NodeViewRemoved {
		ids := s.eng.RemovedNodeIDs()
		if ids == nil {
			ids = []string{}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"nodes": []*models.Node{}, "removed_ids": ids, "total": len(ids)})
		return
	}
	nodes := s.eng.GetNodesView(view)
	total := len(nodes)
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	// Порядок перед срезом — как в androidbridge.GetNodesJSON и по той же причине
	// (найдено 2026-08-24): AddNodeFromLink дописывает узел в КОНЕЦ пула, а срез брал первые
	// N в порядке пула, поэтому вручную добавленный узел не попадал в ответ при пуле в
	// тысячи записей. Закреплённый → проверенные трафиком → ручные → остальные по убыванию Score.
	//
	// ТЗ v1.7 (живой прогон 09-15): проверенные трафиком (IsProven) добавлены в приоритет ДО
	// среза. Раньше срез брал топ-200 ЧИСТО по Score, а в пуле в тысячи узлов сотни имеют Score
	// выше, чем у реально проверенных (0.97+ у непроверенных vs 0.88-0.98 у проверенных) — и
	// проверенные вылетали за 200-й предел, не доходя до клиента. Из-за этого фильтр
	// «Проверенные» на клиенте показывал 1 из 6 (баг «нашло 6, в списке 1»). Проверенных мало,
	// они гарантированно влезают в лимит; так весь список проверенных всегда доходит до UI.
	pinnedID := s.eng.PinnedNodeID()
	rank := func(n *models.Node) int {
		switch {
		case pinnedID != "" && n.ID == pinnedID:
			return 0
		case n.IsProven():
			return 1
		case n.Source == "manual":
			return 2
		default:
			return 3
		}
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		ri, rj := rank(nodes[i]), rank(nodes[j])
		if ri != rj {
			return ri < rj
		}
		return nodes[i].Score > nodes[j].Score
	})
	if len(nodes) > limit {
		nodes = nodes[:limit]
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"nodes": attachVerifyBadges(nodes, time.Now().Unix()),
		"total": total,
	})
}

func (s *Server) apiConnect(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	go s.eng.ScanAndConnect()
	json.NewEncoder(w).Encode(map[string]string{"status": "connecting"})
}

func (s *Server) apiDisconnect(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	go s.eng.Stop()
	json.NewEncoder(w).Encode(map[string]string{"status": "disconnected"})
}

// apiScan — POST /api/scan: кнопка «⟳ Сканировать» на Dashboard.
//
// 2026-09-22: раньше здесь стоял go s.eng.ScanAndConnect() — строка в строку совпадавший с
// apiConnect() (/api/connect, кнопка «Подключить») и отличавшийся только текстом статуса в
// ответе. Найдено живым прогоном на ПК владельца: он работал только со сканом/сбором рабочих
// узлов, а APF без явной команды поднял настоящий туннель и включил Kill Switch — причина
// была именно в этой кнопке. Название уже обещало безопасное действие («Сканировать» ≠
// «Подключить», см. комментарий у apiScanStart, F6) — теперь оно им и является: тот же
// безопасный TCP-обход пула, что и apiScanStart, активное подключение не трогает.
func (s *Server) apiScan(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	if err := s.eng.StartSweep("manual"); err != nil {
		w.WriteHeader(409)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "scanning"})
}

func (s *Server) apiRescan(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	go s.eng.ForceRescan()
	json.NewEncoder(w).Encode(map[string]string{"status": "rescan_started"})
}

func (s *Server) apiAddNode(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var body struct {
		Link string `json:"link"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if err := s.eng.AddNodeFromLink(body.Link); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "added"})
}

// apiConnectChainPartner — POST {link}: роль «Вход» (§4, docs/PLAN_2026-08-28_
// stubs_and_realfunc.md) — вставить ссылку от партнёра в роли «Выход» и сразу подключиться,
// пометив узел IsChainPartner (не конкурирует с публичным пулом при автовыборе/сбое).
func (s *Server) apiConnectChainPartner(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var body struct {
		Link string `json:"link"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	node, err := s.eng.AddChainPartnerFromLink(body.Link)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "connected", "node": node})
}

// apiAddNodeManual — POST {models.Node JSON}: добавить узел из редактора продвинутых полей (B-29).
// Бэкенд (engine.AddNodeManual + models.ValidateNode) был готов, но не имел боевого вызывателя —
// этот endpoint закрывает разрыв (HTTP-обвязка). UI-форма редактора остаётся за фронтендом.
func (s *Server) apiAddNodeManual(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var node models.Node
	if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if err := s.eng.AddNodeManual(&node); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "added", "node_id": node.ID})
}

// apiConnectNode — POST {node_id}: подключиться к конкретному узлу и закрепить его (FR-4, B-08.5).
func (s *Server) apiConnectNode(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var body struct {
		NodeID string `json:"node_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if err := s.eng.ConnectByID(body.NodeID); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "connecting", "pinned_node_id": body.NodeID})
}

// apiPin — POST {node_id,pinned}: закрепить/снять закрепление узла (FR-4, B-08.5).
func (s *Server) apiPin(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var body struct {
		NodeID string `json:"node_id"`
		Pinned bool   `json:"pinned"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if body.Pinned {
		// ТЗ v1.3 F2: с валидацией — неизвестный ID не закрепляется молча.
		if err := s.eng.Pin(body.NodeID); err != nil {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
	} else {
		s.eng.UnpinNode()
	}
	json.NewEncoder(w).Encode(map[string]string{"pinned_node_id": s.eng.PinnedNodeID()})
}

// apiConnectOnce — POST {node_id}: подключиться к узлу, НЕ меняя закрепление (ТЗ v1.3 F2 PIN-8).
func (s *Server) apiConnectOnce(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var body struct {
		NodeID string `json:"node_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if err := s.eng.ConnectOnce(body.NodeID); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "connecting", "node_id": body.NodeID})
}

// apiFavorite — POST {node_id,favorite}: добавить/убрать узел из избранного (ТЗ v1.3 F2).
func (s *Server) apiFavorite(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var body struct {
		NodeID   string `json:"node_id"`
		Favorite bool   `json:"favorite"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	var err error
	if body.Favorite {
		err = s.eng.AddFavorite(body.NodeID)
	} else {
		err = s.eng.RemoveFavorite(body.NodeID)
	}
	if err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"favorite_ids": s.eng.FavoriteIDs()})
}

// nodeActionBody — общее тело POST-действий над узлом (ТЗ v1.3 F3).
type nodeActionBody struct {
	NodeID   string  `json:"node_id"`
	Banned   bool    `json:"banned"`
	Name     *string `json:"name"`
	UserNote *string `json:"user_note"`
}

func (s *Server) nodeAction(w http.ResponseWriter, r *http.Request, do func(nodeActionBody) error) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var body nodeActionBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if err := do(body); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "node_id": body.NodeID})
}

// apiNodeRemove — POST {node_id}: удалить узел с надгробием.
func (s *Server) apiNodeRemove(w http.ResponseWriter, r *http.Request) {
	s.nodeAction(w, r, func(b nodeActionBody) error { return s.eng.RemoveNode(b.NodeID) })
}

// apiNodeBan — POST {node_id,banned}: ручной чёрный список.
func (s *Server) apiNodeBan(w http.ResponseWriter, r *http.Request) {
	s.nodeAction(w, r, func(b nodeActionBody) error { return s.eng.BanNode(b.NodeID, b.Banned) })
}

// apiNodeUpdate — POST {node_id,name?,user_note?}: имя/заметка.
func (s *Server) apiNodeUpdate(w http.ResponseWriter, r *http.Request) {
	s.nodeAction(w, r, func(b nodeActionBody) error {
		return s.eng.UpdateNode(b.NodeID, models.NodePatch{Name: b.Name, UserNote: b.UserNote})
	})
}

// apiNodeReset — POST {node_id}: сброс статистики узла.
func (s *Server) apiNodeReset(w http.ResponseWriter, r *http.Request) {
	s.nodeAction(w, r, func(b nodeActionBody) error { return s.eng.ResetNodeStats(b.NodeID) })
}

// apiScanProgress — GET: прогресс обхода пула (ТЗ v1.3 F4 Stage 1).
func (s *Server) apiScanProgress(w http.ResponseWriter, r *http.Request) {
	cors(w)
	json.NewEncoder(w).Encode(s.eng.GetScanProgress())
}

// apiScanStart — POST: запустить обход пула («Сканировать» ≠ «Подключить», F6).
func (s *Server) apiScanStart(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	if err := s.eng.StartSweep("manual"); err != nil {
		w.WriteHeader(409)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

// apiScanCancel — POST: прервать обход.
func (s *Server) apiScanCancel(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	s.eng.CancelSweep()
	json.NewEncoder(w).Encode(map[string]string{"status": "cancelling"})
}

// apiNodeCheckStatus — GET: прогресс пробы РЕАЛЬНОГО трафика (ТЗ v1.5 §3 N-1/N-3, N-9). Отдаёт
// engine.NodeCheckStatusSnapshot как есть (running/phase/total/probed/verified/failed/target_k/
// started_at) — счётчики уже коалесцированы движком (checkMu, ~300мс), UI только отображает.
func (s *Server) apiNodeCheckStatus(w http.ResponseWriter, r *http.Request) {
	cors(w)
	json.NewEncoder(w).Encode(s.eng.NodeCheckStatus())
}

// apiNodeCheckStart — POST: запустить «Собрать список рабочих узлов» (ТЗ v1.5 N-3). В отличие от
// apiScanStart/apiScanCancel (TCP-обход, Stage 1), эта проба поднимает для каждого узла лёгкий
// SOCKS-only инстанс (БЕЗ TUN) и делает реальный HTTP GET наружу — см. node_check.go. N-9: успех
// пишется как VerifiedViaSOCKS ("выход в интернет проверен"/"канал проверен"), НИКОГДА как
// TUN-подтверждение — слово «через туннель» для этой пробы запрещено (см. рендер ниже в apiUI).
func (s *Server) apiNodeCheckStart(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	if err := s.eng.StartNodeCheck(engine.NodeCheckOptions{}); err != nil {
		w.WriteHeader(409)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

// apiNodeCheckCancel — POST: отменить текущую пробу трафика. Идемпотентна (CancelNodeCheck —
// no-op, если проба не идёт), как apiScanCancel.
func (s *Server) apiNodeCheckCancel(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	s.eng.CancelNodeCheck()
	json.NewEncoder(w).Encode(map[string]string{"status": "cancelling"})
}

// apiHarvestStart — POST /api/nodes/harvest: ручной проход харвестера (L5-WEB, ТЗ v1.4 §5).
// engine.HarvestNow синхронный и может быть долгим (до бюджета), поэтому запускаем его в фоновой
// горутине сервера (trackedGo — переживёт HTTP-запрос, но не переживёт сервер) и сразу отвечаем;
// прогресс/итог — по опросу /api/nodes/harvest-status. Повторный запуск при идущем проходе — 409
// (единственный источник истины «идёт» — серверный harvestRunning; движок дополнительно защищён
// своим single-flight ErrHarvestBusy).
func (s *Server) apiHarvestStart(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	s.harvestMu.Lock()
	if s.harvestRunning {
		s.harvestMu.Unlock()
		w.WriteHeader(409)
		json.NewEncoder(w).Encode(map[string]string{"error": "харвест уже идёт"})
		return
	}
	s.harvestRunning = true
	s.harvestDone = false
	s.harvestErr = ""
	s.harvestResult = nil
	s.harvestProgress = harvester.Progress{}
	s.harvestMu.Unlock()

	// Прогресс движка → серверный снимок (только для отображения).
	s.eng.OnHarvestProgress = func(p harvester.Progress) {
		s.harvestMu.Lock()
		s.harvestProgress = p
		s.harvestMu.Unlock()
	}

	s.trackedGo(func(ctx context.Context) {
		res, err := s.eng.HarvestNow(ctx)
		s.harvestMu.Lock()
		s.harvestRunning = false
		s.harvestDone = true
		if err != nil {
			s.harvestErr = err.Error()
		} else {
			s.harvestResult = res
		}
		s.harvestMu.Unlock()
	})
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

// apiHarvestStatus — GET /api/nodes/harvest-status: прогресс/итог последнего харвеста. Наружу идут
// ТОЛЬКО счётчики и контролируемые строки (Stopped ∈ {"",timeout,canceled,budget}) — сырые ссылки/
// содержимое источников НЕ передаются (анти-XSS и анти-утечка секретов: субкрипшн-URL могут нести
// токены, поэтому отдаём лишь их ЧИСЛО, а не сами адреса).
func (s *Server) apiHarvestStatus(w http.ResponseWriter, r *http.Request) {
	cors(w)
	s.harvestMu.Lock()
	defer s.harvestMu.Unlock()
	resp := map[string]interface{}{
		"running": s.harvestRunning,
		"done":    s.harvestDone,
		"progress": map[string]interface{}{
			"source_index": s.harvestProgress.SourceIndex,
			"source_total": s.harvestProgress.SourceTotal,
			"found":        s.harvestProgress.Found,
			"phase":        s.harvestProgress.Phase,
		},
	}
	if s.harvestErr != "" {
		resp["error"] = s.harvestErr
	}
	if s.harvestResult != nil {
		resp["result"] = map[string]interface{}{
			"found":             s.harvestResult.Report.Found,
			"parsed":            s.harvestResult.Parsed,
			"merged":            s.harvestResult.Merged,
			"parse_failed":      s.harvestResult.ParseFailed,
			"subscription_urls": s.harvestResult.SubscriptionURLs,
			"not_substring":     s.harvestResult.Report.NotSubstring,
			"sources_processed": s.harvestResult.Report.SourcesProcessed,
			"sources_total":     s.harvestResult.Report.SourcesTotal,
			"stopped":           s.harvestResult.Report.Stopped,
		}
	}
	json.NewEncoder(w).Encode(resp)
}

// apiHarvestTextStart — POST /api/nodes/harvest-text {text}: детерминированный разбор вставленного
// пользователем текста (несколько ссылок/дамп/подписка) тем же харвестером, что и /api/nodes/harvest,
// но БЕЗ обращения к источникам — тело приносит сам пользователь (I-1 соблюдён тривиально). Прогресс/
// итог общие с обычным харвестом (/api/nodes/harvest-status, поля harvestRunning/harvestResult): оба
// пути защищены одним серверным single-flight (409, если проход уже идёт) поверх engine.harvestActive.
func (s *Server) apiHarvestTextStart(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	// Текст вставляет пользователь — он может быть большим (подписка), но не безграничным
	// (defense-in-depth: харвестер и так режет тело бюджетом, но HTTP-тело ограничиваем раньше).
	r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
	var body struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if strings.TrimSpace(body.Text) == "" {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "пустой ввод"})
		return
	}

	s.harvestMu.Lock()
	if s.harvestRunning {
		s.harvestMu.Unlock()
		w.WriteHeader(409)
		json.NewEncoder(w).Encode(map[string]string{"error": "харвест уже идёт"})
		return
	}
	s.harvestRunning = true
	s.harvestDone = false
	s.harvestErr = ""
	s.harvestResult = nil
	s.harvestProgress = harvester.Progress{}
	s.harvestMu.Unlock()

	s.eng.OnHarvestProgress = func(p harvester.Progress) {
		s.harvestMu.Lock()
		s.harvestProgress = p
		s.harvestMu.Unlock()
	}

	text := body.Text
	s.trackedGo(func(ctx context.Context) {
		res, err := s.eng.HarvestFromText(ctx, text)
		s.harvestMu.Lock()
		s.harvestRunning = false
		s.harvestDone = true
		if err != nil {
			s.harvestErr = err.Error()
		} else {
			s.harvestResult = res
		}
		s.harvestMu.Unlock()
	})
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

// apiNodesRestoreRemoved — POST: снять все надгробия.
func (s *Server) apiNodesRestoreRemoved(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"restored": s.eng.RestoreRemovedNodes()})
}

// apiFavorites — GET: ID избранных узлов в порядке добавления. W3 (ТЗ v1.5 §2, лот L2-WEB-B):
// вдобавок к favorite_ids (объединение обоих классов — как и раньше, обратная совместимость с
// уже читающими его клиентами) отдаём разбивку по классу — user_favorite_ids (звезда
// пользователя, eng.UserFavoriteIDs) и system_favorite_ids (сборка каталога по пробе трафика,
// eng.SystemFavoriteIDs) — UI использует её, чтобы показать разные бейджи и разное поведение
// звезды (см. renderNodes/doFavoriteNode в webUI).
func (s *Server) apiFavorites(w http.ResponseWriter, r *http.Request) {
	cors(w)
	ids := s.eng.FavoriteIDs()
	if ids == nil {
		ids = []string{}
	}
	userIDs := s.eng.UserFavoriteIDs()
	if userIDs == nil {
		userIDs = []string{}
	}
	systemIDs := s.eng.SystemFavoriteIDs()
	if systemIDs == nil {
		systemIDs = []string{}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"favorite_ids":        ids,
		"user_favorite_ids":   userIDs,
		"system_favorite_ids": systemIDs,
	})
}

// apiCatalogReviewInterval — GET/POST W3 (ТЗ v1.5 §5, TZ_v1.5_NODE_CATALOG_2026-09-14, лот
// L2-WEB-B). GET отдаёт текущее значение (eng.CatalogReviewInterval() сам откатывается на
// "each_scan" при пустом/незнакомом config.json — см. её комментарий в internal/engine/engine.go,
// эта ручка ничего не решает повторно). POST {value} валидирует и сохраняет через
// eng.SetCatalogReviewInterval — неизвестное значение здесь ОШИБКА (в отличие от чтения):
// явный пользовательский ввод должен получить внятный отказ, а не тихую подмену дефолтом.
//
// Честная формулировка (C-20/N-9): это НЕ расписание автосканирования — сборка каталога
// («Собрать список рабочих узлов») всегда только по кнопке пользователя, автоскана нет
// (owner-декрет консилиума TZ_v1.5_NODE_CATALOG_2026-09-14). Интервал — только гейт давности:
// после какого срока с последнего подтверждения трафиком проваленная проба вправе снять узел
// из СИСТЕМНОГО избранного на следующей ручной сборке.
func (s *Server) apiCatalogReviewInterval(w http.ResponseWriter, r *http.Request) {
	cors(w)
	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(map[string]string{"interval": s.eng.CatalogReviewInterval()})
	case http.MethodPost:
		var body struct {
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		if err := s.eng.SetCatalogReviewInterval(body.Value); err != nil {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "ok",
			"interval": s.eng.CatalogReviewInterval(),
		})
	default:
		http.Error(w, "GET or POST", 405)
	}
}

func (s *Server) apiResetNetwork(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	res := s.eng.ResetNetworkDetailed()
	status := http.StatusOK
	if !res.Success {
		status = http.StatusInternalServerError
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      map[bool]string{true: "reset_completed", false: "reset_failed"}[res.Success],
		"message":     "Firewall and DNS restored to baseline",
		"success":     res.Success,
		"duration_ms": res.DurationMs,
		"warnings":    res.Warnings,
		"error":       res.Error,
	})
}

// apiConnectivityCheck — POST /api/connectivity-check
// Быстрый тест доступности внешних ресурсов после recovery/reset.
func (s *Server) apiConnectivityCheck(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}

	type checkResult struct {
		URL    string `json:"url"`
		OK     bool   `json:"ok"`
		Status int    `json:"status"`
		Error  string `json:"error,omitempty"`
	}

	type dnsResult struct {
		Host  string   `json:"host"`
		OK    bool     `json:"ok"`
		IPs   []string `json:"ips,omitempty"`
		Error string   `json:"error,omitempty"`
	}

	targets := []string{
		"https://1.1.1.1/cdn-cgi/trace",
		"https://example.com",
		"https://www.wikipedia.org",
	}

	client := connectivityHTTPClientFn()
	results := make([]checkResult, 0, len(targets))
	okCount := 0
	for _, u := range targets {
		resp, err := client.Get(u)
		if err != nil {
			results = append(results, checkResult{URL: u, OK: false, Error: err.Error()})
			continue
		}
		_ = resp.Body.Close()
		ok := resp.StatusCode >= 200 && resp.StatusCode < 500
		if ok {
			okCount++
		}
		results = append(results, checkResult{URL: u, OK: ok, Status: resp.StatusCode})
	}

	// DNS check: helps differentiate "no internet" vs "DNS broken".
	dnsHost := "cloudflare.com"
	dnsOK := false
	var dnsIPs []string
	var dnsErr string
	{
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		ips, err := connectivityDNSLookupFn(ctx, dnsHost)
		if err != nil {
			dnsErr = err.Error()
		} else {
			dnsOK = len(ips) > 0
			for _, ip := range ips {
				if ip.IP != nil {
					dnsIPs = append(dnsIPs, ip.IP.String())
				}
			}
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":       okCount > 0,
		"ok_count": okCount,
		"total":    len(targets),
		"results":  results,
		"dns": dnsResult{
			Host:  dnsHost,
			OK:    dnsOK,
			IPs:   dnsIPs,
			Error: dnsErr,
		},
	})
}

func (s *Server) apiSaveConfig(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var patch map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	// Аудит 2026-09-01 (раздел D, тест-закрепитель дефекта TestApiSaveConfig_PatchError):
	// раньше ошибка PatchConfig отдавалась с HTTP 200 — неотличимо для любого вызывающего
	// кода, который (справедливо) проверяет r.ok/response.status, а не парсит тело каждого
	// успешного ответа на предмет "error". Часть JS-обработчиков в этом файле именно так и
	// делали (bare `await fetch(...)` без разбора тела) — показывали "Сохранено" на
	// отклонённом PatchConfig (см. saveSettings/togInstant ниже).
	needsRestart, err := s.eng.PatchConfigDetailed(patch)
	if err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if needsRestart == nil {
		needsRestart = []string{}
	}
	// ТЗ v1.3 F5.4: ключи, которые подействуют только после перезапуска (listen_port/webui_port),
	// — UI показывает тост, а не молчит.
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "saved", "needs_restart": needsRestart})
}

func (s *Server) apiDiagnostics(w http.ResponseWriter, r *http.Request) {
	cors(w)
	diag := s.eng.GetDiagnostics()
	last, history := readWatchdogEvents()
	diag["watchdog_event"] = last
	diag["watchdog_events"] = history
	json.NewEncoder(w).Encode(diag)
}

func readWatchdogEvents() (map[string]interface{}, []map[string]interface{}) {
	lastPath := filepath.Join(config.DataDir(), "watchdog_last_event.json")
	historyPath := filepath.Join(config.DataDir(), "watchdog_events.json")

	var last map[string]interface{}
	if raw, err := os.ReadFile(lastPath); err == nil {
		_ = json.Unmarshal(raw, &last)
	}

	var history []map[string]interface{}
	if raw, err := os.ReadFile(historyPath); err == nil {
		_ = json.Unmarshal(raw, &history)
	}
	return last, history
}

// ── Фаза 5: API LeakGuard ─────────────────────────────────────────────────────

// apiLeakGuardStatus — GET /api/leakguard/status
// Возвращает статус всех защит устройства
func (s *Server) apiLeakGuardStatus(w http.ResponseWriter, r *http.Request) {
	cors(w)
	json.NewEncoder(w).Encode(s.eng.GetLeakGuardStatus())
}

// apiDNSLeakTest — POST /api/leakguard/dns-test
// Запускает полную проверку DNS-утечки (занимает ~8 секунд)
func (s *Server) apiDNSLeakTest(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := s.eng.RunDNSLeakTest(ctx)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":  err.Error(),
			"leaked": false,
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"leaked":         result.Leaked,
		"system_dns":     result.SystemDNS,
		"tunnel_dns":     result.TunnelDNS,
		"system_ips":     result.SystemIPs,
		"tunnel_ips":     result.TunnelIPs,
		"diagnosis":      result.Diagnosis,
		"recommendation": result.Recommendation,
	})
}

// apiIPv6Block — POST /api/leakguard/ipv6
// Body: {"enabled": true/false}
func (s *Server) apiIPv6Block(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if err := engEnableIPv6BlockFn(s.eng, body.Enabled); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   err.Error(),
			"enabled": !body.Enabled, // не изменился
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"enabled": body.Enabled,
	})
}

// apiWebRTCBlock — POST /api/leakguard/webrtc
// Body: {"enabled": true/false}
func (s *Server) apiWebRTCBlock(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if err := engEnableWebRTCBlockFn(s.eng, body.Enabled); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   err.Error(),
			"enabled": !body.Enabled,
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"enabled": body.Enabled,
	})
}

// apiBrowserInstructions — GET /api/leakguard/browser-instructions
// Возвращает инструкции для отключения WebRTC в браузерах
func (s *Server) apiBrowserInstructions(w http.ResponseWriter, r *http.Request) {
	cors(w)
	status := s.eng.GetLeakGuardStatus()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"instructions":    status["browser_instructions"],
		"firefox_user_js": status["firefox_user_js"],
	})
}

// apiSetPassword — POST /api/crypto/set-password
// Body: {"password": "..."} — устанавливает мастер-пароль шифрования
// Body: {"password": ""} — отключает шифрование
func (s *Server) apiSetPassword(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	s.eng.SetMasterPassword(body.Password)

	enabled := body.Password != ""
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"enabled": enabled,
		"message": map[bool]string{
			true:  "Шифрование AES-256-GCM включено. nodes_cache.json защищён.",
			false: "Шифрование отключено.",
		}[enabled],
	})
}

// apiEmergencyWipe — POST /api/emergency/wipe
// Body: {"wipe_all": false} — стирает данные APF
// Body: {"wipe_all": true}  — стирает данные + бинарники
// ВНИМАНИЕ: требует подтверждения через UI
func (s *Server) apiEmergencyWipe(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var body struct {
		WipeAll bool   `json:"wipe_all"`
		Confirm string `json:"confirm"` // должен быть "WIPE"
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}

	// Дополнительная защита от случайного вызова
	if body.Confirm != "WIPE" {
		json.NewEncoder(w).Encode(map[string]string{
			"error": "confirmation required: send confirm=WIPE",
		})
		return
	}

	result := s.eng.EmergencyWipe(body.WipeAll)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "wiped",
		"files_deleted": result.FilesDeleted,
		"bytes_deleted": result.BytesDeleted,
		"errors":        result.Errors,
		"duration_ms":   result.Duration.Milliseconds(),
	})
}

// ── P2.3 (docs/TZ_APF_ROADMAP_v1.2.md): роль «Выход»/«Транзит» на Windows ──────────────

// apiServerRoleStatus — GET: снимок состояния (running/listen_port).
func (s *Server) apiServerRoleStatus(w http.ResponseWriter, r *http.Request) {
	cors(w)
	json.NewEncoder(w).Encode(s.eng.GetServerRoleStatus())
}

// apiServerRoleIdentity — GET: ранее сохранённый ключ звена, если уже сгенерирован.
// found=false — не ошибка, обычный случай до первого generate-identity.
//
// S-3 (ТЗ v1.4, консилиум O-3): ДО этого пункта ответ отдавал identity ЦЕЛИКОМ, включая
// приватный ключ Reality — GET не проверялся ни происхождением (см. S-18), ни токеном (до
// S-2). Уточнение консилиума: чтение чужой веб-страницей было закрыто отсутствием
// Access-Control-Allow-Origin (см. cors ниже), но ЛЮБОЙ локальный процесс ключ читал.
// Приватный ключ фронтенду не нужен (build-link строится на сервере, BuildServerRoleLink
// использует только PublicKey/ShortID) — отдаём публичную часть, приватный ключ — только
// явным POST /api/server-role/identity/export (см. ниже), под токеном и с записью в журнал.
func (s *Server) apiServerRoleIdentity(w http.ResponseWriter, r *http.Request) {
	cors(w)
	id, found, err := s.eng.LoadServerRoleIdentity()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	id.PrivateKey = ""
	json.NewEncoder(w).Encode(map[string]interface{}{"found": found, "identity": id})
}

// apiServerRoleIdentityExport — POST {"confirm":"EXPORT"}: единственный путь, отдающий
// приватный ключ Reality целиком (S-3). Требует токен (это обычный "/api/*" — см.
// requireAuth) и явное подтверждение в теле, как apiEmergencyWipe (confirm="WIPE") —
// одноимённый механизм защиты от случайного/автоматического вызова. Каждый успешный
// экспорт пишет строку в журнал (appendLog), без самого ключа в записи.
func (s *Server) apiServerRoleIdentityExport(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != http.MethodPost {
		http.Error(w, "POST", 405)
		return
	}
	var body struct {
		Confirm string `json:"confirm"` // должен быть "EXPORT"
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if body.Confirm != "EXPORT" {
		http.Error(w, "confirmation required: send confirm=EXPORT", 400)
		return
	}
	id, found, err := s.eng.LoadServerRoleIdentity()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if !found {
		http.Error(w, "identity not generated yet", 404)
		return
	}
	s.appendLog(fmt.Sprintf("[SECURITY] экспорт приватного ключа Reality (identity/export) remote=%s", r.RemoteAddr))
	json.NewEncoder(w).Encode(map[string]interface{}{"identity": id})
}

// apiServerRoleGenerateIdentity — POST: новый независимый ключ звена, заменяет сохранённый
// (все ранее выданные ссылки «Входу» перестанут работать — фронтенд обязан явно
// предупредить перед вызовом, см. ServerRole.GenerateServerRoleIdentity).
func (s *Server) apiServerRoleGenerateIdentity(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	id, err := s.eng.GenerateServerRoleIdentity()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"identity": id})
}

// apiServerRoleBuildLink — POST {identity, host, listen_port, reality_dest, label}: готовая
// vless://-ссылка для передачи «Входу» (ТЗ §5.2).
func (s *Server) apiServerRoleBuildLink(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var body struct {
		Identity         singbox.ServerIdentity `json:"identity"`
		Host             string                 `json:"host"`
		ListenPort       int                    `json:"listen_port"`
		RealityDest      string                 `json:"reality_dest"`
		Label            string                 `json:"label"`
		RelayAddr        string                 `json:"relay_addr"`
		RelayFingerprint string                 `json:"relay_fingerprint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	link, err := s.eng.BuildServerRoleLink(body.Identity, body.Host, body.ListenPort, body.RealityDest, body.Label, body.RelayAddr, body.RelayFingerprint)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"link": link})
}

// apiServerRoleStart — POST {identity, listen_port, reality_dest}: поднимает роль «Выход».
func (s *Server) apiServerRoleStart(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var body struct {
		Identity    singbox.ServerIdentity `json:"identity"`
		ListenPort  int                    `json:"listen_port"`
		RealityDest string                 `json:"reality_dest"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if err := s.eng.StartServerRole(body.ListenPort, body.RealityDest, body.Identity); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(s.eng.GetServerRoleStatus())
}

// apiServerRoleStop — POST: останавливает роль «Выход». Идемпотентен.
func (s *Server) apiServerRoleStop(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	if err := s.eng.StopServerRole(); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(s.eng.GetServerRoleStatus())
}

// ── P2.1 (docs/TZ_APF_ROADMAP_v1.2.md): каталог платных провайдеров ────────────────────

// apiPaidProviderAdd — POST models.PaidProviderEntry: добавляет провайдера, тестирует
// подключение и загружает узлы в пул (см. Engine.AddPaidProvider — реальный сетевой вызов,
// может занять до 15с).
func (s *Server) apiPaidProviderAdd(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var entry models.PaidProviderEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if err := s.eng.AddPaidProvider(entry); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "added"})
}

// apiPaidProviderRemove — POST {id}: удаляет провайдера и его узлы из пула.
func (s *Server) apiPaidProviderRemove(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if !s.eng.RemovePaidProvider(body.ID) {
		json.NewEncoder(w).Encode(map[string]string{"error": "not found: " + body.ID})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "removed"})
}

// apiPaidProviderTest — POST models.PaidProviderEntry: пробное подключение БЕЗ сохранения
// (форма «Проверить» перед «Добавить», до 20с).
func (s *Server) apiPaidProviderTest(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var entry models.PaidProviderEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	count, err := s.eng.TestPaidProvider(entry)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"node_count": count})
}

// ── Фаза 7: Аварийные туннели + Watchdog ────────────────────────────────────

// apiFallbackStatus — GET /api/fallback/status
func (s *Server) apiFallbackStatus(w http.ResponseWriter, r *http.Request) {
	cors(w)
	json.NewEncoder(w).Encode(s.eng.GetFallbackStatus())
}

// apiFallbackActivate — POST /api/fallback/activate
// Body: {"tunnel": "tor" | "tor_snowflake" | "psiphon"}
func (s *Server) apiFallbackActivate(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var body struct {
		Tunnel string `json:"tunnel"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if err := s.eng.ActivateFallbackTunnel(body.Tunnel); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "activating", "tunnel": body.Tunnel})
}

// apiFallbackAutoSelect — POST /api/fallback/auto-select
// Автоматически выбирает лучший аварийный туннель
func (s *Server) apiFallbackAutoSelect(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	tunnel := s.eng.AutoSelectFallback()
	json.NewEncoder(w).Encode(map[string]string{"tunnel": tunnel, "status": "selected"})
}

// apiWatchdogStatus — GET /api/watchdog/status
func (s *Server) apiWatchdogStatus(w http.ResponseWriter, r *http.Request) {
	cors(w)
	json.NewEncoder(w).Encode(s.eng.GetWatchdogStatus())
}

// apiWatchdogHistory — GET/DELETE /api/watchdog/history
// GET: отдаёт полную историю watchdog-событий.
// DELETE: очищает историю и последний event.
func (s *Server) apiWatchdogHistory(w http.ResponseWriter, r *http.Request) {
	cors(w)
	historyPath := filepath.Join(config.DataDir(), "watchdog_events.json")
	lastPath := filepath.Join(config.DataDir(), "watchdog_last_event.json")

	switch r.Method {
	case http.MethodGet:
		var history []map[string]interface{}
		if raw, err := os.ReadFile(historyPath); err == nil && len(raw) > 0 {
			_ = json.Unmarshal(raw, &history)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count":   len(history),
			"history": history,
		})
	case http.MethodDelete:
		_ = os.Remove(historyPath)
		_ = os.Remove(lastPath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "cleared",
			"message": "watchdog history cleared",
		})
	default:
		http.Error(w, "GET/DELETE", http.StatusMethodNotAllowed)
	}
}

// ── Sticky Session API ────────────────────────────────────────────────────────

// apiSessionStatus — GET /api/session/status
func (s *Server) apiSessionStatus(w http.ResponseWriter, r *http.Request) {
	cors(w)
	json.NewEncoder(w).Encode(s.eng.GetStickySessionStatus())
}

// apiSessionPolicy — POST /api/session/policy
// Body: {"policy": "sticky" | "free" | "timed"}
func (s *Server) apiSessionPolicy(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var body struct {
		Policy string `json:"policy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	s.eng.SetStickyPolicy(body.Policy)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"policy": body.Policy,
	})
}

// apiForceSwitch — POST /api/session/force-switch
// Принудительное переключение сервера несмотря на Sticky Session
func (s *Server) apiForceSwitch(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	s.eng.ForceSwitchNow()
	json.NewEncoder(w).Encode(map[string]string{"status": "switching"})
}

// ── Фаза 6: DPI обход ────────────────────────────────────────────────────────

// apiDPIStatus — GET /api/dpi/status
// Возвращает статус всех DPI-защит (Canary, Padding, CDN, ShadowTLS)
func (s *Server) apiDPIStatus(w http.ResponseWriter, r *http.Request) {
	cors(w)
	json.NewEncoder(w).Encode(s.eng.GetDPIStatus(context.Background()))
}

// apiCanaryTest — POST /api/dpi/canary-test
// Запускает Canary-тест (~15 секунд), определяет видит ли провайдер VPN
func (s *Server) apiCanaryTest(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	result, err := s.eng.RunCanaryTest(ctx)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": err.Error(),
			"score": 0,
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"score":           result.Score,
		"vpn_detectable":  result.VPNDetectable,
		"tls_leaked":      result.TLSFingerprintLeaked,
		"timing_anomaly":  result.TimingAnomaly,
		"entropy_high":    result.EntropyHigh,
		"diagnosis":       result.Diagnosis,
		"recommendation":  result.Recommendation,
		"counter_measure": result.CounterMeasure,
		"duration_ms":     result.Duration,
		"score_label":     fmt.Sprintf("%d/100", result.Score),
	})
}

// apiTrafficPadding — POST /api/dpi/padding
// Body: {"enabled": true, "aggressive": false}
func (s *Server) apiTrafficPadding(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var body struct {
		Enabled    bool `json:"enabled"`
		Aggressive bool `json:"aggressive"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	s.eng.EnableTrafficPadding(body.Enabled, body.Aggressive)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "ok",
		"enabled":    body.Enabled,
		"aggressive": body.Aggressive,
	})
}

// apiCDNFronting — POST /api/dpi/cdn
// Body: {"worker_domain": "my.workers.dev", "backend_host": "1.2.3.4", "backend_port": 443}
func (s *Server) apiCDNFronting(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == "GET" {
		json.NewEncoder(w).Encode(s.eng.GetDPIStatus(context.Background()))
		return
	}
	if r.Method != "POST" {
		http.Error(w, "POST or GET", 405)
		return
	}
	var body struct {
		WorkerDomain string `json:"worker_domain"`
		BackendHost  string `json:"backend_host"`
		BackendPort  int    `json:"backend_port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	s.eng.SetCDNConfig(body.WorkerDomain, body.BackendHost, body.BackendPort)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "ok",
		"worker_domain": body.WorkerDomain,
		"enabled":       body.WorkerDomain != "",
	})
}

// apiCDNWorkerScript — GET /api/dpi/cdn-worker-script
// Возвращает JavaScript код Cloudflare Worker для деплоя
func (s *Server) apiCDNWorkerScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// Подстановочный CORS убран по той же причине, что и в cors() — см. комментарий там.
	w.Header().Set("Content-Disposition", "attachment; filename=worker.js")
	fmt.Fprint(w, s.eng.GetCDNWorkerScript())
}

// apiShadowTLS — POST /api/dpi/shadowtls
// Body: {"enabled": true, "password": "secret", "sni": "www.bing.com", "server": "www.bing.com:443",
//
//	"server_addr": "203.0.113.7:8443"}
//
// P1-1 (аудит 2026-09-01): добавлено поле server_addr — адрес РЕАЛЬНОГО сервера ShadowTLS
// (host:port), куда физически уходит соединение. "server" остаётся тем, чем был всегда —
// необязательным переопределением маскировочного SNI-сайта (для проверки доступности), не
// имеет отношения к тому, куда реально уходит трафик.
func (s *Server) apiShadowTLS(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == "GET" {
		json.NewEncoder(w).Encode(s.eng.GetDPIStatus(context.Background()))
		return
	}
	if r.Method != "POST" {
		http.Error(w, "POST or GET", 405)
		return
	}
	var body struct {
		Enabled    bool   `json:"enabled"`
		Password   string `json:"password"`
		SNI        string `json:"sni"`
		Server     string `json:"server"`
		ServerAddr string `json:"server_addr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if err := s.eng.SetShadowTLSConfig(body.Enabled, body.Password, body.SNI, body.Server, body.ServerAddr); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"enabled": body.Enabled,
		"sni":     body.SNI,
	})
}

// apiShadowTLSAutoSNI — POST /api/dpi/shadowtls-auto-sni
// Автоматически выбирает лучший SNI для ShadowTLS
func (s *Server) apiShadowTLSAutoSNI(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	sni, err := engAutoSelectSNIFn(s.eng, ctx)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": err.Error(),
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"sni":    sni,
	})
}

// ── Sprint S2: Catalog API ───────────────────────────────────────────────────

func (s *Server) apiCatalogStatus(w http.ResponseWriter, r *http.Request) {
	cors(w)
	json.NewEncoder(w).Encode(s.eng.GetCatalogStatus())
}

func (s *Server) apiCatalogRefresh(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	// П18 (аудит F1/2026-09-07): раньше здесь была голая `go func(){...}()` с
	// context.Background() — фоновая запись переживала завершение обработчика и, в тестах,
	// сам тест. trackedGo регистрирует горутину в s.wg и даёт ей s.ctx, который Close()
	// отменяет вместе с остановкой сервера (см. Server.Close/trackedGo выше).
	s.trackedGo(func(ctx context.Context) {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
		added, err := catalogRefreshFn(s.eng, ctx)
		if err != nil {
			s.appendLog(fmt.Sprintf("Catalog refresh error: %v", err))
		} else {
			s.appendLog(fmt.Sprintf("Catalog refresh: +%d nodes", added))
		}
	})
	json.NewEncoder(w).Encode(map[string]string{"status": "refreshing"})
}

func (s *Server) apiCatalogProvider(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var body struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	ok := s.eng.SetProviderEnabled(body.ID, body.Enabled)
	if !ok {
		json.NewEncoder(w).Encode(map[string]string{"error": "provider not found: " + body.ID})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "id": body.ID, "enabled": body.Enabled})
}

// ── Sprint S4: AdBlock API ────────────────────────────────────────────────────

func (s *Server) apiAdBlockStatus(w http.ResponseWriter, r *http.Request) {
	cors(w)
	json.NewEncoder(w).Encode(s.eng.GetAdBlockStatus())
}

func (s *Server) apiAdBlockProfile(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var body struct {
		Profile string `json:"profile"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if err := s.eng.SetAdBlockProfile(body.Profile); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"profile": body.Profile,
		"note":    "Блок-листы загружаются в фоне (~1-2 минуты)",
	})
}

func (s *Server) apiAdBlockAllowlist(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var body struct {
		Domain string `json:"domain"`
		Add    bool   `json:"add"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if body.Domain == "" {
		http.Error(w, "domain required", 400)
		return
	}
	// P1-6 (аудит 2026-09-01): раньше ответ был "status":"ok" безусловно — даже когда движок
	// не принял ввод (не домен, а, скажем, вставленный из адресной строки URL с путём) или
	// когда домен уже был в списке. Пользователь видел успех и не понимал, почему сайт всё
	// ещё блокируется.
	changed := s.eng.AdBlockToggleAllowlist(body.Domain, body.Add)
	action := "-"
	if body.Add {
		action = "+"
	}
	if !changed {
		msg := "домен уже в белом списке или указан неверно (ожидается имя вида example.com)"
		if !body.Add {
			msg = "домена нет в белом списке или он указан неверно"
		}
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"domain": body.Domain,
			"action": action,
			"error":  msg,
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"domain": body.Domain,
		"action": action,
	})
}

// ── Sprint S6: Anti-VPN-Block API ──────────────────────────────────────────────────────

// apiAntiBlockStatus — GET /api/antiblock/status
func (s *Server) apiAntiBlockStatus(w http.ResponseWriter, r *http.Request) {
	cors(w)
	json.NewEncoder(w).Encode(s.eng.GetAntiBlockStatus())
}

// apiAntiBlockCheckIP — POST /api/antiblock/check-ip
// Body: {"ip": "1.2.3.4"} или {"ip": "current"} — проверить текущий узел
func (s *Server) apiAntiBlockCheckIP(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var body struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
		http.Error(w, "ip required", 400)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var result map[string]interface{}
	var err error

	if body.IP == "current" {
		// Проверяем IP текущего активного узла
		result, err = s.eng.CheckCurrentIP(ctx)
	} else {
		// Проверяем произвольный IP
		result, err = s.eng.CheckCurrentIPByAddr(ctx, body.IP)
	}

	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(result)
}

// apiAntiBlockCheckNode — POST /api/antiblock/check-node
// Body: {"node_id": "..."}
func (s *Server) apiAntiBlockCheckNode(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var body struct {
		NodeID string `json:"node_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.NodeID == "" {
		http.Error(w, "node_id required", 400)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := s.eng.CheckNodeIP(ctx, body.NodeID)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(result)
}

// apiAntiBlockConfig — POST /api/antiblock/config
// Body: {"enabled": true, "residential_only": false, "auto_switch": true, "api_key": ""}
func (s *Server) apiAntiBlockConfig(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var body struct {
		Enabled         bool   `json:"enabled"`
		ResidentialOnly bool   `json:"residential_only"`
		AutoSwitch      bool   `json:"auto_switch"`
		APIKey          string `json:"api_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	s.eng.SetAntiBlockConfig(body.Enabled, body.ResidentialOnly, body.AutoSwitch, body.APIKey)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":           "ok",
		"enabled":          body.Enabled,
		"residential_only": body.ResidentialOnly,
		"auto_switch":      body.AutoSwitch,
	})
}

// apiAntiBlockBypassList — GET/POST /api/antiblock/bypass-list
// GET: отдаёт список bypass-правил
// POST: {"id":"netflix","enabled":true} — вкл/выкл правило
func (s *Server) apiAntiBlockBypassList(w http.ResponseWriter, r *http.Request) {
	cors(w)
	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(s.eng.GetBypassRules())
	case http.MethodPost:
		var body struct {
			ID      string `json:"id"`
			Enabled bool   `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
			http.Error(w, "id required", 400)
			return
		}
		ok := s.eng.SetBypassRule(body.ID, body.Enabled)
		if !ok {
			json.NewEncoder(w).Encode(map[string]string{"error": "rule not found: " + body.ID})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "id": body.ID, "enabled": body.Enabled})
	default:
		http.Error(w, "GET/POST", 405)
	}
}

// apiAntiBlockBypassDomain — POST /api/antiblock/bypass-domain
// Добавление: {"domain":"example.com","name":"Example","residential":true,"direct_route":false}
// Редактирование: то же + {"id":"user_example_com"} (id непустой и remove=false → update)
// Удаление: {"id":"user_example_com","remove":true}
func (s *Server) apiAntiBlockBypassDomain(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != "POST" {
		http.Error(w, "POST", 405)
		return
	}
	var body struct {
		Domain      string `json:"domain"`
		Name        string `json:"name"`
		Residential bool   `json:"residential"`
		DirectRoute bool   `json:"direct_route"`
		Remove      bool   `json:"remove"`
		ID          string `json:"id"` // для удаления/редактирования
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if body.Remove {
		if body.ID == "" {
			http.Error(w, "id required for remove", 400)
			return
		}
		ok := s.eng.RemoveBypassDomain(body.ID)
		if !ok {
			json.NewEncoder(w).Encode(map[string]string{"error": "not found or builtin"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "removed"})
		return
	}
	if body.ID != "" {
		ok := s.eng.UpdateBypassDomain(body.ID, body.Domain, body.Name, body.Residential, body.DirectRoute)
		if !ok {
			json.NewEncoder(w).Encode(map[string]string{"error": "not found or builtin"})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "updated", "id": body.ID})
		return
	}
	if body.Domain == "" {
		http.Error(w, "domain required", 400)
		return
	}
	ok := s.eng.AddBypassDomain(body.Domain, body.Name, body.Residential, body.DirectRoute)
	if !ok {
		json.NewEncoder(w).Encode(map[string]string{"error": "domain already exists"})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "added", "domain": body.Domain})
}

// appendLog добавляет сообщение в буфер логов сервера
func (s *Server) appendLog(msg string) {
	s.logsMu.Lock()
	s.logs = append(s.logs, msg)
	if len(s.logs) > 300 {
		s.logs = s.logs[len(s.logs)-300:]
	}
	s.logsMu.Unlock()
}

// ── UI ────────────────────────────────────────────────────────────────────────

func (s *Server) apiUI(w http.ResponseWriter, r *http.Request) {
	// F-33: "/" в http.ServeMux — catch-all. Отдаём UI только для точного корня;
	// прочие неизвестные пути → 404 (раньше любой опечатанный URL возвращал 200+HTML).
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// P1.4 (docs/TZ_APF_ROADMAP_v1.2.md): было захардкожено "v1.0.7" отдельно от
	// version.Version ("1.1.0") — ровно та рассинхронизация, о которой предупреждает сам
	// roadmap-документ. strings.Replace вместо fmt.Sprintf(webUI, ...): webUI — многотысячная
	// строка CSS/HTML, где встречаются буквальные "%" (проценты ширины и т.п.) — Sprintf на
	// них бы упал, точечная замена по маркеру безопаснее и не требует экранировать всю строку.
	fmt.Fprint(w, strings.Replace(webUI, ">v1.0.7<", ">v"+version.Version+"<", 1))
}

// cors выставляет заголовки ответа API.
//
// Заголовка Access-Control-Allow-Origin здесь СОЗНАТЕЛЬНО НЕТ (убран 2026-08-24).
// Раньше стояло «*» — на КАЖДОМ эндпоинте, включая /api/server-role/identity, который
// отдаёт приватный ключ Reality звена «Выход». Сервер слушает 127.0.0.1, но подстановочный
// CORS означает, что ЛЮБАЯ открытая пользователем веб-страница могла выполнить
// кросс-доменный запрос к локальному API и ПРОЧИТАТЬ ответ — то есть увести приватный ключ
// и прочую конфигурацию. Порт при этом перебирается тривиально (base..base+10).
//
// Всем законным потребителям заголовок не нужен: встроенный веб-интерфейс отдаётся с того
// же origin (для одинакового источника CORS не применяется вовсе), десктопный GUI ходит
// через Wails-биндинги, а режим наблюдателя (gui/webclient.go) — обычный Go-клиент, для
// которого политика браузера неприменима.
func cors(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	// Не давать браузеру угадывать тип: ответы API — строго JSON.
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

// ─── P0-2: защита от межсайтовых запросов (CSRF) ─────────────────────────────
//
// Отсутствие Access-Control-Allow-Origin (см. cors) закрывает ЧТЕНИЕ ответа чужой страницей,
// но НЕ закрывает сам побочный эффект. Запрос `fetch(url, {method:'POST', mode:'no-cors'})`
// без нестандартных заголовков — «простой» по спецификации CORS: preflight не отправляется,
// запрос доходит до сервера и выполняется, и атакующему не нужно читать ответ.
//
// Что этим достигалось до фикса, за один визит на любую страницу (порт перебирается за 100
// попыток): /api/emergency/wipe со строкой подтверждения "WIPE" — необратимое стирание;
// /api/save-config с enable_kill_switch:false — снятие защиты; /api/antiblock/bypass-domain с
// direct_route:true — вывод произвольного домена ИЗ туннеля, то есть деанонимизация по выбору
// атакующего без единого признака в UI; /api/add-node — подсадка узла атакующего в пул.
//
// Требовать Content-Type: application/json (что само по себе перевело бы запрос в разряд
// непростых) НЕЛЬЗЯ: собственный встроенный UI шлёт часть POST'ов без тела и без этого
// заголовка (/api/connect, /api/disconnect, /api/scan, /api/rescan, /api/reset-network,
// /api/connectivity-check) — проверено по коду страницы.
//
// Поэтому решение — проверка происхождения:
//   - Sec-Fetch-Site: современные браузеры шлют его ВСЕГДА; принимаем только same-origin и
//     none (адресная строка/закладка). cross-site и same-site отвергаем.
//   - Origin: браузер обязан прислать его при межсайтовом POST; принимаем только петлю.
//
// Не-браузерные клиенты (gui/webclient.go в режиме наблюдателя, curl, Android-мост) этих
// заголовков не шлют вовсе и проходят без изменений — их браузерная политика не касается.
//
// S-18 (ТЗ v1.4, консилиум O-2/O-3, P1): ДО этого пункта проверка происхождения включалась
// только для isMutatingMethod (POST/PUT/PATCH/DELETE) — GET не проверялся вовсе. Это
// открывало диагностику, конфиг, список узлов и /api/server-role/identity (приватный
// ключ Reality, S-3) для любого локального процесса, делающего простой GET. После S-2
// аутентификация обязательна для любого метода на "/api/*", поэтому фильтр происхождения
// перестаёт быть единственной защитой мутирующих маршрутов — но должен закрывать и
// GET-и тоже (защита в глубину: origin проверяется РАНЬШЕ токена, см. Handler()/S-13).
// Исключения — ровно GET "/" и GET "/ui" (isPublicEntryPoint): вход по handoff-ключу
// не может сам себя защитить проверкой происхождения, не сломав browser-навигацию.
func guardCrossOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isPublicEntryPoint(r) {
			if reason := crossOriginReason(r); reason != "" {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Content-Type-Options", "nosniff")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "cross-origin request rejected: " + reason,
				})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// isPublicEntryPoint — точки входа, которым по построению нечего защищать ни проверкой
// происхождения (guardCrossOrigin, S-18), ни токеном (requireAuth, S-2): GET "/" отдаёт
// статическую страницу без секрета в теле (S-2 — токен НИКОГДА не печатается в HTML, в
// отличие от отклонённого консилиумом черновика), GET "/ui" сам проверяет одноразовый
// handoff-ключ (см. apiUIHandoff) и не может требовать токен, которого у браузера ещё нет.
func isPublicEntryPoint(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	return r.URL.Path == "/" || r.URL.Path == "/ui"
}

// crossOriginReason возвращает пустую строку, если запрос допустим, иначе — причину отказа.
func crossOriginReason(r *http.Request) string {
	// Sec-Fetch-Site шлют все современные браузеры. Его отсутствие означает не-браузерного
	// клиента (или очень старый браузер) — тогда решение принимается по Origin ниже.
	switch r.Header.Get("Sec-Fetch-Site") {
	case "cross-site", "same-site":
		return "Sec-Fetch-Site=" + r.Header.Get("Sec-Fetch-Site")
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		// Ни Origin, ни запрещающего Sec-Fetch-Site — обычный локальный клиент.
		return ""
	}
	u, err := url.Parse(origin)
	if err != nil {
		return "нераспознанный Origin"
	}
	if !isLoopbackHost(u.Hostname()) {
		return "Origin=" + origin
	}
	return ""
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// ─── S-2 (ТЗ v1.4, O-2): requireAuth — токен или cookie для ЛЮБОГО метода на "/api/*" ──

// requireAuth оборачивает mux (внутри guardCrossOrigin — Handler(), порядок "сначала
// происхождение, потом аутентификация" зафиксирован тестом S18_OriginCheckedBeforeAuth).
// Исключения — те же две публичные точки входа, что и у guardCrossOrigin (isPublicEntryPoint).
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicEntryPoint(r) || s.isAuthorized(r) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "unauthorized: требуется Authorization: Bearer <token> или cookie apf_ui",
		})
	})
}

// isAuthorized сравнивает предъявленный токен с s.authToken ПОСТОЯННЫМ по времени
// сравнением (subtle.ConstantTimeCompare) — тайминг-атака на сам барьер была бы новым
// каналом утечки токена, ровно тем классом дыры, ради закрытия которой S-2 вводится.
func (s *Server) isAuthorized(r *http.Request) bool {
	want := s.authToken
	if want == "" {
		// generateAuthToken() в New() провалился — fail-closed (см. комментарий у поля
		// authToken): молчаливый обход аутентификации был бы той же дырой, что и раньше.
		return false
	}
	if h := r.Header.Get("Authorization"); h != "" {
		const prefix = "Bearer "
		if strings.HasPrefix(h, prefix) {
			got := strings.TrimPrefix(h, prefix)
			if subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1 {
				return true
			}
		}
	}
	if c, err := r.Cookie("apf_ui"); err == nil {
		if subtle.ConstantTimeCompare([]byte(c.Value), []byte(want)) == 1 {
			return true
		}
	}
	return false
}

// ─── S-2 п.4: handoff — одноразовый ключ → HttpOnly-cookie для браузерного входа ──────
//
// Свой клиент (трей/GUI, вне владения этого лота — см. result.md token_contract), уже
// владеющий постоянным токеном из файла (writeAuthTokenFile), запрашивает одноразовый
// ключ POST /api/ui/handoff (сам этот запрос — обычный "/api/*", требует токен) и
// открывает системный браузер на "/ui?k=<k>". Постоянный токен в URL не появляется
// НИКОГДА — только k, TTL 10с, одноразовый, хранится исключительно в памяти сервера.

// apiUIHandoffKey — POST /api/ui/handoff: минтит одноразовый ключ.
func (s *Server) apiUIHandoffKey(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != http.MethodPost {
		http.Error(w, "POST", 405)
		return
	}
	k, err := s.mintHandoffKey()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"k": k})
}

const handoffKeyTTL = 10 * time.Second

func (s *Server) mintHandoffKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("web: генерация handoff-ключа: %w", err)
	}
	k := base64.RawURLEncoding.EncodeToString(buf)
	s.handoffMu.Lock()
	if s.handoffKeys == nil {
		s.handoffKeys = map[string]time.Time{}
	}
	s.handoffKeys[k] = time.Now().Add(handoffKeyTTL)
	s.handoffMu.Unlock()
	return k, nil
}

// consumeHandoffKey инвалидирует k НЕМЕДЛЕННО при первом предъявлении, независимо от
// того, истёк TTL или нет ("одноразов" — S-2 п.4): повторное предъявление того же k,
// даже в пределах TTL, обязано вернуть отказ.
func (s *Server) consumeHandoffKey(k string) bool {
	s.handoffMu.Lock()
	defer s.handoffMu.Unlock()
	exp, ok := s.handoffKeys[k]
	if ok {
		delete(s.handoffKeys, k)
	}
	return ok && time.Now().Before(exp)
}

// apiUIHandoff — GET /ui?k=<одноразовый ключ>: обменивает k на HttpOnly-cookie apf_ui
// (SameSite=Strict, сессионная — без Max-Age, "живёт" ровно сессию браузера) и
// редиректит на "/". Публичная точка входа (isPublicEntryPoint) — сама проверяет k,
// поэтому не требует ни происхождения (guardCrossOrigin), ни токена (requireAuth).
func (s *Server) apiUIHandoff(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/ui" || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	k := r.URL.Query().Get("k")
	if k == "" || !s.consumeHandoffKey(k) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid or expired handoff key"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "apf_ui",
		Value:    s.authToken,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

// ─── S-13 (ТЗ v1.4, P2): журналирование отказов происхождения/аутентификации ──────────
//
// guardCrossOrigin (403) и requireAuth (401) — единственные два места во всём mux,
// отвечающие этими кодами (ни один хэндлер s.mux напрямую 401/403 не пишет — проверено
// grep по файлу), поэтому перехват по коду ОТВЕТА не даёт ложных срабатываний и не
// требует менять сигнатуру guardCrossOrigin, которую напрямую вызывает существующий
// internal/web/csrf_guard_test.go (чужой файл, не в периметре этого лота).

// statusCapture запоминает код ответа, не меняя поведение исходного http.ResponseWriter
// ни для одного хэндлера — нужен только logSecurityDenials, чтобы узнать исход запроса.
type statusCapture struct {
	http.ResponseWriter
	status int
}

func (c *statusCapture) WriteHeader(code int) {
	c.status = code
	c.ResponseWriter.WriteHeader(code)
}

// logSecurityDenials — самый внешний слой Handler(): видит итоговый статус-код после
// guardCrossOrigin/requireAuth/mux и пишет строку в тот же журнал, что и остальной лог
// сервера (appendLog → s.logs → apiLogs/apiLogsExport), БЕЗ тела запроса и без токена —
// только причина/путь/метод/адрес (ТЗ S-13).
func (s *Server) logSecurityDenials(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sc := &statusCapture{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sc, r)
		var reason string
		switch sc.status {
		case http.StatusForbidden:
			reason = "origin"
		case http.StatusUnauthorized:
			reason = "auth"
		default:
			return
		}
		if !s.allowSecurityLog(reason) {
			return
		}
		s.appendLog(fmt.Sprintf("[SECURITY] отказ (%s): %s %s remote=%s", reason, r.Method, r.URL.Path, r.RemoteAddr))
	})
}

// allowSecurityLog — не чаще ОДНОЙ записи в секунду НА ПРИЧИНУ (ТЗ S-13): шторм из сотен
// отказов (например, сканирование порта скриптом) не должен вытеснить из 300-строчного
// s.logs (appendLog) весь остальной лог сервера.
func (s *Server) allowSecurityLog(reason string) bool {
	now := time.Now()
	s.secLogMu.Lock()
	defer s.secLogMu.Unlock()
	if s.secLogLast == nil {
		s.secLogLast = map[string]time.Time{}
	}
	if last, ok := s.secLogLast[reason]; ok && now.Sub(last) < time.Second {
		return false
	}
	s.secLogLast[reason] = now
	return true
}

var webUI = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>APF</title>
<style>
:root{--bg:#0d1117;--s1:#161b22;--s2:#1c2128;--s3:#21262d;--bd:#30363d;--bd2:#484f58;--t1:#e6edf3;--t2:#8b949e;--t3:#484f58;--ac:#4f8ef7;--ac2:#2563d4;--gr:#2ea043;--ye:#d29922;--re:#da3633;--pu:#a78bfa;--or:#f0883e}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--t1);font:14px/1.5 'Segoe UI',system-ui,sans-serif;min-height:100vh}
button,input,select{font-family:inherit;outline:none}
.layout{display:grid;grid-template-columns:220px 1fr;min-height:100vh}
.sidebar{background:var(--s1);border-right:1px solid var(--bd);display:flex;flex-direction:column;padding:16px 10px;gap:2px;position:sticky;top:0;height:100vh}
.logo{display:flex;align-items:center;gap:8px;padding:8px 10px;margin-bottom:12px}
.logo-icon{font-size:20px}.logo-text{font-size:16px;font-weight:700;letter-spacing:-.3px}
.logo-text span{color:var(--ac)}.logo-ver{font-size:10px;color:var(--t3);margin-left:auto;font-family:monospace}
.nav{display:flex;flex-direction:column;gap:2px}
.n{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:8px;color:var(--t2);cursor:pointer;transition:.12s;font-size:13px;position:relative;border:none;background:none;width:100%;text-align:left}
.n:hover{background:var(--s3);color:var(--t1)}.n.on{background:var(--s2);color:var(--t1)}
.n.on::before{content:'';position:absolute;left:0;top:6px;bottom:6px;width:3px;border-radius:0 3px 3px 0;background:var(--ac)}
.n-ic{font-size:15px;width:20px;text-align:center;flex-shrink:0}
.n-badge{margin-left:auto;font-size:10px;background:var(--ac2);color:#fff;padding:1px 6px;border-radius:99px;font-weight:600}
.n-badge.warn{background:var(--re)}.nav-sep{height:1px;background:var(--bd);margin:8px 0}
.nav-label{font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:.08em;padding:4px 10px}
.sb-bottom{margin-top:auto;padding-top:12px;border-top:1px solid var(--bd)}
.status-pill{display:flex;align-items:center;gap:6px;padding:7px 10px;border-radius:8px;background:var(--s2);margin-bottom:8px;font-size:12px}
.status-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.main{background:var(--bg);overflow-y:auto}
.page{display:none;padding:24px}.page.on{display:block}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:20px}
.card{background:var(--s1);border:1px solid var(--bd);border-radius:10px;padding:14px 16px}
.card-lbl{font-size:11px;color:var(--t2);text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px}
.card-val{font-size:22px;font-weight:700;color:var(--t1);line-height:1.2}
.card-sub{font-size:11px;color:var(--t2);margin-top:3px}
.btns{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border-radius:8px;border:1px solid var(--bd);background:transparent;color:var(--t1);font-size:13px;cursor:pointer;transition:.12s;white-space:nowrap}
.btn:hover{background:var(--s2);border-color:var(--bd2)}
.btn-pri{background:var(--ac);border-color:var(--ac);color:#fff}.btn-pri:hover{background:#6ba3ff;border-color:#6ba3ff}
.btn-red{border-color:rgba(218,54,51,.4);color:var(--re)}.btn-red:hover{background:rgba(218,54,51,.1)}
.btn-sm{padding:5px 12px;font-size:12px}
.btn-warn{border-color:rgba(240,136,62,.4);color:var(--or)}.btn-warn:hover{background:rgba(240,136,62,.08)}
.btn-gr{border-color:rgba(46,160,67,.4);color:var(--gr)}.btn-gr:hover{background:rgba(46,160,67,.08)}
.panel{background:var(--s1);border:1px solid var(--bd);border-radius:10px;margin-bottom:14px;overflow:hidden}
.panel-hd{padding:11px 16px;border-bottom:1px solid var(--bd);font-size:12px;font-weight:600;color:var(--t2);text-transform:uppercase;letter-spacing:.05em;display:flex;align-items:center;justify-content:space-between}
.panel-bd{padding:16px}
.tbl{width:100%;border-collapse:collapse}
.tbl th{text-align:left;padding:8px 10px;font-size:10px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid var(--bd)}
.tbl td{padding:9px 10px;font-size:12px;border-bottom:1px solid rgba(48,54,61,.5);vertical-align:middle}
.tbl tr:hover td{background:var(--s2)}.tbl tr:last-child td{border-bottom:none}
.pill{font-size:10px;padding:2px 7px;border-radius:99px;font-weight:600;font-family:monospace}
.p-ok{background:rgba(46,160,67,.15);color:var(--gr)}.p-slow{background:rgba(210,153,34,.15);color:var(--ye)}
.p-bad{background:rgba(218,54,51,.15);color:var(--re)}.p-unk{background:rgba(139,148,158,.1);color:var(--t2)}
.inp{background:var(--s2);border:1px solid var(--bd);border-radius:7px;padding:8px 12px;color:var(--t1);font-size:13px;transition:.12s;width:100%}
.inp:focus{border-color:var(--ac)}.inp::placeholder{color:var(--t3)}
.inp-row{display:flex;gap:8px}.inp-row .inp{flex:1}
.inp-fb{font-size:12px;margin-top:6px;min-height:18px}
.inp-fb.ok{color:var(--gr)}.inp-fb.err{color:var(--re)}
.srow{display:flex;align-items:center;justify-content:space-between;padding:12px 0;border-bottom:1px solid rgba(48,54,61,.5)}
.srow:last-child{border-bottom:none}.srow-l{flex:1}
.srow-title{font-size:13px;color:var(--t1)}.srow-sub{font-size:11px;color:var(--t2);margin-top:2px;line-height:1.4}
.toggle{width:36px;height:20px;border-radius:10px;background:var(--bd);position:relative;cursor:pointer;transition:.2s;flex-shrink:0;border:none}
.toggle.on{background:var(--ac)}.toggle::after{content:'';position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:#fff;transition:.2s}
.toggle.on::after{left:18px}
.help-ico{display:inline-flex;align-items:center;justify-content:center;width:14px;height:14px;border-radius:50%;margin-left:6px;font-size:10px;line-height:1;font-style:normal;cursor:pointer;color:var(--t2);border:1px solid var(--bd);vertical-align:middle}
.help-ico:hover,.help-ico:focus{color:var(--ac);border-color:var(--ac);outline:none}
/* U-8 (ТЗ v1.4): было hover-only title= — не читается с тач-экрана (E2/K10-UIC). Поповер по
   клику/фокусу, как уже сделано в Wails (index.html) — та же идея, отдельная реализация, т.к.
   у Web нет общего кода с Wails. */
.help-pop{position:fixed;max-width:280px;background:var(--s2);border:1px solid var(--bd2);border-radius:8px;padding:10px 12px;font-size:12px;line-height:1.5;color:var(--t1);box-shadow:0 10px 30px rgba(0,0,0,.35);z-index:9999;display:none}
.quick-toggles{display:flex;gap:20px;align-items:center;flex-wrap:wrap;padding:10px 14px;margin:-4px 0 14px;border-radius:8px;background:var(--s1);border:1px solid var(--bd)}
.quick-toggle-item{display:flex;align-items:center;gap:8px}
.quick-toggle-item .srow-title{white-space:nowrap}
.sinp{background:var(--s2);border:1px solid var(--bd);border-radius:6px;padding:5px 10px;color:var(--t1);font-size:12px;font-family:monospace;width:90px}
.logbox{background:var(--bg);border:1px solid var(--bd);border-radius:8px;padding:10px 12px;height:280px;overflow-y:auto;font-family:monospace;font-size:11px;line-height:1.7}
.ll{color:var(--t2)}.ll.ok{color:var(--gr)}.ll.err{color:var(--re)}.ll.info{color:var(--ac)}.ll.leak{color:var(--or)}
.lt{color:var(--t3);margin-right:8px}
.chart-wrap{background:var(--s1);border:1px solid var(--bd);border-radius:10px;padding:14px 16px;margin-bottom:14px}
.chart-hd{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;font-size:12px}
.chart-title{color:var(--t2);font-weight:600;text-transform:uppercase;letter-spacing:.05em}
.chart-cur{color:var(--ac);font-family:monospace;font-weight:700}
.chain{display:flex;align-items:center;gap:0;overflow-x:auto;padding:4px 0}
.chain-node{background:var(--s2);border:1px solid var(--bd);border-radius:7px;padding:7px 14px;font-size:11px;font-family:monospace;white-space:nowrap;text-align:center;flex-shrink:0}
.chain-node.you{border-color:var(--pu);color:var(--pu)}.chain-node.active{border-color:var(--ac);color:var(--ac);box-shadow:0 0 0 1px var(--ac) inset}
.chain-node.inet{border-color:var(--gr);color:var(--gr)}.chain-arr{color:var(--t3);padding:0 6px;font-size:14px;flex-shrink:0}
.info-box{border-radius:8px;padding:10px 14px;font-size:13px;line-height:1.55;margin-bottom:12px}
.info-box.warn{background:rgba(210,153,34,.12);border:1px solid rgba(210,153,34,.3);color:var(--ye)}
.info-box.danger{background:rgba(218,54,51,.1);border:1px solid rgba(218,54,51,.25);color:var(--re)}
.info-box.info{background:rgba(79,142,247,.1);border:1px solid rgba(79,142,247,.25);color:#7eb8ff}
.info-box.ok{background:rgba(46,160,67,.1);border:1px solid rgba(46,160,67,.25);color:var(--gr)}
.toast{position:fixed;right:16px;bottom:16px;z-index:9999;max-width:360px;background:var(--s2);border:1px solid var(--bd2);border-radius:10px;padding:10px 12px;color:var(--t1);font-size:12px;line-height:1.5;box-shadow:0 10px 30px rgba(0,0,0,.35);display:none}
.toast.show{display:block;animation:fadeIn .18s ease}
.toast .ttl{font-weight:700;margin-bottom:4px}
.toast .sub{color:var(--t2);font-size:11px}
@keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
/* Leak guard */
.lg-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px}
.lg-card{background:var(--s1);border:1px solid var(--bd);border-radius:10px;padding:14px 16px;display:flex;flex-direction:column;gap:8px}
.lg-card.ok{border-color:rgba(46,160,67,.3)}.lg-card.warn{border-color:rgba(218,54,51,.3)}
.lg-icon{font-size:22px}.lg-title{font-size:13px;font-weight:600}
.lg-status{font-size:11px}.lg-status.ok{color:var(--gr)}.lg-status.warn{color:var(--re)}
.dns-result{background:var(--s2);border:1px solid var(--bd);border-radius:8px;padding:12px;font-family:monospace;font-size:12px;margin-top:8px;white-space:pre-line;min-height:48px;color:var(--t2)}
.browser-tab{display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap}
.browser-tab button{padding:5px 12px;font-size:12px;border-radius:6px;border:1px solid var(--bd);background:transparent;color:var(--t2);cursor:pointer}
.browser-tab button.on{background:var(--s2);border-color:var(--bd2);color:var(--t1)}
.browser-steps{background:var(--s2);border:1px solid var(--bd);border-radius:8px;padding:12px 14px;font-size:13px;line-height:2;color:var(--t2)}
.browser-steps b{color:var(--t1)}
/* Emergency */
.wipe-zone{border:2px dashed rgba(218,54,51,.3);border-radius:10px;padding:20px;text-align:center}
.wipe-confirm{background:var(--s2);border:1px solid var(--bd);border-radius:7px;padding:8px 12px;color:var(--t1);font-size:13px;margin-top:12px;width:100%;text-align:center}
/* Wizard */
.wizard{max-width:600px;margin:0 auto}
.wiz-steps{display:flex;align-items:center;gap:0;margin-bottom:32px}
.wiz-step{display:flex;align-items:center;gap:8px;flex:1}.wiz-step:last-child{flex:0}
.wiz-dot{width:28px;height:28px;border-radius:50%;border:2px solid var(--bd);display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:var(--t2);flex-shrink:0;transition:.3s}
.wiz-dot.done{background:var(--gr);border-color:var(--gr);color:#fff}.wiz-dot.active{background:var(--ac);border-color:var(--ac);color:#fff}
.wiz-line{flex:1;height:1px;background:var(--bd);margin:0 4px}.wiz-line.done{background:var(--gr)}
.wiz-card{background:var(--s1);border:1px solid var(--bd);border-radius:14px;padding:28px;margin-bottom:20px}
.wiz-title{font-size:20px;font-weight:700;margin-bottom:8px}.wiz-sub{color:var(--t2);font-size:14px;margin-bottom:24px;line-height:1.6}
.wiz-options{display:grid;gap:10px;margin-bottom:24px}
.wiz-opt{display:flex;align-items:center;gap:12px;padding:14px 16px;border-radius:10px;border:2px solid var(--bd);cursor:pointer;transition:.15s}
.wiz-opt:hover{border-color:var(--bd2);background:var(--s2)}.wiz-opt.sel{border-color:var(--ac);background:rgba(79,142,247,.06)}
.wiz-opt-icon{font-size:22px;flex-shrink:0}.wiz-opt-text{flex:1}
.wiz-opt-title{font-size:14px;font-weight:600;margin-bottom:2px}.wiz-opt-desc{font-size:12px;color:var(--t2);line-height:1.4}
.wiz-opt-check{width:18px;height:18px;border-radius:50%;border:2px solid var(--bd);transition:.15s;flex-shrink:0}
.wiz-opt.sel .wiz-opt-check{background:var(--ac);border-color:var(--ac)}
.wiz-nav{display:flex;justify-content:space-between;align-items:center}.wiz-progress{font-size:12px;color:var(--t2)}
::-webkit-scrollbar{width:5px;height:5px}::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--s3);border-radius:3px}
</style>
</head>
<body>
<div id="help-pop" class="help-pop" role="tooltip"></div>
<div class="layout">
<nav class="sidebar">
  <div class="logo">
    <span class="logo-icon">⚡</span>
    <span class="logo-text"><span>APF</span></span>
    <span class="logo-ver">v1.0.7</span>
  </div>
  <div class="status-pill" id="sb-status-pill">
    <div class="status-dot" id="sb-dot" style="background:var(--re)"></div>
    <span id="sb-status-text">Отключено</span>
  </div>
  <div class="nav">
    <button class="n on" data-page="dashboard" onclick="nav(this)">
      <span class="n-ic">◈</span> Dashboard
    </button>
    <button class="n" data-page="nodes" onclick="nav(this)">
      <span class="n-ic">◉</span> Узлы
      <span class="n-badge" id="nb-ok">0</span>
    </button>
    <button class="n" data-page="sources" onclick="nav(this)">
      <span class="n-ic">⊕</span> Источники
    </button>
    <button class="n" data-page="log" onclick="nav(this)">
      <span class="n-ic">≡</span> Лог
      <span class="n-badge warn" id="nb-leak" style="display:none">⚠</span>
    </button>
  </div>
  <div class="nav-sep"></div>
  <div class="nav-label">Настройка</div>
  <div class="nav">
    <button class="n" data-page="wizard" onclick="nav(this)">
      <span class="n-ic">★</span> Мастер настройки
    </button>
    <button class="n" data-page="settings" onclick="nav(this)">
      <span class="n-ic">⚙</span> Параметры
    </button>
    <button class="n" data-page="leakguard" onclick="nav(this);loadLeakGuard()">
      <span class="n-ic">🛡</span> Защита
      <span class="n-badge warn" id="nb-leakguard" style="display:none">!</span>
    </button>
    <button class="n" data-page="dpi" onclick="nav(this);loadDPIStatus()">
      <span class="n-ic">👁</span> DPI обход
      <span class="n-badge warn" id="nb-dpi" style="display:none">!</span>
    </button>
    <button class="n" data-page="fallback" onclick="nav(this);loadFallbackStatus()">
      <span class="n-ic">🛡</span> Резерв
    </button>
    <button class="n" data-page="catalog" onclick="nav(this);loadCatalog()">
      <span class="n-ic">📁</span> Каталог
    </button>
    <button class="n" data-page="adblock" onclick="nav(this);loadAdBlock()">
      <span class="n-ic">🚫</span> AdBlock
      <span class="n-badge warn" id="nb-adblock" style="display:none">•</span>
    </button>
    <button class="n" data-page="antiblock" onclick="nav(this);loadAntiBlock()">
      <span class="n-ic">🏠</span> Anti-Block
      <span class="n-badge warn" id="nb-antiblock" style="display:none">•</span>
    </button>
    <button class="n" data-page="help" onclick="nav(this)">
      <span class="n-ic">?</span> Помощь
    </button>
  </div>
  <div class="sb-bottom">
    <button class="n btn-red" onclick="doResetNet()" style="border:none;color:var(--re);width:100%">
      <span class="n-ic">↺</span> Сбросить сеть
    </button>
  </div>
</nav>

<main class="main">

<!-- ══ DASHBOARD ══ -->
<div class="page on" id="page-dashboard">
  <div class="cards">
    <div class="card">
      <div class="card-lbl">Статус</div>
      <div class="card-val" id="c-status" style="font-size:18px;margin-top:2px">Отключено</div>
    </div>
    <div class="card">
      <div class="card-lbl">Активный узел</div>
      <div class="card-val" id="c-node" style="font-size:13px;margin-top:4px">—</div>
      <div class="card-sub" id="c-mode"></div>
    </div>
    <div class="card">
      <div class="card-lbl">Задержка</div>
      <div class="card-val" id="c-lat">—</div>
      <div class="card-sub" id="c-score"></div>
    </div>
    <div class="card">
      <div class="card-lbl">Пул узлов</div>
      <div class="card-val" id="c-pool">—</div>
      <div class="card-sub" id="c-total"></div>
    </div>
    <!-- D3 (ТЗ v1.7 desktop, лот D-WEB-VERIFIED-UX): рядом с «Пул узлов» (TCP-статус) — отдельная
         карточка честного счётчика ПОДТВЕРЖДЁННЫХ трафиком узлов (stats.proven, engine.go
         GetStats() — IsProven(), см. комментарий там же). Та же вёрстка/классы, что у соседних
         карточек (card/card-lbl/card-val) — без card-sub, как и у карточки «Статус» выше. -->
    <div class="card">
      <div class="card-lbl">Узлов с трафиком</div>
      <div class="card-val" id="c-proven">—</div>
    </div>
    <div class="card" id="c-protection-card">
      <div class="card-lbl">Защита</div>
      <div class="card-val" id="c-protection" style="font-size:14px;margin-top:4px">—</div>
      <div class="card-sub" id="c-protection-sub"></div>
    </div>
  </div>
  <div class="btns">
    <button class="btn btn-pri" id="btn-conn" onclick="doConnect()">▶ Подключить</button>
    <button class="btn" onclick="doScan()" title="Проверить список узлов TCP-пробой без подключения — активное соединение не трогает. Для реального подключения — «Подключить» слева.">⟳ Сканировать</button>
    <button class="btn" onclick="doRescan()">↺ Полный сброс</button>
<button class="btn" onclick="doSweep()" title="Проверить ВЕСЬ список узлов TCP-пробой без подключения (ТЗ v1.3 F4): кто жив, кто мёртв. Продолжается с места прошлой остановки.">🔎 Сканировать все</button>
<span id="scan-status" style="font-size:12px;color:var(--t3);margin-left:8px"></span>
<!-- ТЗ v1.5 N-3 (L2-WEB): «Собрать список рабочих узлов» — проба РЕАЛЬНОГО трафика (HTTP через
     свой SOCKS-канал на узел, без подключения устройства), а не TCP-эхо, как «Сканировать все»
     выше. N-9: подпись честная — «выход в интернет проверен»/«канал проверен», НЕ «через туннель»
     (это отдельная TUN-проба при реальном подключении, см. C-20 UI_CONTRACT_v1.4 §2.4). -->
<button class="btn" onclick="doNodeCheck()" title="Поднять для каждого узла отдельный SOCKS-канал (без TUN) и реальным HTTP-запросом проверить, что через него проверен выход в интернет — не просто TCP-отклик. Останавливается сама, как только набралось достаточно рабочих узлов.">📡 Собрать список рабочих узлов</button><i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Поднимает для каждого узла отдельный SOCKS-канал (без подключения устройства) и настоящим HTTP-запросом проверяет, что через него РЕАЛЬНО проходит трафик — не только отвечает TCP-порт. Если вы подключены с включённым Kill Switch на Windows, ниже появится предупреждение: в этом случае проба покажет почти все узлы нерабочими, хотя это не так.">?</i>
<span id="node-check-status" style="font-size:12px;color:var(--t3);margin-left:8px"></span>
<!-- L5-WEB (ТЗ v1.4 §5): ручной харвест — обойти НАСТРОЕННЫЕ источники, снять ссылки узлов и
     добавить новые в пул (непроверенными; «рабочими» их сделает отдельная проба/скан). Движок сам
     ссылки-подписки НЕ качает — их число показывается, чтобы пользователь добавил источником сам. -->
<button class="btn" onclick="doHarvest()" title="Обойти настроенные источники и добавить найденные узлы в список (непроверенными — потом проверьте их «Собрать список рабочих узлов» или обычным сканом).">🌾 Обновить узлы (харвест)</button><i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Скачивает уже настроенные вами источники (подписки/каналы/страницы), находит в них ссылки узлов и добавляет новые в общий список. Узлы добавляются НЕПРОВЕРЕННЫМИ: работоспособность подтверждает отдельная проба трафика («Собрать список рабочих узлов») или подключение. Сам харвест в интернет за подписками по найденным ссылкам НЕ ходит — если такие ссылки встретятся, покажет их число, чтобы вы добавили источником вручную.">?</i>
<span id="harvest-status" style="font-size:12px;color:var(--t3);margin-left:8px"></span>
    <!-- Task A (2026-09-21): извлечение узлов из вставленного текста (детерминированный разбор,
         БЕЗ ИИ) — POST /api/nodes/harvest-text {text}. Прогресс/итог общие с харвестом источников
         выше: тот же #harvest-status и тот же loadHarvestStatus() (см. doHarvestText() в script). -->
    <div style="flex-basis:100%;display:flex;gap:8px;align-items:flex-start;margin-top:2px">
      <textarea class="inp" id="harvest-text-input" rows="2" style="resize:vertical;min-height:44px;max-width:520px" placeholder="Вставьте ссылки (vless:// vmess:// ss:// trojan://), base64-подписку или дамп из Telegram / страницы"></textarea>
      <button class="btn" onclick="doHarvestText()">🔎 Извлечь узлы из текста</button><i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Детерминированный разбор без ИИ: ищет в вставленном тексте ссылки узлов (vless/vmess/ss/trojan) и base64-подписки. Ссылки-подписки (http-адреса) сам НЕ скачивает — их число покажет в статусе ниже, такую ссылку добавьте источником вручную на странице «Источники». Найденные узлы входят в список НЕПРОВЕРЕННЫМИ — «рабочим» узел делает отдельная проба трафика («Собрать список рабочих узлов») или обычный скан.">?</i>
    </div>
    <button class="btn btn-red" id="btn-disc" onclick="doDisconnect()" style="display:none">■ Отключить</button>
    <!-- U-16-web / §1.1 UI_CONTRACT_v1.4: единое имя действия «⇄ Сменить сервер» на всех трёх
         UI (было «⇄ Сменить IP» здесь, «Сменить сервер» на Android, «⇄ Сменить сервер» в Wails). -->
    <button class="btn btn-warn btn-sm" id="btn-force-switch" onclick="doForceSwitch()" style="display:none" title="Переключить несмотря на активные сессии">⇄ Сменить сервер</button>
  </div>
  <!-- P0-2/UI-A-WEB (ТЗ v1.6, живой прогон 09-14): предупреждение из
       engine.NodeCheckStatusSnapshot.KillSwitchWarning (node_check.go) — непусто, только пока
       Windows+подключено+Kill Switch реально включён, ЧИСТО диагностика от loadNodeCheckStatus()
       ниже. Сама проба ничем не блокируется и не меняется этим баннером — только отображение. -->
  <div id="node-check-ks-warning" class="info-box warn" style="display:none"><span aria-hidden="true">⚠️</span> <span id="node-check-ks-warning-text"></span></div>
  <div style="font-size:11px;color:var(--t3);margin:-8px 0 10px" id="session-pill"></div>
  <!-- Быстрый доступ к Kill Switch/Системному прокси — та же пара, что в Настройках
       (id t-ks/t-sysproxy синхронизируются через setTogById), но под рукой на главном
       экране: важно видеть и контролировать оба сразу, т.к. Kill Switch в режиме
       прокси не защищает ничего без включённого системного прокси. -->
  <div class="quick-toggles">
    <div class="quick-toggle-item">
      <span class="srow-title">Kill Switch<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Блокирует ВЕСЬ исходящий трафик системы, если туннель пропадёт или ещё не поднят. В режиме прокси работает ТОЛЬКО вместе с «Системный прокси» рядом (оба должны быть включены разом) — иначе блокирует интернет целиком.">?</i></span>
      <button class="toggle on" id="t-ks-dash" onclick="togInstant(this,'enable_kill_switch','t-ks')"></button>
    </div>
    <div class="quick-toggle-item">
      <span class="srow-title">Системный прокси<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Направляет трафик обычных приложений через локальный прокси APF. В режиме прокси нужен ОБЯЗАТЕЛЬНО, если включён Kill Switch — без него Kill Switch заблокирует ВЕСЬ интернет, а не только цель.">?</i></span>
      <button class="toggle" id="t-sysproxy-dash" onclick="togInstant(this,'set_system_proxy','t-sysproxy')"></button>
    </div>
  </div>
  <!-- U-10 (ТЗ v1.4): togInstant раньше молча проглатывал отказ (400/сетевую ошибку) —
       тумблер просто «не нажимался» без единого слова (§7.3 UI_CONTRACT_v1.4). -->
  <div id="qt-err" style="display:none;font-size:12px;color:var(--re);margin:-6px 0 10px"></div>
  <div id="leak-alert" style="display:none"></div>
  <div class="chart-wrap">
    <div class="chart-hd">
      <span class="chart-title">Задержка</span>
      <span class="chart-cur" id="chart-cur">— мс</span>
    </div>
    <canvas id="lat-c" style="width:100%;height:56px;display:block"></canvas>
  </div>
  <div class="panel">
    <div class="panel-hd">Маршрут трафика</div>
    <div class="panel-bd" style="padding:12px 16px">
      <div class="chain" id="chain-row">
        <div class="chain-node you">Вы</div>
        <div class="chain-arr">→</div>
        <div class="chain-node" style="color:var(--t3)">Нет маршрута</div>
        <div class="chain-arr">→</div>
        <div class="chain-node inet">Интернет</div>
      </div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-hd">Добавить узел</div>
    <div class="panel-bd">
      <div class="inp-row">
        <input class="inp" id="add-link" placeholder="vless://...  vmess://...  ss://...  trojan://...">
        <button class="btn btn-pri" onclick="doAdd()">Добавить</button>
      </div>
      <div class="inp-fb" id="add-fb"></div>
      <!-- U-9 (ТЗ v1.4, минимум по В-1): /api/add-node-manual уже существовал на бэкенде
           (B-29), но не имел вызывателя во встроенном UI — редактор продвинутых полей. -->
      <div style="margin-top:8px"><a href="#" onclick="toggleManualAdd();return false" style="font-size:12px;color:var(--ac)">✎ Добавить вручную (продвинутые поля)</a></div>
      <div id="manual-add-form" style="display:none;margin-top:12px;padding-top:12px;border-top:1px solid var(--bd)">
        <div class="inp-row">
          <input class="inp" id="ma-name" placeholder="Название (необязательно)">
          <select class="inp sinp" id="ma-protocol" onchange="renderManualAddFields()" style="max-width:140px;width:auto">
            <option value="vless">VLESS</option>
            <option value="vmess">VMess</option>
            <option value="trojan">Trojan</option>
            <option value="ss">Shadowsocks</option>
          </select>
        </div>
        <div class="inp-row">
          <input class="inp" id="ma-address" placeholder="Адрес (IP или домен)">
          <input class="inp" id="ma-port" placeholder="Порт" style="max-width:100px">
        </div>
        <div id="ma-proto-fields"></div>
        <div class="inp-row">
          <button class="btn btn-pri" onclick="doAddManual()">Добавить узел</button>
        </div>
        <div class="inp-fb" id="ma-fb"></div>
      </div>
    </div>
  </div>
  <div class="panel" id="diag-panel">
    <div class="panel-hd">Диагностика сети</div>
    <div class="panel-bd" style="padding:0">
      <div class="srow" style="padding:9px 16px">
        <span class="srow-title">Тип блокировки</span>
        <span id="diag-type" style="font-family:monospace;font-size:12px;color:var(--ye)">—</span>
      </div>
      <div class="srow" style="padding:9px 16px">
        <span class="srow-title">Стратегия</span>
        <span id="diag-strat" style="font-size:12px;color:var(--t2)">—</span>
      </div>
      <div class="srow" style="padding:9px 16px;border:none">
        <span class="srow-title">IPv6 Guard / WebRTC Guard</span>
        <span id="diag-guards" style="font-size:12px;color:var(--t2)">—</span>
      </div>
      <div class="srow" style="padding:9px 16px;border:none">
        <span class="srow-title">Последний rollback</span>
        <span id="diag-rollback" style="font-size:12px;color:var(--t2);max-width:55%;text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">—</span>
      </div>
      <div class="srow" style="padding:9px 16px;border:none">
        <span class="srow-title">Watchdog событие</span>
        <span id="diag-watchdog" style="font-size:12px;color:var(--t2);max-width:55%;text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">—</span>
      </div>
    </div>
  </div>
  <div class="btns">
    <button class="btn btn-warn btn-sm" onclick="doResetNet()">⚠ Сбросить сетевые настройки</button>
  </div>
</div>

<!-- ══ NODES ══ -->
<div class="page" id="page-nodes">
  <!-- U-9 (ТЗ v1.4, минимум по В-1): ?view= уже существовал на бэкенде (F3/GetNodesView), но
       не имел вкладок во встроенном UI — только клиентский фильтр по статусу (ряд ниже). -->
  <div class="btns" style="margin-bottom:6px">
    <button class="btn btn-sm btn-pri" data-v="" onclick="setView(this)">Все узлы</button>
    <button class="btn btn-sm" data-v="proven" onclick="setView(this)">Подтверждённые трафиком</button><i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Показывает только узлы, для которых хотя бы раз подтверждён реальный трафик (значок ✅ или 🟢 в колонке «Проверка») — не просто отвечающие по TCP. Список обновляется кнопкой «Собрать список рабочих узлов» на главном экране.">?</i>
    <button class="btn btn-sm" data-v="manual" onclick="setView(this)">Ручные</button>
    <button class="btn btn-sm" data-v="favorites" onclick="setView(this)">Избранные</button>
    <button class="btn btn-sm" data-v="banned" onclick="setView(this)">Забаненные</button>
    <button class="btn btn-sm" data-v="removed" onclick="setView(this)">Удалённые</button>
  </div>
  <div id="nodes-counter" style="font-size:12px;color:var(--t2);margin:-2px 0 10px"></div>
  <!-- U-17-web (ТЗ v1.4, UI_CONTRACT §7.2): «узлы не сохранены: <причина>» рядом со списком
       узлов, пока last_persist_error непусто (диагностика, не connection state — движок
       намеренно не пишет это поле в GetState()). Постоянная подсказка, не toast/диалог. -->
  <div id="persist-error-alert" class="info-box danger" style="display:none"></div>
  <div id="nodes-removed-box" style="display:none;margin-bottom:10px">
    <div class="info-box info" id="nodes-removed-info"></div>
    <button class="btn btn-sm" onclick="doRestoreRemoved()">♻ Восстановить все удалённые</button>
  </div>
  <div class="btns" id="nodes-status-filters">
    <input class="inp" id="nodes-search" placeholder="Поиск..." oninput="filterNodes()" style="max-width:240px">
    <button class="btn btn-sm" data-f="all" onclick="setF(this)">Все</button>
    <button class="btn btn-sm" data-f="ok" onclick="setF(this)">OK</button>
    <button class="btn btn-sm" data-f="slow" onclick="setF(this)">Медленные</button>
    <button class="btn btn-sm" data-f="blocked" onclick="setF(this)">Заблок.</button>
    <span style="margin-left:auto;font-size:11px;color:var(--t2)" id="nodes-cnt"></span>
  </div>
  <div class="panel" style="overflow-x:auto" id="nodes-table-panel">
    <table class="tbl">
      <thead><tr><th>Название</th><th>Протокол</th><th>Адрес</th><th>Задержка</th><th>Score<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Оценка по итогам обычного TCP-скана: выше — меньше задержка/потери/джиттер и свежее последняя проверка; список сортируется по этому числу автоматически (лучшие сверху). Это НЕ показатель того, что через узел проходит настоящий трафик — для этого смотрите колонку «Проверка».">?</i></th><th>Статус<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Отвечает ли узел по TCP при обычном сканировании пула (OK/Медленные/Заблок./Бан) — это только проверка порта, не подтверждение реального трафика. За честной проверкой следите по колонке «Проверка» правее.">?</i></th><th>Проверка<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Значок показывает, проходил ли через узел РЕАЛЬНЫЙ трафик (проба «Собрать список рабочих узлов»), а не просто TCP-ответ: ✅/🟢 — проходил (свежо/давно), ⚠️ — раньше проходил, но последняя проба провалилась, 🟡 — ещё не проверялся трафиком, 🔴 — не отвечает. Точная причина — во всплывающей подсказке на самом значке.">?</i></th><th>Действия</th></tr></thead>
      <tbody id="nodes-body"><tr><td colspan="8" style="text-align:center;padding:30px;color:var(--t3)">Нажмите «Сканировать» для загрузки узлов</td></tr></tbody>
    </table>
  </div>
</div>

<!-- ══ SOURCES ══ -->
<div class="page" id="page-sources">
  <div class="info-box info">APF автоматически обновляет источники каждые 6–12 часов.</div>
  <div id="sources-list"></div>
</div>

<!-- ══ LOG ══ -->
<div class="page" id="page-log">
  <div class="btns">
    <button class="btn btn-sm" onclick="clearLog()">Очистить</button>
      <a class="btn btn-sm" href="/api/logs/export" download title="Скачать полный лог-файл (ротация 5×2 МБ, 72 ч; пароли и ключи замаскированы)">💾 Экспорт лога</a>
    <span style="font-size:11px;color:var(--t2);align-self:center" id="log-cnt">0 записей</span>
  </div>
  <div class="logbox" id="logbox"></div>
</div>

<!-- ══ LEAKGUARD ══ -->
<div class="page" id="page-leakguard">
  <div class="info-box info" id="lg-info">
    Загрузка статуса защиты...
  </div>

  <div class="lg-grid">
    <div class="lg-card" id="lg-ipv6-card">
      <div class="lg-icon">🔒</div>
      <div class="lg-title">IPv6 Leak Block<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="На Windows реальную блокировку IPv6-утечки при активном туннеле обеспечивает Kill Switch (в TUN-режиме), не этот переключатель напрямую — здесь он в основном фиксирует намерение и (на Linux) реально отключает IPv6 через sysctl. Оставляйте включённым по умолчанию.">?</i></div>
      <div class="lg-status" id="lg-ipv6-status">Проверяю...</div>
      <div class="srow-sub">Блокирует IPv6-трафик мимо VPN-туннеля. Без этого провайдер видит реальный IP через IPv6.</div>
      <button class="btn btn-sm" id="lg-ipv6-btn" onclick="toggleIPv6()">Включить</button>
    </div>
    <div class="lg-card" id="lg-webrtc-card">
      <div class="lg-icon">🌐</div>
      <div class="lg-title">WebRTC Guard<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Браузеры через WebRTC могут раскрыть реальный IP в обход VPN — известная утечка, о которой сам VPN-протокол не знает. Выключайте, только если нужны WebRTC-звонки и защита им мешает — тогда используйте браузерные расширения вместо этого переключателя.">?</i></div>
      <div class="lg-status" id="lg-webrtc-status">Проверяю...</div>
      <div class="srow-sub">Блокирует STUN-серверы. Без этого браузер раскрывает реальный IP через WebRTC (JavaScript).</div>
      <button class="btn btn-sm" id="lg-webrtc-btn" onclick="toggleWebRTC()">Включить</button>
    </div>
  </div>

  <!-- DNS Leak Test -->
  <div class="panel">
    <div class="panel-hd">
      DNS Leak Test
      <button class="btn btn-sm btn-gr" onclick="runDNSTest()" id="dns-test-btn">▶ Проверить</button>
    </div>
    <div class="panel-bd">
      <div class="srow-sub" style="margin-bottom:10px">
        Проверяет что DNS-запросы идут <b>через туннель</b>, а не напрямую к провайдеру. Провайдер видит DNS → провайдер видит какие сайты вы посещаете.
      </div>
      <div class="dns-result" id="dns-result">Нажмите «Проверить» для запуска теста (~10 секунд)</div>
    </div>
  </div>

  <!-- Шифрование -->
  <div class="panel">
    <div class="panel-hd">
      🔐 Шифрование хранилища
    </div>
    <div class="panel-bd">
      <div class="srow-sub" style="margin-bottom:12px">
        Шифрует <code>nodes_cache.json</code> алгоритмом AES-256-GCM с мастер-паролем. Без пароля — список серверов невозможно прочитать.
        PBKDF2 с 600 000 итерациями защищает от брутфорса.
      </div>
      <div class="inp-row" style="margin-bottom:8px">
        <input class="inp" type="password" id="crypto-pwd" placeholder="Мастер-пароль (минимум 12 символов)">
        <button class="btn btn-pri" onclick="setCrypto()">Включить</button>
        <button class="btn btn-red btn-sm" onclick="disableCrypto()">Выкл.</button>
      </div>
      <div class="inp-fb" id="crypto-fb"></div>
      <div class="info-box warn" style="margin-top:10px;margin-bottom:0">
        ⚠ Без мастер-пароля APF не сможет загрузить список серверов при следующем запуске. Запомни пароль.
      </div>
    </div>
  </div>

  <!-- WebRTC браузерные инструкции -->
  <div class="panel">
    <div class="panel-hd">Браузерная защита от WebRTC</div>
    <div class="panel-bd">
      <div class="srow-sub" style="margin-bottom:12px">
        Файрвол блокирует публичные STUN-серверы, но сайт может использовать свой STUN. Для полной защиты — отключите WebRTC в браузере:
      </div>
      <div class="browser-tab" id="browser-tab">
        <button class="on" onclick="showBrowser(this,'chrome')">Chrome</button>
        <button onclick="showBrowser(this,'firefox')">Firefox</button>
        <button onclick="showBrowser(this,'brave')">Brave</button>
        <button onclick="showBrowser(this,'edge')">Edge</button>
      </div>
      <div class="browser-steps" id="browser-steps">Загрузка...</div>
      <button class="btn btn-sm btn-gr" style="margin-top:10px" onclick="downloadFirefoxJS()" id="ff-dl-btn" style="display:none">
        ⬇ Скачать user.js для Firefox
      </button>
    </div>
  </div>

  <!-- Аварийное удаление -->
  <div class="panel">
    <div class="panel-hd" style="color:var(--re)">🚨 Аварийное удаление</div>
    <div class="panel-bd">
      <div class="srow-sub" style="margin-bottom:12px">
        Мгновенно удаляет все данные APF: конфиги, кэш серверов, логи, ключи. Сначала останавливает sing-box и сбрасывает сеть.
        <br><br>
        <b>Горячая клавиша:</b> <code id="hotkey-label">Ctrl+Shift+F12</code> — только удаляет данные, не бинарники.
        Регистрирует и слушает её только запущенное окно APF (Wails-приложение); эта веб-страница сама по себе
        глобальную комбинацию клавиш не ловит, даже когда открыта.
      </div>
      <div class="wipe-zone">
        <div style="font-size:13px;color:var(--t2);margin-bottom:12px">
          Для подтверждения введи <code style="color:var(--re)">WIPE</code> и нажми кнопку:
        </div>
        <input class="wipe-confirm" id="wipe-confirm" placeholder="Введите WIPE для подтверждения" oninput="checkWipeConfirm()">
        <div style="display:flex;gap:8px;justify-content:center;margin-top:12px">
          <button class="btn btn-warn btn-sm" id="wipe-data-btn" disabled onclick="doWipe(false)">
            🗑 Удалить данные APF
          </button>
          <button class="btn btn-red btn-sm" id="wipe-all-btn" disabled onclick="doWipe(true)">
            💀 Удалить всё (+ бинарники)
          </button>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- ══ SETTINGS ══ -->
<div class="page" id="page-settings">
  <div class="panel">
    <div class="panel-hd">Соединение</div>
    <div class="panel-bd">
      <!-- ТЗ v1.3 F6 (D1/D2 HIGH): раньше режим VPN/прокси нельзя было сменить нигде, кроме
           Wails-GUI — headless/веб-путь (cmd/apf, apf-svc) был лишён этого переключателя, хотя
           backend (PatchConfig connection_mode) давно его поддерживает. -->
      <div class="srow">
        <div class="srow-l"><div class="srow-title">Режим подключения<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Прокси: работает только то, что явно настроено на SOCKS5/HTTP 127.0.0.1 — легче поднять, ничего не требует от ОС. VPN: создаёт системный TUN-адаптер, через него идёт ВЕСЬ трафик ОС (включая сторонние приложения), может запросить права администратора. Нельзя сменить при активном подключении — сначала отключитесь.">?</i></div><div class="srow-sub">Смена требует отключения текущей сессии</div></div>
        <select class="sinp" id="s-connmode" style="width:120px">
          <option value="proxy">Прокси</option>
          <option value="vpn">VPN (TUN)</option>
          <option value="hybrid">Гибрид</option>
        </select>
      </div>
      <div class="srow">
        <div class="srow-l"><div class="srow-title">Kill Switch<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Блокирует ВЕСЬ исходящий трафик системы, если туннель пропадёт или ещё не поднят — защита от утечки реального IP при обрыве VPN. В режиме прокси работает ТОЛЬКО вместе с «Системный прокси» ниже (оба должны быть включены разом) — иначе блокирует интернет целиком, подключение будет честно отказывать. Включайте для гарантии от утечек; выключайте, если тестируете нестабильные узлы и не хотите терять интернет на время автопереключения.">?</i></div><div class="srow-sub">Блокировать трафик при потере туннеля</div></div>
        <button class="toggle on" id="t-ks" onclick="tog(this,'enable_kill_switch')"></button>
      </div>
      <div class="srow">
        <div class="srow-l"><div class="srow-title">Системный прокси<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Направляет трафик обычных приложений через локальный прокси APF, меняя системные настройки прокси Windows. В режиме прокси ОБЯЗАТЕЛЕН вместе с Kill Switch — без него Kill Switch блокирует ВЕСЬ интернет, а не только цель. Включайте вместе с Kill Switch или если хотите, чтобы приложения работали через APF без ручной настройки прокси в каждом.">?</i></div><div class="srow-sub">В режиме прокси ОБЯЗАТЕЛЕН вместе с Kill Switch — иначе Kill Switch заблокирует весь интернет, а не только цель</div></div>
        <button class="toggle" id="t-sysproxy" onclick="tog(this,'set_system_proxy')"></button>
      </div>
      <div class="srow">
        <div class="srow-l"><div class="srow-title">Автоподключение при старте<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Подключается к лучшему узлу автоматически при запуске APF, без нажатия «Подключить». Включайте для защиты сразу при старте компьютера; выключайте, если настраиваете параметры и не хотите неожиданного автоподключения.">?</i></div></div>
        <button class="toggle on" id="t-auto" onclick="tog(this,'auto_connect')"></button>
      </div>
      <div class="srow">
        <div class="srow-l"><div class="srow-title">Переключать только при потере связи<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Не переключает узел просто потому, что нашёлся вариант получше — только при реальном сбое. Стабильнее для активных сессий (звонки, скачивание, логины). Выключите, если важнее средняя скорость, чем стабильность одного узла.">?</i></div><div class="srow-sub">Стабильнее для активных сессий</div></div>
        <button class="toggle on" id="t-stab" onclick="tog(this,'switch_only_on_fail')"></button>
      </div>
      <div class="srow">
        <div class="srow-l"><div class="srow-title">Цепочка VPN→Proxy<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Двойной туннель: сначала VPN-узел, затем ещё один прокси-узел поверх — сложнее для DPI-анализа ценой скорости. Включайте, если провайдер блокирует одиночные VPN-протоколы; выключайте, если обычное подключение и так проходит.">?</i></div><div class="srow-sub">Двойной туннель, медленнее но надёжнее</div></div>
        <button class="toggle" id="t-chain" onclick="tog(this,'enable_chain')"></button>
      </div>
      <!-- [консилиум, TZ_TAILS_HARDENING_2026-08-31.md кластер A, находка №2] раньше этого
           тумблера не было во встроенном веб-UI вовсе — паритет с desktop (Wails) GUI, где он
           уже есть, был нарушен: в headless-режиме (cmd/apf без Wails) включить multi-hop было
           физически нечем. -->
      <div class="srow">
        <div class="srow-l"><div class="srow-title">Многохоповая цепочка (разнообразие протоколов)<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Уточняет «Цепочка VPN→Proxy» выше: когда цепочка всё равно строится (либо включена явно, либо APF сам эскалирует при глубокой блокировке), выбирать узлы РАЗНЫХ протоколов для каждого звена, а не просто два узла с максимальным Score. Не работает сама по себе без «Цепочка VPN→Proxy» или автоматической эскалации.">?</i></div><div class="srow-sub">Выбирать узлы с разными протоколами на каждом звене цепочки</div></div>
        <button class="toggle" id="t-multihop" onclick="tog(this,'multihop_enabled')"></button>
      </div>
      <div class="srow">
        <div class="srow-l"><div class="srow-title">Число хопов в цепочке<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Сколько звеньев в многохоповой цепочке: 2 — быстрее и требует меньше рабочих узлов; 3 — анонимнее (ни один узел не видит одновременно и вас, и цель), но каждое звено добавляет задержку и точку отказа. Другие значения недопустимы — откатываются на 2.">?</i></div><div class="srow-sub">3 хопа анонимнее, но медленнее и требует больше рабочих узлов в пуле</div></div>
        <select class="sinp" id="s-multihop-count" style="width:100px">
          <option value="2">2 хопа</option>
          <option value="3">3 хопа</option>
        </select>
      </div>
      <div class="srow">
        <div class="srow-l"><div class="srow-title">Минимальное время на сервере (сек)<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Сколько ждать после подключения, прежде чем разрешить обычное (не аварийное) переключение на другой узел — защита от бессмысленного «дёргания» между близкими по качеству серверами.">?</i></div></div>
        <input class="sinp" id="s-uptime" type="number" value="120" min="30" max="3600">
      </div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-hd">Защита (Фаза 5)</div>
    <div class="panel-bd">
      <div class="srow">
        <div class="srow-l"><div class="srow-title">IPv6 Leak Block<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="На Windows реальную блокировку IPv6-утечки при активном туннеле обеспечивает Kill Switch (в TUN-режиме), не этот переключатель напрямую — здесь он в основном фиксирует намерение и (на Linux) реально отключает IPv6 через sysctl. Оставляйте включённым по умолчанию.">?</i></div><div class="srow-sub">Блокировать IPv6 мимо VPN при старте</div></div>
        <button class="toggle on" id="t-ipv6" onclick="tog(this,'block_ipv6_leak')"></button>
      </div>
      <div class="srow">
        <div class="srow-l"><div class="srow-title">WebRTC Guard<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Браузеры через WebRTC могут раскрыть реальный IP в обход VPN — известная утечка, о которой сам VPN-протокол не знает. Выключайте, только если нужны WebRTC-звонки и защита им мешает — тогда используйте браузерные расширения вместо этого переключателя.">?</i></div><div class="srow-sub">Блокировать STUN-серверы</div></div>
        <button class="toggle on" id="t-webrtc" onclick="tog(this,'block_webrtc')"></button>
      </div>
      <div class="srow">
        <div class="srow-l"><div class="srow-title">Фильтр безопасных узлов<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Отсеивает узлы с плохой репутацией (известные botnet/spam-источники) при сканировании пула. Оставляйте включённым — выключение расширяет список кандидатов ценой безопасности.">?</i></div><div class="srow-sub">Исключать botnet/spam серверы</div></div>
        <button class="toggle on" id="t-safe" onclick="tog(this,'safety_filter')"></button>
      </div>
      <div class="srow">
        <div class="srow-l"><div class="srow-title">Интервал DNS Leak Test (сек, 0=выкл)<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Как часто проверять, не идут ли DNS-запросы мимо туннеля. 0 — проверку выключить полностью (не рекомендуется, вы не узнаете об утечке DNS).">?</i></div></div>
        <input class="sinp" id="s-dns-interval" type="number" value="300" min="0" max="3600">
      </div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-hd">Сеть</div>
    <div class="panel-bd">
      <div class="srow">
        <div class="srow-l"><div class="srow-title">SOCKS5 порт<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Локальный порт, на котором APF слушает SOCKS5 (HTTP — на следующем после него). Меняйте только если порт 10808 занят другой программой на этой машине. Допустимо 1024–65530. После смены APF нужно перезапустить.">?</i></div><div class="srow-sub">127.0.0.1:порт в настройках браузера</div></div>
        <input class="sinp" id="s-port" type="number" value="10808">
      </div>
      <div class="srow">
        <div class="srow-l"><div class="srow-title">Интервал мониторинга (сек)<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Как часто (в секундах) APF проверяет, жив ли текущий узел. Меньше — быстрее замечает проблему и переключается, но чаще нагружает узел проверками. Больше — реже проверяет, медленнее реагирует на обрыв. По умолчанию подходит для большинства случаев, уменьшайте только если узлы часто «висят» незамеченными. Допустимо 5–3600 с; вне диапазона — вернётся значение по умолчанию.">?</i></div></div>
        <input class="sinp" id="s-interval" type="number" value="30" min="10" max="300">
      </div>
    </div>
  </div>
  <!-- W3 (ТЗ v1.5 §5, TZ_v1.5_NODE_CATALOG_2026-09-14, лот L2-WEB-B): интервал пересмотра
       системного избранного. Отдельная ручка (/api/catalog-review-interval, instant-apply как
       AdBlock-профиль/Sticky policy выше) — НЕ часть общего saveSettings()/PatchConfig, тот же
       приём единственного писателя, что и у SetAdBlockProfile/SetStickyPolicy на бэкенде. -->
  <div class="panel">
    <div class="panel-hd">Каталог узлов</div>
    <div class="panel-bd">
      <div class="srow">
        <div class="srow-l"><div class="srow-title">Интервал пересмотра системного избранного<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Узлы, автоматически добавленные в избранное пробой трафика («📡 Собрать список рабочих узлов»), пересматриваются на СЛЕДУЮЩЕЙ ручной сборке каталога: провалившие пробу снимаются из избранного, только если с последнего подтверждения трафиком прошло больше выбранного здесь срока. Сборка каталога всегда запускается вручную — автоматического сканирования в фоне нет.">?</i></div><div class="srow-sub">Сборка каталога — всегда вручную, авто-скана нет</div></div>
        <select class="sinp" id="s-catalog-review-interval" onchange="setCatalogReviewInterval(this.value)" style="width:140px">
          <option value="each_scan">Каждая сборка</option>
          <option value="daily">Раз в сутки</option>
          <option value="weekly">Раз в неделю</option>
          <option value="monthly">Раз в месяц</option>
        </select>
      </div>
      <!-- ТЗ v1.7 (PROBE-DEPTH-SETTING), запрос владельца 09-14: по умолчанию «Собрать
           список» пробует реальным трафиком только top-30 узлов по TCP-рангу — владелец
           хочет находить больше подтверждённых узлов. Часть общего saveSettings()/
           loadConfig() (как check_interval_sec/listen_port ниже), НЕ отдельная ручка
           instant-apply, как s-catalog-review-interval выше. -->
      <div class="srow">
        <div class="srow-l"><div class="srow-title">Глубина проверки узлов трафиком<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Сколько верхних по TCP-рангу узлов проверять реальным трафиком при «📡 Собрать список рабочих узлов». Больше узлов — больше шанс найти рабочие, но сканирование идёт дольше. «Все рабочие» проверяет весь пул целиком (узел с трафиком может стоять ниже потолка) — самый полный, но и самый долгий режим.">?</i></div><div class="srow-sub">Проверка идёт по топ-N лучших по TCP-задержке (или по всему пулу)</div></div>
        <select class="sinp" id="s-probe-depth" style="width:180px">
          <option value="30">Быстро (30 узлов)</option>
          <option value="60">Обычно (60 узлов)</option>
          <option value="150">Тщательно (150 узлов)</option>
          <option value="1000000000">Все рабочие (весь пул)</option>
        </select>
      </div>
    </div>
  </div>
  <div class="btns">
    <button class="btn btn-pri" onclick="saveSettings()">Сохранить настройки</button>
    <span style="font-size:11px;color:var(--t2);align-self:center" id="settings-status"></span>
  </div>
</div>

<!-- ══ WIZARD ══ -->
<div class="page" id="page-wizard">
<div class="wizard">
  <div id="wiz-setup">
  <div class="wiz-steps" id="wiz-steps">
    <div class="wiz-step"><div class="wiz-dot active" id="wd-0">1</div><div class="wiz-line" id="wl-0"></div></div>
    <div class="wiz-step"><div class="wiz-dot" id="wd-1">2</div><div class="wiz-line" id="wl-1"></div></div>
    <div class="wiz-step"><div class="wiz-dot" id="wd-2">3</div><div class="wiz-line" id="wl-2"></div></div>
    <div class="wiz-step"><div class="wiz-dot" id="wd-3">4</div></div>
  </div>
  <div class="wiz-card" id="ws-0">
    <div class="wiz-title">Где вы находитесь?</div>
    <div class="wiz-sub">APF подберёт оптимальные серверы и протоколы для вашего региона.</div>
    <div class="wiz-options">
      <div class="wiz-opt sel" data-val="RU" onclick="selWiz(this,'country')"><span class="wiz-opt-icon">🇷🇺</span><div class="wiz-opt-text"><div class="wiz-opt-title">Россия</div><div class="wiz-opt-desc">РКН · Instagram, Threads, некоторые VPN</div></div><div class="wiz-opt-check"></div></div>
      <div class="wiz-opt" data-val="BY" onclick="selWiz(this,'country')"><span class="wiz-opt-icon">🇧🇾</span><div class="wiz-opt-text"><div class="wiz-opt-title">Беларусь</div><div class="wiz-opt-desc">Аналогично РФ + политические блокировки</div></div><div class="wiz-opt-check"></div></div>
      <div class="wiz-opt" data-val="OTHER" onclick="selWiz(this,'country')"><span class="wiz-opt-icon">🌍</span><div class="wiz-opt-text"><div class="wiz-opt-title">Другая страна</div><div class="wiz-opt-desc">Иран, Китай, Казахстан...</div></div><div class="wiz-opt-check"></div></div>
    </div>
    <div class="wiz-nav"><span class="wiz-progress">Шаг 1 из 4</span><button class="btn btn-pri" onclick="wizNext(0)">Далее →</button></div>
  </div>
  <div class="wiz-card" id="ws-1" style="display:none">
    <div class="wiz-title">Режим работы</div>
    <div class="wiz-sub">Баланс между скоростью и уровнем маскировки трафика.</div>
    <div class="wiz-options">
      <div class="wiz-opt sel" data-val="auto" onclick="selWiz(this,'mode')"><span class="wiz-opt-icon">⚡</span><div class="wiz-opt-text"><div class="wiz-opt-title">Автоматически (рекомендуется)</div><div class="wiz-opt-desc">APF сам выбирает. Переключается только при потере связи.</div></div><div class="wiz-opt-check"></div></div>
      <div class="wiz-opt" data-val="stealth" onclick="selWiz(this,'mode')"><span class="wiz-opt-icon">🛡</span><div class="wiz-opt-text"><div class="wiz-opt-title">Максимальная защита</div><div class="wiz-opt-desc">Reality + цепочка + IPv6/WebRTC блок. Провайдер не видит VPN.</div></div><div class="wiz-opt-check"></div></div>
    </div>
    <div class="wiz-nav"><button class="btn" onclick="wizBack(1)">← Назад</button><span class="wiz-progress">Шаг 2 из 4</span><button class="btn btn-pri" onclick="wizNext(1)">Далее →</button></div>
  </div>
  <div class="wiz-card" id="ws-2" style="display:none">
    <div class="wiz-title">Защита устройства</div>
    <div class="wiz-sub">Рекомендуем включить все пункты для максимальной безопасности.</div>
    <div class="wiz-options">
      <div class="wiz-opt sel" data-val="full" onclick="selWiz(this,'security')"><span class="wiz-opt-icon">🔐</span><div class="wiz-opt-text"><div class="wiz-opt-title">Полная защита</div><div class="wiz-opt-desc">Kill Switch + IPv6 Block + WebRTC Guard + DNS защита. Провайдер не видит ничего.</div></div><div class="wiz-opt-check"></div></div>
      <div class="wiz-opt" data-val="standard" onclick="selWiz(this,'security')"><span class="wiz-opt-icon">🔒</span><div class="wiz-opt-text"><div class="wiz-opt-title">Стандартная</div><div class="wiz-opt-desc">Kill Switch + DNS. Быстрее, но IPv6 и WebRTC не защищены.</div></div><div class="wiz-opt-check"></div></div>
    </div>
    <div class="wiz-nav"><button class="btn" onclick="wizBack(2)">← Назад</button><span class="wiz-progress">Шаг 3 из 4</span><button class="btn btn-pri" onclick="wizNext(2)">Далее →</button></div>
  </div>
  <div class="wiz-card" id="ws-3" style="display:none">
    <div class="wiz-title" style="color:var(--gr)">✓ Готово!</div>
    <div class="wiz-sub">APF настроен. Параметры:</div>
    <div id="wiz-summary" style="margin-bottom:20px"></div>
    <div class="info-box ok">Нажмите «Применить» — APF найдёт лучший сервер (~30 сек) и включит защиты.</div>
    <div class="wiz-nav" style="margin-top:16px"><button class="btn" onclick="wizBack(3)">← Назад</button><button class="btn btn-pri" onclick="wizFinish()">✓ Применить и подключить</button></div>
  </div>
  </div><!-- /wiz-setup -->
  <div id="wiz-privacy" style="display:none">
    <div class="wiz-steps">
      <div class="wiz-step"><div class="wiz-dot active" id="pwd-0">1</div><div class="wiz-line" id="pwl-0"></div></div>
      <div class="wiz-step"><div class="wiz-dot" id="pwd-1">2</div><div class="wiz-line" id="pwl-1"></div></div>
      <div class="wiz-step"><div class="wiz-dot" id="pwd-2">3</div><div class="wiz-line" id="pwl-2"></div></div>
      <div class="wiz-step"><div class="wiz-dot" id="pwd-3">4</div></div>
    </div>
    <div class="wiz-card" id="pws-0">
      <div class="wiz-title">Защита от утечек IP</div>
      <div class="wiz-sub">Закрываем каналы, по которым ваш реальный IP может «утечь» мимо туннеля.</div>
      <div class="wiz-options">
        <div class="wiz-opt sel" data-val="full" onclick="selPriv(this,'ip_leak')"><span class="wiz-opt-icon">🔒</span><div class="wiz-opt-text"><div class="wiz-opt-title">IPv6 Guard + WebRTC Guard (рекомендуется)</div><div class="wiz-opt-desc">Блокирует IPv6-утечки и STUN/WebRTC. Максимальная анонимность.</div></div><div class="wiz-opt-check"></div></div>
        <div class="wiz-opt" data-val="ipv6only" onclick="selPriv(this,'ip_leak')"><span class="wiz-opt-icon">🔸</span><div class="wiz-opt-text"><div class="wiz-opt-title">Только IPv6 Guard</div><div class="wiz-opt-desc">Если WebRTC мешает видеозвонкам в браузере.</div></div><div class="wiz-opt-check"></div></div>
        <div class="wiz-opt" data-val="skip" onclick="selPriv(this,'ip_leak')"><span class="wiz-opt-icon">⏩</span><div class="wiz-opt-text"><div class="wiz-opt-title">Оставить текущие настройки</div><div class="wiz-opt-desc">Ничего не менять на этом шаге.</div></div><div class="wiz-opt-check"></div></div>
      </div>
      <div class="wiz-nav"><span class="wiz-progress">Шаг 1 из 4</span><button class="btn btn-pri" onclick="privNext(0)">Далее →</button></div>
    </div>
    <div class="wiz-card" id="pws-1" style="display:none">
      <div class="wiz-title">Мониторинг DNS-утечек</div>
      <div class="wiz-sub">Периодическая проверка, что DNS-запросы идут строго через туннель.</div>
      <div class="wiz-options">
        <div class="wiz-opt sel" data-val="on" onclick="selPriv(this,'dns')"><span class="wiz-opt-icon">✅</span><div class="wiz-opt-text"><div class="wiz-opt-title">Авто-проверка каждые 5 минут (рекомендуется)</div><div class="wiz-opt-desc">APF сам предупредит при утечке DNS.</div></div><div class="wiz-opt-check"></div></div>
        <div class="wiz-opt" data-val="off" onclick="selPriv(this,'dns')"><span class="wiz-opt-icon">⏩</span><div class="wiz-opt-text"><div class="wiz-opt-title">Только вручную</div><div class="wiz-opt-desc">Проверять кнопкой на странице «Защита».</div></div><div class="wiz-opt-check"></div></div>
      </div>
      <div class="wiz-nav"><button class="btn" onclick="privBack(1)">← Назад</button><span class="wiz-progress">Шаг 2 из 4</span><button class="btn btn-pri" onclick="privNext(1)">Далее →</button></div>
    </div>
    <div class="wiz-card" id="pws-2" style="display:none">
      <div class="wiz-title">Блокировка рекламы и трекеров</div>
      <div class="wiz-sub">DNS-фильтрация рекламы и слежки. Можно отключить в любой момент.</div>
      <div class="wiz-options">
        <div class="wiz-opt sel" data-val="standard" onclick="selPriv(this,'adblock')"><span class="wiz-opt-icon">🟢</span><div class="wiz-opt-text"><div class="wiz-opt-title">Standard (~50k доменов, рекомендуется)</div><div class="wiz-opt-desc">Реклама + трекеры + вредоносные домены.</div></div><div class="wiz-opt-check"></div></div>
        <div class="wiz-opt" data-val="light" onclick="selPriv(this,'adblock')"><span class="wiz-opt-icon">🟡</span><div class="wiz-opt-text"><div class="wiz-opt-title">Light (~10k доменов)</div><div class="wiz-opt-desc">Только самая агрессивная реклама. Меньше ложных срабатываний.</div></div><div class="wiz-opt-check"></div></div>
        <div class="wiz-opt" data-val="disabled" onclick="selPriv(this,'adblock')"><span class="wiz-opt-icon">⏩</span><div class="wiz-opt-text"><div class="wiz-opt-title">Выключен</div><div class="wiz-opt-desc">Не фильтровать DNS.</div></div><div class="wiz-opt-check"></div></div>
      </div>
      <div class="wiz-nav"><button class="btn" onclick="privBack(2)">← Назад</button><span class="wiz-progress">Шаг 3 из 4</span><button class="btn btn-pri" onclick="privNext(2)">Далее →</button></div>
    </div>
    <div class="wiz-card" id="pws-3" style="display:none">
      <div class="wiz-title" style="color:var(--gr)">✓ Почти готово</div>
      <div class="wiz-sub">Проверьте выбранные настройки приватности:</div>
      <div id="priv-summary" style="margin-bottom:16px"></div>
      <div id="priv-status" style="font-size:13px;margin-bottom:12px;color:var(--t2)"></div>
      <div class="wiz-nav" style="margin-top:16px"><button class="btn" onclick="privBack(3)">← Назад</button><button class="btn btn-pri" onclick="privFinish()">✓ Применить</button></div>
    </div>
  </div>
</div>
</div>

<!-- ══ HELP ══ -->
<div class="page" id="page-help">
  <div class="panel"><div class="panel-hd">Быстрый старт</div><div class="panel-bd"><div style="font-size:13px;color:var(--t2);line-height:2"><b style="color:var(--t1)">1.</b> Нажмите <b style="color:var(--ac)">Подключить</b> — APF найдёт лучший сервер (~30 сек)<br><b style="color:var(--t1)">2.</b> Откройте Instagram, Telegram, ChatGPT — должны работать<br><b style="color:var(--t1)">3.</b> Если не открывается — <b style="color:var(--ac)">Сменить сервер</b><br><b style="color:var(--t1)">4.</b> Полное обновление серверов — <b style="color:var(--ac)">Полный сброс</b></div></div></div>
  <div class="panel"><div class="panel-hd">Настройка браузера</div><div class="panel-bd"><div style="font-size:13px;color:var(--t2);line-height:1.9">SOCKS5: <span style="font-family:monospace;color:var(--ac)">127.0.0.1:10808</span><br><b>Firefox:</b> Настройки → Сеть → SOCKS-прокси<br><b>Chrome:</b> Расширение Proxy SwitchyOmega</div></div></div>
  <div class="panel"><div class="panel-hd">Интернет не работает после APF?</div><div class="panel-bd"><div style="font-size:13px;color:var(--t2);line-height:1.9;margin-bottom:12px">Нажмите кнопку ниже — удалит все изменения APF в сетевых настройках и восстановит DNS.</div><div class="btns" style="margin-bottom:10px"><button class="btn btn-warn" onclick="doResetNet()">⚠ Восстановить сетевые настройки</button><button class="btn btn-pri" onclick="startRecoveryWizard()">🧭 Запустить мастер восстановления</button></div><div id="recovery-wizard-box" class="info-box info" style="display:none"><div style="font-size:13px;font-weight:600;margin-bottom:8px">Recovery Wizard</div><div id="recovery-wizard-status" style="font-size:12px;line-height:1.7;color:var(--t1)"></div><div class="btns" style="margin-top:10px;margin-bottom:8px"><button class="btn btn-sm" id="recovery-retry-btn" onclick="runRecoveryConnectivityCheck()" style="display:none">↻ Повторить проверку</button><button class="btn btn-sm btn-pri" id="recovery-safe-btn" onclick="applySafeSettingsAndConnect()" style="display:none">✓ Безопасные настройки и подключить</button></div><div id="recovery-checklist" style="display:none;font-size:12px;line-height:1.7;color:var(--t2)"></div></div></div></div>
  <div class="panel"><div class="panel-hd">🔒 Privacy Wizard</div><div class="panel-bd"><div style="font-size:13px;color:var(--t2);line-height:1.9;margin-bottom:12px">Быстрый мастер настройки приватности — IPv6 Guard, WebRTC Guard, DNS-мониторинг и AdBlock за 4 шага. Занимает ~2 минуты.</div><div class="btns"><button class="btn btn-pri" onclick="startPrivacyWizard()">🔒 Запустить Privacy Wizard</button></div></div></div>
</div>

<!-- ══ DPI ══ -->
<div class="page" id="page-dpi">
  <div class="panel">
    <div class="panel-hd">👁 Canary-тест
      <button class="btn btn-sm btn-gr" onclick="runCanaryTest()" id="canary-btn">▶ Тест</button>
    </div>
    <div class="panel-bd">
      <div class="srow-sub" style="margin-bottom:10px">Проверяет насколько хорошо маскирован трафик: TLS fingerprint, timing. При высоком score — автоматически включает противодействие.</div>
      <div id="canary-score-bar" style="background:var(--s2);border:1px solid var(--bd);border-radius:8px;padding:14px;margin-bottom:10px">
        <div style="display:flex;justify-content:space-between;margin-bottom:8px"><span style="font-size:12px;color:var(--t2)">Score (0=невиден, 100=очевиден)</span><span id="canary-score-label" style="font-family:monospace;font-size:13px;font-weight:700">-</span></div>
        <div style="background:var(--bd);border-radius:4px;height:8px;overflow:hidden"><div id="canary-score-fill" style="height:100%;width:0%;border-radius:4px;background:var(--gr);transition:.4s"></div></div>
      </div>
      <div id="canary-result" class="dns-result">▶ Нажмите «Тест» для запуска (~15 с)</div>
      <div id="canary-checks" style="display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:10px"></div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-hd">🔀 Traffic Padding <span style="font-weight:400;font-size:11px;color:var(--t2);text-transform:none;letter-spacing:0">(не реализовано)</span></div>
    <div class="panel-bd">
      <div class="info-box warn" style="margin-bottom:12px">Эта защита не реализована в движке APF — маскировка временных паттернов трафика сейчас не работает. Переключатели ниже отключены, чтобы не обещать защиту, которой нет.</div>
      <div class="srow">
        <div class="srow-l"><div class="srow-title">Стандартный (jitter ±50-200мс)<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Не реализовано: этот режим должен добавлять случайную задержку между пакетами, чтобы DPI не узнавал протокол по временным паттернам трафика — но движок не применяет её к туннелю.">?</i></div><div class="srow-sub">Скрывает timing fingerprint. Небольшая потеря скорости.</div></div>
        <span class="pill p-unk">Недоступно</span>
      </div>
      <div class="srow">
        <div class="srow-l"><div class="srow-title">Агрессивный (jitter ±100-500мс)<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Не реализовано: этот режим должен сильнее маскировать timing ценой заметно большей задержки — но движок не применяет её к туннелю.">?</i></div><div class="srow-sub">Максимальная маскировка. Включается автоматически при DPI детекции.</div></div>
        <span class="pill p-unk">Недоступно</span>
      </div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-hd">🌐 CDN Fronting (Cloudflare)<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Трафик уходит через воркер на популярном CDN (например Cloudflare Workers) вместо прямого подключения к VPN-серверу — блокировщику видно только обращение к CDN, а не к реальному серверу за ним. Требует СВОЙ развёрнутый воркер (скачайте worker.js кнопкой ниже, загрузите на workers.cloudflare.com — домены-заглушки не подойдут). Когда настраивать: провайдер блокирует IP VPN-серверов напрямую, но не блокирует весь CDN целиком. Когда не нужно: нет своего воркера или обычное подключение и так работает.">?</i></div>
    <div class="panel-bd">
      <div class="srow-sub" style="margin-bottom:12px">Трафик через Cloudflare CDN — DPI видит легитимный HTTPS. Требует свой Cloudflare Worker.</div>
      <div class="inp-row" style="margin-bottom:8px">
        <input class="inp" id="cdn-worker" placeholder="my-app.workers.dev">
        <button class="btn btn-pri" onclick="saveCDN()">✓ Сохранить</button>
        <button class="btn btn-sm" onclick="downloadWorkerScript()">⬇ worker.js</button>
      </div>
      <div class="inp-fb" id="cdn-fb"></div>
      <div class="info-box info" style="margin-top:10px;margin-bottom:0;font-size:12px">1. Скачай worker.js → 2. Загрузи на <a href="https://workers.cloudflare.com" target="_blank" style="color:var(--ac)">workers.cloudflare.com</a> → 3. Вставь домен</div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-hd">👤 ShadowTLS v3</div>
    <div class="panel-bd">
      <div class="srow-sub" style="margin-bottom:12px">Проходит полный TLS handshake с настоящим сайтом — DPI не отличает от HTTPS. Требует shadow-tls daemon на сервере.</div>
      <div class="srow">
        <div class="srow-l"><div class="srow-title">Включить ShadowTLS v3<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Маскирует хендшейк под настоящий TLS-хендшейк известного сайта (SNI) — для наблюдателя выглядит как обращение к этому сайту. Требует shadow-tls daemon на сервере и совпадающий пароль. Включайте, если провайдер блокирует по SNI/сертификату; без настроенного пароля/SNI просто не заработает.">?</i></div></div>
        <button class="toggle" id="t-stls" onclick="togShadowTLS(this)"></button>
      </div>
      <div id="stls-form" style="margin-top:12px;display:grid;gap:8px">
        <input class="inp" id="stls-server" placeholder="Реальный сервер: 203.0.113.7:8443 (где поднят shadow-tls daemon)">
        <input class="inp" id="stls-pwd" type="password" placeholder="HMAC пароль (теже на сервере)">
        <div class="inp-row">
          <input class="inp" id="stls-sni" placeholder="Маскировка (SNI): www.bing.com">
          <button class="btn btn-sm btn-gr" onclick="autoSelectSNI()">✨ Авто</button>
        </div>
        <button class="btn btn-pri btn-sm" onclick="saveShadowTLS()">✓ Сохранить</button>
        <div class="inp-fb" id="stls-fb"></div>
        <div style="font-size:11px;color:var(--t3)">Реальный сервер — это НЕ SNI: SNI лишь маскировка (что видит DPI), трафик уходит на адрес выше. Хорошие SNI: www.bing.com, www.microsoft.com, addons.mozilla.org<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Требует адрес РЕАЛЬНОГО сервера с shadow-tls daemon в формате host:port (не подставляйте домены-заглушки вроде example.com) — именно на него реально уходит трафик. Пароль — тот же, что задан на сервере (HMAC, совпадение обязательно). SNI — домен маскировки, который видит DPI-наблюдатель; можно подобрать кнопкой «✨ Авто».">?</i></div>
      </div>
    </div>
  </div>
</div>

<!-- ══ FALLBACK ══ -->
<div class="page" id="page-fallback">
  <!-- Watchdog -->
  <div class="panel">
    <div class="panel-hd">💘 Watchdog — монитор туннеля</div>
    <div class="panel-bd">
      <div class="srow-sub" style="margin-bottom:10px">HTTP-проверка туннеля каждые 15 секунд. При 3 подряд сбоях — автопереключение.</div>
      <div id="watchdog-status-box" style="background:var(--s2);border:1px solid var(--bd);border-radius:8px;padding:12px;font-size:13px">
        <div style="display:flex;justify-content:space-between;margin-bottom:6px">
          <span>Состояние:</span><span id="wd-state" style="font-family:monospace">-</span>
        </div>
        <div style="display:flex;justify-content:space-between;margin-bottom:6px">
          <span>Задержка:</span><span id="wd-latency" style="font-family:monospace">-</span>
        </div>
        <div style="display:flex;justify-content:space-between;margin-bottom:6px">
          <span>Сбоев:</span><span id="wd-fails" style="font-family:monospace">-</span>
        </div>
        <div style="display:flex;justify-content:space-between">
          <span>Проверок:</span><span id="wd-checks" style="font-family:monospace">-</span>
        </div>
        <div id="wd-error" style="color:var(--re);font-size:12px;margin-top:6px;display:none"></div>
      </div>
      <div style="margin-top:10px;background:var(--s2);border:1px solid var(--bd);border-radius:8px;padding:10px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;gap:8px">
          <div style="font-size:12px;color:var(--t2)">История watchdog (последние события)</div>
          <div style="display:flex;gap:6px">
            <span id="wd-history-new" style="display:none;font-size:10px;background:var(--ac2);color:#fff;padding:2px 8px;border-radius:99px;align-self:center">new</span>
            <button class="btn btn-sm" onclick="downloadWatchdogHistory()">⬇ JSON</button>
            <button class="btn btn-sm" onclick="copyWatchdogHistory()">⧉ Копировать</button>
            <button class="btn btn-sm btn-red" onclick="clearWatchdogHistory()">✖ Очистить</button>
          </div>
        </div>
        <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
          <button class="btn btn-sm" id="wd-chip-today" onclick="toggleWatchdogQuickChip('today')">Сегодня</button>
          <button class="btn btn-sm" id="wd-chip-crash" onclick="toggleWatchdogQuickChip('crash')">Только крахи</button>
          <button class="btn btn-sm" id="wd-chip-errors" onclick="toggleWatchdogQuickChip('errors')">С ошибками</button>
          <input id="wd-filter-query" class="inp" style="max-width:240px" placeholder="Поиск: event / описание / ошибка" oninput="applyWatchdogHistoryFilters()">
          <select id="wd-filter-kind" class="sinp" style="width:170px" onchange="applyWatchdogHistoryFilters()">
            <option value="all">Все события</option>
            <option value="crash">Только crash reset</option>
            <option value="normal">Только normal shutdown</option>
          </select>
          <label style="font-size:11px;color:var(--t2);display:flex;align-items:center;gap:4px">
            <input type="checkbox" id="wd-filter-errors" onchange="applyWatchdogHistoryFilters()"> Только с ошибками
          </label>
          <label style="font-size:11px;color:var(--t2);display:flex;align-items:center;gap:4px">
            Показать
            <select id="wd-filter-limit" class="sinp" style="width:75px" onchange="applyWatchdogHistoryFilters()">
              <option value="10">10</option>
              <option value="20">20</option>
              <option value="30" selected>30</option>
            </select>
          </label>
          <label style="font-size:11px;color:var(--t2);display:flex;align-items:center;gap:4px">
            Сортировка
            <select id="wd-filter-sort" class="sinp" style="width:110px" onchange="applyWatchdogHistoryFilters()">
              <option value="newest" selected>newest</option>
              <option value="oldest">oldest</option>
              <option value="severity">severity</option>
            </select>
          </label>
        </div>
        <div id="wd-history-stats" style="font-size:11px;color:var(--t3);margin-bottom:6px">shown: 0 / total: 0 · errors: 0 · crash resets: 0</div>
        <div id="wd-history-list" style="max-height:150px;overflow:auto;font-size:11px;line-height:1.7;color:var(--t2)">Загрузка...</div>
      </div>
    </div>
  </div>

  <!-- Аварийные туннели -->
  <div class="panel">
    <div class="panel-hd">🌐 Аварийные туннели</div>
    <div class="panel-bd">
      <div class="srow-sub" style="margin-bottom:14px">Используются когда все обычные сервера заблокированы. Требуют установки Tor.</div>
      <div style="display:grid;gap:10px">
        <div style="background:var(--s2);border:1px solid var(--bd);border-radius:8px;padding:12px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
            <span style="font-weight:600">🧕 Tor (прямой)</span>
            <span id="fb-tor-avail" style="font-size:12px;color:var(--t3)">-</span>
          </div>
          <div style="font-size:12px;color:var(--t2);margin-bottom:8px">Прямое подключение к Tor Network. Быстрее Snowflake, но может быть заблокирован.</div>
          <button class="btn btn-sm btn-gr" onclick="activateFallback('tor')">▶ Активировать</button>
        </div>
        <div style="background:var(--s2);border:1px solid var(--bd);border-radius:8px;padding:12px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
            <span style="font-weight:600">❄️ Tor + Snowflake</span>
            <span style="font-size:12px;color:var(--t2)">WebRTC маскировка</span>
          </div>
          <div style="font-size:12px;color:var(--t2);margin-bottom:8px">Маскирует Tor под WebRTC — практически невозможно заблокировать. Медленнее.</div>
          <button class="btn btn-sm btn-gr" onclick="activateFallback('tor_snowflake')">▶ Активировать</button>
        </div>
        <div style="background:var(--s2);border:1px solid var(--bd);border-radius:8px;padding:12px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
            <span style="font-weight:600">🇨🇦 Psiphon</span>
            <span style="font-size:12px;color:var(--t3)">Требует psiphond</span>
          </div>
          <div style="font-size:12px;color:var(--t2);margin-bottom:8px">Автоматически выбирает из 10+ протоколов. Встроенные сервера. Требует запущенный psiphond.</div>
          <button class="btn btn-sm btn-gr" onclick="activateFallback('psiphon')">▶ Активировать</button>
        </div>
      </div>
      <div style="display:flex;gap:8px;margin-top:12px">
        <button class="btn btn-pri btn-sm" onclick="autoSelectFallback()">✨ Автовыбор туннеля</button>
        <span id="fallback-fb" style="font-size:12px;align-self:center"></span>
      </div>
    </div>
  </div>

  <!-- Инструкции -->
  <div class="panel">
    <div class="panel-hd">📝 Установка Tor</div>
    <div class="panel-bd">
      <pre id="tor-install-guide" style="font-size:11px;color:var(--t2);white-space:pre-wrap;line-height:1.7;background:var(--bg);border-radius:6px;padding:10px">Загрузка...</pre>
    </div>
  </div>
</div>

<!-- ══ CATALOG ══ -->
<div class="page" id="page-catalog">
  <div class="btns">
    <button class="btn btn-pri btn-sm" onclick="doCatalogRefresh()" id="catalog-refresh-btn">↺ Обновить</button>
    <span style="font-size:11px;color:var(--t2);align-self:center" id="catalog-status-txt"></span>
  </div>
  <div class="info-box info">Провайдеры бесплатных узлов. Обновление загружает узлы из всех активных источников в единый пул.</div>
  <div id="catalog-providers-list"></div>
</div>

<!-- ══ ADBLOCK ══ -->
<div class="page" id="page-adblock">
  <div class="info-box info" id="ab-info">DNS-блокировка рекламы и трекеров. Работает через sing-box DNS rules.</div>

  <!-- Профиль -->
  <div class="panel">
    <div class="panel-hd">Профиль блокировки<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Блокирует рекламу/трекеры на уровне DNS для всего трафика через APF. «Light» — минимум блокировок, почти не ломает сайты. «Standard» — баланс блокировки и совместимости, подходит для большинства. «Strict» — блокирует максимум, но иногда ломает вёрстку/функциональность сайтов, использующих те же домены для контента. Добавляйте домены в белый список ниже, если строгий профиль что-то сломал.">?</i></div>
    <div class="panel-bd">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px">
        <div class="wiz-opt" id="ab-p-disabled" onclick="setAdBlockProfile('disabled')" style="cursor:pointer;border:2px solid var(--bd);border-radius:10px;padding:12px">
          <div style="font-weight:600;margin-bottom:4px">⏸ Выключен</div>
          <div style="font-size:11px;color:var(--t2)">AdBlock отключён, DNS без фильтрации</div>
        </div>
        <div class="wiz-opt" id="ab-p-light" onclick="setAdBlockProfile('light')" style="cursor:pointer;border:2px solid var(--bd);border-radius:10px;padding:12px">
          <div style="font-weight:600;margin-bottom:4px">🟡 Light</div>
          <div style="font-size:11px;color:var(--t2)">Только реклама (~10k доменов)</div>
        </div>
        <div class="wiz-opt" id="ab-p-standard" onclick="setAdBlockProfile('standard')" style="cursor:pointer;border:2px solid var(--bd);border-radius:10px;padding:12px">
          <div style="font-weight:600;margin-bottom:4px">🟢 Standard</div>
          <div style="font-size:11px;color:var(--t2)">Реклама + трекеры (~50k доменов)</div>
        </div>
        <div class="wiz-opt" id="ab-p-strict" onclick="setAdBlockProfile('strict')" style="cursor:pointer;border:2px solid var(--bd);border-radius:10px;padding:12px">
          <div style="font-weight:600;margin-bottom:4px">🔴 Strict</div>
          <div style="font-size:11px;color:var(--t2)">Реклама + трекеры + телеметрия (100k+)</div>
        </div>
      </div>
      <div id="ab-profile-status" style="font-size:12px;color:var(--t2)">Загрузка...</div>
    </div>
  </div>

  <!-- Статистика -->
  <div class="panel">
    <div class="panel-hd">Статистика</div>
    <div class="panel-bd" style="padding:0">
      <div class="srow" style="padding:9px 16px">
        <span>Доменов в базе</span>
        <span id="ab-domains" style="font-family:monospace;font-weight:700;color:var(--ac)">-</span>
      </div>
      <div class="srow" style="padding:9px 16px">
        <span>Источников загружено</span>
        <span id="ab-sources" style="font-family:monospace">-</span>
      </div>
      <div class="srow" style="padding:9px 16px;border:none">
        <span>Последнее обновление</span>
        <span id="ab-updated" style="font-size:11px;color:var(--t2)">-</span>
      </div>
    </div>
  </div>

  <!-- Белый список -->
  <div class="panel">
    <div class="panel-hd">Белый список (allowlist)<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Домен из белого списка НЕ блокируется AdBlock'ом никогда, даже на профиле Strict и даже если есть в базе блокировки. Используйте, если выбранный профиль по ошибке ломает нужный вам сайт — добавьте его домен сюда, применяется сразу, без пересборки списков.">?</i></div>
    <div class="panel-bd">
      <div class="srow-sub" style="margin-bottom:10px">Домены в allowlist не блокируются даже если есть в блок-листе.</div>
      <div class="inp-row" style="margin-bottom:10px">
        <input class="inp" id="ab-allow-inp" placeholder="example.com">
        <button class="btn btn-gr btn-sm" onclick="addToAllowlist()">+ Добавить</button>
      </div>
      <div id="ab-allowlist" style="font-size:12px;color:var(--t2)"></div>
    </div>
  </div>
</div>

<!-- ══ ANTIBLOCK ══ -->
<div class="page" id="page-antiblock">
  <div class="info-box info" id="ab2-info">
    Anti-VPN-Block — защита от блокировки сайтами (Netflix, банки, Госуслуги).
    Использует residential IP чтобы не быть заблокированным.
  </div>

  <!-- Настройки -->
  <div class="panel">
    <div class="panel-hd">Настройки Anti-VPN-Block</div>
    <div class="panel-bd">
      <div class="srow">
        <div class="srow-l"><div class="srow-title">Включить Anti-VPN-Block<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Многие сайты (банки, стриминг) блокируют IP дата-центров как типичные адреса VPN, но пропускают «домашние» резидентские IP. Включённая опция учитывает это при выборе узла наравне со скоростью. Включайте, если сайты часто просят капчу/блокируют по типу IP; выключайте, если не сталкиваетесь с этим — так остаётся больше узлов на выбор.">?</i></div><div class="srow-sub">Проверяет насколько хороший IP узла для стриминга / банков</div></div>
        <button class="toggle" id="t-ab2-enabled" onclick="toggleAntiBlock(this,'enabled')"></button>
      </div>
      <div class="srow">
        <div class="srow-l"><div class="srow-title">Только Residential IP<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Жёсткий вариант опции выше: датацентровые узлы не просто менее предпочтительны, а исключаются полностью. Включайте, если сайт блокирует ЛЮБОЙ дата-центровый IP без исключений; выключайте, если хватает мягкого предпочтения — так остаётся больше узлов.">?</i></div><div class="srow-sub">Априори не подключаться через datacenter IP. Может уменьшить пул узлов.</div></div>
        <button class="toggle" id="t-ab2-res" onclick="toggleAntiBlock(this,'residential')"></button>
      </div>
      <div class="srow">
        <div class="srow-l"><div class="srow-title">Автопереключение<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="Если тип IP узла выясняется только ПОСЛЕ подключения и оказывается датацентровым, APF сам переключится, не дожидаясь сбоя. Включайте для проактивной защиты; выключайте, если устраивает переключение только при реальных сбоях (через Watchdog).">?</i></div><div class="srow-sub">Если после подключения обнаружен datacenter IP — автоматически переключиться на residential</div></div>
        <button class="toggle" id="t-ab2-auto" onclick="toggleAntiBlock(this,'auto')"></button>
      </div>
    </div>
  </div>

  <!-- Текущий IP -->
  <div class="panel">
    <div class="panel-hd">
      🏠 Текущий IP узла
      <div style="display:flex;gap:6px">
        <button class="btn btn-sm btn-gr" onclick="checkCurrentIP()">&#9654; Проверить</button>
      </div>
    </div>
    <div class="panel-bd">
      <div id="ab2-ip-result" style="background:var(--s2);border:1px solid var(--bd);border-radius:8px;padding:14px">
        <div style="color:var(--t3);font-size:12px">Нажмите «Проверить» чтобы узнать качество IP активного узла</div>
      </div>
      <div style="margin-top:10px">
        <div style="font-size:12px;color:var(--t2);margin-bottom:6px">Проверить любой IP:</div>
        <div class="inp-row">
          <input class="inp" id="ab2-check-ip" placeholder="1.2.3.4">
          <button class="btn btn-sm btn-gr" onclick="checkCustomIP()">&#9654;</button>
        </div>
        <div id="ab2-custom-result" style="margin-top:8px;font-size:12px;color:var(--t2)"></div>
      </div>
    </div>
  </div>

  <!-- Статистика пула -->
  <div class="panel">
    <div class="panel-hd">Статистика пула узлов</div>
    <div class="panel-bd" style="padding:0">
      <div class="srow" style="padding:9px 16px">
        <span>Residential ISP</span>
        <span id="ab2-stat-res" style="font-family:monospace;color:var(--gr);font-weight:700">-</span>
      </div>
      <div class="srow" style="padding:9px 16px">
        <span>Datacenter / Hosting</span>
        <span id="ab2-stat-dc" style="font-family:monospace;color:var(--re);font-weight:700">-</span>
      </div>
      <div class="srow" style="padding:9px 16px">
        <span>Proxy / VPN</span>
        <span id="ab2-stat-proxy" style="font-family:monospace;color:var(--ye);font-weight:700">-</span>
      </div>
      <div class="srow" style="padding:9px 16px;border:none">
        <span>Неизвестных</span>
        <span id="ab2-stat-unk" style="font-family:monospace;color:var(--t2)">-</span>
      </div>
    </div>
  </div>

  <!-- Bypass Rules -->
  <div class="panel">
    <div class="panel-hd">
      🌎 Bypass Rules
      <span style="font-size:11px;color:var(--t3)">Residential IP для этих сайтов</span>
    </div>
    <div class="panel-bd" style="padding:0">
      <div id="ab2-bypass-list"></div>
      <div style="padding:12px 16px;border-top:1px solid var(--bd)">
        <div style="font-size:12px;color:var(--t2);margin-bottom:8px" id="ab2-domain-form-title">Добавить домен:</div>
        <!-- U-11 (ТЗ v1.4): раньше UI жёстко слал residential:true — переключатель типа
             правила вместо этого; бэкенд (AddUserRuleChecked/UpdateBypassDomain) уже принимал
             оба поля, звонка не было только отсюда. -->
        <div class="inp-row">
          <input class="inp" id="ab2-domain-inp" placeholder="example.com">
          <select class="inp sinp" id="ab2-domain-type" style="max-width:200px;width:auto" onchange="updateDirectRouteWarning()">
            <option value="residential">Через VPN, Residential IP</option>
            <option value="direct">Прямой маршрут (в обход VPN)</option>
          </select><i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key==='Enter')showHelp(this)" data-help="«Прямой маршрут» отправляет трафик этого домена НАПРЯМУЮ, в обход VPN/туннеля целиком — сайт увидит ваш настоящий IP-адрес (риск утечки), домен НЕ защищён VPN. Используйте только если домену точно не нужен VPN и важна максимальная скорость/совместимость (локальные сервисы, банк, который блокирует именно VPN-IP). «Через VPN, Residential IP» — обычный безопасный вариант: домен всё ещё идёт через туннель, просто предпочитается резидентский (не датацентр) IP.">?</i>
        </div>
        <div id="ab2-direct-warn" class="info-box warn" style="display:none;margin-top:8px;margin-bottom:0;font-size:11px">
          ⚠ «Прямой маршрут» отправляет трафик этого домена НАПРЯМУЮ, в обход VPN целиком — сайт
          увидит ваш настоящий IP-адрес. Используйте только для сайтов, которым это осознанно нужно.
        </div>
        <div class="inp-row" style="margin-top:8px">
          <button class="btn btn-sm btn-gr" id="ab2-domain-submit" onclick="addBypassDomain()">+ Добавить</button>
          <button class="btn btn-sm" id="ab2-domain-cancel" onclick="cancelEditBypassRule()" style="display:none">Отмена</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Подсказка -->
  <div class="info-box info" style="font-size:12px">
    <b>Почему сайты блокируют VPN?</b><br>
    Netflix, Disney+, банки видят что IP из <b>датацентра</b> (Digital Ocean, Hetzner, AWS) — значит VPN.
    <b>Residential IP</b> — это IP обычного домашнего интернета (телеком, интернет-провайдер). Сайты его не блокируют.
    APF автоматически отбирает residential-узлы из пула.
  </div>
</div>

</main>
</div>
<div id="wd-toast" class="toast">
  <div class="ttl" id="wd-toast-title">Watchdog</div>
  <div id="wd-toast-body"></div>
  <div class="sub" id="wd-toast-sub"></div>
</div>

<script>
const B=location.origin;
const lats=Array(40).fill(null);
let nodes=[], nodeFilter='all', logSeen=new Set();
let wizData={country:'RU',mode:'auto',security:'full'};
let cfg={};
let lgStatus={};
let browserData={};
let leakCount=0;
let pinnedNodeId='', favoriteIdSet=new Set();
// W3 (ТЗ v1.5 §2, лот L2-WEB-B): класс избранного — звезда пользователя (userFavoriteIdSet,
// снимается только пользователем) отдельно от автодобавленного сборкой каталога
// (systemFavoriteIdSet, может само уйти при провале следующей пробы). favoriteIdSet выше
// остаётся объединением обоих классов, как и раньше — для мест, которым класс не важен.
let userFavoriteIdSet=new Set(), systemFavoriteIdSet=new Set();

// Состояния проверки канала (общий контракт трёх UI — Web/Wails/Android, 2026-09-06):
// туннель поднят (connected) и туннель РЕАЛЬНО пропускает трафик (verified) — разные вещи, и
// между ними есть «ещё проверяю» и «проверка провалилась, но туннель не снят». Тексты и цвета
// обязаны совпадать дословно с другими UI — если меняешь, меняй везде.
const VERIFY_STATE_UI={
  idle:     {color:'var(--t2)', text:'Отключено'},
  checking: {color:'var(--ye)', text:'Проверяю канал…'},
  verified: {color:'var(--gr)', text:'Подключено'},
  failed:   {color:'var(--re)', text:'Туннель поднят, но трафик не идёт'}
};

// Значки проверенности узла (models.Node.VerifyBadge — источник истины на сервере, см.
// verify_badge в ответе /api/nodes; JS здесь только отображает готовое значение, а не считает
// его заново). ВАЖНО: tcp_alive — это «не проверялось трафиком», а НЕ «трафика нет»: обычное
// TCP-сканирование пула не умеет подтверждать канал, это делает только реальное подключение.
const VERIFY_BADGE_UI={
  proven_fresh:  {icon:'✅', title:'Трафик проходил недавно'},
  proven_stale:  {icon:'🟢', title:'Трафик проходил, но давно'},
  proven_failed: {icon:'⚠️', title:'Раньше пропускал, последняя проверка — сбой'},
  tcp_alive:     {icon:'🟡', title:'Отвечает по TCP, трафик не проверялся'},
  dead:          {icon:'🔴', title:'Не отвечает'},
  unchecked:     {icon:'⚪', title:'Не проверен'}
};

function nav(el){
  document.querySelectorAll('.n').forEach(n=>n.classList.remove('on'));
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('on'));
  el.classList.add('on');
  document.getElementById('page-'+el.dataset.page).classList.add('on');
  if(el.dataset.page==='wizard'){var ws=document.getElementById('wiz-setup');var wp=document.getElementById('wiz-privacy');if(ws)ws.style.display='';if(wp)wp.style.display='none';}
}

async function refresh(){
  try{
    const [st,stats,sb]=await Promise.all([
      fetch(B+'/api/state').then(r=>r.json()),
      fetch(B+'/api/stats').then(r=>r.json()),
      fetch(B+'/api/singbox').then(r=>r.json()),
    ]);
    const conn=st.connected;
    // Честное состояние проверки канала вместо одного зелёного «Подключено» по connected
    // (ТЗ 2026-09-06): connected==true означает только «туннель поднят», НЕ «трафик идёт».
    // verify_state пусто, пока движок (LOT-04) его не заполняет, — деградация ниже держит
    // интерфейс осмысленным независимо от порядка вливания правок:
    //   пусто + не connected → idle («Отключено»), пусто + connected → checking («Проверяю…»).
    let vs=st.verify_state;
    if(!vs){vs=conn?'checking':'idle';}
    const vsUI=VERIFY_STATE_UI[vs]||VERIFY_STATE_UI.idle;
    document.getElementById('sb-dot').style.background=vsUI.color;
    document.getElementById('sb-status-text').textContent=vsUI.text;
    document.getElementById('c-status').innerHTML='<span style="color:'+vsUI.color+'">●&nbsp;'+esc(vsUI.text)+'</span>';
    document.getElementById('btn-conn').style.display=conn?'none':'';
    document.getElementById('btn-disc').style.display=conn?'':'none';
    const n=st.active_node;
    document.getElementById('c-node').textContent=n?n.name:'—';
    document.getElementById('c-mode').textContent=n?('via '+n.protocol):'';
    document.getElementById('c-lat').textContent=n&&n.latency_ms?n.latency_ms+'мс':'—';
    document.getElementById('c-score').textContent=n&&n.score?'score '+n.score.toFixed(1):'';
    document.getElementById('c-pool').textContent=(stats.ok||0)+' ✓';
    document.getElementById('c-total').textContent='из '+(stats.total||0);
    // D3 (ТЗ v1.7 desktop, лот D-WEB-VERIFIED-UX): stats.proven — engine.go GetStats(), уже
    // отдаётся /api/stats (см. комментарий там же), здесь только отображение.
    document.getElementById('c-proven').textContent=stats.proven||0;
    document.getElementById('nb-ok').textContent=stats.ok||0;
    if(n&&n.latency_ms){lats.push(n.latency_ms);lats.shift();drawChart();document.getElementById('chart-cur').textContent=n.latency_ms+' мс';}
    // singbox status (no DOM element sb-inst in current UI)
    const row=document.getElementById('chain-row');
    let h='<div class="chain-node you">Вы</div><div class="chain-arr">→</div>';
    if(conn&&n){h+='<div class="chain-node active">'+esc(n.name)+'</div><div class="chain-arr">→</div>';}
    else{h+='<div class="chain-node" style="color:var(--t3)">Нет маршрута</div><div class="chain-arr">→</div>';}
    h+='<div class="chain-node inet">Интернет</div>';
    row.innerHTML=h;
    // Карточка защиты
    const ipv6On=lgStatus.ipv6_guard_enabled;
    const wrtcOn=lgStatus.webrtc_guard_enabled;
    const bothOn=ipv6On&&wrtcOn;
    document.getElementById('c-protection').innerHTML=
      bothOn?'<span style="color:var(--gr)">✓ Полная</span>':
      (ipv6On||wrtcOn)?'<span style="color:var(--ye)">⚠ Частичная</span>':
      '<span style="color:var(--re)">✗ Выкл.</span>';
    document.getElementById('c-protection-sub').textContent=
      (ipv6On?'IPv6 ✓':'')+' '+(wrtcOn?'WebRTC ✓':'');
  }catch(e){}
}

function drawChart(){
  const cv=document.getElementById('lat-c');
  const W=cv.offsetWidth,H=56; cv.width=W;cv.height=H;
  const ctx=cv.getContext('2d');
  const vals=lats.filter(v=>v!==null);
  if(vals.length<2)return;
  const mx=Math.max(...vals,50),mn=Math.min(...vals,0),rng=mx-mn||1;
  const step=W/(lats.length-1);
  const grd=ctx.createLinearGradient(0,0,0,H);
  grd.addColorStop(0,'rgba(79,142,247,.2)');grd.addColorStop(1,'rgba(79,142,247,0)');
  ctx.beginPath();let first=true;
  lats.forEach((v,i)=>{if(v===null){first=true;return}const x=i*step,y=H-((v-mn)/rng)*(H-8)-4;first?ctx.moveTo(x,y):ctx.lineTo(x,y);first=false;});
  ctx.lineTo(W,H);ctx.lineTo(0,H);ctx.closePath();
  ctx.fillStyle=grd;ctx.fill();
  ctx.beginPath();first=true;
  lats.forEach((v,i)=>{if(v===null){first=true;return}const x=i*step,y=H-((v-mn)/rng)*(H-8)-4;first?ctx.moveTo(x,y):ctx.lineTo(x,y);first=false;});
  ctx.strokeStyle='rgba(79,142,247,.9)';ctx.lineWidth=1.5;ctx.stroke();
}

// U-9 (ТЗ v1.4, минимум по В-1): ?view= — представления, которые движок уже поддерживал
// (GetNodesView: all|proven|manual|banned|favorites|removed), но встроенный UI не давал вкладок
// для них — только клиентский фильтр по статусу (setF/nodeFilter, ниже). currentView — какая
// вкладка выбрана; '' значит «Все узлы» (без ?view=).
let currentView='';
function setView(el){
  document.querySelectorAll('[data-v]').forEach(b=>b.classList.remove('btn-pri'));
  el.classList.add('btn-pri');
  currentView=el.dataset.v||'';
  const isRemoved=currentView==='removed';
  document.getElementById('nodes-status-filters').style.display=isRemoved?'none':'';
  document.getElementById('nodes-table-panel').style.display=isRemoved?'none':'';
  document.getElementById('nodes-removed-box').style.display=isRemoved?'':'none';
  loadNodes();
}
async function doRestoreRemoved(){
  const r=await fetch(B+'/api/nodes/restore-removed',{method:'POST'});
  const d=await r.json().catch(()=>({}));
  alert('Восстановлено надгробий: '+(d.restored||0));
  loadNodes();
}
async function loadNodes(){
  if(currentView==='removed'){
    const d=await fetch(B+'/api/nodes?view=removed').then(r=>r.json()).catch(()=>({removed_ids:[]}));
    const ids=d.removed_ids||[];
    document.getElementById('nodes-removed-info').textContent=ids.length?
      ('Удалено (надгробие): '+ids.length+' узл(ов) — не будут заново подхвачены из источников. ID: '+ids.join(', ')):
      'Удалённых узлов нет.';
    return;
  }
  const qs=currentView?('?view='+encodeURIComponent(currentView)):'';
  const [d,pin,fav]=await Promise.all([
    fetch(B+'/api/nodes'+qs).then(r=>r.json()),
    fetch(B+'/api/pinned-node').then(r=>r.json()).catch(()=>({})),
    fetch(B+'/api/favorites').then(r=>r.json()).catch(()=>({})),
  ]);
  nodes=d.nodes||[];
  pinnedNodeId=pin.pinned_node_id||'';
  favoriteIdSet=new Set(fav.favorite_ids||[]);
  // W3: /api/favorites теперь отдаёт разбивку по классу вдобавок к объединению выше.
  userFavoriteIdSet=new Set(fav.user_favorite_ids||[]);
  systemFavoriteIdSet=new Set(fav.system_favorite_ids||[]);
  renderNodes();
}
// C-18 (ТЗ v1.4): счётчик из трёх чисел — «в пуле» ≠ «отвечает по TCP» ≠ «подтверждено
// трафиком» (K8-LIVE D7: обход дал «живых 1480 из 5467 · подтверждённых трафиком: 2» — 99,96%
// пула не подтверждено ни разу; одно общее число «работает» скрывало бы это). Данные — из уже
// существующих /api/stats (total/ok/slow) и /api/scan/progress (verified, живой provenCount()),
// без новых полей движка.
async function updatePoolCounter(){
  try{
    const [stats,prog]=await Promise.all([
      fetch(B+'/api/stats').then(r=>r.json()),
      fetch(B+'/api/scan/progress').then(r=>r.json()),
    ]);
    const el=document.getElementById('nodes-counter');
    if(!el)return;
    const tcpAlive=(stats.ok||0)+(stats.slow||0);
    el.textContent='В пуле '+(stats.total||0)+' · отвечает по TCP '+tcpAlive+' · подтверждено трафиком '+(prog.verified||0);
  }catch(e){}
}
updatePoolCounter();setInterval(updatePoolCounter,5000);
// D1 (ТЗ v1.7 desktop, лот D-WEB-VERIFIED-UX): владелец нашёл узлы с подтверждённым трафиком,
// но они терялись в общем списке, отсортированном только по score. Закреплённый узел остаётся
// АБСОЛЮТНО первым (rank 0, как и раньше подразумевалось меткой 📌, только теперь это ещё и
// влияет на порядок), следующими — узлы с verified_count>0 (rank 1, тот же признак, что красит
// VERIFY_BADGE_UI/данные для фильтра «Подтверждённые трафиком» выше), остальные — rank 2. Внутри
// каждого ранга — прежняя сортировка по score, поведение для непроверенных узлов не меняется.
function nodeSortRank(n){
  if(n.id&&n.id===pinnedNodeId)return 0;
  if((n.verified_count||0)>0)return 1;
  return 2;
}
function renderNodes(){
  const q=(document.getElementById('nodes-search').value||'').toLowerCase();
  let list=nodes.filter(n=>{
    const mq=!q||n.name.toLowerCase().includes(q)||(n.address||'').includes(q);
    const mf=nodeFilter==='all'||n.status===nodeFilter;
    return mq&&mf;
  }).sort((a,b)=>nodeSortRank(a)-nodeSortRank(b)||b.score-a.score);
  document.getElementById('nodes-cnt').textContent=list.length+' узлов';
  if(!list.length){document.getElementById('nodes-body').innerHTML='<tr><td colspan="8" style="text-align:center;padding:30px;color:var(--t3)">Нет узлов</td></tr>';return;}
  const mx=Math.max(...list.map(n=>n.score||0),0.001);
  document.getElementById('nodes-body').innerHTML=list.map(n=>{
    const [pc,pl]=pillFor(n.status);
    // verify_badge считается на сервере (models.Node.VerifyBadge) — здесь только отображение
    // готового значения, деградация на unchecked если сервер ещё не проставил поле.
    const bd=VERIFY_BADGE_UI[n.verify_badge]||VERIFY_BADGE_UI.unchecked;
    let marks='';
    if(n.id&&n.id===pinnedNodeId)marks+='<span title="Закреплён">📌</span> ';
    // W3 (ТЗ v1.5 §2, лот L2-WEB-B): звезда пользователя (⭐, снимается только пользователем)
    // отдельно от автодобавленного сборкой каталога (🤖, может само уйти при провале следующей
    // пробы) — оба бейджа кликабельны и сразу снимают избранное (favorite:false), не дожидаясь
    // звезды в колонке действий ниже (та для системного класса теперь ПОВЫШАЕТ, а не снимает).
    if(n.id&&userFavoriteIdSet.has(n.id)){
      marks+='<span title="Избранное (добавлено вами). Нажмите, чтобы убрать" style="cursor:pointer" onclick="doFavoriteNode(\''+esc(n.id)+'\',false)">⭐</span> ';
    }else if(n.id&&systemFavoriteIdSet.has(n.id)){
      marks+='<span title="Добавлен автоматически по трафик-пробе — снимется, если перестанет давать трафик. Нажмите, чтобы убрать сейчас" style="cursor:pointer" onclick="doFavoriteNode(\''+esc(n.id)+'\',false)">🤖</span> ';
    }
    if(n.user_banned)marks+='<span title="В чёрном списке">🚫</span> ';
    const noteAttr=n.user_note?' title="'+esc(n.user_note)+'"':'';
    // B4 #4 (аудит 2026-09-07, опционально): значки закрепления/избранного/бана рисовались,
    // но ни одна из 4 существующих кнопок-маршрутов (/api/pin,/api/favorite,/api/node/ban,
    // /api/connect-once) не была доступна из строки таблицы. n.id — из публичной подписки,
    // поэтому идёт через esc() перед вставкой внутрь onclick="...('...')" — тот же приём,
    // что toggleProvider(esc(p.id)) и toggleBypassRule(esc(r.id)) выше по файлу (P0-3).
    const nid=esc(n.id||'');
    const pinned=!!(n.id&&n.id===pinnedNodeId);
    const favUser=!!(n.id&&userFavoriteIdSet.has(n.id));
    const favSystem=!!(n.id&&systemFavoriteIdSet.has(n.id));
    const fav=favUser||favSystem;
    const banned=!!n.user_banned;
    // W3 (ТЗ v1.5 §2, лот L2-WEB-B): звезда в колонке действий на СИСТЕМНОМ фаворите теперь не
    // тумблер «вкл/выкл», а ПОВЫШЕНИЕ до пользовательского (sticky) — всегда шлёт favorite:true
    // (Engine.AddFavorite на уже-системном фаворите промоутит его, см. engine.go
    // addFavoriteWithOrigin). Снять системный фаворит целиком можно кликом по 🤖-бейджу в имени
    // узла (marks выше) — там же честно объяснено, что он может уйти сам при провале пробы.
    const favTitle=favSystem?'Добавлен автоматически по пробе трафика — нажмите ⭐, чтобы закрепить как избранное (не снимется само)':(favUser?'Убрать из избранного':'В избранное');
    const favNextVal=favSystem?true:!fav;
    // V13-3 (ТЗ v1.4): «пин/избранное/бан/удалить» — /api/node/remove и /api/node/update уже
    // существовали (F3, ТЗ v1.3) без единого вызывателя из встроенного UI (K2-W подключил
    // только pin/favorite/ban/connect-once). Ручные узлы (n.source==='manual') не восстановить
    // через "Удалённые" единой кнопкой «повторно из источника» — но остаются в списке removed_ids
    // и снимаются тем же «Восстановить все» (RestoreRemovedNodes не различает источник).
    const actions=n.id?(
      '<button class="btn btn-sm'+(pinned?' btn-pri':'')+'" title="'+(pinned?'Открепить':'Закрепить')+'" onclick="doPinNode(\''+nid+'\','+(!pinned)+')">📌</button>'+
      '<button class="btn btn-sm'+(fav?' btn-pri':'')+'" title="'+favTitle+'" onclick="doFavoriteNode(\''+nid+'\','+favNextVal+')">⭐</button>'+
      '<button class="btn btn-sm'+(banned?' btn-red':'')+'" title="'+(banned?'Разбанить':'Забанить')+'" onclick="doBanNode(\''+nid+'\','+(!banned)+')">🚫</button>'+
      '<button class="btn btn-sm btn-gr" title="Подключиться именно к этому узлу" onclick="doConnectOnce(\''+nid+'\')">▶</button>'+
      '<button class="btn btn-sm" title="Изменить название/заметку" onclick="doEditNode(\''+nid+'\')">✎</button>'+
      '<button class="btn btn-sm btn-red" title="Удалить узел" onclick="doRemoveNode(\''+nid+'\')">🗑</button>'
    ):'—';
    // C-21-ui (ТЗ v1.4, §2.5 UI_CONTRACT): метка каталога (из имени) vs фактический выход
    // (LastVerifiedCountry, заполняется движком/L1b-ENG2 после успешной проверки через узел).
    // Условно — до заполнения exit_country ничего не рисуем, список не падает и не показывает
    // пустую метку (contract: "не блокировать ожиданием кода другого лота").
    let countryNote='';
    if(n.exit_country){
      countryNote=n.country_mismatch?
        '<div style="font-size:10px;color:var(--ye)" title="Фактический выход отличается от метки каталога — проверено реальным подключением">⚠ факт. выход: '+esc(n.exit_country)+'</div>':
        '<div style="font-size:10px;color:var(--t3)">факт. выход: '+esc(n.exit_country)+'</div>';
    }
    // C-20-ui (ТЗ v1.4, §2.4 UI_CONTRACT): «через туннель» — ТОЛЬКО для TUN-bound замера
    // (last_verified_via==='tun'); обычный post-connect замер идёт через локальный SOCKS5 и
    // подписывается «через прокси-канал узла». Величины нет — не показываем её вовсе.
    let verifiedNote='';
    if(n.last_verified_latency_ms){
      const via=n.last_verified_via==='tun'?'через туннель':'через прокси-канал узла';
      verifiedNote='<div style="font-size:10px;color:var(--t3)">'+n.last_verified_latency_ms+' мс '+via+'</div>';
    }
    return '<tr><td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"'+noteAttr+'>'+marks+esc(n.name)+countryNote+'</td>'+
      '<td><span style="font-family:monospace;font-size:11px;color:var(--t2)">'+esc(n.protocol)+'</span></td>'+
      '<td style="font-family:monospace;font-size:11px;color:var(--t3)">'+esc(n.address||'')+'</td>'+
      '<td>'+(n.latency_ms?n.latency_ms+'мс':'—')+verifiedNote+'</td>'+
      '<td><span style="display:inline-block;width:40px;height:3px;background:var(--bd);border-radius:2px;vertical-align:middle;margin-right:5px;overflow:hidden"><span style="display:block;width:'+Math.min(100,(n.score||0)/mx*100)+'%;height:100%;background:var(--ac)"></span></span>'+(n.score?n.score.toFixed(1):'—')+'</td>'+
      '<td><span class="pill '+pc+'">'+pl+'</span></td>'+
      '<td style="font-size:14px" title="'+esc(bd.title)+'">'+bd.icon+'</td>'+
      '<td style="white-space:nowrap">'+actions+'</td></tr>';
  }).join('');
}
function filterNodes(){renderNodes()}
// B4 #4: кнопки строки таблицы узлов на существующие маршруты — доп. запросов не вводят,
// только используют то, что уже отдаёт /api/pin,/api/favorite,/api/node/ban,/api/connect-once.
async function doPinNode(id,pinned){
  const r=await fetch(B+'/api/pin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({node_id:id,pinned:pinned})});
  if(!r.ok){const d=await r.json().catch(()=>({}));alert('Ошибка: '+(d.error||('HTTP '+r.status)));return;}
  await loadNodes();
}
async function doFavoriteNode(id,favorite){
  const r=await fetch(B+'/api/favorite',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({node_id:id,favorite:favorite})});
  if(!r.ok){const d=await r.json().catch(()=>({}));alert('Ошибка: '+(d.error||('HTTP '+r.status)));return;}
  await loadNodes();
}
async function doBanNode(id,banned){
  if(banned&&!confirm('Забанить этот узел? APF перестанет выбирать его автоматически.'))return;
  const r=await fetch(B+'/api/node/ban',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({node_id:id,banned:banned})});
  if(!r.ok){const d=await r.json().catch(()=>({}));alert('Ошибка: '+(d.error||('HTTP '+r.status)));return;}
  await loadNodes();
}
async function doConnectOnce(id){
  const r=await fetch(B+'/api/connect-once',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({node_id:id})});
  const d=await r.json().catch(()=>({}));
  if(!r.ok){alert('Ошибка: '+(d.error||('HTTP '+r.status)));return;}
}
// V13-3 (ТЗ v1.4): /api/node/update и /api/node/remove существовали (F3, ТЗ v1.3) без единого
// вызывателя из встроенного UI. Текущее имя/заметка берутся из уже загруженного массива nodes
// (в памяти JS), а не из значения, вставленного в onclick — вставка произвольного n.name прямо
// в атрибут onclick была бы новым классом XSS того же рода, что уже закрыт P0-3 для n.id/n.protocol
// (esc() экранирует ТЕКСТ HTML, но не защищает от разрыва JS-строки внутри onclick после
// HTML-декодирования атрибута браузером) — поэтому имя не передаётся через onclick вовсе.
async function doEditNode(id){
  const n=nodes.find(x=>x.id===id);
  const name=prompt('Название узла:',n?n.name:'');
  if(name===null)return;
  const note=prompt('Заметка (необязательно):',n?(n.user_note||''):'');
  if(note===null)return;
  const r=await fetch(B+'/api/node/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({node_id:id,name:name,user_note:note})});
  if(!r.ok){const d=await r.json().catch(()=>({}));alert('Не удалось сохранить: '+(d.error||('HTTP '+r.status)));return;}
  await loadNodes();
}
async function doRemoveNode(id){
  if(!confirm('Удалить этот узел? Он перестанет предлагаться и не будет заново подхвачен из источников — восстановить можно кнопкой «Удалённые → Восстановить все».'))return;
  const r=await fetch(B+'/api/node/remove',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({node_id:id})});
  if(!r.ok){const d=await r.json().catch(()=>({}));alert('Не удалось удалить: '+(d.error||('HTTP '+r.status)));return;}
  await loadNodes();
}
function setF(el){document.querySelectorAll('[data-f]').forEach(b=>b.classList.remove('btn-pri'));el.classList.add('btn-pri');nodeFilter=el.dataset.f;renderNodes();}
function pillFor(s){switch(s){case'ok':return['p-ok','OK'];case'slow':return['p-slow','Медл.'];case'blocked':return['p-bad','Блок.'];case'blacklist':return['p-bad','Бан'];default:return['p-unk','?'];}}

function renderSources(cfg){
  if(!cfg||!cfg.sources)return;
  const icons={subscription:'📦',tor:'🧅',manual:'✎'};
  // U-9 (ТЗ v1.4, минимум по В-1): вкладка «Источники» была read-only (D2 §6.2) — ни одного
  // переключателя. /api/save-config уже принимает ключ "sources" целиком (models.AppConfig.
  // Sources, разрешён общим белым списком S-7/patchAllowedKeys — не read-only) — шлём весь
  // массив с одним изменённым enabled, без нового бэкенд-эндпоинта.
  document.getElementById('sources-list').innerHTML=cfg.sources.map((s,i)=>
    '<div class="panel" style="margin-bottom:10px"><div class="panel-hd">'+icons[s.type]+' '+esc(s.name)+
    '<button class="toggle'+(s.enabled?' on':'')+'" style="margin-left:auto" title="'+(s.enabled?'Выключить источник':'Включить источник')+'" onclick="toggleSource('+i+')"></button></div>'+
    '<div class="panel-bd" style="padding:10px 16px;font-size:12px;color:var(--t2)">'+(s.url?esc(s.url):'Встроенный')+'<br>'+(s.auto_update?'Обновление каждые '+esc(s.update_interval_hours)+'ч':'Ручное')+'</div></div>'
  ).join('');
}
async function toggleSource(idx){
  if(!cfg||!cfg.sources||!cfg.sources[idx])return;
  const list=cfg.sources.map((s,i)=>i===idx?Object.assign({},s,{enabled:!s.enabled}):s);
  const r=await fetch(B+'/api/save-config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sources:list})});
  if(!r.ok){const d=await r.json().catch(()=>({}));alert('Не удалось изменить источник: '+(d.error||('HTTP '+r.status)));return;}
  cfg.sources=list;
  renderSources(cfg);
}

async function refreshLogs(){
  try{
    const logs=await fetch(B+'/api/logs').then(r=>r.json());
    const box=document.getElementById('logbox');
    let hasLeak=false,lastLeakMsg='';
    logs.forEach(msg=>{
      if(logSeen.has(msg))return; logSeen.add(msg);
      const d=document.createElement('div');
      const t=new Date().toTimeString().slice(0,8);
      const isLeak=msg.includes('LEAK')||msg.includes('⚠️');
      const cls=isLeak?'leak':msg.includes('FAIL')||msg.includes('ERR')||msg.includes('error')?'err':
                 msg.includes('OK')||msg.includes('Connected')?'ok':
                 msg.includes('scan')||msg.includes('Starting')?'info':'';
      d.className='ll'+(cls?' '+cls:'');
      d.innerHTML='<span class="lt">'+t+'</span>'+esc(msg);
      box.prepend(d);
      if(isLeak){hasLeak=true;leakCount++;lastLeakMsg=msg;}
    });
    if(box.children.length>300)while(box.children.length>300)box.lastChild.remove();
    document.getElementById('log-cnt').textContent=box.children.length+' записей';
    if(hasLeak){
      document.getElementById('nb-leak').style.display='';
      document.getElementById('nb-leakguard').style.display='';
      // U-12 (ТЗ v1.4): #leak-alert раньше никогда не наполнялся (мёртвая разметка, D2 §6.1) —
      // подключаем к уже существующему обнаружению утечки (OnLeakDetected → лог "⚠️ LEAK […]"),
      // а не удаляем: у пользователя должно быть видно на Dashboard, а не только в глубине Log.
      const la=document.getElementById('leak-alert');
      if(la&&lastLeakMsg){
        la.innerHTML='<div class="info-box danger">'+esc(lastLeakMsg.replace(/^⚠️\s*/,'⚠️ '))+
          ' <a href="#" onclick="dismissLeakAlert();return false" style="color:inherit;text-decoration:underline;margin-left:6px">скрыть</a></div>';
        la.style.display='';
      }
    }
  }catch(e){}
}
function dismissLeakAlert(){const la=document.getElementById('leak-alert');if(la){la.style.display='none';la.innerHTML='';}}
function clearLog(){document.getElementById('logbox').innerHTML='';logSeen.clear();document.getElementById('log-cnt').textContent='0 записей';}

// ── Actions ───────────────────────────────────────────────────────────────
async function doConnect(){document.getElementById('c-status').innerHTML='<span style="color:var(--ye)">● Подключение...</span>';await fetch(B+'/api/connect',{method:'POST'});}
async function doDisconnect(){await fetch(B+'/api/disconnect',{method:'POST'});}
// 2026-09-22: /api/scan теперь безопасный TCP-обход (см. apiScan) — активное подключение не трогает.
async function doScan(){await fetch(B+'/api/scan',{method:'POST'});loadScanProgress();}
async function doRescan(){await fetch(B+'/api/rescan',{method:'POST'});}
// ТЗ v1.3 F4 Stage 1 / F6: «Сканировать» ≠ «Подключить» — обход всего пула без подключения.
async function doSweep(){try{const r=await fetch(B+'/api/scan/start',{method:'POST'});const j=await r.json();if(j.error){alert('Обход: '+j.error);}else{loadScanProgress();}}catch(e){alert('Обход: '+e);}}
async function loadScanProgress(){try{const p=await (await fetch(B+'/api/scan/progress')).json();const el=document.getElementById('scan-status');if(!el)return;const v=p.verified?' · подтверждённых трафиком: '+p.verified:'';if(p.phase==='running'){const eta=p.eta_sec>0?' · осталось ~'+(p.eta_sec>=90?Math.round(p.eta_sec/60)+' мин':p.eta_sec+' с'):'';el.innerHTML='Обход: '+p.done+' / '+p.total+' · живых '+p.alive+eta+v+' <a href="#" onclick="fetch(B+\'/api/scan/cancel\',{method:\'POST\'});return false">■ стоп</a>';}else if(p.phase==='done'){el.textContent='Обход завершён: живых '+p.alive+' из '+p.total+v;}else if(p.phase==='cancelled'){el.textContent='Обход остановлен на '+p.done+' / '+p.total+' — продолжится с этого места'+v;}else{el.textContent=p.verified?'Подтверждённых трафиком: '+p.verified:'';}}catch(e){}}
setInterval(loadScanProgress,3000);
// ТЗ v1.5 N-3/N-1 (L2-WEB): «Собрать список рабочих узлов» — проба РЕАЛЬНОГО трафика (реальный
// HTTP GET через свой SOCKS-канал на узел, без TUN и без подключения устройства), в отличие от
// doSweep() выше (TCP-эхо всего пула — отвечает порт, не «есть трафик»). N-9: результат подписан
// ТОЛЬКО «выход в интернет проверен» / «канал проверен» — слово «через туннель» здесь ЗАПРЕЩЕНО
// (C-20, UI_CONTRACT_v1.4 §2.4: это слово зарезервировано за отдельной TUN-bound пробой на живом
// подключении устройства — данная проба TUN не поднимает и его состояние не подтверждает).
// D4 (ТЗ v1.7 desktop, лот D-WEB-VERIFIED-UX, живой прогон ПК 09-14: apf-killswitch-blocks-
// traffic-probe-windows) — при активном подключении+Kill Switch проба видит только текущий
// endpoint (allow-правило), все прочие узлы блокируются и проба лживо показывает «0 рабочих».
// node-check-ks-warning ниже — уже существующая ДИАГНОСТИКА постфактум (пишется из ответа
// /api/nodes/check-status, только отображение, ничего не меняет и не убирается этой правкой).
// Здесь — проактивный вопрос ДО запуска пробы, пока не поздно: если подключены, предлагаем
// сначала отключиться. И «да», и «нет» всё равно запускают саму пробу.
async function doNodeCheck(){
  try{
    const st=await fetch(B+'/api/state').then(r=>r.json()).catch(()=>({connected:false}));
    if(st.connected&&confirm('Для честной проверки узлов лучше отключиться — при активном подключении и Kill Switch проба увидит только текущий узел, а остальные покажет нерабочими. Отключиться и собрать список?')){
      await fetch(B+'/api/disconnect',{method:'POST'}).catch(()=>null);
      // Disconnect асинхронный (apiDisconnect запускает eng.Stop() в горутине и отвечает сразу,
      // см. server.go) — короткая пауза, чтобы Kill Switch/firewall успели снять правила до
      // старта пробы, тот же приём, что уже используется в recovery-мастере выше (1200мс).
      await new Promise(res=>setTimeout(res,1200));
    }
    const r=await fetch(B+'/api/nodes/check-all',{method:'POST'});
    const j=await r.json();
    if(j.error){alert('Проверка узлов: '+j.error);}else{loadNodeCheckStatus();}
  }catch(e){alert('Проверка узлов: '+e);}
}
async function loadNodeCheckStatus(){try{const p=await (await fetch(B+'/api/nodes/check-status')).json();const kw=document.getElementById('node-check-ks-warning'),kwt=document.getElementById('node-check-ks-warning-text');if(kw&&kwt){if(p.kill_switch_warning){kwt.textContent=p.kill_switch_warning;kw.style.display='';}else{kw.style.display='none';kwt.textContent='';}}const el=document.getElementById('node-check-status');if(!el)return;if(p.phase==='probing'){el.innerHTML='Проверка: '+p.probed+' / '+p.total+' · выход в интернет проверен: '+p.verified+' (цель '+p.target_k+')'+' <a href="#" onclick="fetch(B+\'/api/nodes/check-cancel\',{method:\'POST\'});return false">■ стоп</a>';}else if(p.phase==='done'){el.textContent='Проверка завершена: канал проверен у '+p.verified+' из '+p.probed+' (просмотрено '+p.total+')';}else if(p.phase==='cancelled'){el.textContent='Проверка остановлена: выход в интернет проверен у '+p.verified+' из '+p.probed;}else{el.textContent='';}}catch(e){}}
setInterval(loadNodeCheckStatus,3000);
// L5-WEB (ТЗ v1.4 §5): ручной харвест. Запуск асинхронный (сервер крутит проход в горутине), итог
// и прогресс — опросом. Весь UI-текст через textContent (не innerHTML) — анти-XSS: даже если бы в
// ответ просочилась строка из источника, она не исполнится (сейчас сервер сырьё и не отдаёт).
async function doHarvest(){
  try{
    const r=await fetch(B+'/api/nodes/harvest',{method:'POST'});
    const j=await r.json();
    if(j.error){alert('Харвест: '+j.error);}else{loadHarvestStatus();}
  }catch(e){alert('Харвест: '+e);}
}
async function loadHarvestStatus(){try{const p=await (await fetch(B+'/api/nodes/harvest-status')).json();const el=document.getElementById('harvest-status');if(!el)return;if(p.running){const pr=p.progress||{};el.textContent='Харвест: источник '+(pr.source_index||0)+' / '+(pr.source_total||0)+' · найдено '+(pr.found||0);}else if(p.error){el.textContent='Харвест: '+p.error;}else if(p.done&&p.result){const r=p.result;let t='Харвест: обработано '+r.sources_processed+'/'+r.sources_total+', добавлено новых '+r.merged+' (распознано '+r.parsed+')';if(r.subscription_urls>0)t+=' · ссылок-подписок '+r.subscription_urls+' (добавьте их источником вручную)';if(r.stopped)t+=' · '+({timeout:'по таймауту',canceled:'отменён',budget:'достигнут лимит'}[r.stopped]||r.stopped);el.textContent=t;}else{el.textContent='';}}catch(e){}}
setInterval(loadHarvestStatus,3000);
// Task A (2026-09-21): извлечение узлов из вставленного текста — POST /api/nodes/harvest-text
// {text}; статус/прогресс общие с обычным харвестом (серверные harvestRunning/harvestResult),
// поэтому просто переиспользуем loadHarvestStatus()/#harvest-status выше, как и doHarvest().
async function doHarvestText(){
  const ta=document.getElementById('harvest-text-input');
  const text=ta?ta.value.trim():'';
  if(!text){alert('Вставьте текст со ссылками');return;}
  try{
    const r=await fetch(B+'/api/nodes/harvest-text',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:text})});
    const j=await r.json();
    if(j.error){alert('Харвест: '+j.error);}else{loadHarvestStatus();}
  }catch(e){alert('Харвест: '+e);}
}
async function doAdd(){
  const lnk=document.getElementById('add-link').value.trim();
  const fb=document.getElementById('add-fb');
  if(!lnk)return;
  fb.textContent='Добавление...';fb.className='inp-fb';
  try{
    const r=await fetch(B+'/api/add-node',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({link:lnk})});
    const d=await r.json();
    if(d.error){fb.textContent='✗ '+d.error;fb.className='inp-fb err';}
    else{fb.textContent='✓ Добавлен';fb.className='inp-fb ok';document.getElementById('add-link').value='';setTimeout(()=>{fb.textContent=''},3000);loadNodes();}
  }catch(e){fb.textContent='✗ '+e.message;fb.className='inp-fb err';}
}
// U-9 (ТЗ v1.4, минимум по В-1): редактор продвинутых полей для /api/add-node-manual —
// бэкенд (B-29, engine.AddNodeManual+models.ValidateNode) существовал без вызывателя из UI.
function toggleManualAdd(){
  const el=document.getElementById('manual-add-form');
  const show=el.style.display==='none';
  el.style.display=show?'':'none';
  if(show)renderManualAddFields();
}
function renderManualAddFields(){
  const proto=document.getElementById('ma-protocol').value;
  const box=document.getElementById('ma-proto-fields');
  let h='';
  if(proto==='vless'||proto==='vmess'){
    h+='<div class="inp-row"><input class="inp" id="ma-uuid" placeholder="UUID"></div>';
  }
  if(proto==='trojan'||proto==='ss'){
    h+='<div class="inp-row"><input class="inp" id="ma-password" placeholder="Пароль"></div>';
  }
  if(proto==='ss'){
    h+='<div class="inp-row"><input class="inp" id="ma-method" placeholder="Метод (например, aes-256-gcm)"></div>';
  }
  if(proto==='vless'){
    // Подписи полей — дословно словарь §1.3 UI_CONTRACT_v1.4.md (пп.18/19/20, переиспользованы
    // из формы Wails index.html, а не придуманы заново).
    h+='<div class="srow-sub" style="margin:8px 0 4px">Дополнительно: маскировка соединения (TLS / Reality) — необязательно<i class="help-ico" tabindex="0" role="button" aria-label="Пояснение" onclick="showHelp(this)" onkeydown="if(event.key===\'Enter\')showHelp(this)" data-help="SNI — имя сайта, под который маскируется TLS-соединение (для наблюдателя выглядит как обращение к этому сайту). Reality pbk/sid — публичный ключ и короткий ID Reality-маскировки; эти значения даёт администратор VPN-сервера вместе с адресом и портом. Заполняйте, только если параметры получены отдельными значениями, а не готовой ссылкой vless:// — для обычной ссылки используйте поле «Добавить узел» выше.">?</i></div>'+
       '<div class="inp-row"><input class="inp" id="ma-sni" placeholder="SNI (имя сайта для маскировки)"></div>'+
       '<div class="inp-row"><input class="inp" id="ma-pbk" placeholder="Reality — публичный ключ (pbk)"></div>'+
       '<div class="inp-row"><input class="inp" id="ma-sid" placeholder="Reality — короткий ID (sid, необязательно)"></div>';
  }
  box.innerHTML=h;
}
async function doAddManual(){
  const fb=document.getElementById('ma-fb');
  const proto=document.getElementById('ma-protocol').value;
  const address=document.getElementById('ma-address').value.trim();
  const port=parseInt(document.getElementById('ma-port').value)||0;
  if(!address||!port){fb.textContent='Укажите адрес и порт';fb.className='inp-fb err';return;}
  const node={protocol:proto,address:address,port:port};
  const nameV=document.getElementById('ma-name').value.trim();if(nameV)node.name=nameV;
  const uuidEl=document.getElementById('ma-uuid');if(uuidEl&&uuidEl.value.trim())node.uuid=uuidEl.value.trim();
  const pwdEl=document.getElementById('ma-password');if(pwdEl&&pwdEl.value)node.password=pwdEl.value;
  const methodEl=document.getElementById('ma-method');if(methodEl&&methodEl.value.trim())node.method=methodEl.value.trim();
  const sniEl=document.getElementById('ma-sni');
  const pbkEl=document.getElementById('ma-pbk');
  if(pbkEl&&pbkEl.value.trim()){
    const sidEl=document.getElementById('ma-sid');
    node.tls={enabled:true,server_name:sniEl?sniEl.value.trim():'',reality:{public_key:pbkEl.value.trim(),short_id:sidEl?sidEl.value.trim():''}};
  }else if(sniEl&&sniEl.value.trim()){
    node.tls={enabled:true,server_name:sniEl.value.trim()};
  }
  fb.textContent='Добавление...';fb.className='inp-fb';
  try{
    const r=await fetch(B+'/api/add-node-manual',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(node)});
    const d=await r.json().catch(()=>({}));
    if(!r.ok||d.error){fb.textContent='✗ '+(d.error||('HTTP '+r.status));fb.className='inp-fb err';return;}
    fb.textContent='✓ Узел добавлен';fb.className='inp-fb ok';
    document.getElementById('ma-address').value='';document.getElementById('ma-port').value='';
    setTimeout(()=>{fb.textContent=''},3000);
    loadNodes();
  }catch(e){fb.textContent='✗ Ошибка сети: '+e.message;fb.className='inp-fb err';}
}
async function doResetNet(){
  if(!confirm('Восстановить DNS и правила файрвола?'))return;
  try{
    const rr=await requestNetworkReset();
    if(!rr.ok){
      alert('Сброс завершился с ошибкой: '+(rr.error||'unknown error'));
      return;
    }
    const d=rr.data;
    const warn=(d.warnings&&d.warnings.length)?'\nПредупреждения:\n- '+d.warnings.join('\n- '):'';
    alert('Сеть восстановлена за '+(d.duration_ms||0)+'мс.'+warn);
  }catch(e){
    alert('Ошибка сброса: '+e.message);
  }
}

async function requestNetworkReset(){
  try{
    const r=await fetch(B+'/api/reset-network',{method:'POST'});
    const d=await r.json();
    return {ok:r.ok&&!!d.success,data:d,error:d.error||''};
  }catch(e){
    return {ok:false,data:null,error:e.message};
  }
}

function setRecoveryWizardStatus(lines){
  const box=document.getElementById('recovery-wizard-box');
  const status=document.getElementById('recovery-wizard-status');
  box.style.display='';
  status.innerHTML=lines.map(l=>'<div>'+esc(l)+'</div>').join('');
}

function showRecoveryChecklist(items){
  const el=document.getElementById('recovery-checklist');
  if(!items||!items.length){
    el.style.display='none';
    el.innerHTML='';
    return;
  }
  el.style.display='';
  el.innerHTML='<div style="color:var(--t1);font-weight:600;margin-bottom:4px">Что проверить:</div>'+
    items.map(i=>'<div>• '+esc(i)+'</div>').join('');
}

function setRecoveryRetryVisible(show){
  const btn=document.getElementById('recovery-retry-btn');
  btn.style.display=show?'':'none';
}

function setRecoverySafeConnectVisible(show){
  const btn=document.getElementById('recovery-safe-btn');
  btn.style.display=show?'':'none';
}

async function runRecoveryConnectivityCheck(){
  const lines=['⏳ Повторная проверка доступа к контрольным адресам...'];
  setRecoveryWizardStatus(lines);
  const cc=await fetch(B+'/api/connectivity-check',{method:'POST'}).then(r=>r.json()).catch(()=>null);
  if(cc&&cc.ok){
    lines[0]='✅ Интернет доступен ('+cc.ok_count+'/'+cc.total+'). Можно заново запускать подключение APF.';
    setRecoveryWizardStatus(lines);
    showRecoveryChecklist([]);
    setRecoveryRetryVisible(false);
    setRecoverySafeConnectVisible(true);
    return;
  }
  lines[0]='⚠ Доступ к контрольным адресам не подтвержден.';
  setRecoveryWizardStatus(lines);
  const dnsOk=cc&&cc.dns&&cc.dns.ok;
  showRecoveryChecklist(dnsOk?[
    'DNS работает, но сайты не открываются — возможно блокировка/фильтрация или остался прокси',
    'Проверьте, не остался ли прокси в браузере/системе',
    'Отключи/включи Wi-Fi или сетевой адаптер',
    'Запусти windows/reset_network.bat от имени администратора',
    'Если не помогло, попробуй другой интернет (мобильный/другая сеть)',
  ]:[
    'Похоже, DNS не работает (домены не резолвятся)',
    'Запусти windows/reset_network.bat от имени администратора',
    'Проверьте DNS в системе (авто/8.8.8.8/1.1.1.1) и перезагрузите сеть',
    'Если используешь роутер — перезагрузи роутер и ПК',
  ]);
  setRecoveryRetryVisible(true);
  setRecoverySafeConnectVisible(false);
}

async function applySafeSettingsAndConnect(){
  const lines=['⏳ Применяю безопасные настройки и подключаюсь...'];
  setRecoveryWizardStatus(lines);
  try{
    // Safe-mode: минимально рискованные настройки для повторного подключения.
    const patch={
      mode:'auto',
      enable_chain:false,
      enable_kill_switch:true,
      switch_only_on_fail:true,
      min_uptime_sec:180,
      safety_filter:true,
      block_ipv6_leak:true,
      block_webrtc:true,
      dns_leak_test_interval:300,
      // не меняем listen_port/webui_port чтобы не ломать локальные настройки
    };
    const r=await fetch(B+'/api/save-config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(patch)});
    const d=await r.json().catch(()=>({}));
    if(!r.ok||d.error){
      lines[0]='❌ Не удалось сохранить настройки: '+(d.error||('HTTP '+r.status));
      setRecoveryWizardStatus(lines);
      return;
    }
    lines[0]='✅ Безопасные настройки применены. Запускаю подключение...';
    setRecoveryWizardStatus(lines);
    await fetch(B+'/api/connect',{method:'POST'}).catch(()=>null);
    setTimeout(()=>{document.querySelector('[data-page=\"dashboard\"]').click();},400);
  }catch(e){
    lines[0]='❌ Ошибка safe connect: '+e.message;
    setRecoveryWizardStatus(lines);
  }
}

async function startRecoveryWizard(){
  const lines=[
    '1/4 Проверяю текущее состояние подключения...',
    '2/4 Останавливаю активное подключение APF...',
    '3/4 Выполняю безопасный сетевой откат...',
    '4/4 Проверяю результат и даю рекомендации...'
  ];
  setRecoveryWizardStatus(lines.map(l=>'⏳ '+l));
  setRecoveryRetryVisible(false);
  setRecoverySafeConnectVisible(false);
  showRecoveryChecklist([]);

  try{
    // Шаг 1: состояние
    let st=await fetch(B+'/api/state').then(r=>r.json()).catch(()=>({connected:false}));
    lines[0]='✅ 1/4 Состояние получено: '+(st.connected?'подключено':'отключено');
    setRecoveryWizardStatus(lines);

    // Шаг 2: отключение при необходимости
    if(st.connected){
      await fetch(B+'/api/disconnect',{method:'POST'}).catch(()=>null);
      await new Promise(res=>setTimeout(res,1200));
      lines[1]='✅ 2/4 Активное подключение остановлено';
    }else{
      lines[1]='✅ 2/4 Подключение уже было остановлено';
    }
    setRecoveryWizardStatus(lines);

    // Шаг 3: reset
    const rr=await requestNetworkReset();
    if(!rr.ok){
      lines[2]='❌ 3/4 Сетевой откат завершился ошибкой: '+(rr.error||'unknown error');
      lines[3]='➡ 4/4 Рекомендация: запусти reset_network.bat от имени администратора.';
      setRecoveryWizardStatus(lines);
      return;
    }
    const d=rr.data;
    const warn=(d.warnings&&d.warnings.length)?(' (с предупреждениями: '+d.warnings.length+')'):'';
    lines[2]='✅ 3/4 Сетевой откат выполнен за '+(d.duration_ms||0)+'мс'+warn;
    setRecoveryWizardStatus(lines);

    // Шаг 4: диагностика + проверка интернета
    const diag=await fetch(B+'/api/diagnostics').then(r=>r.json()).catch(()=>null);
    const cc=await fetch(B+'/api/connectivity-check',{method:'POST'}).then(r=>r.json()).catch(()=>null);
    if(cc&&cc.ok){
      lines[3]='✅ 4/4 Интернет восстановлен ('+cc.ok_count+'/'+cc.total+' контрольных адресов доступны).';
      if(diag&&diag.last_rollback&&diag.last_rollback.reason){
        lines[3]+=' Последняя причина rollback: '+diag.last_rollback.reason;
      }
      setRecoveryRetryVisible(false);
      showRecoveryChecklist([]);
      setRecoverySafeConnectVisible(true);
    }else{
      lines[3]='⚠ 4/4 Сброс выполнен, но доступ к контрольным адресам не подтверждён. Проверьте Wi-Fi/провайдера и запустите reset_network.bat от имени администратора.';
      setRecoveryRetryVisible(true);
      showRecoveryChecklist([
        'Отключи/включи Wi-Fi или Ethernet',
        'Проверьте, что APF отключен и kill switch не активен',
        'Сбрось прокси в браузере или системных настройках',
        'Запусти windows/reset_network.bat от имени администратора',
      ]);
      setRecoverySafeConnectVisible(false);
    }
    setRecoveryWizardStatus(lines);
  }catch(e){
    lines[3]='❌ 4/4 Ошибка мастера: '+e.message;
    setRecoveryRetryVisible(true);
    setRecoverySafeConnectVisible(false);
    showRecoveryChecklist([
      'Повтори мастер восстановления',
      'Запусти windows/reset_network.bat от имени администратора',
      'Проверьте интернет без APF',
    ]);
    setRecoveryWizardStatus(lines);
  }
}

// ── Settings ──────────────────────────────────────────────────────────────
function tog(el,key){el.classList.toggle('on');}
// togInstant — в отличие от tog() (только красит тумблер, ждёт общего «Сохранить»
// в Настройках), применяет ОДИН параметр сразу — нужна быстрым тумблерам на главном
// экране (Kill Switch/Системный прокси): их смысл в том, чтобы не идти в Настройки
// и не жать «Сохранить» ради срочного изменения. mirrorId — id парной копии того же
// параметра в Настройках, синхронизируется тем же кликом.
// P1 (аудит 2026-09-01, раздел D): апстрим /api/save-config раньше отдавал 200 даже при
// отклонённом PatchConfig — эта функция полагалась на факт, что fetch() не бросает
// исключение на HTTP-уровне, и БЕЗУСЛОВНО красила тумблер в новое состояние сразу после
// запроса. Комментарий ниже годами описывал НАМЕРЕНИЕ ("класс не трогаем при отказе"),
// которое код не реализовывал: единственный способ отказа, который сюда доходил, — это
// сетевая ошибка (catch), а сам факт REST-отказа (400) был неотличим от успеха. Теперь
// эндпоинт возвращает 400, и класс переключателя красится только при r.ok.
async function togInstant(el,key,mirrorId){
  const turningOn=!el.classList.contains('on')
  const qtErr=document.getElementById('qt-err')
  if(qtErr){qtErr.style.display='none';qtErr.textContent=''}
  // П14 (аудит E2/K2-W 2026-09-07): снятие защиты одним кликом без вопроса — асимметрия
  // с Wails, где ВКЛЮЧЕНИЕ Kill Switch уже подтверждается. Спрашиваем только на ВЫКЛЮЧЕНИЕ,
  // включение — как раньше, без изменений.
  if(!turningOn&&key==='enable_kill_switch'){
    if(!confirm('Выключить Kill Switch? Если туннель оборвётся, трафик пойдёт в обход VPN без защиты.'))return
  }
  try{
    const r=await fetch(B+'/api/save-config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({[key]:turningOn})})
    if(!r.ok){
      // U-10 (ТЗ v1.4, §7.3 UI_CONTRACT_v1.4): раньше отказ (400/сетевая ошибка) не показывал
      // НИЧЕГО — тумблер просто «не нажимался». Класс всё ещё не трогаем (тумблер обязан
      // отражать реальное состояние, не намерение), но причина отказа теперь видна рядом.
      const d=await r.json().catch(()=>({}))
      if(qtErr){qtErr.textContent='✗ '+(d.error||('Не удалось изменить: HTTP '+r.status));qtErr.style.display=''}
      return
    }
    el.classList.toggle('on',turningOn)
    const mirror=document.getElementById(mirrorId)
    if(mirror)mirror.classList.toggle('on',turningOn)
    if(cfg)cfg[key]=turningOn
  }catch(e){
    // U-10: сетевая ошибка — тот же принцип (класс не трогаем), но теперь тоже видна.
    if(qtErr){qtErr.textContent='✗ Ошибка сети: '+e.message;qtErr.style.display=''}
  }
}
async function saveSettings(){
  const st=document.getElementById('settings-status');
  const patch={
    connection_mode:document.getElementById('s-connmode').value,
    enable_kill_switch:document.getElementById('t-ks').classList.contains('on'),
    set_system_proxy:document.getElementById('t-sysproxy').classList.contains('on'),
    auto_connect:document.getElementById('t-auto').classList.contains('on'),
    switch_only_on_fail:document.getElementById('t-stab').classList.contains('on'),
    enable_chain:document.getElementById('t-chain').classList.contains('on'),
    multihop_enabled:document.getElementById('t-multihop').classList.contains('on'),
    multihop_count:parseInt(document.getElementById('s-multihop-count').value)||2,
    safety_filter:document.getElementById('t-safe').classList.contains('on'),
    block_ipv6_leak:document.getElementById('t-ipv6').classList.contains('on'),
    block_webrtc:document.getElementById('t-webrtc').classList.contains('on'),
    min_uptime_sec:parseInt(document.getElementById('s-uptime').value)||120,
    listen_port:parseInt(document.getElementById('s-port').value)||10808,
    check_interval_sec:parseInt(document.getElementById('s-interval').value)||30,
    dns_leak_test_interval:parseInt(document.getElementById('s-dns-interval').value)||300,
    node_check_top_n:parseInt(document.getElementById('s-probe-depth').value)||30,
  };
  try{
    const r=await fetch(B+'/api/save-config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(patch)});
    if(!r.ok){
      const d=await r.json().catch(()=>({}));
      st.textContent='✗ '+(d.error||('Ошибка HTTP '+r.status));st.style.color='var(--re)';
      return;
    }
    const resp=await r.json().catch(()=>({}));
    // ТЗ v1.3 F5.4: ключи, которые подействуют только после перезапуска APF (listen_port,
    // webui_port), — честный тост, а не молчание (сервер уже возвращает needs_restart).
    if(resp.needs_restart&&resp.needs_restart.length){
      st.textContent='✓ Сохранено — нужен перезапуск APF для: '+resp.needs_restart.join(', ');
      st.style.color='var(--ye)';
    }else{
      st.textContent='✓ Сохранено';st.style.color='var(--gr)';setTimeout(()=>{st.textContent=''},3000);
    }
  }catch(e){st.textContent='✗ Ошибка';st.style.color='var(--re)';}
}
async function loadConfig(){
  try{
    cfg=await fetch(B+'/api/config').then(r=>r.json());
    if(document.getElementById('s-connmode'))document.getElementById('s-connmode').value=cfg.connection_mode||'proxy';
    setTog('t-ks',cfg.enable_kill_switch!==false);
    setTog('t-ks-dash',cfg.enable_kill_switch!==false);
    setTog('t-sysproxy',cfg.set_system_proxy===true);
    setTog('t-sysproxy-dash',cfg.set_system_proxy===true);
    setTog('t-auto',cfg.auto_connect!==false);
    setTog('t-stab',cfg.switch_only_on_fail!==false);
    setTog('t-chain',cfg.enable_chain===true);
    setTog('t-multihop',cfg.multihop_enabled===true);
    if(cfg.multihop_count)document.getElementById('s-multihop-count').value=cfg.multihop_count;
    setTog('t-safe',cfg.safety_filter!==false);
    setTog('t-ipv6',cfg.block_ipv6_leak!==false);
    setTog('t-webrtc',cfg.block_webrtc!==false);
    if(cfg.min_uptime_sec)document.getElementById('s-uptime').value=cfg.min_uptime_sec;
    if(cfg.listen_port)document.getElementById('s-port').value=cfg.listen_port;
    if(cfg.check_interval_sec)document.getElementById('s-interval').value=cfg.check_interval_sec;
    if(cfg.dns_leak_test_interval!==undefined)document.getElementById('s-dns-interval').value=cfg.dns_leak_test_interval;
    setProbeDepthSel(cfg.node_check_top_n||30);
    if(cfg.emergency_hotkey)document.getElementById('hotkey-label').textContent=cfg.emergency_hotkey;
    renderSources(cfg);
  }catch(e){}
  loadCatalogReviewInterval();
}
function setTog(id,val){const el=document.getElementById(id);if(el)el.className='toggle'+(val?' on':'');}
// setProbeDepthSel — ТЗ v1.7 (PROBE-DEPTH-SETTING): <select> знает пресеты 30/60/150 и «Все
// рабочие» (сигнал 1000000000 = models.NodeCheckTopNAll, запрос владельца 09-15), но config.json
// может хранить любое клампленное Normalize()'ом значение 10-300 (ручная правка файла, апгрейд со
// старой сборки и т.п.) — выбираем БЛИЖАЙШИЙ пресет вместо того, чтобы молча упасть на первый
// <option>. Сигнал «Все рабочие» огромен, поэтому для обычных значений он никогда не выигрывает,
// а точное совпадение даёт diff=0 и выбирает именно его.
function setProbeDepthSel(n){
  const presets=[30,60,150,1000000000];
  let best=presets[0],diff=Math.abs(n-best);
  for(const p of presets){const d=Math.abs(n-p);if(d<diff){best=p;diff=d;}}
  const el=document.getElementById('s-probe-depth');
  if(el)el.value=String(best);
}
// W3 (ТЗ v1.5 §5, лот L2-WEB-B): интервал пересмотра системного избранного — отдельная ручка
// (instant-apply на onchange, как AdBlock-профиль/Sticky policy выше), не часть saveSettings()/
// PatchConfig. Не блокирует loadConfig() при ошибке — тот же приём try/catch, что и остальные
// second-tier загрузки настроек в этом файле.
async function loadCatalogReviewInterval(){
  try{
    const d=await fetch(B+'/api/catalog-review-interval').then(r=>r.json());
    const el=document.getElementById('s-catalog-review-interval');
    if(el&&d.interval)el.value=d.interval;
  }catch(e){}
}
async function setCatalogReviewInterval(v){
  try{
    await fetch(B+'/api/catalog-review-interval',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({value:v})});
  }catch(e){}
}

// ── LeakGuard ─────────────────────────────────────────────────────────────
async function loadLeakGuard(){
  try{
    lgStatus=await fetch(B+'/api/leakguard/status').then(r=>r.json());
    renderLeakGuardStatus();
    // Загружаем браузерные инструкции
    const bi=await fetch(B+'/api/leakguard/browser-instructions').then(r=>r.json());
    browserData=bi;
    showBrowserInstructions('chrome');
    document.getElementById('lg-info').style.display='none';
  }catch(e){
    document.getElementById('lg-info').textContent='Ошибка загрузки: '+e.message;
  }
}

function renderLeakGuardStatus(){
  const ipv6=lgStatus.ipv6_guard_enabled;
  const webrtc=lgStatus.webrtc_guard_enabled;
  // V13-6-web (ТЗ v1.4): раньше карточка красилась только по голому enabled-флагу — тумблер
  // мог быть "включён", пока единственный реальный механизм (Kill Switch на Windows) не
  // применяет вообще ничего. Движок уже отдаёт честный статус в /api/leakguard/status
  // (ipv6_status.enforced: full|delegated|none, webrtc_status.enforced: partial|none, оба с
  // готовым русским .note) — JS этим полем раньше не пользовался вовсе.
  const ipv6St=lgStatus.ipv6_status||{};
  const webrtcSt=lgStatus.webrtc_status||{};
  const ipv6OK=ipv6St.enforced==='full'||ipv6St.enforced==='delegated';
  const webrtcOK=webrtcSt.enforced==='partial'; // "partial" — максимум, что WebRTC-защита вообще даёт

  const ipv6Card=document.getElementById('lg-ipv6-card');
  const webrtcCard=document.getElementById('lg-webrtc-card');
  ipv6Card.className='lg-card '+(ipv6OK?'ok':'warn');
  webrtcCard.className='lg-card '+(webrtcOK?'ok':'warn');

  document.getElementById('lg-ipv6-status').innerHTML=ipv6OK?
    '<span class="lg-status ok">✓ '+esc(ipv6St.note||'Включён')+'</span>':
    '<span class="lg-status warn">'+(ipv6?'⚠ ':'✗ ')+esc(ipv6St.note||'Выключен — возможна утечка IPv6')+'</span>';
  document.getElementById('lg-webrtc-status').innerHTML=webrtcOK?
    '<span class="lg-status ok">✓ '+esc(webrtcSt.note||'Включён')+'</span>':
    '<span class="lg-status warn">'+(webrtc?'⚠ ':'✗ ')+esc(webrtcSt.note||'Выключен — браузер может слить IP')+'</span>';

  document.getElementById('lg-ipv6-btn').textContent=ipv6?'Выключить':'Включить';
  document.getElementById('lg-ipv6-btn').className='btn btn-sm '+(ipv6?'btn-red':'btn-gr');
  document.getElementById('lg-webrtc-btn').textContent=webrtc?'Выключить':'Включить';
  document.getElementById('lg-webrtc-btn').className='btn btn-sm '+(webrtc?'btn-red':'btn-gr');
}

async function toggleIPv6(){
  const enabled=lgStatus.ipv6_guard_enabled;
  // П14 (аудит E2/K2-W 2026-09-07): снятие защиты — спрашиваем; включение (enabled===false
  // сейчас) остаётся без изменений, как раньше.
  if(enabled){
    if(!confirm('Выключить IPv6 Leak Block? Возможна утечка реального IP через IPv6 в обход VPN.'))return;
  }
  const r=await fetch(B+'/api/leakguard/ipv6',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:!enabled})});
  const d=await r.json();
  if(!d.error){lgStatus.ipv6_guard_enabled=d.enabled;renderLeakGuardStatus();}
}
async function toggleWebRTC(){
  const enabled=lgStatus.webrtc_guard_enabled;
  // U-16-web (ТЗ v1.4, §4.2-4.3 UI_CONTRACT_v1.4): единственная из четырёх защит без
  // подтверждения на выключение (асимметрия с toggleIPv6 тремя строками выше) — текст
  // дословно из контракта, единый на все три UI (это единственный из четырёх диалогов,
  // который пишется впервые сразу на всех платформах, а не переиспользует уже проверенный).
  if(enabled){
    if(!confirm('Выключить блокировку WebRTC? WebRTC может раскрыть ваш реальный IP-адрес в обход VPN даже при активном туннеле — известная уязвимость браузеров. Без блокировки часть сайтов сможет узнать ваше настоящее местоположение; часть функций сайтов (видеозвонки в браузере) при этом будет работать как обычно.'))return;
  }
  const r=await fetch(B+'/api/leakguard/webrtc',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:!enabled})});
  const d=await r.json();
  if(!d.error){lgStatus.webrtc_guard_enabled=d.enabled;renderLeakGuardStatus();}
}

async function runDNSTest(){
  const btn=document.getElementById('dns-test-btn');
  const res=document.getElementById('dns-result');
  btn.textContent='⏳ Тест...';btn.disabled=true;
  res.textContent='Выполняется DNS Leak Test (~10 секунд)...';
  try{
    const d=await fetch(B+'/api/leakguard/dns-test',{method:'POST'}).then(r=>r.json());
    if(d.error){res.textContent='Ошибка: '+d.error;return;}
    const icon=d.leaked?'⚠️ УТЕЧКА ОБНАРУЖЕНА':'✅ Утечки нет';
    res.textContent=icon+'\n\n'+d.diagnosis+(d.recommendation?'\n\n'+d.recommendation:'');
    res.style.color=d.leaked?'var(--re)':'var(--gr)';
  }catch(e){res.textContent='Ошибка: '+e.message;}
  finally{btn.textContent='▶ Проверить';btn.disabled=false;}
}

function showBrowser(el,browser){
  document.querySelectorAll('.browser-tab button').forEach(b=>b.classList.remove('on'));
  el.classList.add('on');
  showBrowserInstructions(browser);
  document.getElementById('ff-dl-btn').style.display=browser==='firefox'?'':'none';
}
function showBrowserInstructions(browser){
  const inst=browserData.instructions;
  if(!inst||!inst[browser]){document.getElementById('browser-steps').textContent='Загрузка...';return;}
  const b=inst[browser];
  document.getElementById('browser-steps').innerHTML=
    '<b>'+esc(b.name)+'</b> — '+esc(b.method)+':<br>'+
    b.steps.map((s,i)=>'<b>'+(i+1)+'.</b> '+esc(s)).join('<br>');
}
function downloadFirefoxJS(){
  const js=browserData.firefox_user_js||'';
  const blob=new Blob([js],{type:'text/plain'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='user.js';a.click();
}

// Crypto
async function setCrypto(){
  const pwd=document.getElementById('crypto-pwd').value;
  const fb=document.getElementById('crypto-fb');
  if(pwd.length<12){fb.textContent='⚠ Минимум 12 символов';fb.className='inp-fb err';return;}
  fb.textContent='Применяю...';fb.className='inp-fb';
  try{
    const r=await fetch(B+'/api/crypto/set-password',{method:'POST',
      headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pwd})});
    const d=await r.json();
    fb.textContent='✓ '+d.message;fb.className='inp-fb ok';
    document.getElementById('crypto-pwd').value='';
  }catch(e){fb.textContent='✗ '+e.message;fb.className='inp-fb err';}
}
async function disableCrypto(){
  if(!confirm('Выключить шифрование? Данные сохранятся в открытом виде.'))return;
  const r=await fetch(B+'/api/crypto/set-password',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({password:''})});
  const d=await r.json();
  const fb=document.getElementById('crypto-fb');
  fb.textContent=d.message;fb.className='inp-fb';
}

// Wipe
function checkWipeConfirm(){
  const ok=document.getElementById('wipe-confirm').value==='WIPE';
  document.getElementById('wipe-data-btn').disabled=!ok;
  document.getElementById('wipe-all-btn').disabled=!ok;
}
async function doWipe(wipeAll){
  const label=wipeAll?'ВСЁ включая sing-box':'только данные APF';
  if(!confirm('ВНИМАНИЕ!\n\nУдалить '+label+'?\n\nЭто действие НЕОБРАТИМО.'))return;
  try{
    const r=await fetch(B+'/api/emergency/wipe',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({wipe_all:wipeAll,confirm:'WIPE'})});
    const d=await r.json();
    if(d.error){alert('Ошибка: '+d.error);return;}
    alert('Удалено:\n'+d.files_deleted+' файлов\n'+d.bytes_deleted+' байт\nВремя: '+d.duration_ms+'мс');
  }catch(e){alert('Ошибка: '+e.message);}
}

// Wizard
let wizStep=0;
function selWiz(el,key){el.closest('.wiz-options').querySelectorAll('.wiz-opt').forEach(o=>o.classList.remove('sel'));el.classList.add('sel');wizData[key]=el.dataset.val;}
function wizNext(step){
  document.getElementById('ws-'+step).style.display='none';
  document.getElementById('wd-'+step).className='wiz-dot done';
  document.getElementById('wd-'+step).textContent='✓';
  if(document.getElementById('wl-'+step))document.getElementById('wl-'+step).className='wiz-line done';
  wizStep=step+1;
  const next=document.getElementById('ws-'+wizStep);
  if(next)next.style.display='block';
  document.getElementById('wd-'+wizStep).className='wiz-dot active';
  if(wizStep===3)buildWizSummary();
}
function wizBack(step){
  document.getElementById('ws-'+step).style.display='none';
  document.getElementById('wd-'+(step-1)).className='wiz-dot active';
  document.getElementById('wd-'+(step-1)).textContent=step;
  if(document.getElementById('wl-'+(step-1)))document.getElementById('wl-'+(step-1)).className='wiz-line';
  wizStep=step-1;
  document.getElementById('ws-'+wizStep).style.display='block';
}
function buildWizSummary(){
  const fullSec=wizData.security==='full';
  document.getElementById('wiz-summary').innerHTML=
    '<div style="font-size:13px;color:var(--t2);line-height:2">'+
    '🌍 Регион: <b style="color:var(--t1)">'+(wizData.country==='RU'?'Россия':wizData.country==='BY'?'Беларусь':'Другой')+'</b><br>'+
    '⚡ Режим: <b style="color:var(--t1)">'+(wizData.mode==='stealth'?'Максимальная защита':'Автоматически')+'</b><br>'+
    '🔒 IPv6 Guard: <b style="color:var(--t1)">'+(fullSec?'✓ Включён':'✗')+'</b><br>'+
    '🌐 WebRTC Guard: <b style="color:var(--t1)">'+(fullSec?'✓ Включён':'✗')+'</b><br>'+
    '🔗 Kill Switch: <b style="color:var(--t1)">✓ Всегда включён</b><br>'+
    '</div>';
}
async function wizFinish(){
  const fullSec=wizData.security==='full';
  const patch={
    user_country:wizData.country,mode:wizData.mode,
    enable_chain:wizData.mode==='stealth',
    enable_kill_switch:true,safety_filter:true,switch_only_on_fail:true,
    block_ipv6_leak:fullSec,block_webrtc:fullSec,setup_done:true,
  };
  try{
    const r=await fetch(B+'/api/save-config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(patch)});
    if(!r.ok){
      const d=await r.json().catch(()=>({}));
      alert('Не удалось сохранить настройки мастера: '+(d.error||('HTTP '+r.status)));
    }
  }catch(e){}
  document.querySelector('[data-page="dashboard"]').click();
  setTimeout(doConnect,500);
}

async function loadDiagnostics(){
  try{
    const d=await fetch(B+'/api/diagnostics').then(r=>r.json());
    // U-17-web (ТЗ v1.4): last_persist_error непусто → saveNodes() отказал (напр. шифрование
    // сломано, K2-E fail-closed) — раньше это терялось молча. Пропадает само, когда движок
    // сообщает пустую строку следующей успешной записью.
    const pe=document.getElementById('persist-error-alert');
    if(pe){
      if(d.last_persist_error){
        pe.textContent='⚠ узлы не сохранены: '+d.last_persist_error;
        pe.style.display='';
      }else{
        pe.style.display='none';
        pe.textContent='';
      }
    }
    const types={'none':'Нет','dns':'DNS','ip':'IP','sni':'SNI (ТСПУ)','deep_dpi':'Глубокая DPI','complete':'Полная'};
    const colors={'none':'var(--gr)','dns':'var(--ye)','ip':'var(--ye)','sni':'var(--or)','deep_dpi':'var(--re)','complete':'var(--re)'};
    const bt=d.blockage_type||'none';
    const el=document.getElementById('diag-type');
    if(el){el.textContent=types[bt]||bt;el.style.color=colors[bt]||'var(--t2)';}
    const st=document.getElementById('diag-strat');if(st)st.textContent=d.strategy_reason||'—';
    const gd=document.getElementById('diag-guards');
    if(gd)gd.innerHTML=(d.ipv6_block?'IPv6 <span style="color:var(--gr)">✓</span>':'IPv6 <span style="color:var(--re)">✗</span>')+
      ' &nbsp; '+(d.webrtc_block?'WebRTC <span style="color:var(--gr)">✓</span>':'WebRTC <span style="color:var(--re)">✗</span>')+
      ' &nbsp; '+(d.crypto_enabled?'Crypto <span style="color:var(--gr)">✓</span>':'Crypto <span style="color:var(--t3)">—</span>');
    const rb=document.getElementById('diag-rollback');
    if(rb){
      if(d.last_rollback&&d.last_rollback.stage){
        const r=d.last_rollback;
        rb.textContent=(r.stage||'unknown')+': '+(r.reason||'no details');
        rb.style.color='var(--or)';
        rb.title=(r.at?('at '+r.at+' | '):'')+(r.reason||'');
      }else{
        rb.textContent='не было';
        rb.style.color='var(--gr)';
        rb.title='';
      }
    }
    const wd=document.getElementById('diag-watchdog');
    if(wd){
      const we=d.watchdog_event;
      const hist=Array.isArray(d.watchdog_events)?d.watchdog_events:[];
      if(we&&we.event){
        wd.textContent=String(we.event)+(we.reset_done?' ✓':'')+' ('+hist.length+')';
        wd.style.color=we.reset_done?'var(--or)':'var(--t2)';
        wd.title=(we.timestamp?('at '+we.timestamp+' | '):'')+(we.description||'');
      }else{
        wd.textContent='нет данных (0)';
        wd.style.color='var(--t3)';
        wd.title='';
      }
    }
    // Обновляем глобальный статус для карточки защиты
    if(d.ipv6_block!==undefined)lgStatus.ipv6_guard_enabled=d.ipv6_block;
    if(d.webrtc_block!==undefined)lgStatus.webrtc_guard_enabled=d.webrtc_block;
  }catch(e){}
}

/* P0-3 (аудит 2026-09-01): добавлены КАВЫЧКИ. Раньше покрывались только & < > —
   элементный контекст был безопасен, но почти все вставки идут в атрибут или внутрь
   onclick='...', где кавычка выводит в исполняемый код. Источники — имя узла и протокол из
   публичной подписки, id провайдера каталога, id bypass-правила и ответ стороннего
   IP-репутационного API (renderIPResult). */
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}

// ── U-8 (ТЗ v1.4): поповер подсказки по клику вместо hover-only title= ─────
// Раньше help-ico полагался на нативный title= — не открывается тапом на тач-экране (E2,
// K10-UIC §1.3). showHelp/hideHelp — тот же паттерн, что уже проверен в Wails (клик/фокус,
// не hover), отдельная реализация здесь (Web не делит код с Wails).
function showHelp(el){
  const pop=document.getElementById('help-pop');
  if(!pop||!el)return;
  if(pop.style.display==='block'&&pop._src===el){hideHelp();return;}
  pop.textContent=el.getAttribute('data-help')||'';
  pop.style.display='block';
  pop._src=el;
  const r=el.getBoundingClientRect();
  let left=Math.min(r.left,window.innerWidth-296);
  if(left<8)left=8;
  let top=r.bottom+6;
  if(top+120>window.innerHeight)top=Math.max(8,r.top-6-pop.offsetHeight);
  pop.style.left=left+'px';
  pop.style.top=top+'px';
}
function hideHelp(){const pop=document.getElementById('help-pop');if(pop){pop.style.display='none';pop._src=null;}}
document.addEventListener('click',function(e){
  const pop=document.getElementById('help-pop');
  if(!pop||pop.style.display!=='block')return;
  if(e.target.classList&&e.target.classList.contains('help-ico'))return;
  if(!pop.contains(e.target))hideHelp();
});
document.addEventListener('keydown',function(e){if(e.key==='Escape')hideHelp();});

// ── Init ──────────────────────────────────────────────────────────────────
refresh();loadNodes();refreshLogs();loadConfig();loadDiagnostics();loadSessionStatus();
setInterval(refresh,4000);setInterval(loadDiagnostics,10000);
setInterval(loadNodes,12000);setInterval(refreshLogs,2500);
setInterval(loadSessionStatus,8000);
// Fallback Phase 7
let fallbackStatus={};
let wdHistoryCache=[];
let wdFilteredHistory=[];
let wdQuickFilter={today:false,crash:false,errors:false};
let wdLastSeenCount=0;
let wdToastTimer=null;
async function loadFallbackStatus(){
  try{
    const d=await fetch(B+'/api/fallback/status').then(r=>r.json());
    fallbackStatus=d;
    renderFallbackStatus(d);
  }catch(e){}
  try{
    const wd=await fetch(B+'/api/watchdog/status').then(r=>r.json());
    renderWatchdogStatus(wd);
  }catch(e){}
  try{
    const diag=await fetch(B+'/api/diagnostics').then(r=>r.json());
    const next=Array.isArray(diag.watchdog_events)?diag.watchdog_events:[];
    if(next.length>wdLastSeenCount){
      const delta=next.length-wdLastSeenCount;
      showWatchdogNewBadge(true,delta);
      const latest=next[next.length-1]||{};
      const ev=latest.event||'watchdog_event';
      const desc=latest.description||'Новое событие watchdog';
      showWatchdogToast('Watchdog update','+'+delta+' событ. · '+ev,desc);
    }
    wdHistoryCache=next;
    wdLastSeenCount=next.length;
    applyWatchdogHistoryFilters();
  }catch(e){}
}
function showWatchdogNewBadge(show,count){
  const el=document.getElementById('wd-history-new');
  if(!el)return;
  if(show){
    el.style.display='';
    el.textContent='new'+(count&&count>1?(' +'+count):'');
  }else{
    el.style.display='none';
    el.textContent='new';
  }
}
function showWatchdogToast(title,body,sub){
  const t=document.getElementById('wd-toast');
  if(!t)return;
  const ttl=document.getElementById('wd-toast-title');
  const b=document.getElementById('wd-toast-body');
  const s=document.getElementById('wd-toast-sub');
  if(ttl)ttl.textContent=title||'Watchdog';
  if(b)b.textContent=body||'Новое событие';
  if(s)s.textContent=sub||'';
  t.classList.add('show');
  if(wdToastTimer)clearTimeout(wdToastTimer);
  wdToastTimer=setTimeout(()=>{t.classList.remove('show');},3800);
}
function renderWatchdogStatus(s){
  if(!s)return;
  const stateEl=document.getElementById('wd-state');
  const latEl=document.getElementById('wd-latency');
  const failEl=document.getElementById('wd-fails');
  const chkEl=document.getElementById('wd-checks');
  const errEl=document.getElementById('wd-error');
  const colors={'healthy':'var(--gr)','degraded':'var(--ye)','failed':'var(--re)','idle':'var(--t3)','disabled':'var(--t3)'};
  if(stateEl){stateEl.textContent=s.state||'-';stateEl.style.color=colors[s.state]||'var(--t2)';}
  if(latEl)latEl.textContent=(s.latency_ms?s.latency_ms+'ms':'-');
  if(failEl)failEl.textContent=(s.fail_count||0)+'/'+(s.total_fails||0);
  if(chkEl)chkEl.textContent=(s.total_checks||0);
  if(errEl){errEl.textContent=s.last_error||'';errEl.style.display=s.last_error?'':'none';}
}
function renderWatchdogHistory(events){
  const el=document.getElementById('wd-history-list');
  if(!el)return;
  const arr=Array.isArray(events)?events:[];
  if(!arr.length){
    el.innerHTML='<div style="color:var(--t3)">Событий пока нет</div>';
    return;
  }
  const items=arr.slice();
  el.innerHTML=items.map(ev=>{
    const ts=ev.timestamp?new Date(ev.timestamp).toLocaleString():'-';
    const event=ev.event||'unknown';
    const ok=ev.reset_done===true;
    const color=ok?'var(--or)':(event==='normal_shutdown'?'var(--gr)':'var(--t2)');
    const desc=ev.description||'';
    const err=ev.error?(' | err: '+ev.error):'';
    return '<div style="margin-bottom:4px"><span style="color:var(--t3)">'+esc(ts)+'</span> · '+
      '<span style="color:'+color+'">'+esc(event)+'</span> · '+
      '<span>'+esc(desc+err)+'</span></div>';
  }).join('');
}
function applyWatchdogHistoryFilters(){
  const kindEl=document.getElementById('wd-filter-kind');
  const errEl=document.getElementById('wd-filter-errors');
  const limitEl=document.getElementById('wd-filter-limit');
  const queryEl=document.getElementById('wd-filter-query');
  const sortEl=document.getElementById('wd-filter-sort');
  const all=Array.isArray(wdHistoryCache)?wdHistoryCache.slice():[];
  let arr=all.slice();
  const kind=kindEl?kindEl.value:'all';
  const onlyErrors=errEl?errEl.checked:false;
  const limit=limitEl?parseInt(limitEl.value,10):30;
  const query=((queryEl&&queryEl.value)||'').trim().toLowerCase();
  const sort=(sortEl&&sortEl.value)||'newest';

  if(kind==='crash'){
    arr=arr.filter(ev=>String(ev.event||'').indexOf('crash_reset_')===0);
  }else if(kind==='normal'){
    arr=arr.filter(ev=>String(ev.event||'')==='normal_shutdown');
  }
  if(onlyErrors){
    arr=arr.filter(ev=>!!ev.error);
  }
  if(wdQuickFilter.errors){
    arr=arr.filter(ev=>!!ev.error);
  }
  if(wdQuickFilter.crash){
    arr=arr.filter(ev=>String(ev.event||'').indexOf('crash_reset_')===0);
  }
  if(wdQuickFilter.today){
    const dayStart=new Date();
    dayStart.setHours(0,0,0,0);
    const ts=dayStart.getTime();
    arr=arr.filter(ev=>{
      const t=ev.timestamp?new Date(ev.timestamp).getTime():0;
      return t>=ts;
    });
  }
  if(query){
    arr=arr.filter(ev=>{
      const event=String(ev.event||'').toLowerCase();
      const desc=String(ev.description||'').toLowerCase();
      const err=String(ev.error||'').toLowerCase();
      return event.includes(query)||desc.includes(query)||err.includes(query);
    });
  }
  if(sort==='oldest'){
    arr.sort((a,b)=>toTs(a)-toTs(b));
  }else if(sort==='severity'){
    arr.sort((a,b)=>severityRank(b)-severityRank(a) || (toTs(b)-toTs(a)));
  }else{
    arr.sort((a,b)=>toTs(b)-toTs(a));
  }
  if(Number.isFinite(limit)&&limit>0&&arr.length>limit){
    arr=arr.slice(0,limit);
  }
  wdFilteredHistory=arr.slice();
  updateWatchdogStats(all,arr);
  renderWatchdogHistory(arr);
  // Пользователь увидел обновлённую историю — скрываем badge.
  showWatchdogNewBadge(false,0);
}
function toTs(ev){
  const t=ev&&ev.timestamp?new Date(ev.timestamp).getTime():0;
  return Number.isFinite(t)?t:0;
}
function severityRank(ev){
  if(ev&&ev.error)return 3;
  const e=String((ev&&ev.event)||'');
  if(e==='crash_reset_failed')return 3;
  if(e==='crash_reset_done')return 2;
  if(e==='normal_shutdown')return 1;
  return 0;
}
function updateWatchdogStats(all,shown){
  const el=document.getElementById('wd-history-stats');
  if(!el)return;
  const total=(Array.isArray(all)?all:[]).length;
  const displayed=(Array.isArray(shown)?shown:[]).length;
  const errors=(Array.isArray(shown)?shown:[]).filter(ev=>!!ev.error).length;
  const crash=(Array.isArray(shown)?shown:[]).filter(ev=>String(ev.event||'').indexOf('crash_reset_')===0).length;
  el.textContent='shown: '+displayed+' / total: '+total+' · errors: '+errors+' · crash resets: '+crash;
}
function toggleWatchdogQuickChip(kind){
  wdQuickFilter[kind]=!wdQuickFilter[kind];
  const id='wd-chip-'+kind;
  const btn=document.getElementById(id);
  if(btn){
    btn.classList.toggle('btn-pri',wdQuickFilter[kind]);
  }
  if(kind==='errors'){
    const c=document.getElementById('wd-filter-errors');
    if(c)c.checked=wdQuickFilter.errors;
  }
  applyWatchdogHistoryFilters();
}
async function downloadWatchdogHistory(){
  try{
    const arr=Array.isArray(wdFilteredHistory)&&wdFilteredHistory.length?wdFilteredHistory:[];
    const blob=new Blob([JSON.stringify(arr,null,2)],{type:'application/json'});
    const a=document.createElement('a');
    a.href=URL.createObjectURL(blob);
    a.download='watchdog-events-filtered.json';
    a.click();
  }catch(e){
    alert('Не удалось скачать историю watchdog: '+e.message);
  }
}
async function copyWatchdogHistory(){
  try{
    const arr=Array.isArray(wdFilteredHistory)?wdFilteredHistory:[];
    const text=JSON.stringify(arr,null,2);
    if(navigator.clipboard&&navigator.clipboard.writeText){
      await navigator.clipboard.writeText(text);
    }else{
      const ta=document.createElement('textarea');
      ta.value=text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    alert('История watchdog скопирована в буфер ('+arr.length+' записей).');
  }catch(e){
    alert('Не удалось скопировать историю watchdog: '+e.message);
  }
}
async function clearWatchdogHistory(){
  if(!confirm('Очистить историю watchdog?'))return;
  try{
    await fetch(B+'/api/watchdog/history',{method:'DELETE'});
    wdHistoryCache=[];
    wdFilteredHistory=[];
    wdLastSeenCount=0;
    wdQuickFilter={today:false,crash:false,errors:false};
    const q=document.getElementById('wd-filter-query');
    if(q)q.value='';
    const s=document.getElementById('wd-filter-sort');
    if(s)s.value='newest';
    ['today','crash','errors'].forEach(k=>{
      const b=document.getElementById('wd-chip-'+k);
      if(b)b.classList.remove('btn-pri');
    });
    renderWatchdogHistory([]);
    updateWatchdogStats([],[]);
    showWatchdogNewBadge(false,0);
    const wd=document.getElementById('diag-watchdog');
    if(wd){
      wd.textContent='нет данных (0)';
      wd.style.color='var(--t3)';
      wd.title='';
    }
  }catch(e){
    alert('Не удалось очистить историю watchdog: '+e.message);
  }
}
function renderFallbackStatus(d){
  const fb=d.fallback;
  if(!fb)return;
  const torAvailEl=document.getElementById('fb-tor-avail');
  if(torAvailEl)torAvailEl.innerHTML=fb.tor_available?'<span style="color:var(--gr)">✔ Установлен</span>':'<span style="color:var(--re)">✖ Не найден</span>';
  const guide=document.getElementById('tor-install-guide');
  if(guide&&fb.install_guide)guide.textContent=fb.install_guide;
}
async function activateFallback(tunnel){
  const fb=document.getElementById('fallback-fb');
  if(fb){fb.textContent='Активация '+tunnel+'...';}
  try{
    const d=await fetch(B+'/api/fallback/activate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tunnel})}).then(r=>r.json());
    if(fb){
      if(d.error){fb.textContent='Ошибка: '+d.error;fb.style.color='var(--re)';}
      else{fb.textContent='✓ Активирован: '+tunnel;fb.style.color='var(--gr)';}
    }
  }catch(e){if(fb){fb.textContent='Ошибка';fb.style.color='var(--re)';}}
  setTimeout(()=>{if(fb)fb.textContent=''},4000);
}
async function autoSelectFallback(){
  const fb=document.getElementById('fallback-fb');
  if(fb)fb.textContent='Анализирую...';
  try{
    const d=await fetch(B+'/api/fallback/auto-select',{method:'POST'}).then(r=>r.json());
    if(fb){fb.textContent='Выбран: '+d.tunnel;fb.style.color='var(--ac)';}
    if(d.tunnel&&d.tunnel!=='none')await activateFallback(d.tunnel);
  }catch(e){if(fb)fb.textContent='err';}
}
setInterval(()=>{if(document.getElementById('page-fallback').classList.contains('on'))loadFallbackStatus();},5000);
// DPI Phase 6
let dpiStatus={};
async function loadDPIStatus(){try{dpiStatus=await fetch(B+'/api/dpi/status').then(r=>r.json());renderDPIStatus();}catch(e){}}
// Sticky Session
let sessionStatus={};
async function loadSessionStatus(){try{sessionStatus=await fetch(B+'/api/session/status').then(r=>r.json());renderSessionStatus();}catch(e){}}
function renderSessionStatus(){
  const s=sessionStatus;
  if(!s||!s.policy)return;
  const pill=document.getElementById('session-pill');
  if(!pill)return;
  const active=s.session_active;
  const policy=s.policy;
  const canSwitch=s.can_switch;
  const conns=s.active_conns||0;
  let label='';
  let color='var(--t2)';
  if(policy==='free'){label='\u{1F7E2} \u0421\u0432\u043e\u0431\u043e\u0434\u043d\u043e\u0435 \u043f\u0435\u0440\u0435\u043a\u043b.';color='var(--t2)';}
  else if(!canSwitch){label='\u{1F512} \u0421\u0435\u0441\u0441\u0438\u044f \u0430\u043a\u0442\u0438\u0432\u043d\u0430 ('+conns+' conn)';color='var(--ye)';}
  else{label='\u{1F7E2} \u041c\u043e\u0436\u043d\u043e \u043f\u0435\u0440\u0435\u043a\u043b\u044e\u0447\u0438\u0442\u044c';color='var(--gr)';}
  pill.textContent=label;
  pill.style.color=color;
  // \u041a\u043d\u043e\u043f\u043a\u0430 Force Switch
  const fsBtn=document.getElementById('btn-force-switch');
  if(fsBtn)fsBtn.style.display=sessionStatus.connected?'':'none';
}
async function setSessionPolicy(policy){
  await fetch(B+'/api/session/policy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({policy})});
  await loadSessionStatus();
}
async function doForceSwitch(){
  if(!confirm('\u0421\u043c\u0435\u043d\u0438\u0442\u044c \u0441\u0435\u0440\u0432\u0435\u0440 \u0441\u0435\u0439\u0447\u0430\u0441? \u041e\u0442\u043a\u0440\u044b\u0442\u044b\u0435 \u0441\u0430\u0439\u0442\u044b \u043c\u043e\u0433\u0443\u0442 \u043f\u043e\u0442\u0440\u0435\u0431\u043e\u0432\u0430\u0442\u044c \u043f\u043e\u0432\u0442\u043e\u0440\u043d\u0443\u044e \u0430\u0432\u0442\u043e\u0440\u0438\u0437\u0430\u0446\u0438\u044e.'))return;
  await fetch(B+'/api/session/force-switch',{method:'POST'});
  await loadSessionStatus();
}
async function loadDPIStatus(){try{dpiStatus=await fetch(B+'/api/dpi/status').then(r=>r.json());renderDPIStatus();}catch(e){}}
function renderDPIStatus(){
  // U-12 (TZ v1.4): dead pad/#t-pad-std/#t-pad-agg/#padding-status branch removed. Traffic
  // Padding was already marked "not implemented" by K2-W (TestTrafficPadding_NotActivePromise)
  // and the toggles were removed from the HTML then, but this JS status-sync leftover stayed
  // dead (structural test of this lot, TestUIStructure_NoDeadElementIDs, caught the remainder).
  const cdn=dpiStatus.cdn_status;if(cdn&&cdn.worker_domain){const w=document.getElementById('cdn-worker');if(w)w.value=cdn.worker_domain;}const stls=dpiStatus.shadowtls_status;if(stls){const ts=document.getElementById('t-stls');if(ts)ts.className='toggle'+(stls.enabled?' on':'');const ss=document.getElementById('stls-sni');if(ss&&stls.handshake_sni)ss.value=stls.handshake_sni;const sa=document.getElementById('stls-server');if(sa&&stls.server_addr)sa.value=stls.server_addr;}const c=dpiStatus.canary;if(c)renderCanaryResult(c);}
async function runCanaryTest(){const btn=document.getElementById('canary-btn');const res=document.getElementById('canary-result');btn.textContent='\u23f3 \u0422\u0435\u0441\u0442...';btn.disabled=true;if(res){res.textContent='\u0417\u0430\u043f\u0443\u0441\u043a\u0430\u044e...';res.style.color='var(--t2)';}const ch=document.getElementById('canary-checks');if(ch)ch.innerHTML='';try{const d=await fetch(B+'/api/dpi/canary-test',{method:'POST'}).then(r=>r.json());if(d.error){if(res)res.textContent='\u041e\u0448\u0438\u0431\u043a\u0430: '+d.error;return;}renderCanaryResult(d);if(d.vpn_detectable){const nb=document.getElementById('nb-dpi');if(nb)nb.style.display='';}await loadDPIStatus();}catch(e){if(res)res.textContent='\u041e\u0448\u0438\u0431\u043a\u0430: '+e.message;}finally{btn.textContent='\u25b6 \u0422\u0435\u0441\u0442';btn.disabled=false;}}
function renderCanaryResult(d){const score=d.score||0;const lbl=document.getElementById('canary-score-label');const fill=document.getElementById('canary-score-fill');const res=document.getElementById('canary-result');const checks=document.getElementById('canary-checks');if(lbl)lbl.textContent=score+'/100';if(fill){fill.style.width=score+'%';fill.style.background=score>=75?'var(--re)':score>=50?'var(--or)':score>=25?'var(--ye)':'var(--gr)';}if(res){const icon=score>=50?'\ud83d\udd34':score>=25?'\ud83d\udfe1':'\ud83d\udfe2';res.textContent=icon+' '+(d.diagnosis||'')+(d.recommendation?'\n\u0420\u0435\u043a.: '+d.recommendation:'');res.style.color=score>=50?'var(--re)':score>=25?'var(--ye)':'var(--gr)';}if(checks){const items=[{label:'TLS Fingerprint',val:d.tls_leaked,bad:true},{label:'Timing Anomaly',val:d.timing_anomaly,bad:true},{label:'High Entropy',val:d.entropy_high,bad:true}];checks.innerHTML=items.map(i=>{const ok=i.bad?!i.val:i.val;return '<div style="background:var(--s2);border:1px solid var(--bd);border-radius:6px;padding:8px 10px;font-size:11px"><span style="color:'+(ok?'var(--gr)':'var(--re)')+'">'+(ok?'\u2714':'\u2716')+'</span> '+esc(i.label)+'</div>';}).join('');}}
async function saveCDN(){const domain=document.getElementById('cdn-worker').value.trim();const fb=document.getElementById('cdn-fb');if(fb){fb.textContent='...';fb.className='inp-fb';}try{const d=await fetch(B+'/api/dpi/cdn',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({worker_domain:domain,backend_host:'',backend_port:443})}).then(r=>r.json());if(fb){fb.textContent=d.status==='ok'?'\u2713 \u0421\u043e\u0445\u0440\u0430\u043d\u0435\u043d\u043e':'\u041e\u0448\u0438\u0431\u043a\u0430';fb.className='inp-fb '+(d.status==='ok'?'ok':'err');}}catch(e){if(fb){fb.textContent='\u041e\u0448\u0438\u0431\u043a\u0430';fb.className='inp-fb err';}}setTimeout(()=>{if(fb)fb.textContent=''},3000);}
function downloadWorkerScript(){window.open(B+'/api/dpi/cdn-worker-script','_blank');}
// P1-1 (аудит 2026-09-01): раньше клик по тумблеру всегда красил его "on" независимо от
// ответа сервера — при отсутствии пароля/адреса реального сервера запрос отклонялся (400),
// а UI молча показывал "включено". Теперь тумблер откатывается назад и ошибка видна в
// подсказке под формой.
async function togShadowTLS(el){
  const wasOn=el.classList.contains('on');
  el.classList.toggle('on');
  const enabled=el.classList.contains('on');
  const si=document.getElementById('stls-sni');const pi=document.getElementById('stls-pwd');
  const sa=document.getElementById('stls-server');
  const sni=(si?si.value:'')||'www.bing.com';const pwd=pi?pi.value:'';const serverAddr=sa?sa.value.trim():'';
  const fb=document.getElementById('stls-fb');
  try{
    const r=await fetch(B+'/api/dpi/shadowtls',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled,password:pwd,sni,server:sni+':443',server_addr:serverAddr})});
    if(!r.ok){
      el.classList.toggle('on',wasOn);
      const msg=await r.text();
      if(fb){fb.textContent='Ошибка: '+msg;fb.className='inp-fb err';setTimeout(()=>{fb.textContent='';},5000);}
    }
  }catch(e){
    el.classList.toggle('on',wasOn);
  }
}
async function autoSelectSNI(){const btns=document.querySelectorAll('[onclick="autoSelectSNI()"]');const btn=btns[0];const fb=document.getElementById('stls-fb');if(btn){btn.textContent='\u23f3...';btn.disabled=true;}try{const d=await fetch(B+'/api/dpi/shadowtls-auto-sni',{method:'POST'}).then(r=>r.json());const si=document.getElementById('stls-sni');if(d.sni&&si){si.value=d.sni;if(fb){fb.textContent='\u2713 '+d.sni;fb.className='inp-fb ok';}}else if(fb){fb.textContent='\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c';fb.className='inp-fb err';}}catch(e){if(fb){fb.textContent='err';fb.className='inp-fb err';}}if(btn){btn.textContent='\u2728 \u0410\u0432\u0442\u043e';btn.disabled=false;}setTimeout(()=>{if(fb)fb.textContent=''},3000);}
async function saveShadowTLS(){const fb=document.getElementById('stls-fb');const ts=document.getElementById('t-stls');const pi=document.getElementById('stls-pwd');const si=document.getElementById('stls-sni');const sa=document.getElementById('stls-server');const enabled=ts?ts.classList.contains('on'):false;const pwd=pi?pi.value:'';const sni=(si?si.value:'')||'www.bing.com';const serverAddr=sa?sa.value.trim():'';if(fb){fb.textContent='...';fb.className='inp-fb';}try{const r=await fetch(B+'/api/dpi/shadowtls',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled,password:pwd,sni,server:sni+':443',server_addr:serverAddr})});const ok=r.ok;const msg=ok?'\u2713 \u0421\u043e\u0445\u0440\u0430\u043d\u0435\u043d\u043e':'\u041e\u0448\u0438\u0431\u043a\u0430: '+await r.text();if(fb){fb.textContent=msg;fb.className='inp-fb '+(ok?'ok':'err');}}catch(e){if(fb){fb.textContent='\u041e\u0448\u0438\u0431\u043a\u0430';fb.className='inp-fb err';}}setTimeout(()=>{if(fb)fb.textContent=''},4000);}

// ── Catalog ───────────────────────────────────────────────────────────────
let catalogData=[];
async function loadCatalog(){
  try{
    catalogData=await fetch(B+'/api/catalog/status').then(r=>r.json())||[];
    renderCatalog();
  }catch(e){}
}
function renderCatalog(){
  const el=document.getElementById('catalog-providers-list');
  if(!catalogData||!catalogData.length){el.innerHTML='<div style="color:var(--t2);padding:20px">\u041d\u0435\u0442 \u043f\u0440\u043e\u0432\u0430\u0439\u0434\u0435\u0440\u043e\u0432</div>';return;}
  el.innerHTML=catalogData.map(p=>{
    const total=p.node_count||0;
    const ok=p.enabled;
    const trust=Math.round((p.trust_score||0)*100);
    const updated=p.last_updated?new Date(p.last_updated).toLocaleString('ru'):'\u2014';
    return '<div class="panel" style="margin-bottom:10px"><div class="panel-hd">'+
      '<span>'+esc(p.name)+'</span>'+
      '<div style="display:flex;align-items:center;gap:8px">'+
      '<span class="pill '+(ok?'p-ok':'p-unk')+'">'+(ok?'\u0410\u043a\u0442':'\u0412\u044b\u043a\u043b')+'</span>'+
      '<button class="btn btn-sm" onclick="toggleProvider(\''+esc(p.id)+'\','+!ok+')">'+(ok?'\u0412\u044b\u043a\u043b':'\u0412\u043a\u043b')+'</button>'+
      '</div></div>'+
      '<div class="panel-bd" style="padding:10px 16px;font-size:12px;color:var(--t2)">'+
      '\u0422\u0438\u043f: <b>'+esc(p.type)+'</b> &nbsp;&nbsp; \u0414\u043e\u0432\u0435\u0440\u0438\u0435: <b>'+trust+'%</b> &nbsp;&nbsp; \u0423\u0437\u043b\u043e\u0432: <b>'+total+'</b><br>'+
      '\u0421\u043a\u043e\u0440\u043e\u0441\u0442\u044c: '+esc(p.speed_class||'\u2014')+' &nbsp;&nbsp; \u041e\u0431\u043d.: '+updated+
      '</div></div>';
  }).join('');
}
async function toggleProvider(id,enabled){
  await fetch(B+'/api/catalog/provider',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,enabled})});
  await loadCatalog();
}
async function doCatalogRefresh(){
  const btn=document.getElementById('catalog-refresh-btn');
  const txt=document.getElementById('catalog-status-txt');
  btn.disabled=true;btn.textContent='\u23f3 \u0417\u0430\u0433\u0440\u0443\u0437\u043a\u0430...';
  txt.textContent='';
  try{
    await fetch(B+'/api/catalog/refresh',{method:'POST'});
    txt.textContent='\u0417\u0430\u043f\u0443\u0449\u0435\u043d\u043e! \u0417\u0430\u0433\u0440\u0443\u0437\u043a\u0430 \u0437\u0430\u043d\u0438\u043c\u0430\u0435\u0442 1-3 \u043c\u0438\u043d.';
    txt.style.color='var(--gr)';
    // \u0427\u0435\u0440\u0435\u0437 30\u0441 \u043e\u0431\u043d\u043e\u0432\u043b\u044f\u0435\u043c \u0441\u0442\u0430\u0442\u0443\u0441 \u043f\u0440\u043e\u0432\u0430\u0439\u0434\u0435\u0440\u043e\u0432
    setTimeout(loadCatalog,30000);
  }catch(e){
    txt.textContent='\u041e\u0448\u0438\u0431\u043a\u0430';
    txt.style.color='var(--re)';
  }
  setTimeout(()=>{btn.disabled=false;btn.textContent='\u21ba \u041e\u0431\u043d\u043e\u0432\u0438\u0442\u044c';},3000);
}

// ── AdBlock ───────────────────────────────────────────────────────────────
let abStatus={};
async function loadAdBlock(){
  try{
    abStatus=await fetch(B+'/api/adblock/status').then(r=>r.json());
    renderAdBlock();
  }catch(e){}
}
function renderAdBlock(){
  const s=abStatus;
  const prof=s.profile||'disabled';
  // \u0412\u044b\u0441\u0432\u0435\u0447\u0438\u0432\u0430\u0435\u043c \u0430\u043a\u0442\u0438\u0432\u043d\u044b\u0439 \u043f\u0440\u043e\u0444\u0438\u043b\u044c
  ['disabled','light','standard','strict'].forEach(p=>{
    const el=document.getElementById('ab-p-'+p);
    if(!el)return;
    el.style.borderColor=prof===p?'var(--ac)':'var(--bd)';
    el.style.background=prof===p?'rgba(79,142,247,.06)':'';
  });
  const ps=document.getElementById('ab-profile-status');
  if(ps){
    const labels={disabled:'\u0412\u044b\u043a\u043b\u044e\u0447\u0435\u043d',light:'Light \u2014 \u0437\u0430\u0433\u0440\u0443\u0437\u043a\u0430 \u0437\u0430\u043d\u0438\u043c\u0430\u0435\u0442 ~1 \u043c\u0438\u043d',standard:'Standard \u2014 \u0437\u0430\u0433\u0440\u0443\u0437\u043a\u0430 ~2 \u043c\u0438\u043d',strict:'Strict \u2014 \u0437\u0430\u0433\u0440\u0443\u0437\u043a\u0430 ~3-5 \u043c\u0438\u043d'};
    ps.textContent='\u041f\u0440\u043e\u0444\u0438\u043b\u044c: '+(labels[prof]||prof);
  }
  const d=document.getElementById('ab-domains');
  if(d)d.textContent=(s.total_domains||0).toLocaleString();
  const src=document.getElementById('ab-sources');
  if(src)src.textContent=(s.sources_loaded||0)+'/'+(s.sources_loaded+s.sources_failed||0);
  const upd=document.getElementById('ab-updated');
  if(upd&&s.last_updated)upd.textContent=new Date(s.last_updated).toLocaleString('ru');
  // allowlist
  const al=document.getElementById('ab-allowlist');
  if(al){
    const list=s.allowlist||[];
    if(!list.length){al.innerHTML='<span style="color:var(--t3)">\u041f\u0443\u0441\u0442\u043e</span>';return;}
    al.innerHTML=list.map(d=>'<div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-bottom:1px solid var(--bd)"><span>'+esc(d)+'</span><button class="btn btn-red btn-sm" onclick="removeAllowlist(\''+esc(d)+'\')">&times;</button></div>').join('');
  }
}
async function setAdBlockProfile(p){
  try{
    await fetch(B+'/api/adblock/profile',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({profile:p})});
    abStatus.profile=p;
    renderAdBlock();
    // \u0427\u0435\u0440\u0435\u0437 10\u0441 \u043e\u0431\u043d\u043e\u0432\u043b\u044f\u0435\u043c \u0441\u0442\u0430\u0442\u0438\u0441\u0442\u0438\u043a\u0443
    setTimeout(loadAdBlock,10000);
  }catch(e){}
}
// P1-6: ответ сервера теперь может быть отказом (не домен / уже в списке) — молча его
// проглатывать нельзя, иначе поле очищается и выглядит как успех.
async function toggleAllowlist(d,add){
  const r=await fetch(B+'/api/adblock/allowlist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain:d,add:add})});
  if(!r.ok){
    let msg='';
    try{msg=(await r.json()).error||'';}catch(e){}
    alert('Белый список: '+(msg||('ошибка '+r.status)));
    return false;
  }
  return true;
}
async function addToAllowlist(){
  const inp=document.getElementById('ab-allow-inp');
  const d=(inp?inp.value:'').trim();
  if(!d)return;
  if(!await toggleAllowlist(d,true))return;
  if(inp)inp.value='';
  await loadAdBlock();
}
async function removeAllowlist(d){
  if(!await toggleAllowlist(d,false))return;
  await loadAdBlock();
}

// ── Sprint S3: Privacy Wizard ───────────────────────────────────────────────────────
let privData={ip_leak:'full',dns:'on',adblock:'standard'};
let privStep=0;

// U-12 (ТЗ v1.4): startWizFlow раньше искал #wiz-flow-select — id, никогда не объявленный в
// HTML (мёртвая ссылка, D2 §6.1) — и wizResetFlow() (тоже завязанный на этот несуществующий
// id) не вызывался ниоткуда вовсе. Переключение между "wiz-setup"/"wiz-privacy" уже полностью
// делает переключатель страниц (см. onclick навигации сайдбара, ветка data-page==='wizard'),
// который прячет/показывает оба блока напрямую — отдельный "экран выбора" не нужен и никогда
// не был реализован. Оба мёртвых фрагмента удалены, а не подключены к несуществующему UI.
function startWizFlow(flow){
  const setup=document.getElementById('wiz-setup');
  const priv=document.getElementById('wiz-privacy');
  // B4 #5 (аудит 2026-09-07): startPrivacyWizard() кликает по «Мастер» (показывает #wiz-setup,
  // см. переключение страниц выше) и ТОЛЬКО ПОТОМ вызывает startWizFlow('privacy') — без явного
  // скрытия соседнего flow оба блока оставались видимыми одновременно наложением. Прячем
  // неактивный flow при каждом вызове, а не только показываем нужный.
  if(flow==='setup'){if(priv)priv.style.display='none';if(setup){setup.style.display='';wizStep=0;resetWizSteps();}}
  else if(flow==='privacy'){if(setup)setup.style.display='none';if(priv){priv.style.display='';privStep=0;resetPrivSteps();}}
}

function resetWizSteps(){
  for(let i=0;i<4;i++){
    const dot=document.getElementById('wd-'+i);
    const card=document.getElementById('ws-'+i);
    const line=document.getElementById('wl-'+i);
    if(dot){dot.className='wiz-dot'+(i===0?' active':'');dot.textContent=i+1;}
    if(card)card.style.display=i===0?'block':'none';
    if(line)line.className='wiz-line';
  }
}

function resetPrivSteps(){
  for(let i=0;i<4;i++){
    const dot=document.getElementById('pwd-'+i);
    const card=document.getElementById('pws-'+i);
    const line=document.getElementById('pwl-'+i);
    if(dot){dot.className='wiz-dot'+(i===0?' active':'');dot.textContent=i+1;}
    if(card)card.style.display=i===0?'block':'none';
    if(line)line.className='wiz-line';
  }
}

function selPriv(el,key){
  el.closest('.wiz-options').querySelectorAll('.wiz-opt').forEach(o=>o.classList.remove('sel'));
  el.classList.add('sel');
  privData[key]=el.dataset.val;
}

function privNext(step){
  const card=document.getElementById('pws-'+step);
  const dot=document.getElementById('pwd-'+step);
  const line=document.getElementById('pwl-'+step);
  if(card)card.style.display='none';
  if(dot){dot.className='wiz-dot done';dot.textContent='\u2713';}
  if(line)line.className='wiz-line done';
  privStep=step+1;
  const next=document.getElementById('pws-'+privStep);
  const nextDot=document.getElementById('pwd-'+privStep);
  if(next)next.style.display='block';
  if(nextDot)nextDot.className='wiz-dot active';
  if(privStep===3)buildPrivSummary();
}

function privBack(step){
  const card=document.getElementById('pws-'+step);
  if(card)card.style.display='none';
  const prevDot=document.getElementById('pwd-'+(step-1));
  const prevLine=document.getElementById('pwl-'+(step-1));
  if(prevDot){prevDot.className='wiz-dot active';prevDot.textContent=step;}
  if(prevLine)prevLine.className='wiz-line';
  privStep=step-1;
  const prev=document.getElementById('pws-'+privStep);
  if(prev)prev.style.display='block';
}

function buildPrivSummary(){
  const ipMap={full:'🔒 IPv6 Guard + WebRTC Guard',ipv6only:'🔸 Только IPv6 Guard',skip:'⏩ Оставить текущие'};
  const dnsMap={on:'✅ Тест каждые 5 мин',off:'⏩ Только вручную'};
  const abMap={standard:'🟢 Standard (50k)',light:'🟡 Light (10k)',disabled:'⏩ Выключен'};
  const el=document.getElementById('priv-summary');
  if(el)el.innerHTML='🌐 IP-утечки: <b>'+(ipMap[privData.ip_leak]||privData.ip_leak)+'</b><br>'+
    '🔍 DNS-монитор: <b>'+(dnsMap[privData.dns]||privData.dns)+'</b><br>'+
    '🚫 AdBlock: <b>'+(abMap[privData.adblock]||privData.adblock)+'</b>';
}

async function privFinish(){
  const status=document.getElementById('priv-status');
  if(status)status.textContent='Применяю...';
  const patch={};
  // IPv6 + WebRTC
  if(privData.ip_leak==='full'){patch.block_ipv6_leak=true;patch.block_webrtc=true;}
  else if(privData.ip_leak==='ipv6only'){patch.block_ipv6_leak=true;patch.block_webrtc=false;}
  // DNS test interval
  if(privData.dns==='on'){patch.dns_leak_test_interval=300;}
  else{patch.dns_leak_test_interval=0;}
  // AdBlock
  patch.adblock_profile=privData.adblock;
  try{
    // Сохраняем конфиг
    const r=await fetch(B+'/api/save-config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(patch)});
    if(!r.ok){
      const d=await r.json().catch(()=>({}));
      if(status){status.textContent='✗ '+(d.error||('Ошибка HTTP '+r.status));status.style.color='var(--re)';}
      return;
    }
    // Применяем IPv6/WebRTC живьём
    if(privData.ip_leak!=='skip'){
      if(privData.ip_leak==='full'||privData.ip_leak==='ipv6only'){
        await fetch(B+'/api/leakguard/ipv6',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:true})}).catch(()=>{});
      }
      if(privData.ip_leak==='full'){
        await fetch(B+'/api/leakguard/webrtc',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:true})}).catch(()=>{});
      }
    }
    // Применяем AdBlock
    if(privData.adblock!=='disabled'){
      await fetch(B+'/api/adblock/profile',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({profile:privData.adblock})}).catch(()=>{});
    }
    if(status){
      status.textContent='✅ Готово! Настройки применены.'+(privData.adblock!=='disabled'?' AdBlock загружается в фоне...':'');
      status.style.color='var(--gr)';
    }
    // Через 3с переходим на Dashboard
    setTimeout(()=>{ document.querySelector('[data-page="dashboard"]').click(); },3000);
  }catch(e){
    if(status){status.textContent='Ошибка: '+e.message;status.style.color='var(--re)';}
  }
}

// Вызывается из Help-страницы
function startPrivacyWizard(){
  document.querySelector('[data-page="wizard"]').click();
  setTimeout(()=>startWizFlow('privacy'),50);
}
// ── Anti-Block (Sprint S6) ──────────────────────────────────────────────────
let ab2Status={};
async function loadAntiBlock(){
  try{
    ab2Status=await fetch(B+'/api/antiblock/status').then(r=>r.json());
    renderAntiBlock();
  }catch(e){}
  try{
    const rules=await fetch(B+'/api/antiblock/bypass-list').then(r=>r.json())||[];
    renderBypassRules(rules);
  }catch(e){}
}
function renderAntiBlock(){
  const s=ab2Status;
  setTog('t-ab2-enabled',s.enabled===true);
  setTog('t-ab2-res',s.residential_only===true);
  setTog('t-ab2-auto',s.auto_switch===true);
  const ps=s.pool_stats||{};
  const res=document.getElementById('ab2-stat-res');
  if(res)res.textContent=(ps.residential||0);
  const dc=document.getElementById('ab2-stat-dc');
  if(dc)dc.textContent=(ps.datacenter||0);
  const pr=document.getElementById('ab2-stat-proxy');
  if(pr)pr.textContent=(ps.proxy_vpn||0);
  const uk=document.getElementById('ab2-stat-unk');
  if(uk)uk.textContent=(ps.unknown||0);
  // Текущий IP
  const ipInfo=s.current_ip_info;
  if(ipInfo)renderIPResult('ab2-ip-result',ipInfo);
}
function renderIPResult(elId,info){
  const el=document.getElementById(elId);
  if(!el)return;
  const label=info.label||'unknown';
  const score=info.risk_score||0;
  const ok=info.good_streaming;
  const color=ok?'var(--gr)':(score>60?'var(--re)':'var(--ye)');
  const icon=ok?'✅':'⚠️';
  el.innerHTML=
    '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">'+
    '<span style="font-size:14px;font-weight:700;color:'+color+'">'+icon+' '+esc(label.charAt(0).toUpperCase()+label.slice(1))+'</span>'+
    '<span style="font-family:monospace;font-size:12px;color:var(--t2)">Риск: '+score+'/100</span>'+
    '</div>'+
    '<div style="font-size:12px;color:var(--t2);line-height:1.8">'+
    /* P0-3: это ответ СТОРОННЕГО API репутации IP (ip-api.com / proxycheck.io), который
       вдобавок ходит по открытому HTTP — то есть содержимое подменяемо на пути. Раньше все
       пять полей вставлялись в innerHTML вообще без экранирования. */
    'IP: <b style="color:var(--t1)">'+esc(info.ip||'—')+'</b><br>'+
    'ISP: <b>'+esc(info.isp||'—')+'</b><br>'+
    'ASN: '+esc(info.asn||'—')+'<br>'+
    'Страна: '+esc(info.country||'—')+'<br>'+
    'Источник: '+esc(info.source||'—')+
    '</div>'+
    '<div style="margin-top:8px;font-size:12px;color:'+(ok?'var(--gr)':'var(--re)')+'">'+(ok?'✔ Подходит для Netflix/банков':'✖ Может быть заблокирован стримингами')+'</div>';
}
async function checkCurrentIP(){
  const el=document.getElementById('ab2-ip-result');
  if(el)el.innerHTML='<div style="color:var(--t2);font-size:12px">Проверяю...</div>';
  try{
    const d=await fetch(B+'/api/antiblock/check-ip',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:'current'})}).then(r=>r.json());
    if(d.error){if(el)el.innerHTML='<div style="color:var(--re);font-size:12px">Ошибка: '+esc(d.error)+'</div>';return;}
    renderIPResult('ab2-ip-result',d);
  }catch(e){if(el)el.innerHTML='<div style="color:var(--re);font-size:12px">Ошибка: '+e.message+'</div>';}
}
async function checkCustomIP(){
  const inp=document.getElementById('ab2-check-ip');
  const res=document.getElementById('ab2-custom-result');
  const ip=(inp?inp.value:'').trim();
  if(!ip)return;
  if(res)res.textContent='Проверяю...';
  try{
    const d=await fetch(B+'/api/antiblock/check-ip',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})}).then(r=>r.json());
    if(d.error){if(res)res.textContent='Ошибка: '+d.error;return;}
    const ok=d.good_streaming;
    const label=d.label||'unknown';
    const color=ok?'var(--gr)':(d.risk_score>60?'var(--re)':'var(--ye)');
    if(res){
      res.innerHTML='<span style="color:'+color+'">'+(ok?'✅':'⚠️')+'</span>'+
        ' '+esc(label)+' | ISP: '+esc(d.isp||'—')+ ' | Риск: '+d.risk_score+'/100';
    }
  }catch(e){if(res)res.textContent='Ошибка: '+e.message;}
}
async function toggleAntiBlock(el,type){
  el.classList.toggle('on');
  const enabled=document.getElementById('t-ab2-enabled').classList.contains('on');
  const res=document.getElementById('t-ab2-res').classList.contains('on');
  const auto=document.getElementById('t-ab2-auto').classList.contains('on');
  await fetch(B+'/api/antiblock/config',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({enabled,residential_only:res,auto_switch:auto})});
}
let bypassRules=[],editingBypassId='';
function renderBypassRules(rules){
  bypassRules=rules||[];
  const el=document.getElementById('ab2-bypass-list');
  if(!el)return;
  if(!rules||!rules.length){el.innerHTML='<div style="color:var(--t3);padding:12px 16px;font-size:12px">Список пуст</div>';return;}
  el.innerHTML=rules.map(r=>{
    const ok=r.enabled;
    return '<div style="display:flex;align-items:center;justify-content:space-between;padding:8px 16px;border-bottom:1px solid var(--bd)">'+
      '<div>'+
      '<span style="font-size:13px;font-weight:600">'+(r.direct_route?'➡ ':r.require_residential?'🏠 ':'🌐 ')+esc(r.name)+'</span>'+
      '<span class="pill '+(ok?'p-ok':'p-unk')+'" style="margin-left:8px">'+(ok?'Вкл':'Выкл')+'</span>'+
      (r.direct_route?'<span style="margin-left:6px;font-size:11px;color:var(--re)">прямой маршрут</span>':'')+
      (r.prefer_country?'<span style="margin-left:6px;font-size:11px;color:var(--t3)">🏳️'+esc(r.prefer_country)+'</span>':'')+
      '<br><span style="font-size:11px;color:var(--t3)">'+(r.notes?esc(r.notes):'')+'</span>'+
      '</div>'+
      '<div style="display:flex;gap:6px">'+
      (!r.builtin?'<button class="btn btn-sm" onclick="editBypassRule(\'' + esc(r.id) + '\')">✎</button>':'')+
      '<button class="btn btn-sm" onclick="toggleBypassRule(\'' + esc(r.id) + '\',' + !ok + ')">'+(ok?'Выкл':'Вкл')+'</button>'+
      (!r.builtin?'<button class="btn btn-sm btn-red" onclick="removeBypassRule(\'' + esc(r.id) + '\')">&#10005;</button>':'')+
      '</div></div>';
  }).join('');
}
function updateDirectRouteWarning(){
  const sel=document.getElementById('ab2-domain-type');
  const warn=document.getElementById('ab2-direct-warn');
  if(warn)warn.style.display=(sel&&sel.value==='direct')?'':'none';
}
// U-11 (ТЗ v1.4): редактирование существующего правила — заполняет ту же форму добавления
// значениями правила и переключает submit-кнопку в режим "Сохранить" (UpdateBypassDomain по id).
function editBypassRule(id){
  const r=bypassRules.find(x=>x.id===id);
  if(!r)return;
  editingBypassId=id;
  document.getElementById('ab2-domain-inp').value=r.domain||r.name||'';
  document.getElementById('ab2-domain-type').value=r.direct_route?'direct':'residential';
  updateDirectRouteWarning();
  document.getElementById('ab2-domain-form-title').textContent='Изменить правило:';
  document.getElementById('ab2-domain-submit').textContent='✓ Сохранить';
  document.getElementById('ab2-domain-cancel').style.display='';
}
function cancelEditBypassRule(){
  editingBypassId='';
  document.getElementById('ab2-domain-inp').value='';
  document.getElementById('ab2-domain-type').value='residential';
  updateDirectRouteWarning();
  document.getElementById('ab2-domain-form-title').textContent='Добавить домен:';
  document.getElementById('ab2-domain-submit').textContent='+ Добавить';
  document.getElementById('ab2-domain-cancel').style.display='none';
}
async function toggleBypassRule(id,enabled){
  await fetch(B+'/api/antiblock/bypass-list',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,enabled})});
  await loadAntiBlock();
}
async function removeBypassRule(id){
  if(!confirm('Удалить это правило bypass?'))return;
  await fetch(B+'/api/antiblock/bypass-domain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,remove:true})});
  await loadAntiBlock();
}
async function addBypassDomain(){
  const inp=document.getElementById('ab2-domain-inp');
  const d=(inp?inp.value:'').trim();
  if(!d)return;
  const typeSel=document.getElementById('ab2-domain-type');
  const isDirect=typeSel&&typeSel.value==='direct';
  // U-11: правило может нести risk класса "деанонимизация по выбору" (прямой маршрут, в обход
  // VPN) — тот же класс подтверждения, что и остальные опасные действия (§4 UI_CONTRACT_v1.4),
  // отдельно от общего confirm() выключения защит, т.к. здесь речь о СОЗДАНИИ нового риска.
  if(isDirect&&!confirm('Направить домен «'+d+'» напрямую, в обход VPN? Сайт увидит ваш настоящий IP-адрес.'))return;
  const body={domain:d,name:d,residential:!isDirect,direct_route:isDirect};
  if(editingBypassId)body.id=editingBypassId;
  const r=await fetch(B+'/api/antiblock/bypass-domain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const dd=await r.json().catch(()=>({}));
  if(dd.error){alert('Не удалось сохранить правило: '+dd.error);return;}
  if(inp)inp.value='';
  cancelEditBypassRule();
  await loadAntiBlock();
}
</script>
</body>
</html>`
