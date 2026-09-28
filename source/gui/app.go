package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/engine"
	"github.com/apf/adaptive-pathfinder/internal/harvester"
	"github.com/apf/adaptive-pathfinder/internal/hotkey"
	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/relay"
	"github.com/apf/adaptive-pathfinder/internal/singbox"
	"github.com/apf/adaptive-pathfinder/internal/singleinstance"
	"github.com/apf/adaptive-pathfinder/internal/version"
	"github.com/apf/adaptive-pathfinder/internal/web"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App — главный объект приложения, методы которого вызываются из JS
//
// Э-Win-TUN-2 (docs/TZ_WINDOWS_TUN_VPN_v1.0.md): до этой правки startup() поднимал
// СВОЙ engine.Engine безусловно, не участвуя в singleinstance.AcquireEngine() (которым
// уже пользуются cmd/apf, cmd/apf-tray, cmd/apf-svc, см. cmd/apf-tray/main.go:192-211).
// Для VPN-режима это структурная дыра: если движком уже владеет привилегированная
// служба apf-svc (Э-Win-TUN-1 — она и должна владеть TUN-сессией), GUI пытался бы
// поднять ВТОРОЙ sing-box без нужных прав на создание TUN-адаптера и падал бы с
// непонятным пользователю отказом ОС, вместо осмысленного делегирования владельцу.
//
// Теперь GUI тоже участвует в арбитраже: если лок достался — ведёт себя как раньше
// (владелец, локальный Engine). Если лок занят другим процессом — становится
// «наблюдателем»: не создаёт Engine вообще, а ходит в Web UI API (internal/web/
// server.go) уже запущенного владельца через webClient (webclient.go). Разделение по
// полю (a.engine != nil ⇔ владелец, a.remote != nil ⇔ наблюдатель) — оба разом не
// бывают ненулевыми.
type App struct {
	ctx    context.Context
	engine *engine.Engine // владелец: nil у наблюдателя
	remote *webClient     // наблюдатель: nil у владельца
	cfg    *models.AppConfig
	lock   *singleinstance.Lock // владелец, для освобождения в shutdown(); nil иначе

	// webSrv — S-8 (ТЗ v1.4): шов для web.Server.Close() на пути штатной остановки (см.
	// shutdown()/stopProcess ниже). ВСЕГДА nil в текущем коде: GUI (в отличие от cmd/apf-svc
	// и cmd/apf-tray) никогда не поднимает собственный internal/web.Server — владелец
	// (a.engine != nil) работает через Wails-биндинги напрямую, а не через встроенный HTTP
	// Web UI (проверено grep "web.New" по всему пакету gui — пусто). Поле и вызов Close()
	// оставлены для симметрии с остальными тремя владельцами процесса (acceptance-критерий
	// лота L1b-CLI прямо называет gui/app.go) и на случай, если GUI когда-нибудь тоже начнёт
	// поднимать web.Server — тогда достаточно один раз присвоить это поле.
	webSrv *web.Server

	// hotkeyMgr — P1.1 (docs/TZ_APF_ROADMAP_v1.2.md): активная регистрация системного
	// хоткея аварийного стирания (models.AppConfig.EmergencyHotkey). nil, если хоткей
	// выключен (пустая строка в конфиге) или регистрация не удалась (лог предупредит,
	// приложение всё равно продолжает работать — это не критичная для запуска функция).
	hotkeyMgr hotkey.Manager

	// logMu/pendingLogs — буфер для пакетной отправки логов во фронтенд (см. flushLogs).
	logMu       sync.Mutex
	pendingLogs []string
	// recentLogs — НЕ дренируется (в отличие от pendingLogs, который EventsEmit
	// опустошает каждые logFlushInterval): отдельный кольцевой буфер той же ёмкости, что
	// у web.Server.logs (300 строк), нужен только для CheckDomainRouting в
	// owner-режиме — она должна видеть историю, а не только то, что не успело
	// улететь во фронтенд с прошлого тика.
	recentLogs []string

	// ── L5-UI (ТЗ v1.4 §5): состояние ручного харвеста в owner-режиме ──
	// engine.HarvestNow синхронный и небыстрый, поэтому owner крутит его в горутине и отдаёт
	// прогресс/итог через HarvestStatus (index.html опрашивает, как GetScanProgress). Наблюдатель
	// (a.remote) сюда не пишет — он проксирует в web-API владельца. harvestMu защищает поля ниже.
	harvestMu       sync.Mutex
	harvestRunning  bool
	harvestDone     bool
	harvestErr      string
	harvestProgress harvester.Progress
	harvestResult   *engine.HarvestResult
}

// HarvestStatusView — плоский снимок прогресса/итога харвеста для фронтенда (Wails сериализует
// возврат биндинга в JSON). Наружу — только счётчики и контролируемые строки, БЕЗ сырых URL/
// содержимого источников (анти-XSS/анти-утечка секретов, как в web-лоте).
type HarvestStatusView struct {
	Running          bool   `json:"running"`
	Done             bool   `json:"done"`
	Error            string `json:"error,omitempty"`
	Phase            string `json:"phase"`
	SourceIndex      int    `json:"source_index"`
	SourceTotal      int    `json:"source_total"`
	Found            int    `json:"found"`
	Parsed           int    `json:"parsed"`
	Merged           int    `json:"merged"`
	SubscriptionURLs int    `json:"subscription_urls"`
	SourcesProcessed int    `json:"sources_processed"`
	SourcesTotal     int    `json:"sources_total"`
	Stopped          string `json:"stopped,omitempty"`
}

// NewApp создаёт экземпляр приложения
//
// Загружаем сохранённый config.json поверх DefaultConfig() — до этой правки GUI, как и
// служба/трей/CLI, каждый раз начинал с чистых дефолтов, молча теряя все сохранённые
// настройки пользователя между запусками (см. docs/TZ_CONFIG_RELOAD_AND_KS_SAFETY_v1.0.md,
// причина A — универсальный разрыв на всех точках входа).
func NewApp() *App {
	cfg := models.DefaultConfig()
	if found, err := config.LoadInto(cfg); err != nil {
		log.Printf("[APF] конфиг не загружен (%v), использую значения по умолчанию", err)
	} else if found {
		log.Printf("[APF] конфиг загружен: %s", config.ConfigPath())
	}
	// ТЗ v1.3 F5.2: одна нормализация на всех точках входа — неверное значение = дефолт + WARN.
	for _, w := range cfg.Normalize() {
		log.Printf("[APF] конфиг: %s", w)
	}
	return &App{cfg: cfg}
}

// startup вызывается при старте Wails-приложения
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.registerEmergencyHotkey()
	// Синхронно, НЕ go ensureServiceStarted() — см. waitServiceRunning в servicestart.go
	// (аудит: гонка singleinstance между GUI и свежезапущенной службой). Стоит лишний
	// раз подчеркнуть: цена этого — до serviceStartWaitTimeout добавочной задержки перед
	// появлением окна, и ТОЛЬКО в редком случае "служба не была поднята и её пришлось
	// запускать только что" (уже запущена/не установлена — обе ветки возвращаются почти
	// мгновенно, как и раньше).
	ensureServiceStarted()

	// B-0403 · R-3.1 (C-2), тот же паттерн, что в cmd/apf-tray/main.go:192-211 — захват
	// ДО engine.New, чтобы не создать движок, который тут же придётся бросить.
	lock, siErr := singleinstance.AcquireEngine()
	switch {
	case errors.Is(siErr, singleinstance.ErrAlreadyRunning):
		// config.ReadPortFile: владелец мог сесть не на cfg.WebUIPort (порт занят чужим
		// процессом — живой инцидент 2026-08-25, Docker Desktop/WSL); ok=false — файла
		// нет или он не читается, откатываемся на настроенный порт, как раньше этого
		// механизма (см. комментарий у WritePortFile).
		port := a.cfg.WebUIPort
		if real, ok := config.ReadPortFile(); ok {
			port = real
		}
		a.remote = newWebClient(port)
		a.startObserverPolling()
		return
	case siErr != nil:
		// Fail-open (тот же контракт, что и у остальных вызывающих singleinstance):
		// невозможность проверить — не повод не запускаться, продолжаем владельцем.
		log.Printf("[APF] проверка единственности экземпляра не удалась: %v (продолжаем)", siErr)
	default:
		a.lock = lock
	}

	a.engine = engine.New(a.cfg)

	// Пробрасываем события из engine во фронтенд через Wails Events.
	//
	// Лог — пакетно, НЕ одно EventsEmit на строку. Найдено живым инцидентом 2026-08-19
	// (docs/TZ_CONFIG_RELOAD_AND_KS_SAFETY_v1.0.md): при активном соединении sing-box
	// пишет по несколько строк В СЕКУНДУ (на каждое inbound/outbound-соединение), а при
	// шторме переподключений (нестабильные бесплатные узлы, Watchdog видит сбой →
	// Reload → снова сбой) — существенно больше. Раньше каждая строка была отдельным
	// EventsEmit → отдельная синхронная вставка DOM во фронтенде; десятки таких вставок
	// в секунду и давали ощущение «тупит» на клики. go func + startLogFlusher ниже
	// собирает строки и отдаёт фронтенду пачкой не чаще logFlushInterval.
	a.engine.OnLog = a.bufferLog
	a.startLogFlusher(ctx)
	a.engine.OnStateChange = func(state *models.ConnectionState) {
		wailsruntime.EventsEmit(ctx, "apf:state", state)
		updateTrayState(state)
	}
	a.engine.OnNodeUpdated = func(node *models.Node) {
		wailsruntime.EventsEmit(ctx, "apf:node_updated", node)
	}
	a.engine.OnProgress = func(pct int, msg string) {
		wailsruntime.EventsEmit(ctx, "apf:progress", map[string]interface{}{
			"pct": pct, "msg": msg,
		})
	}
	// ТЗ v1.3 F4 Stage 1: прогресс обхода пула — одно событие на пачку (200 узлов), не на узел.
	a.engine.OnScanProgress = func(p engine.ScanProgress) {
		wailsruntime.EventsEmit(ctx, "apf:scan", p)
	}
	// N-3 (ТЗ APF v1.5): прогресс пробы РЕАЛЬНОГО трафика («Собрать список рабочих узлов»,
	// internal/engine/node_check.go) — уже коалесцированный снимок с движка (буфер под checkMu,
	// флаш на каждое изменение счётчика, не по таймеру, см. bumpNodeCheck/emitNodeCheckStatus),
	// тот же приём EventsEmit-на-снимок, что и apf:scan чуть выше.
	a.engine.OnNodeCheckBatch = func(snap engine.NodeCheckStatusSnapshot) {
		wailsruntime.EventsEmit(ctx, "apf:node_check", snap)
	}
	// L5-UI (ТЗ v1.4 §5): прогресс ручного харвеста — и в снимок App (для опроса HarvestStatus),
	// и событием во фронтенд, тем же приёмом EventsEmit-на-снимок, что apf:scan/apf:node_check.
	a.engine.OnHarvestProgress = func(p harvester.Progress) {
		a.harvestMu.Lock()
		a.harvestProgress = p
		a.harvestMu.Unlock()
		wailsruntime.EventsEmit(ctx, "apf:harvest", p)
	}

	// Запускаем движок
	if err := a.engine.Start(); err != nil {
		a.bufferLog(fmt.Sprintf("Engine start error: %v", err))
	}
}

// logFlushInterval — как часто пачка накопленных строк лога уходит во фронтенд.
// Компромисс: реже — заметнее лаг между реальным событием и появлением строки в логе;
// чаще — меньше выигрыш от батчинга. 150мс незаметно для человека и на порядок снижает
// частоту EventsEmit/DOM-вставок при активном соединении (десятки строк/сек → ~6-7 пачек/сек).
const logFlushInterval = 150 * time.Millisecond

// bufferLog — обработчик Engine.OnLog: копит строки, не шлёт каждую немедленно
// (см. комментарий у startup() про инцидент 2026-08-19).
func (a *App) bufferLog(msg string) {
	a.logMu.Lock()
	a.pendingLogs = append(a.pendingLogs, msg)
	a.recentLogs = append(a.recentLogs, msg)
	if len(a.recentLogs) > 300 {
		a.recentLogs = a.recentLogs[len(a.recentLogs)-300:]
	}
	a.logMu.Unlock()
}

// startLogFlusher — периодически отдаёт накопленные строки фронтенду ОДНИМ EventsEmit
// (массив строк вместо одной строки за раз). Фронтенд (index.html) обрабатывает событие
// apf:log как массив и добавляет строки по очереди — сам порядок и мгновенность появления
// каждой строки в логе не меняются, меняется только частота пересечения Go↔JS границы.
func (a *App) startLogFlusher(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(logFlushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.logMu.Lock()
				if len(a.pendingLogs) == 0 {
					a.logMu.Unlock()
					continue
				}
				batch := a.pendingLogs
				a.pendingLogs = nil
				a.logMu.Unlock()
				wailsruntime.EventsEmit(ctx, "apf:log", batch)
			}
		}
	}()
}

// startObserverPolling — у наблюдателя нет колбэков движка (OnLog/OnStateChange и
// т.п. — это Go-объекты внутри ЧУЖОГО процесса), поэтому apf:state эмулируется
// периодическим опросом Web UI API владельца. Опрашивается только состояние
// подключения — этого достаточно, чтобы шапка интерфейса показывала актуальный
// статус; apf:log/apf:node_updated/apf:progress намеренно НЕ эмулируются в этой
// версии (не критично для корректности владения TUN — то, ради чего затевался
// Э-Win-TUN-2 — а не для полного паритета живых событий с владельцем).
func (a *App) startObserverPolling() {
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-a.ctx.Done():
				return
			case <-ticker.C:
				state := a.remote.GetState()
				wailsruntime.EventsEmit(a.ctx, "apf:state", state)
				updateTrayState(state)
			}
		}
	}()
}

// domReady вызывается когда DOM готов
func (a *App) domReady(ctx context.Context) {
	// Отправляем начальное состояние во фронтенд
	wailsruntime.EventsEmit(ctx, "apf:state", a.GetState())
	wailsruntime.EventsEmit(ctx, "apf:stats", a.GetStats())
}

// ─── S-8 (ТЗ v1.4): web.Server.Close() на пути штатной остановки ──────────────────────────
//
// K2-W добавил Server.Close() (internal/web/server.go), но ни один владелец процесса его не
// звал — фоновые горутины сервера (trackedGo, напр. apiCatalogRefresh) переживали остановку.
// webCloser/engineStopper — минимальные интерфейсы-швы: тест проверяет сам факт вызова без
// реального HTTP-сервера/сети (правило лота — бинарники не запускать). См. doc-комментарий у
// поля App.webSrv — в GUI это поле сейчас всегда nil, closer в этом случае остаётся
// нетипизированным nil (не typed-nil-в-интерфейсе), и stopProcess просто пропускает Close().

type webCloser interface{ Close() }
type engineStopper interface{ Stop() }

func stopProcess(webSrv webCloser, eng engineStopper) {
	if webSrv != nil {
		webSrv.Close()
	}
	if eng != nil {
		eng.Stop()
	}
}

// shutdown вызывается при закрытии
func (a *App) shutdown(ctx context.Context) {
	// Наблюдатель ничего не поднимал — закрывать нечего, и уж тем более не сигналим
	// remote.Disconnect(): закрытие ЭТОГО окна не должно рвать подключение владельца.
	if a.engine != nil {
		var closer webCloser
		if a.webSrv != nil {
			closer = a.webSrv
		}
		stopProcess(closer, a.engine)
	}
	if a.lock != nil {
		_ = a.lock.Close()
	}
	if a.hotkeyMgr != nil {
		a.hotkeyMgr.Unregister()
	}
}

// OpenWebUI — S-2 п.4 (ТЗ v1.4): открывает системный браузер на встроенный Web UI ВЛАДЕЛЬЦА
// процесса (служба/трей/другой экземпляр — см. webClient.Handoff()), а НЕ на голый "/":
// запрашивает одноразовый handoff-ключ под постоянным токеном и переходит на ".../ui?k=<k>".
// Постоянный токен в URL никогда не появляется.
//
// Работает только в режиме наблюдателя (a.remote != nil). У владельца (a.engine != nil)
// собственного web.Server в процессе GUI нет (см. doc-комментарий у App.webSrv) — открывать
// нечего, явная понятная ошибка вместо тихого перехода на "/" (который под S-2 отдал бы
// страницу без данных — токена/cookie у встроенного JS нет).
func (a *App) OpenWebUI() error {
	if a.remote == nil {
		return fmt.Errorf("APF управляет этим окном напрямую — отдельного Web UI здесь нет")
	}
	url, err := a.remote.Handoff()
	if err != nil {
		return fmt.Errorf("не удалось открыть Web UI: %w", err)
	}
	wailsruntime.BrowserOpenURL(a.ctx, url)
	return nil
}

// registerEmergencyHotkey — P1.1 (docs/TZ_APF_ROADMAP_v1.2.md): models.AppConfig.EmergencyHotkey
// годами показывался в UI/конфиге как рабочая аварийная защита, но ни один системный хоткей
// нигде не регистрировался — поле было чистым текстом. Работает и для владельца, и для
// наблюдателя (EmergencyWipe сама умеет оба пути), поэтому вызывается ДО ветвления
// владелец/наблюдатель в startup(). Пустая строка в конфиге = хоткей осознанно выключен
// пользователем — не пытаемся регистрировать пустую комбинацию. Провал регистрации (например,
// комбинация уже занята другим приложением) — не фатален для запуска APF, только лог.
func (a *App) registerEmergencyHotkey() {
	combo := a.cfg.EmergencyHotkey
	if combo == "" {
		return
	}
	mgr, err := hotkey.Register(combo, func() {
		// Прямой вызов EmergencyWipe(false, "WIPE") в обход обычного контракта "наберите
		// WIPE в поле подтверждения" (см. комментарий у App.EmergencyWipe) — тот контракт
		// защищает от случайного клика по кнопке в интерфейсе; здесь его аналог — сама
		// зажатая физически комбинация модификаторов, требовать от пользователя ЕЩЁ и
		// напечатать WIPE во время паники обесценивает саму идею аварийного хоткея.
		// wipeAll=false — тот же дефолт, что и у тумблера в интерфейсе (не трогает
		// bin/sing-box, только данные пользователя): полное стирание бинарника — редкий
		// сценарий, который эта комбинация никогда не спрашивает явно.
		result, err := a.EmergencyWipe(false, "WIPE")
		if err != nil {
			a.bufferLog(fmt.Sprintf("Аварийный хоткей: стирание не удалось: %v", err))
			return
		}
		a.bufferLog(fmt.Sprintf("Аварийный хоткей сработал: удалено файлов %v", result["files_deleted"]))
	})
	if err != nil {
		log.Printf("[APF] аварийный хоткей %q не зарегистрирован: %v", combo, err)
		return
	}
	a.hotkeyMgr = mgr
	log.Printf("[APF] аварийный хоткей зарегистрирован: %s", combo)
}

// ─── API методы — вызываются из JavaScript ────────────────────────────────────

// Connect запускает сканирование и подключение
func (a *App) Connect() error {
	if a.remote != nil {
		return a.remote.Connect()
	}
	go func() {
		if err := a.engine.ScanAndConnect(); err != nil {
			// U-14 (ТЗ v1.4): отдельное событие, а не apf:log — ошибка сканирования
			// рождается АСИНХРОННО (в этой горутине), синхронный return nil выше уже
			// ушёл вызывающей стороне JS до этого места, поймать её обычным try/catch
			// вокруг await App.Connect() невозможно. apf:log остаётся общим журналом
			// (без класса, попадает только на страницу «Лог»); apf:connect_error даёт
			// фронтенду шанс показать её тем же путём, что и остальные ошибки действий
			// пользователя (addLog(msg,'err') → toast, см. index.html).
			msg := fmt.Sprintf("Connect error: %v", err)
			wailsruntime.EventsEmit(a.ctx, "apf:connect_error", msg)
		}
	}()
	return nil
}

// Disconnect отключается
func (a *App) Disconnect() {
	if a.remote != nil {
		_ = a.remote.Disconnect()
		return
	}
	a.engine.Stop()
}

// ForceRescan — принудительное полное пересканирование
func (a *App) ForceRescan() {
	if a.remote != nil {
		_ = a.remote.ForceRescan()
		return
	}
	a.engine.ForceRescan()
}

// AddNode добавляет узел по ссылке
func (a *App) AddNode(link string) error {
	if a.remote != nil {
		return a.remote.AddNode(link)
	}
	return a.engine.AddNodeFromLink(link)
}

// AddNodeManual — P2.4 (docs/TZ_APF_ROADMAP_v1.2.md): редактор узла с продвинутыми полями
// (Reality public_key/short_id, transport ws/grpc, VMess AltID и т.п.) — то, что не влезает в
// формат простой ссылки vless://.../.  Engine.AddNodeManual и HTTP-эквивалент
// /api/add-node-manual существовали и были протестированы задолго до этой правки (B-29); не
// хватало только формы во фронтенде, которая их вызывает.
func (a *App) AddNodeManual(node *models.Node) error {
	if a.remote != nil {
		return a.remote.AddNodeManual(node)
	}
	return a.engine.AddNodeManual(node)
}

// ConnectChainPartner — точка входа роли «Вход» (§4, docs/PLAN_2026-08-28_
// stubs_and_realfunc.md): вставить ссылку от партнёра в роли «Выход» и подключиться сразу,
// без ожидания планового ScanAndConnect. Отдельно от AddNode — партнёр не взаимозаменяем с
// публичными узлами (см. Engine.AddChainPartnerFromLink).
func (a *App) ConnectChainPartner(link string) (*models.Node, error) {
	if a.remote != nil {
		return a.remote.ConnectChainPartner(link)
	}
	return a.engine.AddChainPartnerFromLink(link)
}

// GetState возвращает текущее состояние соединения
func (a *App) GetState() *models.ConnectionState {
	if a.remote != nil {
		return a.remote.GetState()
	}
	return a.engine.GetState()
}

// nodeWithVerifyBadge — узел плюс значок проверенности трафиком (models.Node.VerifyBadge),
// то же зеркало, что уже есть в internal/web/server.go (nodeWithBadge/attachVerifyBadges).
// VerifyBadge — МЕТОД, сам по себе в JSON не попадает; вычисляем один раз здесь. Опционально
// B4 #3 (консилиум BLACKBOX_AUDIT 2026-09-07): раньше Wails отдавал голый []*models.Node без
// этого поля — таблица узлов показывала только бинарный ✓/пусто из verified_count вместо
// шести состояний, которые уже видят Android/Web (D3 §3).
// C-21-ui (ТЗ v1.4, §2.5 контракта UI_CONTRACT_v1.4.md): CatalogCountry/ExitCountry/
// CountryMismatch — методы models.Node (не JSON-поля), поэтому JSON *models.Node,
// возвращаемый как есть, их не несёт — тем же приёмом, что уже применён к VerifyBadge
// ниже, вычисляем один раз здесь и отдаём готовыми полями. Данные для ExitCountry
// (models.Node.LastVerifiedCountry) заполняет движок (L1b-ENG2, C-21) — этот лот только
// показывает то, что уже есть в узле.
type nodeWithVerifyBadge struct {
	*models.Node
	VerifyBadge     string `json:"verify_badge"`
	CatalogCountry  string `json:"catalog_country,omitempty"`
	ExitCountry     string `json:"exit_country,omitempty"`
	CountryMismatch bool   `json:"country_mismatch,omitempty"`
}

// GetNodes возвращает список узлов вместе со значком проверенности трафиком (verify_badge)
// и парой «метка каталога / фактический выход» (C-21-ui). Источник истины по-прежнему
// models.Node — JS в index.html только отображает готовые значения, не считает их заново.
func (a *App) GetNodes() []nodeWithVerifyBadge {
	var nodes []*models.Node
	if a.remote != nil {
		nodes = a.remote.GetNodes()
	} else {
		nodes = a.engine.GetNodes()
	}
	now := time.Now().Unix()
	out := make([]nodeWithVerifyBadge, len(nodes))
	for i, n := range nodes {
		out[i] = nodeWithVerifyBadge{
			Node:            n,
			VerifyBadge:     n.VerifyBadge(now),
			CatalogCountry:  n.CatalogCountry(),
			ExitCountry:     n.ExitCountry(),
			CountryMismatch: n.CountryMismatch(),
		}
	}
	return out
}

// PinNode закрепляет узел БЕЗ немедленного подключения — авто-выбор будет предпочитать его
// при следующем ScanAndConnect/emergencySwitch, текущий сеанс не трогает. ТЗ v1.3 F2: с
// валидацией (неизвестный ID — ошибка, закрепление не меняется) и персистентно (config.json).
func (a *App) PinNode(nodeID string) error {
	if a.remote != nil {
		return a.remote.PinNode(nodeID)
	}
	return a.engine.Pin(nodeID)
}

// ConnectOnce подключается к узлу, НЕ меняя закрепление (ТЗ v1.3 F2, «▶ Подключить»).
func (a *App) ConnectOnce(nodeID string) error {
	if a.remote != nil {
		return a.remote.ConnectOnce(nodeID)
	}
	return a.engine.ConnectOnce(nodeID)
}

// AddFavorite / RemoveFavorite / GetFavoriteIDs — избранное (ТЗ v1.3 F2): порядок авто-выбора
// pinned → favorites → остальное; хранится в config.json.
func (a *App) AddFavorite(nodeID string) error {
	if a.remote != nil {
		return a.remote.SetFavorite(nodeID, true)
	}
	return a.engine.AddFavorite(nodeID)
}

func (a *App) RemoveFavorite(nodeID string) error {
	if a.remote != nil {
		return a.remote.SetFavorite(nodeID, false)
	}
	return a.engine.RemoveFavorite(nodeID)
}

// ─── ТЗ v1.3 F4 Stage 1: обход пула ──────────────────────────────────────────────────────

// StartSweep запускает обход всего пула TCP-пробой без подключения («Сканировать» ≠ «Подключить»).
func (a *App) StartSweep() error {
	if a.remote != nil {
		return a.remote.StartSweep()
	}
	return a.engine.StartSweep("manual")
}

func (a *App) CancelSweep() {
	if a.remote != nil {
		a.remote.CancelSweep()
		return
	}
	a.engine.CancelSweep()
}

func (a *App) GetScanProgress() engine.ScanProgress {
	if a.remote != nil {
		return a.remote.GetScanProgress()
	}
	return a.engine.GetScanProgress()
}

// ─── N-3 (ТЗ APF v1.5 §3): проба РЕАЛЬНОГО трафика — «Собрать список рабочих узлов» ──────
//
// Движок (internal/engine/node_check.go, ownership L1-ENG, НЕ трогается этим лотом) уже
// умеет StartNodeCheck/CancelNodeCheck/NodeCheckStatus — имена намеренно 1:1 с Engine (C13
// ТЗ: «НЕ catalog», занято провайдерами подписок). Пара owner/observer — тот же образец, что
// StartSweep/CancelSweep/GetScanProgress чуть выше: владелец (a.engine != nil) зовёт движок
// напрямую; наблюдатель (a.remote != nil, GUI не выиграл singleinstance.AcquireEngine) идёт
// через HTTP к Web UI API уже запущенного владельца. Эндпоинты /api/nodes/check-* — епархия
// L2-WEB (тот же документ ТЗ, тот же явный список путей), здесь только вызывающая сторона;
// webclient.go — вне ownership этого лота, поэтому вызываем уже существующие
// webClient.postJSON/getJSON (пакет main общий с webclient.go) вместо добавления туда новых
// типизированных методов — тот же приём, каким свежий /api-путь мог бы быть подключён без
// правки чужого файла.
//
// N-9 (честность значков): узел помечается пройденным ТОЛЬКО этой пробой — подпись
// «выход в интернет проверен», «через туннель» ЗАПРЕЩЕНО (проба — SOCKS-only инстанс слота,
// активное подключение/TUN не трогает). Формулировка — в renderNodeCheck (index.html), не
// здесь: Go-сторона только транспортирует NodeCheckStatusSnapshot как есть.

// StartNodeCheck запускает один прогон пробы реального трафика по top-N кандидатам пула.
// Параметры — нулевые (движок сам подставляет умолчания §6 ТЗ v1.5: N=30, K=8,
// concurrency=6/1, per-node=10с, withDefaults в node_check.go); config.json полей под них
// пока нет (N-1 схему не меняет) — заводить их вне ownership этого лота. Возвращается сразу,
// прогресс — событием apf:node_check (владелец) или опросом NodeCheckStatus (наблюдатель,
// см. index.html loadNodes()), отмена — CancelNodeCheck().
func (a *App) StartNodeCheck() error {
	if a.remote != nil {
		var resp struct {
			Error string `json:"error"`
		}
		if err := a.remote.postJSON("/api/nodes/check-all", map[string]interface{}{}, &resp); err != nil {
			return err
		}
		if resp.Error != "" {
			return fmt.Errorf("%s", resp.Error)
		}
		return nil
	}
	return a.engine.StartNodeCheck(engine.NodeCheckOptions{})
}

// CancelNodeCheck отменяет текущий прогон пробы. Идемпотентна (Engine.CancelNodeCheck сама
// это гарантирует) — как и CancelSweep, ошибку HTTP-пути у наблюдателя намеренно глушим:
// отмена — best-effort, пользователю нечего с этой ошибкой сделать, кроме как увидеть, что
// кнопка «Остановить» не спрятана.
func (a *App) CancelNodeCheck() {
	if a.remote != nil {
		_ = a.remote.postJSON("/api/nodes/check-cancel", map[string]interface{}{}, nil)
		return
	}
	a.engine.CancelNodeCheck()
}

// NodeCheckStatus — коалесцированный снимок прогресса пробы (running/phase/total/probed/
// verified/failed/target_k). У наблюдателя событие apf:node_check не приходит (колбэк живёт
// в ЧУЖОМ процессе-владельце, см. doc-комментарий у App.remote в начале файла) — index.html
// опрашивает этот метод тем же приёмом, каким уже опрашивается GetScanProgress().
func (a *App) NodeCheckStatus() engine.NodeCheckStatusSnapshot {
	if a.remote != nil {
		var status engine.NodeCheckStatusSnapshot
		if err := a.remote.getJSON("/api/nodes/check-status", &status); err != nil {
			return engine.NodeCheckStatusSnapshot{}
		}
		return status
	}
	return a.engine.NodeCheckStatus()
}

// ─── L5-UI (ТЗ v1.4 §5): ручной харвест узлов из источников ───────────────────────────────
//
// Тот же owner/observer-образец, что StartNodeCheck/NodeCheckStatus: владелец (a.engine != nil)
// крутит engine.HarvestNow в горутине и хранит снимок в App; наблюдатель (a.remote != nil)
// проксирует в web-API владельца (/api/nodes/harvest*). Узлы входят в пул непроверенными через
// mergeFetchedNodes (граница доверия) — «рабочими» их делает отдельная проба/скан, не харвест.

// HarvestNow запускает один проход харвестера. Возвращается сразу; прогресс/итог — HarvestStatus
// (опрос) или событие apf:harvest (владелец).
func (a *App) HarvestNow() error {
	if a.remote != nil {
		var resp struct {
			Error string `json:"error"`
		}
		if err := a.remote.postJSON("/api/nodes/harvest", map[string]interface{}{}, &resp); err != nil {
			return err
		}
		if resp.Error != "" {
			return fmt.Errorf("%s", resp.Error)
		}
		return nil
	}
	if a.engine == nil {
		return fmt.Errorf("движок недоступен")
	}
	a.harvestMu.Lock()
	if a.harvestRunning {
		a.harvestMu.Unlock()
		return fmt.Errorf("харвест уже идёт")
	}
	a.harvestRunning = true
	a.harvestDone = false
	a.harvestErr = ""
	a.harvestResult = nil
	a.harvestProgress = harvester.Progress{}
	a.harvestMu.Unlock()

	go func() {
		res, err := a.engine.HarvestNow(context.Background())
		a.harvestMu.Lock()
		a.harvestRunning = false
		a.harvestDone = true
		if err != nil {
			a.harvestErr = err.Error()
		} else {
			a.harvestResult = res
		}
		a.harvestMu.Unlock()
	}()
	return nil
}

// HarvestFromText запускает разбор вставленного пользователем текста (несколько ссылок/дамп/
// подписка) тем же харвестером, что и HarvestNow, но без обращения к источникам. Возвращается сразу;
// прогресс/итог — HarvestStatus (общие поля) или событие apf:harvest (владелец).
func (a *App) HarvestFromText(text string) error {
	if a.remote != nil {
		var resp struct {
			Error string `json:"error"`
		}
		if err := a.remote.postJSON("/api/nodes/harvest-text", map[string]interface{}{"text": text}, &resp); err != nil {
			return err
		}
		if resp.Error != "" {
			return fmt.Errorf("%s", resp.Error)
		}
		return nil
	}
	if a.engine == nil {
		return fmt.Errorf("движок недоступен")
	}
	a.harvestMu.Lock()
	if a.harvestRunning {
		a.harvestMu.Unlock()
		return fmt.Errorf("харвест уже идёт")
	}
	a.harvestRunning = true
	a.harvestDone = false
	a.harvestErr = ""
	a.harvestResult = nil
	a.harvestProgress = harvester.Progress{}
	a.harvestMu.Unlock()

	go func() {
		res, err := a.engine.HarvestFromText(context.Background(), text)
		a.harvestMu.Lock()
		a.harvestRunning = false
		a.harvestDone = true
		if err != nil {
			a.harvestErr = err.Error()
		} else {
			a.harvestResult = res
		}
		a.harvestMu.Unlock()
	}()
	return nil
}

// HarvestStatus — плоский снимок прогресса/итога последнего харвеста.
func (a *App) HarvestStatus() HarvestStatusView {
	if a.remote != nil {
		// Web-API отдаёт вложенную форму {running,done,progress:{…},result:{…}} — разбираем её и
		// уплощаем в тот же вид, что owner отдаёт из полей App.
		var raw struct {
			Running  bool   `json:"running"`
			Done     bool   `json:"done"`
			Error    string `json:"error"`
			Progress struct {
				SourceIndex int    `json:"source_index"`
				SourceTotal int    `json:"source_total"`
				Found       int    `json:"found"`
				Phase       string `json:"phase"`
			} `json:"progress"`
			Result *struct {
				Parsed           int    `json:"parsed"`
				Merged           int    `json:"merged"`
				SubscriptionURLs int    `json:"subscription_urls"`
				SourcesProcessed int    `json:"sources_processed"`
				SourcesTotal     int    `json:"sources_total"`
				Stopped          string `json:"stopped"`
			} `json:"result"`
		}
		if err := a.remote.getJSON("/api/nodes/harvest-status", &raw); err != nil {
			return HarvestStatusView{}
		}
		v := HarvestStatusView{
			Running: raw.Running, Done: raw.Done, Error: raw.Error,
			Phase: raw.Progress.Phase, SourceIndex: raw.Progress.SourceIndex,
			SourceTotal: raw.Progress.SourceTotal, Found: raw.Progress.Found,
		}
		if raw.Result != nil {
			v.Parsed = raw.Result.Parsed
			v.Merged = raw.Result.Merged
			v.SubscriptionURLs = raw.Result.SubscriptionURLs
			v.SourcesProcessed = raw.Result.SourcesProcessed
			v.SourcesTotal = raw.Result.SourcesTotal
			v.Stopped = raw.Result.Stopped
		}
		return v
	}

	a.harvestMu.Lock()
	defer a.harvestMu.Unlock()
	v := HarvestStatusView{
		Running:     a.harvestRunning,
		Done:        a.harvestDone,
		Error:       a.harvestErr,
		Phase:       a.harvestProgress.Phase,
		SourceIndex: a.harvestProgress.SourceIndex,
		SourceTotal: a.harvestProgress.SourceTotal,
		Found:       a.harvestProgress.Found,
	}
	if a.harvestResult != nil {
		v.Parsed = a.harvestResult.Parsed
		v.Merged = a.harvestResult.Merged
		v.SubscriptionURLs = a.harvestResult.SubscriptionURLs
		v.SourcesProcessed = a.harvestResult.Report.SourcesProcessed
		v.SourcesTotal = a.harvestResult.Report.SourcesTotal
		v.Stopped = a.harvestResult.Report.Stopped
	}
	return v
}

// ─── ТЗ v1.3 F3: управление узлами ───────────────────────────────────────────────────────

func (a *App) RemoveNode(nodeID string) error {
	if a.remote != nil {
		return a.remote.NodeAction("/api/node/remove", map[string]interface{}{"node_id": nodeID})
	}
	return a.engine.RemoveNode(nodeID)
}

func (a *App) BanNode(nodeID string, banned bool) error {
	if a.remote != nil {
		return a.remote.NodeAction("/api/node/ban", map[string]interface{}{"node_id": nodeID, "banned": banned})
	}
	return a.engine.BanNode(nodeID, banned)
}

// UpdateNode — имя (пусто — не менять) и заметка (пусто — убрать).
func (a *App) UpdateNode(nodeID, name, note string) error {
	if a.remote != nil {
		return a.remote.NodeAction("/api/node/update", map[string]interface{}{"node_id": nodeID, "name": name, "user_note": note})
	}
	patch := models.NodePatch{UserNote: &note}
	if strings.TrimSpace(name) != "" {
		patch.Name = &name
	}
	return a.engine.UpdateNode(nodeID, patch)
}

func (a *App) ResetNodeStats(nodeID string) error {
	if a.remote != nil {
		return a.remote.NodeAction("/api/node/reset", map[string]interface{}{"node_id": nodeID})
	}
	return a.engine.ResetNodeStats(nodeID)
}

func (a *App) RestoreRemovedNodes() int {
	if a.remote != nil {
		return a.remote.RestoreRemovedNodes()
	}
	return a.engine.RestoreRemovedNodes()
}

func (a *App) GetRemovedNodeIDs() []string {
	var ids []string
	if a.remote != nil {
		ids = a.remote.GetRemovedNodeIDs()
	} else {
		ids = a.engine.RemovedNodeIDs()
	}
	if ids == nil {
		ids = []string{}
	}
	return ids
}

// ExportLog — ТЗ v1.3 F5.1: сохранить полный лог (файл владельца движка; у наблюдателя —
// через /api/logs/export службы) в выбранный пользователем файл. Возвращает путь ("" — отмена).
func (a *App) ExportLog() (string, error) {
	data, err := a.logExportBytes()
	if err != nil {
		return "", err
	}
	path, err := wailsruntime.SaveFileDialog(a.ctx, wailsruntime.SaveDialogOptions{
		Title:           "Сохранить лог APF",
		DefaultFilename: "apf-log-" + time.Now().Format("2006-01-02_15-04") + ".txt",
		Filters:         []wailsruntime.FileFilter{{DisplayName: "Текстовый файл (*.txt)", Pattern: "*.txt"}},
	})
	if err != nil || path == "" {
		return "", err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", err
	}
	return path, nil
}

func (a *App) logExportBytes() ([]byte, error) {
	if a.remote != nil {
		return a.remote.ExportLogBytes()
	}
	if a.engine != nil {
		if p := a.engine.LogFilePath(); p != "" {
			a.engine.FlushLog()
			return os.ReadFile(p)
		}
	}
	a.logMu.Lock()
	text := strings.Join(a.recentLogs, "\n")
	a.logMu.Unlock()
	return []byte(text), nil
}

// OpenLogFolder открывает каталог с лог-файлом в проводнике (F5.1).
func (a *App) OpenLogFolder() error {
	dir := config.DataDir()
	if a.engine != nil {
		if p := a.engine.LogFilePath(); p != "" {
			dir = filepath.Dir(p)
		}
	}
	if runtime.GOOS == "windows" {
		return exec.Command("explorer.exe", dir).Start()
	}
	wailsruntime.BrowserOpenURL(a.ctx, "file://"+dir)
	return nil
}

// GetLogFilePath — путь лог-файла владельца ("" — наблюдатель/не ведётся).
func (a *App) GetLogFilePath() string {
	if a.engine != nil {
		return a.engine.LogFilePath()
	}
	return ""
}

func (a *App) GetFavoriteIDs() []string {
	var ids []string
	if a.remote != nil {
		ids = a.remote.GetFavoriteIDs()
	} else {
		ids = a.engine.FavoriteIDs()
	}
	if ids == nil {
		ids = []string{}
	}
	return ids
}

// FavoriteOrigin / UserFavoriteIDs / SystemFavoriteIDs — W3 (ТЗ APF v1.5 §2,
// TZ_v1.5_NODE_CATALOG_2026-09-14): класс записи избранного. "user" — звезда пользователя
// (sticky, только сам пользователь снимает); "system" — сборка каталога по трафик-пробе
// (node_check.go reconcileFavoritesFromNodeCheck), может быть эвиктирован реконсиляцией, если
// узел перестанет давать трафик. "" — узел вообще не в избранном. UI (index.html renderNodes)
// использует эти три биндинга, чтобы показать разные значки (⭐ user / 🤖 system) вместо одной
// неразличимой звезды — иначе пользователь не может понять, что можно молча исчезнуть само.
//
// Наблюдатель (a.remote != nil) ходит на GET /api/favorites — КАНОНИЧЕСКИЙ контракт лота
// L2-WEB-B (internal/web/server.go: apiFavorites, читан заново при интеграционном исправлении
// этого места): вдобавок к старому общему favorite_ids отдаёт user_favorite_ids/
// system_favorite_ids одним ответом. (Исправление: до интеграционной проверки этот файл ходил
// на три изобретённых пути /api/favorites/origin|user|system, которых на сервере не существует
// — L2-WEB-B реализовал другой, реальный контракт; см. remoteFavoriteClasses ниже.) Если
// /api/favorites недоступен — методы честно деградируют на "нет данных" (пустой класс/пустой
// список), а не падают.
func (a *App) FavoriteOrigin(nodeID string) string {
	if a.remote != nil {
		userIDs, systemIDs, err := a.remoteFavoriteClasses()
		if err != nil {
			return ""
		}
		for _, id := range systemIDs {
			if id == nodeID {
				return models.OriginSystem
			}
		}
		for _, id := range userIDs {
			if id == nodeID {
				return models.OriginUser
			}
		}
		return ""
	}
	return a.engine.FavoriteOrigin(nodeID)
}

func (a *App) UserFavoriteIDs() []string {
	var ids []string
	if a.remote != nil {
		userIDs, _, err := a.remoteFavoriteClasses()
		if err == nil {
			ids = userIDs
		}
	} else {
		ids = a.engine.UserFavoriteIDs()
	}
	if ids == nil {
		ids = []string{}
	}
	return ids
}

func (a *App) SystemFavoriteIDs() []string {
	var ids []string
	if a.remote != nil {
		_, systemIDs, err := a.remoteFavoriteClasses()
		if err == nil {
			ids = systemIDs
		}
	} else {
		ids = a.engine.SystemFavoriteIDs()
	}
	if ids == nil {
		ids = []string{}
	}
	return ids
}

// remoteFavoriteClasses — общее тело наблюдателя для FavoriteOrigin/UserFavoriteIDs/
// SystemFavoriteIDs выше: один GET /api/favorites (канонический контракт L2-WEB-B), разбор
// user_favorite_ids/system_favorite_ids. Общий favorite_ids из того же ответа этому лоту не
// нужен — GetFavoriteIDs() (выше по файлу) уже отдаёт его отдельным вызовом через существующий
// webClient.GetFavoriteIDs (webclient.go, не тронут этим лотом).
func (a *App) remoteFavoriteClasses() (userIDs, systemIDs []string, err error) {
	var resp struct {
		UserFavoriteIDs   []string `json:"user_favorite_ids"`
		SystemFavoriteIDs []string `json:"system_favorite_ids"`
	}
	if err := a.remote.getJSON("/api/favorites", &resp); err != nil {
		return nil, nil, err
	}
	return resp.UserFavoriteIDs, resp.SystemFavoriteIDs, nil
}

// UnpinNode снимает закрепление узла.
func (a *App) UnpinNode() {
	if a.remote != nil {
		a.remote.UnpinNode()
		return
	}
	a.engine.UnpinNode()
}

// GetPinnedNodeID возвращает id закреплённого узла ("" — не закреплён).
func (a *App) GetPinnedNodeID() string {
	if a.remote != nil {
		return a.remote.GetPinnedNodeID()
	}
	return a.engine.PinnedNodeID()
}

// GetStats возвращает статистику пула
func (a *App) GetStats() map[string]int {
	if a.remote != nil {
		return a.remote.GetStats()
	}
	return a.engine.GetStats()
}

// GetSingBoxInfo возвращает статус sing-box
func (a *App) GetSingBoxInfo() map[string]interface{} {
	if a.remote != nil {
		return a.remote.GetSingBoxInfo()
	}
	return a.engine.GetSingBoxInfo()
}

// GetConfig возвращает текущую конфигурацию
func (a *App) GetConfig() *models.AppConfig {
	return a.cfg
}

// GetLastPersistError — U-17-desktop (ТЗ v1.4, §7.2 контракта UI_CONTRACT_v1.4.md):
// «узлы не сохранены: <причина>» рядом со списком узлов, когда движок сообщил об ошибке
// записи nodes_cache.json (C-4/L1-SEC). Поле сознательно НЕ добавлено в
// models.ConnectionState/GetState() (см. комментарий движка, engine.go:5943-5947,
// на момент контракта) — источник для UI-лотов это диагностика (GetDiagnostics()/
// LastPersistError()), не состояние. У владельца — прямой геттер движка; у наблюдателя
// собственного Diagnostics-биндинга в webclient.go нет (не в ownership этого лота) —
// тот же приём, что и у ServerRoleExportIdentity/PatchConfig выше: getJSON общего
// HTTP-клиента вызывается прямо отсюда (тот же пакет main), без изменений webclient.go.
// Пустая строка — норма (последняя запись прошла успешно), не ошибка вызова.
func (a *App) GetLastPersistError() (string, error) {
	if a.remote != nil {
		var diag map[string]interface{}
		if err := a.remote.getJSON("/api/diagnostics", &diag); err != nil {
			return "", err
		}
		if s, ok := diag["last_persist_error"].(string); ok {
			return s, nil
		}
		return "", nil
	}
	return a.engine.LastPersistError(), nil
}

// PatchConfig — Э-Win-TUN-4 (docs/TZ_WINDOWS_TUN_VPN_v1.0.md): частичное изменение
// конфигурации ЖИВОГО движка, а не только файла на диске. В отличие от старого SaveConfig
// (писал a.cfg/файл, но никогда не трогал a.engine и мог рассинхронизировать a.cfg с
// a.engine.cfg — см. историю у бывшего App.SetKillSwitch, удалён этим лотом вместе с
// SaveConfig, U-15/R12-4: оба биндинга были невызываемыми, а держать их означало бы
// сохранять готовый обходной путь мимо PatchConfig), поле connection_mode требует
// синхронного отклика прямо сейчас: builder/killswitch должны пересобраться до
// следующего Connect(), иначе переключатель в интерфейсе «молча повиснет» (то, от
// чего явно предостерегает ТЗ). У наблюдателя нет своего a.engine — единственный
// канал повлиять на конфигурацию чужого владельца — Web UI API того же процесса,
// что уже обслуживает переключатель в internal/web/server.go (apiSaveConfig →
// eng.PatchConfigDetailed).
//
// V13-5-wails (ТЗ v1.4, F5.5): возвращает список ключей конфига, которые применятся
// только после перезапуска APF (сейчас — listen_port/webui_port,
// internal/engine/engine.go restartPatchKeys). Раньше сигнатура была просто error —
// PatchConfigDetailed этот список УЖЕ вычислял, но обёртка a.engine.PatchConfig
// отбрасывала его молча, и Wails ни разу не мог показать тот же тост, что уже показывает
// Web (server.go apiSaveConfig → needs_restart). Наблюдатель не имеет отдельного
// PatchConfigDetailed-эквивалента в webclient.go (не в ownership этого лота) — читаем
// needs_restart из ответа /api/save-config напрямую тем же postJSON, которым уже
// пользуется webClient.PatchConfig (тот же пакет main, метод не экспортирован, но виден).
func (a *App) PatchConfig(patch map[string]interface{}) ([]string, error) {
	if a.remote != nil {
		var resp struct {
			NeedsRestart []string `json:"needs_restart"`
			Error        string   `json:"error"`
		}
		if err := a.remote.postJSON("/api/save-config", patch, &resp); err != nil {
			return nil, err
		}
		if resp.Error != "" {
			return nil, fmt.Errorf("%s", resp.Error)
		}
		return resp.NeedsRestart, nil
	}
	return a.engine.PatchConfigDetailed(patch)
}

// GetDataDir возвращает путь к директории данных
func (a *App) GetDataDir() string {
	return config.DataDir()
}

// GetVersion возвращает версию приложения
func (a *App) GetVersion() string {
	return version.Label()
}

// OpenBrowser открывает URL в браузере
func (a *App) OpenBrowser(url string) {
	wailsruntime.BrowserOpenURL(a.ctx, url)
}

// MinimizeWindow сворачивает окно
func (a *App) MinimizeWindow() {
	wailsruntime.WindowMinimise(a.ctx)
}

// ─── Приватность/аварийная очистка (аудит паритета Wails GUI vs Web UI,
// 2026-08-12): internal/leakguard/internal/emergency/internal/crypto давно
// работают и открыты во встроенном Web UI (internal/web/server.go,
// page-leakguard), но здесь не имели ни Go-биндинга, ни HTML вообще — та же
// форма разрыва, что уже была найдена и закрыта на Android (см.
// docs/TZ_ANDROID_UI_PARITY_v1.0.md §1.4/1.7). ─────────────────────────────

// GetLeakGuardStatus возвращает статус защит устройства (IPv6/WebRTC guard,
// шифрование, инструкции для браузера).
func (a *App) GetLeakGuardStatus() map[string]interface{} {
	if a.remote != nil {
		return a.remote.GetLeakGuardStatus()
	}
	return a.engine.GetLeakGuardStatus()
}

// RunDNSLeakTest запускает полную проверку DNS-утечки (~8с, таймаут 15с).
// В отличие от Android-моста (mobile/androidbridge), где этот же вызов
// блокирует поток JS-биндинга напрямую и Kotlin обязан звать его в фоновом
// потоке, Wails сам оборачивает (T, error) в JS Promise — фронтенду достаточно
// await, отдельная горутина на стороне JS не нужна.
func (a *App) RunDNSLeakTest() (map[string]interface{}, error) {
	if a.remote != nil {
		return a.remote.RunDNSLeakTest()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := a.engine.RunDNSLeakTest(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"leaked":         result.Leaked,
		"system_dns":     result.SystemDNS,
		"tunnel_dns":     result.TunnelDNS,
		"system_ips":     result.SystemIPs,
		"tunnel_ips":     result.TunnelIPs,
		"diagnosis":      result.Diagnosis,
		"recommendation": result.Recommendation,
	}, nil
}

// SetWebRTCBlock включает/выключает защиту от утечки IP через WebRTC.
func (a *App) SetWebRTCBlock(enabled bool) error {
	if a.remote != nil {
		return a.remote.SetWebRTCBlock(enabled)
	}
	return a.engine.EnableWebRTCBlock(enabled)
}

// SetMasterPassword включает/выключает AES-256-GCM шифрование nodes_cache.json.
// Пустой пароль выключает шифрование.
func (a *App) SetMasterPassword(password string) {
	if a.remote != nil {
		_ = a.remote.SetMasterPassword(password)
		return
	}
	a.engine.SetMasterPassword(password)
}

// EmergencyWipe НЕОБРАТИМО стирает данные APF (nodes_cache/конфиг/логи; при
// wipeAll=true — ещё и bin/sing-box) и обрывает текущий сеанс движка. confirm
// ДОЛЖЕН быть ровно "WIPE" — тот же защитный контракт, что уже принят и на
// встроенном Web UI (apiEmergencyWipe), и на Android-мосте (EmergencyWipeJSON)
// — не решение этого файла, повторение уже дважды принятого правила. Проверка
// стоит ДО ветвления владелец/наблюдатель: наблюдатель не должен полагаться
// только на серверную проверку, раз клиентская дешева и её всё равно надо
// пройти сначала.
func (a *App) EmergencyWipe(wipeAll bool, confirm string) (map[string]interface{}, error) {
	if confirm != "WIPE" {
		return nil, fmt.Errorf("confirmation required: pass confirm=WIPE")
	}
	if a.remote != nil {
		return a.remote.EmergencyWipe(wipeAll, confirm)
	}
	// P1 (аудит 2026-09-01, security-раздел, находка №20б): registerEmergencyHotkey()
	// регистрируется в startup() ДО a.engine = engine.New(...) — между ними идут
	// go ensureServiceStarted() и singleinstance.AcquireEngine() (файловые операции, не
	// мгновенные). Если аварийный хоткей сработает в этом окне (пользователь держит
	// комбинацию при запуске приложения — узкое, но детерминированно достижимое условие),
	// a.remote и a.engine оба nil, и разыменование ниже паникует В ПОТОКЕ ЦИКЛА СООБЩЕНИЙ
	// хоткея — падение всего GUI, причём вызвано ровно тем действием, которое должно было
	// спасти данные пользователя в панике.
	if a.engine == nil {
		return nil, fmt.Errorf("APF ещё запускается — аварийное стирание недоступно первые секунды после старта")
	}
	result := a.engine.EmergencyWipe(wipeAll)
	return map[string]interface{}{
		"status":        "wiped",
		"files_deleted": result.FilesDeleted,
		"bytes_deleted": result.BytesDeleted,
		"errors":        result.Errors,
		"duration_ms":   result.Duration.Milliseconds(),
	}, nil
}

// ─── Сессия: force-switch, sticky policy (тот же аудит паритета — server.go
// дашборда имеет отдельную кнопку «⇄ Сменить IP», которая идёт НЕ через
// ForceRescan/rescan (полное пересканирование всего пула узлов), а через
// стики-сессию: мгновенное переключение на уже известный узел в обход
// закрепления). ─────────────────────────────────────────────────────────────

// ForceSwitch принудительно переключается на другой узел в обход Sticky
// Session — быстрее и «мягче», чем ForceRescan (полное пересканирование).
func (a *App) ForceSwitch() {
	if a.remote != nil {
		_ = a.remote.ForceSwitch()
		return
	}
	a.engine.ForceSwitchNow()
}

// SetStickyPolicy устанавливает политику Sticky Session: "sticky"/"free"/"timed".
func (a *App) SetStickyPolicy(policy string) {
	if a.remote != nil {
		_ = a.remote.SetStickyPolicy(policy)
		return
	}
	a.engine.SetStickyPolicy(policy)
}

// GetSessionStatus возвращает статус Sticky Session.
func (a *App) GetSessionStatus() map[string]interface{} {
	if a.remote != nil {
		return a.remote.GetSessionStatus()
	}
	return a.engine.GetStickySessionStatus()
}

// ─── Анти-DPI/скрытность (аудит паритета, область #2) ──────────────────────

func (a *App) GetDPIStatus() map[string]interface{} {
	if a.remote != nil {
		return a.remote.GetDPIStatus()
	}
	return a.engine.GetDPIStatus(context.Background())
}

func (a *App) RunCanaryTest() (map[string]interface{}, error) {
	if a.remote != nil {
		return a.remote.RunCanaryTest()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	result, err := a.engine.RunCanaryTest(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"score":          result.Score,
		"vpn_detectable": result.VPNDetectable,
	}, nil
}

func (a *App) SetTrafficPadding(enabled, aggressive bool) {
	if a.remote != nil {
		_ = a.remote.SetTrafficPadding(enabled, aggressive)
		return
	}
	a.engine.EnableTrafficPadding(enabled, aggressive)
}

// SetShadowTLSConfig настраивает ShadowTLS v3. serverAddr — P1-1 (аудит 2026-09-01): адрес
// РЕАЛЬНОГО сервера (host:port), обязателен при enabled=true — server остаётся необязательным
// переопределением маскировочного SNI-сайта, трафик туда никогда не идёт.
func (a *App) SetShadowTLSConfig(enabled bool, password, sni, server, serverAddr string) error {
	if a.remote != nil {
		return a.remote.SetShadowTLSConfig(enabled, password, sni, server, serverAddr)
	}
	return a.engine.SetShadowTLSConfig(enabled, password, sni, server, serverAddr)
}

func (a *App) AutoSelectShadowTLSSNI() (string, error) {
	if a.remote != nil {
		return a.remote.AutoSelectShadowTLSSNI()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return a.engine.AutoSelectShadowTLSSNI(ctx)
}

func (a *App) SetCDNConfig(workerDomain, backendHost string, backendPort int) {
	if a.remote != nil {
		_ = a.remote.SetCDNConfig(workerDomain, backendHost, backendPort)
		return
	}
	a.engine.SetCDNConfig(workerDomain, backendHost, backendPort)
}

// ─── Fallback-туннели + watchdog (область #3) ──────────────────────────────

func (a *App) GetFallbackStatus() map[string]interface{} {
	if a.remote != nil {
		return a.remote.GetFallbackStatus()
	}
	return a.engine.GetFallbackStatus()
}

func (a *App) ActivateFallback(tunnel string) error {
	if a.remote != nil {
		return a.remote.ActivateFallback(tunnel)
	}
	return a.engine.ActivateFallbackTunnel(tunnel)
}

func (a *App) AutoSelectFallback() string {
	if a.remote != nil {
		return a.remote.AutoSelectFallback()
	}
	return a.engine.AutoSelectFallback()
}

func (a *App) GetWatchdogStatus() map[string]interface{} {
	if a.remote != nil {
		return a.remote.GetWatchdogStatus()
	}
	return a.engine.GetWatchdogStatus()
}

// ─── Каталог серверов (область #4) ─────────────────────────────────────────

func (a *App) GetCatalogStatus() []map[string]interface{} {
	if a.remote != nil {
		return a.remote.GetCatalogStatus()
	}
	return a.engine.GetCatalogStatus()
}

func (a *App) RefreshCatalog() (int, error) {
	if a.remote != nil {
		return a.remote.RefreshCatalog()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return a.engine.RefreshCatalog(ctx)
}

func (a *App) SetCatalogProviderEnabled(id string, enabled bool) error {
	if a.remote != nil {
		return a.remote.SetCatalogProviderEnabled(id, enabled)
	}
	if !a.engine.SetProviderEnabled(id, enabled) {
		return fmt.Errorf("provider not found: %s", id)
	}
	return nil
}

// CatalogReviewInterval / SetCatalogReviewInterval — W3 §5 (TZ_v1.5_NODE_CATALOG_2026-09-14):
// как часто пересматривается системный класс избранного — ГЕЙТ ДАВНОСТИ, после которого
// проваленная проба на следующей РУЧНОЙ сборке каталога вправе снять узел из системного
// избранного. НЕ триггер автозапуска сборки — сканирование остаётся только по кнопке
// «Обновить каталог» (owner-декрет консилиума, см. engine.go CatalogReviewInterval). Значения:
// each_scan(default)|daily|weekly|monthly (models.ReviewInterval* — engine уже валидирует).
//
// Тот же приём владелец/наблюдатель, что и SetCatalogProviderEnabled чуть выше; наблюдатель
// ходит на GET/POST /api/catalog-review-interval — КАНОНИЧЕСКИЙ контракт лота L2-WEB-B
// (internal/web/server.go: apiCatalogReviewInterval, читан заново при интеграционном
// исправлении этого места). Исправление: до интеграционной проверки этот файл ходил на
// /api/catalog/review-interval (с /-разделителем) и POST-ил {"interval": v} — L2-WEB-B
// реализовал другой путь (catalog-review-interval, через дефис) и другое тело POST
// ({"value": v}). Ответ POST на успех — 200 {"status":"ok","interval": v}; на отказ валидации
// — HTTP 400 {"error": "..."} (см. SetCatalogReviewInterval ниже — postJSON, webclient.go, на
// статусах ≥400 отдаёт сырое тело ответа как текст ошибки, поэтому JSON разбирается здесь).
func (a *App) CatalogReviewInterval() string {
	if a.remote != nil {
		var resp struct {
			Interval string `json:"interval"`
		}
		if err := a.remote.getJSON("/api/catalog-review-interval", &resp); err != nil || resp.Interval == "" {
			return models.ReviewIntervalEachScan
		}
		return resp.Interval
	}
	return a.engine.CatalogReviewInterval()
}

func (a *App) SetCatalogReviewInterval(v string) error {
	if a.remote != nil {
		err := a.remote.postJSON("/api/catalog-review-interval", map[string]interface{}{"value": v}, nil)
		if err == nil {
			return nil
		}
		// postJSON (webclient.go, вне scope) на HTTP-статусах ≥400 возвращает ошибку с СЫРЫМ
		// телом ответа как текстом сообщения, а не распарсенным полем error — разворачиваем
		// {"error":"..."} тело apiCatalogReviewInterval для читаемого сообщения пользователю;
		// если тело не JSON (сеть недоступна, узел не отвечает и т.п.) — остаёмся на исходной
		// ошибке как есть.
		var body struct {
			Error string `json:"error"`
		}
		if jsonErr := json.Unmarshal([]byte(err.Error()), &body); jsonErr == nil && body.Error != "" {
			return fmt.Errorf("%s", body.Error)
		}
		return err
	}
	return a.engine.SetCatalogReviewInterval(v)
}

// ─── Блокировка рекламы (область #5) ───────────────────────────────────────

func (a *App) GetAdBlockStatus() map[string]interface{} {
	if a.remote != nil {
		return a.remote.GetAdBlockStatus()
	}
	return a.engine.GetAdBlockStatus()
}

func (a *App) SetAdBlockProfile(profile string) error {
	if a.remote != nil {
		return a.remote.SetAdBlockProfile(profile)
	}
	return a.engine.SetAdBlockProfile(profile)
}

// AdBlockToggleAllowlist возвращает ошибку, если домен не принят (не домен либо уже в
// нужном состоянии) — P1-6 (аудит 2026-09-01): раньше метод был void, и фронтенд Wails не
// имел никакой возможности отличить принятый домен от молча отброшенного.
func (a *App) AdBlockToggleAllowlist(domain string, add bool) error {
	if a.remote != nil {
		return a.remote.AdBlockToggleAllowlist(domain, add)
	}
	if !a.engine.AdBlockToggleAllowlist(domain, add) {
		if add {
			return fmt.Errorf("домен уже в белом списке или указан неверно " +
				"(ожидается имя вида example.com)")
		}
		return fmt.Errorf("домена нет в белом списке или он указан неверно")
	}
	return nil
}

// ─── Анти-блокировка/residential IP (область #6) ───────────────────────────

func (a *App) GetAntiBlockStatus() map[string]interface{} {
	if a.remote != nil {
		return a.remote.GetAntiBlockStatus()
	}
	return a.engine.GetAntiBlockStatus()
}

func (a *App) CheckCurrentIP() (map[string]interface{}, error) {
	if a.remote != nil {
		return a.remote.CheckCurrentIP()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return a.engine.CheckCurrentIP(ctx)
}

func (a *App) SetAntiBlockConfig(enabled, residentialOnly, autoSwitch bool, apiKey string) {
	if a.remote != nil {
		_ = a.remote.SetAntiBlockConfig(enabled, residentialOnly, autoSwitch, apiKey)
		return
	}
	a.engine.SetAntiBlockConfig(enabled, residentialOnly, autoSwitch, apiKey)
}

func (a *App) GetBypassRules() []map[string]interface{} {
	if a.remote != nil {
		return a.remote.GetBypassRules()
	}
	return a.engine.GetBypassRules()
}

// CheckDomainRouting — «сайт всё ещё видит VPN, хотя обход включён — что реально идёт
// через туннель?» (см. web.CheckDomainRouting и internal/web/domain_check.go для полного
// разбора живого инцидента 2026-08-25, из которого выросла эта функция). В owner-режиме
// читает собственный recentLogs (см. bufferLog); в observer — тот же лог, но с той
// стороны, что реально владеет движком (и, значит, реально видит трафик sing-box).
func (a *App) CheckDomainRouting(query string) []web.DomainRouteResult {
	if a.remote != nil {
		return a.remote.CheckDomainRouting(query)
	}
	a.logMu.Lock()
	logs := make([]string, len(a.recentLogs))
	copy(logs, a.recentLogs)
	a.logMu.Unlock()
	return web.CheckDomainRouting(logs, query)
}

func (a *App) SetBypassRule(id string, enabled bool) error {
	if a.remote != nil {
		return a.remote.SetBypassRule(id, enabled)
	}
	if !a.engine.SetBypassRule(id, enabled) {
		return fmt.Errorf("rule not found: %s", id)
	}
	return nil
}

func (a *App) AddBypassDomain(domain, name string, residential bool, directRoute bool) error {
	if a.remote != nil {
		return a.remote.AddBypassDomain(domain, name, residential, directRoute)
	}
	if !a.engine.AddBypassDomain(domain, name, residential, directRoute) {
		return fmt.Errorf("domain already exists: %s", domain)
	}
	return nil
}

func (a *App) UpdateBypassDomain(id, domain, name string, residential bool, directRoute bool) error {
	if a.remote != nil {
		return a.remote.UpdateBypassDomain(id, domain, name, residential, directRoute)
	}
	if !a.engine.UpdateBypassDomain(id, domain, name, residential, directRoute) {
		return fmt.Errorf("not found or builtin: %s", id)
	}
	return nil
}

func (a *App) RemoveBypassDomain(id string) error {
	if a.remote != nil {
		return a.remote.RemoveBypassDomain(id)
	}
	if !a.engine.RemoveBypassDomain(id) {
		return fmt.Errorf("not found or builtin: %s", id)
	}
	return nil
}

// GetUptime возвращает время работы соединения
func (a *App) GetUptime() string {
	state := a.GetState()
	if !state.Connected || state.Since.IsZero() {
		return ""
	}
	d := time.Since(state.Since)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dч %02dм", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dм %02dс", m, s)
	}
	return fmt.Sprintf("%dс", s)
}

// ─── P2.3 (docs/TZ_APF_ROADMAP_v1.2.md): роль «Выход»/«Транзит» на Windows ─────────────
//
// identity передаётся через границу Wails как map[string]interface{} (UUID/PrivateKey/
// PublicKey/ShortID — те же имена полей, что и в singbox.ServerIdentity без json-тегов),
// не отдельным TS-классом — тот же приём, что уже принят у PatchConfig, вместо того чтобы
// вручную поддерживать ещё один класс в wailsjs/go/models.ts в синхроне с Go-стороной.

func identityToMap(id singbox.ServerIdentity) map[string]interface{} {
	return map[string]interface{}{
		"UUID": id.UUID, "PrivateKey": id.PrivateKey, "PublicKey": id.PublicKey, "ShortID": id.ShortID,
	}
}

func mapToIdentity(m map[string]interface{}) (singbox.ServerIdentity, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return singbox.ServerIdentity{}, err
	}
	var id singbox.ServerIdentity
	if err := json.Unmarshal(data, &id); err != nil {
		return singbox.ServerIdentity{}, err
	}
	return id, nil
}

// ServerRoleLocalIPCandidates — кандидаты на Host для ссылки роли «Выход» (живой вопрос
// 2026-08-27: зачем вводить IP вручную, если программа может определить его сама — см.
// singbox.LocalIPCandidates про то, почему список, а не один «угаданный» адрес). Чисто
// локальный запрос к сетевым интерфейсам ЭТОЙ машины — не зависит от того, кто владеет
// движком (owner/observer дают ОДИНАКОВЫЙ ответ, раз выполняются на одном хосте), поэтому
// без делегирования через a.remote, в отличие от остальных ServerRole*-методов выше.
func (a *App) ServerRoleLocalIPCandidates() []singbox.LocalIPCandidate {
	return singbox.LocalIPCandidates()
}

// ServerRoleDetectReachability — живой запрос пользователя 2026-08-28: «каждый должен
// определять свой IP» для того, чтобы ссылка роли «Выход» работала не только в одной
// локальной сети, но и между устройствами в разных сетях/странах (см. internal/relay,
// realReachability). Пробует UPnP-проброс порта на роутере, затем STUN как запасной
// вариант определения вероятного внешнего IP. Тот же принцип, что и у
// ServerRoleLocalIPCandidates — чисто сетевой запрос к этой машине и её роутеру, не
// зависит от владения движком, поэтому без делегирования через a.remote.
func (a *App) ServerRoleDetectReachability(port int) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	r := relay.NewReachability()
	method, err := r.Detect(ctx, port)
	if err != nil {
		return nil, err
	}
	host, extPort, ok := r.ExternalAddress()
	return map[string]interface{}{
		"method":        int(method),
		"explanation":   r.Explain(method),
		"external_host": host,
		"external_port": extPort,
		"has_address":   ok,
	}, nil
}

// ServerRoleGenerateIdentity создаёт НОВЫЙ ключ звена, заменяя ранее сохранённый (см.
// Engine.GenerateServerRoleIdentity) — все ранее выданные пользователем ссылки перестанут
// работать, фронтенд обязан явно предупредить перед вызовом.
func (a *App) ServerRoleGenerateIdentity() (map[string]interface{}, error) {
	if a.remote != nil {
		return a.remote.ServerRoleGenerateIdentity()
	}
	id, err := a.engine.GenerateServerRoleIdentity()
	if err != nil {
		return nil, err
	}
	return identityToMap(id), nil
}

// ServerRoleLoadIdentity — ранее сохранённый ключ звена, если уже сгенерирован. Возвращает
// nil (без ошибки), если ключа ещё нет — обычный случай до первого
// ServerRoleGenerateIdentity, не ошибка.
func (a *App) ServerRoleLoadIdentity() (map[string]interface{}, error) {
	if a.remote != nil {
		return a.remote.ServerRoleLoadIdentity()
	}
	id, found, err := a.engine.LoadServerRoleIdentity()
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return identityToMap(id), nil
}

// ServerRoleExportIdentity — S-3-frontend (ТЗ v1.4): полный ключ звена (включая приватный)
// нужен только явному подтверждённому действию пользователя, не автоматической загрузке
// страницы. L1-WEB закрыл S-3 на сервере: GET /api/server-role/identity (тот путь, которым
// идёт ServerRoleLoadIdentity выше у наблюдателя) теперь ВСЕГДА отдаёт PrivateKey пустым —
// единственный способ получить ключ целиком у наблюдателя стал новый
// POST /api/server-role/identity/export с {"confirm":"EXPORT"}. Без этого метода
// doStartServerRole/doCopyServerLink во фронтенде наблюдателя молча пытались бы поднять
// роль «Выход» и построить ссылку с пустым приватным ключом — рабочая до фикса L1-WEB
// функциональность стала бы фактически сломанной для окна-наблюдателя, если бы фронтенд
// продолжал полагаться на ServerRoleLoadIdentity вместо явного экспорта.
//
// У владельца — прежний прямой геттер движка (a.engine.LoadServerRoleIdentity): это чтение
// локального файла в своём же процессе, HTTP-поверхности здесь нет вовсе, редактировать
// нечего — тот же метод, что и у ServerRoleLoadIdentity владельца.
func (a *App) ServerRoleExportIdentity() (map[string]interface{}, error) {
	if a.remote != nil {
		var resp struct {
			Identity map[string]interface{} `json:"identity"`
			Error    string                 `json:"error"`
		}
		body := map[string]interface{}{"confirm": "EXPORT"}
		if err := a.remote.postJSON("/api/server-role/identity/export", body, &resp); err != nil {
			return nil, fmt.Errorf("не удалось получить ключ звена: %w", err)
		}
		if resp.Error != "" {
			return nil, fmt.Errorf("%s", resp.Error)
		}
		return resp.Identity, nil
	}
	id, found, err := a.engine.LoadServerRoleIdentity()
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return identityToMap(id), nil
}

// ServerRoleBuildLink собирает готовую vless://-ссылку для передачи «Входу» (ТЗ §5.2).
// relayAddr пустая строка ⇒ обычная прямая ссылка (прежнее поведение); непустая ⇒
// relay-формат (docs/TZ_APF_RELAY_v1.0.md §3).
func (a *App) ServerRoleBuildLink(identity map[string]interface{}, host string, listenPort int, realityDest, label, relayAddr, relayFingerprint string) (string, error) {
	if a.remote != nil {
		return a.remote.ServerRoleBuildLink(identity, host, listenPort, realityDest, label, relayAddr, relayFingerprint)
	}
	id, err := mapToIdentity(identity)
	if err != nil {
		return "", err
	}
	return a.engine.BuildServerRoleLink(id, host, listenPort, realityDest, label, relayAddr, relayFingerprint)
}

// ServerRoleStart поднимает роль «Выход»/«Транзит».
func (a *App) ServerRoleStart(identity map[string]interface{}, listenPort int, realityDest string) error {
	if a.remote != nil {
		return a.remote.ServerRoleStart(identity, listenPort, realityDest)
	}
	id, err := mapToIdentity(identity)
	if err != nil {
		return err
	}
	return a.engine.StartServerRole(listenPort, realityDest, id)
}

// ServerRoleStop останавливает роль «Выход». Идемпотентен.
func (a *App) ServerRoleStop() error {
	if a.remote != nil {
		return a.remote.ServerRoleStop()
	}
	return a.engine.StopServerRole()
}

// ServerRoleStatus — снимок состояния роли «Выход» для UI.
func (a *App) ServerRoleStatus() map[string]interface{} {
	if a.remote != nil {
		return a.remote.ServerRoleStatus()
	}
	return a.engine.GetServerRoleStatus()
}

// ─── P2.1 (docs/TZ_APF_ROADMAP_v1.2.md): каталог платных провайдеров ───────────────────
// Engine.AddPaidProvider/RemovePaidProvider/TestPaidProvider были готовы и протестированы
// давно (см. models.PaidProviderEntry) — не хватало точки входа ни на одной платформе.
// Список существующих провайдеров — через уже существующий App.GetConfig().PaidProviders,
// отдельный метод не нужен.

// AddPaidProvider добавляет провайдера, тестирует подключение и загружает узлы в пул.
// Реальный сетевой вызов, может занять до 15с.
func (a *App) AddPaidProvider(entry models.PaidProviderEntry) error {
	if a.remote != nil {
		return a.remote.AddPaidProvider(entry)
	}
	return a.engine.AddPaidProvider(entry)
}

// RemovePaidProvider удаляет провайдера и его узлы из пула.
func (a *App) RemovePaidProvider(id string) error {
	if a.remote != nil {
		return a.remote.RemovePaidProvider(id)
	}
	if !a.engine.RemovePaidProvider(id) {
		return fmt.Errorf("not found: %s", id)
	}
	return nil
}

// TestPaidProvider — пробное подключение БЕЗ сохранения (кнопка «Проверить» перед
// «Добавить», до 20с). Возвращает число узлов, которые вернул провайдер.
func (a *App) TestPaidProvider(entry models.PaidProviderEntry) (int, error) {
	if a.remote != nil {
		return a.remote.TestPaidProvider(entry)
	}
	return a.engine.TestPaidProvider(entry)
}
