// Package androidbridge — мост между Go-ядром APF и Android Kotlin слоем.
//
// gomobile bind экспортирует этот пакет как .aar библиотеку для Android.
// Все экспортируемые типы и методы должны удовлетворять ограничениям gomobile:
//   - Только примитивы, string, error, интерфейсы с методами-примитивами
//   - Никаких map, slice в публичном API (используем JSON строки)
//   - Методы только с одним error возвращаемым значением (или без него)
//
// ПОЧЕМУ ПАКЕТ НЕ В internal/. gomobile порождает вспомогательный пакет `gobind`
// во ВРЕМЕННОМ каталоге вне нашего дерева и импортирует связываемый пакет оттуда.
// Из-за правила Go об internal-пакетах такой импорт запрещён, и сборка падает с
// «use of internal package … not allowed». Поэтому мост живёт в mobile/androidbridge.
// Обратное направление ограничением не является: пакет внутри модуля по-прежнему
// может импортировать internal/engine, internal/config и остальные внутренние пакеты.
//
// Сборка:
//
//	gomobile bind -target android/arm64 -androidapi 26 \
//	  -o apf.aar ./mobile/androidbridge
//
// либо готовым инструментом: tools/android/build_aar.ps1 -Apply
package androidbridge

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/engine"
	"github.com/apf/adaptive-pathfinder/internal/harvester"
	"github.com/apf/adaptive-pathfinder/internal/killswitch"
	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/version"
)

// ─── Глобальное состояние ─────────────────────────────────────────────────────

var (
	globalEngine *engine.Engine
	globalMu     sync.Mutex
	globalCancel context.CancelFunc
)

// Два пути завершения сеанса, и путать их нельзя.
//
// restartEngine — ОБРАТИМЫЙ: снимает сетевые изменения, гасит sing-box, пересоздаёт
// контекст и снова поднимает движок. Это то, что означает кнопка «Отключить».
// stopEngine    — ТЕРМИНАЛЬНЫЙ: отменяет контекст движка безвозвратно. Годится только
// для выгрузки ядра вместе со службой.
//
// Вынесены в переменные ради испытания: тест обязан доказать, что Disconnect идёт по
// обратимому пути. Дефект D-A17 состоял ровно в том, что Disconnect звал Stop, после
// чего второе подключение в том же сеансе приложения было невозможно (см. комментарий
// к engine.Restart: «после Stop() контекст отменён и повторный Start() не работает»).
var (
	restartEngine = func(e *engine.Engine) error { return e.Restart() }
	stopEngine    = func(e *engine.Engine) { e.Stop() }
)

// ─── P0-9: барьер паник на границе gomobile ──────────────────────────────────
//
// Паника в Go, вызванном из Kotlin через gobind, НЕ превращается в исключение — она убивает
// процесс приложения целиком, вместе с активным туннелем. До аудита 2026-09-01 во всём пакете
// mobile/ не было ни одного recover(), при этом достижимые пути паники существовали: nil в
// пуле узлов (повреждённый nodes_cache.json) разыменовывался в GetNodesJSON/GetStats, а
// loadNodes падал на `[null]` при КАЖДОМ запуске — то есть приложение переставало
// запускаться навсегда, до переустановки.
//
// Сами причины устранены (nil-guard'ы в engine + атомарная запись кэша), но barrier нужен как
// защита в глубину: цена паники здесь — не сообщение об ошибке, а падение всего приложения.
//
// bridgeRecover ставится через defer в функциях, обрабатывающих коллекции/внешние данные.
func bridgeRecover(fn string) {
	if r := recover(); r != nil {
		log.Printf("[androidbridge] ПАНИКА в %s подавлена: %v", fn, r)
	}
}

// bridgeRecoverStr — вариант для функций, возвращающих строку: подставляет безопасный
// результат вместо падения. Использование: `defer bridgeRecoverStr("Имя", &out)`.
func bridgeRecoverStr(fn string, out *string) {
	if r := recover(); r != nil {
		log.Printf("[androidbridge] ПАНИКА в %s подавлена: %v", fn, r)
		if out != nil {
			*out = fmt.Sprintf("внутренняя ошибка в %s", fn)
		}
	}
}

// ─── Lifecycle ────────────────────────────────────────────────────────────────

// Init инициализирует APF движок.
//
// dataDir      — каталог данных приложения (getFilesDir()).
// nativeLibDir — каталог нативных библиотек (applicationInfo.nativeLibraryDir).
//
// Зачем второй параметр. Начиная с Android 10 выполнение файлов из каталога данных
// приложения запрещено (W^X), а sing-box запускается как отдельный процесс. Единственный
// каталог, откуда запуск разрешён, — nativeLibraryDir, куда упаковщик кладёт файлы вида
// lib*.so. Поэтому sing-box поставляется в APK как jniLibs/<abi>/libsingbox.so, а этот путь
// передаётся ядру. Без него config.BinDir() указывал бы на /system/bin/bin, EnsureDirs()
// падал бы на MkdirAll, и Init не доходил бы до движка вообще.
//
// Возвращает "" при успехе, описание ошибки при неудаче.
func Init(dataDir string, nativeLibDir string) string {
	globalMu.Lock()
	defer globalMu.Unlock()

	if globalEngine != nil {
		// Повторный Init — НЕ ошибка (дефект D-A18). Служба Android может быть уничтожена
		// и создана заново внутри живого процесса; тогда onCreate вызывает Init второй раз.
		// Прежний код возвращал "already initialized", нативный слой считал любую непустую
		// строку отказом и навсегда оставлял engineReady = false — приложение переставало
		// работать до полного перезапуска процесса. Контракт выхода: "" означает «ядро
		// готово к работе», а оно готово.
		return ""
	}
	if dataDir == "" {
		return "init: dataDir пуст"
	}

	// Устанавливаем переменную окружения чтобы config.DataDir() вернул правильный путь
	os.Setenv("APF_DATA_DIR", dataDir)
	if nativeLibDir != "" {
		os.Setenv("APF_BIN_DIR", nativeLibDir)
	}

	if err := config.EnsureDirs(); err != nil {
		return fmt.Sprintf("init dirs: %v", err)
	}

	_, globalCancel = context.WithCancel(context.Background())
	globalEngine = engine.New(androidConfig())

	if err := globalEngine.Start(); err != nil {
		globalEngine = nil
		globalCancel()
		return fmt.Sprintf("engine start: %v", err)
	}

	return ""
}

// androidConfig — конфигурация ядра для Android.
//
// Вынесено из Init отдельной функцией, чтобы испытание могло проверить её, не поднимая
// движок: каждое из пяти отличий от DefaultConfig существует по конкретной причине,
// и молчаливая потеря любого из них ломает стенд.
func androidConfig() *models.AppConfig {
	cfg := models.DefaultConfig()

	// ТЗ v1.3 F2 (консилиум 2026-09-03, V2 NEW): config.json на Android до сих пор только
	// ПИСАЛСЯ (PatchConfig → saveConfig), но никогда не читался — каждый старт службы начинал с
	// DefaultConfig, и закрепление/избранное/LastActiveNodeID/настройки движка терялись.
	// Читаем поверх дефолтов; платформенные инварианты ниже применяются ПОСЛЕ чтения и потому
	// не могут быть перекрыты файлом. Ошибка чтения — не повод не стартовать: дефолты.
	if found, err := config.LoadInto(cfg); err != nil {
		log.Printf("androidbridge: config.json не прочитан, использую значения по умолчанию: %v", err)
	} else if found {
		log.Printf("androidbridge: config.json загружен (%s)", config.ConfigPath())
	}
	// ТЗ v1.3 F5.2: одна нормализация на всех точках входа — неверное значение = дефолт + WARN.
	for _, w := range cfg.Normalize() {
		log.Printf("androidbridge: конфиг: %s", w)
	}

	// Подключение запускает пользователь. Автоподключение на старте службы означало бы,
	// что телефон уходит в туннель до того, как за ним кто-то наблюдает.
	cfg.AutoConnect = false

	// Web UI на телефоне не нужен, а открытый слушатель — лишняя поверхность.
	cfg.WebUIPort = 0

	cfg.ListenPort = 10808

	// Режим прибит гвоздями, а не унаследован от DefaultConfig. От ConnectionMode зависит
	// флаг tunMode в singbox.NewBuilder: при ModeVPN/ModeHybrid в конфигурацию sing-box
	// попадает tun-inbound. На Android sing-box работает отдельным процессом без root и
	// создать TUN не может — в лучшем случае подключение молча не состоится. Дескриптор
	// туннеля здесь выдаёт только VpnService, и передавать его будет Э-4.
	cfg.ConnectionMode = models.ModeProxy

	// Kill Switch НЕ запрашивается (дефект D-A24). DefaultConfig включает его, и на телефоне
	// это делало подключение невозможным в принципе — вот вся цепочка:
	//
	//   1. движок при EnableKillSwitch обязан применить защиту (engine.go, fail-closed D-2);
	//   2. бэкенд androidKS честно отвечает Capabilities{false,false}, пока система не включит
	//      «Always-on VPN» + «Блокировать соединения без VPN» — включить их из приложения
	//      невозможно, это настройка ОС;
	//   3. capability-gate отвергает применение, подключение откатывается на стадии killswitch.
	//
	// В журнале телефона это выглядело как «Kill Switch не может защитить режим "proxy" этим
	// бэкендом (нужен WFP...)» на КАЖДОЙ попытке, включая все ветки fallback, и заканчивалось
	// «таймаут подключения (20 с)». Текст про WFP и netsh здесь вводит в заблуждение вдвойне:
	// на Android нет ни того, ни другого.
	//
	// Это НЕ fail-open. Защиты, которой нет, приложение не заявляет: фактическое состояние
	// системной защиты по-прежнему сообщается через SetSystemKillSwitch и видно в
	// IsSystemKillSwitchActive. Разница в том, что APF больше не ТРЕБУЕТ применить механизм,
	// которого на этой платформе у него нет. Вдобавок в режиме «прокси» защищать нечего:
	// туннеля не существует, трафик идёт мимо APF, если приложение само не настроено на SOCKS.
	//
	// ПЕРЕСМОТРЕТЬ НА Э-4/Э-5. Когда VpnService выдаст настоящий TUN и пользователь включит
	// системную защиту, SetSystemKillSwitch(true) сделает Capabilities истинными, и запрос
	// Kill Switch снова станет осмысленным.
	cfg.EnableKillSwitch = false

	return cfg
}

// Shutdown останавливает движок APF.
func Shutdown() {
	globalMu.Lock()
	defer globalMu.Unlock()

	if globalEngine != nil {
		stopEngine(globalEngine)
		globalEngine = nil
	}
	if globalCancel != nil {
		globalCancel()
		globalCancel = nil
	}
}

// ─── Подключение ──────────────────────────────────────────────────────────────

// Connect запускает автоматический поиск и подключение к лучшему серверу.
// Возвращает "" при успехе.
func Connect() string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	go func() {
		if err := eng.ScanAndConnect(); err != nil {
			// Логируется внутри engine
			_ = err
		}
	}()
	return ""
}

// ConnectNode подключается к конкретному серверу по ссылке (vless://, vmess://, etc).
func ConnectNode(link string) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if err := eng.AddNodeFromLink(link); err != nil {
		return err.Error()
	}
	go eng.ScanAndConnect()
	return ""
}

// Disconnect завершает текущий сеанс, оставляя ядро готовым к следующему подключению.
//
// Вход:      нет.
// Тело:      обратимая остановка: снятие сетевых изменений, гашение sing-box,
// пересоздание контекста движка.
// Выход:     "" при успехе, текст ошибки при неудаче.
// Fail-safe: вызов до инициализации — не ошибка: отключать нечего.
// Инвариант: после Disconnect повторный Connect обязан работать (дефект D-A17).
//
// Прежняя версия звала engine.Stop(), который отменяет контекст движка безвозвратно.
// Внешне отключение выглядело успешным, но все фоновые циклы (монитор, обновление
// источников, watchdog) были мертвы, и следующее нажатие «Подключить» уходило в никуда —
// испытание циклами Connect/Disconnect обрывалось на втором круге.
func Disconnect() string {
	eng := getEngine()
	if eng == nil {
		return ""
	}
	if err := restartEngine(eng); err != nil {
		return err.Error()
	}
	return ""
}

// ForceSwitch принудительно переключается на другой сервер.
func ForceSwitch() {
	if eng := getEngine(); eng != nil {
		eng.ForceSwitchNow()
	}
}

// ─── Статус ───────────────────────────────────────────────────────────────────

// stateEnvelope — то же состояние, что отдаёт движок, плюс поля, которые UI обязан видеть
// всегда (общий контракт трёх интерфейсов, 2026-09-06).
//
// Зачем обёртка, а не marshal самого ConnectionState. У models.ConnectionState.VerifyState
// стоит `omitempty`, то есть при пустом значении поле ИСЧЕЗАЕТ из JSON — а Kotlin по нему
// определяет, что показывать пользователю. Внешнее поле того же имени объявлено без
// omitempty и по правилу encoding/json (меньшая глубина побеждает) перекрывает встроенное,
// поэтому verify_state присутствует в ответе ВСЕГДА, даже пока движок его не заполняет.
//
// Остальные поля ConnectionState не копируются и не переименовываются: встроенная структура
// разворачивается в тот же плоский JSON, что и раньше — существующие читатели не ломаются.
type stateEnvelope struct {
	*models.ConnectionState
	// VerifyState — idle | checking | verified | failed (models.Verify*), никогда не пустой.
	VerifyState string `json:"verify_state"`
	// ActiveVerifiedLatencyMs — задержка активного узла, ИЗМЕРЕННАЯ ЧЕРЕЗ ТУННЕЛЬ (HTTP), а
	// не TCP-дозвон до порта (D12): это разные величины, и показывать TCP-задержку как
	// «задержку подключения» — вводить в заблуждение. 0 — сквозной замер не делался.
	ActiveVerifiedLatencyMs int64 `json:"active_verified_latency_ms"`
	// ActiveVerifyBadge — тот же значок проверенности, что и у узлов списка (models.Badge*),
	// но для активного узла: экран может показать его, не разыскивая узел в списке.
	ActiveVerifyBadge string `json:"active_verify_badge"`
}

// effectiveVerifyState — verify_state, пригодный для показа, даже если движок его ещё не
// заполняет (поле появилось 2026-09-06 и наполняется отдельным слоем).
//
// Пустое значение НЕ означает «состояние неизвестно, покажи серое»: bool Verified и флаг
// Connected несут ту же информацию грубее, и вывести из них корректное состояние можно
// однозначно. Иначе на непроливших ещё verify_state сборках экран показывал бы «Отключено»
// поверх живого туннеля — ровно то враньё, ради устранения которого поле и вводилось.
func effectiveVerifyState(st *models.ConnectionState) string {
	if st == nil {
		return models.VerifyIdle
	}
	if st.VerifyState != "" {
		return st.VerifyState
	}
	switch {
	case st.Verified:
		return models.VerifyVerified
	case st.Connected:
		// Туннель поднят, подтверждения ещё нет — это «проверяю», а не «провал»: провал
		// умеет объявить только сам движок (health-check дал отрицательный результат).
		return models.VerifyChecking
	default:
		return models.VerifyIdle
	}
}

// GetStateJSON возвращает текущее состояние подключения как JSON строку.
// Kotlin парсит это через JSONObject.
//
// Гарантии контракта для Kotlin: ключи "verify_state", "active_verified_latency_ms" и
// "active_verify_badge" присутствуют ВСЕГДА, включая ветку «ядро не инициализировано».
func GetStateJSON() string {
	defer bridgeRecover("GetStateJSON")
	eng := getEngine()
	if eng == nil {
		return `{"connected":false,"verified":false,"verify_state":"idle",` +
			`"active_verified_latency_ms":0,"active_verify_badge":"unchecked",` +
			`"error":"not initialized"}`
	}
	state := eng.GetState()
	env := stateEnvelope{
		ConnectionState:   state,
		VerifyState:       effectiveVerifyState(state),
		ActiveVerifyBadge: models.BadgeUnchecked,
	}
	if state != nil && state.ActiveNode != nil {
		env.ActiveVerifiedLatencyMs = state.ActiveNode.LastVerifiedLatencyMs
		env.ActiveVerifyBadge = state.ActiveNode.VerifyBadge(time.Now().Unix())
	}
	data, err := json.Marshal(env)
	if err != nil {
		return `{"connected":false,"verified":false,"verify_state":"idle",` +
			`"active_verified_latency_ms":0,"active_verify_badge":"unchecked"}`
	}
	return string(data)
}

// GetVerifyState возвращает одно из models.Verify* (idle|checking|verified|failed) — то же,
// что и поле verify_state в GetStateJSON, но без разбора JSON на стороне Kotlin.
//
// Появилось вместе с исправлением D4: экран Android определял «канал не подтверждён»
// разбором ПОДСТРОКИ русского текста сообщения службы, и любая переформулировка молча
// ломала статус.
func GetVerifyState() string {
	eng := getEngine()
	if eng == nil {
		return models.VerifyIdle
	}
	return effectiveVerifyState(eng.GetState())
}

// GetActiveNodeVerifiedLatency — задержка активного узла, подтверждённая ЧЕРЕЗ ТУННЕЛЬ, мс.
// 0 означает «сквозного замера не было», а НЕ «нулевая задержка»; в этом случае UI обязан
// либо показать TCP-задержку (GetActiveNodeLatency) с явной пометкой, что это другое
// измерение, либо не показывать ничего.
func GetActiveNodeVerifiedLatency() int {
	eng := getEngine()
	if eng == nil {
		return 0
	}
	state := eng.GetState()
	if state == nil || state.ActiveNode == nil {
		return 0
	}
	return int(state.ActiveNode.LastVerifiedLatencyMs)
}

// GetStatsJSON возвращает статистику узлов как JSON.
// {"total":150,"ok":45,"slow":20,"blocked":5}
func GetStatsJSON() string {
	defer bridgeRecover("GetStatsJSON")
	eng := getEngine()
	if eng == nil {
		return `{}`
	}
	stats := eng.GetStats()
	data, _ := json.Marshal(stats)
	return string(data)
}

// IsConnected возвращает true если VPN активен.
func IsConnected() bool {
	eng := getEngine()
	if eng == nil {
		return false
	}
	return eng.GetState().Connected
}

// IsVerified возвращает true только если активный узел подтвердил реальный сквозной
// трафик (post-connect health check), а не просто поднял сокет sing-box. Kotlin использует
// это, чтобы показывать "ищу рабочий узел" вместо "подключено" до подтверждения — см.
// models.ConnectionState.Verified и apf-russia-nodes-no-internet в памяти проекта.
func IsVerified() bool {
	eng := getEngine()
	if eng == nil {
		return false
	}
	return eng.GetState().Verified
}

// GetActiveNodeName возвращает имя активного узла или пустую строку.
func GetActiveNodeName() string {
	eng := getEngine()
	if eng == nil {
		return ""
	}
	state := eng.GetState()
	if state.ActiveNode == nil {
		return ""
	}
	return state.ActiveNode.Name
}

// GetActiveNodeLatency возвращает задержку активного узла в мс (0 если нет).
func GetActiveNodeLatency() int {
	eng := getEngine()
	if eng == nil {
		return 0
	}
	state := eng.GetState()
	if state.ActiveNode == nil {
		return 0
	}
	return int(state.ActiveNode.Latency)
}

// GetSOCKSPort возвращает порт локального SOCKS5 прокси.
func GetSOCKSPort() int {
	eng := getEngine()
	if eng == nil {
		return 10808
	}
	return eng.GetConfig().ListenPort
}

// ─── Узлы ─────────────────────────────────────────────────────────────────────

// nodeListLimit — сколько узлов отдаём в UI. Пул реально содержит тысячи узлов
// (у пользователя — 4600+), сериализовать их все на каждый тик обновления незачем.
const nodeListLimit = 200

// GetNodesJSON возвращает список узлов для экрана «Мои серверы» как JSON строку.
//
// Порядок ОБЯЗАН быть осмысленным, а не «как лежит в пуле». Найдено 2026-08-24 по жалобе
// «не получилось ввести вручную узел и добавить»: `AddNodeFromLink` дописывает узел в КОНЕЦ
// пула, а здесь раньше брались первые 50 записей подряд — то есть вручную добавленный узел
// оказывался на позиции ~4600 и не появлялся в списке НИКОГДА. Пользователь видел тост
// «Сервер добавлен», не находил узел и делал единственно возможный вывод — добавление не
// работает, хотя узел лежал в пуле и сохранялся на диск.
//
// Порядок: закреплённый узел → добавленные вручную → остальные по убыванию Score. Ручные
// узлы идут выше автоимпортированных сознательно: пользователь добавил их явным действием,
// это сильнее любого Score, а свежий узел ещё и имеет Score=0 (не проверен).
func GetNodesJSON() string {
	defer bridgeRecover("GetNodesJSON")
	eng := getEngine()
	if eng == nil {
		return "[]"
	}
	nodes := eng.GetNodes()
	pinnedID := eng.PinnedNodeID()

	// ТЗ v1.7 (живой прогон 09-15): проверенные трафиком (IsProven) — в приоритет ДО среза
	// nodeListLimit, тот же фикс и та же причина, что в internal/web/server.go apiNodes: при пуле
	// в тысячи узлов проверенные (Score 0.88-0.98) вылетали за предел из-за непроверенных с более
	// высоким Score (0.97+), и фильтр «Проверенные» в UI показывал не всех. Порядок:
	// закреплённый → проверенные трафиком → ручные → остальные по убыванию Score.
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
	if len(nodes) > nodeListLimit {
		nodes = nodes[:nodeListLimit]
	}
	// Возвращаем облегчённую версию (без лишних полей).
	//
	// Почему одного bool Proven мало (найдено ревью 2026-09-06). Он отвечает только на вопрос
	// «подтверждался ли узел хоть раз», и на телефоне «трафик проходил минуту назад» и
	// «трафик проходил неделю назад» выглядели ОДИНАКОВО — при том, что выбирать между ними
	// пользователю приходится постоянно. VerifyBadge — общий для Web/Wails/Kotlin разбор на
	// шесть состояний (models.Badge*), считается ЗДЕСЬ, потому что это метод Go, а в JSON сам
	// он не попадёт. Proven оставлен намеренно: его уже читают существующие сборки UI.
	type lightNode struct {
		ID             string  `json:"id"`
		Name           string  `json:"name"`
		Protocol       string  `json:"protocol"`
		Latency        int64   `json:"latency_ms"`
		Score          float64 `json:"score"`
		Status         string  `json:"status"`
		Pinned         bool    `json:"pinned"`
		Favorite       bool    `json:"favorite"` // ТЗ v1.3 F2
		Proven         bool    `json:"proven"`   // ТЗ v1.3 F1.5: подтверждён реальным трафиком
		Banned         bool    `json:"banned"`   // ТЗ v1.3 F3: ручной чёрный список
		Note           string  `json:"note"`     // ТЗ v1.3 F3: заметка пользователя
		VerifyBadge    string  `json:"verify_badge"`
		LastVerifiedAt int64   `json:"last_verified_at"` // unix-секунды, 0 — никогда
		VerifiedCount  int     `json:"verified_count"`
		// VerifiedLatency — та самая задержка «через туннель» (D12), 0 — не измерялась.
		VerifiedLatency int64 `json:"verified_latency_ms"`
	}
	now := time.Now().Unix()
	light := make([]lightNode, len(nodes))
	for i, n := range nodes {
		light[i] = lightNode{
			ID:              n.ID,
			Name:            n.Name,
			Protocol:        string(n.Protocol),
			Latency:         n.Latency,
			Score:           n.Score,
			Status:          string(n.Status),
			Pinned:          pinnedID != "" && n.ID == pinnedID,
			Favorite:        eng.IsFavorite(n.ID),
			Proven:          n.IsProven(),
			Banned:          n.UserBanned,
			Note:            n.UserNote,
			VerifyBadge:     n.VerifyBadge(now),
			LastVerifiedAt:  n.LastVerifiedAt,
			VerifiedCount:   n.VerifiedCount,
			VerifiedLatency: n.LastVerifiedLatencyMs,
		}
	}
	data, _ := json.Marshal(light)
	return string(data)
}

// ConnectByID подключается к конкретному узлу по ID и закрепляет его (B-08.2, FR-4) —
// список «Мои серверы» (docs/TZ_APF_QA_AND_BACKLOG_v1.0.md §5): тап по узлу.
// Возвращает "" при успехе, описание ошибки при неудаче (пустой/неизвестный ID).
func ConnectByID(nodeID string) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if err := eng.ConnectByID(nodeID); err != nil {
		return err.Error()
	}
	return ""
}

// PinNode закрепляет узел — авто-выбор будет предпочитать его вместо топ-по-Score
// (docs/TZ_APF_QA_AND_BACKLOG_v1.0.md §5). В отличие от ConnectByID НЕ переподключает
// сразу — закрепление подействует при следующем авто-выборе (ScanAndConnect/emergencySwitch).
func PinNode(nodeID string) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if strings.TrimSpace(nodeID) == "" {
		return "empty node id"
	}
	// ТЗ v1.3 F2: с валидацией и персистентно (config.json читается при Init — см. androidConfig).
	if err := eng.Pin(nodeID); err != nil {
		return err.Error()
	}
	return ""
}

// ConnectOnce подключается к узлу, НЕ меняя закрепление (ТЗ v1.3 F2, PIN-8): тап по узлу в
// «Мои серверы». Закрепление — отдельное действие (PinNode).
func ConnectOnce(nodeID string) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if err := eng.ConnectOnce(nodeID); err != nil {
		return err.Error()
	}
	return ""
}

// AddFavorite / RemoveFavorite / GetFavoriteIDsJSON — избранное (ТЗ v1.3 F2): порядок
// авто-выбора pinned → favorites → остальное; хранится в config.json.
func AddFavorite(nodeID string) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if err := eng.AddFavorite(nodeID); err != nil {
		return err.Error()
	}
	return ""
}

func RemoveFavorite(nodeID string) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if err := eng.RemoveFavorite(nodeID); err != nil {
		return err.Error()
	}
	return ""
}

// ─── ТЗ v1.3 F4 Stage 1: обход пула ──────────────────────────────────────────────────────

// StartSweep запускает обход всего пула TCP-пробой (без подключения). "" — успех.
func StartSweep() string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if err := eng.StartSweep("manual"); err != nil {
		return err.Error()
	}
	return ""
}

// CancelSweep прерывает обход.
func CancelSweep() {
	if eng := getEngine(); eng != nil {
		eng.CancelSweep()
	}
}

// GetScanProgressJSON — прогресс обхода: {"phase","done","total","alive","verified","eta_sec",…}.
func GetScanProgressJSON() string {
	eng := getEngine()
	if eng == nil {
		return `{"phase":"idle"}`
	}
	data, _ := json.Marshal(eng.GetScanProgress())
	return string(data)
}

// ─── ТЗ v1.5 N-1/N-3: проба реального трафика (каталог рабочих узлов) ───────────────────
//
// StartSweep (выше) — Stage 1: TCP-фильтр всего пула (отвечает ли порт). StartNodeCheck —
// Stage 2: реальный HTTP GET через SOCKS-only инстанс sing-box на top-N кандидатов из уже
// существующего ранжирования (N-1/N-2 ТЗ v1.5). Узел получает Verified*/бейдж proven_fresh
// ТОЛЬКО после того, как через него реально прошёл трафик — не по TCP-задержке.

// StartNodeCheck запускает один прогон пробы реального трафика по топ-N узлам пула
// (умолчания N/K/concurrency/per-node — движок, withDefaults). "" — успех, прогон уже идёт.
// Прогресс — GetNodeCheckStatusJSON(), отмена — CancelNodeCheck(). N-9/C3: результат пробы —
// значок «выход в интернет проверен» (VerifiedViaSOCKS); подпись «через туннель» для этой
// пробы ЗАПРЕЩЕНА — проба идёт через локальный SOCKS проб-слота, а не системный TUN устройства.
func StartNodeCheck() string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if err := eng.StartNodeCheck(engine.NodeCheckOptions{}); err != nil {
		return err.Error()
	}
	return ""
}

// CancelNodeCheck отменяет текущий прогон пробы (если идёт). Идемпотентна — вызов без
// активного прогона ничего не делает.
func CancelNodeCheck() {
	if eng := getEngine(); eng != nil {
		eng.CancelNodeCheck()
	}
}

// GetNodeCheckStatusJSON — прогресс пробы:
// {"running","phase","total","probed","verified","failed","added","target_k","started_at"}.
func GetNodeCheckStatusJSON() string {
	eng := getEngine()
	if eng == nil {
		return `{"running":false,"phase":""}`
	}
	data, _ := json.Marshal(eng.NodeCheckStatus())
	return string(data)
}

// ─── L5-UI Android (ТЗ v1.4 §5): ручной харвест узлов из источников ────────────
//
// engine.HarvestNow синхронный и небыстрый (до бюджета), а gomobile-вызов из Kotlin не
// должен блокировать UI-поток надолго, поэтому мост крутит проход в горутине и отдаёт
// прогресс/итог через GetHarvestStatusJSON (Kotlin опрашивает, как GetNodeCheckStatusJSON).
// Наружу — ТОЛЬКО счётчики/контролируемые строки, БЕЗ сырых URL/содержимого (анти-XSS/
// анти-утечка секретов, как в web/wails-лотах). Узлы входят в пул непроверенными через
// mergeFetchedNodes (граница доверия) — «рабочими» их делает отдельная проба/скан.
var (
	harvestMu       sync.Mutex
	harvestRunning  bool
	harvestDone     bool
	harvestErr      string
	harvestProgress harvester.Progress
	harvestResult   *engine.HarvestResult
)

// HarvestNow запускает один проход харвестера. "" — успех/запущено; иначе текст ошибки
// ("not initialized" / "харвест уже идёт"). Прогресс/итог — GetHarvestStatusJSON().
func HarvestNow() string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	harvestMu.Lock()
	if harvestRunning {
		harvestMu.Unlock()
		return "харвест уже идёт"
	}
	harvestRunning = true
	harvestDone = false
	harvestErr = ""
	harvestResult = nil
	harvestProgress = harvester.Progress{}
	harvestMu.Unlock()

	eng.OnHarvestProgress = func(p harvester.Progress) {
		harvestMu.Lock()
		harvestProgress = p
		harvestMu.Unlock()
	}

	go func() {
		res, err := eng.HarvestNow(context.Background())
		harvestMu.Lock()
		harvestRunning = false
		harvestDone = true
		if err != nil {
			harvestErr = err.Error()
		} else {
			harvestResult = res
		}
		harvestMu.Unlock()
	}()
	return ""
}

// HarvestFromText запускает разбор вставленного пользователем текста (несколько ссылок/дамп/
// подписка) тем же харвестером, что и HarvestNow, но без обращения к источникам. "" — успех/запущено;
// иначе текст ошибки ("not initialized" / "пустой ввод" / "харвест уже идёт"). Прогресс/итог —
// GetHarvestStatusJSON().
func HarvestFromText(text string) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if strings.TrimSpace(text) == "" {
		return "пустой ввод"
	}
	harvestMu.Lock()
	if harvestRunning {
		harvestMu.Unlock()
		return "харвест уже идёт"
	}
	harvestRunning = true
	harvestDone = false
	harvestErr = ""
	harvestResult = nil
	harvestProgress = harvester.Progress{}
	harvestMu.Unlock()

	eng.OnHarvestProgress = func(p harvester.Progress) {
		harvestMu.Lock()
		harvestProgress = p
		harvestMu.Unlock()
	}

	go func() {
		res, err := eng.HarvestFromText(context.Background(), text)
		harvestMu.Lock()
		harvestRunning = false
		harvestDone = true
		if err != nil {
			harvestErr = err.Error()
		} else {
			harvestResult = res
		}
		harvestMu.Unlock()
	}()
	return ""
}

// GetHarvestStatusJSON — прогресс/итог последнего харвеста (плоский JSON):
// {"running","done","error","phase","source_index","source_total","found",
//
//	"parsed","merged","subscription_urls","sources_processed","sources_total","stopped"}.
func GetHarvestStatusJSON() string {
	harvestMu.Lock()
	defer harvestMu.Unlock()
	out := map[string]interface{}{
		"running":      harvestRunning,
		"done":         harvestDone,
		"error":        harvestErr,
		"phase":        harvestProgress.Phase,
		"source_index": harvestProgress.SourceIndex,
		"source_total": harvestProgress.SourceTotal,
		"found":        harvestProgress.Found,
	}
	if harvestResult != nil {
		out["parsed"] = harvestResult.Parsed
		out["merged"] = harvestResult.Merged
		out["subscription_urls"] = harvestResult.SubscriptionURLs
		out["sources_processed"] = harvestResult.Report.SourcesProcessed
		out["sources_total"] = harvestResult.Report.SourcesTotal
		out["stopped"] = harvestResult.Report.Stopped
	}
	data, _ := json.Marshal(out)
	return string(data)
}

// AnyLongOpRunning — true, если сейчас идёт любая из трёх длинных фоновых операций (обход
// пула/скан, проба реального трафика, харвест). Единая точка правды для Android
// foreground-сервиса (LongOpForegroundService): вместо дублирования фазовой логики трёх
// разных статусов в Kotlin, сервис раз в секунду опрашивает этот один флаг и завершает себя,
// как только все три операции закончились — не раньше, иначе Doze/OOM-killer может убить
// процесс раньше, чем скан/сбор/харвест дойдут до конца при свёрнутом приложении или
// погашенном экране (жалоба владельца 2026-09-22, issue 2 "уход в другую вкладку" уже
// проверен как не баг — здесь закрывается более тяжёлый случай: сворачивание/экран выключен).
func AnyLongOpRunning() bool {
	if eng := getEngine(); eng != nil {
		if eng.SweepRunning() {
			return true
		}
		if eng.NodeCheckStatus().Running {
			return true
		}
	}
	harvestMu.Lock()
	running := harvestRunning
	harvestMu.Unlock()
	return running
}

// ─── Fix B (ТЗ v1.7 PROBE-DEPTH-SETTING): глубина пробы узлов на Android ────────
// Паритет с desktop (там настройка «Глубина проверки узлов трафиком» уже есть). Значение —
// models.AppConfig.NodeCheckTopN: 0 = встроенный дефолт движка (30), иначе 10–300. Валидацию
// и персист берёт на себя eng.PatchConfig (тот же путь, что у остальных настроек Android,
// engine.go node_check_top_n) — новые движковые методы не заводим.

// SetNodeCheckTopN задаёт глубину пробы. "" — успех, иначе текст ошибки валидации.
func SetNodeCheckTopN(n int) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if err := eng.PatchConfig(map[string]interface{}{"node_check_top_n": n}); err != nil {
		return err.Error()
	}
	return ""
}

// GetNodeCheckTopN — текущая глубина пробы (0 = встроенный дефолт 30) для инициализации UI.
func GetNodeCheckTopN() int {
	eng := getEngine()
	if eng == nil {
		return 0
	}
	if cfg := eng.GetConfig(); cfg != nil {
		return cfg.NodeCheckTopN
	}
	return 0
}

// ─── ТЗ v1.3 F3: управление узлами ───────────────────────────────────────────────────────

// RemoveNode удаляет узел с надгробием (подписки не вернут). "" — успех.
func RemoveNode(nodeID string) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if err := eng.RemoveNode(nodeID); err != nil {
		return err.Error()
	}
	return ""
}

// BanNode ставит/снимает ручной чёрный список.
func BanNode(nodeID string, banned bool) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if err := eng.BanNode(nodeID, banned); err != nil {
		return err.Error()
	}
	return ""
}

// UpdateNodeJSON — правка: JSON {"name":"…","user_note":"…"} (отсутствующее поле — не трогать).
func UpdateNodeJSON(nodeID string, patchJSON string) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	var patch models.NodePatch
	if err := json.Unmarshal([]byte(patchJSON), &patch); err != nil {
		return "bad json: " + err.Error()
	}
	if err := eng.UpdateNode(nodeID, patch); err != nil {
		return err.Error()
	}
	return ""
}

// ResetNodeStats обнуляет статистику узла.
func ResetNodeStats(nodeID string) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if err := eng.ResetNodeStats(nodeID); err != nil {
		return err.Error()
	}
	return ""
}

// RestoreRemovedNodes снимает надгробия; возвращает число восстановленных.
func RestoreRemovedNodes() int {
	eng := getEngine()
	if eng == nil {
		return 0
	}
	return eng.RestoreRemovedNodes()
}

// GetFavoriteIDsJSON — JSON-массив ID избранных узлов в порядке добавления.
func GetFavoriteIDsJSON() string {
	eng := getEngine()
	if eng == nil {
		return "[]"
	}
	ids := eng.FavoriteIDs()
	if ids == nil {
		ids = []string{}
	}
	data, _ := json.Marshal(ids)
	return string(data)
}

// ─── W3 (ТЗ v1.5 §2, TZ_v1.5_NODE_CATALOG_2026-09-14): классы избранного ─────────────────
//
// Два класса избранного (models.OriginUser/OriginSystem — internal/models/node.go): звезда
// пользователя (sticky, снять может только сам пользователь через RemoveFavorite выше) и
// системный фаворит (пишет ТОЛЬКО реконсиляция каталога после пробы реального трафика,
// reconcileFavoritesFromNodeCheck в node_check.go). UI обязан различать бейджи — см.
// FavoriteOrigin ниже и showMyServersDialog в MainActivity.kt. AddFavorite/RemoveFavorite
// (выше) остаются ЕДИНОЙ точкой входа для обоих классов — звезда на системном фаворите
// повышает его до пользовательского (engine.addFavoriteWithOrigin), а не создаёт вторую запись.

// FavoriteOrigin возвращает класс избранного узла: "user" | "system" | "" — узел не в
// избранном. eng == nil — тоже "" (нечего классифицировать, ядро не поднято).
func FavoriteOrigin(nodeID string) string {
	defer bridgeRecover("FavoriteOrigin")
	eng := getEngine()
	if eng == nil {
		return ""
	}
	return eng.FavoriteOrigin(nodeID)
}

// UserFavoriteIDsJSON — JSON-массив ID ПОЛЬЗОВАТЕЛЬСКИХ фаворитов (звезда), в порядке
// добавления. W3: раздельный список от системных — см. SystemFavoriteIDsJSON ниже.
func UserFavoriteIDsJSON() string {
	defer bridgeRecover("UserFavoriteIDsJSON")
	eng := getEngine()
	if eng == nil {
		return "[]"
	}
	ids := eng.UserFavoriteIDs()
	if ids == nil {
		ids = []string{}
	}
	data, _ := json.Marshal(ids)
	return string(data)
}

// SystemFavoriteIDsJSON — JSON-массив ID СИСТЕМНЫХ фаворитов (сборка каталога, после пробы
// реального трафика), в порядке добавления. W3: см. UserFavoriteIDsJSON выше.
func SystemFavoriteIDsJSON() string {
	defer bridgeRecover("SystemFavoriteIDsJSON")
	eng := getEngine()
	if eng == nil {
		return "[]"
	}
	ids := eng.SystemFavoriteIDs()
	if ids == nil {
		ids = []string{}
	}
	data, _ := json.Marshal(ids)
	return string(data)
}

// UnpinNode снимает закрепление узла — авто-выбор возвращается к обычному ранжированию
// по Score (docs/TZ_APF_QA_AND_BACKLOG_v1.0.md §5).
func UnpinNode() string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	eng.UnpinNode()
	return ""
}

// AddNode добавляет узел по ссылке (vless://, vmess://, ss://, trojan://).
// Возвращает "" при успехе, описание ошибки при неудаче.
func AddNode(link string) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if err := eng.AddNodeFromLink(link); err != nil {
		return err.Error()
	}
	return ""
}

// ConnectChainPartner — точка входа роли «Вход» (§4, docs/PLAN_2026-08-28_
// stubs_and_realfunc.md): вставить ссылку от партнёра в роли «Выход» и подключиться сразу,
// без ожидания планового ScanAndConnect. Отдельно от AddNode — партнёр по цепочке не
// взаимозаменяем с публичными узлами: помечается IsChainPartner, поэтому обычный
// автовыбор/пересканирование его не трогает, а при сбое движок повторяет попытку
// подключения именно к нему, а не подменяет случайным публичным узлом
// (Engine.AddChainPartnerFromLink/emergencySwitch).
// Возвращает "" при успехе, описание ошибки при неудаче.
func ConnectChainPartner(link string) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if _, err := eng.AddChainPartnerFromLink(link); err != nil {
		return err.Error()
	}
	return ""
}

// ─── Каталог узлов (Э-UI-2, docs/TZ_ANDROID_UI_PARITY_v1.0.md §1.2) ────────────

// GetCatalogStatusJSON возвращает статус всех провайдеров каталога (платные/бесплатные/
// Tor/ручной) как JSON-массив — тот же eng.GetCatalogStatus(), которым уже пользуется
// десктопный Web UI (/api/catalog/status, internal/web/server.go: apiCatalogStatus),
// просто через мост вместо HTTP.
func GetCatalogStatusJSON() string {
	defer bridgeRecover("GetCatalogStatusJSON")
	eng := getEngine()
	if eng == nil {
		return "[]"
	}
	data, _ := json.Marshal(eng.GetCatalogStatus())
	return string(data)
}

// RefreshCatalog запускает фоновое обновление узлов у всех включённых провайдеров.
// Не ждёт завершения (Fetch по каждому провайдеру, до 3 минут суммарно) — тот же
// fire-and-forget контракт, что у /api/catalog/refresh на десктопе (apiCatalogRefresh).
// Прогресс и результат идут через уже подписанный LogCallback: eng.RefreshCatalog сам
// логирует каждый шаг (per-provider успех/отказ, число добавленных узлов) — отдельный
// callback здесь не нужен.
func RefreshCatalog() string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		_, _ = eng.RefreshCatalog(ctx)
	}()
	return ""
}

// GetPaidProvidersJSON — [TZ_TAILS_HARDENING_2026-08-31.md кластер C] список сохранённых
// платных провайдеров (для списка с кнопкой «Удалить» на экране «Платные провайдеры»). Windows
// GUI получает тот же список другим путём (App.GetConfig().PaidProviders — общий конфиг), у
// Android-моста общего вызова "весь конфиг" нет, отдельный узкий геттер (Engine.GetPaidProviders).
func GetPaidProvidersJSON() string {
	defer bridgeRecover("GetPaidProvidersJSON")
	eng := getEngine()
	if eng == nil {
		return "[]"
	}
	data, _ := json.Marshal(eng.GetPaidProviders())
	return string(data)
}

// AddPaidProvider — [TZ_TAILS_HARDENING_2026-08-31.md кластер C] раньше на Android не было ни
// этой функции, ни экрана — вся бизнес-логика (Engine.AddPaidProvider) уже существовала
// (реализована для Windows в рамках roadmap v1.2, P2.1), но добавить платного провайдера с
// телефона было физически нечем. entryJSON — JSON-сериализованный models.PaidProviderEntry
// (тот же набор полей, что и в Windows-панели «Источники»: id/name/type/url/username/password/
// token/subscription_url/enabled/insecure_tls). Возвращает "" при успехе, описание ошибки при
// отказе — тот же контракт, что у AddNode.
func AddPaidProvider(entryJSON string) string {
	defer bridgeRecover("AddPaidProvider")
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	var entry models.PaidProviderEntry
	if err := json.Unmarshal([]byte(entryJSON), &entry); err != nil {
		return "bad json: " + err.Error()
	}
	if err := eng.AddPaidProvider(entry); err != nil {
		return err.Error()
	}
	return ""
}

// RemovePaidProvider удаляет платного провайдера и его узлы из пула по ID.
// Возвращает "" при успехе, описание ошибки, если провайдер с таким ID не найден.
func RemovePaidProvider(id string) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if !eng.RemovePaidProvider(id) {
		return "not found: " + id
	}
	return ""
}

// TestPaidProvider — пробное подключение БЕЗ сохранения (кнопка «Проверить» перед
// «Добавить», до 20с — тот же контракт, что и у Windows-версии, App.TestPaidProvider,
// gui/app.go). entryJSON — тот же формат, что у AddPaidProvider. Возвращает JSON
// {"count":N,"error":""} — число узлов, которые вернул провайдер, или {"count":0,"error":"..."}
// при отказе (тот же приём "JSON с полем error", что уже используется в этом файле —
// см. RunDNSLeakTestJSON выше).
func TestPaidProvider(entryJSON string) string {
	defer bridgeRecover("TestPaidProvider")
	eng := getEngine()
	if eng == nil {
		data, _ := json.Marshal(map[string]interface{}{"count": 0, "error": "not initialized"})
		return string(data)
	}
	var entry models.PaidProviderEntry
	if err := json.Unmarshal([]byte(entryJSON), &entry); err != nil {
		data, _ := json.Marshal(map[string]interface{}{"count": 0, "error": "bad json: " + err.Error()})
		return string(data)
	}
	count, err := eng.TestPaidProvider(entry)
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	data, _ := json.Marshal(map[string]interface{}{"count": count, "error": errStr})
	return string(data)
}

// SetCatalogProviderEnabled включает/выключает провайдера каталога по ID.
// Возвращает "" при успехе, описание ошибки, если провайдер с таким ID не найден.
func SetCatalogProviderEnabled(id string, enabled bool) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if !eng.SetProviderEnabled(id, enabled) {
		return "provider not found: " + id
	}
	return ""
}

// ─── W3 (ТЗ v1.5 §5): интервал пересмотра каталога ───────────────────────────────────────
//
// Интервал НЕ запускает сборку каталога сам — сборка остаётся только по кнопке пользователя
// (RefreshCatalog/StartNodeCheck выше, owner-декрет консилиума TZ_v1.5_NODE_CATALOG_2026-09-14).
// Он лишь задаёт гейт давности: после этого срока проваленная проба на СЛЕДУЮЩЕЙ ручной сборке
// вправе снять узел из системного избранного (reconcileFavoritesFromNodeCheck, node_check.go).

// CatalogReviewInterval — текущий интервал пересмотра каталога:
// each_scan|daily|weekly|monthly (models.ReviewInterval* в internal/models/node.go).
// eng == nil (ядро не поднято) — тот же дефолт, что у голого движка без конфига: each_scan.
func CatalogReviewInterval() string {
	defer bridgeRecover("CatalogReviewInterval")
	eng := getEngine()
	if eng == nil {
		return models.ReviewIntervalEachScan
	}
	return eng.CatalogReviewInterval()
}

// SetCatalogReviewInterval сохраняет интервал пересмотра каталога: each_scan|daily|weekly|
// monthly. Возвращает "" при успехе; иначе — "not initialized" либо, для нераспознанного
// значения, текст ошибки движка (в отличие от CatalogReviewInterval выше, здесь неизвестное
// значение — ЯВНАЯ ошибка, а не молчаливый откат на дефолт, см. doc-комментарий у
// engine.SetCatalogReviewInterval).
func SetCatalogReviewInterval(v string) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if err := eng.SetCatalogReviewInterval(v); err != nil {
		return err.Error()
	}
	return ""
}

// ─── Блокировка рекламы (Э-UI-3, docs/TZ_ANDROID_UI_PARITY_v1.0.md §1.3) ───────

// GetAdBlockStatusJSON возвращает статус AdBlock (профиль, статистика загрузки
// блок-листов, белый список) как JSON — тот же eng.GetAdBlockStatus(), что уже
// отдаёт десктопный Web UI (/api/adblock/status).
func GetAdBlockStatusJSON() string {
	defer bridgeRecover("GetAdBlockStatusJSON")
	eng := getEngine()
	if eng == nil {
		return "{}"
	}
	data, _ := json.Marshal(eng.GetAdBlockStatus())
	return string(data)
}

// SetAdBlockProfile переключает профиль AdBlock: "disabled", "light", "standard",
// "strict". Загрузка блок-листов для НЕ-disabled профиля идёт в фоне (до 2 минут на
// движке, eng.SetAdBlockProfile сам запускает горутину) — эта функция не ждёт.
// Возвращает "" при успехе, описание ошибки (например, неизвестный профиль) при отказе.
func SetAdBlockProfile(profile string) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if err := eng.SetAdBlockProfile(profile); err != nil {
		return err.Error()
	}
	return ""
}

// AdBlockToggleAllowlist добавляет (add=true) или убирает (add=false) домен из
// белого списка AdBlock. До Init не делает ничего.
//
// Возвращает true, если состояние действительно изменилось. false — ввод не является
// доменом либо домен уже был (не был) в списке; UI обязан показать это пользователю, а не
// рисовать успех. P1-6 (аудит 2026-09-01): раньше возврата не было вовсе, и Kotlin-слой не
// мог отличить принятый домен от отброшенного.
func AdBlockToggleAllowlist(domain string, add bool) bool {
	if eng := getEngine(); eng != nil {
		return eng.AdBlockToggleAllowlist(domain, add)
	}
	return false
}

// ─── Приватность: DNS-leak/WebRTC (Э-UI-4, docs/TZ_ANDROID_UI_PARITY_v1.0.md §1.4) ─

// GetLeakGuardStatusJSON возвращает статус защит устройства (IPv6/WebRTC guard,
// шифрование хранилища, инструкции для браузера, firefox user.js) как JSON — тот же
// eng.GetLeakGuardStatus(), что отдаёт десктопный /api/leakguard/status.
func GetLeakGuardStatusJSON() string {
	defer bridgeRecover("GetLeakGuardStatusJSON")
	eng := getEngine()
	if eng == nil {
		return "{}"
	}
	data, _ := json.Marshal(eng.GetLeakGuardStatus())
	return string(data)
}

// RunDNSLeakTestJSON запускает полную проверку DNS-утечки и БЛОКИРУЕТ вызывающий
// поток на время теста (~8с, таймаут 15с) — тот же контракт, что у
// /api/leakguard/dns-test на десктопе (HTTP-запрос тоже не возвращается раньше).
// Kotlin обязан звать эту функцию НЕ на главном потоке UI (см. doc-комментарий у
// showLeakGuardDialog в MainActivity.kt) — иначе ANR.
// Возвращает JSON результата ({"leaked":bool,"system_dns":...,...}) либо
// {"error":"...","leaked":false} при отказе/до инициализации.
func RunDNSLeakTestJSON() string {
	eng := getEngine()
	if eng == nil {
		return `{"error":"not initialized","leaked":false}`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := eng.RunDNSLeakTest(ctx)
	if err != nil {
		data, _ := json.Marshal(map[string]interface{}{"error": err.Error(), "leaked": false})
		return string(data)
	}
	data, _ := json.Marshal(map[string]interface{}{
		"leaked":         result.Leaked,
		"system_dns":     result.SystemDNS,
		"tunnel_dns":     result.TunnelDNS,
		"system_ips":     result.SystemIPs,
		"tunnel_ips":     result.TunnelIPs,
		"diagnosis":      result.Diagnosis,
		"recommendation": result.Recommendation,
	})
	return string(data)
}

// SetWebRTCBlock включает/выключает защиту от утечки IP через WebRTC.
// Возвращает "" при успехе, описание ошибки при отказе.
func SetWebRTCBlock(enabled bool) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if err := eng.EnableWebRTCBlock(enabled); err != nil {
		return err.Error()
	}
	return ""
}

// ─── Анти-DPI/скрытность (Э-UI-5, docs/TZ_ANDROID_UI_PARITY_v1.0.md §1.5) ──────

// GetDPIStatusJSON возвращает статус анти-DPI подсистем (последний результат
// Canary, Traffic Padding, CDN Fronting, ShadowTLS) как JSON — тот же
// eng.GetDPIStatus(), что отдаёт десктопный /api/dpi/status.
func GetDPIStatusJSON() string {
	defer bridgeRecover("GetDPIStatusJSON")
	eng := getEngine()
	if eng == nil {
		return "{}"
	}
	data, _ := json.Marshal(eng.GetDPIStatus(context.Background()))
	return string(data)
}

// RunCanaryTestJSON запускает Canary-тест (определяет, видит ли провайдер VPN) и
// БЛОКИРУЕТ вызывающий поток на время теста (~15с, таймаут 25с) — тот же
// контракт, что у /api/dpi/canary-test на десктопе. Kotlin обязан звать это НЕ
// на главном потоке (тот же приём, что уже принят для RunDNSLeakTestJSON).
func RunCanaryTestJSON() string {
	eng := getEngine()
	if eng == nil {
		return `{"error":"not initialized","score":0}`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	result, err := eng.RunCanaryTest(ctx)
	if err != nil {
		data, _ := json.Marshal(map[string]interface{}{"error": err.Error(), "score": 0})
		return string(data)
	}
	data, _ := json.Marshal(map[string]interface{}{
		"score":           result.Score,
		"vpn_detectable":  result.VPNDetectable,
		"tls_leaked":      result.TLSFingerprintLeaked,
		"timing_anomaly":  result.TimingAnomaly,
		"entropy_high":    result.EntropyHigh,
		"diagnosis":       result.Diagnosis,
		"recommendation":  result.Recommendation,
		"counter_measure": result.CounterMeasure,
		"duration_ms":     result.Duration,
	})
	return string(data)
}

// SetTrafficPadding включает/выключает маскировку размера пакетов трафика.
func SetTrafficPadding(enabled bool, aggressive bool) {
	if eng := getEngine(); eng != nil {
		eng.EnableTrafficPadding(enabled, aggressive)
	}
}

// SetShadowTLSConfig настраивает ShadowTLS v3 (маскировка под обычный TLS).
// serverAddr — P1-1 (аудит 2026-09-01): адрес РЕАЛЬНОГО сервера (host:port), обязателен
// при enabled=true. server остаётся необязательным переопределением маскировочного
// SNI-сайта (для проверки доступности) — трафик туда никогда не идёт.
// Возвращает "" при успехе, иначе — текст ошибки (напр. пустой пароль/serverAddr при enabled=true).
func SetShadowTLSConfig(enabled bool, password string, sni string, server string, serverAddr string) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if err := eng.SetShadowTLSConfig(enabled, password, sni, server, serverAddr); err != nil {
		return err.Error()
	}
	return ""
}

// AutoSelectShadowTLSSNIJSON автоматически подбирает лучший SNI для ShadowTLS.
// БЛОКИРУЕТ вызывающий поток (до 15с) — тот же контракт, что и у Canary/DNS-leak
// тестов. Возвращает {"status":"ok","sni":"..."} либо {"error":"..."}.
func AutoSelectShadowTLSSNIJSON() string {
	eng := getEngine()
	if eng == nil {
		return `{"error":"not initialized"}`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sni, err := eng.AutoSelectShadowTLSSNI(ctx)
	if err != nil {
		data, _ := json.Marshal(map[string]interface{}{"error": err.Error()})
		return string(data)
	}
	data, _ := json.Marshal(map[string]interface{}{"status": "ok", "sni": sni})
	return string(data)
}

// SetCDNConfig настраивает CDN Fronting (маскировка под трафик к CDN).
// workerDomain пустой — выключает CDN Fronting.
func SetCDNConfig(workerDomain string, backendHost string, backendPort int) {
	if eng := getEngine(); eng != nil {
		eng.SetCDNConfig(workerDomain, backendHost, backendPort)
	}
}

// ─── Анти-блокировка/residential IP (Э-UI-6, docs/TZ_ANDROID_UI_PARITY_v1.0.md §1.6) ─

// GetAntiBlockStatusJSON возвращает статус анти-блокировки как JSON — тот же
// eng.GetAntiBlockStatus(), что отдаёт десктопный /api/antiblock/status.
func GetAntiBlockStatusJSON() string {
	defer bridgeRecover("GetAntiBlockStatusJSON")
	eng := getEngine()
	if eng == nil {
		return "{}"
	}
	data, _ := json.Marshal(eng.GetAntiBlockStatus())
	return string(data)
}

// CheckCurrentIPJSON проверяет IP активного узла на признаки датацентра.
// БЛОКИРУЕТ вызывающий поток (до 10с) — тот же контракт, что у
// /api/antiblock/check-ip?ip=current на десктопе. Kotlin обязан звать НЕ на
// главном потоке (тот же приём, что у RunDNSLeakTestJSON/RunCanaryTestJSON).
func CheckCurrentIPJSON() string {
	eng := getEngine()
	if eng == nil {
		return `{"error":"not initialized"}`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := eng.CheckCurrentIP(ctx)
	if err != nil {
		data, _ := json.Marshal(map[string]interface{}{"error": err.Error()})
		return string(data)
	}
	data, _ := json.Marshal(result)
	return string(data)
}

// SetAntiBlockConfig настраивает анти-блокировку. Пустой apiKey НЕ сбрасывает уже
// сохранённый ключ (тот же контракт, что у eng.SetAntiBlockConfig).
func SetAntiBlockConfig(enabled bool, residentialOnly bool, autoSwitch bool, apiKey string) {
	if eng := getEngine(); eng != nil {
		eng.SetAntiBlockConfig(enabled, residentialOnly, autoSwitch, apiKey)
	}
}

// SetNodeAutoSwitchEnabled включает/выключает автопереключение узлов при сбое (см.
// комментарий у models.AppConfig.NodeAutoSwitchEnabled в internal/models/node.go — тот же
// живой инцидент 2026-08-19, паритет с desktop GUI).
func SetNodeAutoSwitchEnabled(enabled bool) {
	if eng := getEngine(); eng != nil {
		eng.SetNodeAutoSwitchEnabled(enabled)
	}
}

// IsNodeAutoSwitchEnabled — текущее состояние тумблера (для инициализации UI при старте).
func IsNodeAutoSwitchEnabled() bool {
	eng := getEngine()
	if eng == nil {
		return true
	}
	return eng.IsNodeAutoSwitchEnabled()
}

// SetCyclicNodeSearch включает/выключает круговой обход пула узлов при автопереключении
// (см. комментарий у models.AppConfig.CyclicNodeSearch — паритет с desktop GUI).
func SetCyclicNodeSearch(enabled bool) {
	if eng := getEngine(); eng != nil {
		eng.SetCyclicNodeSearch(enabled)
	}
}

// IsCyclicNodeSearchEnabled — текущее состояние тумблера (для инициализации UI при старте).
func IsCyclicNodeSearchEnabled() bool {
	eng := getEngine()
	if eng == nil {
		return false
	}
	return eng.IsCyclicNodeSearchEnabled()
}

// SetChainMode включает/выключает режим цепочки VPN → Proxy (см. models.AppConfig.EnableChain).
func SetChainMode(enabled bool) {
	if eng := getEngine(); eng != nil {
		eng.SetChainMode(enabled)
	}
}

// IsChainModeEnabled — текущее состояние тумблера (для инициализации UI при старте).
func IsChainModeEnabled() bool {
	eng := getEngine()
	if eng == nil {
		return false
	}
	return eng.IsChainModeEnabled()
}

// SetMultihopEnabled включает/выключает выбор узлов разных протоколов на каждом звене
// цепочки (см. models.AppConfig.MultiHopEnabled) — уточняет SetChainMode, без него эффекта
// не даёт.
func SetMultihopEnabled(enabled bool) {
	if eng := getEngine(); eng != nil {
		eng.SetMultihopEnabled(enabled)
	}
}

// IsMultihopEnabled — текущее состояние тумблера (для инициализации UI при старте).
func IsMultihopEnabled() bool {
	eng := getEngine()
	if eng == nil {
		return false
	}
	return eng.IsMultihopEnabled()
}

// SetMultihopCount задаёт число хопов многохоповой цепочки (допустимо 2 или 3, иное
// откатывается на 2).
func SetMultihopCount(n int) {
	if eng := getEngine(); eng != nil {
		eng.SetMultihopCount(n)
	}
}

// GetMultihopCount — текущее число хопов (для инициализации UI при старте).
func GetMultihopCount() int {
	eng := getEngine()
	if eng == nil {
		return 2
	}
	return eng.GetMultihopCount()
}

// GetBypassRulesJSON возвращает список bypass-правил (встроенных и пользовательских).
func GetBypassRulesJSON() string {
	eng := getEngine()
	if eng == nil {
		return "[]"
	}
	data, _ := json.Marshal(eng.GetBypassRules())
	return string(data)
}

// ─── Приложения вне VPN ───────────────────────────────────────────────────────
//
// Механизм СОЗНАТЕЛЬНО общий: список задаёт пользователь, любой пакет. Госуслуги — лишь
// самый частый пример; так же ведут себя банковские приложения, платёжные сервисы,
// маркетплейсы и часть государственных сервисов — все они отказываются работать, обнаружив
// признаки VPN/прокси. Хардкодить конкретные пакеты в ядре нельзя: список у каждого свой и
// меняется чаще, чем выходят сборки.

// GetDisallowedAppsJSON возвращает JSON-массив пакетов, исключённых из VPN.
func GetDisallowedAppsJSON() string {
	eng := getEngine()
	if eng == nil {
		return "[]"
	}
	data, err := json.Marshal(eng.DisallowedApps())
	if err != nil {
		return "[]"
	}
	return string(data)
}

// SetDisallowedAppsJSON заменяет список пакетов, исключённых из VPN.
// Принимает JSON-массив строк — gomobile не умеет передавать []string.
// Возвращает "" при успехе, текст ошибки иначе.
//
// Изменение вступает в силу при следующей сборке VPN-интерфейса: список читает Kotlin в
// момент VpnService.Builder. Для применения к живому сеансу вызывающая сторона обязана
// пересоздать TUN (тот же путь, что у задачи #11) — см. APFVpnService.
func SetDisallowedAppsJSON(jsonArray string) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	var pkgs []string
	if err := json.Unmarshal([]byte(jsonArray), &pkgs); err != nil {
		return fmt.Sprintf("некорректный список приложений: %v", err)
	}
	eng.SetDisallowedApps(pkgs)
	return ""
}

// SetBypassRule включает/выключает bypass-правило по ID.
func SetBypassRule(id string, enabled bool) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if !eng.SetBypassRule(id, enabled) {
		return "rule not found: " + id
	}
	return ""
}

// AddBypassDomain добавляет пользовательское bypass-правило. directRoute=true — домен идёт
// НАПРЯМУЮ, в обход VPN целиком (не защищён VPN); residential — домен идёт через VPN, но
// предпочтителен residential-узел. Независимые флаги.
func AddBypassDomain(domain string, name string, residential bool, directRoute bool) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if !eng.AddBypassDomain(domain, name, residential, directRoute) {
		return "failed to add"
	}
	return ""
}

// UpdateBypassDomain редактирует пользовательское bypass-правило (встроенные — нельзя).
func UpdateBypassDomain(id string, domain string, name string, residential bool, directRoute bool) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if !eng.UpdateBypassDomain(id, domain, name, residential, directRoute) {
		return "not found or builtin"
	}
	return ""
}

// RemoveBypassDomain удаляет пользовательское bypass-правило по ID (встроенные
// правила удалить нельзя — вернётся отказ).
func RemoveBypassDomain(id string) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if !eng.RemoveBypassDomain(id) {
		return "not found or builtin"
	}
	return ""
}

// ─── Аварийная очистка + шифрование (Э-UI-7, docs/TZ_ANDROID_UI_PARITY_v1.0.md §1.7) ─

// SetMasterPassword включает/выключает AES-256-GCM шифрование nodes_cache.json.
// Пустой пароль — выключает шифрование. Чистое состояние в памяти (пересоздаёт
// e.cryptoStore), файлов не касается — тот же контракт, что у
// eng.SetMasterPassword/desktop apiSetPassword.
func SetMasterPassword(password string) {
	if eng := getEngine(); eng != nil {
		eng.SetMasterPassword(password)
	}
}

// EmergencyWipeJSON СТИРАЕТ данные APF (nodes_cache/конфиг/логи; при wipeAll=true
// — ещё и bin/sing-box) и НЕОБРАТИМО завершает текущий сеанс движка (eng.cancel()
// внутри eng.EmergencyWipe). confirm ДОЛЖЕН быть ровно "WIPE" — тот же защитный
// контракт, что у /api/emergency/wipe на десктопе (apiEmergencyWipe); это
// требование самого бриджа, а не только Kotlin-диалога сверху — случайный вызов
// с любым другим текстом (или пустым) ничего не удалит.
//
// Kotlin-стороне ОБЯЗАТЕЛЬНО нужен собственный подтверждающий диалог поверх
// этой проверки (см. showEmergencyDialog в MainActivity.kt) — WIPE здесь не
// оценка риска пользователем, а фиксированная строка протокола.
func EmergencyWipeJSON(wipeAll bool, confirm string) string {
	eng := getEngine()
	if eng == nil {
		return `{"error":"not initialized"}`
	}
	if confirm != "WIPE" {
		return `{"error":"confirmation required: pass confirm=WIPE"}`
	}
	result := eng.EmergencyWipe(wipeAll)
	data, _ := json.Marshal(map[string]interface{}{
		"status":        "wiped",
		"files_deleted": result.FilesDeleted,
		"bytes_deleted": result.BytesDeleted,
		"errors":        result.Errors,
		"duration_ms":   result.Duration.Milliseconds(),
	})
	return string(data)
}

// ─── Логи ─────────────────────────────────────────────────────────────────────

// LogCallback — интерфейс для получения логов из Go в Kotlin.
// Kotlin реализует этот интерфейс и передаёт в SetLogCallback.
type LogCallback interface {
	OnLog(message string)
}

// SetLogCallback устанавливает callback для получения логов.
func SetLogCallback(cb LogCallback) {
	eng := getEngine()
	if eng == nil || cb == nil {
		return
	}
	eng.OnLog = func(msg string) {
		cb.OnLog(msg)
	}
}

// StateCallback — интерфейс для уведомлений об изменении состояния.
type StateCallback interface {
	OnStateChanged(connectedJSON string)
}

// SetStateCallback устанавливает callback для изменений состояния подключения.
func SetStateCallback(cb StateCallback) {
	eng := getEngine()
	if eng == nil || cb == nil {
		return
	}
	eng.OnStateChange = func(state *models.ConnectionState) {
		data, _ := json.Marshal(state)
		cb.OnStateChanged(string(data))
	}
}

// LeakCallback — интерфейс для уведомлений об утечках.
type LeakCallback interface {
	OnLeakDetected(leakType string, details string)
}

// SetLeakCallback устанавливает callback для утечек.
func SetLeakCallback(cb LeakCallback) {
	eng := getEngine()
	if eng == nil || cb == nil {
		return
	}
	eng.OnLeakDetected = func(leakType, details string) {
		cb.OnLeakDetected(leakType, details)
	}
}

// ─── Конфиг ───────────────────────────────────────────────────────────────────

// SetKillSwitch включает/выключает ТРЕБОВАНИЕ Kill Switch в конфигурации APF.
//
// Вход:  enabled — требуется ли защита.
// Тело:  включение разрешается ТОЛЬКО если система уже её обеспечивает; выключение — всегда.
// Выход: "" — настройка принята; иначе причина отказа для показа пользователю.
//
// Почему включение может быть отвергнуто (дефект D-A24). На Android приложение не может
// включить Kill Switch: блокировку трафика мимо туннеля выполняет система («Always-on VPN»
// + «Блокировать соединения без VPN»). Пока она выключена, бэкенд честно сообщает, что не
// защищает ни один режим, и движок при fail-closed ОТКАЗЫВАЕТСЯ подключаться вовсе. То есть
// переключатель, включённый «на всякий случай», не добавлял защиты, а отбирал связь —
// и понять это по интерфейсу было нельзя.
//
// Поэтому требование принимается только тогда, когда его можно выполнить. Как только
// пользователь включит защиту в настройках ОС, нативный слой сообщит об этом через
// SetSystemKillSwitch, и переключатель заработает.
// IsKillSwitchEnabled — ТЗ v1.3 F6 (D1/D2 HIGH, UI-A-3): читает СОХРАНЁННОЕ намерение
// пользователя (cfg.EnableKillSwitch), а не системное состояние защиты (см.
// IsSystemKillSwitchActive) — тумблер на экране должен совпадать с тем, что реально
// применяется движком, а не всегда стартовать выключенным до первого клика.
func IsKillSwitchEnabled() bool {
	eng := getEngine()
	if eng == nil {
		return false
	}
	return eng.GetConfig().EnableKillSwitch
}

func SetKillSwitch(enabled bool) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if enabled && !killswitch.AndroidSystemProtection() {
		return "Kill Switch включает только система: Настройки → VPN → «Always-on VPN» и " +
			"«Блокировать соединения без VPN». Пока они выключены, APF не может требовать " +
			"защиту — иначе подключение будет отклоняться, а защиты всё равно не появится"
	}
	eng.PatchConfig(map[string]interface{}{"enable_kill_switch": enabled})
	return ""
}

// SetSystemKillSwitch сообщает ядру ФАКТИЧЕСКОЕ состояние системной защиты Android.
//
// Нативный слой обязан вызывать этот метод при старте и при каждом возврате приложения
// на передний план, опросив состояние «Always-on VPN» и «Блокировать соединения без VPN».
// Пока не вызван — ядро считает, что защиты нет (fail-closed по решению D-2), и откажется
// применять Kill Switch вместо того, чтобы делать вид, будто он работает.
func SetSystemKillSwitch(active bool) {
	killswitch.SetAndroidSystemProtection(active)
}

// IsSystemKillSwitchActive возвращает последнее переданное состояние системной защиты.
func IsSystemKillSwitchActive() bool {
	return killswitch.AndroidSystemProtection()
}

// SetIPv6Block включает/выключает IPv6 блокировку.
func SetIPv6Block(enabled bool) string {
	eng := getEngine()
	if eng == nil {
		return "not initialized"
	}
	if err := eng.EnableIPv6Block(enabled); err != nil {
		return err.Error()
	}
	return ""
}

// IsIPv6BlockEnabled — ФАКТИЧЕСКОЕ состояние защиты от IPv6-утечки.
//
// Свод C трек 1 п.2 (B4 #1, D1): экран Android брал начальное положение тумблера
// «IPv6 Block» из XML-дефолта (checked=true) и никогда не спрашивал ядро. После
// перезапуска активити пользователь видел включённую защиту независимо от того,
// выключил ли он её сам — то есть ровно тот класс лжи, ради которого вводился
// контракт VerifyState: экран показывает не то, что применено.
//
// Тонкая обёртка над уже существующим eng.GetLeakGuardStatus() (тот же источник, что
// отдаёт GetLeakGuardStatusJSON и десктопный /api/leakguard/status) — отдельного
// движкового геттера намеренно не заводится: новое поведение здесь не появляется,
// появляется только читаемость с Kotlin-стороны без разбора JSON.
//
// До инициализации — false: «защиты нет» безопаснее, чем «защита есть» (fail-closed,
// тот же принцип, что у IsSystemKillSwitchActive и updateKillSwitchHint на Kotlin).
func IsIPv6BlockEnabled() bool {
	defer bridgeRecover("IsIPv6BlockEnabled")
	eng := getEngine()
	if eng == nil {
		return false
	}
	enabled, _ := eng.GetLeakGuardStatus()["ipv6_guard_enabled"].(bool)
	return enabled
}

// SetStickySession устанавливает политику Sticky Session.
// policy: "sticky", "free", "timed"
func SetStickySession(policy string) {
	if eng := getEngine(); eng != nil {
		eng.SetStickyPolicy(policy)
	}
}

// GetStickySessionPolicy — текущая политика Sticky Session ("sticky"/"free"/"timed").
//
// Свод C трек 1 п.2 (B4 #1, D1): спиннер на Android всегда стартовал с позиции 0
// («Держаться узла»), потому что у моста был только сеттер. Выбор «Свободно менять»
// применялся к движку, но при следующем открытии экрана спиннер показывал прежнюю
// первую строку — а его onItemSelected при построении списка тут же возвращал движок
// на "sticky", молча отменяя выбор пользователя.
//
// Обёртка над eng.GetStickySessionStatus()["policy"] (тот же источник, что читают
// Web и Wails) — единый источник истины, а не вторая копия выбора на телефоне.
//
// Пустая строка = «нечего показывать» (движок не поднят): Kotlin в этом случае
// оставляет позицию по умолчанию, а не подставляет выдуманную политику.
func GetStickySessionPolicy() (policy string) {
	defer bridgeRecover("GetStickySessionPolicy")
	eng := getEngine()
	if eng == nil {
		return ""
	}
	p, _ := eng.GetStickySessionStatus()["policy"].(string)
	return p
}

// GetDiagnosticsJSON возвращает диагностику как JSON.
func GetDiagnosticsJSON() string {
	defer bridgeRecover("GetDiagnosticsJSON")
	eng := getEngine()
	if eng == nil {
		return "{}"
	}
	data, _ := json.Marshal(eng.GetDiagnostics())
	return string(data)
}

// ─── Вспомогательные ──────────────────────────────────────────────────────────

func getEngine() *engine.Engine {
	globalMu.Lock()
	defer globalMu.Unlock()
	return globalEngine
}

// Version возвращает версию APF из единого источника истины (internal/version).
// Хардкод здесь недопустим: отчёт об испытании обязан соотноситься со сборкой.
func Version() string {
	return version.Version
}

// ─── C-13 (ТЗ v1.4, FAIL B2): трёхзначное состояние тумблеров защиты ──────────────────────
//
// ЧТО БЫЛО. `IsIPv6BlockEnabled` (и все остальные read-back-геттеры) начинались с
// `eng := getEngine(); if eng == nil { return false }`. Движок на Android поднимается только
// при подключении, поэтому на свежем старте приложения ЛЮБОЙ тумблер читался как «выключено»,
// и Kotlin рисовал его выключенным (`MainActivity.kt:349,355`). Живой прогон K8-LIVE B2 видел
// это как «тумблер ВЫКЛ, а Диагностика и config.json говорят ВКЛ».
//
// ЧТО СТАЛО. Состояний три: "on" | "off" | "unknown". «unknown» означает «ядро не запущено»,
// и UI обязан показать положение из КОНФИГА с пометкой, а не выдуманное «выключено».
// Значения конфига мост умеет прочитать и без движка — тем же путём, что androidConfig().
//
// КОНТРАКТ ДЛЯ UI-ЛОТОВ (L2-A / L2-W / L2-D):
//
//	GetToggleState(name) string   → "on" | "off" | "unknown"; name — одна из Toggle*-констант.
//	GetProtectionStateJSON()      → {"known":bool,"source":"engine"|"config",
//	                                 "ipv6_block":bool,"webrtc_block":bool,
//	                                 "cyclic_search":bool,"node_auto_switch":bool,
//	                                 "sticky_policy":"sticky|free|timed"}
//	                                при known=false значения взяты из config.json (положение
//	                                верное, но ядро их ещё не применяло — показать пометку).
//
// Прежние bool-геттеры (IsIPv6BlockEnabled, IsCyclicNodeSearchEnabled, …) сохранены, чтобы
// текущий Kotlin собирался; они по-прежнему отвечают false без движка и потому НЕ годятся для
// инициализации экрана — переводить экраны следует на функции выше.
const (
	// ToggleOn — тумблер включён (по данным ядра либо конфига).
	ToggleOn = "on"
	// ToggleOff — тумблер выключен.
	ToggleOff = "off"
	// ToggleUnknown — состояние неизвестно: ядро не запущено (или имя тумблера незнакомо).
	ToggleUnknown = "unknown"
)

// Имена тумблеров для GetToggleState. Строки, а не константы Kotlin: через границу gomobile
// проходят только простые типы.
const (
	ToggleIPv6Block      = "ipv6_block"
	ToggleWebRTCBlock    = "webrtc_block"
	ToggleCyclicSearch   = "cyclic_search"
	ToggleNodeAutoSwitch = "node_auto_switch"
	ToggleChainMode      = "chain_mode"
	ToggleMultihop       = "multihop"
)

// protectionState — сводка тумблеров для UI (см. контракт выше).
type protectionState struct {
	Known          bool   `json:"known"`
	Source         string `json:"source"`
	IPv6Block      bool   `json:"ipv6_block"`
	WebRTCBlock    bool   `json:"webrtc_block"`
	CyclicSearch   bool   `json:"cyclic_search"`
	NodeAutoSwitch bool   `json:"node_auto_switch"`
	ChainMode      bool   `json:"chain_mode"`
	Multihop       bool   `json:"multihop"`
	StickyPolicy   string `json:"sticky_policy"`
}

// configProtectionState — положение тумблеров по config.json, когда движка нет.
//
// Читает файл тем же способом, что androidConfig() при старте: дефолты + LoadInto. Ошибку
// чтения не превращает в отказ — дефолты честнее выдуманного «выключено».
func configProtectionState() protectionState {
	cfg := models.DefaultConfig()
	if _, err := config.LoadInto(cfg); err != nil {
		log.Printf("androidbridge: состояние тумблеров читается из дефолтов: %v", err)
	}
	cfg.Normalize()
	policy := cfg.StickySessionPolicy
	if policy == "" {
		policy = "sticky"
	}
	return protectionState{
		Known:          false,
		Source:         "config",
		IPv6Block:      cfg.BlockIPv6Leak,
		WebRTCBlock:    cfg.BlockWebRTC,
		CyclicSearch:   cfg.CyclicNodeSearch,
		NodeAutoSwitch: cfg.NodeAutoSwitchEnabled,
		ChainMode:      cfg.EnableChain,
		Multihop:       cfg.MultiHopEnabled,
		StickyPolicy:   policy,
	}
}

// engineProtectionState — положение тумблеров по живому ядру.
func engineProtectionState(eng *engine.Engine) protectionState {
	cfg := eng.GetConfig()
	st := protectionState{Known: true, Source: "engine"}
	if cfg != nil {
		// Истина — конфиг (C-13 п.2): guard/менеджер лишь исполнители.
		st.IPv6Block = cfg.BlockIPv6Leak
		st.WebRTCBlock = cfg.BlockWebRTC
		st.CyclicSearch = cfg.CyclicNodeSearch
		st.NodeAutoSwitch = cfg.NodeAutoSwitchEnabled
		st.ChainMode = cfg.EnableChain
		st.Multihop = cfg.MultiHopEnabled
		st.StickyPolicy = cfg.StickySessionPolicy
	}
	if st.StickyPolicy == "" {
		if p, _ := eng.GetStickySessionStatus()["policy"].(string); p != "" {
			st.StickyPolicy = p
		} else {
			st.StickyPolicy = "sticky"
		}
	}
	return st
}

// GetProtectionStateJSON — сводка тумблеров защиты с признаком «известно ли это ядру».
func GetProtectionStateJSON() string {
	defer bridgeRecover("GetProtectionStateJSON")
	st := configProtectionState()
	if eng := getEngine(); eng != nil {
		st = engineProtectionState(eng)
	}
	data, err := json.Marshal(st)
	if err != nil {
		return `{"known":false,"source":"config"}`
	}
	return string(data)
}

// GetToggleState — трёхзначное состояние одного тумблера: "on" | "off" | "unknown".
func GetToggleState(name string) string {
	defer bridgeRecover("GetToggleState")
	if getEngine() == nil {
		return ToggleUnknown
	}
	st := engineProtectionState(getEngine())
	var v bool
	switch name {
	case ToggleIPv6Block:
		v = st.IPv6Block
	case ToggleWebRTCBlock:
		v = st.WebRTCBlock
	case ToggleCyclicSearch:
		v = st.CyclicSearch
	case ToggleNodeAutoSwitch:
		v = st.NodeAutoSwitch
	case ToggleChainMode:
		v = st.ChainMode
	case ToggleMultihop:
		v = st.Multihop
	default:
		return ToggleUnknown
	}
	if v {
		return ToggleOn
	}
	return ToggleOff
}

// GetActiveNodeVerifiedLatencySource — чем получен замер LastVerifiedLatencyMs активного узла
// (C-20): "tun" — прямой пробой мимо SOCKS, тем же путём, что у браузера (только про такую
// величину честно говорить «через туннель»); "socks5" — через локальный SOCKS движка;
// "" — сквозного замера не было.
func GetActiveNodeVerifiedLatencySource() string {
	defer bridgeRecover("GetActiveNodeVerifiedLatencySource")
	eng := getEngine()
	if eng == nil {
		return ""
	}
	state := eng.GetState()
	if state == nil || state.ActiveNode == nil {
		return ""
	}
	return state.ActiveNode.LastVerifiedVia
}

// GetActiveNodeExitCountry — ФАКТИЧЕСКАЯ страна выхода активного узла (C-21), "" — неизвестна.
// Отличается от метки каталога в имени узла; когда обе известны и различаются, UI обязан
// показать обе (живой прогон: метка 🇬🇧GB, фактический выход — Нидерланды).
func GetActiveNodeExitCountry() string {
	defer bridgeRecover("GetActiveNodeExitCountry")
	eng := getEngine()
	if eng == nil {
		return ""
	}
	state := eng.GetState()
	if state == nil || state.ActiveNode == nil {
		return ""
	}
	return state.ActiveNode.ExitCountry()
}

// GetPoolCountsJSON — три честных числа о пуле (C-18):
// {"total":N,"tcp_alive":M,"proven_traffic":K,"verify_stale":S}.
// «Отвечает по TCP» и «подтверждён трафиком» — разные величины, и одним числом «живых N»
// их смешивать нельзя (живой прогон D7: живых 1480 из 5467, подтверждённых трафиком — 2).
func GetPoolCountsJSON() string {
	defer bridgeRecover("GetPoolCountsJSON")
	eng := getEngine()
	if eng == nil {
		return `{"total":0,"tcp_alive":0,"proven_traffic":0,"verify_stale":0}`
	}
	data, err := json.Marshal(eng.PoolVerificationCounts())
	if err != nil {
		return `{"total":0,"tcp_alive":0,"proven_traffic":0,"verify_stale":0}`
	}
	return string(data)
}

// GetSwitchNotice — объяснение результата последнего ручного «Сменить сервер» (C-15).
// "" — объяснять нечего. Непустая строка означает, что другой рабочий узел не нашёлся и
// пользователь остался на прежнем: раньше движок в этой ситуации молчал, а экран показывал
// тот же сервер как ни в чём не бывало (живой прогон D3, семь нажатий подряд).
func GetSwitchNotice() string {
	defer bridgeRecover("GetSwitchNotice")
	eng := getEngine()
	if eng == nil {
		return ""
	}
	state := eng.GetState()
	if state == nil {
		return ""
	}
	return state.SwitchNotice
}
