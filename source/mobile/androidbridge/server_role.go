package androidbridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/netutil"
	"github.com/apf/adaptive-pathfinder/internal/relay"
	"github.com/apf/adaptive-pathfinder/internal/singbox"
)

var errIdentityRequired = errors.New("identity обязателен (см. GenerateServerIdentityJSON)")

// defaultMaxConnectedClientsAndroid — дефолт для телефона (docs/TZ_APF_RELAY_v1.0.md §10.1):
// «микро-сервер» на батарее и мобильном интернете тянет заметно меньше одновременных «Входов»,
// чем ПК. Тот же смысл, что defaultMaxConnectedClientsWindows у internal/engine/server_role.go
// (там 5), просто другое платформенное число.
const defaultMaxConnectedClientsAndroid = 2

// upnpUnmapTimeout — [консилиум, MEDIUM, находка №20, TZ_RELAY_HARDENING_2026-08-29.md
// кластер F] тот же контракт, что и Windows-версия (internal/engine/server_role.go): best-effort
// и всегда в фоне, отсутствие UPnP-роутера/маппинга не задерживает саму остановку роли.
const upnpUnmapTimeout = 5 * time.Second

// ─── Э-Выход-2 (docs/PLAN_APF_VHOD_VYHOD_v1.0.md) · роль «Выход» на Android ───────
//
// Независимая от клиентского Engine (globalEngine/getEngine в bridge.go) поверхность:
// устройство может одновременно быть «Входом» (обычный VPN-клиент) и «Выходом» (звеном
// цепочки, принимающим подключения) — ТЗ §1 явно требует, чтобы ни одна роль не
// предполагала выключения другой. Поэтому здесь свой package-level держатель состояния
// и свой мьютекс (serverRoleMu), не переиспользуется globalMu/globalEngine.
//
// serverRoleRunner создаётся ОДИН раз на первый успешный StartServerRole и переживает
// последующие вызовы — StartServerRole на уже существующем runner-е означает
// WriteConfig+Start заново, что для androidServerRunner эквивалентно горячей
// перезагрузке (см. internal/singbox/android_server_runner.go, StartOrReloadService).
// Пересоздание runner-а на каждый вызов было бы той же ошибкой, что уже нашлась и
// исправлена для клиентского пути в задаче #11 (два оверлеппящихся sing-box инстанса).
//
// [Фаза E, docs/PLAN_APF_RELAY_v1.0.md] Admission control + relay-fallback — тот же
// контракт, что Engine.StartServerRole на Windows (internal/engine/server_role.go), тот же
// комментарий про AdmissionProxy применим здесь без изменений: публичный listenPort (тот,
// что в ссылке) слушает НЕ сам sing-box, а AdmissionProxy — лимит подключений действует
// одинаково для прямых подключений и для relay-пути. sing-box слушает отдельный эфемерный
// внутренний порт (netutil.ReserveFreePort).
var (
	serverRoleMu              sync.Mutex
	serverRoleProtectCB       ProtectCallback
	serverRoleRunner          *singbox.AndroidServerRunner
	serverRoleListen          int
	serverRoleInternal        int
	serverRoleAdmission       *singbox.AdmissionProxy
	serverRoleAdmissionCancel context.CancelFunc
	serverRoleExit            *relay.ExitClient
	serverRoleExitCancel      context.CancelFunc
	// serverRoleExitAddr/serverRoleExitFingerprint — relay-адрес и отпечаток TLS-сертификата,
	// на которые сейчас реально настроен serverRoleExit (оба "", если relay-fallback не
	// поднят) — TZ_RELAY_HARDENING_2026-08-29.md кластеры A и B: hot-reload сверяет их с
	// переданными relayAddr/relayFingerprint, чтобы понять, нужно ли пересоздавать
	// ExitClient, а не гасить и поднимать заново при КАЖДОМ hot-reload вне зависимости от
	// того, менялось ли хоть что-то из relay-настроек.
	serverRoleExitAddr        string
	serverRoleExitFingerprint string
)

// serverRelayCredentialsPath — exit-id + relay-token (docs/TZ_APF_RELAY_v1.0.md §2.1, §3),
// тот же смысл и тот же JSON-формат, что у Windows-версии (internal/engine/server_role.go) —
// оба читают/пишут через общий relay.EnsureExitCredentials, разница только в пути (свой
// config.DataDir() на каждой платформе). Отдельный файл от server-identity (Kotlin хранит
// identity в EncryptedSharedPreferences, не здесь) — exit-id/relay-token НЕ производные от
// identity.UUID/PrivateKey (см. TZ §3).
func serverRelayCredentialsPath() string {
	return filepath.Join(config.DataDir(), "server_relay_credentials.json")
}

// SetServerProtectCallback устанавливает ProtectCallback (VpnService.protect) ДО вызова
// StartServerRole — тот же приём, что и SetProtectCallback для клиентского TUN-пути
// (tun.go), но отдельный сеттер: роль «Выход» — независимый жизненный цикл, у неё может
// не быть открытого TUN вовсе (см. android_server_runner.go — OpenTun у переданного
// PlatformInterface для серверной роли никогда не вызывается).
//
// Зачем protect() нужен серверной роли, у которой нет собственного TUN: BuildServerConfig
// ставит route.auto_detect_interface=true — если на устройстве в это же время активен
// СТОРОННИЙ VPN (или сама APF одновременно работает как «Вход»), исходящий "direct"
// outbound роли «Выход» обязан явно выйти в реальную сеть, а не быть перехваченным чужим
// туннелем. Без установленного колбэка StartServerRole отказывает явно (см. ниже) — не
// молчаливая деградация.
func SetServerProtectCallback(cb ProtectCallback) {
	serverRoleMu.Lock()
	defer serverRoleMu.Unlock()
	serverRoleProtectCB = cb
}

// GenerateServerIdentityJSON генерирует новый независимый ключ звена (ТЗ §2: «у каждого
// звена цепочки свой независимый ключ») — одноразовое действие при первом запуске роли,
// НЕ при каждом StartServerRole. Вызывающая сторона (Kotlin) обязана сохранить результат
// (например, в EncryptedSharedPreferences) и передавать его в последующие StartServerRole.
//
// Возвращает JSON {"UUID":...,"PrivateKey":...,"PublicKey":...,"ShortID":...} при успехе,
// {"error":"..."} при отказе (единственный источник отказа — исчерпание crypto/rand, см.
// singbox.GenerateServerIdentity).
func GenerateServerIdentityJSON() string {
	id, err := singbox.GenerateServerIdentity()
	if err != nil {
		data, _ := json.Marshal(map[string]string{"error": err.Error()})
		return string(data)
	}
	data, _ := json.Marshal(id)
	return string(data)
}

// BuildServerLinkJSON собирает готовую vless://-ссылку для передачи «Входу» (ТЗ §5.2,
// «Готово — вот ваша ссылка»). host — куда «Вход» будет физически подключаться (домен/IP);
// на этом этапе (до Э-Выход-4, реальной Reachability.Detect) вводится пользователем
// вручную, а не определяется автоматически. relayAddr пустая строка ⇒ обычная прямая
// ссылка (прежнее поведение, БЕЗ ИЗМЕНЕНИЙ); непустая ⇒ relay-формат (докс §3) — host в
// этом случае игнорируется, вместо него в ссылку идёт адрес relay-сервера, и
// генерируются/переиспользуются exit-id+relay-token (тот же контракт, что
// Engine.BuildServerRoleLink на Windows). relayFingerprint — отпечаток TLS-сертификата
// relay-сервера (TZ_RELAY_HARDENING_2026-08-29.md кластер B) — обязателен вместе с
// непустым relayAddr, иначе партнёр получит ссылку, по которой EntryBridge гарантированно
// откажет (fail-closed без отпечатка, internal/relay/tunnel_tls.go).
//
// Возвращает JSON {"link":"vless://..."} при успехе, {"error":"..."} при отказе.
// identityJSON — тот же формат, что вернул GenerateServerIdentityJSON.
func BuildServerLinkJSON(identityJSON, host string, listenPort int, realityDest, label, relayAddr, relayFingerprint string) string {
	id, err := decodeIdentity(identityJSON)
	if err != nil {
		data, _ := json.Marshal(map[string]string{"error": err.Error()})
		return string(data)
	}
	if realityDest == "" {
		realityDest = singbox.GoodRealitySNI[0]
	}
	if relayAddr == "" {
		link := singbox.BuildServerLink(id, host, listenPort, realityDest, label)
		data, _ := json.Marshal(map[string]string{"link": link})
		return string(data)
	}

	relayHost, relayPortStr, err := net.SplitHostPort(relayAddr)
	if err != nil {
		data, _ := json.Marshal(map[string]string{"error": fmt.Sprintf("BuildServerLinkJSON: адрес relay %q: %v", relayAddr, err)})
		return string(data)
	}
	relayPort, err := strconv.Atoi(relayPortStr)
	if err != nil {
		data, _ := json.Marshal(map[string]string{"error": fmt.Sprintf("BuildServerLinkJSON: порт relay %q: %v", relayPortStr, err)})
		return string(data)
	}
	if relayFingerprint == "" {
		data, _ := json.Marshal(map[string]string{"error": "BuildServerLinkJSON: не задан отпечаток TLS-сертификата relay (relayFingerprint) — обязателен для relay-режима"})
		return string(data)
	}
	exitID, _, err := relay.EnsureExitCredentials(serverRelayCredentialsPath())
	if err != nil {
		data, _ := json.Marshal(map[string]string{"error": err.Error()})
		return string(data)
	}
	link := singbox.BuildServerRelayLink(id, relayHost, relayPort, exitID, relayFingerprint, realityDest, label)
	data, _ := json.Marshal(map[string]string{"link": link})
	return string(data)
}

// serverRoleLog — общий канал логов роли «Выход» на Android: тот же путь, что уже
// использует OnInternalLog ниже (через globalEngine.OnLog, единственный лог-приёмник,
// который Kotlin успел подписать), с тем же префиксом [SERVER/...], чтобы записи
// admission-control/relay-fallback не терялись отдельно от диагностики sing-box.
func serverRoleLog(msg string) {
	if eng := getEngine(); eng != nil && eng.OnLog != nil {
		eng.OnLog("[SERVER] " + msg)
	}
}

// StartServerRole поднимает роль «Выход» на listenPort с ранее сгенерированной
// identityJSON. realityDest пустая строка ⇒ singbox.GoodRealitySNI[0]. maxClients <= 0 ⇒
// defaultMaxConnectedClientsAndroid (2, докс §10.1). relayAddr пустая строка ⇒ без
// relay-fallback (только прямой путь); непустая ⇒ поднимается ExitClient к указанному
// relay-серверу (докс §1, §5) — тот же контракт, что Engine.StartServerRole на Windows.
//
//	Вход:      listenPort (1..65535 — проверяется внутри singbox.validateServerDoc через
//	           WriteConfig), realityDest, identityJSON (см. GenerateServerIdentityJSON),
//	           maxClients, relayAddr.
//	Тело:      декодирует identity, при первом вызове создаёт androidServerRunner (переживает
//	           последующие вызовы — см. комментарий у serverRoleRunner), иначе переиспользует
//	           существующий (горячая перезагрузка — AndroidServerRunner.Start вызывает
//	           StartOrReloadService, которая умеет безопасно применить новый конфиг поверх
//	           уже работающего in-process инстанса САМА, без внешнего Stop()+Start()). Публичный
//	           listenPort слушает AdmissionProxy, sing-box — отдельный эфемерный внутренний порт.
//	Выход:     "" при успехе; непустая строка — текст ошибки (контракт gomobile).
//	Отвергает: пустой identityJSON/невалидный JSON, отсутствие SetServerProtectCallback —
//	           с внятным текстом, до создания runner-а.
//
// [консилиум 2026-08-29, HIGH, находка №4, TZ_RELAY_HARDENING_2026-08-29.md кластер A]
// Раньше AdmissionProxy/ExitClient гасились БЕЗУСЛОВНО до попытки нового WriteConfig/Start —
// при отказе публичный listener оставался разрушен без восстановления, а
// IsServerRoleRunning()/GetServerRoleStatusJSON() продолжали отражать устаревшие/бессмысленные
// данные. Теперь порядок: WriteConfig+Start выполняются ПЕРВЫМИ (StartOrReloadService и так не
// трогает публичный порт/AdmissionProxy — это отдельный уровень); AdmissionProxy/ExitClient
// гасятся/заменяются, ТОЛЬКО когда новый sing-box уже подтверждённо поднялся. При успехе на
// том же публичном порту — публичный listener НИКОГДА не пересоздаётся (Retarget вместо
// net.Listen заново): уже подключённые «Входы» не видят на этом шаге вообще никакого разрыва,
// не только «почти никакого», как на Windows (там sing-box — отдельный процесс, который
// приходится в момент замены останавливать).
func StartServerRole(listenPort int, realityDest string, identityJSON string, maxClients int, relayAddr, relayFingerprint string) string {
	id, err := decodeIdentity(identityJSON)
	if err != nil {
		return "StartServerRole: " + err.Error()
	}
	if realityDest == "" {
		realityDest = singbox.GoodRealitySNI[0]
	}
	if maxClients <= 0 {
		maxClients = defaultMaxConnectedClientsAndroid
	}

	serverRoleMu.Lock()
	cb := serverRoleProtectCB
	if cb == nil {
		serverRoleMu.Unlock()
		return "StartServerRole: SetServerProtectCallback не установлен — вызовите его раньше"
	}
	runner := serverRoleRunner
	admission := serverRoleAdmission
	prevListenPort := serverRoleListen
	if runner == nil {
		// [консилиум, HIGH, находка №5, TZ_RELAY_HARDENING_2026-08-29.md кластер E] Проверка
		// nil и создание/сохранение runner-а — ОДНА критическая секция: лок держится и через
		// саму конструкцию AndroidServerRunner. Раньше чтение serverRoleRunner и его запись
		// были разнесены по разным захватам serverRoleMu — двойной быстрый тап по кнопке
		// «Запустить» мог провести два конкурентных StartServerRole через одно и то же nil,
		// оба создавали свой AndroidServerRunner, «проигравший» терялся без Stop() (утечка
		// нативного sing-box-инстанса/порта). Запуск роли — не горячий путь (по нажатию
		// кнопки, не в цикле), поэтому широкий лок здесь предпочтён более сложному
		// double-checked locking с последующим Stop() «проигравшего»: тривиально доказуемо
		// корректен и не добавляет отдельную ветку отказа ради выигрыша в задержке, которая
		// тут не нужна.
		adapter := newPlatformAdapter(cb, 0)
		r, rerr := singbox.NewAndroidServerRunner(adapter)
		if rerr != nil {
			serverRoleMu.Unlock()
			return "StartServerRole: " + rerr.Error()
		}
		// Диагностика — тот же приём, что и у клиента (prepareTun/tun.go, задача #25/D-A37):
		// без сырых логов sing-box единственный видимый симптом отказа Reality-рукопожатия —
		// "connection reset by peer" на КЛИЕНТСКОЙ стороне, настоящая причина видна только
		// здесь. Префикс SERVER/ (не SINGBOX/, как у клиента) — разные роли в одном логе
		// должны различаться на глаз.
		r.OnInternalLog = func(level, msg string) {
			serverRoleLog(fmt.Sprintf("[%s] %s", level, msg))
		}
		runner = r
		serverRoleRunner = runner
	}
	serverRoleMu.Unlock()

	wasRunning := runner.IsRunning()

	internalPort, perr := netutil.ReserveFreePort()
	if perr != nil {
		return "StartServerRole: резервирование внутреннего порта: " + perr.Error()
	}

	doc := singbox.BuildServerConfig(id, internalPort, realityDest)
	if werr := runner.WriteConfig(doc); werr != nil {
		return "StartServerRole: " + werr.Error()
	}
	if serr := runner.Start(context.Background()); serr != nil {
		// Не трогаем admission/exit здесь: StartOrReloadService на неудачном hot-reload может
		// оставить старый инстанс живым (тогда старый AdmissionProxy/internalPort по-прежнему
		// валидны — незачем их гасить) либо мог уже его остановить (тогда
		// runner.IsRunning()/GetServerRoleStatusJSON честно отразят это сами, без нашего
		// вмешательства) — в обоих случаях безусловный teardown здесь рисковал бы либо
		// разрушить всё ещё рабочее состояние, либо не добавить ничего к уже честной картине.
		return "StartServerRole: " + serr.Error()
	}

	if wasRunning && admission != nil && listenPort == prevListenPort {
		admission.Retarget(fmt.Sprintf("127.0.0.1:%d", internalPort), singbox.ServerClashAPIPort(internalPort))
		admission.SetMaxClients(maxClients)

		serverRoleMu.Lock()
		serverRoleInternal = internalPort
		serverRoleMu.Unlock()

		reconcileServerRoleExit(listenPort, relayAddr, relayFingerprint)
		serverRoleLog(fmt.Sprintf("роль «Выход»: конфигурация обновлена без разрыва публичного порта %d (лимит подключений: %d)", listenPort, maxClients))
		return ""
	}

	// Первый запуск, либо публичный порт реально меняется по воле вызывающей стороны — старое
	// (если было) гасится ТОЛЬКО теперь, когда новый sing-box уже подтверждённо поднят.
	if wasRunning {
		teardownServerRoleAdmissionAndExit()
	}

	publicLn, lerr := net.Listen("tcp", fmt.Sprintf(":%d", listenPort))
	if lerr != nil {
		runner.Stop()
		return fmt.Sprintf("StartServerRole: публичный порт %d занят: %v", listenPort, lerr)
	}

	admissionProxy := singbox.NewAdmissionProxy(publicLn, fmt.Sprintf("127.0.0.1:%d", internalPort),
		maxClients, singbox.ServerClashAPIPort(internalPort))
	admissionProxy.OnLog = serverRoleLog
	admissionCtx, admissionCancel := context.WithCancel(context.Background())
	go admissionProxy.Serve(admissionCtx)

	serverRoleMu.Lock()
	serverRoleListen = listenPort
	serverRoleInternal = internalPort
	serverRoleAdmission = admissionProxy
	serverRoleAdmissionCancel = admissionCancel
	serverRoleMu.Unlock()

	// Relay-fallback — опционален, только если вызывающая сторона задала адрес (докс §1, §5).
	// Старое (если было) уже полностью погашено выше — здесь всегда свежее подключение.
	if relayAddr != "" {
		exitID, relayToken, credErr := relay.EnsureExitCredentials(serverRelayCredentialsPath())
		if credErr != nil {
			serverRoleLog(fmt.Sprintf("роль «Выход»: relay-fallback не поднят (учётные данные): %v", credErr))
		} else if relayFingerprint == "" {
			serverRoleLog("роль «Выход»: relay-fallback не поднят — не задан отпечаток TLS-сертификата relay (relayFingerprint)")
		} else {
			exitClient := relay.NewExitClient(relayAddr, exitID, relayToken,
				fmt.Sprintf("127.0.0.1:%d", listenPort), relayFingerprint)
			exitClient.OnLog = serverRoleLog
			exitCtx, exitCancel := context.WithCancel(context.Background())
			serverRoleMu.Lock()
			serverRoleExit = exitClient
			serverRoleExitCancel = exitCancel
			serverRoleExitAddr = relayAddr
			serverRoleExitFingerprint = relayFingerprint
			serverRoleMu.Unlock()
			go exitClient.Run(exitCtx)
			serverRoleLog(fmt.Sprintf("роль «Выход»: relay-fallback на %s (exit-id %s)", relayAddr, exitID))
		}
	}

	serverRoleLog(fmt.Sprintf("роль «Выход»: слушаю порт %d (лимит подключений: %d)", listenPort, maxClients))
	return ""
}

// reconcileServerRoleExit синхронизирует serverRoleExit с relayAddr/relayFingerprint на пути
// hot-reload без пересоздания публичного порта (StartServerRole выше) — пересоздаёт
// ExitClient, ТОЛЬКО если relay-настройки реально изменились (включили/выключили/сменили
// адрес или отпечаток), не гасит уже установленный рабочий control-канал просто потому, что
// вызывающая сторона поменяла, например, maxClients.
func reconcileServerRoleExit(listenPort int, relayAddr, relayFingerprint string) {
	serverRoleMu.Lock()
	currentAddr := serverRoleExitAddr
	currentFingerprint := serverRoleExitFingerprint
	prevExitCancel := serverRoleExitCancel
	serverRoleMu.Unlock()

	if relayAddr == currentAddr && relayFingerprint == currentFingerprint {
		return
	}

	if prevExitCancel != nil {
		prevExitCancel()
	}
	serverRoleMu.Lock()
	serverRoleExit = nil
	serverRoleExitCancel = nil
	serverRoleExitAddr = ""
	serverRoleExitFingerprint = ""
	serverRoleMu.Unlock()

	if relayAddr == "" {
		return
	}
	if relayFingerprint == "" {
		serverRoleLog("роль «Выход»: relay-fallback не поднят — не задан отпечаток TLS-сертификата relay (relayFingerprint)")
		return
	}

	exitID, relayToken, credErr := relay.EnsureExitCredentials(serverRelayCredentialsPath())
	if credErr != nil {
		serverRoleLog(fmt.Sprintf("роль «Выход»: relay-fallback не поднят (учётные данные): %v", credErr))
		return
	}
	exitClient := relay.NewExitClient(relayAddr, exitID, relayToken, fmt.Sprintf("127.0.0.1:%d", listenPort), relayFingerprint)
	exitClient.OnLog = serverRoleLog
	exitCtx, exitCancel := context.WithCancel(context.Background())
	serverRoleMu.Lock()
	serverRoleExit = exitClient
	serverRoleExitCancel = exitCancel
	serverRoleExitAddr = relayAddr
	serverRoleExitFingerprint = relayFingerprint
	serverRoleMu.Unlock()
	go exitClient.Run(exitCtx)
	serverRoleLog(fmt.Sprintf("роль «Выход»: relay-fallback на %s (exit-id %s)", relayAddr, exitID))
}

// teardownServerRoleAdmissionAndExit гасит AdmissionProxy/ExitClient и обнуляет связанные
// package-level переменные. НЕ трогает serverRoleRunner — вызывающая сторона решает сама,
// останавливать ли sing-box.
func teardownServerRoleAdmissionAndExit() {
	serverRoleMu.Lock()
	admissionCancel := serverRoleAdmissionCancel
	exitCancel := serverRoleExitCancel
	serverRoleAdmissionCancel = nil
	serverRoleExitCancel = nil
	serverRoleAdmission = nil
	serverRoleExit = nil
	serverRoleExitAddr = ""
	serverRoleExitFingerprint = ""
	serverRoleMu.Unlock()

	if exitCancel != nil {
		exitCancel()
	}
	if admissionCancel != nil {
		admissionCancel()
	}
}

// StopServerRole останавливает роль «Выход». Идемпотентен: не инициализированный или уже
// остановленный runner — не ошибка (тот же контракт, что у StopTun/Process.Stop).
func StopServerRole() string {
	serverRoleMu.Lock()
	runner := serverRoleRunner
	listenPort := serverRoleListen
	serverRoleMu.Unlock()

	// [консилиум, MEDIUM, находка №20, TZ_RELAY_HARDENING_2026-08-29.md кластер F] Тот же
	// best-effort unmap, что и Engine.StopServerRole на Windows — см. комментарий там.
	if listenPort > 0 {
		go func(port int) {
			ctx, cancel := context.WithTimeout(context.Background(), upnpUnmapTimeout)
			defer cancel()
			if err := relay.RemoveUPnPMapping(ctx, port); err != nil {
				serverRoleLog(fmt.Sprintf("роль «Выход»: снятие UPnP-проброса порта %d не удалось (%v) — "+
					"не критично, если он не использовался или роутер уже забыл его", port, err))
			}
		}(listenPort)
	}

	teardownServerRoleAdmissionAndExit()

	if runner == nil {
		return ""
	}
	if err := runner.Stop(); err != nil {
		return err.Error()
	}
	return ""
}

// IsServerRoleRunning отражает истинное состояние androidServerRunner, а не локальный
// флаг — не инициализированный runner честно false, не паника.
func IsServerRoleRunning() bool {
	serverRoleMu.Lock()
	runner := serverRoleRunner
	serverRoleMu.Unlock()
	return runner != nil && runner.IsRunning()
}

// GetLocalIPCandidatesJSON — кандидаты на Host для ссылки роли «Выход» (см.
// singbox.LocalIPCandidates: почему список, а не один «угаданный» адрес). Возвращает
// JSON-массив {"ip":"...","interface_name":"..."}; "[]", если ничего не нашли — НЕ "null":
// json.Marshal(nil-слайс) даёт буквально "null", а не валидный (пустой) JSON-массив, и
// JSONArray(...) на Kotlin-стороне падает на этой строке с исключением вместо пустого
// списка. Живой инцидент 2026-08-28: на реальном Android-устройстве net.Interfaces() внутри
// песочницы приложения (untrusted_app SELinux-контекст) не смог перечислить интерфейсы и
// вернул nil — Kotlin-сторона в итоге перешла на нативный java.net.NetworkInterface вместо
// этой функции (MainActivity.kt, localIpCandidates), но сама функция остаётся корректной
// для остальных вызывающих (CLI/тесты), поэтому фикс не убран, просто не критичен для UI.
func GetLocalIPCandidatesJSON() string {
	candidates := singbox.LocalIPCandidates()
	if candidates == nil {
		candidates = []singbox.LocalIPCandidate{}
	}
	data, _ := json.Marshal(candidates)
	return string(data)
}

// DetectReachabilityJSON — живой запрос пользователя 2026-08-28: «каждый должен определять
// свой IP», чтобы ссылка роли «Выход» работала между устройствами в РАЗНЫХ сетях/странах, не
// только в одной локальной сети (см. internal/relay). Пробует UPnP-проброс порта на роутере,
// затем STUN как запасной вариант определения вероятного внешнего IP.
//
// Android-оговорка про UPnP: SSDP-обнаружение (goupnp) шлёт UDP-мультикаст на
// 239.255.255.250:1900 — Android по умолчанию ГЛУШИТ входящий мультикаст на Wi-Fi-радио ради
// экономии батареи, если ни одно приложение не удерживает WifiManager.MulticastLock. Без
// лока со стороны Kotlin (см. MainActivity.kt) UPnP-часть этой функции может НИЧЕГО не
// найти даже при реально поддерживающем UPnP роутере — не баг этой функции, а платформенное
// ограничение, снимаемое только с Kotlin-стороны. STUN (обычный UDP unicast) этому
// ограничению не подвержен и должен работать независимо.
//
// Возвращает JSON {"method":int,"explanation":"...","external_host":"...","external_port":int,
// "has_address":bool} — то же поле "method", что и internal/relay.Method (0=Unknown
// 1=Direct 2=UPnP 3=ManualPort 4=Relay), или {"error":"..."} при отказе.
func DetectReachabilityJSON(port int) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	r := relay.NewReachability()
	method, err := r.Detect(ctx, port)
	if err != nil {
		data, _ := json.Marshal(map[string]string{"error": err.Error()})
		return string(data)
	}
	host, extPort, ok := r.ExternalAddress()
	data, _ := json.Marshal(map[string]interface{}{
		"method":        int(method),
		"explanation":   r.Explain(method),
		"external_host": host,
		"external_port": extPort,
		"has_address":   ok,
	})
	return string(data)
}

// GetServerRoleStatusJSON — снимок состояния роли «Выход» для UI. connected_clients_count
// (§5, docs/PLAN_2026-08-28_stubs_and_realfunc.md) — начиная с admission-control (докс
// TZ_APF_RELAY_v1.0.md §10.2) читается НАПРЯМУЮ из AdmissionProxy.Count() (локальный
// атомарный счётчик — тот же самый, который решает впустить/отклонить каждое подключение),
// без сетевого опроса ClashAPI — тот же контракт, что Engine.GetServerRoleStatus на Windows.
// relay_exit_connected — работает ли сейчас relay-fallback (поле отсутствует, если
// relayAddr не задавался последнему StartServerRole).
func GetServerRoleStatusJSON() string {
	serverRoleMu.Lock()
	running := serverRoleRunner != nil && serverRoleRunner.IsRunning()
	port := serverRoleListen
	admission := serverRoleAdmission
	exitClient := serverRoleExit
	serverRoleMu.Unlock()

	result := map[string]interface{}{
		"running":     running,
		"listen_port": port,
	}
	if running && admission != nil {
		result["connected_clients_count"] = admission.Count()
		if ip := admission.LastRemoteIP(); ip != "" {
			result["last_client_ip"] = ip
		}
	} else if running {
		result["connected_clients_count"] = -1
	}
	if exitClient != nil {
		// [консилиум, HIGH, находка №11, TZ_RELAY_HARDENING_2026-08-29.md кластер H]
		// IsConnected(), не IsRunning() — тот же контракт, что Engine.GetServerRoleStatus.
		result["relay_exit_connected"] = exitClient.IsConnected()
	}
	data, _ := json.Marshal(result)
	return string(data)
}

// decodeIdentity — общий разбор identityJSON для StartServerRole/BuildServerLinkJSON,
// с честной ошибкой на пустую строку (иначе json.Unmarshal("") тихо не заполнил бы ни
// одного поля, и вызывающая сторона получила бы ServerRunner с нулевым UUID вместо
// понятного отказа на этапе разбора).
func decodeIdentity(identityJSON string) (singbox.ServerIdentity, error) {
	if identityJSON == "" {
		return singbox.ServerIdentity{}, errIdentityRequired
	}
	var id singbox.ServerIdentity
	if err := json.Unmarshal([]byte(identityJSON), &id); err != nil {
		return singbox.ServerIdentity{}, err
	}
	return id, nil
}
