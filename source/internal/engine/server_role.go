package engine

// P2.3 (docs/TZ_APF_ROADMAP_v1.2.md): точка входа роли «Выход»/«Транзит» на Windows.
//
// internal/singbox/windows_server_runner.go был написан и покрыт тестами ещё на этапе
// Э-Выход-1 (docs/PLAN_APF_VHOD_VYHOD_v1.0.md), но не имел ни одной точки входа на Windows —
// в отличие от Android, где тот же слой (singbox.AndroidServerRunner) реально подключён через
// mobile/androidbridge/server_role.go. Этот файл — тот же контракт
// (GenerateIdentity/BuildLink/Start/Stop/IsRunning/Status), перенесённый на Engine.
//
// Проще Android-версии: у роли «Выход» на Windows нет TUN и нет чужого fd (windowsServerRunner
// оборачивает обычный дочерний процесс sing-box), поэтому не нужен ProtectCallback/platform
// adapter — см. комментарий в windows_server_runner.go.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/crypto"
	"github.com/apf/adaptive-pathfinder/internal/netutil"
	"github.com/apf/adaptive-pathfinder/internal/relay"
	"github.com/apf/adaptive-pathfinder/internal/singbox"
)

// upnpUnmapTimeout — [консилиум, MEDIUM, находка №20, TZ_RELAY_HARDENING_2026-08-29.md
// кластер F] бюджет на попытку снять UPnP-проброс при остановке роли — best-effort и всегда в
// фоне (см. StopServerRole): отсутствие UPnP-роутера/маппинга не должно ни на миг задерживать
// сам факт остановки роли, которую пользователь уже видит как мгновенное действие.
const upnpUnmapTimeout = 5 * time.Second

// defaultMaxConnectedClients — дефолты по роли устройства (docs/TZ_APF_RELAY_v1.0.md §10.1).
// ПК-обычный по умолчанию (5) — «выделенный сервер» (20) требует явного выбора пользователя
// в мастере настройки (ещё не реализован, см. PLAN_APF_RELAY_v1.0.md фаза G) и передаётся
// через AppConfig.MaxConnectedClients напрямую, минуя эту функцию.
const defaultMaxConnectedClientsWindows = 5

// admissionProxyFirewallRuleName — [найдено 2026-08-29, живой тест Redmi+ПК] отдельное
// правило файрвола от serverRoleFirewallRuleName (windows_server_runner.go): ТО правило
// разрешает sing-box.exe, но с admission-control (Фаза C/D) публичный порт слушает
// AdmissionProxy ВНУТРИ процесса APF (sing-box теперь только на 127.0.0.1, файрвол его не
// касается вовсе, см. BuildServerConfig) — свой рубеж нужен именно бинарнику APF, иначе
// ровно тот же класс дефекта, что закрывался для sing-box.exe 2026-08-25, просто на другом
// бинарнике: снаружи выглядело бы как REALITY-таймаут без единой зацепки, что порт вообще
// не открывается наружу.
const admissionProxyFirewallRuleName = "APF Server Role (admission proxy)"

// serverIdentityPath — файл сохранённого ключа звена. Android оставляет сохранение
// identity вызывающей стороне (Kotlin, EncryptedSharedPreferences) — на Windows у
// сохранённого файла нет аналогичного места на стороне GUI, поэтому Engine сохраняет сам:
// без этого перезапуск APF генерировал бы НОВЫЙ ключ при каждом Start и обесценивал бы уже
// выданные пользователем ссылки «Входу» (ТЗ §2: «у каждого звена свой НЕЗАВИСИМЫЙ, но
// СТАБИЛЬНЫЙ ключ»).
//
// S-5 (TZ_APF_v1.4_FINAL.md, лот L1b-SEC2). Раньше здесь стояло «не шифруется отдельно —
// это ключ серверной роли, которым в любом случае предстоит поделиться». Довод неверен:
// делятся ПУБЛИЧНОЙ частью (vless-ссылка содержит UUID и public key), а в файле лежит
// ПРИВАТНЫЙ ключ REALITY — им не делятся никогда. Мастер-пароль это место не покрывал даже
// когда был включён, а в headless-службе спросить пароль не у кого. Поэтому файл защищается
// прозрачно, через Windows DPAPI (config.WriteSecretFile/ReadSecretFile); на Android identity
// сохраняет Kotlin (EncryptedSharedPreferences), этот путь его не касается.
func serverIdentityPath() string {
	return filepath.Join(config.DataDir(), "server_identity.json")
}

// serverRelayCredentialsPath — exit-id + relay-token (docs/TZ_APF_RELAY_v1.0.md §2.1, §3),
// отдельный файл от identity: exit-id/relay-token намеренно НЕ производные от
// identity.UUID/PrivateKey (см. §3 — раньше exit-id совпадал с identity.UUID, что смешивало
// публичный маршрутный идентификатор с VLESS-секретом), поэтому и хранятся отдельно, хоть и
// рядом. relay-token — секрет: НИКОГДА не идёт в ссылку, не показывается «Входу».
func serverRelayCredentialsPath() string {
	return filepath.Join(config.DataDir(), "server_relay_credentials.json")
}

// ensureExitCredentials — «загрузить или создать» пару exit-id/relay-token для Windows
// (докс §2.1).
//
// S-5 (лот L1b-SEC2): раньше это была тонкая обёртка над relay.EnsureExitCredentials,
// писавшая relay-token открытым текстом. Логика та же (load-or-generate-and-save), но через
// защищённый слой config.WriteSecretFile/ReadSecretFile. Сам relay.EnsureExitCredentials
// НЕ трогается: по нему живёт Android (mobile/androidbridge/server_role.go), где секреты
// хранит Kotlin, и там менять поведение S-5 не требует.
func ensureExitCredentials() (exitID, relayToken string, err error) {
	path := serverRelayCredentialsPath()

	data, wasProtected, readErr := config.ReadSecretFile(path)
	switch {
	case readErr == nil:
		var creds relay.ExitCredentials
		if jsonErr := json.Unmarshal(data, &creds); jsonErr == nil && creds.ExitID != "" && creds.RelayToken != "" {
			if !wasProtected {
				// Миграция старого открытого файла: содержимое то же, на диск ложится
				// защищённым. Неудача миграции не повод не отдать рабочие креды.
				if _, migErr := config.EnsureSecretFileProtected(path); migErr != nil {
					config.MarkSecretsUnavailable(fmt.Sprintf(
						"не удалось защитить %s при миграции: %v", filepath.Base(path), migErr))
				}
			}
			return creds.ExitID, creds.RelayToken, nil
		}
		// Файл прочитан, но пуст/битый по содержимому — прежнее поведение: молча пересоздать.
	case os.IsNotExist(readErr):
		// Обычный первый запуск.
	default:
		// Ветка «не смог расшифровать» (В-2): файл есть, но не читается на этой машине.
		// Не падаем и не удаляем — уводим в .bak и заводим новую пару, громко.
		quarantineUnreadableSecret(path, readErr, "relay-token роли «Выход»")
	}

	exitID, relayToken, err = relay.GenerateExitCredentials()
	if err != nil {
		return "", "", fmt.Errorf("ensureExitCredentials: %w", err)
	}
	out, err := json.MarshalIndent(relay.ExitCredentials{ExitID: exitID, RelayToken: relayToken}, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("ensureExitCredentials: сериализация: %w", err)
	}
	if err := config.WriteSecretFile(path, out); err != nil {
		return "", "", fmt.Errorf("ensureExitCredentials: сохранение: %w", err)
	}
	return exitID, relayToken, nil
}

// quarantineUnreadableSecret — общая ветка «не смог расшифровать» для обоих секретных файлов
// роли «Выход» (В-2, обязательное условие решения владельца): исходный файл уводится в .bak,
// человеку остаётся видимое предупреждение (Engine.SecretsWarning), вызывающая сторона
// пересоздаёт секрет. Ни потери данных, ни тихого падения.
func quarantineUnreadableSecret(path string, cause error, what string) {
	bak, bakErr := config.QuarantineSecretFile(path)
	if bakErr != nil {
		config.MarkSecretsUnavailable(fmt.Sprintf(
			"%s не читается на этой машине (%v), и убрать файл %s в сторону не удалось: %v — пересоздание невозможно",
			what, cause, filepath.Base(path), bakErr))
		return
	}
	config.MarkSecretsUnavailable(fmt.Sprintf(
		"%s не читается на этой машине (%v). Старый файл сохранён как %s, создан новый — ранее выданные ссылки и подключения к этому звену перестанут работать",
		what, cause, filepath.Base(bak)))
}

// SecretsWarning — видимое человеку предупреждение о том, что часть секретов на диске не
// расшифровывается (перенос профиля на другую машину, пересозданная учётная запись).
// Пустая строка и false — всё в порядке.
//
// Отдельный метод, а не поле статуса: engine.go в этом лоте не правится (владеют другие
// лоты), поэтому вставка в Status оставлена как явная заявка в open_questions лота L1b-SEC2.
func (e *Engine) SecretsWarning() (string, bool) {
	unavailable, reason := config.SecretsState()
	return reason, unavailable
}

// GenerateServerRoleIdentity создаёт НОВЫЙ независимый ключ звена (ТЗ §2 Вход/Выход: «у
// каждого звена цепочки свой независимый ключ») и сохраняет его в serverIdentityPath —
// повторный вызов заменяет ключ (все ранее выданные пользователем ссылки перестанут
// работать, вызывающая сторона в UI должна явно предупредить об этом перед вызовом, это не
// то же самое, что LoadServerRoleIdentity).
func (e *Engine) GenerateServerRoleIdentity() (singbox.ServerIdentity, error) {
	id, err := singbox.GenerateServerIdentity()
	if err != nil {
		return id, err
	}
	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return id, fmt.Errorf("GenerateServerRoleIdentity: сериализация: %w", err)
	}
	if err := os.MkdirAll(config.DataDir(), 0700); err != nil {
		return id, fmt.Errorf("GenerateServerRoleIdentity: каталог данных: %w", err)
	}
	// S-5: приватный ключ REALITY уходит на диск защищённым (DPAPI). При отказе защиты файл
	// НЕ пишется открытым текстом — ошибка идёт наверх.
	if err := config.WriteSecretFile(serverIdentityPath(), data); err != nil {
		return id, fmt.Errorf("GenerateServerRoleIdentity: сохранение: %w", err)
	}
	// Предупреждение SecretsWarning здесь НЕ сбрасывается намеренно: слот один на все секреты,
	// а причина могла прийти от config.json — пересоздание ключа звена её не лечит. Снимать
	// предупреждение должен тот, кто его показал пользователю (config.ClearSecretsState).
	return id, nil
}

// LoadServerRoleIdentity читает ранее сохранённый ключ звена. found=false, err=nil — ключ
// ещё не сгенерирован (обычный случай до первого GenerateServerRoleIdentity), не ошибка —
// тот же контракт, что у config.LoadInto.
// S-5 (лот L1b-SEC2) добавляет сюда две ветки, обе — без потери данных:
//   - старый ОТКРЫТЫЙ файл читается как раньше и тут же переписывается защищённым (миграция);
//   - защищённый файл, который на этой машине не расшифровывается (перенесли профиль, сменили
//     учётку), уводится в .bak, выставляется Engine.SecretsWarning и возвращается
//     found=false — то есть ключ будет пересоздан вызывающей стороной, как того требует
//     обязательное условие решения В-2. Тупика «есть файл, но им нельзя пользоваться и его
//     нельзя заменить» не остаётся.
func (e *Engine) LoadServerRoleIdentity() (id singbox.ServerIdentity, found bool, err error) {
	path := serverIdentityPath()
	data, wasProtected, readErr := config.ReadSecretFile(path)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return id, false, nil
		}
		if errors.Is(readErr, crypto.ErrSecretUnreadable) {
			quarantineUnreadableSecret(path, readErr, "ключ звена «Выход» (server_identity.json)")
			return id, false, nil
		}
		return id, false, readErr
	}
	if err := json.Unmarshal(data, &id); err != nil {
		return id, false, fmt.Errorf("LoadServerRoleIdentity: разбор: %w", err)
	}
	if !wasProtected {
		if _, migErr := config.EnsureSecretFileProtected(path); migErr != nil {
			config.MarkSecretsUnavailable(fmt.Sprintf(
				"не удалось защитить %s при миграции: %v", filepath.Base(path), migErr))
		}
	}
	return id, true, nil
}

// BuildServerRoleLink собирает готовую vless://-ссылку для передачи «Входу» (ТЗ §5.2,
// «Готово — вот ваша ссылка»). host — куда «Вход» будет физически подключаться, вводится
// пользователем вручную (до Э-Выход-4, реальной автоматической Reachability.Detect).
// realityDest пустая строка ⇒ singbox.GoodRealitySNI[0]. relayAddr пустая строка ⇒ обычная
// прямая ссылка (прежнее поведение, БЕЗ ИЗМЕНЕНИЙ); непустая ⇒ relay-формат
// (docs/TZ_APF_RELAY_v1.0.md §3) — host в этом случае игнорируется, вместо него в ссылку
// идёт адрес relay-сервера, и генерируются/переиспользуются exit-id+relay-token
// (ensureExitCredentials). relayFingerprint — отпечаток TLS-сертификата relay-сервера
// (TZ_RELAY_HARDENING_2026-08-29.md кластер B) — обязателен вместе с непустым relayAddr,
// иначе партнёр («Вход») получит ссылку, по которой EntryBridge гарантированно откажет
// (fail-closed без отпечатка, см. internal/relay/tunnel_tls.go).
func (e *Engine) BuildServerRoleLink(id singbox.ServerIdentity, host string, listenPort int, realityDest, label, relayAddr, relayFingerprint string) (string, error) {
	if realityDest == "" {
		realityDest = singbox.GoodRealitySNI[0]
	}
	if relayAddr == "" {
		return singbox.BuildServerLink(id, host, listenPort, realityDest, label), nil
	}
	relayHost, relayPort, err := net.SplitHostPort(relayAddr)
	if err != nil {
		return "", fmt.Errorf("BuildServerRoleLink: адрес relay %q: %w", relayAddr, err)
	}
	port, err := strconv.Atoi(relayPort)
	if err != nil {
		return "", fmt.Errorf("BuildServerRoleLink: порт relay %q: %w", relayPort, err)
	}
	if relayFingerprint == "" {
		return "", fmt.Errorf("BuildServerRoleLink: не задан отпечаток TLS-сертификата relay (relayFingerprint) — обязателен для relay-режима")
	}
	exitID, _, err := ensureExitCredentials()
	if err != nil {
		return "", fmt.Errorf("BuildServerRoleLink: %w", err)
	}
	return singbox.BuildServerRelayLink(id, relayHost, port, exitID, relayFingerprint, realityDest, label), nil
}

// StartServerRole поднимает роль «Выход»/«Транзит» на listenPort с ранее сгенерированной
// identity (см. GenerateServerRoleIdentity). runner создаётся один раз и переживает
// последующие вызовы. realityDest пустая строка ⇒ singbox.GoodRealitySNI[0].
//
// [консилиум, CRITICAL×2, docs/TZ_APF_RELAY_v1.0.md §10.2] Публичный listenPort (тот, что в
// ссылке) слушает НЕ сам sing-box, а AdmissionProxy — лимит подключений (§10) действует
// одинаково для прямых подключений и для relay-пути (ExitClient дозванивается сюда же, не в
// обход). sing-box слушает отдельный эфемерный внутренний порт (netutil.ReserveFreePort) —
// никакой арифметики со сдвигом порта, никакого риска переполнения диапазона/рассинхрона с
// ServerClashAPIPort.
//
// [консилиум 2026-08-29, CRITICAL, находки №1/№23, TZ_RELAY_HARDENING_2026-08-29.md кластер A]
// Повторный вызов на уже работающей роли (пользователь поменял maxClients/realityDest/
// relay-адрес и снова нажал «Запустить») — ГОРЯЧАЯ ПЕРЕЗАГРУЗКА, не второй независимый запуск.
// Раньше AdmissionProxy/ExitClient гасились БЕЗУСЛОВНО до попытки нового старта — при отказе
// (а на Windows Process.Start ВСЕГДА отказывает "already running", если старый sing-box не
// остановлен явно — перезапуск себя на лету он не умеет) роль оставалась полностью
// недостижимой, а IsServerRoleRunning()/GetServerRoleStatus() продолжали врать "работает" на
// старых объектах. Теперь порядок: (1) WriteConfig нового конфига — файл, никак не влияет на
// уже работающий процесс; (2) если роль уже работала — Stop() старого sing-box НЕПОСРЕДСТВЕННО
// перед Start() нового (единственный способ на Windows избежать "already running" — дочерний
// процесс, не in-process инстанс, полноценный zero-downtime blue-green с двумя параллельными
// sing-box.exe оставлен задокументированным stretch-goal, не реализован в этом проходе — см.
// текст ТЗ); (3) если новый Start отказал — старое admission/exit гасится ЯВНО и честно
// (не остаётся врать), но НЕ восстанавливается автоматически — пользователь получает понятную
// ошибку и настройки на диске не тронуты, может попробовать снова; (4) если новый Start
// удался И публичный порт НЕ менялся — публичный listener НИКОГДА не пересоздаётся, меняется
// только внутренняя цель AdmissionProxy (Retarget) — уже подключённые «Входы» не видят на этом
// шаге ни одного мгновения разрыва (единственный реальный разрыв — на шаге (2), время
// перезапуска sing-box-процесса, обычно порядка десятков мс).
func (e *Engine) StartServerRole(listenPort int, realityDest string, id singbox.ServerIdentity) error {
	if realityDest == "" {
		realityDest = singbox.GoodRealitySNI[0]
	}

	internalPort, err := netutil.ReserveFreePort()
	if err != nil {
		return fmt.Errorf("StartServerRole: резервирование внутреннего порта: %w", err)
	}

	e.serverRoleMu.Lock()
	runner := e.serverRoleRunner
	admission := e.serverRoleAdmission
	prevListenPort := e.serverRoleListen
	e.serverRoleMu.Unlock()

	wasRunning := runner != nil && runner.IsRunning()
	if runner == nil {
		runner = singbox.NewWindowsServerRunner(config.BinDir(), config.DataDir())
	}

	doc := singbox.BuildServerConfig(id, internalPort, realityDest)
	if err := runner.WriteConfig(doc); err != nil {
		return fmt.Errorf("StartServerRole: %w", err)
	}

	if wasRunning {
		if stopErr := runner.Stop(); stopErr != nil {
			e.log(fmt.Sprintf("Роль «Выход»: не удалось штатно остановить предыдущий sing-box перед перезапуском (%v) — пробую запустить новый поверх", stopErr))
		}
	}

	if err := runner.Start(context.Background()); err != nil {
		if wasRunning {
			e.teardownServerRoleAdmissionAndExit()
			e.log("Роль «Выход»: перезапуск с новой конфигурацией не удался, роль остановлена — прежние настройки автоматически не восстанавливаются")
		}
		return fmt.Errorf("StartServerRole: %w", err)
	}

	e.serverRoleMu.Lock()
	e.serverRoleRunner = runner
	e.serverRoleMu.Unlock()

	maxClients := e.cfg.MaxConnectedClients
	if maxClients <= 0 {
		maxClients = defaultMaxConnectedClientsWindows
	}

	if wasRunning && admission != nil && listenPort == prevListenPort {
		admission.Retarget(fmt.Sprintf("127.0.0.1:%d", internalPort), singbox.ServerClashAPIPort(internalPort))
		admission.SetMaxClients(maxClients)

		e.serverRoleMu.Lock()
		e.serverRoleInternal = internalPort
		e.serverRoleMu.Unlock()

		e.reconcileServerRoleExit(listenPort)
		e.log(fmt.Sprintf("Роль «Выход»: конфигурация обновлена без разрыва публичного порта %d (лимит устройств: %d)", listenPort, maxClients))
		return nil
	}

	// Первый запуск, либо публичный порт реально меняется по воле пользователя — старое
	// (если было) гасится ТОЛЬКО теперь, когда новый sing-box уже подтверждённо поднят:
	// ни один отказ выше по этой функции не тронул старое рабочее состояние.
	if wasRunning {
		e.teardownServerRoleAdmissionAndExit()
	}

	publicLn, err := net.Listen("tcp", fmt.Sprintf(":%d", listenPort))
	if err != nil {
		runner.Stop()
		return fmt.Errorf("StartServerRole: публичный порт %d занят: %w", listenPort, err)
	}

	// Файрвол-разрешение для САМОГО процесса APF (см. комментарий у
	// admissionProxyFirewallRuleName) — best-effort, тот же контракт, что у
	// windowsServerRunner.Start для sing-box.exe: служба APF уже работает от SYSTEM, netsh
	// не требует лишней элевации; при явном запуске без повышения (или на не-Windows) просто
	// не сработает — не блокируем публичный листенер из-за этого, только логируем.
	if exePath, exeErr := os.Executable(); exeErr == nil {
		if fwErr := singbox.EnsureInboundFirewallRule(admissionProxyFirewallRuleName, exePath, listenPort); fwErr != nil {
			e.log(fmt.Sprintf("Роль «Выход»: не удалось завести правило файрвола (%v) — "+
				"«Вход» из другой сети может не достучаться, пока правило не добавлено вручную", fwErr))
		}
	}

	admissionProxy := singbox.NewAdmissionProxy(publicLn, fmt.Sprintf("127.0.0.1:%d", internalPort),
		maxClients, singbox.ServerClashAPIPort(internalPort))
	admissionProxy.OnLog = e.log
	admissionCtx, admissionCancel := context.WithCancel(context.Background())
	e.goTracked(func() { admissionProxy.Serve(admissionCtx) })

	e.serverRoleMu.Lock()
	e.serverRoleListen = listenPort
	e.serverRoleInternal = internalPort
	e.serverRoleAdmission = admissionProxy
	e.serverRoleAdmissionCancel = admissionCancel
	e.serverRoleMu.Unlock()

	// Relay-fallback — опционален, только если пользователь задал адрес (докс §1, §5). Старый
	// (если был) уже полностью погашен выше (teardownServerRoleAdmissionAndExit) — здесь всегда
	// свежее подключение, не нужна сверка "изменился ли адрес" (та нужна только в ветке
	// hot-reload-без-пересоздания-порта выше, см. reconcileServerRoleExit).
	if e.cfg.RelayServerAddr != "" {
		exitID, relayToken, credErr := ensureExitCredentials()
		if credErr != nil {
			e.log(fmt.Sprintf("Роль «Выход»: relay-fallback не поднят (учётные данные): %v", credErr))
		} else {
			exitClient := relay.NewExitClient(e.cfg.RelayServerAddr, exitID, relayToken,
				fmt.Sprintf("127.0.0.1:%d", listenPort), e.cfg.RelayServerFingerprint)
			exitClient.OnLog = e.log
			// Relay-путь идёт через тот же лимит УСТРОЙСТВ, что и прямой (ТЗ §10.2), и получает от
			// посредника адрес настоящего «Входа» — иначе все они выглядели бы как 127.0.0.1.
			exitClient.DialLocal = admissionProxy.AdmitAndDial
			exitCtx, exitCancel := context.WithCancel(context.Background())
			e.serverRoleMu.Lock()
			e.serverRoleExit = exitClient
			e.serverRoleExitCancel = exitCancel
			e.serverRoleExitAddr = e.cfg.RelayServerAddr
			e.serverRoleExitFingerprint = e.cfg.RelayServerFingerprint
			e.serverRoleMu.Unlock()
			e.goTracked(func() { exitClient.Run(exitCtx) })
			e.log(fmt.Sprintf("Роль «Выход»: relay-fallback на %s (exit-id %s)", e.cfg.RelayServerAddr, exitID))
		}
	}

	e.log(fmt.Sprintf("Роль «Выход»: слушаю порт %d (лимит устройств: %d)", listenPort, maxClients))
	return nil
}

// reconcileServerRoleExit синхронизирует serverRoleExit с текущим e.cfg.RelayServerAddr на
// пути hot-reload без пересоздания публичного порта (StartServerRole выше) — пересоздаёт
// ExitClient, ТОЛЬКО если relay-адрес реально изменился (включили/выключили/сменили), не
// гасит уже установленный рабочий control-канал просто потому, что пользователь поменял,
// например, maxClients или realityDest.
func (e *Engine) reconcileServerRoleExit(listenPort int) {
	e.serverRoleMu.Lock()
	currentAddr := e.serverRoleExitAddr
	currentFingerprint := e.serverRoleExitFingerprint
	prevExitCancel := e.serverRoleExitCancel
	admission := e.serverRoleAdmission
	e.serverRoleMu.Unlock()

	wantAddr := e.cfg.RelayServerAddr
	wantFingerprint := e.cfg.RelayServerFingerprint
	if wantAddr == currentAddr && wantFingerprint == currentFingerprint {
		return
	}

	if prevExitCancel != nil {
		prevExitCancel()
	}
	e.serverRoleMu.Lock()
	e.serverRoleExit = nil
	e.serverRoleExitCancel = nil
	e.serverRoleExitAddr = ""
	e.serverRoleExitFingerprint = ""
	e.serverRoleMu.Unlock()

	if wantAddr == "" {
		return
	}

	exitID, relayToken, credErr := ensureExitCredentials()
	if credErr != nil {
		e.log(fmt.Sprintf("Роль «Выход»: relay-fallback не поднят (учётные данные): %v", credErr))
		return
	}
	exitClient := relay.NewExitClient(wantAddr, exitID, relayToken, fmt.Sprintf("127.0.0.1:%d", listenPort), wantFingerprint)
	exitClient.OnLog = e.log
	if admission != nil {
		exitClient.DialLocal = admission.AdmitAndDial // см. StartServerRole: лимит устройств и адрес «Входа»
	}
	exitCtx, exitCancel := context.WithCancel(context.Background())
	e.serverRoleMu.Lock()
	e.serverRoleExit = exitClient
	e.serverRoleExitCancel = exitCancel
	e.serverRoleExitAddr = wantAddr
	e.serverRoleExitFingerprint = wantFingerprint
	e.serverRoleMu.Unlock()
	e.goTracked(func() { exitClient.Run(exitCtx) })
	e.log(fmt.Sprintf("Роль «Выход»: relay-fallback на %s (exit-id %s)", wantAddr, exitID))
}

// teardownServerRoleAdmissionAndExit гасит AdmissionProxy/ExitClient, снимает файрвол-правило
// процесса APF и обнуляет связанные поля. НЕ трогает serverRoleRunner — вызывающая сторона
// решает сама, останавливать ли sing-box (StopServerRole — да; неудачный hot-reload в
// StartServerRole — sing-box уже остановлен отдельным путём до вызова этой функции).
func (e *Engine) teardownServerRoleAdmissionAndExit() {
	e.serverRoleMu.Lock()
	admissionCancel := e.serverRoleAdmissionCancel
	exitCancel := e.serverRoleExitCancel
	e.serverRoleAdmissionCancel = nil
	e.serverRoleExitCancel = nil
	e.serverRoleAdmission = nil
	e.serverRoleExit = nil
	e.serverRoleExitAddr = ""
	e.serverRoleExitFingerprint = ""
	e.serverRoleMu.Unlock()

	if exitCancel != nil {
		exitCancel()
	}
	if admissionCancel != nil {
		admissionCancel()
	}
	singbox.RemoveInboundFirewallRule(admissionProxyFirewallRuleName)
}

// StopServerRole останавливает роль «Выход». Идемпотентен: ни разу не запущенная или уже
// остановленная роль — не ошибка (тот же контракт, что у Process.Stop/Android StopServerRole).
func (e *Engine) StopServerRole() error {
	e.serverRoleMu.Lock()
	runner := e.serverRoleRunner
	listenPort := e.serverRoleListen
	e.serverRoleMu.Unlock()

	// [консилиум, MEDIUM, находка №20, TZ_RELAY_HARDENING_2026-08-29.md кластер F] Best-effort
	// снятие UPnP-проброса — StopServerRole не хранит, использовался ли UPnP для этого запуска
	// (дешевле безусловно попробовать снять, чем нести это состояние через весь жизненный цикл
	// роли), поэтому пробуем всегда, в фоне, с коротким бюджетом — отсутствие UPnP-роутера или
	// самого маппинга просто вернёт ошибку, которую логируем и игнорируем.
	if listenPort > 0 {
		go func(port int) {
			ctx, cancel := context.WithTimeout(context.Background(), upnpUnmapTimeout)
			defer cancel()
			if err := relay.RemoveUPnPMapping(ctx, port); err != nil {
				e.log(fmt.Sprintf("Роль «Выход»: снятие UPnP-проброса порта %d не удалось (%v) — "+
					"не критично, если он не использовался или роутер уже забыл его", port, err))
			}
		}(listenPort)
	}

	e.teardownServerRoleAdmissionAndExit()

	if runner == nil {
		return nil
	}
	if err := runner.Stop(); err != nil {
		return err
	}
	e.log("Роль «Выход»: остановлена")
	return nil
}

// IsServerRoleRunning отражает истинное состояние процесса sing-box роли «Выход», а не
// отдельный локальный флаг — ни разу не созданный runner честно false, не паника.
func (e *Engine) IsServerRoleRunning() bool {
	e.serverRoleMu.Lock()
	defer e.serverRoleMu.Unlock()
	return e.serverRoleRunner != nil && e.serverRoleRunner.IsRunning()
}

// GetServerRoleStatus — снимок состояния роли «Выход» для UI. connected_clients_count
// (§5, docs/PLAN_2026-08-28_stubs_and_realfunc.md) — начиная с admission-control (докс
// TZ_APF_RELAY_v1.0.md §10.2) читается НАПРЯМУЮ из AdmissionProxy.Count() (локальный
// атомарный счётчик — тот же самый, который решает впустить/отклонить каждое подключение),
// а не через сетевой опрос ClashAPI: всегда точное число, без сетевого round-trip и без
// прежнего "-1 = не удалось узнать" — сама причина той неопределённости (clash-api мог быть
// ещё не поднят / порт мог разойтись с реальным) была именно в сетевом опросе, которого
// больше нет на этом пути. relayExitConnected — работает ли сейчас relay-fallback (пусто,
// если e.cfg.RelayServerAddr не задан).
func (e *Engine) GetServerRoleStatus() map[string]interface{} {
	e.serverRoleMu.Lock()
	running := e.serverRoleRunner != nil && e.serverRoleRunner.IsRunning()
	port := e.serverRoleListen
	admission := e.serverRoleAdmission
	exitClient := e.serverRoleExit
	e.serverRoleMu.Unlock()

	result := map[string]interface{}{"running": running, "listen_port": port}
	if running && admission != nil {
		result["connected_clients_count"] = admission.Count() // УСТРОЙСТВА (у кого есть открытое соединение)
		result["connections_count"] = admission.ConnCount()   // TCP-соединения — для диагностики
		if ip := admission.LastRemoteIP(); ip != "" {
			result["last_client_ip"] = ip
		}
	} else if running {
		result["connected_clients_count"] = -1
	}
	if exitClient != nil {
		// [консилиум, HIGH, находка №11, TZ_RELAY_HARDENING_2026-08-29.md кластер H]
		// IsConnected(), не IsRunning() — running остаётся true и во время backoff-паузы
		// между попытками переподключения, когда control-канала в этот момент физически нет;
		// пользователю нужен честный факт "подключён прямо сейчас", а не "горутина жива".
		result["relay_exit_connected"] = exitClient.IsConnected()
	}
	return result
}
