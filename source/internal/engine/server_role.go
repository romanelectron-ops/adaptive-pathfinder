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
	"sync"
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

// Швы для тестов: настоящий netsh меняет реальный файрвол Windows (StopServerRole снимает
// правило по имени — им же пользуется и работающая на машине роль «Выход»), а настоящий runner
// запускает sing-box.exe — недопустимо под `go test` (тот же приём, что execCommandFn в
// internal/singbox и discoverUPnPClientsFn в internal/relay). Раньше у StartServerRole/
// StopServerRole шва не было вовсе, поэтому у них не было ни одного теста (см. заголовок
// internal/web/server_scenarios_v3_test.go).
var (
	newServerRunnerFn = func() singbox.ServerRunner {
		return singbox.NewWindowsServerRunner(config.BinDir(), config.DataDir())
	}
	ensureInboundFirewallRuleFn = singbox.EnsureInboundFirewallRule
	removeInboundFirewallRuleFn = singbox.RemoveInboundFirewallRule
)

// ErrServerRoleStarting — повторный StartServerRole, пока предыдущий запуск ещё не вернулся.
//
// Ревью 1.1.10 (compat F5). Запуск роли теперь законно длится до serverRoleReadyTimeout (120 с,
// живой случай 2026-09-29: процессор занят на 100%, порт sing-box открывается от 3 до 48 с), а
// runner публикуется в e.serverRoleRunner только ПОСЛЕ возврата Start. За это окно StopServerRole
// не видел ни runner, ни запуск и тихо возвращал nil («остановлено», а sing-box через минуту всё
// равно поднимался), второй StartServerRole видел runner==nil и создавал ВТОРОЙ runner поверх
// того же server_current.json и порта. Одиночный запуск (single-flight) закрывает оба хода;
// вызывающая сторона может отличить этот отказ через errors.Is.
var ErrServerRoleStarting = errors.New("запуск роли «Выход» уже выполняется")

// serverRoleStartCancelWait — сколько StopServerRole ждёт, пока прерванный запуск реально
// вернётся. Отмена контекста доходит до awaitReady за один тик опроса порта (~150 мс), но
// создание процесса ОС бывает медленным (замеры на загруженной машине — десятки секунд) и отмену
// не слушает; вечно держать вызывающего (HTTP-обработчик остановки) из-за этого нельзя. По
// истечении срока Stop идёт дальше: запуск уже отменён и сам уберёт за собой, когда вернётся
// (см. проверку контекста после runner.Start в StartServerRole). var — чтобы тест не ждал секунды.
var serverRoleStartCancelWait = 15 * time.Second

// listenPublicFn — шов публичного listener'а роли. В тестах подменяется на 127.0.0.1:0: go test
// не должен открывать порт на всех интерфейсах (Windows покажет владельцу запрос брандмауэра
// для каждого нового тестового exe).
var listenPublicFn = func(port int) (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf(":%d", port))
}

// serverRoleStart — состояние ОДНОГО выполняющегося StartServerRole: cancel прерывает ожидание
// порта в runner.Start, done закрывается, когда StartServerRole вернулся (после этого и
// runner, и firewall-правила уже убраны за неудачным запуском).
type serverRoleStart struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// Состояние single-flight лежит отдельно от serverRoleMu: замок serverRoleMu защищает поля роли
// и берётся коротко, а запуск идёт минуты — держать его на время runner.Start нельзя (Stop и
// опрос статуса встали бы намертво). serverRoleStartMu защищает только эту карту и НЕ берётся
// вокруг runner.Start / IsRunning. Карта, а не поля Engine: запись существует только на время
// запуска (begin добавляет, finish удаляет), утечки записей между запусками нет.
var (
	serverRoleStartMu sync.Mutex
	serverRoleStarts  = map[*Engine]*serverRoleStart{}
	// serverRoleRunCancels — отмена контекста, ПОД КОТОРЫМ живёт уже запущенный sing-box роли.
	// Process.Start создаёт процесс через exec.CommandContext(ctx, …): отмена контекста убивает
	// дочерний процесс. Поэтому у УСПЕШНОГО запуска контекст нельзя отменять — он должен жить,
	// пока живёт роль (ревью 2026-09-30 поймало это в первой версии single-flight: defer
	// отменял контекст при любом возврате, и каждый успешный «Запустить» убивал свежий sing-box).
	// Отмена хранится здесь и вызывается только когда роль остановлена (StopServerRole) либо
	// следующим успешным запуском, у которого прежний процесс уже остановлен.
	serverRoleRunCancels = map[*Engine]context.CancelFunc{}
)

// beginServerRoleStart занимает единственный слот запуска. Если слот занят — ErrServerRoleStarting.
// Возвращает контекст запуска (его отменяет StopServerRole) и finish, который обязан быть вызван
// ровно один раз после окончания запуска. Контекст — от Background, а не от
// e.currentCtx(): у роли «Выход» жизненный цикл независим от клиентского Connect/Disconnect
// (см. поля serverRole* в Engine), Engine.Stop не должен прерывать её запуск.
//
// finish(ok): при неудаче (ok=false) контекст отменяется сразу; при успехе (ok=true) контекст
// НЕ отменяется — он привязан к времени жизни запущенного sing-box (см. serverRoleRunCancels).
func (e *Engine) beginServerRoleStart() (context.Context, func(ok bool), error) {
	serverRoleStartMu.Lock()
	defer serverRoleStartMu.Unlock()
	if _, busy := serverRoleStarts[e]; busy {
		return nil, nil, fmt.Errorf("StartServerRole: %w — дождитесь его окончания или остановите роль", ErrServerRoleStarting)
	}
	ctx, cancel := context.WithCancel(context.Background())
	st := &serverRoleStart{cancel: cancel, done: make(chan struct{})}
	serverRoleStarts[e] = st
	return ctx, func(ok bool) {
		// Слот освобождается ДО закрытия done: тот, кто дождался done (StopServerRole), обязан
		// сразу же мочь запустить роль заново.
		serverRoleStartMu.Lock()
		delete(serverRoleStarts, e)
		var prev context.CancelFunc
		if ok {
			prev = serverRoleRunCancels[e]
			serverRoleRunCancels[e] = cancel
		}
		serverRoleStartMu.Unlock()
		if ok {
			// Контекст предыдущего успешного запуска: его sing-box к этому моменту уже остановлен
			// (перезапуск идёт через runner.Stop до нового Start), отмена безвредна и освобождает ресурсы.
			if prev != nil {
				prev()
			}
		} else {
			cancel()
		}
		close(st.done)
	}, nil
}

// releaseServerRoleRunCtx отменяет контекст запущенного sing-box роли — вызывается ПОСЛЕ
// runner.Stop() в StopServerRole (процесс уже остановлен, отмена лишь освобождает ресурсы).
func (e *Engine) releaseServerRoleRunCtx() {
	serverRoleStartMu.Lock()
	cancel := serverRoleRunCancels[e]
	delete(serverRoleRunCancels, e)
	serverRoleStartMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// abortServerRoleStart прерывает выполняющийся StartServerRole (если он есть) и ждёт, пока он
// вернётся, но не дольше serverRoleStartCancelWait. Нет запуска — ничего не делает.
func (e *Engine) abortServerRoleStart() {
	serverRoleStartMu.Lock()
	st := serverRoleStarts[e]
	serverRoleStartMu.Unlock()
	if st == nil {
		return
	}
	st.cancel()
	e.log("Роль «Выход»: остановка во время запуска — запуск sing-box прерван, жду его возврата")
	timer := time.NewTimer(serverRoleStartCancelWait)
	defer timer.Stop()
	select {
	case <-st.done:
	case <-timer.C:
		e.log(fmt.Sprintf("Роль «Выход»: запуск не вернулся за %s после отмены (процесс ещё создаётся ОС) — "+
			"он уберёт за собой сам, как только вернётся", serverRoleStartCancelWait))
	}
}

// serverRoleStartCancelled — единая ошибка «запуск прерван остановкой роли»: отличима от
// настоящего отказа запуска (пользователь сам нажал «Остановить», пугать его ошибкой не надо).
func serverRoleStartCancelled(cause error) error {
	return fmt.Errorf("StartServerRole: запуск отменён — роль «Выход» остановлена во время запуска: %w", cause)
}

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
//
// [ревью 1.1.10, compat F5] Запуск — одиночный (single-flight): пока предыдущий StartServerRole
// не вернулся, повторный вызов сразу получает ErrServerRoleStarting и НЕ создаёт второй runner.
// Ожидание порта sing-box теперь идёт до двух минут, а runner виден остальному коду только после
// возврата Start, — без этого второй «Запустить» поднимал второй sing-box поверх первого, а
// «Остановить» в это окно ничего не делало. StopServerRole отменяет контекст запуска: ожидание
// порта в Process.awaitReady слушает ctx.Done() и добивает процесс, запуск возвращает ошибку
// «отменён», а Windows-runner при ошибке Start сам снимает своё firewall-правило.
func (e *Engine) StartServerRole(listenPort int, realityDest string, id singbox.ServerIdentity) (retErr error) {
	if realityDest == "" {
		realityDest = singbox.GoodRealitySNI[0]
	}

	startCtx, finishStart, err := e.beginServerRoleStart()
	if err != nil {
		e.log("Роль «Выход»: повторный запуск отвергнут — предыдущий ещё выполняется")
		return err
	}
	// Контекст запуска отменяется только при НЕУДАЧЕ: у успешного запуска он привязан к процессу
	// sing-box (exec.CommandContext) и должен жить, пока живёт роль — см. serverRoleRunCancels.
	defer func() { finishStart(retErr == nil) }()

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
		runner = newServerRunnerFn()
		// Вывод sing-box роли — в журнал: без этого «причина в строках [sing-box] выше»
		// вела в пустоту (см. windowsServerRunner.SetLogger).
		if l, ok := runner.(interface{ SetLogger(func(string)) }); ok {
			l.SetLogger(e.log)
		}
	}

	doc := singbox.BuildServerConfig(id, internalPort, realityDest)
	if err := runner.WriteConfig(doc); err != nil {
		return fmt.Errorf("StartServerRole: %w", err)
	}

	// Остановка пришла ещё до запуска sing-box (пока резервировали порт и писали конфиг) — не
	// трогаем ни работающий старый процесс, ни новый: StopServerRole сам остановит всё, что есть.
	if err := startCtx.Err(); err != nil {
		e.log("Роль «Выход»: запуск прерван остановкой роли до старта sing-box")
		return serverRoleStartCancelled(err)
	}

	if wasRunning {
		if stopErr := runner.Stop(); stopErr != nil {
			e.log(fmt.Sprintf("Роль «Выход»: не удалось штатно остановить предыдущий sing-box перед перезапуском (%v) — пробую запустить новый поверх", stopErr))
		}
	}

	e.log("Роль «Выход»: запускаю sing-box (на загруженном компьютере это может занять до двух минут)…")
	if err := runner.Start(startCtx); err != nil {
		cancelled := startCtx.Err() != nil
		if wasRunning {
			e.teardownServerRoleAdmissionAndExit()
			if !cancelled {
				e.log("Роль «Выход»: перезапуск с новой конфигурацией не удался, роль остановлена — прежние настройки автоматически не восстанавливаются")
			}
		}
		if cancelled {
			// Отмена — не отказ запуска: пользователь сам остановил роль. Cold start: runner в
			// e.serverRoleRunner ещё не опубликован, добавлять нечего — Process.awaitReady уже
			// добил sing-box, а windowsServerRunner.Start снял своё firewall-правило.
			e.log("Роль «Выход»: запуск прерван остановкой роли")
			return serverRoleStartCancelled(err)
		}
		return fmt.Errorf("StartServerRole: %w", err)
	}

	// Гонка на границе: sing-box успел открыть порт в тот же миг, когда пришла остановка (Start
	// вернул nil, хотя контекст уже отменён). Публиковать такую роль нельзя — StopServerRole
	// считает свою работу сделанной, как только запуск вернулся, и поднятый после этого
	// AdmissionProxy остался бы жить сам по себе. Останавливаем свой же sing-box и выходим.
	if err := startCtx.Err(); err != nil {
		if stopErr := runner.Stop(); stopErr != nil {
			e.log(fmt.Sprintf("Роль «Выход»: не удалось остановить sing-box, поднявшийся одновременно с остановкой роли: %v", stopErr))
		}
		if wasRunning {
			e.teardownServerRoleAdmissionAndExit()
		}
		e.log("Роль «Выход»: запуск прерван остановкой роли, sing-box остановлен")
		return serverRoleStartCancelled(err)
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

	publicLn, err := listenPublicFn(listenPort)
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
		if fwErr := ensureInboundFirewallRuleFn(admissionProxyFirewallRuleName, exePath, listenPort); fwErr != nil {
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
	removeInboundFirewallRuleFn(admissionProxyFirewallRuleName)
}

// StopServerRole останавливает роль «Выход». Идемпотентен: ни разу не запущенная или уже
// остановленная роль — не ошибка (тот же контракт, что у Process.Stop/Android StopServerRole).
//
// [ревью 1.1.10, compat F5] Если в этот момент идёт StartServerRole (ожидание порта sing-box до
// двух минут), сначала прерываем его и дожидаемся возврата (abortServerRoleStart). Раньше Stop
// в это окно видел serverRoleRunner==nil (runner публикуется только после Start) и тихо
// возвращал nil, а sing-box через минуту всё равно поднимался. Снимок состояния роли берётся
// ПОСЛЕ ожидания: запуск мог успеть что-то опубликовать, и это «что-то» тоже надо погасить.
func (e *Engine) StopServerRole() error {
	e.abortServerRoleStart()

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

	// Контекст запущенного sing-box освобождается ПОСЛЕ остановки процесса (отмена убила бы его
	// сама, но штатный Stop должен идти первым — он же снимает firewall-правило sing-box).
	defer e.releaseServerRoleRunCtx()

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
//
// IsRunning зовётся ВНЕ serverRoleMu: Process.Start держит внутренний мьютекс процесса на весь срок
// ожидания порта (до serverRoleReadyTimeout, 120 с), и IsRunning на нём ждёт. Под serverRoleMu
// это парализовало бы и Stop, и сам Start (тот же замок) на время горячей перезагрузки, пока UI
// опрашивает статус.
func (e *Engine) IsServerRoleRunning() bool {
	e.serverRoleMu.Lock()
	runner := e.serverRoleRunner
	e.serverRoleMu.Unlock()
	return runner != nil && runner.IsRunning()
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
	runner := e.serverRoleRunner
	port := e.serverRoleListen
	admission := e.serverRoleAdmission
	exitClient := e.serverRoleExit
	e.serverRoleMu.Unlock()
	// IsRunning — вне замка, по той же причине, что в IsServerRoleRunning.
	running := runner != nil && runner.IsRunning()

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
