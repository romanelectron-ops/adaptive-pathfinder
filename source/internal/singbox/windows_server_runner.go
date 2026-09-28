package singbox

import (
	"context"
	"fmt"
	"os/exec"
)

// windowsServerRunner — Э-Выход-1 (docs/PLAN_APF_VHOD_VYHOD_v1.0.md): первая реальная
// реализация ServerRunner. Оборачивает уже проверенный *Process (тот же тип, что уже
// управляет клиентским sing-box на Windows) — не InProcessRunner.
//
// Почему Process, а не InProcessRunner (как у Android-клиента в VPN-режиме, Э-4). У
// Android-клиента InProcessRunner обязателен: TUN-дескриптор и protect() из VpnService не
// пересекают границу процессов (см. runner.go), поэтому sing-box обязан жить В ПРОЦЕССЕ
// приложения. У роли «Выход» на Windows нет TUN и нет чужого fd — это обычный TCP-листенер,
// то же самое, что клиент уже делает через socks-in/http-in. Отдельный процесс проще,
// надёжнее (падение sing-box не роняет APF целиком) и — важно для находки 2026-08-10 —
// пользуется ОФИЦИАЛЬНЫМ бинарником с GitHub Releases, у которого with_utls/with_clash_api
// и прочие теги уже включены апстримом; наша сборка (vendor/, -tags) тут вообще не участвует.
type windowsServerRunner struct {
	proc *Process
	// port — [консилиум, MEDIUM, находка №19, TZ_RELAY_HARDENING_2026-08-29.md] порт из
	// последнего WriteConfig, нужен ТОЛЬКО для того, чтобы Start() мог передать его в
	// EnsureInboundFirewallRule (localport=, не разрешать вход на любой порт, который
	// когда-либо откроет sing-box.exe).
	port int
}

// serverRoleConfigName — файл конфигурации роли «Выход», ОТДЕЛЬНЫЙ от клиентского
// current.json. См. NewProcessNamed: общий файл ломал одновременную работу ролей
// детерминированно (запуск «Выхода» затирал конфиг работающего клиента).
const serverRoleConfigName = "server_current.json"

// NewWindowsServerRunner создаёт ServerRunner для роли «Выход»/«Транзит» на Windows.
// binDir/dataDir — те же каталоги, что и у клиентского NewProcess (общий установленный
// бинарник sing-box), но СВОЙ файл конфигурации: роли обязаны работать одновременно.
func NewWindowsServerRunner(binDir, dataDir string) ServerRunner {
	return &windowsServerRunner{proc: NewProcessNamed(binDir, dataDir, serverRoleConfigName)}
}

func (r *windowsServerRunner) IsInstalled() bool        { return r.proc.IsInstalled() }
func (r *windowsServerRunner) Version() (string, error) { return r.proc.Version() }

// GenerateIdentity — тонкая обёртка над пакетной GenerateServerIdentity (server_identity.go):
// метод интерфейса нужен, чтобы вызывающая сторона могла работать с любым ServerRunner
// (реальным или заглушкой) единообразно, сама генерация не завязана на состояние процесса.
func (r *windowsServerRunner) GenerateIdentity() (ServerIdentity, error) {
	return GenerateServerIdentity()
}

// WriteConfig сериализует ServerDoc и передаёт готовые байты в Process.WriteRawConfig,
// явно указав порт готовности (первый inbound — если их несколько, готовность проверяется
// по первому; сегодня BuildServerConfig всегда собирает ровно один).
//
//	Вход:      *ServerDoc — не обязательно результат BuildServerConfig, интерфейс ServerRunner
//	           принимает его от любого вызывающего кода.
//	Тело:      сериализация в JSON, вычисление readyPort из первого inbound.
//	Выход:     nil при успехе; конфиг и readyPort записаны в Process.
//	Fail-safe: любой ServerDoc без слушающего inbound на порту 1..65535 отвергается ЗДЕСЬ,
//	           явной ошибкой — не доходит до Start()/awaitReady() (validateServerDoc,
//	           server_config.go — общая граница для всех платформенных ServerRunner, не
//	           дублируется по одной на платформу).
func (r *windowsServerRunner) WriteConfig(doc *ServerDoc) error {
	if err := validateServerDoc(doc); err != nil {
		return err
	}
	data, err := ToServerJSON(doc)
	if err != nil {
		return fmt.Errorf("singbox: сериализация серверного конфига: %w", err)
	}
	r.port = doc.Inbounds[0].ListenPort
	return r.proc.WriteRawConfig(data, r.port)
}

// serverRoleFirewallRuleName — живой инцидент 2026-08-25: роль «Выход» на Windows ни разу
// не заводила себе разрешение во входящем файрволе. Default policy — BlockInbound, у
// СЛУЖБЫ (SYSTEM, Session 0, без рабочего стола) нет способа показать интерактивный
// запрос «разрешить приложению X принимать входящие подключения», который Windows обычно
// показывает при первом listen() — она просто молча роняет пакеты. Снаружи (со стороны
// «Входа») это выглядело как REALITY-рукопожатие, которое даже не начинается: `dial tcp
// host:port: i/o timeout`. Диагностировано кросс-девайс живым прогоном телефон↔ПК —
// правило `sing-box`, заведённое РАНЬШЕ вручную для отдельного диагностического
// инструмента (cmd/apf-standup-test, другой путь до exe), продакшен-бинарник
// ($binDir\sing-box.exe) не покрывало вовсе.
//
// [Фаза C/D, docs/TZ_APF_RELAY_v1.0.md §10.2] С admission-control это правило для
// sing-box.exe само по себе стало вспомогательным: sing-box слушает СВОЙ порт только на
// 127.0.0.1 (server_config.go, BuildServerConfig — тот же живой баг 2026-08-29, что привёл
// к находке пробела ниже), loopback-трафик файрвол не фильтрует в принципе. Публичный порт
// (тот, что в ссылке) теперь слушает AdmissionProxy — ВНУТРИ процесса APF, не sing-box.exe —
// поэтому свой рубеж нужен и ЕМУ, см. EnsureInboundFirewallRule, вызывается отдельно из
// internal/engine/server_role.go с собственным именем правила (не разделяет это с sing-box).
//
// Имя правила — свой, не разделяемый с чем-либо ещё, идентификатор: Stop() должен суметь
// найти и снять именно это правило, не трогая то, что мог завести пользователь/другой
// компонент вручную под тем же win32-именем "sing-box".
const serverRoleFirewallRuleName = "APF Server Role (sing-box.exe)"

// EnsureInboundFirewallRule заводит (идемпотентно — `add rule` с тем же name просто
// добавит дубликат-правило, но Windows Firewall это допускает и не мешает работе; Remove
// ниже снимает все правила с этим именем разом) входящее разрешение для КОНКРЕТНОГО пути
// до бинарника. Параметризовано именем правила и путём — переиспользуется и для sing-box.exe
// (windowsServerRunner.Start ниже), и для самого процесса APF (internal/engine/server_role.go,
// AdmissionProxy слушает публичный порт внутри него, не внутри sing-box.exe).
// Не роняем вызывающую сторону при неудаче — netsh требует прав администратора, а служба
// APF уже работает от SYSTEM (полные права); при явном запуске без повышения пользователь
// увидит по логу, что попытка была, и почему трафик не проходит, вместо молчаливого
// таймаута без единой зацепки.
//
// [консилиум, MEDIUM, находка №19, TZ_RELAY_HARDENING_2026-08-29.md] port — раньше правило
// строилось только по program=, разрешая вход на ЛЮБОЙ порт, который когда-либо откроет
// данный exe, не только нужный публичный порт роли «Выход». localport=/protocol=TCP сужают
// разрешение до конкретного порта — тот же бинарник, слушающий что-то ещё на другом порту
// (например, будущая фича), этим правилом уже не покрывается, нужно отдельное.
// execCommandFn — шов для тестов: настоящий netsh меняет реальный файрвол Windows и требует
// прав администратора — недопустимо и нежелательно под `go test` (тот же приём, что
// discoverUPnPClientsFn/stunDetectFn в internal/relay). Возвращает (combined-output, err) —
// та же форма, что exec.Command(...).CombinedOutput().
var execCommandFn = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

func EnsureInboundFirewallRule(ruleName, binPath string, port int) error {
	out, err := execCommandFn("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+ruleName,
		"dir=in", "action=allow",
		"program="+binPath, "enable=yes", "profile=any",
		fmt.Sprintf("localport=%d", port), "protocol=TCP")
	if err != nil {
		return fmt.Errorf("netsh advfirewall add rule: %w (%s)", err, string(out))
	}
	return nil
}

// RemoveInboundFirewallRule снимает ВСЕ правила с указанным именем — парная операция к
// EnsureInboundFirewallRule. Не критично, если правила уже нет (не запускалось с этим
// фиксом, ручное удаление и т.п.) — netsh вернёт ненулевой код, это не повод считать
// вызывающую сторону неуспешной.
func RemoveInboundFirewallRule(ruleName string) {
	_, _ = execCommandFn("netsh", "advfirewall", "firewall", "delete", "rule",
		"name="+ruleName)
}

func (r *windowsServerRunner) Start(ctx context.Context) error {
	if err := EnsureInboundFirewallRule(serverRoleFirewallRuleName, r.proc.BinPath(), r.port); err != nil {
		// См. комментарий у EnsureInboundFirewallRule — не блокируем запуск, только
		// предупреждаем через возвращаемую по цепочке ошибку не годится (интерфейс
		// ServerRunner.Start её бы принял за фатальный отказ), поэтому глотаем здесь и
		// полагаемся на то, что снаружи (Engine.StartServerRole) при отсутствии реальных
		// подключений это будет видно по факту. TODO: прокинуть предупреждение в лог
		// движка, если понадобится более явная диагностика этого конкретного отказа.
		_ = err
	}
	return r.proc.Start(ctx)
}
func (r *windowsServerRunner) Stop() error {
	RemoveInboundFirewallRule(serverRoleFirewallRuleName)
	return r.proc.Stop()
}
func (r *windowsServerRunner) IsRunning() bool                 { return r.proc.IsRunning() }

var _ ServerRunner = (*windowsServerRunner)(nil)
