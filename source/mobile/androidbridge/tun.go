package androidbridge

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/apf/adaptive-pathfinder/internal/engine"
	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/parser"
	"github.com/apf/adaptive-pathfinder/internal/singbox"
)

const (
	minMTU = 576
	maxMTU = 9000
)

var (
	tunMu       sync.Mutex
	protectCB   ProtectCallback
	tunFdCB     TunFdCallback
	tunFdHolder *os.File // владеет исходным fd от VpnService.Builder.establish() до StopTun
)

// SetProtectCallback устанавливает реализацию ProtectCallback (B-A02) ДО вызова StartTun.
//
// Отдельный сеттер, а не параметр StartTun — тот же приём, что уже есть в bridge.go
// (SetLogCallback, SetStateCallback): gomobile лучше связывает интерфейсы отдельным
// вызовом, чем как позиционный параметр в функции с примитивами.
func SetProtectCallback(cb ProtectCallback) {
	tunMu.Lock()
	defer tunMu.Unlock()
	protectCB = cb
}

// TunFdCallback — запрашивает у платформы АБСОЛЮТНО НОВЫЙ TUN-fd пересозданием
// системного интерфейса (задача #11, вариант 2, см. singbox.TunReloader). Kotlin
// реализует его повторным вызовом VpnService.Builder(...).establish() — тем же кодом,
// что и при первом StartTun/StartTunToNode, — и возвращает detachFd() от нового
// ParcelFileDescriptor.
//
// Выход:     новый fd (> 0), владение переходит Go; <= 0 — Kotlin не смог пересоздать
// интерфейс (например, VPN-разрешение отозвано между переключениями).
func SetTunFdCallback(cb TunFdCallback) {
	tunMu.Lock()
	defer tunMu.Unlock()
	tunFdCB = cb
}

// getTunFdCallback — доступ из tun_runner.go под тем же tunMu, что и остальное
// TUN-состояние этого файла.
func getTunFdCallback() TunFdCallback {
	tunMu.Lock()
	defer tunMu.Unlock()
	return tunFdCB
}

// swapHeldTunFd заменяет держатель исходного TUN-fd на новый, полученный через
// TunFdCallback (задача #11, вариант 2), и закрывает прежний.
//
// Закрывать безопасно: Android НЕ закрывает прежний ParcelFileDescriptor сама при
// повторном establish() ("seamless handover" переключает только МАРШРУТИЗАЦИЮ на новый
// интерфейс) — прежний fd остаётся открытым, пока владелец не закроет его явно, а
// владелец здесь всегда мы (Kotlin передаёт его через detachFd(), то есть безвозвратно).
// Закрытие этого fd — НЕ то же самое, что закрытие внутреннего dup()-дескриптора старого
// sing-box-инстанса (см. platform_adapter.go/OpenTun): тот принадлежит и закрывается
// собственным Close() старого InProcessRunner, независимо от этого.
func swapHeldTunFd(newFd int) {
	tunMu.Lock()
	old := tunFdHolder
	tunFdHolder = os.NewFile(uintptr(newFd), "apf-tun")
	tunMu.Unlock()
	if old != nil {
		_ = old.Close()
	}
}

// ─── B-A13 · StartTun(fd, mtu) ───────────────────────────────────────────────────
//
// Вход:      fd от VpnService.Builder.establish() (> 0, владение переходит Go-слою);
// mtu 576…9000; ProtectCallback должен быть установлен заранее через SetProtectCallback.
// Тело:      готовит platformAdapter + InProcessRunner, подключает их к движку
// (Engine.SetRunner, Engine.SetTunMode), запускает обычный ScanAndConnect — той же дорогой,
// что и Connect() для режима "прокси": подбор узла, watchdog, аварийное переключение
// остаются ОБЩИМ кодом, потому что дальше engine.go работает через singbox.Runner и не
// отличает, какая реализация активна (см. internal/singbox/runner.go).
// Выход:     "" при успехе; непустая строка — текст ошибки (контракт gomobile).
// Отвергает: fd <= 0 (единственный случай, где fd НЕ закрывается — он ещё не подтверждён
// валидным, закрывать произвольное значение рискованно, например fd=0 — это stdin), mtu вне
// диапазона, повторный вызов при уже поднятом туннеле ("already running"), отсутствие
// ProtectCallback, отсутствие инициализации (Init не вызван) — с внятным текстом.
// Fail-safe: с момента, когда fd>0 подтверждён, владение им безусловно у Go — ЛЮБОЙ
// дальнейший отказ (mtu, already running, нет ProtectCallback, ошибка InProcessRunner)
// закрывает fd здесь же, без исключений (см. prepareTun; находка консилиума 2026-08-10,
// HIGH — раньше закрывал только один из четырёх случаев отказа).
// Инвариант: после StopTun ни одного открытого fd от TUN и ни одной горутины
// InProcessRunner не остаётся (обеспечивается StopTun, см. ниже).
func StartTun(fd int, mtu int) string {
	eng, err := prepareTun(fd, mtu)
	if err != "" {
		return err
	}
	go func() {
		if err := eng.ScanAndConnect(); err != nil {
			// Логируется внутри engine, как и в Connect() — тот же путь.
			_ = err
		}
	}()
	return ""
}

// ─── StartTunToNode(fd, mtu, link) ───────────────────────────────────────────────
//
// Находка Ш-6 (приёмка на устройстве): у вставленной пользователем ссылки не было
// пути «подключиться именно к ней» — StartTun всегда уходит в ScanAndConnect, а тот
// тестирует случайную выборку 50 узлов из всего пула (тысячи). Вручную добавленный
// узел, даже подтверждённо живой фоновой проверкой (checker.CheckOne), имел около 1%
// шанс попасть в выборку за одну попытку подключения — воспроизведено на телефоне:
// 4 подряд подключения не выбрали заведомо рабочий узел.
//
// Вход:      fd/mtu — как у StartTun; link — vless/vmess/ss/trojan/wireguard-ссылка.
// Тело:      ссылка разбирается и семантически проверяется (models.ValidateNode — те же
// правила, что применяет AddNodeFromLink, но ДО того, как TUN смонтирован) — только потом
// prepareTun; далее добавление узла в пул (если его там ещё нет) и Engine.ConnectByID
// (B-08.2, FR-4) — тот же путь, что уже используется закреплением узла в режиме «прокси»,
// просто впервые подключается к TUN-запуску.
// Отвергает: невалидную ссылку — с тем же текстом ошибки, что вернул бы parser.ParseLink
// или models.ValidateNode при обычном AddNodeFromLink, — ДО монтирования TUN (находка
// консилиума 2026-08-10, CRITICAL: раньше монтаж происходил раньше валидации, потому что
// её выполняет только AddNodeFromLink, вызываемый ПОСЛЕ prepareTun; отказ узла уже ПОСЛЕ
// смонтированного TUN не откатывался ни в Go, ни в Kotlin — воспроизводило дефект D-A3).
// Fail-safe: ошибка парсинга/валидации ⇒ TUN не поднимается вовсе, fd закрыт здесь же.
// Ошибка ПОСЛЕ успешного prepareTun (AddNodeFromLink/ConnectByID) ⇒ откат тем же путём,
// что и штатный StopTun (rollbackTun) — движок и fd возвращаются в состояние до вызова.
func StartTunToNode(fd int, mtu int, link string) string {
	if fd <= 0 {
		return "StartTun: fd <= 0"
	}

	node, perr := parser.ParseLink(link)
	if perr != nil {
		closeTunFd(fd)
		return "StartTunToNode: " + perr.Error()
	}
	if verr := models.ValidateNode(node); verr != nil {
		closeTunFd(fd)
		return "StartTunToNode: " + verr.Error()
	}

	eng, err := prepareTun(fd, mtu)
	if err != "" {
		return err
	}

	if addErr := eng.AddNodeFromLink(link); addErr != nil && !strings.Contains(addErr.Error(), "already exists") {
		rollbackTun(eng)
		return "StartTunToNode: " + addErr.Error()
	}
	// ТЗ v1.3 F2 PIN-8: подключение к конкретному узлу НЕ закрепляет его — закрепление
	// отдельное действие пользователя (PinNode), иначе каждый тап молча менял pin.
	if connErr := eng.ConnectOnce(node.ID); connErr != nil {
		rollbackTun(eng)
		return "StartTunToNode: " + connErr.Error()
	}
	return ""
}

// StartTunToNodeID — как StartTunToNode, но узел задаётся ID из пула («Мои серверы», ТЗ v1.3
// F6/КТ-14: подключение к конкретному узлу в IDLE идёт через службу, а не напрямую в движок,
// чтобы состояние экрана и TUN совпадали). Закрепление не меняется (ConnectOnce, PIN-8).
func StartTunToNodeID(fd int, mtu int, nodeID string) string {
	if fd <= 0 {
		return "StartTun: fd <= 0"
	}
	if strings.TrimSpace(nodeID) == "" {
		closeTunFd(fd)
		return "StartTunToNodeID: empty node id"
	}
	eng, err := prepareTun(fd, mtu)
	if err != "" {
		return err
	}
	if connErr := eng.ConnectOnce(nodeID); connErr != nil {
		rollbackTun(eng)
		return "StartTunToNodeID: " + connErr.Error()
	}
	return ""
}

// ─── StartTunToChainPartner(fd, mtu, link) ──────────────────────────────────────
//
// Живая находка 2026-09-28 (ПК = «Выход» на мобильной раздаче, телефон = «Вход» на Wi-Fi):
// кнопка «Это ссылка от партнёра Вход-Выход» вызывала ConnectChainPartner ПРЯМО из
// активити, мимо APFVpnService. Итог: канал поднимался всегда в режиме «прокси» (движок с
// runner'ом по умолчанию), даже при включённом «Режим VPN» — браузер и прочие приложения
// телефона шли мимо партнёра; главный экран показывал «Отключено» при работающем канале;
// без foreground-службы Android мог убить такое подключение в фоне. Корень — две точки
// входа подключения, и путь партнёра не был заведён в службу.
//
// Вход:      fd/mtu — как у StartTun; link — ссылка партнёра (прямая или relay-формата).
// Тело:      ссылка разбирается и проверяется ДО монтажа TUN (тот же принцип, что у
// StartTunToNode — невалидная ссылка не трогает TUN), затем prepareTun и
// Engine.AddChainPartnerFromLink — он помечает узел IsChainPartner (автопереключение не
// подменит партнёра случайным публичным узлом) и подключается через уже смонтированный
// TUN-runner.
// Выход:     "" — успех; иначе текст отказа, TUN откатан тем же обратимым rollbackTun.
func StartTunToChainPartner(fd int, mtu int, link string) string {
	if fd <= 0 {
		return "StartTun: fd <= 0"
	}
	node, perr := parser.ParseLink(link)
	if perr != nil {
		closeTunFd(fd)
		return "StartTunToChainPartner: " + perr.Error()
	}
	if verr := models.ValidateNode(node); verr != nil {
		closeTunFd(fd)
		return "StartTunToChainPartner: " + verr.Error()
	}

	eng, err := prepareTun(fd, mtu)
	if err != "" {
		return err
	}
	if _, cerr := eng.AddChainPartnerFromLink(link); cerr != nil {
		rollbackTun(eng)
		return "StartTunToChainPartner: " + cerr.Error()
	}
	return ""
}

// rollbackTun откатывает состояние, которое prepareTun уже успел смонтировать
// (SetRunner/SetTunMode/tunFdHolder), когда следующий шаг после него (AddNodeFromLink/
// ConnectByID) не удался. Тот же обратимый путь, что у штатного StopTun (restartEngine,
// не терминальный stopEngine — см. bridge.go, дефект D-A17), плюс закрытие TUN fd.
func rollbackTun(eng *engine.Engine) {
	_ = restartEngine(eng)
	closeHeldTunFd()
}

// prepareTun — общая часть StartTun/StartTunToNode: проверки входа, platformAdapter,
// InProcessRunner, подключение к движку (Engine.SetRunner/SetTunMode). Вызывающая
// сторона сама решает, КАК запустить подключение (ScanAndConnect или ConnectByID).
//
// Fail-safe (находка консилиума 2026-08-10, HIGH: раньше только отказ NewInProcessRunner
// закрывал fd — mtu вне диапазона/"already running"/отсутствие ProtectCallback оставляли
// валидный fd открытым вопреки doc-комментарию StartTun, а на стороне Kotlin к этому
// моменту уже нет обёртки, чтобы закрыть его самостоятельно — detachFd() уже случился).
// С этой точки (fd>0 подтверждён) владение уже безусловно у Go: ЛЮБОЙ дальнейший отказ
// в этой функции обязан закрыть fd здесь же, без исключений.
func prepareTun(fd int, mtu int) (*engine.Engine, string) {
	eng := getEngine()
	if eng == nil {
		return nil, "not initialized"
	}
	if fd <= 0 {
		return nil, "StartTun: fd <= 0"
	}
	if mtu < minMTU || mtu > maxMTU {
		closeTunFd(fd)
		return nil, fmt.Sprintf("StartTun: mtu %d вне диапазона %d..%d", mtu, minMTU, maxMTU)
	}
	if eng.IsConnected() {
		closeTunFd(fd)
		return nil, "already running"
	}

	tunMu.Lock()
	cb := protectCB
	tunMu.Unlock()
	if cb == nil {
		closeTunFd(fd)
		return nil, "StartTun: ProtectCallback не установлен — вызовите SetProtectCallback раньше"
	}

	adapter := newPlatformAdapter(cb, int32(fd))
	runner, rerr := singbox.NewInProcessRunner(adapter)
	if rerr != nil {
		closeTunFd(fd)
		return nil, "StartTun: " + rerr.Error()
	}
	// Диагностика D-A37 (Task #25, 2026-08-11) — временно, см. комментарий у
	// InProcessRunner.OnInternalLog. Префикс SINGBOX/ отличает сырые логи движка sing-box
	// от собственных сообщений APF ("[ENGINE]"/"[FSM]"/т.п.), которые тоже идут в eng.OnLog.
	runner.OnInternalLog = func(level, msg string) {
		if eng.OnLog != nil {
			eng.OnLog(fmt.Sprintf("[SINGBOX/%s] %s", level, msg))
		}
	}

	tunMu.Lock()
	// Находка консилиума 2026-08-10 (medium): безусловная перезапись без закрытия
	// прежнего значения теряла ссылку на предыдущий fd, если предыдущий вызов не дошёл
	// до штатного StopTun. Структурный инвариант — держатель никогда не перезаписывается
	// молча, независимо от дисциплины вызывающего кода.
	if tunFdHolder != nil {
		_ = tunFdHolder.Close()
	}
	tunFdHolder = os.NewFile(uintptr(fd), "apf-tun")
	tunMu.Unlock()

	// tunRunner (задача #11, вариант 2) оборачивает InProcessRunner и подменяет системный
	// TUN-интерфейс целиком на каждом Reload — см. tun_runner.go. cb (ProtectCallback) тот
	// же, что уже передан адаптеру: пересозданный на новом fd platformAdapter внутри
	// ReloadWithFreshTun использует его для того же protect(), не второй источник истины.
	eng.SetRunner(newTunRunner(runner, cb))
	eng.SetTunMode(true, mtu)
	return eng, ""
}

// ─── StopTun (симметрия B-A13) ───────────────────────────────────────────────────
//
// Тело:      обратимая остановка — та же restartEngine-дорога, что у Disconnect (дефект
// D-A17: недопустим терминальный Stop, иначе следующее StartTun/Connect в этом сеансе
// приложения работать не будет), плюс закрытие исходного TUN-дескриптора, которым
// platformAdapter больше не пользуется.
// Инвариант: после успешного StopTun в процессе не остаётся открытого fd от TUN.
func StopTun() string {
	eng := getEngine()
	if eng == nil {
		closeHeldTunFd()
		return ""
	}
	if err := restartEngine(eng); err != nil {
		return err.Error()
	}
	closeHeldTunFd()
	return ""
}

func closeHeldTunFd() {
	tunMu.Lock()
	f := tunFdHolder
	tunFdHolder = nil
	tunMu.Unlock()
	if f != nil {
		_ = f.Close()
	}
}

// closeTunFd закрывает "голый" fd, ещё не обёрнутый в *os.File (путь отказа StartTun
// до того, как fd передан в держателя).
func closeTunFd(fd int) {
	_ = os.NewFile(uintptr(fd), "apf-tun-reject").Close()
}
