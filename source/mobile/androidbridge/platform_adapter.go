package androidbridge

import (
	"errors"

	libbox "github.com/sagernet/sing-box/experimental/libbox"
)

// ─── B-A02 · ProtectCallback ────────────────────────────────────────────────────
//
// Kotlin реализует Protect через VpnService.protect(fd) и передаёт реализацию в StartTun.
//
// Вход:      fd — дескриптор сокета, созданного Go-слоем (sing-box).
// Тело:      Kotlin вызывает VpnService.protect(fd).
// Выход:     true — сокет выведен из-под туннеля.
// Fail-safe: false ⇒ вызывающая сторона (platformAdapter.AutoDetectInterfaceControl)
// обязана вернуть ошибку, а не тихо продолжить: незащищённый исходящий сокет sing-box
// уходит обратно в собственный TUN — петля и полный обрыв связи на телефоне.
// Инвариант: ни один исходящий сокет sing-box не остаётся незащищённым.
type ProtectCallback interface {
	Protect(fd int) bool
}

// ─── Задача #11, вариант 2 · TunFdCallback ─────────────────────────────────────
//
// Kotlin реализует пересозданием системного TUN-интерфейса: тем же кодом, что строит
// первый Builder().establish() (buildVpnInterface() в APFVpnService.kt), и возвращает
// detachFd() от НОВОГО ParcelFileDescriptor. Симметрично ProtectCallback выше — тот же
// приём "интерфейс с одним примитивным методом" ради gomobile.
//
// Вход:      нет.
// Выход:     новый fd (> 0), владение переходит Go; <= 0 — не удалось (например,
// VpnService.prepare() перестал быть пройден между переключениями).
// Используется из mobile/androidbridge/tun_runner.go (ReloadWithFreshTun), не из
// platformAdapter напрямую — platformAdapter остаётся неизменяемым держателем ОДНОГО
// fd на весь свой жизненный цикл (см. OpenTun выше); пересоздание строит НОВЫЙ
// platformAdapter с новым fd, а не мутирует существующий.
type TunFdCallback interface {
	RequestFd() int
}

// ─── B-A14 · platformAdapter (реализация libbox.PlatformInterface) ─────────────
//
// Вход:      ProtectCallback от Kotlin; уже установленный TUN-дескриптор (его владелец —
// StartTun, см. tun.go; platformAdapter только пользуется значением, не закрывает его).
// Тело:      три содержательных метода — AutoDetectInterfaceControl (protect),
// OpenTun (возврат уже установленного fd), UsePlatformAutoDetectInterfaceControl (true,
// без этого sing-box вообще не станет спрашивать про protect — см. ниже); плюс двенадцать
// сознательных заглушек.
// Выход:     ответы по контракту sing-box (experimental/libbox/platform.go, v1.13.16).
// Fail-safe: AutoDetectInterfaceControl при отказе protect() возвращает ошибку — sing-box
// закрывает незащищённый сокет сам (стандартное поведение net.Dialer.Control при ошибке
// Control-функции), a platformAdapter не обязан закрывать его повторно.
// Инвариант: ни один метод не возвращает выдуманных сведений — там, где ответа нет,
// возвращается честно пустое значение или ошибка, а не правдоподобная догадка.
//
// Почему заглушки бывают ДВУХ разных форм — "верни ошибку" и "верни пусто-но-успешно" —
// и это не оговорка, а разные последствия при разной форме отказа:
//
//   - FindConnectionOwner, SendNotification — опциональные, вызываются точечно (по одному
//     соединению, по одному уведомлению); ошибка там просто теряет один опциональный ответ.
//
//   - StartDefaultInterfaceMonitor запускается ИЗНУТРИ старта туннеля
//     (experimental/libbox/monitor.go: platformDefaultInterfaceMonitor.Start вызывается
//     из старта network-менеджера) — ошибка оттуда прерывает весь box.New()/instance.Start().
//     Поэтому здесь "не реализовано" обязано означать "молча ничего не делать" (nil), а не
//     "вернуть ошибку", иначе VPN не поднимался бы вовсе. Это рассуждение по исходнику
//     (§7 ТЗ Э-4), не проверено включением настоящего туннеля на устройстве — проверить
//     на Ш-6.
//
// Что теряется от такой деградации (честно, не молчанием): GetInterfaces()/
// StartDefaultInterfaceMonitor() без моста к Android ConnectivityManager — sing-box не
// узнаёт о смене сети (Wi-Fi ⇄ мобильная) и не отличает "дорогое" соединение от обычного.
// Для одного всегда-включённого туннеля (без per-app роутинга и без ручного выбора сети)
// это не отказ функциональности, а её сужение — заведено отдельным пунктом в ТЗ, не решено
// втихую.
type platformAdapter struct {
	protect ProtectCallback
	tunFd   int32
}

func newPlatformAdapter(protect ProtectCallback, tunFd int32) *platformAdapter {
	return &platformAdapter{protect: protect, tunFd: tunFd}
}

// UsePlatformAutoDetectInterfaceControl — ЖЁСТКО true.
//
// Это не заглушка, а обязательное условие: сама обёртка sing-box
// (platformInterfaceWrapper.UsePlatformAutoDetectInterfaceControl) транслирует наш ответ
// наружу, и ИМЕННО он решает, пойдёт ли sing-box за protect() к нам, или попробует
// собственный auto_detect_interface на базе netlink — а netlink на Android запрещён
// (см. §1.3 ТЗ Э-4, дефект D-A28). false здесь тихо возвращает нас к уже пройденному отказу.
func (p *platformAdapter) UsePlatformAutoDetectInterfaceControl() bool {
	return true
}

// AutoDetectInterfaceControl — protect() каждого исходящего сокета sing-box (B-A02).
func (p *platformAdapter) AutoDetectInterfaceControl(fd int32) error {
	if p.protect == nil {
		return errors.New("platformAdapter: ProtectCallback не задан")
	}
	if !p.protect.Protect(int(fd)) {
		return errors.New("platformAdapter: VpnService.protect(fd) отказал — " +
			"сокет остаётся под защитой стандартного поведения net.Dialer при ошибке Control")
	}
	return nil
}

// OpenTun возвращает уже установленный дескриптор TUN.
//
// Дескриптор получен через VpnService.Builder.establish() ДО вызова StartTun — адреса,
// маршруты и DNS уже применены на уровне ОС самим Android Builder-ом. Поэтому options
// (маршруты/адреса, которые sing-box вычислил бы для САМОСТОЯТЕЛЬНОГО создания TUN)
// сознательно не используются: TUN не создаётся заново, а переиспользуется существующий.
func (p *platformAdapter) OpenTun(options libbox.TunOptions) (int32, error) {
	if p.tunFd <= 0 {
		return 0, errors.New("platformAdapter: TUN-дескриптор не установлен")
	}
	return p.tunFd, nil
}

// UseProcFS — честно false: определение процесса-владельца соединения через /proc не
// реализовано (не входит в Э-4, см. FindConnectionOwner ниже).
func (p *platformAdapter) UseProcFS() bool {
	return false
}

// FindConnectionOwner — сознательная заглушка. Используется для per-app роутинга/UI
// ("какое приложение открыло это соединение"), которого в APF нет.
func (p *platformAdapter) FindConnectionOwner(ipProtocol int32, sourceAddress string, sourcePort int32, destinationAddress string, destinationPort int32) (*libbox.ConnectionOwner, error) {
	return nil, errors.New("platformAdapter: определение процесса-владельца соединения не реализовано")
}

// StartDefaultInterfaceMonitor — намеренно nil-op, см. комментарий у platformAdapter.
func (p *platformAdapter) StartDefaultInterfaceMonitor(listener libbox.InterfaceUpdateListener) error {
	return nil
}

// CloseDefaultInterfaceMonitor — симметрично StartDefaultInterfaceMonitor: закрывать нечего.
func (p *platformAdapter) CloseDefaultInterfaceMonitor(listener libbox.InterfaceUpdateListener) error {
	return nil
}

// GetInterfaces — пустой, но УСПЕШНЫЙ список (см. комментарий у platformAdapter про две
// формы заглушек). nil здесь означало бы "не удалось узнать", а пустой список — честное
// "интерфейсы платформой не сообщаются".
func (p *platformAdapter) GetInterfaces() (libbox.NetworkInterfaceIterator, error) {
	return emptyNetworkInterfaceIterator{}, nil
}

// UnderNetworkExtension — понятие из iOS Network Extension, на Android не применимо.
func (p *platformAdapter) UnderNetworkExtension() bool {
	return false
}

// IncludeAllNetworks — тоже iOS-специфика (NEIncludeAllNetworks).
func (p *platformAdapter) IncludeAllNetworks() bool {
	return false
}

// ReadWIFIState — сознательная заглушка: имя текущей Wi-Fi сети APF нигде не показывает.
func (p *platformAdapter) ReadWIFIState() *libbox.WIFIState {
	return nil
}

// SystemCertificates — пустой список.
//
// Пусто НЕ означает "TLS без проверки сертификатов": box/common/certificate/store.go
// при пустом ответе откатывается на x509.SystemCertPool(), который на Android читает
// /system/etc/security/cacerts (проверено по исходнику Go 1.26.2, crypto/x509/root_linux.go,
// ветка goos.IsAndroid) — то есть системные корневые сертификаты по-прежнему проверяются.
// Не видны только сертификаты, добавленные пользователем вручную через
// Settings → Security → «Установить сертификат» — до android.security.KeyChain моста нет.
// Сознательное сужение, а не тихий отказ от проверки сертификатов.
func (p *platformAdapter) SystemCertificates() libbox.StringIterator {
	return emptyStringIterator{}
}

// ClearDNSCache — платformAdapter не ведёт собственного DNS-кэша, чистить нечего.
func (p *platformAdapter) ClearDNSCache() {}

// LocalDNSTransport — nil: у APF уже есть свой dns-local/dns-remote в конфигурации
// (см. internal/singbox/config_builder.go), отдельный платформенный DNS-транспорт не нужен.
func (p *platformAdapter) LocalDNSTransport() libbox.LocalDNSTransport {
	return nil
}

// SendNotification — системные уведомления вне туннеля не реализованы.
func (p *platformAdapter) SendNotification(notification *libbox.Notification) error {
	return errors.New("platformAdapter: системные уведомления не реализованы")
}

// ─── Пустые итераторы ───────────────────────────────────────────────────────────
//
// libbox.newIterator — неэкспортированная функция своего пакета, извне недоступна.
// Для честно-пустых ответов нужны собственные реализации тех же двух маленьких
// интерфейсов (StringIterator, NetworkInterfaceIterator).

type emptyStringIterator struct{}

func (emptyStringIterator) Len() int32    { return 0 }
func (emptyStringIterator) HasNext() bool { return false }
func (emptyStringIterator) Next() string  { return "" }

type emptyNetworkInterfaceIterator struct{}

func (emptyNetworkInterfaceIterator) Next() *libbox.NetworkInterface { return nil }
func (emptyNetworkInterfaceIterator) HasNext() bool                  { return false }
