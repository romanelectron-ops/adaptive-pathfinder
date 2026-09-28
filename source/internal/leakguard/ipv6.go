package leakguard

import (
	"net"
	"os/exec"
	"runtime"
	"sync/atomic"

	"github.com/apf/adaptive-pathfinder/internal/hostguard"
)

// currentGOOS is replaceable in tests to simulate a different OS environment.
var currentGOOS = runtime.GOOS

// interfacesFn is replaceable in tests to inject synthetic network interfaces.
var interfacesFn = net.Interfaces

// enabled — atomic.Bool: пишется в Enable/Disable (напр. из engine.enableDeviceProtection на
// Start), читается в IsEnabled/Status (напр. из engine.Stop). Гонка данных 2026-09-14: голый bool
// давал WARNING под -race при Restart||Stop. Атомарность делает само поле безопасным при любом
// пути доступа, без дисциплины блокировок.
type IPv6Guard struct {
	enabled atomic.Bool
}

func NewIPv6Guard() *IPv6Guard {
	return &IPv6Guard{}
}

// Enable включает защиту от IPv6-утечки.
//
// Windows: НИЧЕГО не выполняет на уровне ОС — и это осознанное решение, а не пропуск.
// Прежняя реализация звала `netsh interface ipv6 set prefixpolicy ::1/128 50 0`. Эта команда:
//   - НЕ блокирует IPv6 (::1/128 50 0 — и есть значения по умолчанию для loopback);
//   - при этом ПЕРЕВОДИТ машинную таблицу политик префиксов RFC 6724 из состояния «по умолчанию»
//     в явное, схлопывая её до заданных записей. Пропадают строки ::/0, ::ffff:0:0/96 и др.,
//     от которых зависит выбор адреса назначения в getaddrinfo → сетевые сбои на всей машине;
//   - НЕ откатывалась: в Disable() ветки "windows" не было вообще.
//
// Реальную блокировку IPv6 при активном туннеле обеспечивает Kill Switch (WFP-фильтры в слое
// ALE_AUTH_CONNECT_V6 / block-all6, см. internal/killswitch/wfp_plan.go), а не эта функция.
// Держать здесь параллельный, неоткатываемый механизм — источник поломок хоста.
//
// Linux: sysctl-переключатель сохранён (он симметричен и откатывается в Disable).
func (g *IPv6Guard) Enable(_ string) error {
	g.enabled.Store(true)
	if currentGOOS == "linux" {
		if !hostguard.Allow("leakguard.IPv6Guard.Enable(sysctl)") {
			return nil
		}
		_ = exec.Command("sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1").Run()
	}
	return nil
}

func (g *IPv6Guard) Disable() error {
	g.enabled.Store(false)
	if currentGOOS == "linux" {
		if !hostguard.Allow("leakguard.IPv6Guard.Disable(sysctl)") {
			return nil
		}
		_ = exec.Command("sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0").Run()
	}
	return nil
}

// Status — ЧЕСТНЫЙ статус защиты от IPv6-утечки (в духе WebRTCGuard.Status, T-13).
// UI не должен показывать «защищено» там, где механизм ничего не делает.
//
// killSwitchActive — РЕАЛЬНОЕ (не запрошенное) состояние Kill Switch прямо сейчас
// (Engine.KillSwitchStatus().Active). На Windows это единственный механизм, который делает
// хоть что-то (см. комментарий у Enable) — на "delegated" тут нечего делегировать, если сам
// Kill Switch не применён (выключен пользователем, отказал без прав администратора, ждёт
// UAC и т.п., см. аудит 2026-09-01, security-раздел, находка №16). Раньше Status() отвечал
// "delegated"/Enabled:true на голом g.enabled, не спрашивая, действует ли Kill Switch на
// самом деле — пользователь с включённой галочкой "Блокировать утечку IPv6", но снятым (или
// никогда не поднявшимся) Kill Switch видел бы "защищено", хотя IPv6 на Windows не блокирует
// ничего, кроме DNS-правила sing-box (которое обходится DoH/IPv6-литералом в адресе).
func (g *IPv6Guard) Status(killSwitchActive bool) IPv6Status {
	if !g.enabled.Load() {
		return IPv6Status{Enabled: false, Enforced: "none", Note: "Защита от IPv6-утечки выключена."}
	}
	if currentGOOS == "linux" {
		return IPv6Status{Enabled: true, Enforced: "full",
			Note: "IPv6 отключён через sysctl net.ipv6.conf.all.disable_ipv6."}
	}
	if !killSwitchActive {
		return IPv6Status{Enabled: true, Enforced: "none",
			Note: "Включено, но НЕ действует: на Windows блокировку IPv6 обеспечивает только " +
				"Kill Switch (WFP), а он сейчас не активен. Включите Kill Switch, иначе " +
				"реальный IPv6-адрес может утечь."}
	}
	return IPv6Status{Enabled: true, Enforced: "delegated",
		Note: "На Windows IPv6-трафик блокирует Kill Switch (WFP, слой ALE_AUTH_CONNECT_V6). " +
			"Отдельного системного переключателя APF не трогает — это ломало таблицу политик " +
			"префиксов всей машины."}
}

// IPv6Status — наблюдаемое состояние защиты от IPv6-утечки.
type IPv6Status struct {
	Enabled  bool   `json:"enabled"`
	Enforced string `json:"enforced"` // "full" | "delegated" | "none"
	Note     string `json:"note"`
}

func (g *IPv6Guard) IsEnabled() bool {
	return g.enabled.Load()
}

// TestIPv6Leak проверяет наличие глобального IPv6 адреса.
func TestIPv6Leak() (bool, string) {
	ifaces, err := interfacesFn()
	if err != nil {
		return false, ""
	}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP == nil {
				continue
			}
			ip := ipNet.IP
			if ip.To16() == nil || ip.To4() != nil {
				continue
			}
			if ip.IsLinkLocalUnicast() || ip.IsLoopback() {
				continue
			}
			return true, ip.String()
		}
	}
	return false, ""
}
