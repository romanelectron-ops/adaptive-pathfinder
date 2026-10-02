package singbox

import (
	"net"
	"strings"

	"github.com/apf/adaptive-pathfinder/internal/netutil"
)

// LocalIPCandidate — один вариант локального адреса этого устройства для роли «Выход».
type LocalIPCandidate struct {
	IP            string `json:"ip"`
	InterfaceName string `json:"interface_name"`
	// IsDefaultRoute — это адрес интерфейса маршрута по умолчанию (см. defaultRouteIP). Не
	// сериализуется: JSON-контракт для окон (ip, interface_name) не меняется. Нужен internal/relay:
	// адрес на виртуальном адаптере годится для UPnP/«видно снаружи» только если именно через
	// этот адаптер система выходит в сеть (внешний виртуальный коммутатор Hyper-V, «vEthernet
	// (External)») — иначе Detect не нашёл бы ни одного адреса на таком хосте (ревью 2026-09-30).
	IsDefaultRoute bool `json:"-"`
}

// ifaceSnapshot — снимок одного сетевого интерфейса: ровно то, что нужно LocalIPCandidates.
// Введён ради шва listInterfacesFn: net.Interfaces() отдаёт живую систему, а порядок
// кандидатов (виртуальный коммутатор Hyper-V против настоящего Wi-Fi) надо проверять без
// реальной сети и без привязки к машине, на которой идёт go test.
type ifaceSnapshot struct {
	Name     string
	Up       bool
	Loopback bool
	Addrs    []net.Addr
}

// Швы для тестов (тот же приём, что upnpAddPortMappingFn/stunDetectFn в internal/relay).
var (
	listInterfacesFn = listInterfaces
	outboundIPFn     = defaultRouteIP
)

func listInterfaces() ([]ifaceSnapshot, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]ifaceSnapshot, 0, len(ifaces))
	for _, iface := range ifaces {
		snap := ifaceSnapshot{
			Name:     iface.Name,
			Up:       iface.Flags&net.FlagUp != 0,
			Loopback: iface.Flags&net.FlagLoopback != 0,
		}
		// Адреса нужны только у поднятых не-loopback интерфейсов — остальные LocalIPCandidates
		// всё равно пропустит, а iface.Addrs() на Windows — отдельный системный вызов.
		if snap.Up && !snap.Loopback {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			snap.Addrs = addrs
		}
		out = append(out, snap)
	}
	return out, nil
}

// defaultRouteIP возвращает адрес интерфейса маршрута по умолчанию — тот, с которого система
// сама отправила бы пакет в интернет. Пакетов НЕ шлёт: connect() у UDP-сокета лишь просит у
// ядра маршрут до адреса и фиксирует исходящий адрес (LocalAddr), в сеть при этом ничего не
// уходит. 203.0.113.1 — TEST-NET-3 (RFC 5737): на него гарантированно ничего не отвечает, но
// маршрут по умолчанию к нему существует ровно тогда, когда есть маршрут в интернет. Нет
// маршрута (сеть отключена) — Dial возвращает ошибку, nil означает «не знаю».
func defaultRouteIP() net.IP {
	conn, err := net.Dial("udp", "203.0.113.1:9")
	if err != nil {
		return nil
	}
	defer conn.Close()
	ua, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil
	}
	return ua.IP
}

// virtualInterfaceMarkers — подстроки (в нижнем регистре) имён адаптеров, которые создают
// гипервизоры, контейнеры и WSL для связи с гостями, а НЕ выходят в сеть хоста сами по себе.
// Живой инцидент 2026-09-29: окно роли «Выход» подставило в поле «Хост» адрес вида 172.x.x.1 — это
// «vEthernet (Default Switch)» Hyper-V, приватный адрес, который «Вход» из настоящей сети
// достичь не может, а настоящий Wi-Fi ноутбука в списке шёл позже (порядок был «любой
// приватный первым»).
var virtualInterfaceMarkers = []string{
	"vethernet", "wsl", "hyper-v", "vmware", "vmnet", "virtualbox", "vboxnet",
	"docker", "veth", "virbr", "br-", "loopback", "default switch",
}

// IsVirtualInterfaceName — имя адаптера похоже на виртуальный (гипервизор/контейнер/WSL/
// туннель). Экспортируется для internal/relay: Detect не должен брать такой адрес ни как
// «устройство видно снаружи напрямую», ни как внутренний адрес для UPnP-проброса.
func IsVirtualInterfaceName(name string) bool {
	lower := strings.ToLower(name)
	for _, m := range virtualInterfaceMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return isTunnelInterfaceName(lower)
}

// apfTunHostIPv4 — адрес собственного TUN-интерфейса APF (tunAddressV4 из config_builder.go
// без маски; совпадение проверяет тест TestAPFTunHostIPv4_MatchesConfigBuilder).
const apfTunHostIPv4 = "172.19.0.1"

// isTunnelInterfaceName — туннельные адаптеры: собственный TUN APF («apf0»), wintun,
// сторонние VPN («... Tunnel»). Адрес на них — адрес виртуальной сети поверх настоящей, а не
// адрес, по которому достучится «Вход»; по той же причине он не может быть «адресом маршрута
// по умолчанию» для подстановки в «Хост» (при включённом VPN-режиме APF маршрут по умолчанию
// ведёт как раз в apf0). Имена tun0/utun3 (Linux/Android/macOS) начинаются с «tun»; как
// подстроку «tun» не ищем — она встречается в обычных словах. Принимает имя в нижнем регистре.
func isTunnelInterfaceName(lower string) bool {
	return strings.HasPrefix(lower, "tun") || strings.HasPrefix(lower, "utun") ||
		strings.Contains(lower, "apf0") || strings.Contains(lower, "wintun") ||
		strings.Contains(lower, "tunnel")
}

// IsLinkLocalIPv4 — 169.254.0.0/16 (APIPA): адрес, который Windows/Android назначают сами,
// когда DHCP не ответил. Наружу не маршрутизируется никогда и в «Хост» ссылки не годится.
func IsLinkLocalIPv4(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 169 && v4[1] == 254
}

// usableLocalIPv4 — адрес вообще может быть кандидатом: не «0.0.0.0», не link-local, не 127/8.
func usableLocalIPv4(ip4 net.IP) bool {
	return !ip4.IsUnspecified() && !ip4.IsLoopback() && !IsLinkLocalIPv4(ip4)
}

// LocalIPCandidates перечисляет вероятные локальные IPv4-адреса этого устройства — живой
// вопрос 2026-08-27: почему для ссылки роли «Выход» нужно вводить IP вручную, разве
// программа не может определить его сама? Не угадывает ЕДИНСТВЕННО верный ответ: при
// нескольких активных интерфейсах угадать однозначно нельзя — у ноутбука кабель/Wi-Fi/
// USB-модем ведут в РАЗНЫЕ сети, у телефона Wi-Fi и мобильная сеть тоже; какой из них
// физически достижим для «Входа» решает топология сети (роутер, NAT, проброс портов), не
// сама программа. Вместо этого даёт КАНДИДАТОВ на выбор — избавляет от необходимости
// узнавать свой IP вручную (ipconfig/настройки телефона), не отбирая решение там, где оно
// принципиально зависит от контекста, которого программа не видит.
//
// Порядок списка осмысленный (первый — то, что окно подставит в «Хост» по умолчанию):
//
//  1. адрес интерфейса маршрута по умолчанию (см. defaultRouteIP) — с него система сама
//     выходит в сеть, это почти всегда тот адрес, который нужен; не берётся, если стоит на
//     туннельном адаптере (свой TUN/VPN: адрес виртуальной сети, не сети устройства);
//
//  2. физические приватные адреса (192.168.*, 10.*, 172.16-31.*, 100.64/10);
//
//  3. физические непубличные/публичные остальные (настоящий публичный IP на интерфейсе);
//
//  4. ВИРТУАЛЬНЫЕ адаптеры (Hyper-V/WSL/VMware/VirtualBox/Docker/туннели, см.
//     virtualInterfaceMarkers) — в самом конце и не удаляются: на машине, где хост сам сидит
//     в виртуальной сети, такой адрес может оказаться нужным.
//
//     Тело:      перебирает интерфейсы, пропускает down/loopback интерфейсы, IPv6-адреса
//     (роль «Выход» сегодня собирает vless-ссылку с IPv4/доменным host — IPv6 за
//     рамками этой функции), а также 0.0.0.0, 127/8 и link-local 169.254.0.0/16 —
//     тот не маршрутизируется никогда. Один и тот же адрес не повторяется.
//     Выход:     пустой слайс, если ни одного адреса не нашлось — не ошибка, вызывающая
//     сторона просто оставляет поле Host пустым для ручного ввода (прежнее
//     поведение до этого фикса).
func LocalIPCandidates() []LocalIPCandidate {
	ifaces, err := listInterfacesFn()
	if err != nil {
		return nil
	}

	var outbound string
	if ip := outboundIPFn(); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			outbound = v4.String()
		}
	}

	var (
		first                                          LocalIPCandidate
		haveFirst                                      bool
		physPrivate, physOther, virtPrivate, virtOther []LocalIPCandidate
	)
	// Предпроход: один и тот же адрес может стоять на виртуальном И на физическом адаптере
	// (мост, общий доступ к сети). Дубликат отбрасывался по первому встреченному интерфейсу, и если
	// виртуальный шёл в перечислении раньше — адрес получал метку виртуального и уезжал в конец
	// списка (ревью 2026-09-30). Теперь для такого адреса берётся физический адаптер.
	physicalName := make(map[string]string)
	for _, iface := range ifaces {
		if !iface.Up || iface.Loopback || IsVirtualInterfaceName(iface.Name) {
			continue
		}
		for _, addr := range iface.Addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ip4 := ipNet.IP.To4(); ip4 != nil && usableLocalIPv4(ip4) {
					if _, dup := physicalName[ip4.String()]; !dup {
						physicalName[ip4.String()] = iface.Name
					}
				}
			}
		}
	}

	seen := make(map[string]bool)
	for _, iface := range ifaces {
		if !iface.Up || iface.Loopback {
			continue
		}
		ifaceVirtual := IsVirtualInterfaceName(iface.Name)
		ifaceTunnel := isTunnelInterfaceName(strings.ToLower(iface.Name))
		for _, addr := range iface.Addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil || !usableLocalIPv4(ip4) {
				continue
			}
			ipStr := ip4.String()
			if seen[ipStr] {
				continue
			}
			seen[ipStr] = true
			ifaceName := iface.Name
			if phys, ok := physicalName[ipStr]; ok && ipStr != apfTunHostIPv4 {
				// Адрес есть и на физическом адаптере — он и определяет класс и имя кандидата.
				ifaceName, ifaceVirtual, ifaceTunnel = phys, false, false
			}
			// Собственный TUN APF узнаём и по фиксированному адресу: имя адаптера у VPN-сервиса
			// на части прошивок Android отличается от «apf0»/«tun0», а адрес — нет (то же делает
			// Kotlin-сторона, MainActivity.localIpCandidates).
			virtual := ifaceVirtual || ipStr == apfTunHostIPv4
			tunnel := ifaceTunnel || ipStr == apfTunHostIPv4
			cand := LocalIPCandidate{IP: ipStr, InterfaceName: ifaceName}
			private := netutil.IsPrivateIPv4(ip4)
			switch {
			case ipStr == outbound && !tunnel:
				cand.IsDefaultRoute = true
				first, haveFirst = cand, true
			case virtual && private:
				virtPrivate = append(virtPrivate, cand)
			case virtual:
				virtOther = append(virtOther, cand)
			case private:
				physPrivate = append(physPrivate, cand)
			default:
				physOther = append(physOther, cand)
			}
		}
	}

	var out []LocalIPCandidate
	if haveFirst {
		out = append(out, first)
	}
	out = append(out, physPrivate...)
	out = append(out, physOther...)
	out = append(out, virtPrivate...)
	out = append(out, virtOther...)
	return out
}
