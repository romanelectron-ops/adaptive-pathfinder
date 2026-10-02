package singbox

import (
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"testing"
)

// cidrAddr строит net.Addr так же, как его отдаёт iface.Addrs(): IP — конкретный адрес
// интерфейса, Mask — маска сети.
func cidrAddr(t *testing.T, cidr string) net.Addr {
	t.Helper()
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", cidr, err)
	}
	return &net.IPNet{IP: ip, Mask: ipNet.Mask}
}

func upIface(t *testing.T, name string, cidrs ...string) ifaceSnapshot {
	t.Helper()
	snap := ifaceSnapshot{Name: name, Up: true}
	for _, c := range cidrs {
		snap.Addrs = append(snap.Addrs, cidrAddr(t, c))
	}
	return snap
}

// withNetStubs подменяет перечисление интерфейсов и определение маршрута по умолчанию на время
// теста (outbound == "" — «маршрута по умолчанию нет»): без реальной сети и без привязки к
// машине, на которой идёт go test.
func withNetStubs(t *testing.T, ifaces []ifaceSnapshot, outbound string) {
	t.Helper()
	origList, origOut := listInterfacesFn, outboundIPFn
	listInterfacesFn = func() ([]ifaceSnapshot, error) { return ifaces, nil }
	outboundIPFn = func() net.IP {
		if outbound == "" {
			return nil
		}
		return net.ParseIP(outbound)
	}
	t.Cleanup(func() { listInterfacesFn, outboundIPFn = origList, origOut })
}

func candidateIPs(cands []LocalIPCandidate) []string {
	out := make([]string, 0, len(cands))
	for _, c := range cands {
		out = append(out, c.IP)
	}
	return out
}

// Живой инцидент 2026-09-29: окно подставило в «Хост» адрес вида 172.x.x.1 — адрес виртуального
// коммутатора Hyper-V «Default Switch». Раньше любой приватный адрес шёл впереди любого
// другого, и коммутатор (приватный) обгонял настоящий Wi-Fi. Виртуальный адаптер обязан быть в
// конце списка — но не пропасть из него.
func TestLocalIPCandidates_VirtualSwitchGoesLast(t *testing.T) {
	withNetStubs(t, []ifaceSnapshot{
		upIface(t, "vEthernet (Default Switch)", "172.31.250.1/20"),
		upIface(t, "Wi-Fi", "192.0.2.44/24"),
	}, "")

	got := LocalIPCandidates()
	want := []LocalIPCandidate{
		{IP: "192.0.2.44", InterfaceName: "Wi-Fi"},
		{IP: "172.31.250.1", InterfaceName: "vEthernet (Default Switch)"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LocalIPCandidates() = %+v, ожидалось %+v (виртуальный коммутатор — в конец, не удалять)", got, want)
	}
}

// Адрес интерфейса маршрута по умолчанию — первый, даже если по порядку перечисления он
// позже других физических приватных.
func TestLocalIPCandidates_DefaultRouteAddressFirst(t *testing.T) {
	ifaces := []ifaceSnapshot{
		upIface(t, "Ethernet", "10.1.2.3/24"),
		upIface(t, "Wi-Fi", "192.168.1.5/24"),
	}

	withNetStubs(t, ifaces, "192.168.1.5")
	got := candidateIPs(LocalIPCandidates())
	if want := []string{"192.168.1.5", "10.1.2.3"}; !reflect.DeepEqual(got, want) {
		t.Errorf("с маршрутом по умолчанию через Wi-Fi: %v, ожидалось %v", got, want)
	}

	// Маршрута нет (сеть отключена) — порядок перечисления, ничего не теряется.
	withNetStubs(t, ifaces, "")
	got = candidateIPs(LocalIPCandidates())
	if want := []string{"10.1.2.3", "192.168.1.5"}; !reflect.DeepEqual(got, want) {
		t.Errorf("без маршрута по умолчанию: %v, ожидалось %v", got, want)
	}
}

// Адрес маршрута по умолчанию, которого НЕТ среди интерфейсов, не становится кандидатом —
// «первым» может быть только реально существующий адрес.
func TestLocalIPCandidates_OutboundNotAmongInterfacesIgnored(t *testing.T) {
	withNetStubs(t, []ifaceSnapshot{upIface(t, "Wi-Fi", "192.168.1.5/24")}, "198.51.100.99")

	got := candidateIPs(LocalIPCandidates())
	if want := []string{"192.168.1.5"}; !reflect.DeepEqual(got, want) {
		t.Errorf("LocalIPCandidates() = %v, ожидалось %v (выдуманный адрес в список попасть не должен)", got, want)
	}
}

// Хост, у которого настоящий адаптер «отдан» внешнему виртуальному коммутатору Hyper-V
// (vEthernet (External)), выходит в сеть именно через него — маршрут по умолчанию главнее
// имени адаптера.
func TestLocalIPCandidates_DefaultRouteOnVirtualSwitchStillFirst(t *testing.T) {
	withNetStubs(t, []ifaceSnapshot{
		upIface(t, "Ethernet", "10.1.2.3/24"),
		upIface(t, "vEthernet (External)", "192.168.1.5/24"),
	}, "192.168.1.5")

	got := candidateIPs(LocalIPCandidates())
	if want := []string{"192.168.1.5", "10.1.2.3"}; !reflect.DeepEqual(got, want) {
		t.Errorf("LocalIPCandidates() = %v, ожидалось %v", got, want)
	}
}

// При включённом VPN-режиме APF маршрут по умолчанию ведёт в собственный TUN (apf0), и
// «адрес маршрута по умолчанию» оказывается адресом туннеля — его нельзя ставить первым.
func TestLocalIPCandidates_DefaultRouteOnTunnelNotPromoted(t *testing.T) {
	withNetStubs(t, []ifaceSnapshot{
		upIface(t, "apf0", "172.19.0.1/30"),
		upIface(t, "Wi-Fi", "192.168.1.5/24"),
	}, "172.19.0.1")

	got := candidateIPs(LocalIPCandidates())
	if want := []string{"192.168.1.5", "172.19.0.1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("LocalIPCandidates() = %v, ожидалось %v (адрес туннеля — в конец)", got, want)
	}
}

// На части прошивок Android адаптер VPN-сервиса называется не «tun0»/«apf0», но адрес у
// собственного TUN APF фиксирован — по нему его тоже узнаём (как и Kotlin-сторона): адрес
// туннеля не ставится первым, даже когда он же — «маршрут по умолчанию», и уходит в конец.
func TestLocalIPCandidates_OwnTunAddressRecognisedByAddress(t *testing.T) {
	withNetStubs(t, []ifaceSnapshot{
		upIface(t, "VPN-adapter-x", "172.19.0.1/30"),
		upIface(t, "wlan0", "192.168.1.5/24"),
	}, "172.19.0.1")

	got := candidateIPs(LocalIPCandidates())
	if want := []string{"192.168.1.5", "172.19.0.1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("LocalIPCandidates() = %v, ожидалось %v", got, want)
	}
}

// Константа адреса собственного TUN не должна разойтись с тем, что реально настраивает
// config_builder.go.
func TestAPFTunHostIPv4_MatchesConfigBuilder(t *testing.T) {
	if want := apfTunHostIPv4 + "/30"; tunAddressV4 != want {
		t.Errorf("tunAddressV4 = %q, а apfTunHostIPv4+\"/30\" = %q — обновите apfTunHostIPv4 в local_ip.go", tunAddressV4, want)
	}
}

// Link-local (169.254/16), 0.0.0.0 и 127/8 — не кандидаты вообще; down/loopback-интерфейсы и
// IPv6 пропускаются, как и раньше.
func TestLocalIPCandidates_ExcludesLinkLocalUnspecifiedAndSkippedInterfaces(t *testing.T) {
	down := upIface(t, "Ethernet 3", "192.168.50.7/24")
	down.Up = false
	lo := upIface(t, "lo", "127.0.0.1/8")
	lo.Loopback = true
	withNetStubs(t, []ifaceSnapshot{
		upIface(t, "Ethernet 2", "169.254.7.7/16", "0.0.0.0/0", "127.0.0.2/8", "fe80::1/64", "2001:db8::5/64"),
		down,
		lo,
		upIface(t, "Wi-Fi", "192.168.1.5/24"),
	}, "")

	got := candidateIPs(LocalIPCandidates())
	if want := []string{"192.168.1.5"}; !reflect.DeepEqual(got, want) {
		t.Errorf("LocalIPCandidates() = %v, ожидалось %v (link-local/0.0.0.0/loopback/IPv6/down — вон)", got, want)
	}
}

// Внутри физических: приватные впереди публичных; виртуальные — после всех физических
// (сами тоже приватные впереди), при этом ни один адрес не пропадает.
func TestLocalIPCandidates_FullOrdering(t *testing.T) {
	withNetStubs(t, []ifaceSnapshot{
		upIface(t, "docker0", "172.17.0.1/16"),
		upIface(t, "Ethernet", "198.51.100.7/24"),
		upIface(t, "VMware Network Adapter VMnet8", "192.0.2.200/24"),
		upIface(t, "wlan0", "192.168.1.5/24"),
	}, "")

	got := candidateIPs(LocalIPCandidates())
	want := []string{"192.168.1.5", "198.51.100.7", "172.17.0.1", "192.0.2.200"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("LocalIPCandidates() = %v, ожидалось %v", got, want)
	}
}

// Один и тот же адрес на двух интерфейсах (мост + физический) — один кандидат.
func TestLocalIPCandidates_DeduplicatesSameIP(t *testing.T) {
	withNetStubs(t, []ifaceSnapshot{
		upIface(t, "Ethernet", "192.168.1.5/24"),
		upIface(t, "vEthernet (External)", "192.168.1.5/24"),
	}, "192.168.1.5")

	got := LocalIPCandidates()
	if len(got) != 1 || got[0].IP != "192.168.1.5" {
		t.Errorf("LocalIPCandidates() = %+v, ожидался ровно один 192.168.1.5", got)
	}
}

// Ошибка перечисления интерфейсов — не паника и не мусор: пустой результат (вызывающая сторона
// оставляет «Хост» для ручного ввода).
func TestLocalIPCandidates_EnumerationErrorGivesNone(t *testing.T) {
	origList, origOut := listInterfacesFn, outboundIPFn
	listInterfacesFn = func() ([]ifaceSnapshot, error) { return nil, errors.New("netlink: отказано") }
	outboundIPFn = func() net.IP { return net.ParseIP("192.168.1.5") }
	t.Cleanup(func() { listInterfacesFn, outboundIPFn = origList, origOut })

	if got := LocalIPCandidates(); len(got) != 0 {
		t.Errorf("LocalIPCandidates() = %+v, ожидалось пусто", got)
	}
}

// Настоящее определение маршрута по умолчанию не должно ни паниковать, ни возвращать
// нерабочие значения (0.0.0.0, link-local): по контракту — либо nil, либо адрес.
func TestDefaultRouteIP_NoPanicAndSane(t *testing.T) {
	ip := defaultRouteIP()
	if ip == nil {
		return // сети/маршрута нет — допустимо
	}
	if ip.IsUnspecified() {
		t.Errorf("defaultRouteIP() = %v — 0.0.0.0 не адрес интерфейса", ip)
	}
}

// Контракт JSON (Kotlin/Wails разбирают эти поля) не менялся.
func TestLocalIPCandidate_JSONContractUnchanged(t *testing.T) {
	data, err := json.Marshal(LocalIPCandidate{IP: "192.0.2.44", InterfaceName: "Wi-Fi"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"ip":"192.0.2.44","interface_name":"Wi-Fi"}`; string(data) != want {
		t.Errorf("JSON = %s, ожидалось %s", data, want)
	}
}

func TestIsVirtualInterfaceName(t *testing.T) {
	virtual := []string{
		"vEthernet (Default Switch)", "vEthernet (WSL)", "vEthernet (External)",
		"Hyper-V Virtual Ethernet Adapter", "VMware Network Adapter VMnet8", "vmnet1",
		"VirtualBox Host-Only Network", "vboxnet0", "docker0", "veth1a2b3c", "virbr0",
		"br-3f2a9c", "Loopback Pseudo-Interface 1", "WSL",
		"apf0", "tun0", "utun3", "Wintun Userspace Tunnel", "Teredo Tunneling Pseudo-Interface",
	}
	for _, n := range virtual {
		if !IsVirtualInterfaceName(n) {
			t.Errorf("IsVirtualInterfaceName(%q) = false, ожидалось true", n)
		}
	}
	physical := []string{
		"Wi-Fi", "Ethernet", "Ethernet 2", "wlan0", "eth0", "en0", "ccmni1", "rmnet_data0",
		"Беспроводная сеть", "Подключение по локальной сети", "Local Area Connection* 10", "",
	}
	for _, n := range physical {
		if IsVirtualInterfaceName(n) {
			t.Errorf("IsVirtualInterfaceName(%q) = true, ожидалось false", n)
		}
	}
}

// Ревью 2026-09-30: один и тот же адрес на виртуальном и физическом адаптере. Дубликат
// отбрасывался по ПЕРВОМУ встреченному интерфейсу — если виртуальный шёл в перечислении раньше,
// адрес получал метку виртуального и уезжал в конец списка (и Detect потом отбрасывал его по имени).
// Теперь класс и имя такого адреса определяет физический адаптер.
func TestLocalIPCandidates_DuplicateIPPrefersPhysicalAdapter(t *testing.T) {
	withNetStubs(t, []ifaceSnapshot{
		upIface(t, "vEthernet (External)", "192.168.1.5/24"),
		upIface(t, "Ethernet", "192.168.1.5/24"),
		upIface(t, "Wi-Fi", "10.1.2.3/24"),
	}, "")

	got := LocalIPCandidates()
	if len(got) != 2 {
		t.Fatalf("LocalIPCandidates() = %+v, ожидалось два адреса", got)
	}
	if got[0].IP != "192.168.1.5" || got[0].InterfaceName != "Ethernet" {
		t.Errorf("первым должен идти 192.168.1.5 с именем физического адаптера (Ethernet), получено %+v", got[0])
	}
	if IsVirtualInterfaceName(got[0].InterfaceName) {
		t.Errorf("адрес, стоящий и на физическом адаптере, помечен виртуальным: %+v", got[0])
	}
}

// IsDefaultRoute ставится только у адреса интерфейса маршрута по умолчанию и НЕ попадает в JSON
// (контракт окон — ip, interface_name).
func TestLocalIPCandidates_DefaultRouteFlag(t *testing.T) {
	withNetStubs(t, []ifaceSnapshot{
		upIface(t, "Ethernet", "10.1.2.3/24"),
		upIface(t, "vEthernet (External)", "192.168.1.5/24"),
	}, "192.168.1.5")

	got := LocalIPCandidates()
	if len(got) != 2 || !got[0].IsDefaultRoute || got[0].IP != "192.168.1.5" {
		t.Fatalf("первым — адрес маршрута по умолчанию с IsDefaultRoute=true, получено %+v", got)
	}
	if got[1].IsDefaultRoute {
		t.Errorf("IsDefaultRoute у второго кандидата: %+v", got[1])
	}
	data, err := json.Marshal(got[0])
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"ip":"192.168.1.5","interface_name":"vEthernet (External)"}`; string(data) != want {
		t.Errorf("JSON = %s, ожидалось %s (IsDefaultRoute в JSON не идёт)", data, want)
	}
}

func TestIsLinkLocalIPv4(t *testing.T) {
	cases := map[string]bool{
		"169.254.0.1": true, "169.254.255.255": true,
		"169.253.255.255": false, "169.255.0.1": false, "192.168.1.5": false, "203.0.113.1": false,
	}
	for s, want := range cases {
		if got := IsLinkLocalIPv4(net.ParseIP(s)); got != want {
			t.Errorf("IsLinkLocalIPv4(%s) = %v, ожидалось %v", s, got, want)
		}
	}
	if IsLinkLocalIPv4(net.ParseIP("fe80::1")) {
		t.Error("IsLinkLocalIPv4(fe80::1) = true — это IPv6, не 169.254/16")
	}
}
