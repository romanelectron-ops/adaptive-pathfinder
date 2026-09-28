package killswitch

import (
	"fmt"
	"net"
)

// B-0402.4 · Я-41.2 — ЧИСТОЕ описание набора WFP-фильтров (без ОС-зависимостей, тестируется везде).
// Боевое применение (marshaling + FwpmFilterAdd) — в wfp_windows.go. Поддержка v4 и v6.

// wfpLogf — приёмник предупреждений WFP-бэкенда. B-0403 · R-6.1 требует, чтобы ситуация
// «LUID туннеля не разрешился» была ВИДНА, а не молча превращалась в пропущенный permit-tun.
// По умолчанию — «в никуда»: бэкенд не должен зависеть от того, подключил ли кто-то логгер.
var wfpLogf = func(string) {}

// SetWFPLogger подключает логгер WFP-бэкенда (служба apf-svc — в свой eventlog).
// Передача nil сбрасывает на «в никуда».
func SetWFPLogger(f func(string)) {
	if f == nil {
		wfpLogf = func(string) {}
		return
	}
	wfpLogf = f
}

// NewWFPBackend возвращает WFP-исполнитель KS (B-0402.4), если платформа поддерживает; иначе (nil,false).
// Интеграция: apf-svc выбирает его при APF_KS_BACKEND=wfp (+admin), иначе netsh-бэкенд (windowsKS).
func NewWFPBackend() (KillSwitch, bool) { return newWFPKS() }

type wfpAction int

const (
	wfpActionPermit wfpAction = iota
	wfpActionBlock
)

type wfpConditionKind int

const (
	wfpCondNone               wfpConditionKind = iota
	wfpCondRemoteAddrV4Range                   // remote IPv4 ∈ addr/mask
	wfpCondRemoteAddrV4Equal                   // remote IPv4 == addr
	wfpCondRemoteAddrV6Range                   // remote IPv6 ∈ addr6/prefix6
	wfpCondLocalInterfaceLUID                  // local interface == LUID (TUN apf0)
)

type wfpCondition struct {
	Kind    wfpConditionKind
	Addr    uint32   // v4 host-order (range/equal)
	Mask    uint32   // v4 маска (range)
	Addr6   [16]byte // v6 адрес
	Prefix6 uint8    // v6 длина префикса (128 = equal)
	LUID    uint64   // интерфейс
}

// wfpFilterSpec — платформо-независимая спецификация одного фильтра.
type wfpFilterSpec struct {
	Name      string
	Action    wfpAction
	Weight    uint8 // permit > block (детерминизм — снимает D-31)
	V6        bool  // фильтр в слое ALE_AUTH_CONNECT_V6
	Condition wfpCondition
}

const (
	wfpWeightPermit uint8 = 15
	wfpWeightBlock  uint8 = 0
)

type v4Range struct{ addr, mask uint32 }

func ipv4ToUint32(ip net.IP) (uint32, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3]), true
}

func cidrToRange(cidr string) v4Range {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil || len(n.Mask) != 4 {
		return v4Range{}
	}
	a, _ := ipv4ToUint32(n.IP)
	m := n.Mask
	return v4Range{a, uint32(m[0])<<24 | uint32(m[1])<<16 | uint32(m[2])<<8 | uint32(m[3])}
}

func ipTo16(ip net.IP) ([16]byte, bool) {
	var a [16]byte
	v6 := ip.To16()
	if v6 == nil {
		return a, false
	}
	copy(a[:], v6)
	return a, true
}

func cidrToV6(cidr string) ([16]byte, uint8) {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return [16]byte{}, 0
	}
	a, _ := ipTo16(n.IP)
	ones, _ := n.Mask.Size()
	return a, uint8(ones)
}

var (
	wfpPrivateRanges = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}
	wfpV6LanRanges   = []string{"fe80::/10", "fc00::/7"} // link-local + ULA
)

func permitV4Range(nameSuffix string, r v4Range) wfpFilterSpec {
	return wfpFilterSpec{Name: ksRuleName + nameSuffix, Action: wfpActionPermit, Weight: wfpWeightPermit,
		Condition: wfpCondition{Kind: wfpCondRemoteAddrV4Range, Addr: r.addr, Mask: r.mask}}
}

func permitV6Range(nameSuffix string, a [16]byte, prefix uint8) wfpFilterSpec {
	return wfpFilterSpec{Name: ksRuleName + nameSuffix, Action: wfpActionPermit, Weight: wfpWeightPermit, V6: true,
		Condition: wfpCondition{Kind: wfpCondRemoteAddrV6Range, Addr6: a, Prefix6: prefix}}
}

func blockAll(nameSuffix string, v6 bool) wfpFilterSpec {
	return wfpFilterSpec{Name: ksRuleName + nameSuffix, Action: wfpActionBlock, Weight: wfpWeightBlock, V6: v6}
}

// wfpVpnNamePrefix — общий префикс имён permit-фильтров узла. targeted-switch (wfp_windows.go)
// снимает по нему ВСЕ такие фильтры, сколько бы их ни было (R-2.3: узел может иметь несколько
// A/AAAA-записей).
const wfpVpnNamePrefix = ksRuleName + "-permit-vpn"

// wfpVpnSpecs возвращает permit-фильтр(ы) для адреса(ов) VPN-узла: каждый IPv4 → permit-vpn-<i>
// (equal), каждый IPv6 → permit-vpn6-<i> (/128). Вход — транспортная форма Я-31.0 (один IP или
// список через запятую). Отдельная функция — чтобы targeted-switch трогал ТОЛЬКО их.
//
// R-2.3 (C-5): в WFP семейства и так разные слои, но раньше функция принимала РОВНО один IP и
// на списке «1.2.3.4,2001:db8::1» ParseIP возвращал nil → permit-vpn не создавался вовсе → WFP
// блокировал само подключение к узлу.
func wfpVpnSpecs(vpnIP string) []wfpFilterSpec {
	v4, v6 := splitVPNIPs(vpnIP)
	specs := make([]wfpFilterSpec, 0, len(v4)+len(v6))
	for i, s := range v4 {
		u, ok := ipv4ToUint32(net.ParseIP(s))
		if !ok {
			continue
		}
		specs = append(specs, wfpFilterSpec{
			Name: fmt.Sprintf("%s-%d", wfpVpnNamePrefix, i), Action: wfpActionPermit, Weight: wfpWeightPermit,
			Condition: wfpCondition{Kind: wfpCondRemoteAddrV4Equal, Addr: u}})
	}
	for i, s := range v6 {
		a, ok := ipTo16(net.ParseIP(s))
		if !ok {
			continue
		}
		specs = append(specs, wfpFilterSpec{
			Name: fmt.Sprintf("%s6-%d", wfpVpnNamePrefix, i), Action: wfpActionPermit, Weight: wfpWeightPermit, V6: true,
			Condition: wfpCondition{Kind: wfpCondRemoteAddrV6Range, Addr6: a, Prefix6: 128}})
	}
	if len(specs) == 0 {
		return nil
	}
	return specs
}

// wfpTunSpecs — permit «весь трафик, уходящий ЧЕРЕЗ интерфейс TUN» (allow-by-interface).
// Это ЕДИНСТВЕННАЯ семантически верная формулировка защиты VPN-режима: она разрешает трафик по
// исходящему интерфейсу, а не по адресу назначения (C-1). Отдельная функция — чтобы её мог
// применить и EnsureTunPermit, когда apf0 поднялся уже ПОСЛЕ включения KS (R-6.1/C-10).
// tunLUID == 0 ⇒ спецификаций нет (интерфейса ещё не существует).
func wfpTunSpecs(tunLUID uint64) []wfpFilterSpec {
	if tunLUID == 0 {
		return nil
	}
	return []wfpFilterSpec{
		{Name: ksRuleName + "-permit-tun", Action: wfpActionPermit, Weight: wfpWeightPermit,
			Condition: wfpCondition{Kind: wfpCondLocalInterfaceLUID, LUID: tunLUID}},
		{Name: ksRuleName + "-permit-tun6", Action: wfpActionPermit, Weight: wfpWeightPermit, V6: true,
			Condition: wfpCondition{Kind: wfpCondLocalInterfaceLUID, LUID: tunLUID}},
	}
}

// wfpBuildPlan строит полный набор (§2 ТЗ): permit loopback/lan/vpn/tun для v4 и v6 + терминальный
// block-all в обоих семействах. vpnIP "" → без permit-vpn; tunLUID 0 → без permit-tun.
func wfpBuildPlan(vpnIP string, tunLUID uint64) []wfpFilterSpec {
	specs := make([]wfpFilterSpec, 0, 16)

	// v4 loopback + lan
	specs = append(specs, permitV4Range("-permit-loopback", cidrToRange("127.0.0.0/8")))
	for i, cidr := range wfpPrivateRanges {
		specs = append(specs, permitV4Range(fmt.Sprintf("-permit-lan-%d", i), cidrToRange(cidr)))
	}
	// v6 loopback + lan
	lb6, _ := ipTo16(net.ParseIP("::1"))
	specs = append(specs, permitV6Range("-permit-loopback6", lb6, 128))
	for i, cidr := range wfpV6LanRanges {
		a, p := cidrToV6(cidr)
		specs = append(specs, permitV6Range(fmt.Sprintf("-permit-lan6-%d", i), a, p))
	}

	// vpn (v4 ИЛИ v6, по адресу)
	specs = append(specs, wfpVpnSpecs(vpnIP)...)

	// tun по LUID — в обоих семействах (LUID семейство-независим)
	specs = append(specs, wfpTunSpecs(tunLUID)...)

	// терминальный блок в обоих семействах
	specs = append(specs, blockAll("-block-all", false), blockAll("-block-all6", true))
	return specs
}
