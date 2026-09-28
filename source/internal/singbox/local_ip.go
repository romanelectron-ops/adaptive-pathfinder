package singbox

import (
	"net"

	"github.com/apf/adaptive-pathfinder/internal/netutil"
)

// LocalIPCandidate — один вариант локального адреса этого устройства для роли «Выход».
type LocalIPCandidate struct {
	IP            string `json:"ip"`
	InterfaceName string `json:"interface_name"`
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
//	Тело:      перебирает net.Interfaces(), пропускает down/loopback интерфейсы и IPv6-
//	           адреса (роль «Выход» сегодня собирает vless-ссылку с IPv4/доменным host —
//	           IPv6 за рамками этой функции). Приватные диапазоны (192.168.*, 10.*,
//	           172.16-31.*) — впереди списка как наиболее вероятный кандидат для
//	           локальной сети; остальные (интерфейс с настоящим публичным IP) — следом.
//	Выход:     пустой слайс, если ни одного адреса не нашлось — не ошибка, вызывающая
//	           сторона просто оставляет поле Host пустым для ручного ввода (прежнее
//	           поведение до этого фикса).
func LocalIPCandidates() []LocalIPCandidate {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var private, other []LocalIPCandidate
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil {
				continue
			}
			cand := LocalIPCandidate{IP: ip4.String(), InterfaceName: iface.Name}
			if netutil.IsPrivateIPv4(ip4) {
				private = append(private, cand)
			} else {
				other = append(other, cand)
			}
		}
	}
	return append(private, other...)
}
