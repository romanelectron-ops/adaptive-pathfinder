// Package netutil — маленькие сетевые хелперы, общие для нескольких пакетов
// (internal/singbox, internal/relay), которым иначе пришлось бы либо дублировать друг
// друга, либо зависеть друг от друга ради одной функции (риск циклического импорта:
// internal/relay уже зависит от internal/singbox через LocalIPCandidates).
//
// Найдено консилиумом 2026-08-29 (докс docs/TZ_APF_RELAY_v1.0.md §0.2.1): до этого пакета
// в проекте существовали ДВЕ расходящиеся копии isPrivateIPv4 — internal/singbox/local_ip.go
// и internal/relay/reachability.go, — и только вторая учитывала CGNAT-диапазон
// (100.64.0.0/10). Слиты в одну здесь, ДО добавления IPv6-путей (§0.2.1 плана
// PLAN_APF_RELAY_v1.0.md, фаза A) — иначе третья копия того же класса дефекта.
package netutil

import "net"

// Splice сшивает byte-for-byte две стороны соединения (io.Copy в обе стороны) и блокируется,
// пока обе половины не завершатся. Общий хелпер — живёт здесь (не в internal/relay и не в
// internal/singbox), потому что нужен ОБОИМ: internal/relay (RelayServer Entry↔Stream,
// ExitClient Stream↔локальный sing-box, EntryBridge локальное↔Relay) и
// internal/singbox/admission_proxy.go (докс TZ_APF_RELAY_v1.0.md §10.2). internal/relay уже
// импортирует internal/singbox (LocalIPCandidates) — обратный импорт singbox→relay создал бы
// цикл, поэтому общий код живёт в этом независимом от обоих пакете.
func Splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		copyBytes(a, b)
		done <- struct{}{}
	}()
	go func() {
		copyBytes(b, a)
		done <- struct{}{}
	}()
	<-done
	a.Close()
	b.Close()
	<-done
}

func copyBytes(dst, src net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// IsPrivateIPv4 — приватный/не маршрутизируемый извне IPv4-адрес: классические RFC 1918
// диапазоны (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) плюс Carrier-Grade NAT
// (100.64.0.0/10, RFC 6598) — не публичный адрес, даже если не входит в RFC 1918; именно
// такой (100.x.x.x) наблюдался на реальном устройстве оператора связи 2026-08-28. Принимает
// 4-байтовый срез (результат net.IP.To4()) — вызывающая сторона отвечает за то, что это
// действительно IPv4, не IPv6-in-IPv4-обёртка с другой семантикой байт.
func IsPrivateIPv4(ip net.IP) bool {
	return ip[0] == 10 ||
		(ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
		(ip[0] == 192 && ip[1] == 168) ||
		(ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127)
}

// IsPrivateIPv6 — Unique Local Address, RFC 4193 (fc00::/7) — аналог RFC 1918 для IPv6,
// не маршрутизируется в публичном интернете.
func IsPrivateIPv6(ip net.IP) bool {
	return len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc
}

// IsLinkLocalIPv6 — fe80::/10 — действителен только внутри одного сегмента сети, никогда не
// маршрутизируется даже локальным роутером, не годится ни как локальный кандидат для роли
// «Выход», ни тем более как внешний адрес.
func IsLinkLocalIPv6(ip net.IP) bool {
	return len(ip) == net.IPv6len && ip[0] == 0xfe && ip[1]&0xc0 == 0x80
}
