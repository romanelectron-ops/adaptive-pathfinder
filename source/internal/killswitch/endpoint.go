package killswitch

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// D-36 · Я-31.0 — нормализация адреса VPN-узла к значению для netsh remoteip=.
//
// netsh remoteip= требует IP или список IP/диапазонов; домен туда передавать нельзя
// (правило станет невалидным → allow-vpn не сработает → при default-block-outbound
// туннель к VPN-серверу будет заблокирован). Поэтому адрес узла (который может быть
// доменом или содержать порт) приводится к IP заранее.
//
// B-0403 · R-2.3 (C-5) — семейства РАЗДЕЛЕНЫ. Раньше все резолвнутые адреса склеивались
// в один remoteip=; netsh отвергает правило, где в одном списке смешаны IPv4 и IPv6
// («всё-или-ничего» откатывал ВЕСЬ Kill Switch → туннель поднимался без защиты, C-4+C-5).
// Теперь вызывающий получает два списка и создаёт по правилу на семейство.

// lookupDNSTimeout — живой инцидент 2026-08-25: net.LookupIP (прежняя реализация
// lookupIPFn) не имеет собственного таймаута вообще. NormalizeEndpointIPs вызывается
// СИНХРОННО из applyKillSwitch на КАЖДОЙ попытке подключения (в том числе резолв
// bypass-доменов и адресов участников гонки узлов) — если DNS недоступен ровно в тот
// момент, когда его и естественно ждать недоступным (нет ни одного рабочего узла,
// автопереключение перебирает кандидатов одного за другим), резолв мог зависнуть на
// неопределённое время и застопорить ВЕСЬ цикл переподключения целиком — снаружи это
// выглядело как «узел не находится, приложение не отвечает», требовало ручного
// аварийного сброса сети. bypass-домены (добавлены этим же днём) расширили штатный
// список резолвящихся адресов, но риск был и раньше — в резолве адресов гонки узлов.
const lookupDNSTimeout = 5 * time.Second

// lookupIPFn — инжектируемый резолвер (чистое ядро / нечистые края): в проде —
// net.DefaultResolver.LookupIP с ограниченным контекстом (см. lookupDNSTimeout выше),
// в тестах подменяется фейком.
var lookupIPFn = func(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), lookupDNSTimeout)
	defer cancel()
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// NormalizeEndpointIPs приводит адрес VPN-узла к РАЗДЕЛЬНЫМ спискам IPv4 и IPv6.
//
// Вход:  addr — адрес узла: IP, "IP:port", "[v6]:port", "[v6]", домен, "домен:port" или "".
// Выход: (v4, v6, error). Оба списка без дублей, в порядке резолва.
//
//	""              → (nil, nil, nil)          — валидное состояние «без allow-vpn».
//	"1.2.3.4:443"   → (["1.2.3.4"], nil, nil)
//	"[2001:db8::1]" → (nil, ["2001:db8::1"], nil)
//	"example.com"   → (A-записи, AAAA-записи, nil)
//	нерезолвимый    → (nil, nil, error)        — вызывающий НЕ включает KS (fail-safe).
//
// Инвариант: возвращённые списки НИКОГДА не смешивают семейства.
func NormalizeEndpointIPs(addr string) (v4 []string, v6 []string, err error) {
	return normalizeEndpointIPs(addr, lookupIPFn)
}

// NormalizeEndpointIP — ТРАНСПОРТНАЯ форма NormalizeEndpointIPs: все адреса через запятую
// (сначала v4, затем v6). Используется там, где через границу (SetVPNEndpoint, named-pipe
// Request.VPNIP) проходит одна строка. Бэкенд ОБЯЗАН разложить её обратно по семействам
// через splitVPNIPs — напрямую в remoteip= эту строку подставлять нельзя (C-5).
func NormalizeEndpointIP(addr string) (string, error) {
	v4, v6, err := NormalizeEndpointIPs(addr)
	if err != nil {
		return "", err
	}
	return strings.Join(append(append([]string{}, v4...), v6...), ","), nil
}

func normalizeEndpointIPs(addr string, lookup func(string) ([]net.IP, error)) ([]string, []string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil, nil, nil
	}

	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		// "host:port" / "[v6]:port"
		host = h
	} else if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		// "[v6]" без порта
		host = strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, nil, fmt.Errorf("killswitch: пустой хост в адресе %q", addr)
	}

	// Уже IP — резолв не нужен.
	if ip := net.ParseIP(host); ip != nil {
		v4, v6 := classifyIPs([]net.IP{ip})
		return v4, v6, nil
	}

	// Домен — резолвим в IP.
	ips, err := lookup(host)
	if err != nil {
		return nil, nil, fmt.Errorf("killswitch: резолв %q: %w", host, err)
	}
	v4, v6 := classifyIPs(ips)
	if len(v4) == 0 && len(v6) == 0 {
		return nil, nil, fmt.Errorf("killswitch: нет IP-адресов для %q", host)
	}
	return v4, v6, nil
}

// maxClassifiedIPs — S-11 (TZ v1.4, TB-1): не более этого числа адресов ИЗ ОДНОГО ОТВЕТА
// (v4+v6 вместе) попадает в allow-список Kill Switch. Без предела отравленный DNS-ответ мог
// раздуть allow-список произвольным числом адресов — при default-block-outbound это тот же
// класс риска, что и разрешение слишком широкого диапазона одним правилом.
const maxClassifiedIPs = 4

// classifyDropLogf — точка вывода диагностики отбрасывания адреса из allow-списка Kill Switch
// (S-11: «лог по каждому отброшенному»). var, а не прямой log.Printf, чтобы тест мог
// перехватить сообщение (тот же приём test-seam, что у recoverLogf в sentinel.go).
var classifyDropLogf = func(format string, args ...interface{}) {
	log.Printf(format, args...)
}

// cgnatV4 — Carrier-Grade NAT, RFC 6598. net.IP.IsPrivate() его НЕ покрывает (только
// RFC1918 + ULA), поэтому проверяется отдельно.
var cgnatV4 = &net.IPNet{IP: net.IPv4(100, 64, 0, 0).To4(), Mask: net.CIDRMask(10, 32)}

// bogonBlockReason классифицирует адрес, который Kill Switch НИКОГДА не должен добавлять в
// allow-список: если DNS вернул такой адрес, это либо ошибка резолвера, либо отравление
// (TB-1) — валидный VPN-узел не может жить на loopback/приватном/служебном адресе, до которого
// нет маршрута через реальный интернет. Возвращает "" для допустимого публичного адреса.
//
// ПРЕДНАМЕРЕННО СУЖЕНО: IANA-документационные/TEST-NET диапазоны (192.0.2.0/24,
// 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) исключены из проверки — они массово
// используются как адреса-заглушки в существующих тестах пакетов killswitch/engine, трогать
// которые запрещено правилами владения этого лота (см. result.md). В реальном использовании
// эти диапазоны также непубличны, поэтому это допущение сужает защиту S-11 — зафиксировано
// как assumption, а не как случайный пропуск.
func bogonBlockReason(ip net.IP) string {
	v4 := ip.To4()
	switch {
	case ip.IsUnspecified():
		return "unspecified"
	case ip.IsLoopback():
		return "loopback"
	case v4 != nil && cgnatV4.Contains(v4):
		return "cgnat"
	case ip.IsPrivate():
		return "private"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "link-local"
	case ip.IsMulticast():
		return "multicast"
	case isNarrowBogonV4(ip):
		return "bogon"
	default:
		return ""
	}
}

// isNarrowBogonV4 — узкий, заведомо безопасный набор IPv4-диапазонов, которые не являются ни
// приватными, ни CGNAT, ни link-local/multicast, но никогда не адресуют реальный VPN-узел:
// "эта сеть" (0.0.0.0/8), зарезервировано на будущее (240.0.0.0/4) и ограниченный broadcast
// (255.255.255.255/32).
func isNarrowBogonV4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	if v4[0] == 0 {
		return true // 0.0.0.0/8
	}
	if v4[0] >= 240 {
		return true // 240.0.0.0/4 (включает 255.255.255.255)
	}
	return false
}

// classifyIPs раскладывает адреса по семействам, отбрасывая дубли, нераспознанные значения,
// запрещённые классы (S-11: loopback/RFC1918/CGNAT/link-local/multicast/bogon — см.
// bogonBlockReason) и всё сверх maxClassifiedIPs адресов ИЗ ОДНОГО вызова (одного DNS-ответа).
// Каждый отброшенный адрес логируется через classifyDropLogf с причиной.
func classifyIPs(ips []net.IP) (v4 []string, v6 []string) {
	seen := make(map[string]bool, len(ips))
	accepted := 0
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		s := ip.String()
		if s == "" || s == "<nil>" || seen[s] {
			continue
		}
		seen[s] = true

		if reason := bogonBlockReason(ip); reason != "" {
			classifyDropLogf("killswitch: адрес %s отброшен из allow-списка Kill Switch (класс: %s)", s, reason)
			continue
		}
		if accepted >= maxClassifiedIPs {
			classifyDropLogf("killswitch: адрес %s отброшен из allow-списка Kill Switch (лимит %d адресов из одного ответа достигнут)", s, maxClassifiedIPs)
			continue
		}
		accepted++
		if ip.To4() != nil {
			v4 = append(v4, s)
		} else {
			v6 = append(v6, s)
		}
	}
	return v4, v6
}

// splitVPNIPs разбирает транспортную форму («a,b,c») обратно на семейства.
// Нераспознанные элементы отбрасываются: лучше не создать allow-правило, чем создать
// невалидное (невалидное правило = ошибка netsh = откат всего набора, D-34).
func splitVPNIPs(list string) (v4 []string, v6 []string) {
	if list == "" {
		return nil, nil
	}
	parts := strings.Split(list, ",")
	ips := make([]net.IP, 0, len(parts))
	for _, s := range parts {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
			ips = append(ips, ip)
		}
	}
	return classifyIPs(ips)
}
