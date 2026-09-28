package web

import (
	"regexp"
	"sort"
	"strings"
)

// DomainRouteResult — куда реально ушёл трафик конкретного домена: напрямую (в обход
// туннеля) или через один из VPN-outbound'ов sing-box.
type DomainRouteResult struct {
	Domain   string `json:"domain"`
	Outbound string `json:"outbound"` // "direct", "shadowsocks", "vless" и т.п. — как в логе sing-box
	Direct   bool   `json:"direct"`
}

var (
	ansiCodeRe   = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	sniffDomain  = regexp.MustCompile(`\[(\d+) \S+\] router: sniffed protocol: \S+, domain: (\S+)`)
	outboundLine = regexp.MustCompile(`\[(\d+) \S+\] outbound/(\w+)\[`)
)

// checkDomainRouting ищет в буфере логов sing-box, куда реально ушёл трафик доменов,
// содержащих query (пустая строка — все найденные). Идея живого расследования
// 2026-08-25: правило DirectRoute для Госуслуг само по себе работало верно для
// gosuslugi.ru, но сайт продолжал видеть VPN — причина оказалась в НЕПОКРЫТОМ
// поддомене (gu-st.ru, статика/инфраструктура), чей трафик тихо уходил через
// туннель рядом с верно маршрутизированным основным доменом. Раньше этот разбор
// делался вручную (grep по логу), эта функция — то же самое, но для пользователя.
//
// Метод корреляции: sing-box логирует ID соединения одним и тем же числом на строке
// "router: sniffed protocol: ..., domain: X" и на следующей "outbound/TYPE[...]" —
// сопоставляем по этому ID (после снятия ANSI-кодов подсветки, которыми обёрнут сам
// ID и остальной текст).
func CheckDomainRouting(logs []string, query string) []DomainRouteResult {
	domainByID := make(map[string]string)
	routeByDomain := make(map[string]string)
	query = strings.ToLower(query)

	for _, raw := range logs {
		line := ansiCodeRe.ReplaceAllString(raw, "")
		if m := sniffDomain.FindStringSubmatch(line); m != nil {
			domainByID[m[1]] = m[2]
			continue
		}
		if m := outboundLine.FindStringSubmatch(line); m != nil {
			domain, ok := domainByID[m[1]]
			if !ok {
				continue
			}
			if query != "" && !strings.Contains(strings.ToLower(domain), query) {
				continue
			}
			routeByDomain[domain] = m[2]
		}
	}

	result := make([]DomainRouteResult, 0, len(routeByDomain))
	for domain, outbound := range routeByDomain {
		result = append(result, DomainRouteResult{
			Domain:   domain,
			Outbound: outbound,
			Direct:   outbound == "direct",
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Domain < result[j].Domain })
	return result
}
