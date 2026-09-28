//go:build windows

package leakguard

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// tcpipInterfacesKey — куст, где Windows хранит per-adapter сетевые настройки, включая DNS.
// Читаем ТОЛЬКО этот путь (никаких мутаций) — в отличие от internal/sysproxy, здесь нет
// причины идти через hostguard: чтение реестра не меняет состояние машины.
const tcpipInterfacesKey = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`

// realSystemDNSServers перечисляет DNS-серверы по всем сетевым адаптерам через реестр —
// тот же источник, из которого их читает сам Windows (ipconfig/netsh идут за теми же
// значениями). NameServer — статически заданный список (приоритет), DhcpNameServer —
// полученный по DHCP; берём NameServer, если он непустой, иначе DhcpNameServer, для КАЖДОГО
// адаптера (активных и неактивных — различить без обхода таблицы маршрутов нельзя, поэтому
// отдаём все настроенные; это честнее пустого списка и уж тем более честнее "127.0.0.1").
//
// P1 (аудит 2026-09-01, security-раздел, находка №15): раньше systemDNSServers() резолвила
// имя "localhost" и возвращала АДРЕСА localhost (127.0.0.1/::1) — не имеющие никакого
// отношения к настроенным DNS-серверам системы. Пользователь, открывший экран диагностики
// DNS-утечки, ВСЕГДА видел "системный DNS: 127.0.0.1" — вводящее в заблуждение показание,
// которое выглядит как "утечки нет" в худшем возможном смысле: оно не пустое и не похоже на
// ошибку, оно похоже на настоящий (безобидный) результат.
func realSystemDNSServers() []string {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, tcpipInterfacesKey, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer root.Close()

	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}

	seen := map[string]bool{}
	var out []string
	for _, name := range names {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, tcpipInterfacesKey+`\`+name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		val, _, err := k.GetStringValue("NameServer")
		if err != nil || strings.TrimSpace(val) == "" {
			val, _, _ = k.GetStringValue("DhcpNameServer")
		}
		k.Close()
		for _, addr := range splitDNSServerList(val) {
			if !seen[addr] {
				seen[addr] = true
				out = append(out, addr)
			}
		}
	}
	return out
}

// splitDNSServerList — Windows разделяет несколько адресов запятой И/ИЛИ пробелом в
// зависимости от того, кто записал значение (netsh пишет через запятую, DHCP-клиент иногда
// через пробел).
func splitDNSServerList(v string) []string {
	fields := strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}
