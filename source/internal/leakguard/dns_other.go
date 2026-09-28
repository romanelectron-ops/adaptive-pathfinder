//go:build !windows

package leakguard

import (
	"bufio"
	"os"
	"strings"
)

// realSystemDNSServers на Linux читает /etc/resolv.conf (стандартный источник, используемый
// самим системным резолвером) — тот же принцип, что и Windows-реализация: настоящий источник
// конфигурации ОС, не побочный эффект резолва произвольного имени.
//
// На Android (тоже !windows) файла обычно нет либо доступ к нему запрещён песочницей
// приложения — ошибка открытия трактуется как "не удалось определить", пустой список, без
// паники и без побочного эффекта; см. тот же контракт в дока systemDNSServers().
func realSystemDNSServers() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			out = append(out, fields[1])
		}
	}
	return out
}
