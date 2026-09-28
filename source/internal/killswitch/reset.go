package killswitch

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/apf/adaptive-pathfinder/internal/hostguard"
)

// Injection vars — overridden in tests.
var (
	resetGOOS      = func() string { return runtime.GOOS }
	quickResetGOOS = func() string { return runtime.GOOS }

	// resetDNSSafe helpers — allow tests to inject fake netsh output.
	showInterfacesFn = func() ([]byte, error) {
		return exec.Command("netsh", "interface", "show", "interface").Output()
	}
	getDNSInfoFn = func(iface string) ([]byte, error) {
		return exec.Command("netsh", "interface", "ip", "show", "dns",
			"name="+iface).Output()
	}
	setDNSDHCPFn = func(iface string) {
		exec.Command("netsh", "interface", "ip", "set", "dns",
			"name="+iface, "source=dhcp").Run()
	}
)

// ResetAll — полный откат ВСЕХ изменений APF в сетевых настройках.
// Вызывать при выходе, по кнопке "Сбросить сеть", или при панике.
//
// КРИТИЧЕСКИ ВАЖНО: НЕ вызываем "netsh winsock reset", "netsh int ip reset",
// "ipconfig /release", "ipconfig /renew" — эти команды перезапускают WiFi адаптер
// и обрывают все сетевые соединения пользователя. Достаточно удалить только правила
// файрвола APF и сбросить DNS.
func ResetAll() error {
	switch resetGOOS() {
	case "windows":
		return resetWindows()
	case "linux":
		return resetLinux()
	default:
		return nil
	}
}

// deleteAllAPFRules удаляет ВСЕ правила APF (текущие + legacy) из Windows Firewall.
// R-7 (C-13): имена берутся из ЕДИНСТВЕННОГО источника — windowsRuleSuffixes; раньше здесь
// и в QuickReset были собственные копии списка, которые уже разошлись с killswitch.go.
// Через runCmd (execCmdFn) — под `go test` DEF-08 нейтрализует, хост не трогаем.
func deleteAllAPFRules() {
	for _, cmd := range ksCleanupCommands() {
		_ = runCmd("netsh", cmd...)
	}
}

func resetWindows() error {
	// 1. Удаляем ВСЕ правила APF из файрвола (текущие + legacy). Best-effort — как и в
	// cleanupRules()/deleteAllAPFRules() везде, отсутствие правила не ошибка.
	deleteAllAPFRules()

	// 2. Восстанавливаем политику файрвола на дефолт — КРИТИЧЕСКАЯ команда.
	//
	// РЕГРЕССИЯ к P0-4 (аудит 2026-09-01, sentinel.go/RecoverIfNeeded): та же ошибка,
	// которую P0-4 уже один раз чинил на уровне windowsKS.disable(), жила ЭТАЖОМ НИЖЕ —
	// здесь. RecoverIfNeeded() снимает sentinel-маркер, ТОЛЬКО если ResetAll() вернул nil
	// (см. sentinel.go). Но пока эта строка была `_ = runCmd(...)`, resetWindows() (и тем
	// самым ResetAll()) возвращал nil ВСЕГДА, даже если у процесса нет прав администратора
	// и critical-команда упала с «Отказано в доступе» — ключевая политика blockoutbound
	// оставалась висеть (она персистентна, переживает перезагрузку), а вызывающий
	// (RecoverIfNeeded, запускаемый именно для восстановления после аварийного выхода)
	// был уверен в успехе и стирал маркер. Следующий запуск уже не видел признака
	// «прошлая сессия оставила KS включённым» и повторной попытки не делал — пользователь
	// оставался без интернета, а лог показывал «восстановление выполнено». Ровно тот
	// сценарий, который комментарий P0-4 в sentinel.go описывает как уже исправленный —
	// фактически он не мог сработать, потому что ResetAll() не мог вернуть ошибку.
	err := runCmd("netsh", "advfirewall", "set", "allprofiles",
		"firewallpolicy", "blockinbound,allowoutbound")

	// 3. Сбрасываем DNS ТОЛЬКО на активных адаптерах, которые APF мог изменить.
	// Используем точечный сброс без перезапуска адаптера. Best-effort — не блокирует
	// восстановление сети сама по себе, поэтому её ошибку не поднимаем наверх.
	resetDNSSafe()

	// 4. Сбрасываем только DNS-кэш — это безопасно и не затрагивает соединения. Best-effort.
	_ = runCmd("ipconfig", "/flushdns")

	// НАМЕРЕННО НЕ делаем:
	// - netsh winsock reset   → требует перезагрузку, сбрасывает LSP
	// - netsh int ip reset    → перезапускает TCP/IP стек, обрывает WiFi
	// - ipconfig /release     → отключает все интерфейсы
	// - ipconfig /renew       → пересогласовывает DHCP (обрывает WiFi на 3-10 сек)

	if err != nil {
		return fmt.Errorf("не удалось вернуть политику брандмауэра (нужны права администратора): %w", err)
	}
	return nil
}

// resetDNSSafe сбрасывает DNS на DHCP только для адаптеров которые APF мог изменить.
// Не перезапускает адаптеры и не обрывает соединения.
func resetDNSSafe() {
	// Получаем список подключённых адаптеров
	out, err := showInterfacesFn()
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		// Ищем строки с подключёнными адаптерами
		if !strings.Contains(line, "Connected") &&
			!strings.Contains(line, "Подключен") &&
			!strings.Contains(line, "Enabled") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Имя адаптера — всё после первых 3 полей
		iface := strings.Join(fields[3:], " ")
		iface = strings.TrimSpace(iface)
		if iface == "" {
			continue
		}

		// Проверяем текущий DNS этого адаптера
		// Если APF выставил статический DNS — сбрасываем на DHCP
		dnsOut, err := getDNSInfoFn(iface)
		if err != nil {
			continue
		}

		// Если видим APF DNS серверы (8.8.8.8 выставленный статически) — сбрасываем
		// Определяем по наличию "Statically Configured" или "Настроен статически"
		dnsStr := string(dnsOut)
		isStaticAPF := (strings.Contains(dnsStr, "Statically") ||
			strings.Contains(dnsStr, "статически")) &&
			(strings.Contains(dnsStr, "8.8.8.8") ||
				strings.Contains(dnsStr, "8.8.4.4") ||
				strings.Contains(dnsStr, "1.1.1.1") ||
				strings.Contains(dnsStr, "1.0.0.1"))

		if isStaticAPF {
			// Тихо сбрасываем DNS без перезапуска адаптера
			setDNSDHCPFn(iface)
		}
	}
}

// tunDeleteFn / dnsRevertFn — S-14 (TZ v1.4, лот L1-KS): resetLinux() раньше вызывал
// exec.Command("ip","link","delete","apf0") и exec.Command("resolvectl","revert") НАПРЯМУЮ —
// в отличие от iptablesRunFn/ip6tablesRunFn (см. killswitch.go), эти два вызова не были ни
// инжектируемыми, ни защищены барьером internal/hostguard. Пакет hostguard требует: «любая
// функция, меняющая состояние ОС, ОБЯЗАНА начинаться с проверки hostguard.Allow()» — resetLinux
// нарушал это напрямую, и под `go test` на реальном Linux-хосте мог по-настоящему удалить
// интерфейс apf0 и откатить DNS хоста. Теперь оба вызова — инжектируемые var'ы (тест может
// подменить и проверить факт вызова) и исполняются ТОЛЬКО когда hostguard.Allow() пропускает.
var (
	tunDeleteFn = func() error {
		return exec.Command("ip", "link", "delete", "apf0").Run()
	}
	dnsRevertFn = func() error {
		return exec.Command("resolvectl", "revert").Run()
	}
)

func resetLinux() error {
	// D3-фикс: снимаем ТОЛЬКО выделенную цепочку APF_KS и ссылку на неё в OUTPUT,
	// НЕ флашим OUTPUT целиком (это уничтожало бы чужие правила пользователя).
	teardownChain(iptablesRunFn)
	teardownChain(ip6tablesRunFn)

	// S-14: удаление TUN-интерфейса и revert DNS — те же мутации хоста, что и firewall-правила
	// выше, поэтому идут за тем же барьером hostguard.Allow(). Под `go test` (без
	// APF_ALLOW_HOST_MUTATION) Allow() всегда возвращает false — швы не вызываются вовсе.
	if hostguard.Allow("killswitch.resetLinux.tun+dns") {
		_ = tunDeleteFn()
		_ = dnsRevertFn()
	}

	return nil
}

// QuickReset — быстрый сброс только правил файрвола APF.
// Безопасен: не трогает WiFi, не обрывает соединения.
// Использовать при обычном выходе из APF.
func QuickReset() {
	switch quickResetGOOS() {
	case "windows":
		deleteAllAPFRules() // R-7: единый источник имён (windowsRuleSuffixes)
		// QuickReset вызывается при штатном выходе → вернуть политику по умолчанию, иначе
		// оставленный blockoutbound (если Enable успел его выставить) обрубит сеть (D-31).
		_ = runCmd("netsh", "advfirewall", "set", "allprofiles",
			"firewallpolicy", "blockinbound,allowoutbound")
		// DNS кэш — безопасно
		_ = runCmd("ipconfig", "/flushdns")

	case "linux":
		// D3-фикс: снимаем только APF_KS, не флашим OUTPUT (см. resetLinux).
		teardownChain(iptablesRunFn)
		teardownChain(ip6tablesRunFn)
	}
}
