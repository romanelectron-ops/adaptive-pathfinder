//go:build windows

// cmd/apf-wfpcheck — рантайм-проверка WFP Kill Switch (B-0402.4) на admin-стенде.
//
// ⚠️ Требует прав администратора и НА ВРЕМЯ теста реально блокирует исходящий трафик мимо туннеля.
//
//	 Запускать ТОЛЬКО под Safety Harness (см. APF_Audit/B0402_3_ACCEPTANCE_CHECKLIST.md).
//
//	apf-wfpcheck.exe            # Enable → показать APF-фильтры → Disable → показать (ожидание: было>0, стало 0)
//	apf-wfpcheck.exe -crashtest # Enable → показать → ВЫЙТИ без Disable (dynamic session должен снять фильтры сам)
//	apf-wfpcheck.exe -vpn 203.0.113.7
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/apf/adaptive-pathfinder/internal/killswitch"
)

func showAPFFilters() int {
	out, _ := exec.Command("netsh", "wfp", "show", "filters").CombinedOutput()
	n := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "APF-KillSwitch") {
			fmt.Println("   ", strings.TrimSpace(line))
			n++
		}
	}
	return n
}

func main() {
	crash := flag.Bool("crashtest", false, "выйти без Disable (проверка авто-снятия dynamic session)")
	vpn := flag.String("vpn", "203.0.113.7", "тестовый VPN allow-IP")
	flag.Parse()

	fmt.Println("APF WFP self-check (нужен admin).")
	ks, ok := killswitch.NewWFPBackend()
	if !ok {
		fmt.Println("WFP-бэкенд недоступен на этой платформе.")
		os.Exit(1)
	}
	if w, ok := ks.(interface{ SetVPNEndpoint(string, int) }); ok {
		w.SetVPNEndpoint(*vpn, 1080)
	}

	fmt.Println("Enable (открываю движок WFP c dynamic session + ставлю фильтры)...")
	if err := ks.Enable("apf0", []int{1080}); err != nil {
		fmt.Println("  Enable ОШИБКА:", err)
		fmt.Println("  (нет прав admin? неверная разметка FWPM-структур? см. ТЗ B-0402.4 §6)")
		os.Exit(1)
	}
	fmt.Printf("Enabled=%v. APF-фильтры в WFP:\n", ks.IsEnabled())
	before := showAPFFilters()
	fmt.Printf("  всего APF-фильтров: %d\n", before)

	if *crash {
		fmt.Println("\n[crashtest] Выхожу БЕЗ Disable. Теперь вручную выполни:")
		fmt.Println("    netsh wfp show filters | findstr APF-KillSwitch")
		fmt.Println("Ожидание: пусто — dynamic session сняла фильтры при выходе процесса (crash-safe, D-33).")
		os.Exit(0)
	}

	fmt.Println("Disable (закрываю движок → dynamic session снимает всё)...")
	_ = ks.Disable()
	after := showAPFFilters()
	fmt.Printf("  APF-фильтров после Disable: %d\n", after)

	if before > 0 && after == 0 {
		fmt.Println("\n[PASS] Фильтры появились и снялись. Проверь ещё leak-tight/switch по чек-листу.")
		os.Exit(0)
	}
	fmt.Println("\n[CHECK] before>0 && after==0 не выполнено — сверь разметку структур и вывод netsh wfp.")
	os.Exit(1)
}
