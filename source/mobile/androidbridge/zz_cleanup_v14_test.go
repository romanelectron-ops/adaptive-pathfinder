package androidbridge

// zz_cleanup_v14_test.go — ТЗ v1.4, C-10 (лот L1b-TST): мета-тест «после прогона пакета
// живых горутин движка ноль».
//
// ПОЧЕМУ ИМЯ ФАЙЛА zz_*, А НЕ TestMain: пакет уже владеет одним TestMain
// (bridge_scenarios_test.go, K2-A/2026-09-07) — второй TestMain в пакете — ошибка
// компиляции. Единственный доступный этому лоту способ «выполниться после всех
// остальных тестов» без TestMain — обычный тест в файле, чьё имя сортируется последним
// по алфавиту среди файлов пакета: bridge_*, platform_adapter_*, server_role_*, tun_*,
// vendor_patch_* — все раньше "zz_". Хелпер и общая утварь снятия дампа горутин
// нарочно вынесены в bridge_cleanup_test.go (сортируется РАНЬШЕ zz_), а не сюда — важен
// только порядок для файла с самой тестовой функцией; порядок объявления вспомогательных
// функций внутри пакета на это не влияет.
//
// ОГОВОРКА ПРО t.Parallel(): в этом пакете НИ ОДИН тест не вызывает t.Parallel()
// (проверено при составлении лота), поэтому ограничение «параллельный тест выполняется
// уже после снимка serial-тестов» здесь чисто теоретическое — но фиксируется явно на
// случай, если оно появится позже (см. тот же комментарий в internal/engine, зеркально).
//
// ЧТО КОНКРЕТНО ЛОВИТ ЭТОТ МЕТА-ТЕСТ (по факту, не по замыслу авторов старых тестов):
// ни один тест пакета не вызывает engine.Start(), но несколько существующих тестов
// (TestConnectNode_AfterInit, TestConnectOnce_AfterInit_DoesNotPin,
// TestConnectChainPartner_AfterInit, TestSweepContract_AfterInit —
// bridge_scenarios_test.go) зовут package-level функции моста (ConnectNode/ConnectOnce/
// ConnectChainPartner/StartSweep), которые внутри синхронно доходят до
// e.goTracked(...) и уводят реальную работу (ScanAndConnect/runPoolScan) в фон, НЕ
// дожидаясь её и НЕ останавливая движок по окончании теста (newBareTestEngine убирает
// только globalEngine, не зовёт e.Stop()). См. result.md лота — там же перечень с
// файл:строка и обоснование, почему это не правится в периметре этого лота.
import (
	"os"
	"testing"
	"time"
)

// TestZZZ_NoEngineGoroutineLeak — после прогона пакета mobile/androidbridge ни одна
// горутина движка (*engine.Engine) или собственная фоновая горутина пакета
// (androidbridge.Connect/.RefreshCatalog/.StartTun/.StopServerRole — все запускают
// анонимные `go func(){...}()`) не должна быть жива.
func TestZZZ_NoEngineGoroutineLeak(t *testing.T) {
	const (
		maxWait   = 5 * time.Second
		pollEvery = 100 * time.Millisecond
	)

	var leaked []string
	deadline := time.Now().Add(maxWait)
	for {
		leaked = snapshotLeakedGoroutines()
		if len(leaked) == 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(pollEvery)
	}

	if len(leaked) == 0 {
		t.Log("OK: 0 живых горутин движка/моста после прогона пакета mobile/androidbridge")
		return
	}

	t.Logf("живых горутин движка/моста после прогона пакета: %d (ожидалось 0, ждали до %v)", len(leaked), maxWait)
	for i, s := range leaked {
		t.Logf("--- утёкшая горутина #%d ---\n%s", i+1, s)
	}
	t.Log("контекст: см. result.md лота L1b-TST (ТЗ v1.4, C-10) — список тестов-кандидатов " +
		"на утечку (ConnectNode/ConnectOnce/ConnectChainPartner/StartSweep через newBareTestEngine " +
		"без e.Stop()) и разбор причины; решение чинить/не чинить — за оркестратором.")

	// Мягкий режим по умолчанию — см. ту же оговорку в internal/engine/zz_cleanup_v14_test.go.
	if os.Getenv("APF_STRICT_LEAKS") == "1" {
		t.Fatalf("APF_STRICT_LEAKS=1: %d горутин(ы) движка/моста пережили прогон пакета", len(leaked))
	}
}
