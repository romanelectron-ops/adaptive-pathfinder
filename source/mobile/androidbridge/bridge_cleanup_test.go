package androidbridge

// bridge_cleanup_test.go — ТЗ v1.4, C-10 (лот L1b-TST): хелпер, гарантирующий остановку
// *engine.Engine, созданного тестом, через t.Cleanup — и общая утварь для мета-теста
// TestZZZ_NoEngineGoroutineLeak (mobile/androidbridge/zz_cleanup_v14_test.go).
//
// КОНТЕКСТ (см. память проекта apf-androidbridge-test-pollution-fix-2026-09-05.md и
// доккомментарий TestMain в bridge_scenarios_test.go, K2-A 2026-09-07): движки, которые
// тесты этого пакета создают через engine.New(androidConfig()), никогда не звали
// .Stop() — обнаружено по факту, что %APPDATA%\APF\nodes_cache.json на реальной машине
// менялся уже ПОСЛЕ restore() из снимка TestMain, то есть фоновой горутиной уже
// остановленного (по логике теста) движка, который на самом деле никогда не
// останавливался. TestMain-снимок/восстановление (K2-A) лечит СИМПТОМ (файл машины),
// этот хелпер — часть лечения ПРИЧИНЫ (сама горутина не должна переживать тест).
//
// КОНТРАКТ ДЛЯ БУДУЩИХ ТЕСТОВ ПАКЕТА mobile/androidbridge (см. также result.md лота
// L1b-TST): тест, которому нужен *engine.Engine, ОБЯЗАН получать его через
// newTestEngineWithCleanup(t) вместо engine.New(androidConfig()) напрямую. Если тесту
// одновременно нужен движок, видимый через package-level API моста (ConnectNode,
// GetNodesJSON и т.п., которые читают глобальный getEngine()), используйте существующий
// newBareTestEngine(t) (bridge_scenarios_test.go) — он уже кладёт движок в globalEngine
// и через t.Cleanup зануляет указатель; ЭТОТ хелпер ниже дополнительно нужен, если
// тесту важна остановка самого движка (e.Stop()), а не только сброс глобальной
// переменной. Оба хелпера не конфликтуют: можно обернуть один и тот же e поочерёдно
// в оба, порядок t.Cleanup — LIFO, е.Stop() выполнится до зануления globalEngine.
//
// ПОЧЕМУ Stop() БЕЗОПАСЕН ПОД `go test` НА РЕАЛЬНОЙ МАШИНЕ: та же причина, что в
// internal/engine/engine_cleanup_test.go — hostguard.Allow(...) внутри
// disableSystemProxy/ksDisable/ksReset под тестовым бинарником всегда false, поэтому
// реестр/фаервол/системный прокси не трогаются. saveNodes()/FlushLog() внутри Stop()
// пишут в config.DataDir() — этот пакет (в отличие от internal/engine) НЕ уводит
// DataDir во временный каталог (см. комментарий TestMain в bridge_scenarios_test.go про
// причину), поэтому реальные файлы затрагиваются, но это уже покрыто
// snapshotDataFilesForPackage/snapshotAndRestoreDataFile в TestMain и по месту — сам
// вызов Stop() ничего нового к этому риску не добавляет по сравнению с уже
// существующими вызовами saveNodes() из New()+AddNode и т.п.
import (
	"runtime"
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/engine"
)

// newTestEngineWithCleanup создаёт голый *engine.Engine (androidConfig(), без
// .Start()) и регистрирует его остановку через t.Cleanup(e.Stop) — сработает после
// теста независимо от исхода (успех, t.Fatal/Fatalf, паника, t.Skip после создания).
//
// В отличие от newBareTestEngine (bridge_scenarios_test.go) НЕ трогает globalEngine —
// используйте newBareTestEngine, если тесту нужны package-level функции моста
// (ConnectNode, AddNode, ...), которые читают getEngine().
func newTestEngineWithCleanup(t *testing.T) *engine.Engine {
	t.Helper()
	e := engine.New(androidConfig())
	t.Cleanup(e.Stop)
	return e
}

// engineGoroutineMarker — та же метка, что в internal/engine/engine_cleanup_test.go:
// подстрока, по которой в дампе runtime.Stack(all=true) опознаётся горутина, выполняющая
// метод *engine.Engine (goTracked-обёртки, monitorLoop, watchdog.Run и т.п.) —
// background движка, порождённый ЛЮБЫМ путём (engine.New(...).Start(), либо, что здесь
// вероятнее, вызовом ConnectNode()/StartSweep()/... на голом движке — они зовут
// e.goTracked(...) не дожидаясь полноценного Start(), см. комментарии
// TestConnectNode_AfterInit/TestSweepContract_AfterInit в bridge_scenarios_test.go).
//
// androidbridgeGoroutineMarker — вторая метка для горутин, которые порождает САМ пакет
// androidbridge напрямую (`go func(){...}()` в Connect/RefreshCatalog/StartTun/
// StopServerRole — см. bridge.go, tun.go, server_role.go). Такие горутины всегда
// анонимные замыкания, поэтому в трассе они получают суффикс ".funcN" у имени
// объемлющей функции пакета — по этому суффиксу отсекаем плоские кадры вида
// "androidbridge.TestXxx" (сами тестовые функции — не замыкания, суффикса не имеют).
const (
	engineGoroutineMarker        = "adaptive-pathfinder/internal/engine.(*Engine)"
	androidbridgeGoroutineMarker = "adaptive-pathfinder/mobile/androidbridge."
)

// fullGoroutineDump — runtime.Stack(all=true) с ретраем на переполнение буфера.
func fullGoroutineDump() string {
	buf := make([]byte, 1<<16)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return string(buf[:n])
		}
		buf = make([]byte, len(buf)*2)
	}
}

// isAndroidbridgeClosureFrame сообщает, что блок горутины содержит анонимное замыкание
// пакета androidbridge (androidbridgeGoroutineMarker + суффикс ".funcN" сразу после
// имени функции) — а не просто упоминание пакета в имени обычной тестовой функции.
func isAndroidbridgeClosureFrame(block string) bool {
	idx := strings.Index(block, androidbridgeGoroutineMarker)
	if idx < 0 {
		return false
	}
	rest := block[idx+len(androidbridgeGoroutineMarker):]
	// Имя функции сразу после точки; ищем ".func" до ближайшей "(" — признак замыкания.
	if paren := strings.IndexByte(rest, '('); paren >= 0 {
		rest = rest[:paren]
	}
	return strings.Contains(rest, ".func")
}

// filterGoroutineBlocks разбивает дамп runtime.Stack(all=true) на блоки по горутинам
// (разделены пустой строкой) и возвращает те, что подходят под match, — за вычетом
// блоков, содержащих любую из строк self (имена функций самого механизма снятия дампа,
// чтобы горутина-наблюдатель не попала в свой же список).
func filterGoroutineBlocks(dump string, match func(block string) bool, self ...string) []string {
	blocks := strings.Split(dump, "\n\n")
	var out []string
blockLoop:
	for _, b := range blocks {
		if !match(b) {
			continue
		}
		for _, s := range self {
			if strings.Contains(b, s) {
				continue blockLoop
			}
		}
		out = append(out, strings.TrimRight(b, "\n"))
	}
	return out
}

// snapshotLeakedGoroutines возвращает горутины, живые ПРЯМО СЕЙЧАС, которые относятся
// либо к фону *engine.Engine (engineGoroutineMarker), либо к собственным анонимным
// горутинам пакета androidbridge (isAndroidbridgeClosureFrame).
func snapshotLeakedGoroutines() []string {
	dump := fullGoroutineDump()
	match := func(b string) bool {
		return strings.Contains(b, engineGoroutineMarker) || isAndroidbridgeClosureFrame(b)
	}
	return filterGoroutineBlocks(dump, match,
		"snapshotLeakedGoroutines", "fullGoroutineDump", "filterGoroutineBlocks", "isAndroidbridgeClosureFrame")
}
