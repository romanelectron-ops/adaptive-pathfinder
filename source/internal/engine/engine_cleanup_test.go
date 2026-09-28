package engine

// engine_cleanup_test.go — ТЗ v1.4, C-10 (лот L1b-TST): хелпер, гарантирующий, что
// *Engine, созданный тестом, останавливается ДАЖЕ если тест падает (t.Fatal/паника
// перехватываются testing раньше, чем дошло бы до "e.Stop() в конце функции").
//
// КОНТРАКТ ДЛЯ БУДУЩИХ ТЕСТОВ ПАКЕТА internal/engine (см. также result.md лота
// L1b-TST — там та же формулировка, читать оттуда, если этот файл переедет):
//
//	Новый тест, которому нужен *Engine, ОБЯЗАН получать его через
//	newTestEngineWithCleanup(t, cfg) (cfg == nil → models.DefaultConfig()), а не звать
//	New(cfg) напрямую. Если тест сам вызывает e.Start(), НЕ нужно ещё раз вручную звать
//	e.Stop() в конце функции — t.Cleanup уже это сделает; повторный Stop() не опасен
//	(идемпотентен по построению — cancel() дважды, wg.Wait() на уже пустой группе,
//	guard'ы на Disable() смотрят IsEnabled()), но и не нужен.
//
// ПОЧЕМУ ЭТО БЕЗОПАСНО ПОД `go test` НА РЕАЛЬНОЙ МАШИНЕ. Engine.Stop() трогает реестр/
// фаервол/системный прокси (disableSystemProxy, ksDisable/ksReset), но каждая такая
// операция начинается с hostguard.Allow(...) (internal/hostguard) и под тестовым
// бинарником всегда получает false → операция становится no-op (см.
// internal/hostguard/hostguard.go: инвариант "go test ./... не изменяет НИ ОДНОГО
// параметра ОС", уже покрытый TestBarrierArmedUnderTest в internal/hostguard). Вызов
// Stop() на никогда не стартовавшем движке безопасен по той же причине — то немногое,
// что он делает мимо hostguard (e.saveNodes(), e.FlushLog()), пишет в config.DataDir(),
// а этот пакет уже уводит его во временный каталог на весь бинарник
// (testmain_isolation_test.go, TestMain — вне периметра лота L1b-TST, не трогаем).
//
// ПОЧЕМУ ХЕЛПЕР ЗДЕСЬ, А НЕ В testmain_isolation_test.go: тот файл принадлежит другому
// лоту, а второй TestMain в пакете — ошибка компиляции («multiple functions named
// TestMain»); этот файл — обычный вспомогательный _test.go, не TestMain.
import (
	"runtime"
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// newTestEngineWithCleanup создаёт *Engine и регистрирует его остановку через
// t.Cleanup(e.Stop) — сработает после теста независимо от того, как он завершился
// (успех, t.Fatal/t.Fatalf, паника, t.Skip после создания движка).
//
// cfg == nil эквивалентно models.DefaultConfig() — самому частому случаю в этом пакете.
func newTestEngineWithCleanup(t *testing.T, cfg *models.AppConfig) *Engine {
	t.Helper()
	if cfg == nil {
		cfg = models.DefaultConfig()
	}
	e := New(cfg)
	t.Cleanup(e.Stop)
	return e
}

// engineGoroutineMarker — подстрока, по которой в дампе runtime.Stack(all=true)
// опознаётся горутина, выполняющая метод *Engine (goTracked-обёртки, monitorLoop,
// sourceUpdateLoop, watchdog.Run и т.п.) — то есть фон движка, а не сам тестовый код.
//
// Матчим именно ".(*Engine)", а не более широкое "internal/engine." — второе поймало бы
// ЛЮБУЮ функцию текущего пакета, включая сами тестовые функции (они
// package-qualified как "internal/engine.TestXxx" в трассе), что дало бы 100%
// ложных срабатываний на собственном тесте-наблюдателе и на любой другой активной
// горутине теста, которая просто ещё не вернула управление.
const engineGoroutineMarker = "adaptive-pathfinder/internal/engine.(*Engine)"

// fullGoroutineDump — runtime.Stack(all=true) с ретраем на переполнение буфера
// (сигнатура: n == len(buf) значит буфер мог быть мал, добор со следующей попытки).
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

// filterGoroutineBlocks разбивает дамп runtime.Stack(all=true) на блоки по горутинам
// (разделены пустой строкой) и возвращает те, что содержат marker — за вычетом блоков,
// содержащих любую из строк self (имена функций самого механизма снятия дампа: без
// исключения горутина, которая ЗОВЁТ этот код, попала бы в свой же список).
func filterGoroutineBlocks(dump, marker string, self ...string) []string {
	blocks := strings.Split(dump, "\n\n")
	var out []string
blockLoop:
	for _, b := range blocks {
		if !strings.Contains(b, marker) {
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

// snapshotEngineGoroutines возвращает полные блоки runtime.Stack(all=true) для горутин,
// чей стек прямо сейчас содержит engineGoroutineMarker.
func snapshotEngineGoroutines() []string {
	return filterGoroutineBlocks(fullGoroutineDump(), engineGoroutineMarker,
		"snapshotEngineGoroutines", "fullGoroutineDump", "filterGoroutineBlocks")
}
