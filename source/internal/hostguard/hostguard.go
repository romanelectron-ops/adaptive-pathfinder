// Package hostguard — единый барьер мутаций ХОСТА (обобщение DEF-08 на весь проект).
//
// ЗАЧЕМ. Барьер DEF-08 закрывал только пакет killswitch (netsh/iptables). Но APF меняет состояние
// машины и из других мест, и они барьером НЕ закрывались:
//
//   - internal/sysproxy — пишет HKCU\...\Internet Settings (ProxyEnable/ProxyServer). Записи в HKCU
//     НЕ требуют прав администратора, поэтому обычный `go test ./internal/engine/` реально включал
//     системный HTTP-прокси на 127.0.0.1:<порт>, где sing-box не слушает → весь WinINET/WinHTTP
//     трафик машины умирал. Именно так «пропадал интернет» во время тестов.
//   - internal/leakguard — выполняла `netsh interface ipv6 set prefixpolicy` — МАШИННУЮ и
//     ПОСТОЯННУЮ таблицу политик префиксов RFC 6724, которую Disable() на Windows не откатывал.
//
// ПРАВИЛО. Любая функция, меняющая состояние ОС (реестр, фаервол, DNS, маршруты, прокси, сетевые
// стеки, автозапуск), ОБЯЗАНА начинаться с проверки hostguard.Allow(). Под `go test` вызов
// возвращает false, операция превращается в no-op и учитывается в счётчике — так guard-тест
// (hostguard_guard_test.go в пакетах-мутаторах) доказывает, что барьер действительно сработал.
//
// ИНВАРИАНТ: `go test ./...` не изменяет НИ ОДНОГО параметра ОС.
package hostguard

import (
	"os"
	"strings"
	"sync"
)

// forceEnv — переменная окружения, снимающая барьер. Значение намеренно длинное и неудобное,
// чтобы его нельзя было выставить случайно или «на всякий случай».
//
// Единственный законный сценарий — ИЗОЛИРОВАННАЯ среда (Windows Sandbox / одноразовая ВМ), где
// порча сетевых настроек не затрагивает рабочую машину. См. tools/sandbox/.
const (
	forceEnv   = "APF_ALLOW_HOST_MUTATION"
	forceValue = "i-know-this-is-an-isolated-vm"
)

var (
	mu         sync.Mutex
	blockedOps []string

	testMode  = detectTestBinary()
	overriden = os.Getenv(forceEnv) == forceValue
)

// detectTestBinary определяет тестовый режим по имени исполняемого файла (`*.test` / `*.test.exe`).
// Надёжно уже на этапе init(), в отличие от flag.Lookup("test.v"), который на момент init() ещё
// не зарегистрирован.
func detectTestBinary() bool {
	a0 := strings.ToLower(os.Args[0])
	return strings.HasSuffix(a0, ".test") || strings.HasSuffix(a0, ".test.exe")
}

// UnderTest сообщает, что процесс запущен как тестовый бинарник.
func UnderTest() bool { return testMode }

// Overridden сообщает, что барьер снят переменной окружения (изолированная ВМ).
func Overridden() bool { return overriden }

// Allowed сообщает, разрешено ли этому процессу менять состояние хоста, НЕ регистрируя попытку.
// Для ветвления внутри мутаторов используйте Allow() — он ещё и ведёт учёт.
func Allowed() bool { return !testMode || overriden }

// Allow — страж мутации хоста.
//
// Вход:  op — имя операции («sysproxy.SetHTTPProxy»), попадает в отчёт guard-теста.
// Выход: true — операцию выполнять можно; false — вызывающий ОБЯЗАН немедленно вернуться,
//
//	не трогая ОС (и, как правило, вернуть nil: для вызывающего это успешный no-op).
//
// Инвариант: под `go test` (без явного override) всегда false.
func Allow(op string) bool {
	if Allowed() {
		return true
	}
	mu.Lock()
	blockedOps = append(blockedOps, op)
	mu.Unlock()
	return false
}

// BlockedOps возвращает список заблокированных операций (для guard-тестов и диагностики).
func BlockedOps() []string {
	mu.Lock()
	defer mu.Unlock()
	return append([]string(nil), blockedOps...)
}

// BlockedCount возвращает число заблокированных мутаций.
func BlockedCount() int {
	mu.Lock()
	defer mu.Unlock()
	return len(blockedOps)
}

// ResetBlocked очищает счётчик (для тестов).
func ResetBlocked() {
	mu.Lock()
	blockedOps = nil
	mu.Unlock()
}
