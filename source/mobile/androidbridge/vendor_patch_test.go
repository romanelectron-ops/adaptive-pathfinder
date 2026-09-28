package androidbridge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Контракт: вендоренный pidfd_android.go не должен снова ссылаться на os.checkPidfdOnce
// (правка §3.2 ТЗ Э-4).
//
// Вход:      файл vendor/github.com/sagernet/sing-box/experimental/libbox/pidfd_android.go.
// Тело:      строковая проверка на отсутствие //go:linkname ... os.checkPidfdOnce.
// Выход:     тест падает, если линкнейм вернулся.
// Fail-safe: очередной `go mod vendor` при обновлении версии sing-box молча перезатирает
// файл апстримной версией — обычная сборка `go build ./...` под ХОСТОВУЮ ОС этого не
// заметит, потому что pidfd_android.go участвует только в GOOS=android сборке. Без этого
// теста регрессия обнаружилась бы только на реальном android/arm64 build или на телефоне.
// Инвариант: линковка под GOOS=android GOARCH=arm64 не падает на
// "invalid reference to os.checkPidfdOnce" (само падение проверяется отдельно, кросс-сборкой
// в CI/скриптах — этот тест ловит причину раньше, чем возникает эффект).
//
// Почему линкнейм убран, а не заменён: символ checkPidfdOnce существует только в
// os/pidfd_linux.go (действует исключительно при GOOS=linux); при GOOS=android собирается
// os/pidfd_other.go, где pidfd вообще не используется. Обходной манёвр вокруг
// golang/go#70508 на этом тулчейне — мёртвый код, а не работающая защита, которую нужно
// сохранить другим способом.
func TestPidfdAndroidPatch_LinkNameRemoved(t *testing.T) {
	path := filepath.Join("..", "..", "vendor", "github.com", "sagernet", "sing-box",
		"experimental", "libbox", "pidfd_android.go")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("не удалось прочитать %s: %v (vendor не развёрнут?)", path, err)
	}

	// Ищем именно ЖИВУЮ директиву //go:linkname, а не упоминание символа в комментарии
	// (объясняющий комментарий этой же правки сам называет "os.checkPidfdOnce" — наивная
	// проверка strings.Contains ловила бы саму себя как ложное срабатывание).
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//go:linkname") && strings.Contains(trimmed, "checkPidfdOnce") {
			t.Fatalf("%s снова содержит директиву %q — вероятно, файл перезатёрт "+
				"апстримной версией при go mod vendor. Символ checkPidfdOnce не существует "+
				"в android-сборке пакета os (Go 1.26.2): линковка под GOOS=android GOARCH=arm64 "+
				"упадёт с \"invalid reference to os.checkPidfdOnce\". См. TZ_ANDROID_E4_v1.1.md "+
				"§3.2 — нужно повторить правку: заменить содержимое файла на пустой package libbox",
				path, trimmed)
		}
	}
}
