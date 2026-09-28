package singbox

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// android_build_tags_guard_test.go — P1 (аудит 2026-09-01, ТЗ_REPAIR раздел P3, п.2):
// страж состава build-тегов gomobile bind в tools/android/build_aar.ps1.
//
// Каждый тег в этом списке был найден ОТДЕЛЬНЫМ живым прогоном на устройстве
// (with_clash_api, with_utls, with_gvisor — см. комментарии в самом скрипте; with_wireguard
// добавлен по аналогии при аудите 2026-09-01, живьём НЕ проверен). Отсутствие тега не валит
// компиляцию — vendor/.../sing-box несёт заглушку на противоположном build-теге
// (`//go:build !with_X`) — и откатывается на честный отказ, но только в RUNTIME, при первой
// попытке воспользоваться защищённым тегом протоколом/режимом:
//   - Reality (VLESS+Reality, ОСНОВНОЙ протокол APF)   → with_utls
//   - Clash API (нужен InProcessRunner/AndroidServerRunner) → with_clash_api
//   - TUN Stack "mixed"/"gvisor" (buildTun)             → with_gvisor
//   - WireGuard/AmneziaWG узлы (nodeToEndpoint, этот же пакет) → with_wireguard
//
// Тест не запускает саму сборку (это требует gomobile/Android SDK, недоступных в `go test`) —
// он читает СТРОКУ вызова gomobile bind и проверяет, что все ожидаемые теги в ней
// присутствуют. Не самодостаточная гарантия (человек может добавить пятый нужный тег и
// забыть внести его сюда), но ловит именно тот класс регрессии, что уже случился минимум
// четыре раза подряд в истории проекта: кто-то отредактировал список тегов, и один потерялся.
func requiredAndroidBuildTags() []string {
	return []string{"with_clash_api", "with_utls", "with_gvisor", "with_wireguard"}
}

var gomobileTagsLineRe = regexp.MustCompile(`-tags\s+([A-Za-z0-9_,]+)`)

// findModuleRoot поднимается от текущей директории теста до каталога с go.mod (корень
// модуля APF, source/). Проще repoRoot() в killswitch/rules_guard_test.go — там страж ищёт
// НЕИЗВЕСТНОЕ число копий скрипта по всему дереву репозитория (включая копии вне модуля);
// здесь путь до скрипта от корня модуля известен заранее и фиксирован.
func findModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for i := 0; i < 12; i++ {
		if st, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && !st.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
	return ""
}

func TestBuildAAR_HasRequiredTags(t *testing.T) {
	root := findModuleRoot(t)
	if root == "" {
		t.Skip("корень модуля не найден — build_aar.ps1 распространяется отдельно от модуля")
	}
	scriptPath := filepath.Join(root, "tools", "android", "build_aar.ps1")
	data, err := os.ReadFile(scriptPath)
	if err != nil {
		// P1-10 научил: t.Skip здесь неотличим от «страж сломан и ничего не проверяет».
		// Но build_aar.ps1, в отличие от скриптов Kill Switch, не гарантированно существует
		// в каждой поставке модуля (Android-сборка — опциональная часть проекта) — поэтому
		// Skip оправдан ТОЛЬКО когда сам файл отсутствует, а не когда он есть, но не читается.
		t.Skipf("tools/android/build_aar.ps1 не найден под %s: %v", root, err)
	}

	// Файл поясняет КАЖДЫЙ тег отдельным блоком комментариев вида "-tags with_clash_api
	// ОБЯЗАТЕЛЕН (находка ...)" — упоминаний "-tags <один_тег>" в файле НЕСКОЛЬКО, и только
	// одно из них — настоящий вызов gomobile bind (список через запятую, без пробелов).
	// Берём совпадение с наибольшим числом тегов, а не первое попавшееся — иначе страж
	// проверяет случайный комментарий вместо реальной команды сборки.
	matches := gomobileTagsLineRe.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		t.Fatalf("%s: не найдена ни одна строка \"-tags ...\" — "+
			"страж не может проверить состав тегов (возможно, сборка была переписана "+
			"без -tags вовсе, что тоже неверно)", scriptPath)
	}
	var best []byte
	for _, m := range matches {
		if len(m[1]) > len(best) {
			best = m[1]
		}
	}
	got := map[string]bool{}
	for _, tag := range regexp.MustCompile(`,`).Split(string(best), -1) {
		got[tag] = true
	}

	for _, want := range requiredAndroidBuildTags() {
		if !got[want] {
			t.Errorf("%s: тег %q отсутствует в списке -tags gomobile bind (нашли: %s) — "+
				"без него соответствующий протокол/режим компилируется как заглушка и "+
				"отказывает в рантайме на устройстве вместо честной ошибки сборки",
				scriptPath, want, string(best))
		}
	}
}
