package updater

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Контракт «не проверяем обновления там, где их нечем применить» (дефект D-A23).
//
// Вход:      целевая ОС.
// Тело:      SelfUpdateSupported → StartAutoCheck.
// Выход:     запущена фоновая проверка либо честное сообщение об отказе.
// Fail-safe: на мобильных системах — не запускаем.
// Инвариант: на Android StartAutoCheck не делает ни одного сетевого запроса.
//
// Что ловится: строка `updater: initial check error: updater: GitHub API returned 404`
// при каждом запуске приложения на телефоне — поход в сеть до поднятия туннеля,
// заведомо безрезультатный: заменить APK может только системный установщик пакетов.

func TestSelfUpdateSupported(t *testing.T) {
	restore := updaterGOOS
	defer func() { updaterGOOS = restore }()

	cases := map[string]bool{
		"android": false,
		"ios":     false,
		"windows": true,
		"linux":   true,
		"darwin":  true,
	}
	for goos, want := range cases {
		updaterGOOS = func() string { return goos }
		if got := SelfUpdateSupported(); got != want {
			t.Errorf("%s: SelfUpdateSupported = %v, ожидалось %v", goos, got, want)
		}
	}
}

func TestStartAutoCheck_SilentOnAndroid(t *testing.T) {
	restoreGOOS, restoreAPI := updaterGOOS, githubAPI
	defer func() { updaterGOOS, githubAPI = restoreGOOS, restoreAPI }()

	updaterGOOS = func() string { return "android" }
	// Адрес заведомо нерабочий: если запрос всё-таки уйдёт, в журнале появится ошибка,
	// и это будет видно ниже.
	githubAPI = "http://127.0.0.1:1/never"

	var logged []string
	u := New("1.0.0")
	u.OnLog = func(s string) { logged = append(logged, s) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	u.StartAutoCheck(ctx)
	u.Wait()

	for _, line := range logged {
		if strings.Contains(line, "check error") {
			t.Errorf("на Android выполнена проверка обновлений: %q", line)
		}
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "установщик пакетов") {
		t.Errorf("нет честного объяснения отказа, журнал: %v", logged)
	}
}

// Обратная сторона: на настольной системе проверка обязана запускаться как прежде.
func TestStartAutoCheck_RunsOnDesktop(t *testing.T) {
	restoreGOOS, restoreAPI := updaterGOOS, githubAPI
	defer func() { updaterGOOS, githubAPI = restoreGOOS, restoreAPI }()

	updaterGOOS = func() string { return "windows" }
	githubAPI = "http://127.0.0.1:1/never" // соединение не пройдёт — нам нужен сам факт попытки

	var logged []string
	u := New("1.0.0")
	u.OnLog = func(s string) { logged = append(logged, s) }

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	u.StartAutoCheck(ctx)
	cancel()
	u.Wait()

	found := false
	for _, line := range logged {
		if strings.Contains(line, "check error") {
			found = true
		}
	}
	if !found {
		t.Errorf("на настольной системе проверка не выполнялась — правка выключила её везде, "+
			"журнал: %v", logged)
	}
}
