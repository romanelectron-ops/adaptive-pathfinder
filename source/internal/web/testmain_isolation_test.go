package web

import (
	"os"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/testenv"
)

// Изоляция каталога данных на весь пакет (дефект D-E2).
//
// Пакет оказался самым «грязным» из всех: за один прогон он переписывал в профиле
// пользователя config.json и оставлял там nodes_cache.json на 3,3 МБ — сервер поднимает
// движок, а тот скачивает каталоги узлов из сети. Загрязнение профиля прекращается здесь;
// зависимость тестов от реальной сети — отдельный открытый пункт (Т-5 в ТЗ Э-3).
func TestMain(m *testing.M) {
	tmp, cleanup := testenv.MustIsolate("apf-web-data-")
	testenv.CheckRedirected(config.DataDir(), tmp)

	code := m.Run()

	cleanup()
	os.Exit(code)
}
