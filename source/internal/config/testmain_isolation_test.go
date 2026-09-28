package config

import (
	"os"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/testenv"
)

// Изоляция каталога данных на весь пакет (дефект D-E2).
//
// Пакет, который вычисляет путь к каталогу данных, сам же в него и писал: тесты
// SaveConfig перезаписывали config.json в профиле пользователя.
//
// Подмена совместима с t.Setenv внутри отдельных тестов: тот меняет значение на время
// теста и восстанавливает — восстанавливает уже во временное, а не в настоящее.
func TestMain(m *testing.M) {
	tmp, cleanup := testenv.MustIsolate("apf-config-data-")
	testenv.CheckRedirected(DataDir(), tmp)

	code := m.Run()

	cleanup()
	os.Exit(code)
}
