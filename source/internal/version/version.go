// Package version — единый источник истины о версии APF.
// Все компоненты (CLI, GUI, Web UI, updater, User-Agent) обязаны брать версию
// отсюда, а не хардкодить строку. Значение можно переопределить при сборке:
//
//	go build -ldflags "-X github.com/apf/adaptive-pathfinder/internal/version.Version=1.0.8"
package version

// Version — текущая версия приложения (semver без префикса "v").
var Version = "1.1.11"

// Label возвращает версию с префиксом "v" для отображения в UI.
func Label() string { return "v" + Version }

// UserAgent возвращает значение заголовка User-Agent для HTTP-запросов APF.
func UserAgent() string { return "APF/" + Version }
