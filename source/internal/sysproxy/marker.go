// Package sysproxy — marker.go: общая для всех платформ метка "APF сам включил системный
// прокси и мог не успеть его снять".
//
// Найдено живым инцидентом 2026-08-13: пользователь сообщил, что на его реальной рабочей
// машине через какое-то время после использования APF пропадал интернет НАВСЕГДА — переживал
// перезагрузки, не было видно ни одного процесса APF, помогло только удаление приложения.
// Ровно то, о чём уже предупреждает комментарий в sysproxy_windows.go: SetHTTPProxy пишет
// ProxyServer/ProxyEnable=1 прямо в реестр HKCU и НЕ снимается автоматически при крахе/
// принудительном завершении процесса. tools/host_watchdog/apf_host_watchdog.ps1 уже существует
// именно для этого случая, но это heartbeat-страховка для сессий, где кто-то (Claude) активно
// поддерживает пульс — она не защищает обычную повседневную работу пользователя без активного
// присмотра ИИ, и неизвестно, была ли она вообще зарегистрирована как Scheduled Task на
// пострадавшей машине.
//
// Метка здесь — единственный сигнал "прошлая сессия точно НЕ откатила прокси" (Disable
// удаляет её при успехе). Пишется марка ДО, а не после самой записи в реестр, — крах между
// этими двумя шагами не должен привести к пропущенной метке.
package sysproxy

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/apf/adaptive-pathfinder/internal/config"
)

// markerPathFn — инжектируемый шов (см. regOpenKeyFn и соседей в sysproxy_windows.go): тесты
// подменяют его на t.TempDir(), чтобы не писать в НАСТОЯЩИЙ %APPDATA% пользователя —
// config.DataDir() на Windows не перенаправляется переменными окружения (см. комментарий в
// internal/config/config.go), поэтому без этого шва тест marker-файла трогал бы реальный диск.
var markerPathFn = func() string {
	return filepath.Join(config.DataDir(), "sysproxy_active.marker")
}

func writeMarker(host string, port int) {
	_ = os.WriteFile(markerPathFn(), []byte(fmt.Sprintf("%s:%d", host, port)), 0o600)
}

func clearMarker() {
	_ = os.Remove(markerPathFn())
}

// readMarker возвращает (host, port, true), если метка есть и разобралась; иначе ok=false —
// вызывающая сторона трактует это как "нечего восстанавливать", а не как ошибку.
func readMarker() (host string, port int, ok bool) {
	data, err := os.ReadFile(markerPathFn())
	if err != nil {
		return "", 0, false
	}
	host, portStr, found := strings.Cut(strings.TrimSpace(string(data)), ":")
	if !found {
		return "", 0, false
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, false
	}
	return host, p, true
}

// originalMarkerPathFn — тот же приём инжекции, что и markerPathFn (см. её комментарий):
// тесты подменяют на t.TempDir().
//
// P1 (аудит 2026-09-01, security-раздел, находка №14): раньше setHTTPProxy/disable не
// сохраняли и не восстанавливали ПРЕЖНИЕ значения ProxyServer/ProxyEnable — пользователь с
// личным/корпоративным прокси после одного цикла подключения APF терял свою настройку
// безвозвратно (ProxyServer затёрт значением APF, disable() снимает только ProxyEnable, но
// не возвращает старый ProxyServer). Отдельный файл, не переиспользующий markerPathFn: тот
// маркер хранит "что APF САМ поставил" (для распознавания "это моя незакрытая сессия" при
// восстановлении после краха, см. recoverStale) — семантически другая вещь, чем "что было
// ДО APF".
var originalMarkerPathFn = func() string {
	return filepath.Join(config.DataDir(), "sysproxy_original.marker")
}

// writeOriginalIfAbsent сохраняет ProxyServer/ProxyEnable, БЫВШИЕ в реестре ДО первой правки
// APF в этой сессии — но ТОЛЬКО если такой снимок ещё не сохранён. Без этого условия
// повторный SetHTTPProxy (например, смена VPN-узла без промежуточного Disable — штатный
// сценарий переключения) затёр бы настоящий "до APF" снимок уже изменённым APF значением, и
// восстановление на Disable вернуло бы пользователю НЕ его исходные настройки, а
// предпоследний узел APF.
func writeOriginalIfAbsent(enabled bool, server string) {
	path := originalMarkerPathFn()
	if _, err := os.Stat(path); err == nil {
		return
	}
	enabledStr := "0"
	if enabled {
		enabledStr = "1"
	}
	_ = os.WriteFile(path, []byte(enabledStr+"\n"+server), 0o600)
}

// readOriginal — снимок настроек прокси до APF, если он есть (ok=false — начинали с
// уже отсутствующего снимка: либо его никогда не было, либо это старая метка до этой
// правки, либо она уже была потрачена предыдущим Disable в ЭТОЙ же сессии).
func readOriginal() (enabled bool, server string, ok bool) {
	data, err := os.ReadFile(originalMarkerPathFn())
	if err != nil {
		return false, "", false
	}
	enabledStr, srv, found := strings.Cut(string(data), "\n")
	if !found {
		return false, "", false
	}
	return enabledStr == "1", srv, true
}

func clearOriginalMarker() {
	_ = os.Remove(originalMarkerPathFn())
}
