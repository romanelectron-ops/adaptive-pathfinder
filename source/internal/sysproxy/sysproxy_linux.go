//go:build linux

// Package sysproxy управляет системным HTTP-прокси на уровне ОС.
// Linux: env-переменные + gsettings (GNOME).
package sysproxy

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/apf/adaptive-pathfinder/internal/hostguard"
)

// SetHTTPProxy устанавливает системный HTTP-прокси (host:port).
//
// ОПАСНАЯ ОПЕРАЦИЯ (см. sysproxy_windows.go): при неработающем sing-box убивает сетевой доступ
// приложений, читающих системные настройки. Под `go test` — no-op (барьер hostguard).
func SetHTTPProxy(host string, port int) error {
	if !hostguard.Allow("sysproxy.SetHTTPProxy") {
		return nil
	}
	return setHTTPProxy(host, port)
}

// setHTTPProxy — тело операции БЕЗ стража (см. sysproxy_windows.go).
func setHTTPProxy(host string, port int) error {
	// Метка — см. marker.go/sysproxy_windows.go про то, зачем нужна и почему пишется
	// ДО, а не после (крах между шагами не должен оставить неоткатываемое состояние).
	writeMarker(host, port)

	portStr := strconv.Itoa(port)
	proxy := fmt.Sprintf("http://%s:%d", host, port)

	os.Setenv("http_proxy", proxy)
	os.Setenv("HTTP_PROXY", proxy)
	os.Setenv("https_proxy", proxy)
	os.Setenv("HTTPS_PROXY", proxy)

	// GNOME / Unity
	if exec.Command("which", "gsettings").Run() == nil {
		exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "manual").Run()
		exec.Command("gsettings", "set", "org.gnome.system.proxy.http", "host", host).Run()
		exec.Command("gsettings", "set", "org.gnome.system.proxy.http", "port", portStr).Run()
		exec.Command("gsettings", "set", "org.gnome.system.proxy.https", "host", host).Run()
		exec.Command("gsettings", "set", "org.gnome.system.proxy.https", "port", portStr).Run()
	}
	return nil
}

// Disable снимает системный HTTP-прокси.
func Disable() error {
	if !hostguard.Allow("sysproxy.Disable") {
		return nil
	}
	return disable()
}

// disable — тело операции БЕЗ стража (см. sysproxy_windows.go).
func disable() error {
	os.Unsetenv("http_proxy")
	os.Unsetenv("HTTP_PROXY")
	os.Unsetenv("https_proxy")
	os.Unsetenv("HTTPS_PROXY")

	if exec.Command("which", "gsettings").Run() == nil {
		exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "none").Run()
	}
	clearMarker()
	return nil
}

// RecoverStale — самолечение после нечистого завершения прошлой сессии (см. marker.go,
// sysproxy_windows.go про полную мотивацию — тот же класс риска, здесь ниже по цене
// восстановления: os.Setenv не переживает завершение процесса сам по себе, а
// gsettings mode=none безопасно вызвать даже вхолостую). В отличие от Windows не
// сверяем текущее значение с меткой перед откатом — disable() здесь безусловно
// безопасен (idempotent, не требует привилегий, не имеет разрушительного эффекта при
// вызове вхолостую).
func RecoverStale() {
	if !hostguard.Allow("sysproxy.RecoverStale") {
		return
	}
	if _, _, ok := readMarker(); !ok {
		return
	}
	_ = disable()
}
