//go:build !windows && !linux

// Package sysproxy — заглушка для Android и прочих платформ.
package sysproxy

// SetHTTPProxy — no-op.
func SetHTTPProxy(host string, port int) error { return nil }

// Disable — no-op.
func Disable() error { return nil }

// RecoverStale — no-op (см. sysproxy_windows.go/sysproxy_linux.go): на Android/прочих
// платформах SetHTTPProxy/Disable сами no-op, восстанавливать нечего.
func RecoverStale() {}
