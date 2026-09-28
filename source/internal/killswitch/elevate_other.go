//go:build !windows

// Package killswitch — заглушка UAC для не-Windows платформ.
package killswitch

import "fmt"

// ErrUACCancelled — заглушка для не-Windows платформ.
var ErrUACCancelled = fmt.Errorf("UAC не поддерживается на этой платформе")

// IsAdmin на не-Windows всегда true (права администратора не нужны для iptables-аналогов).
func IsAdmin() bool { return true }

// RunElevatedNetsh — заглушка для не-Windows платформ.
func RunElevatedNetsh(_ string) error {
	return fmt.Errorf("netsh недоступен на этой платформе")
}
