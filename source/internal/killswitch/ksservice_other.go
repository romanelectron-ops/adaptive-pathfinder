//go:build !windows

// Заглушки служебного KS-канала для не-Windows платформ (Вариант A актуален только на Windows).
// Движок (кросс-платформенный) может звать NewServiceClient/ServiceAvailable — тут они всегда false.
package killswitch

// ServiceAvailable — на не-Windows служебного KS-канала нет.
func ServiceAvailable() bool { return false }

// NewServiceClient — на не-Windows служебного клиента нет.
func NewServiceClient() (KillSwitch, bool) { return nil, false }
