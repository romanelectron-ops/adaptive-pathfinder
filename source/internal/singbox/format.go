// format.go — утилиты форматирования трафика/скорости для sing-box.
package singbox

import "fmt"

// FormatSpeed форматирует скорость в байт/с в читаемую строку.
// Например: 1500000 → "1.4 MB/s", 512 → "512 B/s".
func FormatSpeed(bytesPerSec int64) string {
	switch {
	case bytesPerSec >= 1<<30:
		return fmt.Sprintf("%.1f GB/s", float64(bytesPerSec)/(1<<30))
	case bytesPerSec >= 1<<20:
		return fmt.Sprintf("%.1f MB/s", float64(bytesPerSec)/(1<<20))
	case bytesPerSec >= 1<<10:
		return fmt.Sprintf("%.1f KB/s", float64(bytesPerSec)/(1<<10))
	default:
		return fmt.Sprintf("%d B/s", bytesPerSec)
	}
}

// FormatBytes форматирует количество байт в читаемую строку.
// Например: 1500000 → "1.4 MB", 0 → "0 B".
func FormatBytes(bytes int64) string {
	switch {
	case bytes >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(bytes)/(1<<30))
	case bytes >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1<<20))
	case bytes >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(bytes)/(1<<10))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
