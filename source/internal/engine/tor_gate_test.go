package engine

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/fallback"
)

// Контракт «Tor не применяется, пока его нечем запустить» (дефект D-A29).
//
// Вход:      наличие исполняемого файла tor (системный PATH или каталог бинарей APF).
// Тело:      applyTorFallback.
// Выход:     ErrTorUnavailable либо результат применения конфигурации.
// Fail-safe: нет оркестратора или нет файла → отказ, конфигурация не применяется.
// Инвариант: конфигурация с outbound type:"tor" не доходит до sing-box без файла tor.
//
// Что было до правки: четыре разных места строили конфигурацию с Tor вслепую, sing-box
// падал с «exec: tor: executable file not found», а пользователь видел лишь откат
// подключения и делал вывод, что заблокирована сеть.
func TestApplyTorFallback_RefusesWithoutBinary(t *testing.T) {
	skipIfSystemTor(t)

	e := newTestEngine()
	e.emergencyFallback = fallback.NewFallbackOrchestrator(t.TempDir(), t.TempDir(), nil)

	err := e.applyTorFallback("tor", "Tor")
	if !errors.Is(err, ErrTorUnavailable) {
		t.Fatalf("ожидался ErrTorUnavailable, получено: %v", err)
	}
}

// Отсутствие оркестратора — тоже «нельзя», а не «можно попробовать».
func TestApplyTorFallback_RefusesWithoutOrchestrator(t *testing.T) {
	e := newTestEngine()
	e.emergencyFallback = nil

	if err := e.applyTorFallback("tor", "Tor"); !errors.Is(err, ErrTorUnavailable) {
		t.Fatalf("ожидался ErrTorUnavailable, получено: %v", err)
	}
}

// Ручная кнопка в интерфейсе проходит ту же проверку, что и автоматический фаллбэк:
// иначе пользователь обходит ограничение движка одним нажатием и получает тот же
// невнятный отказ, ради устранения которого всё и делалось.
func TestActivateFallbackTunnel_RefusesWithoutTorBinary(t *testing.T) {
	skipIfSystemTor(t)

	e := newTestEngine()
	e.emergencyFallback = fallback.NewFallbackOrchestrator(t.TempDir(), t.TempDir(), nil)

	for _, tunnel := range []string{"tor", "tor_snowflake", "psiphon"} {
		if err := e.ActivateFallbackTunnel(tunnel); !errors.Is(err, ErrTorUnavailable) {
			t.Errorf("%s: ожидался ErrTorUnavailable, получено: %v", tunnel, err)
		}
	}
}

// Обратная сторона: как только файл появился, отказ снимается. Без этой проверки тесты
// выше проходили бы и у функции, которая отказывает ВСЕГДА.
func TestApplyTorFallback_PassesGateWhenBinaryExists(t *testing.T) {
	binDir := t.TempDir()
	torBin := filepath.Join(binDir, "tor")
	if runtime.GOOS == "windows" {
		torBin += ".exe"
	}
	if err := os.WriteFile(torBin, []byte("not a real tor"), 0o755); err != nil {
		t.Fatalf("подготовка файла: %v", err)
	}

	e := newTestEngine()
	e.emergencyFallback = fallback.NewFallbackOrchestrator(binDir, t.TempDir(), nil)

	// Дальше применение упрётся в отсутствие sing-box — это ожидаемо и не проверяется.
	// Существенно ровно одно: отказ БОЛЬШЕ НЕ ErrTorUnavailable, то есть ворота открылись.
	if err := e.applyTorFallback("tor", "Tor"); errors.Is(err, ErrTorUnavailable) {
		t.Error("файл tor существует, а ворота всё равно закрыты — проверка вырождена")
	}
}

// На машине разработчика Tor может быть установлен системно; тогда ворота законно
// открыты и проверять «отказ» бессмысленно.
func skipIfSystemTor(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("tor"); err == nil {
		t.Skip("в системном PATH есть tor — проверка отказа неприменима")
	}
}
