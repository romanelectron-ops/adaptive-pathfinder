package killswitch

import (
	"strings"
	"testing"
)

// Контракт androidKS (дефект D-A5 — ложно-безопасное состояние).
//
// Вход:      фактическое состояние системной защиты Android («Always-on VPN» + lockdown),
//            переданное нативным слоем через SetAndroidSystemProtection.
// Тело:      отражение этого состояния; НИКАКОГО включения защиты — из приложения это
//            технически невозможно.
// Выход:     Capabilities{ProxyMode, TunMode} == фактическое состояние; Enable() отказывает,
//            если система защиту не обеспечивает.
// Игнорирует: собственный флаг enabled без системного подтверждения.
// Fail-safe: состояние неизвестно ⇒ считаем, что защиты НЕТ (D-2, fail-closed).
// Инвариант: Capabilities() никогда не сообщает защиту, которой нет.

func withProtection(t *testing.T, active bool) {
	t.Helper()
	old := androidSystemProtection.Load()
	androidSystemProtection.Store(active)
	t.Cleanup(func() { androidSystemProtection.Store(old) })
}

func TestAndroidKS_NoSystemProtection_ReportsNothing(t *testing.T) {
	withProtection(t, false)
	k := &androidKS{}

	caps := k.Capabilities()
	if caps.ProxyMode || caps.TunMode {
		t.Fatalf("Capabilities() = %+v — сообщена защита, которой нет; "+
			"при fail-closed движок сочтёт себя защищённым и не затормозит", caps)
	}
}

func TestAndroidKS_SystemProtection_ReportsBothModes(t *testing.T) {
	withProtection(t, true)
	k := &androidKS{}

	caps := k.Capabilities()
	if !caps.ProxyMode || !caps.TunMode {
		t.Fatalf("Capabilities() = %+v — система защищает оба режима, "+
			"ожидались оба true", caps)
	}
}

func TestAndroidKS_Enable_RefusesWithoutSystemProtection(t *testing.T) {
	withProtection(t, false)
	k := &androidKS{}

	err := k.Enable("tun0", nil)
	if err == nil {
		t.Fatal("Enable() вернул nil — молчаливое «ок» при отсутствии защиты " +
			"превращается в незаметную утечку")
	}
	// Текст обязан объяснять пользователю, что делать: он единственный, кто может включить.
	for _, want := range []string{"Always-on", "Настройки"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("сообщение об ошибке не содержит %q: %s", want, err.Error())
		}
	}
	if k.IsEnabled() {
		t.Error("IsEnabled() = true после отказа Enable()")
	}
}

func TestAndroidKS_Enable_SucceedsWithSystemProtection(t *testing.T) {
	withProtection(t, true)
	k := &androidKS{}

	if err := k.Enable("tun0", nil); err != nil {
		t.Fatalf("Enable() = %v, ожидался успех при активной системной защите", err)
	}
	if !k.IsEnabled() {
		t.Error("IsEnabled() = false после успешного Enable()")
	}
}

// Ключевой сценарий: защита была, приложение её «включило», затем пользователь выключил
// системную настройку. Собственный флаг остался — но защиты уже нет, и IsEnabled обязан
// это показать. Иначе движок продолжит считать себя защищённым.
func TestAndroidKS_IsEnabled_FollowsSystemState(t *testing.T) {
	withProtection(t, true)
	k := &androidKS{}
	if err := k.Enable("tun0", nil); err != nil {
		t.Fatalf("подготовка: Enable() = %v", err)
	}

	androidSystemProtection.Store(false) // пользователь выключил в настройках ОС

	if k.IsEnabled() {
		t.Fatal("IsEnabled() = true, хотя системная защита выключена — " +
			"движок считает себя защищённым без защиты")
	}
	if caps := k.Capabilities(); caps.ProxyMode || caps.TunMode {
		t.Fatalf("Capabilities() = %+v после выключения системной защиты", caps)
	}
}

func TestAndroidSystemProtection_RoundTrip(t *testing.T) {
	withProtection(t, false)

	SetAndroidSystemProtection(true)
	if !AndroidSystemProtection() {
		t.Fatal("AndroidSystemProtection() = false после SetAndroidSystemProtection(true)")
	}
	SetAndroidSystemProtection(false)
	if AndroidSystemProtection() {
		t.Fatal("AndroidSystemProtection() = true после SetAndroidSystemProtection(false)")
	}
}

// New() на android обязан отдавать androidKS, а не noop: иначе отказ Enable() не сработает.
func TestNew_AndroidReturnsAndroidKS(t *testing.T) {
	old := newKSGOOS
	newKSGOOS = func() string { return "android" }
	defer func() { newKSGOOS = old }()

	if _, ok := New().(*androidKS); !ok {
		t.Fatalf("New() на android вернул %T, ожидался *androidKS", New())
	}
}
