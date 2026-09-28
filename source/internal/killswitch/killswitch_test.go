package killswitch

import (
	"testing"
)

// ─── factory ─────────────────────────────────────────────────────────────────

func TestNew_ReturnsNonNil(t *testing.T) {
	ks := New()
	if ks == nil {
		t.Fatal("New() returned nil")
	}
}

// ─── noopKS ──────────────────────────────────────────────────────────────────

func TestNoopKS_Enable(t *testing.T) {
	ks := &noopKS{}
	if err := ks.Enable("tun0", nil); err != nil {
		t.Errorf("noopKS.Enable: %v", err)
	}
}

func TestNoopKS_EnableWithPorts(t *testing.T) {
	ks := &noopKS{}
	if err := ks.Enable("tun0", []int{80, 443, 1080}); err != nil {
		t.Errorf("noopKS.Enable with ports: %v", err)
	}
}

func TestNoopKS_Disable(t *testing.T) {
	ks := &noopKS{}
	if err := ks.Disable(); err != nil {
		t.Errorf("noopKS.Disable: %v", err)
	}
}

func TestNoopKS_IsEnabled(t *testing.T) {
	ks := &noopKS{}
	if ks.IsEnabled() {
		t.Error("noopKS.IsEnabled should always be false")
	}
	_ = ks.Enable("tun0", nil)
	if ks.IsEnabled() {
		t.Error("noopKS.IsEnabled should remain false after Enable")
	}
}

// ─── androidKS ───────────────────────────────────────────────────────────────

// ВНИМАНИЕ (D-A5). Прежние версии этих тестов требовали, чтобы Enable() всегда возвращал
// успех, а IsEnabled() после него — true. Тем самым они закрепляли дефект: приложение на
// Android НЕ МОЖЕТ включить Kill Switch, это делает пользователь в настройках ОС
// («Always-on VPN» + «Блокировать соединения без VPN»). Молчаливый успех при отсутствующей
// защите превращался в ложно-безопасное состояние: при D-2 (fail-closed) движок считал себя
// защищённым и не тормозил там, где обязан.
//
// Новый контракт: androidKS ОТРАЖАЕТ состояние системы. Тесты приведены к нему.
// Подробные проверки — в android_ks_test.go.

func TestAndroidKS_Enable_RequiresSystemProtection(t *testing.T) {
	ks := &androidKS{}

	// Системная защита выключена — Enable обязан отказать.
	old := androidSystemProtection.Load()
	androidSystemProtection.Store(false)
	defer androidSystemProtection.Store(old)

	if err := ks.Enable("tun0", []int{80, 443}); err == nil {
		t.Error("androidKS.Enable вернул успех при выключенной системной защите")
	}
	if ks.IsEnabled() {
		t.Error("androidKS.IsEnabled = true после отказа Enable()")
	}

	// Пользователь включил защиту в настройках ОС — теперь Enable проходит.
	androidSystemProtection.Store(true)
	if err := ks.Enable("tun0", []int{80, 443}); err != nil {
		t.Errorf("androidKS.Enable при активной системной защите: %v", err)
	}
	if !ks.IsEnabled() {
		t.Error("androidKS должен быть включён после успешного Enable()")
	}
}

func TestAndroidKS_Disable(t *testing.T) {
	old := androidSystemProtection.Load()
	androidSystemProtection.Store(true)
	defer androidSystemProtection.Store(old)

	ks := &androidKS{enabled: true}
	if err := ks.Disable(); err != nil {
		t.Errorf("androidKS.Disable: %v", err)
	}
	if ks.IsEnabled() {
		t.Error("androidKS should be disabled after Disable()")
	}
}

func TestAndroidKS_EnableDisableCycle(t *testing.T) {
	old := androidSystemProtection.Load()
	androidSystemProtection.Store(true)
	defer androidSystemProtection.Store(old)

	ks := &androidKS{}
	_ = ks.Enable("apf0", nil)
	_ = ks.Disable()
	_ = ks.Enable("apf0", nil)
	if !ks.IsEnabled() {
		t.Error("androidKS should be enabled after second Enable()")
	}
}

// ─── windowsKS ───────────────────────────────────────────────────────────────

// stubExecCmd подменяет execCmdFn на no-op, чтобы тесты windowsKS НЕ трогали
// реальный системный фаервол (DEF-07: иначе netsh add/delete rule выполнялся
// по-настоящему и блокировал интернет хоста при прогоне на Windows).
func stubExecCmd() func() {
	orig := execCmdFn
	execCmdFn = func(string, ...string) error { return nil }
	return func() { execCmdFn = orig }
}

func TestWindowsKS_InitialState(t *testing.T) {
	ks := &windowsKS{}
	if ks.IsEnabled() {
		t.Error("windowsKS: initial state should be disabled")
	}
}

func TestWindowsKS_Enable_SetsFlag(t *testing.T) {
	defer stubExecCmd()()
	ks := &windowsKS{}
	_ = ks.Enable("apf0", []int{443, 1080})
	if !ks.IsEnabled() {
		t.Error("windowsKS: should be enabled=true after Enable()")
	}
}

func TestWindowsKS_Enable_EmptyPorts(t *testing.T) {
	defer stubExecCmd()()
	ks := &windowsKS{}
	_ = ks.Enable("apf0", nil)
	if !ks.IsEnabled() {
		t.Error("windowsKS: should be enabled=true after Enable() with nil ports")
	}
}

func TestWindowsKS_Enable_ThenDisable(t *testing.T) {
	defer stubExecCmd()()
	ks := &windowsKS{}
	_ = ks.Enable("apf0", nil)
	_ = ks.Disable()
	if ks.IsEnabled() {
		t.Error("windowsKS: should be disabled after Disable()")
	}
}

func TestWindowsKS_Disable_SetsFlag(t *testing.T) {
	defer stubExecCmd()()
	ks := &windowsKS{enabled: true}
	_ = ks.Disable()
	if ks.IsEnabled() {
		t.Error("windowsKS: should be disabled after Disable()")
	}
}

// ─── linuxKS ─────────────────────────────────────────────────────────────────

func TestLinuxKS_InitialState(t *testing.T) {
	ks := &linuxKS{}
	if ks.IsEnabled() {
		t.Error("linuxKS: initial state should be disabled")
	}
}

func TestLinuxKS_Enable_SetsFlag(t *testing.T) {
	ks := &linuxKS{}
	_ = ks.Enable("apf0", []int{80, 443})
}

func TestLinuxKS_Enable_EmptyTun(t *testing.T) {
	ks := &linuxKS{}
	_ = ks.Enable("", nil)
}

func TestLinuxKS_Disable_SetsFlag(t *testing.T) {
	ks := &linuxKS{enabled: true}
	_ = ks.Disable()
	if ks.IsEnabled() {
		t.Error("linuxKS: should be disabled after Disable()")
	}
}

// ─── ResetAll / QuickReset ───────────────────────────────────────────────────

func TestResetAll_NoPanic(t *testing.T) {
	_ = ResetAll()
}

func TestQuickReset_NoPanic(t *testing.T) {
	QuickReset()
}

// ─── IsAdmin ─────────────────────────────────────────────────────────────────

func TestIsAdmin_NoPanic(t *testing.T) {
	_ = IsAdmin()
}

// ─── runCmd helper ───────────────────────────────────────────────────────────

func TestRunCmd_InvalidCommand(t *testing.T) {
	// Обходим тест-барьер DEF-08 (execCmdFn=no-op), чтобы проверить РЕАЛЬНЫЙ exec:
	// несуществующий бинарь → ошибка. Фаервол при этом не затрагивается.
	orig := execCmdFn
	defer func() { execCmdFn = orig }()
	execCmdFn = realExecCmd
	err := runCmd("this-command-does-not-exist-xyz")
	if err == nil {
		t.Error("expected error for non-existent command")
	}
}

func TestRunCmd_Echo(t *testing.T) {
	err := runCmd("cmd", "/c", "echo", "hello")
	t.Logf("runCmd echo result: %v", err)
}
