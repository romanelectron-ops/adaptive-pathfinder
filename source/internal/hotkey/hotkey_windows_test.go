//go:build windows

package hotkey

import (
	"testing"
	"time"
)

func TestParseCombo_Valid(t *testing.T) {
	cases := []struct {
		combo    string
		wantMods uint32
		wantVK   uint32
	}{
		{"ctrl+shift+F12", modControl | modShift, 0x7B},
		{"Ctrl+Shift+F12", modControl | modShift, 0x7B},
		{"alt+F1", modAlt, 0x70},
		{"win+A", modWin, 'A'},
		{"control+shift+alt+9", modControl | modShift | modAlt, '9'},
		{"meta+Z", modWin, 'Z'},
	}
	for _, c := range cases {
		mods, vk, err := parseCombo(c.combo)
		if err != nil {
			t.Errorf("parseCombo(%q) unexpected error: %v", c.combo, err)
			continue
		}
		if mods != c.wantMods {
			t.Errorf("parseCombo(%q) mods = %#x, want %#x", c.combo, mods, c.wantMods)
		}
		if vk != c.wantVK {
			t.Errorf("parseCombo(%q) vk = %#x, want %#x", c.combo, vk, c.wantVK)
		}
	}
}

func TestParseCombo_RejectsNoModifier(t *testing.T) {
	if _, _, err := parseCombo("F12"); err == nil {
		t.Error("expected error for hotkey without modifier, got nil")
	}
}

func TestParseCombo_RejectsUnknownModifier(t *testing.T) {
	if _, _, err := parseCombo("hyper+F12"); err == nil {
		t.Error("expected error for unknown modifier, got nil")
	}
}

func TestParseCombo_RejectsUnknownKey(t *testing.T) {
	if _, _, err := parseCombo("ctrl+F99"); err == nil {
		t.Error("expected error for out-of-range F-key, got nil")
	}
	if _, _, err := parseCombo("ctrl+PrintScreen"); err == nil {
		t.Error("expected error for unsupported named key, got nil")
	}
}

func TestParseCombo_Empty(t *testing.T) {
	if _, _, err := parseCombo(""); err == nil {
		t.Error("expected error for empty combo, got nil")
	}
}

func TestRegister_InvalidComboReturnsError(t *testing.T) {
	m, err := Register("not a combo at all", func() {})
	if err == nil {
		t.Fatal("expected error for invalid combo")
	}
	if m != nil {
		t.Error("expected nil Manager on error")
	}
}

// TestRegister_ValidCombo_LifecycleSmoke — реальный RegisterHotKey/GetMessage-цикл целиком
// (не только parseCombo). Комбинация ctrl+alt+shift+F24 выбрана как заведомо не занятая ни
// ОС, ни другими приложениями (F24 практически никогда не используется), чтобы тест был
// безопасен на реальной интерактивной машине и не отбирал чужой хоткей. Не пытается
// синтезировать реальное нажатие клавиши (SendInput — за рамками этого теста, слишком хрупко
// в автоматическом прогоне) — проверяет только то, что регистрация и чистое снятие не виснут
// и не падают, включая корректность раскладки структуры msg под настоящий GetMessageW.
func TestRegister_ValidCombo_LifecycleSmoke(t *testing.T) {
	m, err := Register("ctrl+alt+shift+F24", func() {})
	if err != nil {
		t.Fatalf("Register failed (unexpected on an interactive desktop): %v", err)
	}
	done := make(chan struct{})
	go func() {
		m.Unregister()
		close(done)
	}()
	select {
	case <-done:
		t.Log("OK: Register/Unregister lifecycle completed cleanly")
	case <-time.After(5 * time.Second):
		t.Fatal("Unregister did not return within 5s — message loop likely stuck")
	}
}
