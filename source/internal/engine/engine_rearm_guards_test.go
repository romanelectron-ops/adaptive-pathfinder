package engine

import "testing"

// Регресс живого ПК 2026-10-27: «Отключить» снимает IPv6-защиту, а следующее подключение не
// взводило её заново — конфиг sing-box строился без глобального ipv4_only-правила DNS, и
// приложения уходили в IPv6 через TUN к узлу без IPv6 (curl висел 3–10 с).
func TestRearmDeviceGuards_RestoresAfterDisconnect(t *testing.T) {
	e := newTestEngine()
	e.cfg.BlockIPv6Leak = true
	e.cfg.BlockWebRTC = true

	// То, что делает Stop(): защиты сняты, Start() больше не вызывается.
	_ = e.ipv6Guard.Disable()
	_ = e.webrtcGuard.Disable()
	if e.ipv6Guard.IsEnabled() || e.webrtcGuard.IsEnabled() {
		t.Fatal("setup: защиты должны быть сняты")
	}

	e.rearmDeviceGuards()

	if !e.ipv6Guard.IsEnabled() {
		t.Error("IPv6 Guard не взведён при BlockIPv6Leak=true — подключение построит конфиг без ipv4_only")
	}
	if !e.webrtcGuard.IsEnabled() {
		t.Error("WebRTC Guard не взведён при BlockWebRTC=true")
	}
}

// Выбор пользователя главнее (C-13): выключенное в конфиге не включается.
func TestRearmDeviceGuards_RespectsUserOff(t *testing.T) {
	e := newTestEngine()
	e.cfg.BlockIPv6Leak = false
	e.cfg.BlockWebRTC = false
	_ = e.ipv6Guard.Disable()
	_ = e.webrtcGuard.Disable()

	e.rearmDeviceGuards()

	if e.ipv6Guard.IsEnabled() {
		t.Error("IPv6 Guard включён вопреки BlockIPv6Leak=false")
	}
	if e.webrtcGuard.IsEnabled() {
		t.Error("WebRTC Guard включён вопреки BlockWebRTC=false")
	}
}

// Уже взведённое остаётся взведённым (повторный вызов — на каждое построение конфига).
func TestRearmDeviceGuards_Idempotent(t *testing.T) {
	e := newTestEngine()
	e.cfg.BlockIPv6Leak = true
	_ = e.ipv6Guard.Enable("apf0")
	e.rearmDeviceGuards()
	e.rearmDeviceGuards()
	if !e.ipv6Guard.IsEnabled() {
		t.Error("IPv6 Guard потерял состояние после повторного вызова")
	}
}
