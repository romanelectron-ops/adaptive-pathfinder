package engine

// Тесты доработок аудита v1.1.0:
//   T-01  — verifyTunnelHealthCheck реально дёргает checker.HTTPHealthCheck через локальный SOCKS5;
//   T-13b — GetLeakGuardStatus отдаёт честный webrtc_status (Enforced != "full").

import (
	"context"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/checker"
	"github.com/apf/adaptive-pathfinder/internal/leakguard"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// T-01: когда на ListenPort нет SOCKS5-прокси — verifyTunnelHealthCheck возвращает ошибку
// без паники. Это доказывает, что метод действительно вызывает checker.HTTPHealthCheck
// (через dialViaSOCKS5), который раньше был достижим только из тестов.
func TestVerifyTunnelHealthCheck_NoProxy(t *testing.T) {
	e := &Engine{
		cfg:     &models.AppConfig{ListenPort: 1}, // порт 1 — заведомо нет локального SOCKS5
		checker: checker.New(1, 1),
		state:   &models.ConnectionState{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, _, err := e.verifyTunnelHealthCheck(ctx, ""); err == nil {
		t.Fatal("ожидалась ошибка, когда SOCKS5-прокси не слушает ListenPort")
	}
}

// T-13b: GetLeakGuardStatus обязан отдавать поле webrtc_status, и Enforced никогда не "full"
// (APF не закрывает WebRTC браузера из внешнего процесса — честная маркировка).
func TestGetLeakGuardStatus_WebRTCHonest(t *testing.T) {
	e := &Engine{
		// P1 (аудит 2026-09-01, находка №16): GetLeakGuardStatus теперь спрашивает реальное
		// состояние Kill Switch (KillSwitchStatus → currentKS → e.cfg.ConnectionMode) для
		// честного ipv6_status — cfg обязателен, иначе nil-разыменование глубоко внутри
		// currentKS(). Реальный Engine (engine.New()) его всегда задаёт; здесь минимальный
		// hand-built Engine для юнит-теста, поэтому добавляем явно.
		cfg:         &models.AppConfig{},
		ipv6Guard:   leakguard.NewIPv6Guard(),
		webrtcGuard: leakguard.NewWebRTCGuard(),
		state:       &models.ConnectionState{},
	}
	st := e.GetLeakGuardStatus()
	ws, ok := st["webrtc_status"].(leakguard.WebRTCStatus)
	if !ok {
		t.Fatalf("webrtc_status отсутствует или неверного типа: %T", st["webrtc_status"])
	}
	if ws.Enforced == "full" {
		t.Errorf("WebRTC Enforced никогда не должен быть 'full', получено %q", ws.Enforced)
	}
}
