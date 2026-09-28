// engine_debt6_watchdog_tun_test.go — долг-6 (2026-09-21, см. apf-healthcheck-checks-socks-not-tun /
// apf-connected-vs-verified-lies): сторож (Watchdog) подтверждал бэйдж «Подтверждено» по ОДНОМУ
// SOCKS-in sing-box, из-за чего «зелёная галка, а сайта нет» переживала смерть пути приложений (TUN)
// посреди сессии. Фикс: на платформе с живой прямой (TUN) пробой (directProbeEnforce — сегодня
// Android) OnHealthy подтверждает бэйдж ТОЛЬКО когда и TUN отвечает; иначе честно гасит его через
// markChannelDead, НЕ переключаясь. Полностью офлайн: прямая проба — через шов e.healthProbeDirect,
// платформа — через e.directProbeGOOS. Никакого реального TUN/sing-box.
package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/checker"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

func debt6Engine(t *testing.T, goos, mode, verifyState string) *Engine {
	t.Helper()
	e := newTestEngine()
	e.directProbeGOOS = goos
	e.cfg.ConnectionMode = mode
	e.stateMu.Lock()
	e.state.Connected = true
	e.state.VerifyState = verifyState
	e.state.ActiveNode = &models.Node{ID: "n1", Name: "active", Address: "203.0.113.7"}
	e.stateMu.Unlock()
	return e
}

func okDirectProbe(context.Context, string) (checker.HealthInfo, error) {
	return checker.HealthInfo{}, nil
}
func failDirectProbe(context.Context, string) (checker.HealthInfo, error) {
	return checker.HealthInfo{}, errors.New("tun path dead")
}

// ─── watchdogTunVerdict: решётка ──────────────────────────────────────────────

// Proxy-режим (не TUN) → вердикт неприменим, прямая проба не запускается.
func TestWatchdogTunVerdict_ProxyMode_Undecided(t *testing.T) {
	e := debt6Engine(t, "android", models.ModeProxy, models.VerifyVerified)
	calls := 0
	e.healthProbeDirect = func(ctx context.Context, u string) (checker.HealthInfo, error) { calls++; return okDirectProbe(ctx, u) }
	h, d := e.watchdogTunVerdict()
	if d || !h {
		t.Errorf("proxy: (healthy,decided)=(%v,%v), want (true,false) — прокси ходит через SOCKS, TUN-вердикт неприменим", h, d)
	}
	if calls != 0 {
		t.Errorf("прямая проба вызвана %d раз в proxy-режиме, want 0", calls)
	}
}

// Windows + VPN → observe (не enforce, живого TUN-стенда нет) → вердикт неприменим.
func TestWatchdogTunVerdict_WindowsVPN_Undecided(t *testing.T) {
	e := debt6Engine(t, "windows", models.ModeVPN, models.VerifyVerified)
	calls := 0
	e.healthProbeDirect = func(ctx context.Context, u string) (checker.HealthInfo, error) { calls++; return failDirectProbe(ctx, u) }
	h, d := e.watchdogTunVerdict()
	if d || !h {
		t.Errorf("windows: (healthy,decided)=(%v,%v), want (true,false) — не enforce", h, d)
	}
	if calls != 0 {
		t.Errorf("прямая проба вызвана %d раз на Windows, want 0 (только observe)", calls)
	}
}

// Android + VPN, но идёт пост-коннект проба (VerifyChecking) → не вмешиваемся (она авторитетнее).
func TestWatchdogTunVerdict_AndroidChecking_Undecided(t *testing.T) {
	e := debt6Engine(t, "android", models.ModeVPN, models.VerifyChecking)
	calls := 0
	e.healthProbeDirect = func(ctx context.Context, u string) (checker.HealthInfo, error) { calls++; return failDirectProbe(ctx, u) }
	h, d := e.watchdogTunVerdict()
	if d || !h {
		t.Errorf("checking: (healthy,decided)=(%v,%v), want (true,false) — пост-коннект проба авторитетнее", h, d)
	}
	if calls != 0 {
		t.Errorf("прямая проба вызвана %d раз во время VerifyChecking, want 0", calls)
	}
}

// Android + VPN + VerifyVerified + TUN отвечает → (healthy,decided)=(true,true).
func TestWatchdogTunVerdict_AndroidVerified_TunOk(t *testing.T) {
	e := debt6Engine(t, "android", models.ModeVPN, models.VerifyVerified)
	e.healthProbeDirect = okDirectProbe
	if h, d := e.watchdogTunVerdict(); !h || !d {
		t.Errorf("(healthy,decided)=(%v,%v), want (true,true)", h, d)
	}
}

// Android + VPN + VerifyVerified + TUN мёртв (обе попытки) → (false,true), ровно N попыток.
func TestWatchdogTunVerdict_AndroidVerified_TunDead(t *testing.T) {
	e := debt6Engine(t, "android", models.ModeVPN, models.VerifyVerified)
	calls := 0
	e.healthProbeDirect = func(ctx context.Context, u string) (checker.HealthInfo, error) { calls++; return failDirectProbe(ctx, u) }
	h, d := e.watchdogTunVerdict()
	if h || !d {
		t.Errorf("(healthy,decided)=(%v,%v), want (false,true)", h, d)
	}
	if calls != watchdogTunProbeAttempts {
		t.Errorf("прямая проба вызвана %d раз, want %d (анти-флап)", calls, watchdogTunProbeAttempts)
	}
}

// Анти-флап: первая попытка провалилась, вторая успешна → (true,true), не гасим по одиночному сбою.
func TestWatchdogTunVerdict_AndroidVerified_FlapRecoversOnRetry(t *testing.T) {
	e := debt6Engine(t, "android", models.ModeVPN, models.VerifyVerified)
	calls := 0
	e.healthProbeDirect = func(ctx context.Context, u string) (checker.HealthInfo, error) {
		calls++
		if calls == 1 {
			return checker.HealthInfo{}, errors.New("transient")
		}
		return checker.HealthInfo{}, nil
	}
	if h, d := e.watchdogTunVerdict(); !h || !d {
		t.Errorf("(healthy,decided)=(%v,%v), want (true,true) — вторая попытка успешна", h, d)
	}
	if calls != 2 {
		t.Errorf("calls=%d, want 2", calls)
	}
}

// ─── OnHealthy: интеграция через реальный newWatchdog() ───────────────────────

// Android, TUN мёртв, SOCKS жив → бэйдж честно гаснет (VerifyFailed), свежесть НЕ продлевается,
// переключение НЕ запускается.
func TestOnHealthy_AndroidTunDead_MarksChannelDeadNoRefresh(t *testing.T) {
	withTempDataDir(t)
	e := debt6Engine(t, "android", models.ModeVPN, models.VerifyVerified)
	e.healthProbeDirect = failDirectProbe
	e.stateMu.Lock()
	e.state.ActiveNode.LastVerifiedAt = 1000 // маркер: refresh перезаписал бы на time.Now()
	e.stateMu.Unlock()

	e.newWatchdog().OnHealthy(42)

	e.stateMu.RLock()
	vs := e.state.VerifyState
	lva := e.state.ActiveNode.LastVerifiedAt
	e.stateMu.RUnlock()
	if vs != models.VerifyFailed {
		t.Errorf("VerifyState=%q, want %q — SOCKS жив, TUN нет: бэйдж обязан честно погаснуть", vs, models.VerifyFailed)
	}
	if lva != 1000 {
		t.Errorf("LastVerifiedAt=%d, want 1000 — при мёртвом TUN свежесть продлевать нельзя", lva)
	}
}

// Android, TUN отвечает → прежнее поведение: свежесть продлена, бэйдж остаётся подтверждённым.
func TestOnHealthy_AndroidTunOk_RefreshesKeepsVerified(t *testing.T) {
	withTempDataDir(t)
	e := debt6Engine(t, "android", models.ModeVPN, models.VerifyVerified)
	e.healthProbeDirect = okDirectProbe
	e.stateMu.Lock()
	e.state.ActiveNode.LastVerifiedAt = 1000
	e.stateMu.Unlock()

	e.newWatchdog().OnHealthy(42)

	e.stateMu.RLock()
	vs := e.state.VerifyState
	lva := e.state.ActiveNode.LastVerifiedAt
	e.stateMu.RUnlock()
	if vs != models.VerifyVerified {
		t.Errorf("VerifyState=%q, want verified — TUN жив", vs)
	}
	if lva == 1000 {
		t.Error("LastVerifiedAt не обновился — при живом TUN свежесть обязана продлеваться (прежнее поведение)")
	}
}

// Android, TUN восстановился, был VerifyFailed → OnHealthy возвращает бэйдж в verified.
func TestOnHealthy_AndroidTunRecovers_RestoresVerified(t *testing.T) {
	withTempDataDir(t)
	e := debt6Engine(t, "android", models.ModeVPN, models.VerifyFailed)
	e.healthProbeDirect = okDirectProbe

	e.newWatchdog().OnHealthy(42)

	e.stateMu.RLock()
	vs := e.state.VerifyState
	e.stateMu.RUnlock()
	if vs != models.VerifyVerified {
		t.Errorf("VerifyState=%q, want verified — TUN снова отвечает, бэйдж обязан восстановиться", vs)
	}
}

// Windows (не enforce): TUN-шов игнорируется, поведение прежнее — бэйдж остаётся verified даже при
// «падающей» прямой пробе (её вообще не зовут).
func TestOnHealthy_WindowsVPN_UnchangedBySocks(t *testing.T) {
	withTempDataDir(t)
	e := debt6Engine(t, "windows", models.ModeVPN, models.VerifyVerified)
	tunCalls := 0
	e.healthProbeDirect = func(ctx context.Context, u string) (checker.HealthInfo, error) { tunCalls++; return failDirectProbe(ctx, u) }

	e.newWatchdog().OnHealthy(42)

	e.stateMu.RLock()
	vs := e.state.VerifyState
	e.stateMu.RUnlock()
	if vs != models.VerifyVerified {
		t.Errorf("Windows: VerifyState=%q, want verified — не enforce, TUN-гейт не применяется", vs)
	}
	if tunCalls != 0 {
		t.Errorf("Windows: прямая проба вызвана %d раз, want 0 (только observe, поведение прежнее)", tunCalls)
	}
}
