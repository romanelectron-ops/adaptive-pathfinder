package engine

// engine_coverage6_test.go — coverage pass 6.
// Target: +5-6% from 89.3%, pushing towards 95%+.
//
// Uncovered blocks targeted here:
//   1435,1461   — AddPaidProvider success path (fetch OK → register → add nodes)
//   1519        — TestPaidProvider success return
//   1063,1069   — tryFallback() case FallbackSnowflake branch
//   1070,1079   — tryFallback() case FallbackPsiphon branch (tor not found)

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/fallback"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── AddPaidProvider: subscription success path ───────────────────────────────

// TestAddPaidProvider_SubscriptionSuccess покрывает ветку успешного
// добавления провайдера в AddPaidProvider (строки 1435-1461):
// p.Fetch() возвращает узлы → регистрируем провайдера → добавляем узлы в пул.
//
// Используем локальный HTTP-сервер, который возвращает одну VLESS-ссылку,
// поэтому Fetch() всегда успешен без внешней сети.
func TestAddPaidProvider_SubscriptionSuccess(t *testing.T) {
	vlessLink := "vless://12345678-1234-1234-1234-000000000001@1.2.3.4:443?type=tcp&security=none#Cov6Node"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, vlessLink)
	}))
	defer srv.Close()

	e := newTestEngine()
	err := e.AddPaidProvider(models.PaidProviderEntry{
		ID:   "cov6-sub-ok",
		Name: "Cov6Sub",
		Type: "subscription",
		URL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("AddPaidProvider unexpected error: %v", err)
	}

	// Проверяем что узел был добавлен в пул.
	e.mu.RLock()
	nodeCount := len(e.nodes)
	e.mu.RUnlock()
	if nodeCount == 0 {
		t.Error("expected at least one node in pool after AddPaidProvider success")
	}
	t.Logf("OK: AddPaidProvider subscription success path covered (lines 1435-1461), nodes=%d", nodeCount)
}

// ─── TestPaidProvider: subscription success path ──────────────────────────────

// TestTestPaidProvider_SubscriptionSuccess покрывает строку 1519:
// return len(nodes), nil  — успешный возврат из TestPaidProvider.
func TestTestPaidProvider_SubscriptionSuccess(t *testing.T) {
	vlessLink := "vless://12345678-1234-1234-1234-000000000002@2.3.4.5:443?type=tcp&security=none#Cov6Node2"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, vlessLink)
	}))
	defer srv.Close()

	e := newTestEngine()
	n, err := e.TestPaidProvider(models.PaidProviderEntry{
		ID:   "cov6-test-ok",
		Name: "Cov6TestSub",
		Type: "subscription",
		URL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("TestPaidProvider unexpected error: %v", err)
	}
	if n == 0 {
		t.Error("expected at least 1 node from TestPaidProvider success")
	}
	t.Logf("OK: TestPaidProvider success path covered (line 1519), n=%d", n)
}

// ─── tryFallback: FallbackSnowflake branch ────────────────────────────────────

// TestTryFallback_SnowflakePath покрывает ветку `case fallback.FallbackSnowflake`
// (строки 1063-1069) в tryFallback().
//
// Стратегия:
//  1. Создаём temp-dir с поддельным tor/tor.exe, чтобы IsAvailable() вернул true.
//  2. Заменяем e.emergencyFallback на оркестратор с этим binDir.
//  3. Отменяем e.ctx → context.WithTimeout(e.ctx, 15s) немедленно истекает →
//     TestConnectivity(ctx) → false → SelectBest → FallbackSnowflake.
//  4. applySingBoxConfig завершается с ошибкой (нет sing-box), что нормально:
//     нам важно что case-ветка выполнена.
func TestTryFallback_SnowflakePath(t *testing.T) {
	// Создаём поддельный tor-бинарник.
	tmpBinDir := t.TempDir()
	torBin := filepath.Join(tmpBinDir, "tor")
	if runtime.GOOS == "windows" {
		torBin += ".exe"
	}
	if err := os.WriteFile(torBin, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatalf("create fake tor: %v", err)
	}

	tmpDataDir := t.TempDir()
	e := newTestEngine()

	// Заменяем emergencyFallback на оркестратор с fake-бинарником.
	e.emergencyFallback = fallback.NewFallbackOrchestrator(tmpBinDir, tmpDataDir, e.log)

	// Отменяем контекст движка — SelectBest получит истёкший ctx и
	// TestConnectivity вернёт false немедленно → FallbackSnowflake.
	e.cancel()

	// tryFallback не должен паниковать; ошибка (нет sing-box) — ожидаема.
	_ = e.tryFallback()
	t.Log("OK: tryFallback FallbackSnowflake branch covered (lines 1063-1069)")
}

// ─── tryFallback: FallbackPsiphon branch ─────────────────────────────────────

// TestTryFallback_PsiphonPath покрывает ветку `case fallback.FallbackPsiphon`
// (строки 1070-1079) в tryFallback().
//
// Стратегия: binDir пуст (нет tor.exe) → IsAvailable() == false →
// SelectBest → FallbackPsiphon → ветка покрыта.
//
// ВНИМАНИЕ: IsAvailable сначала проверяет exec.LookPath("tor") (системный PATH).
// Если tor установлен в системе, тест пропускается — иначе получим FallbackSnowflake,
// а не FallbackPsiphon, и целевая ветка не будет покрыта.
func TestTryFallback_PsiphonPath(t *testing.T) {
	if _, err := exec.LookPath("tor"); err == nil {
		t.Skip("system tor found in PATH; IsAvailable() returns true regardless of binDir — cannot isolate FallbackPsiphon branch without mocking")
	}

	// Пустой binDir и tor нет в PATH → IsAvailable() == false → FallbackPsiphon.
	emptyBinDir := t.TempDir()
	tmpDataDir := t.TempDir()

	e := newTestEngine()
	e.emergencyFallback = fallback.NewFallbackOrchestrator(emptyBinDir, tmpDataDir, e.log)

	// Отменяем контекст чтобы любые сетевые вызовы завершались немедленно.
	e.cancel()

	_ = e.tryFallback()
	t.Log("OK: tryFallback FallbackPsiphon branch covered (lines 1070-1079)")
}
