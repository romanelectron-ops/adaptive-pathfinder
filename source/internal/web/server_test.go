package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/engine"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// newTestServer creates a Server with a fresh engine for testing.
// engine.New() initialises all sub-components but does NOT start background
// goroutines – that only happens inside Engine.Start().
//
// cfg.Sources — очищен НАМЕРЕННО (LOT-F1, хрупкость TestApiSaveConfig_ValidPatch).
//
// Диагноз (подтверждён повторным прогоном ^TestApiForceSwitch_Post|TestApiSaveConfig_ValidPatch$,
// -count=1, 8 итераций подряд: 3/8 красных, включая пойманный в логе
// "Sources: ошибка сохранения времени обновления: rename ...config.json.tmp ...config.json:
// The system cannot find the file specified"):
//
// models.DefaultConfig().Sources включает источник "tor-snowflake" (Type: "tor"). У его
// обработчика, sources.Manager.fetchTorBridges, ЛЮБОЙ исход (реальные мосты получены, все
// HTTP-запросы отвергнуты netguard под `go test`, список мостов вообще пуст) возвращает
// (bridges, nil) — err ВСЕГДА nil. Поэтому Manager.FetchAll помечает "tor-snowflake" как
// только что обновлённый при КАЖДОМ вызове updateSources(), независимо от сети. Любой
// хэндлер, запускающий фоновое пересканирование источников движка через goTracked
// (например apiForceSwitch → ForceSwitchNow → ScanAndConnect → updateSources(true), когда
// пул узлов пуст — обычное состояние свежесозданного тестового движка), детерминированно
// уходит в Engine.persistSourceTimestamps → config.SaveConfig → os.Rename(tmp, config.json)
// уже ПОСЛЕ того как http-тест вернул ответ и т.Cleanup передал управление следующему
// тесту. Все тесты пакета делят ОДИН файл config.json (общий DataDir на весь бинарник,
// см. testmain_isolation_test.go) — поэтому фоновый rename одного теста иногда застаёт
// os.Rename СЛЕДУЮЩЕГО теста (например TestApiSaveConfig_ValidPatch) в процессе записи
// того же файла, и один из два конкурентов получает ERROR_SHARING_VIOLATION/"cannot find
// the file specified" на Windows → неверные 400 вместо 200.
//
// Правка тестовая (внутри пакета web, файл *_test.go): очищаем cfg.Sources до engine.New(),
// закрывая источник фоновой записи для ЛЮБОГО теста в пакете, использующего newTestServer, —
// не только для двух исторически столкнувшихся тестов. Ни один тест пакета web не проверяет
// содержимое cfg.Sources (GetCatalogStatus строится из отдельного catalogRegistry/e.nodes),
// поэтому поведение проверяемых хэндлеров не меняется. Продакшен-код (internal/config,
// internal/engine, internal/sources, server.go) НЕ тронут.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := models.DefaultConfig()
	cfg.Sources = nil
	eng := engine.New(cfg)
	return New(eng, 0)
}

// ── helpers ──────────────────────────────────────────────────────────────────

func testGET(s *Server, fn http.HandlerFunc) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	fn(w, r)
	return w
}

func testPOST(s *Server, fn http.HandlerFunc, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	var br *bytes.Reader
	if body != "" {
		br = bytes.NewReader([]byte(body))
	} else {
		br = bytes.NewReader(nil)
	}
	r := httptest.NewRequest(http.MethodPost, "/", br)
	fn(w, r)
	return w
}

// ── cors ─────────────────────────────────────────────────────────────────────

// Подстановочный CORS обязан ОТСУТСТВОВАТЬ (изменено 2026-08-24).
//
// Раньше здесь ожидалось «*», и тест зелёным закреплял реальную дыру: API отдаёт
// /api/server-role/identity с приватным ключом Reality, и при Access-Control-Allow-Origin: *
// любая открытая пользователем веб-страница могла кросс-доменно запросить локальный API и
// ПРОЧИТАТЬ ответ. Законным потребителям заголовок не нужен: веб-интерфейс отдаётся с того
// же origin, десктоп ходит через Wails-биндинги, режим наблюдателя — обычный Go-клиент.
func TestCors_NoWildcardOrigin(t *testing.T) {
	w := httptest.NewRecorder()
	cors(w)
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type: want application/json, got %q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, заголовка быть не должно: подстановочный "+
			"CORS открывает локальное API любой странице в браузере", got)
	}
}

// ── New / callbacks ───────────────────────────────────────────────────────────

func TestNew_OnLog_CapturedInLogs(t *testing.T) {
	cfg := models.DefaultConfig()
	eng := engine.New(cfg)
	s := New(eng, 0)

	eng.OnLog("hello from log")
	s.logsMu.Lock()
	n := len(s.logs)
	s.logsMu.Unlock()
	if n != 1 {
		t.Errorf("expected 1 log entry, got %d", n)
	}
}

func TestNew_OnLeakDetected_CapturedInLogs(t *testing.T) {
	cfg := models.DefaultConfig()
	eng := engine.New(cfg)
	s := New(eng, 0)

	eng.OnLeakDetected("dns", "test details")
	s.logsMu.Lock()
	n := len(s.logs)
	s.logsMu.Unlock()
	if n != 1 {
		t.Errorf("expected 1 log entry after OnLeakDetected, got %d", n)
	}
}

func TestNew_BothCallbacks(t *testing.T) {
	cfg := models.DefaultConfig()
	eng := engine.New(cfg)
	s := New(eng, 0)

	eng.OnLog("msg1")
	eng.OnLeakDetected("webrtc", "details")
	s.logsMu.Lock()
	n := len(s.logs)
	s.logsMu.Unlock()
	if n != 2 {
		t.Errorf("expected 2 log entries, got %d", n)
	}
}

// ── appendLog trim ────────────────────────────────────────────────────────────

func TestAppendLog_TrimsTo300(t *testing.T) {
	s := newTestServer(t)
	for i := 0; i < 305; i++ {
		s.appendLog(fmt.Sprintf("msg-%d", i))
	}
	s.logsMu.Lock()
	n := len(s.logs)
	s.logsMu.Unlock()
	if n != 300 {
		t.Errorf("expected 300 entries after trim, got %d", n)
	}
}

// ── simple GET handlers ───────────────────────────────────────────────────────

func TestApiLogs_Empty(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiLogs)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: want application/json, got %q", ct)
	}
	// Body must be a valid JSON array
	var logs []string
	if err := json.NewDecoder(w.Body).Decode(&logs); err != nil {
		t.Errorf("decode error: %v", err)
	}
}

func TestApiLogs_WithEntries(t *testing.T) {
	s := newTestServer(t)
	s.eng.OnLog("line1")
	s.eng.OnLog("line2")
	w := testGET(s, s.apiLogs)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var logs []string
	json.NewDecoder(w.Body).Decode(&logs) //nolint
	if len(logs) != 2 {
		t.Errorf("expected 2 log entries, got %d", len(logs))
	}
}

func TestApiState(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiState)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiStats(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiStats)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiSingBox(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiSingBox)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiConfig(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiConfig)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiNodes(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiNodes)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiDiagnostics(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiDiagnostics)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiLeakGuardStatus(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiLeakGuardStatus)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiBrowserInstructions(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiBrowserInstructions)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiFallbackStatus(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiFallbackStatus)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiWatchdogStatus(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiWatchdogStatus)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiSessionStatus(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiSessionStatus)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiDPIStatus(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiDPIStatus)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiCDNFronting_Get(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiCDNFronting)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiShadowTLS_Get(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiShadowTLS)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiCDNWorkerScript(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiCDNWorkerScript)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type: want text/plain; charset=utf-8, got %q", ct)
	}
}

func TestApiCatalogStatus(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiCatalogStatus)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiAdBlockStatus(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiAdBlockStatus)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiAntiBlockStatus(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiAntiBlockStatus)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiAntiBlockBypassList_Get(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiAntiBlockBypassList)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiUI(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiUI)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type: want text/html; charset=utf-8, got %q", ct)
	}
}

// ── readWatchdogEvents ────────────────────────────────────────────────────────

func TestReadWatchdogEvents_MissingFiles(t *testing.T) {
	// Files do not exist → must return nil/empty without panic
	last, history := readWatchdogEvents()
	_ = last
	_ = history
}

// ── method-not-allowed (GET on POST-only handlers → 405) ─────────────────────

func methodNotAllowedCases(s *Server) []struct {
	name string
	fn   http.HandlerFunc
} {
	return []struct {
		name string
		fn   http.HandlerFunc
	}{
		{"connect", s.apiConnect},
		{"disconnect", s.apiDisconnect},
		{"scan", s.apiScan},
		{"rescan", s.apiRescan},
		{"add-node", s.apiAddNode},
		{"reset-network", s.apiResetNetwork},
		{"save-config", s.apiSaveConfig},
		{"dns-test", s.apiDNSLeakTest},
		{"ipv6", s.apiIPv6Block},
		{"webrtc", s.apiWebRTCBlock},
		{"set-password", s.apiSetPassword},
		{"emergency-wipe", s.apiEmergencyWipe},
		{"canary-test", s.apiCanaryTest},
		{"padding", s.apiTrafficPadding},
		{"shadowtls-auto-sni", s.apiShadowTLSAutoSNI},
		{"fallback-activate", s.apiFallbackActivate},
		{"fallback-auto-select", s.apiFallbackAutoSelect},
		{"session-policy", s.apiSessionPolicy},
		{"force-switch", s.apiForceSwitch},
		{"catalog-refresh", s.apiCatalogRefresh},
		{"catalog-provider", s.apiCatalogProvider},
		{"adblock-profile", s.apiAdBlockProfile},
		{"adblock-allowlist", s.apiAdBlockAllowlist},
		{"antiblock-check-ip", s.apiAntiBlockCheckIP},
		{"antiblock-check-node", s.apiAntiBlockCheckNode},
		{"antiblock-config", s.apiAntiBlockConfig},
		{"antiblock-bypass-domain", s.apiAntiBlockBypassDomain},
	}
}

func TestMethodNotAllowed_GetOnPostOnly(t *testing.T) {
	s := newTestServer(t)
	for _, tc := range methodNotAllowedCases(s) {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			w := testGET(s, tc.fn)
			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s: expected 405, got %d", tc.name, w.Code)
			}
		})
	}
}

// DELETE on GET/DELETE handlers
func TestApiWatchdogHistory_Get(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/watchdog/history", nil)
	s.apiWatchdogHistory(w, r)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiWatchdogHistory_Delete(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/watchdog/history", nil)
	s.apiWatchdogHistory(w, r)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiWatchdogHistory_BadMethod(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/watchdog/history", nil)
	s.apiWatchdogHistory(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestApiCDNFronting_BadMethod(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/dpi/cdn", nil)
	s.apiCDNFronting(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestApiShadowTLS_BadMethod(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/dpi/shadowtls", nil)
	s.apiShadowTLS(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestApiAntiBlockBypassList_BadMethod(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/antiblock/bypass-list", nil)
	s.apiAntiBlockBypassList(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ── bad JSON → 400 ────────────────────────────────────────────────────────────

type badJSONCase struct {
	name string
	fn   http.HandlerFunc
}

func badJSONCases(s *Server) []badJSONCase {
	return []badJSONCase{
		{"add-node", s.apiAddNode},
		{"save-config", s.apiSaveConfig},
		{"ipv6", s.apiIPv6Block},
		{"webrtc", s.apiWebRTCBlock},
		{"set-password", s.apiSetPassword},
		{"emergency-wipe", s.apiEmergencyWipe},
		{"padding", s.apiTrafficPadding},
		{"cdn-fronting", s.apiCDNFronting},
		{"shadowtls", s.apiShadowTLS},
		{"fallback-activate", s.apiFallbackActivate},
		{"session-policy", s.apiSessionPolicy},
		{"catalog-provider", s.apiCatalogProvider},
		{"adblock-profile", s.apiAdBlockProfile},
		{"adblock-allowlist", s.apiAdBlockAllowlist},
		{"antiblock-check-ip", s.apiAntiBlockCheckIP},
		{"antiblock-check-node", s.apiAntiBlockCheckNode},
		{"antiblock-config", s.apiAntiBlockConfig},
		{"antiblock-bypass-list", s.apiAntiBlockBypassList},
		{"antiblock-bypass-domain", s.apiAntiBlockBypassDomain},
	}
}

func TestBadJSON_Returns400(t *testing.T) {
	s := newTestServer(t)
	for _, tc := range badJSONCases(s) {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			w := testPOST(s, tc.fn, "not-valid-json{{")
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s: expected 400, got %d", tc.name, w.Code)
			}
		})
	}
}

// ── valid POST paths ──────────────────────────────────────────────────────────

func TestApiIPv6Block_DisableOK(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiIPv6Block, `{"enabled":false}`)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiWebRTCBlock_DisableOK(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiWebRTCBlock, `{"enabled":false}`)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiSetPassword_EmptyDisables(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiSetPassword, `{"password":""}`)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp) //nolint
	if enabled, _ := resp["enabled"].(bool); enabled {
		t.Error("expected enabled=false for empty password")
	}
}

func TestApiSetPassword_NonEmpty(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiSetPassword, `{"password":"s3cr3t"}`)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp) //nolint
	if enabled, _ := resp["enabled"].(bool); !enabled {
		t.Error("expected enabled=true for non-empty password")
	}
}

func TestApiEmergencyWipe_NoConfirm(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiEmergencyWipe, `{"wipe_all":false,"confirm":"wrong"}`)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	// Must return JSON error without wiping anything
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp) //nolint
	if resp["error"] == "" {
		t.Error("expected non-empty error when confirm != WIPE")
	}
}

func TestApiTrafficPadding_Disable(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiTrafficPadding, `{"enabled":false,"aggressive":false}`)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiCDNFronting_Post(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiCDNFronting, `{"worker_domain":"x.workers.dev","backend_host":"1.2.3.4","backend_port":443}`)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiShadowTLS_Post(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiShadowTLS, `{"enabled":false,"password":"","sni":"","server":""}`)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestApiShadowTLS_Post_RejectsEmptyPasswordWhenEnabled — задача #23, QA 2026-08-17:
// раньше принимался и сохранялся полностью пустой конфиг (включая enabled=true) без
// единого сообщения об ошибке.
func TestApiShadowTLS_Post_RejectsEmptyPasswordWhenEnabled(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiShadowTLS, `{"enabled":true,"password":"","sni":"","server":""}`)
	if w.Code != 400 {
		t.Errorf("expected 400 for empty password with enabled=true, got %d", w.Code)
	}
}

func TestApiShadowTLS_Post_AcceptsNonEmptyPasswordWhenEnabled(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiShadowTLS, `{"enabled":true,"password":"s3cr3t","sni":"","server":"","server_addr":"192.168.1.10:8443"}`)
	if w.Code != 200 {
		t.Errorf("expected 200 for non-empty password + server_addr, got %d — %s", w.Code, w.Body.String())
	}
}

// TestApiShadowTLS_Post_RejectsEmptyServerAddrWhenEnabled — P1-1 (аудит 2026-09-01),
// симметрично проверке пароля выше: без адреса реального сервера клиенту физически
// некуда подключаться.
func TestApiShadowTLS_Post_RejectsEmptyServerAddrWhenEnabled(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiShadowTLS, `{"enabled":true,"password":"s3cr3t","sni":"","server":"","server_addr":""}`)
	if w.Code != 400 {
		t.Errorf("expected 400 for empty server_addr with enabled=true, got %d", w.Code)
	}
}

func TestApiFallbackActivate_Post(t *testing.T) {
	s := newTestServer(t)
	// ActivateFallbackTunnel("unknown") will return an error JSON – still 200
	w := testPOST(s, s.apiFallbackActivate, `{"tunnel":"unknown"}`)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiFallbackAutoSelect_Post(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiFallbackAutoSelect, "")
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiSessionPolicy_Post(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiSessionPolicy, `{"policy":"sticky"}`)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiForceSwitch_Post(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiForceSwitch, "")
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiSaveConfig_BadJSON_400(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiSaveConfig, "{bad json}")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestApiSaveConfig_ValidPatch(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiSaveConfig, `{"listen_port":10808}`)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiAddNode_BadJSON_400(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiAddNode, "not-json")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestApiAddNode_InvalidLink(t *testing.T) {
	s := newTestServer(t)
	// Valid JSON but invalid VPN link → error JSON (still 200)
	w := testPOST(s, s.apiAddNode, `{"link":"not-a-real-link"}`)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiCatalogRefresh_Post(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiCatalogRefresh, "")
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	// A goroutine is launched but we don't wait for it
}

func TestApiCatalogProvider_Post_NotFound(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiCatalogProvider, `{"id":"nonexistent","enabled":true}`)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp) //nolint
	if resp["error"] == "" {
		t.Error("expected error JSON for unknown provider")
	}
}

func TestApiAdBlockProfile_Post(t *testing.T) {
	s := newTestServer(t)
	// May succeed or return error JSON, both are 200
	w := testPOST(s, s.apiAdBlockProfile, `{"profile":"standard"}`)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiAdBlockAllowlist_EmptyDomain(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiAdBlockAllowlist, `{"domain":"","add":true}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty domain, got %d", w.Code)
	}
}

func TestApiAdBlockAllowlist_ValidDomain(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiAdBlockAllowlist, `{"domain":"example.com","add":true}`)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiAntiBlockConfig_Post(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiAntiBlockConfig, `{"enabled":false,"residential_only":false,"auto_switch":false,"api_key":""}`)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiAntiBlockCheckIP_EmptyIP(t *testing.T) {
	s := newTestServer(t)
	// empty "ip" field → 400 (ip required)
	w := testPOST(s, s.apiAntiBlockCheckIP, `{"ip":""}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty ip, got %d", w.Code)
	}
}

func TestApiAntiBlockCheckNode_EmptyNodeID(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiAntiBlockCheckNode, `{"node_id":""}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty node_id, got %d", w.Code)
	}
}

func TestApiAntiBlockBypassList_Post_NoID(t *testing.T) {
	s := newTestServer(t)
	// "id" is empty → 400
	w := testPOST(s, s.apiAntiBlockBypassList, `{"id":"","enabled":true}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty id, got %d", w.Code)
	}
}

func TestApiAntiBlockBypassList_Post_NotFound(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiAntiBlockBypassList, `{"id":"nonexistent","enabled":true}`)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp) //nolint
	if resp["error"] == "" {
		t.Error("expected error JSON for unknown bypass rule")
	}
}

func TestApiAntiBlockBypassDomain_Remove_NoID(t *testing.T) {
	s := newTestServer(t)
	// remove=true but id="" → 400
	w := testPOST(s, s.apiAntiBlockBypassDomain, `{"remove":true,"id":""}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when remove=true and id empty, got %d", w.Code)
	}
}

func TestApiAntiBlockBypassDomain_Add_NoDomain(t *testing.T) {
	s := newTestServer(t)
	// add without domain → 400
	w := testPOST(s, s.apiAntiBlockBypassDomain, `{"remove":false,"domain":"","name":"test","residential":false}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when domain empty, got %d", w.Code)
	}
}
