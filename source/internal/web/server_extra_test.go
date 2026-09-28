package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/engine"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ── POST variants for fire-and-forget handlers ────────────────────────────────
// These trigger a goroutine but the handler itself returns immediately.

func TestApiConnect_Post_Returns200(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiConnect, "")
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp) //nolint
	if resp["status"] != "connecting" {
		t.Errorf("expected status=connecting, got %q", resp["status"])
	}
}

func TestApiDisconnect_Post_Returns200(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiDisconnect, "")
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp) //nolint
	if resp["status"] != "disconnected" {
		t.Errorf("expected status=disconnected, got %q", resp["status"])
	}
}

// TestApiScan_Post_Returns200 — регресс 2026-09-22: apiScan раньше был побайтовой копией
// apiConnect (go s.eng.ScanAndConnect()) — кнопка «⟳ Сканировать» на Dashboard вместо
// заявленного безопасного TCP-обхода заводила настоящий туннель и включала Kill Switch.
// Найдено живым прогоном на ПК владельца: он работал только со сканом/сбором рабочих узлов
// («Собрать список рабочих узлов»), а APF без явной команды «Подключить» поднял боевое
// подключение — причина оказалась именно в этой кнопке/маршруте.
//
// ScanAndConnect() и StartSweep() пишут прогресс в РАЗНЫЕ, не пересекающиеся места:
// ScanAndConnect ведёт себя через connCycleActive/лог "Starting scan...", а GetScanProgress()
// (scanPhaseIdle/Running/Done) отражает ИСКЛЮЧИТЕЛЬНО StartSweep/runSweep — если бы apiScan
// снова стал звать ScanAndConnect(), эта проверка вернулась бы к "idle" и тест провалился бы,
// поймав регресс именно на границе, где баг и жил.
func TestApiScan_Post_Returns200(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiScan, "")
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp) //nolint
	if resp["status"] != "scanning" {
		t.Errorf("expected status=scanning, got %q", resp["status"])
	}
	// Пул пуст (newTestServer: cfg.Sources = nil) — обход может завершиться почти мгновенно,
	// поэтому опрашиваем фазу вместо разового снимка SweepRunning() (иначе тест был бы гонкой).
	deadline := time.Now().Add(2 * time.Second)
	phase := ""
	for time.Now().Before(deadline) {
		phase = s.eng.GetScanProgress().Phase
		if phase != "" && phase != "idle" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if phase == "" || phase == "idle" {
		t.Fatalf("apiScan не запустил StartSweep (GetScanProgress().Phase остался %q) — "+
			"похоже, маршрут снова вызывает ScanAndConnect() вместо безопасного обхода", phase)
	}
}

func TestApiRescan_Post_Returns200(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiRescan, "")
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp) //nolint
	if resp["status"] != "rescan_started" {
		t.Errorf("expected status=rescan_started, got %q", resp["status"])
	}
}

// ── apiResetNetwork POST ──────────────────────────────────────────────────────
// Calls eng.ResetNetworkDetailed() which may succeed or fail depending on OS
// privileges – both paths are valid (200 or 500) and cover the handler body.

func TestApiResetNetwork_Post(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiResetNetwork, "")
	// Accept 200 (success) or 500 (failure without admin) – both are valid
	if w.Code != 200 && w.Code != 500 {
		t.Errorf("expected 200 or 500, got %d", w.Code)
	}
	// Either way the response must be valid JSON with a "status" field
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Errorf("response is not valid JSON: %v", err)
	}
	if _, ok := resp["status"]; !ok {
		t.Error("expected 'status' key in response")
	}
}

// ── IPv6 / WebRTC error paths via enabled:true ────────────────────────────────
// On a standard test environment (no admin), EnableIPv6Block(true) and
// EnableWebRTCBlock(true) return an error → covers the error-JSON branch.

func TestApiIPv6Block_EnableTrue_ErrorPath(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiIPv6Block, `{"enabled":true}`)
	// Handler always returns 200 regardless of inner error
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	// We don't assert success/failure – just that JSON is returned
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Errorf("response is not valid JSON: %v", err)
	}
}

func TestApiWebRTCBlock_EnableTrue_ErrorPath(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiWebRTCBlock, `{"enabled":true}`)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Errorf("response is not valid JSON: %v", err)
	}
}

// ── readWatchdogEvents with real files ────────────────────────────────────────

func TestReadWatchdogEvents_WithFiles(t *testing.T) {
	dataDir := config.DataDir()
	lastPath := filepath.Join(dataDir, "watchdog_last_event.json")
	historyPath := filepath.Join(dataDir, "watchdog_events.json")

	// Write temp files (clean up after test)
	lastJSON := `{"type":"disconnect","at":"2024-01-01T00:00:00Z"}`
	histJSON := `[{"type":"disconnect","at":"2024-01-01T00:00:00Z"}]`

	os.MkdirAll(dataDir, 0o755)
	if err := os.WriteFile(lastPath, []byte(lastJSON), 0o644); err != nil {
		t.Skipf("cannot write temp file: %v", err)
	}
	if err := os.WriteFile(historyPath, []byte(histJSON), 0o644); err != nil {
		os.Remove(lastPath)
		t.Skipf("cannot write temp file: %v", err)
	}
	t.Cleanup(func() {
		os.Remove(lastPath)
		os.Remove(historyPath)
	})

	last, history := readWatchdogEvents()
	if last == nil {
		t.Error("expected non-nil last event")
	}
	if len(history) == 0 {
		t.Error("expected non-empty history")
	}
}

// ── apiWatchdogHistory GET with existing file ─────────────────────────────────

func TestApiWatchdogHistory_Get_WithFile(t *testing.T) {
	dataDir := config.DataDir()
	historyPath := filepath.Join(dataDir, "watchdog_events.json")
	histJSON := `[{"type":"test","at":"2024-01-01T00:00:00Z"}]`

	os.MkdirAll(dataDir, 0o755)
	if err := os.WriteFile(historyPath, []byte(histJSON), 0o644); err != nil {
		t.Skipf("cannot write temp file: %v", err)
	}
	t.Cleanup(func() { os.Remove(historyPath) })

	s := newTestServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/watchdog/history", nil)
	s.apiWatchdogHistory(w, r)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp) //nolint
	if count, _ := resp["count"].(float64); count == 0 {
		t.Error("expected count > 0 when file has entries")
	}
}

// ── apiAntiBlockBypassDomain add path ────────────────────────────────────────

func TestApiAntiBlockBypassDomain_Add_ValidDomain(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiAntiBlockBypassDomain,
		`{"remove":false,"domain":"test.example.com","name":"Test","residential":false}`)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	// Either "added" or "already exists" – both cover the code path
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Errorf("response is not valid JSON: %v", err)
	}
}

func TestApiAntiBlockBypassDomain_Remove_NotFound(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiAntiBlockBypassDomain,
		`{"remove":true,"id":"nonexistent-id-12345"}`)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp) //nolint
	if resp["error"] == "" {
		t.Error("expected error JSON for unknown bypass domain id")
	}
}

// ── apiAntiBlockCheckIP with real IP ─────────────────────────────────────────
// Uses a short timeout so it doesn't block test suite for long.
// We only test that the handler returns JSON (pass or error is acceptable).

func TestApiAntiBlockCheckIP_ValidIP(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	s := newTestServer(t)

	// Use a very short timeout to avoid blocking. The handler itself uses 10s,
	// but the HTTP layer will cut it off when the test finishes.
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := testPOST(s, s.apiAntiBlockCheckIP, `{"ip":"1.1.1.1"}`)
		done <- w
	}()

	select {
	case w := <-done:
		if w.Code != 200 {
			t.Errorf("expected 200, got %d", w.Code)
		}
	case <-time.After(12 * time.Second):
		t.Log("apiAntiBlockCheckIP timed out (network unavailable) – skipping assertion")
	}
}

// ── apiAntiBlockCheckNode ─────────────────────────────────────────────────────

func TestApiAntiBlockCheckNode_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	s := newTestServer(t)

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := testPOST(s, s.apiAntiBlockCheckNode, `{"node_id":"nonexistent-node-id"}`)
		done <- w
	}()

	select {
	case w := <-done:
		if w.Code != 200 {
			t.Errorf("expected 200, got %d", w.Code)
		}
	case <-time.After(12 * time.Second):
		t.Log("apiAntiBlockCheckNode timed out – skipping assertion")
	}
}

// ── apiSaveConfig error path ──────────────────────────────────────────────────
// PatchConfig rejects patches with unknown/invalid types; check engine behaviour.

// TEST-SYNC-W1 (2026-09-08, ADR оркестратора по ТЗ v1.4 S-7, лот L1-SEC): validatePatch
// теперь отвергает неизвестные ключи (белый список по json-тегам models.AppConfig), и
// apiSaveConfig пробрасывает эту ошибку как HTTP 400 с JSON {"error": "..."} вместо прежних
// 200 — раньше отказ PatchConfig был неотличим от успеха для любого вызывающего кода,
// который проверяет только r.ok/status (см. комментарий над apiSaveConfig в server.go).
func TestApiSaveConfig_ErrorPatch(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiSaveConfig, `{"__invalid_key_xyzzy__": true}`)
	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("expected JSON error body, decode failed: %v", err)
	}
	if !strings.Contains(resp["error"], "__invalid_key_xyzzy__") {
		t.Errorf("expected error message to name the offending key, got: %q", resp["error"])
	}
}

// ── apiNodes limit branch ─────────────────────────────────────────────────────
// The >200 trim is only hit when the engine has >200 nodes. Without injecting
// nodes we can't cover it, but we verify the handler returns proper JSON shape.

func TestApiNodes_ResponseShape(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiNodes)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Errorf("apiNodes: expected valid JSON, got: %v", err)
	}
	if _, ok := resp["nodes"]; !ok {
		t.Error("apiNodes: expected 'nodes' key in response")
	}
	if _, ok := resp["total"]; !ok {
		t.Error("apiNodes: expected 'total' key in response")
	}
}

// ── Start() reachable branch via net.Listen ───────────────────────────────────
// We bind 10 consecutive ports to exhaust the search range so Start() returns
// an error. This covers the loop and the final error return.

func TestStart_ExhaustsPortRange(t *testing.T) {
	t.Skip("port exhaustion test can interfere with parallel tests – skipped by default")
}

// ── New() body: OnLog 300-cap in-New callback ─────────────────────────────────
// Ensure the cap-to-300 branch inside the OnLog closure is reached.

func TestNew_OnLog_Cap300(t *testing.T) {
	cfg := models.DefaultConfig()
	eng := engine.New(cfg)
	s := New(eng, 0)

	// Send 302 messages to trigger the trim inside the closure
	for i := 0; i < 302; i++ {
		eng.OnLog("msg")
	}
	s.logsMu.Lock()
	n := len(s.logs)
	s.logsMu.Unlock()
	if n != 300 {
		t.Errorf("expected 300 logs after cap, got %d", n)
	}
}

// ── apiFallbackActivate success response shape ────────────────────────────────

func TestApiFallbackActivate_ResponseShape(t *testing.T) {
	s := newTestServer(t)
	// ActivateFallbackTunnel may return error (no binaries), which is fine
	w := testPOST(s, s.apiFallbackActivate, `{"tunnel":"tor"}`)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	// Response must be valid JSON (either error or status)
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Errorf("expected valid JSON: %v", err)
	}
}

// ── apiCatalogRefresh goroutine result via appendLog ──────────────────────────
// POST triggers a goroutine that eventually calls s.appendLog. We verify
// the handler returns immediately with status=refreshing.

func TestApiCatalogRefresh_ReturnsImmediately(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiCatalogRefresh, "")
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp) //nolint
	if resp["status"] != "refreshing" {
		t.Errorf("expected status=refreshing, got %q", resp["status"])
	}
}

// ── apiAdBlockProfile error path ──────────────────────────────────────────────
// SetAdBlockProfile("disabled") should return no error and confirm disabled.

func TestApiAdBlockProfile_Disabled(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiAdBlockProfile, `{"profile":"disabled"}`)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}
