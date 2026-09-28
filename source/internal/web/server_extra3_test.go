package web

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
)

// ─── httpServeFn default body ─────────────────────────────────────────────────

// TestHttpServeFn_DefaultBody covers server.go line 22-24
// (the body of the default httpServeFn lambda).
// Calling http.Serve on a closed listener returns an immediate error,
// which is enough to execute the lambda body.
func TestHttpServeFn_DefaultBody(t *testing.T) {
	orig := httpServeFn
	defer func() { httpServeFn = orig }()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// Close the listener before passing it to httpServeFn; http.Serve
	// returns an error immediately when the listener is already closed.
	ln.Close()

	err = orig(ln, http.NewServeMux())
	if err == nil {
		t.Error("expected error from http.Serve on closed listener, got nil")
	}
}

// ─── apiAddNode success ───────────────────────────────────────────────────────

// TestApiAddNode_Success covers server.go line 257
// (json.NewEncoder(w).Encode(map[string]string{"status":"added"})).
func TestApiAddNode_Success(t *testing.T) {
	s := newTestServer(t)
	// Minimal valid VLESS link that the parser can accept.
	// Format matches the pattern used in engine_coverage2_test.go.
	link := "vless://12345678-1234-1234-1234-123456789012@1.2.3.4:443?type=tcp&security=none#TestNode"
	w := testPOST(s, s.apiAddNode, `{"link":"`+link+`"}`)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "added" {
		t.Errorf("expected status=added, got %v (body: %s)", resp, w.Body.String())
	}
}

// ─── apiCatalogProvider not found ────────────────────────────────────────────

// TestApiCatalogProvider_NotFound covers server.go line 900
// (json.NewEncoder(w).Encode(map[string]string{"error": "provider not found: " + body.ID})).
func TestApiCatalogProvider_NotFound(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiCatalogProvider, `{"id":"nonexistent-provider-xyz","enabled":true}`)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "provider not found") {
		t.Errorf("expected 'provider not found' in response, got: %s", body)
	}
}

// ─── apiCatalogProvider success ──────────────────────────────────────────────

// TestApiCatalogProvider_Success covers server.go line 903
// (json.NewEncoder(w).Encode(map[string]interface{}{"status":"ok",...})).
// "v2ray-aggregator" is a built-in catalog provider ID registered in the engine.
func TestApiCatalogProvider_Success(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiCatalogProvider, `{"id":"v2ray-aggregator","enabled":false}`)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status=ok, got %v (body: %s)", resp, w.Body.String())
	}
}

// ─── apiAdBlockProfile invalid profile ──────────────────────────────────────

// TestApiAdBlockProfile_InvalidProfile covers server.go line 926-928
// (the error path when SetAdBlockProfile returns an error).
func TestApiAdBlockProfile_InvalidProfile(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiAdBlockProfile, `{"profile":"nonexistent-profile-xyz"}`)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] == "" {
		t.Errorf("expected error key in response for invalid profile, got %v", resp)
	}
}

// ─── apiSaveConfig PatchConfig error ─────────────────────────────────────────

// TestApiSaveConfig_PatchError covers the error path when PatchConfig returns an error.
// PatchConfig returns error for an invalid listen_port value.
//
// Аудит 2026-09-01 (раздел D): раньше тест ТРЕБОВАЛ status 200 на отклонённый патч —
// закреплял дефект. Вызывающий код, честно проверяющий r.ok (webClient.postJSON,
// gui/webclient.go), не мог отличить успех от отказа никаким иным способом, кроме разбора
// тела АБСОЛЮТНО каждого ответа — а часть JS-обработчиков во встроенном Web UI (bare
// `await fetch(...)` без разбора тела, см. saveSettings/togInstant в server.go) этого не
// делала вовсе и показывала "Сохранено" при отклонённом PatchConfig.
func TestApiSaveConfig_PatchError(t *testing.T) {
	s := newTestServer(t)
	// listen_port: -1 is invalid and causes PatchConfig to return an error.
	w := testPOST(s, s.apiSaveConfig, `{"listen_port":-1}`)
	if w.Code != 400 {
		t.Fatalf("status %d, ожидалось 400: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] == "" {
		t.Errorf("expected error key in response for invalid patch, got %v (body: %s)", resp, w.Body.String())
	}
}

// ─── apiAntiBlockBypassDomain remove not found ───────────────────────────────

// TestApiAntiBlockBypassDomain_RemoveNotFound covers server.go line 1117
// (the !ok path when RemoveBypassDomain returns false for an unknown ID).
func TestApiAntiBlockBypassDomain_RemoveNotFound(t *testing.T) {
	s := newTestServer(t)
	body := `{"remove":true,"id":"nonexistent-uuid-00000000-0000-0000-0000-000000000000"}`
	w := testPOST(s, s.apiAntiBlockBypassDomain, body)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	resp := w.Body.String()
	if !strings.Contains(resp, "not found") {
		t.Errorf("expected 'not found' in response, got: %s", resp)
	}
}

// ─── apiNodes: len(nodes) > 200 truncation ───────────────────────────────────

// TestApiNodes_MoreThan200 covers server.go line 191-193
// (the truncation branch `if len(nodes) > limit { nodes = nodes[:limit] }`).
// We add 201 uniquely-identified VLESS nodes so that GetNodes() returns >200,
// then call apiNodes and verify the response caps at 200.
func TestApiNodes_MoreThan200(t *testing.T) {
	s := newTestServer(t)

	// Add 201 nodes, each with a distinct UUID and port so they are not deduplicated.
	for i := 1; i <= 201; i++ {
		// UUID last segment encodes i in hex (12 hex chars).
		uuid := fmt.Sprintf("12345678-1234-1234-1234-%012x", i)
		link := fmt.Sprintf(
			"vless://%s@1.2.3.4:%d?type=tcp&security=none#BulkNode%d",
			uuid, 10000+i, i,
		)
		testPOST(s, s.apiAddNode, `{"link":"`+link+`"}`)
	}

	w := testGET(s, s.apiNodes)
	if w.Code != 200 {
		t.Fatalf("apiNodes status %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	nodes, _ := resp["nodes"].([]interface{})
	if len(nodes) > 200 {
		t.Errorf("expected nodes capped at 200, got %d", len(nodes))
	}
}
