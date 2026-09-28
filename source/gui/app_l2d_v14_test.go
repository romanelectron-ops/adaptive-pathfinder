package main

// L2-D (ТЗ v1.4, волна W2): тесты новых методов gui/app.go, введённых этим лотом —
// GetLastPersistError (U-17-desktop), ServerRoleExportIdentity (S-3-frontend),
// PatchConfig-needs_restart (V13-5-wails) и C-21-ui поля GetNodes(). testPortApp — общий
// вспомогательный метод из app_v14_test.go (тот же пакет main, файл L1b-CLI не трогается,
// только переиспользуется).
//
// Тест-до (снято до правок этого лота): все функции ниже не компилировались вовсе —
// App.GetLastPersistError/App.ServerRoleExportIdentity не существовали, App.PatchConfig
// возвращал одиночный error (needs_restart отбрасывался), GetNodes() не включал
// catalog_country/exit_country/country_mismatch. Тест-после — см. прогоны ниже, все PASS.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/engine"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

func newTestOwnerApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	config.SetDataDirOverride(dir)
	t.Cleanup(func() { config.SetDataDirOverride("") })
	cfg := models.DefaultConfig()
	eng := engine.New(cfg)
	return &App{engine: eng, cfg: cfg}
}

// ─── U-17-desktop: GetLastPersistError ──────────────────────────────────────────────────

func TestGetLastPersistError_Owner_EmptyByDefault(t *testing.T) {
	a := newTestOwnerApp(t)
	got, err := a.GetLastPersistError()
	if err != nil {
		t.Fatalf("GetLastPersistError: %v", err)
	}
	if got != "" {
		t.Errorf("GetLastPersistError() = %q, ожидалась пустая строка (свежий движок ещё ничего не писал)", got)
	}
}

func TestGetLastPersistError_Observer_ReadsFromDiagnostics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"last_persist_error": "шифрование nodes_cache.json не удалось",
		})
	}))
	defer srv.Close()

	a := &App{remote: newWebClient(testPortApp(t, srv))}
	got, err := a.GetLastPersistError()
	if err != nil {
		t.Fatalf("GetLastPersistError: %v", err)
	}
	if got != "шифрование nodes_cache.json не удалось" {
		t.Errorf("GetLastPersistError() = %q, не то, что отдала /api/diagnostics", got)
	}
}

func TestGetLastPersistError_Observer_MissingField_ReturnsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"other_field": 1})
	}))
	defer srv.Close()

	a := &App{remote: newWebClient(testPortApp(t, srv))}
	got, err := a.GetLastPersistError()
	if err != nil {
		t.Fatalf("GetLastPersistError: %v", err)
	}
	if got != "" {
		t.Errorf("GetLastPersistError() = %q, ожидалась пустая строка при отсутствии поля в ответе", got)
	}
}

// ─── S-3-frontend: ServerRoleExportIdentity ─────────────────────────────────────────────

func TestServerRoleExportIdentity_Owner_NotGenerated_ReturnsNilNoError(t *testing.T) {
	a := newTestOwnerApp(t)
	got, err := a.ServerRoleExportIdentity()
	if err != nil {
		t.Fatalf("ServerRoleExportIdentity: %v", err)
	}
	if got != nil {
		t.Errorf("ServerRoleExportIdentity() = %v, ожидался nil (ключ ещё не сгенерирован)", got)
	}
}

func TestServerRoleExportIdentity_Observer_SendsConfirmExport_ReturnsFullIdentity(t *testing.T) {
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"identity": map[string]interface{}{
				"UUID": "u1", "PrivateKey": "pk-secret", "PublicKey": "pub1", "ShortID": "sid1",
			},
		})
	}))
	defer srv.Close()

	a := &App{remote: newWebClient(testPortApp(t, srv))}
	got, err := a.ServerRoleExportIdentity()
	if err != nil {
		t.Fatalf("ServerRoleExportIdentity: %v", err)
	}
	if gotBody["confirm"] != "EXPORT" {
		t.Errorf("тело запроса не содержит confirm=EXPORT (S-3, сервер требует его для отдачи приватного ключа): %v", gotBody)
	}
	if got["PrivateKey"] != "pk-secret" {
		t.Errorf("ServerRoleExportIdentity() не вернул приватный ключ из ответа export: %v", got)
	}
}

func TestServerRoleExportIdentity_Observer_ServerError_Propagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "identity not generated yet"})
	}))
	defer srv.Close()

	a := &App{remote: newWebClient(testPortApp(t, srv))}
	if _, err := a.ServerRoleExportIdentity(); err == nil {
		t.Fatal("ожидалась ошибка, когда сервер отдал {\"error\":...}")
	}
}

// ─── V13-5-wails: PatchConfig возвращает needs_restart ──────────────────────────────────

func TestPatchConfig_Owner_ReturnsNeedsRestartFromEngine(t *testing.T) {
	a := newTestOwnerApp(t)
	got, err := a.PatchConfig(map[string]interface{}{"listen_port": 18080})
	if err != nil {
		t.Fatalf("PatchConfig: %v", err)
	}
	found := false
	for _, k := range got {
		if k == "listen_port" {
			found = true
		}
	}
	if !found {
		t.Errorf("PatchConfig(listen_port) needsRestart = %v, ожидался элемент \"listen_port\" (internal/engine restartPatchKeys)", got)
	}
}

func TestPatchConfig_Observer_ReturnsNeedsRestartFromResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "saved", "needs_restart": []string{"listen_port"},
		})
	}))
	defer srv.Close()

	a := &App{remote: newWebClient(testPortApp(t, srv))}
	got, err := a.PatchConfig(map[string]interface{}{"listen_port": 18080})
	if err != nil {
		t.Fatalf("PatchConfig: %v", err)
	}
	if len(got) != 1 || got[0] != "listen_port" {
		t.Errorf("PatchConfig needsRestart = %v, ожидалось [\"listen_port\"]", got)
	}
}

func TestPatchConfig_Observer_ServerError_Propagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "connection_mode: нельзя сменить режим при активном подключении"})
	}))
	defer srv.Close()

	a := &App{remote: newWebClient(testPortApp(t, srv))}
	if _, err := a.PatchConfig(map[string]interface{}{"connection_mode": "vpn"}); err == nil {
		t.Fatal("ожидалась ошибка, когда сервер отдал {\"error\":...}")
	}
}

// ─── C-21-ui: GetNodes() отдаёт catalog_country/exit_country/country_mismatch ───────────

func TestGetNodes_C21_CatalogVsExitCountry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"nodes": []map[string]interface{}{
				// K8-LIVE D1: узел подписан GB, фактический выход — Нидерланды (NL) — расхождение.
				{"id": "n1", "name": "🇬🇧GB-82.38.31.179-0124", "last_verified_country": "NL", "verified_count": 1},
				// Совпадение метки и факта — mismatch не должен взводиться.
				{"id": "n2", "name": "🇳🇱NL-1.2.3.4-0001", "last_verified_country": "NL", "verified_count": 2},
				// Никогда не проверялся трафиком — фактический выход неизвестен.
				{"id": "n3", "name": "🇩🇪DE-5.6.7.8-0002"},
			},
		})
	}))
	defer srv.Close()

	a := &App{remote: newWebClient(testPortApp(t, srv))}
	nodes := a.GetNodes()
	if len(nodes) != 3 {
		t.Fatalf("ожидалось 3 узла, получили %d", len(nodes))
	}

	n1 := nodes[0]
	if n1.CatalogCountry != "GB" {
		t.Errorf("n1.CatalogCountry = %q, ожидалось GB", n1.CatalogCountry)
	}
	if n1.ExitCountry != "NL" {
		t.Errorf("n1.ExitCountry = %q, ожидалось NL", n1.ExitCountry)
	}
	if !n1.CountryMismatch {
		t.Error("n1.CountryMismatch = false, ожидалось true (метка GB, факт. выход NL)")
	}

	n2 := nodes[1]
	if n2.CountryMismatch {
		t.Error("n2.CountryMismatch = true, ожидалось false (метка и факт. выход совпадают — NL)")
	}

	n3 := nodes[2]
	if n3.ExitCountry != "" {
		t.Errorf("n3.ExitCountry = %q, ожидалась пустая строка (узел никогда не подтверждался)", n3.ExitCountry)
	}
	if n3.CountryMismatch {
		t.Error("n3.CountryMismatch = true — расхождение не может быть установлено, пока факт. выход неизвестен")
	}
	if n3.CatalogCountry != "DE" {
		t.Errorf("n3.CatalogCountry = %q, ожидалось DE (метка каталога должна остаться видна даже без подтверждения)", n3.CatalogCountry)
	}
}
