package main

// favorites_review_w3_test.go — W3 (ТЗ APF v1.5 §2/§5, TZ_v1.5_NODE_CATALOG_2026-09-14, лот
// L2-WAILS-B): тесты 5 новых биндингов gui/app.go — FavoriteOrigin/UserFavoriteIDs/
// SystemFavoriteIDs/CatalogReviewInterval/SetCatalogReviewInterval.
//
// Owner-путь у этих методов — тонкий passthrough к internal/engine (то же самое поведение уже
// исчерпывающе покрыто на уровне движка — см. internal/engine/nodes_favorites_w3_test.go,
// TestFavoriteOrigin_AddPromoteRemove и соседние: класс избранного, star-promotion, потолок
// системного класса). Здесь проверяется только то, что ЭТОТ слой добавляет сам: honest-дефолты
// на свежем движке (nil-safety нормализация в []string{}, "" для незнакомого узла, "each_scan"
// для непроставленного интервала) и — самое важное, потому что нигде больше не тестируется —
// HTTP-путь наблюдателя (a.remote != nil), написанный этим лотом вручную поверх getJSON/postJSON
// (webclient.go не редактировался), тем же приёмом, что уже применён у StartNodeCheck/
// CancelNodeCheck (N-3, тот же файл).
//
// Интеграционное исправление (пост-факт этого лота): наблюдательская часть изначально ходила на
// три изобретённых пути /api/favorites/origin|user|system и /api/catalog/review-interval
// (POST {"interval":v}) — L2-WEB-B независимо реализовал ДРУГОЙ, реальный контракт в
// internal/web/server.go (apiFavorites/apiCatalogReviewInterval). Тесты ниже проверяют
// КАНОНИЧЕСКИЙ контракт, сверенный чтением internal/web/server.go:
//   GET  /api/favorites               -> {"favorite_ids":[...],"user_favorite_ids":[...],
//                                          "system_favorite_ids":[...]}
//   GET  /api/catalog-review-interval -> {"interval":"each_scan|daily|weekly|monthly"}
//   POST /api/catalog-review-interval {"value":v} -> 200 {"status":"ok","interval":v}
//                                                     | 400 {"error":"..."}
//
// newTestOwnerApp — app_l2d_v14_test.go; testPortApp/newWebClient — app_v14_test.go (тот же
// пакет main).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── Owner: honest-дефолты на свежем движке (без узлов) ─────────────────────────────────────

func TestFavoriteOrigin_Owner_UnknownNode_ReturnsEmpty(t *testing.T) {
	a := newTestOwnerApp(t)
	if got := a.FavoriteOrigin("ghost"); got != "" {
		t.Errorf(`FavoriteOrigin("ghost") = %q, want "" (узел вообще не в избранном)`, got)
	}
}

func TestUserFavoriteIDs_Owner_EmptyByDefault(t *testing.T) {
	a := newTestOwnerApp(t)
	got := a.UserFavoriteIDs()
	if got == nil {
		t.Fatal("UserFavoriteIDs() = nil, want non-nil пустой срез (nil-safety, как у GetFavoriteIDs)")
	}
	if len(got) != 0 {
		t.Errorf("UserFavoriteIDs() = %v, want пустой (свежий движок без избранного)", got)
	}
}

func TestSystemFavoriteIDs_Owner_EmptyByDefault(t *testing.T) {
	a := newTestOwnerApp(t)
	got := a.SystemFavoriteIDs()
	if got == nil {
		t.Fatal("SystemFavoriteIDs() = nil, want non-nil пустой срез (nil-safety, как у GetFavoriteIDs)")
	}
	if len(got) != 0 {
		t.Errorf("SystemFavoriteIDs() = %v, want пустой (свежий движок без избранного)", got)
	}
}

func TestCatalogReviewInterval_Owner_DefaultsToEachScan(t *testing.T) {
	a := newTestOwnerApp(t)
	if got := a.CatalogReviewInterval(); got != models.ReviewIntervalEachScan {
		t.Errorf("CatalogReviewInterval() = %q, want %q (дефолт свежего конфига)", got, models.ReviewIntervalEachScan)
	}
}

func TestCatalogReviewInterval_Owner_RoundTripsThroughSet(t *testing.T) {
	a := newTestOwnerApp(t)
	if err := a.SetCatalogReviewInterval("weekly"); err != nil {
		t.Fatalf("SetCatalogReviewInterval(weekly): %v", err)
	}
	if got := a.CatalogReviewInterval(); got != models.ReviewIntervalWeekly {
		t.Errorf("CatalogReviewInterval() после SetCatalogReviewInterval(weekly) = %q, want %q", got, models.ReviewIntervalWeekly)
	}
}

func TestSetCatalogReviewInterval_Owner_UnknownValue_ReturnsError(t *testing.T) {
	a := newTestOwnerApp(t)
	if err := a.SetCatalogReviewInterval("bogus"); err == nil {
		t.Fatal(`SetCatalogReviewInterval("bogus") должен вернуть ошибку — неизвестное значение, явный пользовательский ввод`)
	}
	// Ошибка не должна иметь побочных эффектов (engine.go: "без побочных эффектов").
	if got := a.CatalogReviewInterval(); got != models.ReviewIntervalEachScan {
		t.Errorf("CatalogReviewInterval() после отказа SetCatalogReviewInterval(bogus) = %q, want дефолт %q (без побочных эффектов)", got, models.ReviewIntervalEachScan)
	}
}

// ─── Observer: HTTP-путь наблюдателя, канонический контракт L2-WEB-B ────────────────────────

func TestFavoriteOrigin_Observer_ParsesFromFavoritesEndpoint(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"favorite_ids":        []string{"n1", "n2"},
			"user_favorite_ids":   []string{"n1"},
			"system_favorite_ids": []string{"n2"},
		})
	}))
	defer srv.Close()

	a := &App{remote: newWebClient(testPortApp(t, srv))}
	if got := a.FavoriteOrigin("n1"); got != models.OriginUser {
		t.Errorf(`FavoriteOrigin("n1") = %q, want %q (в user_favorite_ids)`, got, models.OriginUser)
	}
	if got := a.FavoriteOrigin("n2"); got != models.OriginSystem {
		t.Errorf(`FavoriteOrigin("n2") = %q, want %q (в system_favorite_ids)`, got, models.OriginSystem)
	}
	if got := a.FavoriteOrigin("ghost"); got != "" {
		t.Errorf(`FavoriteOrigin("ghost") = %q, want "" (ни в одном из списков)`, got)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("FavoriteOrigin observer: метод = %s, want GET", gotMethod)
	}
	if !strings.HasSuffix(gotPath, "/api/favorites") {
		t.Errorf("FavoriteOrigin observer: путь = %s, want суффикс /api/favorites (канонический контракт L2-WEB-B, НЕ /api/favorites/origin)", gotPath)
	}
}

func TestFavoriteOrigin_Observer_ServerError_ReturnsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	a := &App{remote: newWebClient(testPortApp(t, srv))}
	if got := a.FavoriteOrigin("n1"); got != "" {
		t.Errorf(`FavoriteOrigin(...) при ошибке сервера = %q, want "" (честная деградация, не паника)`, got)
	}
}

func TestUserFavoriteIDs_Observer_ParsesFromFavoritesEndpoint(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"favorite_ids":        []string{"a", "b", "c"},
			"user_favorite_ids":   []string{"a", "b"},
			"system_favorite_ids": []string{"c"},
		})
	}))
	defer srv.Close()

	a := &App{remote: newWebClient(testPortApp(t, srv))}
	got := a.UserFavoriteIDs()
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf(`UserFavoriteIDs() = %v, want ["a","b"] (поле user_favorite_ids, не favorite_ids целиком)`, got)
	}
	if !strings.HasSuffix(gotPath, "/api/favorites") {
		t.Errorf("UserFavoriteIDs observer: путь = %s, want суффикс /api/favorites", gotPath)
	}
}

func TestUserFavoriteIDs_Observer_ServerError_ReturnsEmptyNotNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	a := &App{remote: newWebClient(testPortApp(t, srv))}
	got := a.UserFavoriteIDs()
	if got == nil {
		t.Fatal("UserFavoriteIDs() = nil при ошибке сервера, want non-nil пустой срез (nil-safety)")
	}
	if len(got) != 0 {
		t.Errorf("UserFavoriteIDs() при ошибке сервера = %v, want пустой", got)
	}
}

func TestSystemFavoriteIDs_Observer_ParsesFromFavoritesEndpoint(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"favorite_ids":        []string{"a", "sys1"},
			"user_favorite_ids":   []string{"a"},
			"system_favorite_ids": []string{"sys1"},
		})
	}))
	defer srv.Close()

	a := &App{remote: newWebClient(testPortApp(t, srv))}
	got := a.SystemFavoriteIDs()
	if len(got) != 1 || got[0] != "sys1" {
		t.Errorf(`SystemFavoriteIDs() = %v, want ["sys1"] (поле system_favorite_ids)`, got)
	}
	if !strings.HasSuffix(gotPath, "/api/favorites") {
		t.Errorf("SystemFavoriteIDs observer: путь = %s, want суффикс /api/favorites", gotPath)
	}
}

func TestCatalogReviewInterval_Observer_ParsesIntervalField(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"interval": "monthly"})
	}))
	defer srv.Close()

	a := &App{remote: newWebClient(testPortApp(t, srv))}
	if got := a.CatalogReviewInterval(); got != "monthly" {
		t.Errorf(`CatalogReviewInterval() = %q, want "monthly"`, got)
	}
	if !strings.HasSuffix(gotPath, "/api/catalog-review-interval") {
		t.Errorf("CatalogReviewInterval observer: путь = %s, want суффикс /api/catalog-review-interval (через дефис, канонический контракт L2-WEB-B)", gotPath)
	}
}

func TestCatalogReviewInterval_Observer_EmptyField_DefaultsToEachScan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{}) // поле отсутствует
	}))
	defer srv.Close()

	a := &App{remote: newWebClient(testPortApp(t, srv))}
	if got := a.CatalogReviewInterval(); got != models.ReviewIntervalEachScan {
		t.Errorf("CatalogReviewInterval() при пустом ответе = %q, want дефолт %q", got, models.ReviewIntervalEachScan)
	}
}

func TestCatalogReviewInterval_Observer_ServerUnreachable_DefaultsToEachScan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	a := &App{remote: newWebClient(testPortApp(t, srv))}
	if got := a.CatalogReviewInterval(); got != models.ReviewIntervalEachScan {
		t.Errorf("CatalogReviewInterval() при недоступном пути = %q, want честный дефолт %q, не панику/пустую строку", got, models.ReviewIntervalEachScan)
	}
}

func TestSetCatalogReviewInterval_Observer_PostsValueField(t *testing.T) {
	var gotBody map[string]interface{}
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "interval": "weekly"})
	}))
	defer srv.Close()

	a := &App{remote: newWebClient(testPortApp(t, srv))}
	if err := a.SetCatalogReviewInterval("weekly"); err != nil {
		t.Fatalf("SetCatalogReviewInterval(weekly): %v", err)
	}
	if gotBody["value"] != "weekly" {
		t.Errorf(`тело запроса = %v, want {"value":"weekly"} (поле "value", НЕ "interval" — канонический контракт L2-WEB-B)`, gotBody)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("SetCatalogReviewInterval observer: метод = %s, want POST", gotMethod)
	}
	if !strings.HasSuffix(gotPath, "/api/catalog-review-interval") {
		t.Errorf("SetCatalogReviewInterval observer: путь = %s, want суффикс /api/catalog-review-interval", gotPath)
	}
}

// TestSetCatalogReviewInterval_Observer_ServerError_Propagates — воспроизводит РЕАЛЬНОЕ
// поведение apiCatalogReviewInterval (internal/web/server.go): отказ валидации — HTTP 400 с
// JSON-телом {"error":"..."}, а не 200 с полем error внутри (в отличие от большинства других
// ручек этого файла). webclient.postJSON на статусах ≥400 отдаёт СЫРОЕ тело как текст ошибки —
// проверяем, что SetCatalogReviewInterval разворачивает JSON и возвращает читаемое сообщение,
// а не голый `{"error":"..."}` литералом.
func TestSetCatalogReviewInterval_Observer_ServerError_Propagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "неизвестный интервал пересмотра каталога"})
	}))
	defer srv.Close()

	a := &App{remote: newWebClient(testPortApp(t, srv))}
	err := a.SetCatalogReviewInterval("bogus")
	if err == nil {
		t.Fatal("ожидалась ошибка при HTTP 400 {\"error\":...}")
	}
	if !strings.Contains(err.Error(), "неизвестный интервал пересмотра каталога") {
		t.Errorf(`err = %q, want сообщение содержащее развёрнутый текст поля "error" сервера, а не сырой JSON`, err.Error())
	}
}

// TestSetCatalogReviewInterval_Observer_NonJSONErrorBody_StillReturnsError — если тело 4xx не
// JSON (не апи-ошибка, а например сырая страница/текст от прокси) — разворачивание JSON должно
// тихо провалиться и вернуть исходную ошибку as-is, а не проглотить её и не запаниковать.
func TestSetCatalogReviewInterval_Observer_NonJSONErrorBody_StillReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	a := &App{remote: newWebClient(testPortApp(t, srv))}
	if err := a.SetCatalogReviewInterval("weekly"); err == nil {
		t.Fatal("ожидалась ошибка при не-JSON теле ответа 5xx, получили nil")
	}
}
