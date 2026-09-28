// server_w3_favorites_test.go — W3 (ТЗ v1.5 §2/§5, TZ_v1.5_NODE_CATALOG_2026-09-14), лот
// L2-WEB-B: HTTP-обвязка двухклассового избранного (apiFavorites) и интервала пересмотра
// каталога (apiCatalogReviewInterval), плюс структурные проверки встроенного UI (бейджи класса
// избранного, селектор интервала). Движковая часть (класс/промоушен/эвикшен/валидация) уже
// покрыта internal/engine/nodes_favorites_w3_test.go (лот L1-ENG-C) — здесь только контракт
// этого пакета: что HTTP-ручки и webUI правильно читают/пишут уже готовый Engine API.
package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── /api/favorites: разбивка по классу (W3 §2) ────────────────────────────────────────────

// TestApiFavorites_ReturnsUserAndSystemClassSeparately — user_favorite_ids/system_favorite_ids
// должны отражать реальный класс (EffectiveOrigin) каждого узла, а favorite_ids — оставаться
// объединением обоих классов (обратная совместимость с уже читающими его клиентами).
func TestApiFavorites_ReturnsUserAndSystemClassSeparately(t *testing.T) {
	s := newTestServer(t)
	idUser := addTestNode(t, s, "10.20.0.1", "userfav")
	idSystem := addTestNode(t, s, "10.20.0.2", "sysfav")
	_ = addTestNode(t, s, "10.20.0.3", "plain")

	if err := s.eng.AddFavorite(idUser); err != nil {
		t.Fatalf("AddFavorite: %v", err)
	}
	if err := s.eng.AddSystemFavorite(idSystem); err != nil {
		t.Fatalf("AddSystemFavorite: %v", err)
	}

	w := testGET(s, s.apiFavorites)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		FavoriteIDs       []string `json:"favorite_ids"`
		UserFavoriteIDs   []string `json:"user_favorite_ids"`
		SystemFavoriteIDs []string `json:"system_favorite_ids"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad json: %v (%s)", err, w.Body.String())
	}
	if len(resp.FavoriteIDs) != 2 {
		t.Errorf("favorite_ids (union) = %v, want 2 entries", resp.FavoriteIDs)
	}
	if len(resp.UserFavoriteIDs) != 1 || resp.UserFavoriteIDs[0] != idUser {
		t.Errorf("user_favorite_ids = %v, want [%s]", resp.UserFavoriteIDs, idUser)
	}
	if len(resp.SystemFavoriteIDs) != 1 || resp.SystemFavoriteIDs[0] != idSystem {
		t.Errorf("system_favorite_ids = %v, want [%s]", resp.SystemFavoriteIDs, idSystem)
	}
}

// TestApiFavorites_EmptyArraysNotNull — те же три поля никогда не JSON null (как и favorite_ids
// раньше, ids==nil→[]string{} в apiFavorites), даже когда избранного нет вовсе.
func TestApiFavorites_EmptyArraysNotNull(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiFavorites)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		FavoriteIDs       []string `json:"favorite_ids"`
		UserFavoriteIDs   []string `json:"user_favorite_ids"`
		SystemFavoriteIDs []string `json:"system_favorite_ids"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad json: %v (%s)", err, w.Body.String())
	}
	if resp.FavoriteIDs == nil {
		t.Error("favorite_ids is JSON null, want [] on empty pool")
	}
	if resp.UserFavoriteIDs == nil {
		t.Error("user_favorite_ids is JSON null, want []")
	}
	if resp.SystemFavoriteIDs == nil {
		t.Error("system_favorite_ids is JSON null, want []")
	}
}

// TestApiFavorites_StarPromotesSystemToUser — сквозной HTTP-путь того же сценария, что и
// TestFavoriteOrigin_AddPromoteRemove в internal/engine: apiFavorite{favorite:true} на уже
// системном фаворите (как шлёт звезда в actions-колонке webUI на системном бейдже) обязан
// перевести узел в user-класс, а не создать дубликат/ошибку.
func TestApiFavorites_StarPromotesSystemToUser(t *testing.T) {
	s := newTestServer(t)
	id := addTestNode(t, s, "10.20.0.4", "promote")
	if err := s.eng.AddSystemFavorite(id); err != nil {
		t.Fatalf("AddSystemFavorite: %v", err)
	}

	w := testPOST(s, s.apiFavorite, `{"node_id":"`+id+`","favorite":true}`)
	if w.Code != 200 {
		t.Fatalf("apiFavorite promote: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if got := s.eng.FavoriteOrigin(id); got != models.OriginUser {
		t.Fatalf("FavoriteOrigin after star-promote via HTTP = %q, want %q", got, models.OriginUser)
	}

	fw := testGET(s, s.apiFavorites)
	var resp struct {
		UserFavoriteIDs   []string `json:"user_favorite_ids"`
		SystemFavoriteIDs []string `json:"system_favorite_ids"`
	}
	if err := json.Unmarshal(fw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if len(resp.SystemFavoriteIDs) != 0 {
		t.Errorf("system_favorite_ids after promotion = %v, want empty", resp.SystemFavoriteIDs)
	}
	if len(resp.UserFavoriteIDs) != 1 || resp.UserFavoriteIDs[0] != id {
		t.Errorf("user_favorite_ids after promotion = %v, want [%s]", resp.UserFavoriteIDs, id)
	}
}

// ─── /api/catalog-review-interval (W3 §5) ──────────────────────────────────────────────────

func TestApiCatalogReviewInterval_GetDefaultEachScan(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiCatalogReviewInterval)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		Interval string `json:"interval"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad json: %v (%s)", err, w.Body.String())
	}
	if resp.Interval != models.ReviewIntervalEachScan {
		t.Errorf("interval = %q, want %q (default)", resp.Interval, models.ReviewIntervalEachScan)
	}
}

func TestApiCatalogReviewInterval_PostValidPersistsAndReflectsOnGet(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiCatalogReviewInterval, `{"value":"weekly"}`)
	if w.Code != 200 {
		t.Fatalf("POST weekly: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if got := s.eng.CatalogReviewInterval(); got != models.ReviewIntervalWeekly {
		t.Fatalf("engine interval after POST = %q, want %q", got, models.ReviewIntervalWeekly)
	}

	w2 := testGET(s, s.apiCatalogReviewInterval)
	var resp struct {
		Interval string `json:"interval"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if resp.Interval != models.ReviewIntervalWeekly {
		t.Errorf("GET after POST weekly = %q, want weekly", resp.Interval)
	}
}

// TestApiCatalogReviewInterval_PostUnknownValue_400NoSideEffect — явный пользовательский ввод,
// которому SetCatalogReviewInterval обязан честно отказать (в отличие от отката пустого/чужого
// значения В КОНФИГЕ на each_scan) — см. комментарий Engine.SetCatalogReviewInterval.
func TestApiCatalogReviewInterval_PostUnknownValue_400NoSideEffect(t *testing.T) {
	s := newTestServer(t)
	before := s.eng.CatalogReviewInterval()
	w := testPOST(s, s.apiCatalogReviewInterval, `{"value":"biweekly"}`)
	if w.Code != 400 {
		t.Fatalf("expected 400 for unknown interval, got %d (%s)", w.Code, w.Body.String())
	}
	if got := s.eng.CatalogReviewInterval(); got != before {
		t.Errorf("unknown value must not change stored interval: before=%q after=%q", before, got)
	}
}

func TestApiCatalogReviewInterval_PostBadJSON_400(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiCatalogReviewInterval, `not json`)
	if w.Code != 400 {
		t.Fatalf("expected 400 for bad json, got %d", w.Code)
	}
}

func TestApiCatalogReviewInterval_UnsupportedMethod_405(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/catalog-review-interval", nil)
	s.apiCatalogReviewInterval(w, r)
	if w.Code != 405 {
		t.Fatalf("expected 405 for DELETE, got %d", w.Code)
	}
}

// ─── Структура встроенного UI: бейджи класса + селектор интервала (W3, лот L2-WEB-B) ───────

func TestW3UI_FavoriteClassBadgesPresent(t *testing.T) {
	if !strings.Contains(webUI, "userFavoriteIdSet") || !strings.Contains(webUI, "systemFavoriteIdSet") {
		t.Fatal("webUI не заводит отдельные JS-множества user/systemFavoriteIdSet (W3 §2)")
	}
	if !strings.Contains(webUI, "🤖") {
		t.Error("webUI не показывает отдельный бейдж 🤖 для системного избранного (W3 §2)")
	}
	// Звезда в колонке действий на системном фаворите обязана слать favorite:true (промоушен),
	// а не переключаться в false — иначе клик по ней тихо удаляет автодобавленный узел вместо
	// того, чтобы закрепить его, см. комментарий у favNextVal в renderNodes.
	if !strings.Contains(webUI, "favSystem?true:!fav") {
		t.Error("звезда в колонке действий не повышает системный фаворит (favSystem?true:!fav отсутствует, W3 §2)")
	}
}

func TestW3UI_CatalogReviewIntervalSelectorPresent(t *testing.T) {
	if !strings.Contains(webUI, `id="s-catalog-review-interval"`) {
		t.Fatal("нет селектора #s-catalog-review-interval в Настройках (W3 §5)")
	}
	for _, v := range []string{"each_scan", "daily", "weekly", "monthly"} {
		if !strings.Contains(webUI, `value="`+v+`"`) {
			t.Errorf("селектор интервала пересмотра не содержит опцию %q", v)
		}
	}
	if !strings.Contains(webUI, "function loadCatalogReviewInterval") {
		t.Error("нет JS-функции loadCatalogReviewInterval")
	}
	if !strings.Contains(webUI, "function setCatalogReviewInterval") {
		t.Error("нет JS-функции setCatalogReviewInterval")
	}
}

// TestW3UI_ReviewIntervalHonestWording — C-20/N-9: текст рядом с новым селектором обязан честно
// говорить, что сборка каталога только вручную (авто-скана нет), и НЕ использовать «через
// туннель» — эта настройка вообще не про TUN-подтверждение.
func TestW3UI_ReviewIntervalHonestWording(t *testing.T) {
	idx := strings.Index(webUI, `id="s-catalog-review-interval"`)
	if idx < 0 {
		t.Fatal("селектор интервала не найден")
	}
	start := idx - 1200
	if start < 0 {
		start = 0
	}
	window := webUI[start:idx]
	if strings.Contains(window, "через туннель") {
		t.Error("формулировка рядом с интервалом пересмотра каталога использует «через туннель» — нарушение C-20/N-9")
	}
	if !strings.Contains(window, "вручную") {
		t.Error("формулировка рядом с интервалом пересмотра не подтверждает честно, что сборка каталога только вручную")
	}
}
