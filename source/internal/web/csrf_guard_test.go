package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// P0-2 (аудит 2026-09-01): защита от межсайтовых запросов.
//
// До фикса локальный API не проверял происхождение запроса вообще. Отсутствие
// Access-Control-Allow-Origin закрывало только ЧТЕНИЕ ответа чужой страницей, но не сам
// побочный эффект: `fetch(url,{method:'POST',mode:'no-cors'})` — «простой» запрос, preflight
// не отправляется, и он доходит до сервера. Одного визита на произвольную страницу хватало,
// чтобы стереть данные пользователя, снять Kill Switch или вывести домен из туннеля.
//
// Тестов на CSRF в проекте не было ни одного — существующий TestCors_NoWildcardOrigin
// проверяет только отсутствие заголовка в ОТВЕТЕ.

// guardedProbe прогоняет запрос через тот же барьер, что стоит в бою (Start → guardCrossOrigin).
func guardedProbe(t *testing.T, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	guardCrossOrigin(inner).ServeHTTP(rec, req)
	if rec.Code == http.StatusOK && !reached {
		t.Fatal("внутренний обработчик не вызван, хотя запрос прошёл барьер")
	}
	return rec
}

// Полный список мутирующих маршрутов. Именно табличный тест: новый опасный маршрут, забытый
// в этом списке, — сам по себе дефект, но барьер стоит на всём mux, поэтому защищён и он.
var mutatingRoutes = []string{
	"/api/connect", "/api/disconnect", "/api/scan", "/api/rescan",
	"/api/add-node", "/api/add-node-manual", "/api/chain-partner/connect",
	"/api/connect-node", "/api/connect-once", "/api/pin", "/api/favorite",
	// W3 (ТЗ v1.5 §5, лот L2-WEB-B): POST здесь persistToggle-ит config.json (SetCatalogReviewInterval)
	// — тот же класс мутации, что и остальные записи в этой таблице; не было в исходном брифе лота,
	// добавлено по аналогии, чтобы новый мутирующий маршрут не остался задокументирован только в
	// knownAPIRoutesV14 (server_v14_ui_test.go), но не здесь — комментарий над таблицей выше
	// специально предупреждает именно об этом классе пропуска.
	"/api/catalog-review-interval",
	"/api/reset-network", "/api/connectivity-check",
	"/api/save-config",
	// ТЗ v1.3 F3/F4: управление узлами + обход пула с прогрессом — были заведены в mux
	// (routes()) уже ПОСЛЕ того, как этот список составили изначально, и не попали сюда.
	// Барьер guardCrossOrigin оборачивает whole mux в Start(), так что дыры в проде эти
	// пропуски не создавали — но пропуск в ЭТОМ табличном тесте означает, что регрессия
	// (например, будущий рефакторинг, который начнёт регистрировать какой-то из этих
	// маршрутов в обход общего mux) прошла бы незамеченной.
	"/api/node/remove", "/api/node/ban", "/api/node/update", "/api/node/reset",
	"/api/nodes/restore-removed", "/api/scan/start", "/api/scan/cancel",
	"/api/server-role/generate-identity", "/api/server-role/build-link",
	"/api/server-role/start", "/api/server-role/stop",
	"/api/paid-providers/add", "/api/paid-providers/remove", "/api/paid-providers/test",
	"/api/leakguard/dns-test", "/api/leakguard/ipv6", "/api/leakguard/webrtc",
	"/api/crypto/set-password", "/api/emergency/wipe",
	"/api/dpi/canary-test", "/api/dpi/padding", "/api/dpi/cdn", "/api/dpi/shadowtls",
	"/api/dpi/shadowtls-auto-sni",
	"/api/session/policy", "/api/session/force-switch",
	"/api/fallback/activate", "/api/fallback/auto-select",
	"/api/catalog/refresh", "/api/catalog/provider",
	"/api/adblock/profile", "/api/adblock/allowlist",
	"/api/antiblock/check-ip", "/api/antiblock/check-node", "/api/antiblock/config",
	"/api/antiblock/bypass-list", "/api/antiblock/bypass-domain",
}

func TestCSRF_ForeignOriginRejectedOnEveryMutatingRoute(t *testing.T) {
	for _, route := range mutatingRoutes {
		t.Run(route, func(t *testing.T) {
			rec := guardedProbe(t, http.MethodPost, route, map[string]string{
				"Origin": "https://evil.example",
			})
			if rec.Code != http.StatusForbidden {
				t.Errorf("POST %s с чужим Origin вернул %d, ожидалось 403 — "+
					"страница атакующего может выполнить это действие", route, rec.Code)
			}
		})
	}
}

func TestCSRF_CrossSiteFetchMetadataRejected(t *testing.T) {
	// Именно так браузер помечает запрос, инициированный чужой страницей, даже когда
	// Origin по каким-то причинам не отправлен.
	for _, site := range []string{"cross-site", "same-site"} {
		t.Run(site, func(t *testing.T) {
			rec := guardedProbe(t, http.MethodPost, "/api/emergency/wipe", map[string]string{
				"Sec-Fetch-Site": site,
			})
			if rec.Code != http.StatusForbidden {
				t.Errorf("Sec-Fetch-Site=%s вернул %d, ожидалось 403", site, rec.Code)
			}
		})
	}
}

// Самый опасный конкретный сценарий из отчёта: «простой» межсайтовый запрос без preflight.
func TestCSRF_SimpleRequestWipeIsBlocked(t *testing.T) {
	rec := guardedProbe(t, http.MethodPost, "/api/emergency/wipe", map[string]string{
		"Origin":       "https://ads.example",
		"Content-Type": "text/plain;charset=UTF-8", // делает запрос «простым»: preflight не шлётся
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("необратимое стирание данных выполнено по запросу чужой страницы (код %d)", rec.Code)
	}
}

// Собственный UI обязан продолжать работать — в том числе POST'ы БЕЗ тела и без
// Content-Type (/api/connect, /api/disconnect, /api/scan, /api/rescan, /api/reset-network,
// /api/connectivity-check шлются именно так). Требование Content-Type сломало бы интерфейс.
func TestCSRF_SameOriginRequestsPass(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
	}{
		{"same-origin fetch", map[string]string{
			"Origin": "http://127.0.0.1:9090", "Sec-Fetch-Site": "same-origin"}},
		{"localhost origin", map[string]string{"Origin": "http://localhost:9090"}},
		{"IPv6 loopback", map[string]string{"Origin": "http://[::1]:9090"}},
		{"адресная строка (Sec-Fetch-Site: none)", map[string]string{"Sec-Fetch-Site": "none"}},
		{"не-браузерный клиент: заголовков нет", map[string]string{}},
		{"POST без Content-Type (так шлёт свой UI)", map[string]string{
			"Sec-Fetch-Site": "same-origin"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := guardedProbe(t, http.MethodPost, "/api/connect", c.headers)
			if rec.Code == http.StatusForbidden {
				t.Errorf("законный запрос отвергнут (403) — барьер ломает собственный UI")
			}
		})
	}
}

// Чтение остаётся доступным: барьер не должен ломать поллинг статуса.
// TEST-SYNC-W1 (2026-09-08, ADR оркестратора по ТЗ v1.4 S-18, лот L1-WEB): guardCrossOrigin
// теперь проверяет происхождение для ВСЕХ методов и путей, кроме GET "/" и GET "/ui"
// (isPublicEntryPoint) — «чтение защищено отсутствием CORS-заголовков» и было тем самым
// дефектом S-18 (простой fetch с mode:'no-cors' читает содержимое /api/state, не показывая
// его в JS, но сам факт утечки происходит через side-channel/timing, и главное — тот же
// непроверенный путь открывал и другие GET-эндпоинты для CSRF-подобной разведки). Новый
// контракт: GET к /api/* с чужим Origin блокируется; публичные точки входа / и /ui — нет.
func TestCSRF_GETNotBlocked(t *testing.T) {
	// GET к /api/* с чужим Origin теперь блокируется (S-18).
	rec := guardedProbe(t, http.MethodGet, "/api/state", map[string]string{
		"Origin": "https://evil.example",
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("GET /api/state с чужим Origin вернул %d, ожидалось 403 (S-18)", rec.Code)
	}

	// Публичные точки входа (GET / и GET /ui) остаются доступны без проверки Origin —
	// это единственные два случая, для которых isPublicEntryPoint(r) возвращает true.
	rec = guardedProbe(t, http.MethodGet, "/", map[string]string{
		"Origin": "https://evil.example",
	})
	if rec.Code == http.StatusForbidden {
		t.Error("GET / заблокирован — публичная точка входа не должна проверять Origin")
	}
}

func TestCSRF_DeleteIsGuarded(t *testing.T) {
	rec := guardedProbe(t, http.MethodDelete, "/api/watchdog/history", map[string]string{
		"Origin": "https://evil.example",
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("DELETE с чужим Origin вернул %d, ожидалось 403", rec.Code)
	}
}

func TestIsLoopbackHost(t *testing.T) {
	ok := []string{"localhost", "127.0.0.1", "127.0.0.53", "::1"}
	bad := []string{"evil.example", "192.168.1.10", "0.0.0.0", "8.8.8.8", ""}
	for _, h := range ok {
		if !isLoopbackHost(h) {
			t.Errorf("%q должен считаться петлёй", h)
		}
	}
	for _, h := range bad {
		if isLoopbackHost(h) {
			t.Errorf("%q НЕ должен считаться петлёй", h)
		}
	}
}
