// server_v14_auth_test.go — ТЗ v1.4 (TZ_APF_v1.4_FINAL.md), лот L1-WEB: S-18 (проверка
// происхождения на все методы), S-2 (аутентификация локального API, серверная часть),
// S-3 (приватный ключ Reality не в GET-ответе), S-13 (журналирование отказов).
//
// TestPre_S18 использует guardCrossOrigin в исходной сигнатуре (не меняется этим лотом,
// см. csrf_guard_test.go) и кодирует ЦЕЛЕВОЕ поведение — перед реализацией S-18 этот тест
// падал (S-18: guardCrossOrigin не проверял происхождение на GET; подтверждено живым
// прогоном при разработке, зафиксировано в result.md). Аналогичные пробы для S-2 и S-3
// были прогнаны отдельно (напрямую через apiConfig/apiServerRoleIdentity и через
// guardCrossOrigin(s.mux) — композицию Start() ДО этого лота) и тоже красные — не
// оставлены здесь постоянно, потому что они проверяли промежуточную, а не финальную
// сборку (Handler()); их роль полностью перекрыта тестами группы S2/S3 ниже, которые
// проходят через ту же цепочку, что и продакшен-код (Handler()).
package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/singbox"
)

// TestPre_S18_GETNotOriginChecked_Vulnerability — S-18: до фикса guardCrossOrigin вообще не
// проверял происхождение для GET (isMutatingMethod пропускал всё, кроме POST/PUT/PATCH/
// DELETE). Цель: GET /api/diagnostics с чужим Sec-Fetch-Site обязан получать 403. Использует
// guardCrossOrigin В ИСХОДНОЙ сигнатуре (не меняется этим лотом, см. csrf_guard_test.go).
func TestPre_S18_GETNotOriginChecked_Vulnerability(t *testing.T) {
	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(200)
	})
	req := httptest.NewRequest(http.MethodGet, "/api/diagnostics", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	guardCrossOrigin(inner).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("S-18: GET /api/diagnostics с Sec-Fetch-Site=cross-site вернул %d (reached=%v), "+
			"ожидалось 403 — guardCrossOrigin не проверяет происхождение на GET", rec.Code, reached)
	}
}

// ── общие помощники для полной цепочки middleware ──────────────────────────────────────

// fullHandlerChain — та же композиция, что Start() отдаёт httpServeFn в бою: Handler()
// (logSecurityDenials(guardCrossOrigin(requireAuth(mux)))). Тесты этого файла проходят
// через неё, а не через мьюкс напрямую, чтобы не разойтись с production-поведением.
func fullHandlerChain(s *Server) http.Handler {
	return s.Handler()
}

func doReq(s *Server, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	fullHandlerChain(s).ServeHTTP(rec, req)
	return rec
}

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

// ── S-18: происхождение проверяется для любого метода, кроме GET / и GET /ui ──────────

func TestS18_GET_CrossSiteRejected(t *testing.T) {
	s := newTestServer(t)
	rec := doReq(s, http.MethodGet, "/api/diagnostics", map[string]string{"Sec-Fetch-Site": "cross-site"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("GET /api/diagnostics Sec-Fetch-Site=cross-site: got %d, want 403", rec.Code)
	}
}

func TestS18_GET_SameSiteRejected(t *testing.T) {
	s := newTestServer(t)
	rec := doReq(s, http.MethodGet, "/api/nodes", map[string]string{"Sec-Fetch-Site": "same-site"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("GET /api/nodes Sec-Fetch-Site=same-site: got %d, want 403", rec.Code)
	}
}

// Порядок: сначала происхождение, потом аутентификация (ТЗ S-18: "оба отказа журналируются,
// сначала origin"). Запрос без токена И с чужим origin обязан получить 403, не 401.
func TestS18_OriginCheckedBeforeAuth(t *testing.T) {
	s := newTestServer(t)
	rec := doReq(s, http.MethodGet, "/api/diagnostics", map[string]string{"Sec-Fetch-Site": "cross-site"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("запрос без токена и с чужим origin: got %d, want 403 (origin проверяется первым)", rec.Code)
	}
}

// GET / и GET /ui — единственные исключения из проверки происхождения (вход по handoff-ключу).
func TestS18_RootAndUI_ExemptFromOriginCheck(t *testing.T) {
	s := newTestServer(t)
	headers := map[string]string{"Sec-Fetch-Site": "cross-site"}

	recRoot := doReq(s, http.MethodGet, "/", headers)
	if recRoot.Code == http.StatusForbidden {
		t.Errorf("GET / с Sec-Fetch-Site=cross-site: got 403, ожидалось прохождение проверки происхождения")
	}

	recUI := doReq(s, http.MethodGet, "/ui", headers)
	if recUI.Code == http.StatusForbidden {
		t.Errorf("GET /ui с Sec-Fetch-Site=cross-site: got 403, ожидалось прохождение проверки происхождения " +
			"(получит 401 из-за отсутствия/невалидности k, но не 403 от guardCrossOrigin)")
	}
}

// Существующее поведение мутирующих маршрутов не сломано (регресс к csrf_guard_test.go).
func TestS18_MutatingRoutesStillGuarded(t *testing.T) {
	s := newTestServer(t)
	rec := doReq(s, http.MethodPost, "/api/emergency/wipe", map[string]string{"Origin": "https://evil.example"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST /api/emergency/wipe с чужим Origin: got %d, want 403", rec.Code)
	}
}

// ── S-2: аутентификация ────────────────────────────────────────────────────────────────

func TestS2_ApiConfig_NoToken_401_GET(t *testing.T) {
	s := newTestServer(t)
	rec := doReq(s, http.MethodGet, "/api/config", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /api/config без токена: got %d, want 401", rec.Code)
	}
}

func TestS2_ApiConfig_NoToken_401_POST(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/save-config", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	fullHandlerChain(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("POST /api/save-config без токена: got %d, want 401", rec.Code)
	}
}

func TestS2_ApiConfig_ValidToken_200(t *testing.T) {
	s := newTestServer(t)
	rec := doReq(s, http.MethodGet, "/api/config", bearer(s.authToken))
	if rec.Code != http.StatusOK {
		t.Errorf("GET /api/config с валидным токеном: got %d, want 200", rec.Code)
	}
}

func TestS2_ApiConfig_WrongToken_401(t *testing.T) {
	s := newTestServer(t)
	rec := doReq(s, http.MethodGet, "/api/config", bearer("not-the-real-token-0000000000000000"))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /api/config с чужим токеном: got %d, want 401", rec.Code)
	}
}

func TestS2_LogsExport_RequiresToken(t *testing.T) {
	s := newTestServer(t)
	recNo := doReq(s, http.MethodGet, "/api/logs/export", nil)
	if recNo.Code != http.StatusUnauthorized {
		t.Errorf("GET /api/logs/export без токена: got %d, want 401", recNo.Code)
	}
	recYes := doReq(s, http.MethodGet, "/api/logs/export", bearer(s.authToken))
	if recYes.Code != http.StatusOK {
		t.Errorf("GET /api/logs/export с токеном: got %d, want 200", recYes.Code)
	}
}

// Токен НИКОГДА не печатается в теле страницы "/" — иначе дыра, ради которой S-2 вводится
// (O-2), осталась бы на месте: любой локальный процесс сделал бы GET / и получил токен.
func TestS2_RootPage_NoTokenInBody(t *testing.T) {
	s := newTestServer(t)
	rec := doReq(s, http.MethodGet, "/", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /: got %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), s.authToken) {
		t.Error("тело страницы \"/\" содержит токен аутентификации")
	}
}

// Handoff: минтинг одноразового ключа требует токена (это /api/*), обмен k→cookie — нет.
func TestS2_UIHandoff_MintRequiresToken(t *testing.T) {
	s := newTestServer(t)
	rec := doReq(s, http.MethodPost, "/api/ui/handoff", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("POST /api/ui/handoff без токена: got %d, want 401", rec.Code)
	}
}

func TestS2_UIHandoff_FullExchange_SetsHttpOnlyCookie(t *testing.T) {
	s := newTestServer(t)
	mintRec := doReq(s, http.MethodPost, "/api/ui/handoff", bearer(s.authToken))
	if mintRec.Code != http.StatusOK {
		t.Fatalf("mint handoff key: got %d, want 200", mintRec.Code)
	}
	var mint struct {
		K string `json:"k"`
	}
	if err := json.Unmarshal(mintRec.Body.Bytes(), &mint); err != nil || mint.K == "" {
		t.Fatalf("mint handoff key: decode error %v, body=%s", err, mintRec.Body.String())
	}

	exReq := httptest.NewRequest(http.MethodGet, "/ui?k="+mint.K, nil)
	exRec := httptest.NewRecorder()
	fullHandlerChain(s).ServeHTTP(exRec, exReq)
	if exRec.Code != http.StatusFound {
		t.Fatalf("GET /ui?k=<valid>: got %d, want 302", exRec.Code)
	}
	setCookie := exRec.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "apf_ui=") {
		t.Fatalf("Set-Cookie не содержит apf_ui: %q", setCookie)
	}
	if !strings.Contains(setCookie, "HttpOnly") {
		t.Errorf("Set-Cookie без HttpOnly: %q", setCookie)
	}
	if !strings.Contains(setCookie, "SameSite=Strict") {
		t.Errorf("Set-Cookie без SameSite=Strict: %q", setCookie)
	}

	// Постоянный токен НИКОГДА не появляется в URL (S-2 п.4) — k одноразовый и отличен от токена.
	if mint.K == s.authToken {
		t.Error("одноразовый handoff-ключ совпал с постоянным токеном")
	}

	// Тот же k повторно — уже инвалидирован, обязан вернуть отказ.
	reuseReq := httptest.NewRequest(http.MethodGet, "/ui?k="+mint.K, nil)
	reuseRec := httptest.NewRecorder()
	fullHandlerChain(s).ServeHTTP(reuseRec, reuseReq)
	if reuseRec.Code != http.StatusUnauthorized {
		t.Errorf("повторное использование того же k: got %d, want 401", reuseRec.Code)
	}

	// Cookie, выданная обменом, сама по себе достаточна для доступа к /api/*.
	cookieReq := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	cookieReq.Header.Set("Cookie", "apf_ui="+s.authToken)
	cookieRec := httptest.NewRecorder()
	fullHandlerChain(s).ServeHTTP(cookieRec, cookieReq)
	if cookieRec.Code != http.StatusOK {
		t.Errorf("GET /api/config с cookie apf_ui: got %d, want 200", cookieRec.Code)
	}
}

func TestS2_UIHandoff_UnknownKey_401(t *testing.T) {
	s := newTestServer(t)
	rec := doReq(s, http.MethodGet, "/ui?k=nonexistent-key-value", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /ui с несуществующим k: got %d, want 401", rec.Code)
	}
}

// TTL 10с — белый ящик (тот же пакет): протухший ключ не обязан ждать реальные 10 секунд в тесте.
func TestS2_UIHandoff_ExpiredKey_401(t *testing.T) {
	s := newTestServer(t)
	k, err := s.mintHandoffKey()
	if err != nil {
		t.Fatalf("mintHandoffKey: %v", err)
	}
	s.handoffMu.Lock()
	s.handoffKeys[k] = time.Now().Add(-time.Second)
	s.handoffMu.Unlock()

	rec := doReq(s, http.MethodGet, "/ui?k="+k, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /ui с протухшим k: got %d, want 401", rec.Code)
	}
}

// ── S-3: приватный ключ Reality не в GET-ответе, экспорт — под токеном, с журналом ────

func TestS3_GetIdentity_NoPrivateKey(t *testing.T) {
	s := newTestServer(t)
	genRec := doReq(s, http.MethodPost, "/api/server-role/generate-identity", bearer(s.authToken))
	if genRec.Code != http.StatusOK {
		t.Fatalf("generate-identity: got %d, want 200 (%s)", genRec.Code, genRec.Body.String())
	}

	idRec := doReq(s, http.MethodGet, "/api/server-role/identity", bearer(s.authToken))
	if idRec.Code != http.StatusOK {
		t.Fatalf("GET identity: got %d, want 200", idRec.Code)
	}
	var resp struct {
		Found    bool                   `json:"found"`
		Identity singbox.ServerIdentity `json:"identity"`
	}
	if err := json.Unmarshal(idRec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Found {
		t.Fatal("found должен быть true после generate-identity")
	}
	if resp.Identity.PrivateKey != "" {
		t.Error("S-3: GET /api/server-role/identity вернул непустой приватный ключ")
	}
	// Публичная часть по-прежнему нужна фронтенду (например для сверки/отпечатка).
	if resp.Identity.PublicKey == "" {
		t.Error("публичный ключ не должен исчезать вместе с приватным")
	}
}

func TestS3_ExportIdentity_RequiresToken(t *testing.T) {
	s := newTestServer(t)
	rec := doReq(s, http.MethodPost, "/api/server-role/identity/export", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("POST identity/export без токена: got %d, want 401", rec.Code)
	}
}

func TestS3_ExportIdentity_NoBody_400(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/server-role/identity/export", nil)
	req.Header.Set("Authorization", "Bearer "+s.authToken)
	rec := httptest.NewRecorder()
	fullHandlerChain(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST identity/export без тела: got %d, want 400", rec.Code)
	}
}

func TestS3_ExportIdentity_WrongConfirm_400(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/server-role/identity/export",
		strings.NewReader(`{"confirm":"no"}`))
	req.Header.Set("Authorization", "Bearer "+s.authToken)
	rec := httptest.NewRecorder()
	fullHandlerChain(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST identity/export с неверным confirm: got %d, want 400", rec.Code)
	}
}

func TestS3_ExportIdentity_WithTokenAndConfirm_ReturnsKeyAndLogs(t *testing.T) {
	s := newTestServer(t)
	genRec := doReq(s, http.MethodPost, "/api/server-role/generate-identity", bearer(s.authToken))
	var genResp struct {
		Identity singbox.ServerIdentity `json:"identity"`
	}
	if err := json.Unmarshal(genRec.Body.Bytes(), &genResp); err != nil {
		t.Fatalf("decode generate response: %v", err)
	}

	s.logsMu.Lock()
	logsBefore := len(s.logs)
	s.logsMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/api/server-role/identity/export",
		strings.NewReader(`{"confirm":"EXPORT"}`))
	req.Header.Set("Authorization", "Bearer "+s.authToken)
	rec := httptest.NewRecorder()
	fullHandlerChain(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST identity/export с confirm=EXPORT: got %d (%s), want 200", rec.Code, rec.Body.String())
	}
	var expResp struct {
		Identity singbox.ServerIdentity `json:"identity"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &expResp); err != nil {
		t.Fatalf("decode export response: %v", err)
	}
	if expResp.Identity.PrivateKey == "" || expResp.Identity.PrivateKey != genResp.Identity.PrivateKey {
		t.Errorf("export должен вернуть тот же приватный ключ: got %q, want %q",
			expResp.Identity.PrivateKey, genResp.Identity.PrivateKey)
	}

	s.logsMu.Lock()
	newLogs := append([]string(nil), s.logs[logsBefore:]...)
	s.logsMu.Unlock()
	found := false
	for _, l := range newLogs {
		if strings.Contains(l, "export") || strings.Contains(l, "эксп") {
			found = true
			if strings.Contains(l, expResp.Identity.PrivateKey) {
				t.Error("запись журнала не должна содержать сам приватный ключ")
			}
		}
	}
	if !found {
		t.Errorf("экспорт приватного ключа не оставил записи в журнале, новые строки: %v", newLogs)
	}
}

// ── S-13: отказы происхождения/аутентификации журналируются, с ограничением частоты ────

func TestS13_OriginDenial_LogsOneLine(t *testing.T) {
	s := newTestServer(t)
	s.logsMu.Lock()
	before := len(s.logs)
	s.logsMu.Unlock()

	doReq(s, http.MethodGet, "/api/diagnostics", map[string]string{"Sec-Fetch-Site": "cross-site"})

	s.logsMu.Lock()
	added := s.logs[before:]
	s.logsMu.Unlock()
	if len(added) != 1 {
		t.Fatalf("один отказ происхождения должен дать ровно одну строку лога, получено %d: %v", len(added), added)
	}
	if !strings.Contains(added[0], "origin") {
		t.Errorf("строка лога не упоминает причину origin: %q", added[0])
	}
	// Без тела запроса и без токена в записи.
	if strings.Contains(added[0], s.authToken) {
		t.Error("запись лога содержит токен аутентификации")
	}
}

func TestS13_AuthDenial_LogsOneLine(t *testing.T) {
	s := newTestServer(t)
	s.logsMu.Lock()
	before := len(s.logs)
	s.logsMu.Unlock()

	doReq(s, http.MethodGet, "/api/config", nil)

	s.logsMu.Lock()
	added := s.logs[before:]
	s.logsMu.Unlock()
	if len(added) != 1 {
		t.Fatalf("один отказ аутентификации должен дать ровно одну строку лога, получено %d: %v", len(added), added)
	}
	if !strings.Contains(added[0], "auth") {
		t.Errorf("строка лога не упоминает причину auth: %q", added[0])
	}
}

// 100 отказов подряд (одна причина) — не более нескольких записей (ограничение частоты,
// не чаще 1 записи/сек на причину; весь цикл укладывается в доли секунды).
func TestS13_RepeatedDenials_RateLimited(t *testing.T) {
	s := newTestServer(t)
	s.logsMu.Lock()
	before := len(s.logs)
	s.logsMu.Unlock()

	for i := 0; i < 100; i++ {
		doReq(s, http.MethodGet, "/api/config", nil)
	}

	s.logsMu.Lock()
	added := len(s.logs) - before
	s.logsMu.Unlock()
	if added < 1 {
		t.Error("100 отказов не оставили ни одной записи — журналирование не работает совсем")
	}
	if added > 3 {
		t.Errorf("100 отказов подряд дали %d записей — ограничение частоты (1/сек на причину) не работает", added)
	}
}
