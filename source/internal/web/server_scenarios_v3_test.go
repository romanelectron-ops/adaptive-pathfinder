// server_scenarios_v3_test.go — верификация HTTP API (100-300 сценариев на проект, доля
// internal/web): маршруты, у которых раньше не было ни одного HTTP-уровневого теста.
//
// Осознанно НЕ трогаем здесь:
//   - apiServerRoleStart / apiServerRoleStop (POST-путь): реально вызывают
//     singbox.EnsureInboundFirewallRule/RemoveInboundFirewallRule → exec.Command("netsh",
//     "advfirewall", ...) БЕЗ доступного из этого пакета шва для инъекции (execCommandFn
//     не экспортирован пакетом singbox) — прогон затронул бы настоящий файрвол хостовой
//     машины. Проверяем у них только безопасную часть (405 на неверный метод — до
//     обращения к движку) и текущее поведение через apiServerRoleStatus (GET, без
//     побочных эффектов).
//   - apiPaidProviderAdd/Test с валидным URL и apiConnectChainPartner/apiConnectOnce/
//     apiConnectNode с реальным дозвоном: в этом тестовом окружении такие попытки
//     блокируются барьером internal/netguard (за пределы петли `go test` не выпускает),
//     но чтобы не зависеть от этого барьера как от единственной страховки, для сетевых
//     хендлеров здесь используются только пути, где движок отказывает ДО набора номера
//     (валидация полей) либо где набор происходит в фоновой горутине уже ПОСЛЕ того, как
//     обработчик безопасно ответил (тот же приём, что и в уже существующих тестах
//     TestApiConnect_Post_Returns200 / TestAPIFavoriteAndConnectOnce).
package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/singbox"
)

// ── /api/logs/export ──────────────────────────────────────────────────────────

// Сценарий: GET /api/logs/export отдаёт лог как вложение (Content-Disposition: attachment)
// с именем файла apf-log-<дата>.txt, даже когда файловый лог не ведётся (тестовый движок
// не запущен) — тогда используется буфер s.logs.
func TestApiLogsExport_AttachmentHeaders(t *testing.T) {
	s := newTestServer(t)
	s.eng.OnLog("test line for export")

	w := testGET(s, s.apiLogsExport)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	cd := w.Header().Get("Content-Disposition")
	if !strings.HasPrefix(cd, "attachment;") {
		t.Errorf("Content-Disposition = %q, ожидался префикс \"attachment;\"", cd)
	}
	if !strings.Contains(cd, "apf-log-") || !strings.HasSuffix(cd, `.txt"`) {
		t.Errorf("Content-Disposition не содержит ожидаемое имя файла: %q", cd)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, ожидался text/plain", ct)
	}
	if !strings.Contains(w.Body.String(), "test line for export") {
		t.Errorf("тело экспорта не содержит записанную строку лога: %q", w.Body.String())
	}
}

// ── /api/domain-check (HTTP-обёртка; сама функция CheckDomainRouting уже покрыта
// domain_check_test.go — здесь проверяем именно HTTP-контракт: статус/JSON/параметр q) ──

func TestApiDomainCheck_NoLogs_EmptyArray(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiDomainCheck)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: want application/json, got %q", ct)
	}
	var got []interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("тело не JSON-массив: %v (%s)", err, w.Body.String())
	}
	if len(got) != 0 {
		t.Errorf("ожидался пустой список без логов, получено %d", len(got))
	}
}

func TestApiDomainCheck_QueryParamFiltersDomains(t *testing.T) {
	s := newTestServer(t)
	s.eng.OnLog("[sing-box] DEBUG[0013] [111 1ms] router: sniffed protocol: tls, domain: example.com")
	s.eng.OnLog("[sing-box] INFO[0013] [111 1ms] outbound/direct[direct]: outbound connection to 1.2.3.4:443")
	s.eng.OnLog("[sing-box] DEBUG[0013] [222 1ms] router: sniffed protocol: tls, domain: other.org")
	s.eng.OnLog("[sing-box] INFO[0013] [222 1ms] outbound/direct[direct]: outbound connection to 5.6.7.8:443")

	r := httptest.NewRequest(http.MethodGet, "/api/domain-check?q=example", nil)
	w := httptest.NewRecorder()
	s.apiDomainCheck(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "example.com") {
		t.Errorf("ожидался example.com в ответе: %s", body)
	}
	if strings.Contains(body, "other.org") {
		t.Errorf("other.org не должен пройти фильтр q=example: %s", body)
	}
}

// ── /api/nodes: представления и лимит ─────────────────────────────────────────

func addTestNode(t *testing.T, s *Server, addr, tag string) string {
	t.Helper()
	link := fmt.Sprintf("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@%s:8388#%s", addr, tag)
	if err := s.eng.AddNodeFromLink(link); err != nil {
		t.Fatalf("add node %s: %v", tag, err)
	}
	nodes := s.eng.GetNodes()
	return nodes[len(nodes)-1].ID
}

// GET /api/nodes?view=favorites должен вернуть только избранные узлы, без остальных.
func TestApiNodes_ViewFavorites_OnlyFavorited(t *testing.T) {
	s := newTestServer(t)
	idFav := addTestNode(t, s, "10.10.0.1", "fav1")
	_ = addTestNode(t, s, "10.10.0.2", "plain")

	if w := testPOST(s, s.apiFavorite, `{"node_id":"`+idFav+`","favorite":true}`); w.Code != 200 {
		t.Fatalf("favorite: expected 200, got %d", w.Code)
	}

	w := httptest.NewRecorder()
	s.apiNodes(w, httptest.NewRequest(http.MethodGet, "/api/nodes?view=favorites", nil))
	var resp struct {
		Nodes []struct {
			ID string `json:"id"`
		} `json:"nodes"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if resp.Total != 1 || len(resp.Nodes) != 1 || resp.Nodes[0].ID != idFav {
		t.Errorf("view=favorites: ожидался только %s, получено %+v", idFav, resp)
	}
}

// GET /api/nodes?view=manual должен включать узел, добавленный через /api/add-node-manual.
//
// Важное уточнение по факту чтения engine/engine.go и engine/nodes_manage.go: и
// AddNodeFromLink (/api/add-node), и AddNodeManual (/api/add-node-manual) проставляют
// одно и то же Source="manual" — представление "manual" в движке означает «добавлено
// пользователем явно (ссылкой или формой), а не найдено автоматически через каталог/
// платного провайдера», а не «конкретно через редактор продвинутых полей». Первая версия
// этого теста ошибочно предполагала обратное и падала — падал тест, не код.
func TestApiNodes_ViewManual_IncludesManuallyAddedNode(t *testing.T) {
	s := newTestServer(t)
	body := `{"protocol":"ss","address":"10.10.0.4","port":8388,"password":"p","method":"aes-256-gcm","name":"ManualOne"}`
	w := httptest.NewRecorder()
	s.apiAddNodeManual(w, httptest.NewRequest(http.MethodPost, "/api/add-node-manual", strings.NewReader(body)))
	if w.Code != 200 {
		t.Fatalf("add-node-manual: expected 200, got %d (%s)", w.Code, w.Body.String())
	}

	w2 := httptest.NewRecorder()
	s.apiNodes(w2, httptest.NewRequest(http.MethodGet, "/api/nodes?view=manual", nil))
	var resp struct {
		Nodes []struct {
			Name string `json:"name"`
		} `json:"nodes"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w2.Body.String())
	}
	found := false
	for _, n := range resp.Nodes {
		if n.Name == "ManualOne" {
			found = true
		}
	}
	if !found {
		t.Errorf("view=manual: ManualOne не найден среди %+v", resp)
	}
}

// GET /api/nodes?limit=1 должен обрезать список ДО 1, даже когда в пуле больше узлов —
// граница, отдельная от жёсткого потолка 200 (уже покрыт TestApiNodes_MoreThan200).
func TestApiNodes_LimitParam_Truncates(t *testing.T) {
	s := newTestServer(t)
	addTestNode(t, s, "10.10.0.5", "n1")
	addTestNode(t, s, "10.10.0.6", "n2")
	addTestNode(t, s, "10.10.0.7", "n3")

	w := httptest.NewRecorder()
	s.apiNodes(w, httptest.NewRequest(http.MethodGet, "/api/nodes?limit=1", nil))
	var resp struct {
		Nodes []interface{} `json:"nodes"`
		Total int           `json:"total"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp) //nolint
	if resp.Total != 3 {
		t.Errorf("total должен отражать полный пул (3), получено %d", resp.Total)
	}
	if len(resp.Nodes) != 1 {
		t.Errorf("limit=1 должен обрезать список до 1 узла, получено %d", len(resp.Nodes))
	}
}

// GET /api/nodes?view=all — эквивалент отсутствия view (весь пул, без фильтра).
func TestApiNodes_ViewAll_ReturnsEverything(t *testing.T) {
	s := newTestServer(t)
	addTestNode(t, s, "10.10.0.8", "a")
	addTestNode(t, s, "10.10.0.9", "b")

	w := httptest.NewRecorder()
	s.apiNodes(w, httptest.NewRequest(http.MethodGet, "/api/nodes?view=all", nil))
	var resp struct {
		Total int `json:"total"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp) //nolint
	if resp.Total != 2 {
		t.Errorf("view=all: ожидалось 2, получено %d", resp.Total)
	}
}

// ── /api/node/update: точная семантика патча (nil — не трогать, "" — по-разному) ─────
//
// Сценарий из ТЗ: пустое имя НЕ должно затирать существующее (защита от случайной отправки
// формы с очищенным полем), а пустая заметка — это явная команда «убрать заметку».
// Существующий TestAPINodeActions_BanUpdateRemoveRestore проверяет только одновременную
// установку непустых name+user_note — эта пара тестов закрывает разницу в поведении.

func TestApiNodeUpdate_EmptyName_DoesNotClearExistingName(t *testing.T) {
	s := newTestServer(t)
	id := addTestNode(t, s, "10.10.1.1", "OriginalName")
	before := s.eng.GetNodes()[0].Name

	w := testPOST(s, s.apiNodeUpdate, `{"node_id":"`+id+`","name":""}`)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	after := s.eng.GetNodes()[0].Name
	if after != before {
		t.Errorf("пустое имя изменило Name: было %q, стало %q", before, after)
	}
}

func TestApiNodeUpdate_EmptyUserNote_ClearsNote(t *testing.T) {
	s := newTestServer(t)
	id := addTestNode(t, s, "10.10.1.2", "n")

	if w := testPOST(s, s.apiNodeUpdate, `{"node_id":"`+id+`","user_note":"initial note"}`); w.Code != 200 {
		t.Fatalf("set note: expected 200, got %d", w.Code)
	}
	if got := s.eng.GetNodes()[0].UserNote; got != "initial note" {
		t.Fatalf("заметка не установилась: %q", got)
	}

	if w := testPOST(s, s.apiNodeUpdate, `{"node_id":"`+id+`","user_note":""}`); w.Code != 200 {
		t.Fatalf("clear note: expected 200, got %d", w.Code)
	}
	if got := s.eng.GetNodes()[0].UserNote; got != "" {
		t.Errorf("пустая user_note должна была убрать заметку, осталось %q", got)
	}
}

// Поле, вообще отсутствующее в JSON (Name==nil), не должно трогать ни имя, ни заметку —
// отличается от присланного, но пустого поля (Name!=nil, *Name=="").
func TestApiNodeUpdate_FieldOmitted_LeavesBothUntouched(t *testing.T) {
	s := newTestServer(t)
	id := addTestNode(t, s, "10.10.1.3", "KeepMe")
	if w := testPOST(s, s.apiNodeUpdate, `{"node_id":"`+id+`","user_note":"keep this too"}`); w.Code != 200 {
		t.Fatalf("set note: expected 200, got %d", w.Code)
	}

	// Патч без полей name/user_note вовсе — {"node_id":...} — обе не тронуты.
	if w := testPOST(s, s.apiNodeUpdate, `{"node_id":"`+id+`"}`); w.Code != 200 {
		t.Fatalf("noop update: expected 200, got %d", w.Code)
	}
	n := s.eng.GetNodes()[0]
	if n.Name != "KeepMe" || n.UserNote != "keep this too" {
		t.Errorf("noop-патч изменил состояние: %+v", n)
	}
}

// ── /api/favorite: удаление никогда не добавленного в избранное узла — не ошибка ─────
//
// Контраст: apiFavorite с favorite:true на неизвестном ID — 400 (валидирует существование
// узла), а favorite:false на узле, который просто не был в избранном, — идемпотентный
// no-op 200 (RemoveFavorite не проверяет существование узла в пуле, только членство в
// карте избранного). Обе половины поведения важны и относятся к разным путям кода.
func TestApiFavorite_RemoveNeverFavorited_NoOp200(t *testing.T) {
	s := newTestServer(t)
	id := addTestNode(t, s, "10.10.1.4", "n")

	w := testPOST(s, s.apiFavorite, `{"node_id":"`+id+`","favorite":false}`)
	if w.Code != 200 {
		t.Errorf("снятие никогда не установленного избранного должно быть no-op 200, получено %d (%s)",
			w.Code, w.Body.String())
	}
	if got := s.eng.FavoriteIDs(); len(got) != 0 {
		t.Errorf("избранное должно остаться пустым, получено %v", got)
	}
}

// ── /api/connect-once и /api/connect-node: успешный путь (фоновый дозвон блокируется
// барьером netguard за пределами теста — обработчик отвечает ДО набора номера) ───────

func TestApiConnectOnce_KnownNode_ReturnsConnecting(t *testing.T) {
	s := newTestServer(t)
	id := addTestNode(t, s, "10.10.1.5", "n")

	w := testPOST(s, s.apiConnectOnce, `{"node_id":"`+id+`"}`)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp) //nolint
	if resp["status"] != "connecting" || resp["node_id"] != id {
		t.Errorf("unexpected response: %+v", resp)
	}
	// Pin не должен меняться (F2 PIN-8) — connect-once НЕ закрепляет.
	if s.eng.PinnedNodeID() == id {
		t.Error("connect-once не должен закреплять узел")
	}
}

func TestApiConnectNode_KnownNode_ReturnsConnectingAndPins(t *testing.T) {
	s := newTestServer(t)
	id := addTestNode(t, s, "10.10.1.6", "n")

	w := testPOST(s, s.apiConnectNode, `{"node_id":"`+id+`"}`)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp) //nolint
	if resp["status"] != "connecting" || resp["pinned_node_id"] != id {
		t.Errorf("unexpected response: %+v", resp)
	}
}

// ── /api/scan/progress, /api/scan/start, /api/scan/cancel ────────────────────────────

func TestApiScanProgress_InitialState_Idle(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiScanProgress)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp) //nolint
	if resp["phase"] != "idle" {
		t.Errorf("ожидалась фаза idle до первого запуска обхода, получено %v", resp["phase"])
	}
}

func TestApiScanStart_Success(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiScanStart, "")
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp) //nolint
	if resp["status"] != "started" {
		t.Errorf("expected status=started, got %q", resp["status"])
	}
	// Не оставляем висящий обход после теста.
	s.eng.CancelSweep()
}

func TestApiScanCancel_WithoutRunningSweep_Idempotent(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiScanCancel, "")
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp) //nolint
	if resp["status"] != "cancelling" {
		t.Errorf("expected status=cancelling, got %q", resp["status"])
	}
}

// TestApiScanStart_SecondCallWhileRunning_Returns409 — регрессия на пример из ТЗ («POST
// /api/scan/start дважды подряд → второй раз 409»).
//
// Пул узлов у тестового движка пуст, поэтому фоновый обход (запущенный внутри StartSweep
// через goTracked → `go func(){...}()`) успевает полностью отработать и сбросить
// sweepRunning обратно в false очень быстро. Первая версия этого теста запускала N
// горутин через закрытие общего канала и НИ РАЗУ не поймала 409: горутина, порождённая
// `go f()`, попадает в "runnext"-слот своего P и в этой связке (allocate+lock+log+return —
// заведомо дешевле, чем переключение P на другую горутину из глобальной очереди) почти
// всегда успевает доработать и сбросить флаг ДО следующей уступки процессора конкурентным
// вызовом — гонка была не там, где ожидалось, и тест был не просто редко нестабилен, а
// систематически ложно-зелёным (0 из 30 попыток поймали контеншн).
//
// Надёжный способ без доступа к внутренним полям движка (sweepRunning не экспортирован) —
// не полагаться на конкуренцию РАЗНЫХ горутин вовсе, а сделать второй вызов СРАЗУ вслед за
// первым в той же самой горутине, без единой точки уступки процессора между ними (не
// вызываем ничего, что могло бы заблокироваться на канале/мьютексе с ожиданием). В Go
// горутина не уступает свой P посреди последовательности обычных вызовов без блокировки —
// поэтому спавненная первым вызовом горутина обхода физически не имеет шанса выполниться
// раньше, чем текущая горутина сделает второй вызов, и CompareAndSwap внутри StartSweep
// обязан увидеть "уже true".
func TestApiScanStart_SecondCallWhileRunning_Returns409(t *testing.T) {
	s := newTestServer(t)

	w1 := testPOST(s, s.apiScanStart, "")
	if w1.Code != 200 {
		t.Fatalf("первый вызов: expected 200, got %d (%s)", w1.Code, w1.Body.String())
	}
	w2 := testPOST(s, s.apiScanStart, "")
	if w2.Code != http.StatusConflict {
		t.Errorf("второй вызов вслед за первым: expected 409, got %d (%s)", w2.Code, w2.Body.String())
	}
	var resp map[string]string
	json.Unmarshal(w2.Body.Bytes(), &resp) //nolint
	if resp["error"] == "" {
		t.Error("409 без текста ошибки — пользователю нечего показать")
	}

	s.eng.CancelSweep()
}

// ── /api/chain-partner/connect: валидационные пути (без реального дозвона) ───────────

func TestApiConnectChainPartner_BadJSON_400(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiConnectChainPartner, "{not-json")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestApiConnectChainPartner_InvalidLink_ErrorJSON(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiConnectChainPartner, `{"link":"not-a-real-link"}`)
	if w.Code != 200 {
		t.Fatalf("expected 200 with error JSON, got %d", w.Code)
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp) //nolint
	if resp["error"] == "" {
		t.Error("ожидалась ошибка разбора ссылки")
	}
}

// Relay-ссылка (apf_relay=1) без apf_exitid обязана отвергаться ДО попытки поднять мост
// или дозвониться — это чисто структурная проверка (internal/engine/engine.go,
// AddChainPartnerFromLink).
func TestApiConnectChainPartner_RelayLink_MissingExitID_Rejected(t *testing.T) {
	s := newTestServer(t)
	link := "vless://12345678-1234-1234-1234-123456789012@1.2.3.4:443" +
		"?type=tcp&security=none&apf_relay=1#RelayTest"
	w := testPOST(s, s.apiConnectChainPartner, `{"link":"`+link+`"}`)
	if w.Code != 200 {
		t.Fatalf("expected 200 with error JSON, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "apf_exitid") {
		t.Errorf("ожидалась ошибка про отсутствующий apf_exitid, получено: %s", body)
	}
}

func TestApiConnectChainPartner_RelayLink_MissingFingerprint_Rejected(t *testing.T) {
	s := newTestServer(t)
	link := "vless://12345678-1234-1234-1234-123456789012@1.2.3.4:443" +
		"?type=tcp&security=none&apf_relay=1&apf_exitid=deadbeef#RelayTest"
	w := testPOST(s, s.apiConnectChainPartner, `{"link":"`+link+`"}`)
	if w.Code != 200 {
		t.Fatalf("expected 200 with error JSON, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "apf_relayfp") {
		t.Errorf("ожидалась ошибка про отсутствующий apf_relayfp, получено: %s", body)
	}
}

// ── /api/add-node-manual: успешный путь (ранее покрыты только GET/bad-json/invalid) ──

func TestApiAddNodeManual_Success(t *testing.T) {
	s := newTestServer(t)
	body := `{"protocol":"ss","address":"10.20.0.1","port":8388,"password":"secret","method":"aes-256-gcm","name":"ManualValid"}`
	w := httptest.NewRecorder()
	s.apiAddNodeManual(w, httptest.NewRequest(http.MethodPost, "/api/add-node-manual", strings.NewReader(body)))
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp) //nolint
	if resp["status"] != "added" || resp["node_id"] == "" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

// ── /api/server-role/*: identity — генерация, чтение, использование в build-link ─────
// Ничего из этого не запускает sing-box и не трогает файрвол (см. комментарий в шапке
// файла) — GenerateServerRoleIdentity/LoadServerRoleIdentity/BuildServerRoleLink это
// чистые операции с ключами и локальным JSON-файлом.

func TestApiServerRoleStatus_Get(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiServerRoleStatus)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestApiServerRoleIdentity_NotYetGenerated_FoundFalse(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiServerRoleIdentity)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp) //nolint
	if found, _ := resp["found"].(bool); found {
		t.Error("found должен быть false до первого generate-identity")
	}
}

func TestApiServerRoleGenerateIdentity_MethodNotAllowed(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiServerRoleGenerateIdentity)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// Round-trip: generate → identity должен появиться с found=true и совпасть с тем, что
// вернул generate.
func TestApiServerRoleGenerateIdentity_ThenIdentity_RoundTrip(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiServerRoleGenerateIdentity, "")
	if w.Code != 200 {
		t.Fatalf("generate: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var genResp struct {
		Identity singbox.ServerIdentity `json:"identity"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &genResp); err != nil {
		t.Fatalf("decode generate response: %v", err)
	}
	if genResp.Identity.UUID == "" {
		t.Fatal("generate-identity вернул пустой UUID")
	}

	w2 := testGET(s, s.apiServerRoleIdentity)
	var idResp struct {
		Found    bool                   `json:"found"`
		Identity singbox.ServerIdentity `json:"identity"`
	}
	json.Unmarshal(w2.Body.Bytes(), &idResp) //nolint
	if !idResp.Found {
		t.Error("found должен стать true после generate-identity")
	}
	if idResp.Identity.UUID != genResp.Identity.UUID {
		t.Errorf("сохранённый identity не совпадает: %q != %q", idResp.Identity.UUID, genResp.Identity.UUID)
	}
}

func TestApiServerRoleBuildLink_BadJSON_400(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiServerRoleBuildLink, "{not-json")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// Успешный путь без relay (relay_addr пустой) — чистая генерация vless://-ссылки, без
// сети и без файловых side-effect'ов сверх уже сгенерированного identity.
func TestApiServerRoleBuildLink_Success_NoRelay(t *testing.T) {
	s := newTestServer(t)
	wGen := testPOST(s, s.apiServerRoleGenerateIdentity, "")
	var genResp struct {
		Identity singbox.ServerIdentity `json:"identity"`
	}
	json.Unmarshal(wGen.Body.Bytes(), &genResp) //nolint

	idJSON, _ := json.Marshal(genResp.Identity)
	body := fmt.Sprintf(`{"identity":%s,"host":"203.0.113.5","listen_port":8443,"label":"TestLink"}`, idJSON)
	w := testPOST(s, s.apiServerRoleBuildLink, body)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp) //nolint
	if !strings.HasPrefix(resp["link"], "vless://") {
		t.Errorf("ожидалась vless://-ссылка, получено: %q", resp["link"])
	}
	if !strings.Contains(resp["link"], "203.0.113.5:8443") {
		t.Errorf("ссылка не содержит host:port: %q", resp["link"])
	}
}

// Relay-режим без обязательного отпечатка TLS-сертификата (relayFingerprint) — честная
// ошибка, а не «тихая» ссылка, по которой партнёр гарантированно не подключится
// (fail-closed, см. комментарий у BuildServerRoleLink в internal/engine/server_role.go).
func TestApiServerRoleBuildLink_RelayWithoutFingerprint_Rejected(t *testing.T) {
	s := newTestServer(t)
	wGen := testPOST(s, s.apiServerRoleGenerateIdentity, "")
	var genResp struct {
		Identity singbox.ServerIdentity `json:"identity"`
	}
	json.Unmarshal(wGen.Body.Bytes(), &genResp) //nolint

	idJSON, _ := json.Marshal(genResp.Identity)
	body := fmt.Sprintf(`{"identity":%s,"host":"ignored","listen_port":8443,"relay_addr":"198.51.100.9:9000"}`, idJSON)
	w := testPOST(s, s.apiServerRoleBuildLink, body)
	if w.Code != 200 {
		t.Fatalf("expected 200 with error JSON, got %d", w.Code)
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp) //nolint
	if resp["error"] == "" {
		t.Error("ожидалась ошибка про отсутствующий relayFingerprint")
	}
}

// apiServerRoleStart/Stop: только безопасная часть (метод не поддерживается → 405 ДО
// обращения к движку/файрволу). См. комментарий в шапке файла — почему дальше не идём.
func TestApiServerRoleStartStop_MethodNotAllowed(t *testing.T) {
	s := newTestServer(t)
	if w := testGET(s, s.apiServerRoleStart); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("start: expected 405, got %d", w.Code)
	}
	if w := testGET(s, s.apiServerRoleStop); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("stop: expected 405, got %d", w.Code)
	}
}

// ── /api/paid-providers/*: валидационные пути (без реального сетевого Fetch) ─────────

func TestApiPaidProviderAdd_BadJSON_400(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiPaidProviderAdd, "{not-json")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// Тип, требующий URL, без URL — движок обязан отказать ДО попытки подключения
// (catalog.NewPaidProvider), поэтому тест не открывает реальных соединений.
func TestApiPaidProviderAdd_MissingURL_ErrorNoNetworkCall(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiPaidProviderAdd, `{"name":"Test3xui","type":"3xui","url":""}`)
	if w.Code != 200 {
		t.Fatalf("expected 200 with error JSON, got %d", w.Code)
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp) //nolint
	if resp["error"] == "" {
		t.Error("ожидалась ошибка про отсутствующий URL")
	}
	if got := s.eng.GetPaidProviders(); len(got) != 0 {
		t.Errorf("провайдер не должен сохраниться при отказавшей проверке: %+v", got)
	}
}

func TestApiPaidProviderTest_BadJSON_400(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiPaidProviderTest, "{not-json")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestApiPaidProviderTest_MissingURL_ErrorNoNetworkCall(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiPaidProviderTest, `{"name":"TestSub","type":"subscription","url":""}`)
	if w.Code != 200 {
		t.Fatalf("expected 200 with error JSON, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp) //nolint
	if resp["error"] == "" || resp["error"] == nil {
		t.Errorf("ожидалась ошибка про отсутствующий URL, получено: %v", resp)
	}
}

func TestApiPaidProviderRemove_BadJSON_400(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiPaidProviderRemove, "{not-json")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// Удаление никогда не существовавшего провайдера: без побочных эффектов, честная ошибка.
func TestApiPaidProviderRemove_UnknownID_NotFound(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiPaidProviderRemove, `{"id":"nonexistent-provider-id"}`)
	if w.Code != 200 {
		t.Fatalf("expected 200 with error JSON, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "not found") {
		t.Errorf("ожидалась ошибка 'not found', получено: %s", body)
	}
}
