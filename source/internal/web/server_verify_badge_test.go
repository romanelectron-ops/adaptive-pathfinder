// server_verify_badge_test.go — LOT-05 (2026-09-06): Web UI обязан показывать честное
// состояние проверки канала (verify_state) вместо безусловного зелёного «Подключено» по
// connected, и значок проверенности трафиком (verify_badge) возле каждого узла.
//
// Значок вычисляется на сервере ОДНИМ методом — models.Node.VerifyBadge — общим для всех
// трёх UI (Web/Wails/Android), см. комментарий у VerifyBadge в internal/models/node.go.
// attachVerifyBadges (server.go) — единственное место в этом пакете, где значок считается;
// тесты ниже гоняют его напрямую на всех шести состояниях, БЕЗ обращения к движку: у
// AddNodeManual/AddNodeFromLink есть фоновая горутина TCP-проверки (checker.CheckOne), которая
// гоняется за полями, выставленными тестом до вставки узла в пул, и делает результат
// недетерминированным под -race. Для узлов, добавленных через движок, тест ниже проверяет
// только форму ответа (ключ verify_badge есть и содержит одну из шести известных констант),
// а не конкретное значение.
package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ── attachVerifyBadges: все шесть состояний, зеркало internal/models/verify_badge_test.go ──

func TestAttachVerifyBadges_AllSixStates(t *testing.T) {
	now := time.Now().Unix()
	hour := int64(3600)

	cases := []struct {
		name string
		node *models.Node
		want string
	}{
		{"нулевой узел — не проверен", &models.Node{}, models.BadgeUnchecked},
		{
			"подтверждён час назад — свежий",
			&models.Node{Status: models.StatusOK, VerifiedCount: 1, LastVerifiedAt: now - hour},
			models.BadgeProvenFresh,
		},
		{
			"подтверждён 3 суток назад — давний",
			&models.Node{Status: models.StatusOK, VerifiedCount: 1, LastVerifiedAt: now - 72*hour},
			models.BadgeProvenStale,
		},
		{
			"подтверждался, но последний исход — сбой",
			&models.Node{Status: models.StatusOK, VerifiedCount: 1, LastVerifiedAt: now - hour, LastFailedAt: now - 60},
			models.BadgeProvenFailed,
		},
		{
			"TCP отвечает, трафик не проверялся",
			&models.Node{Status: models.StatusOK, LastChecked: time.Now()},
			models.BadgeTCPAlive,
		},
		{
			"проверялся и не отвечает — мёртв",
			&models.Node{Status: models.StatusBlocked, LastChecked: time.Now()},
			models.BadgeDead,
		},
	}

	nodes := make([]*models.Node, len(cases))
	for i, c := range cases {
		nodes[i] = c.node
	}

	got := attachVerifyBadges(nodes, now)
	if len(got) != len(cases) {
		t.Fatalf("attachVerifyBadges вернул %d элементов, ожидалось %d", len(got), len(cases))
	}
	for i, c := range cases {
		if got[i].Badge != c.want {
			t.Errorf("%s: verify_badge = %q, ожидалось %q", c.name, got[i].Badge, c.want)
		}
		// Значок обязан совпадать с прямым вызовом метода — attachVerifyBadges не имеет
		// права пересчитывать логику по-своему, только звать VerifyBadge.
		if want := c.node.VerifyBadge(now); got[i].Badge != want {
			t.Errorf("%s: attachVerifyBadges разошёлся с VerifyBadge(): %q != %q", c.name, got[i].Badge, want)
		}
	}

	// Все шесть констант из контракта должны быть охвачены явно хотя бы одним кейсом выше.
	allBadges := []string{
		models.BadgeProvenFresh, models.BadgeProvenStale, models.BadgeProvenFailed,
		models.BadgeTCPAlive, models.BadgeDead, models.BadgeUnchecked,
	}
	seen := make(map[string]bool, len(allBadges))
	for _, g := range got {
		seen[g.Badge] = true
	}
	for _, b := range allBadges {
		if !seen[b] {
			t.Errorf("состояние значка %q не покрыто тестовыми кейсами", b)
		}
	}
}

// JSON-сериализация обёртки не должна терять поля исходного узла (embedding *models.Node)
// и обязана добавлять verify_badge отдельным ключом — форма ответа {nodes,total} не меняется,
// её проверяют уже существующие TestApiNodes_ResponseShape и TestApiNodes_ViewFavorites_*.
func TestAttachVerifyBadges_JSONHasOriginalFieldsPlusBadge(t *testing.T) {
	n := &models.Node{ID: "n1", Name: "TestNode", Protocol: models.ProtoVLESS, Status: models.StatusOK, LastChecked: time.Now()}
	out := attachVerifyBadges([]*models.Node{n}, time.Now().Unix())

	b, err := json.Marshal(out[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["id"] != "n1" {
		t.Errorf("id потерян при обёртке: %+v", m)
	}
	if m["name"] != "TestNode" {
		t.Errorf("name потерян при обёртке: %+v", m)
	}
	got, ok := m["verify_badge"]
	if !ok {
		t.Fatal("verify_badge отсутствует в JSON")
	}
	if got != models.BadgeTCPAlive {
		t.Errorf("verify_badge = %v, ожидалось %q", got, models.BadgeTCPAlive)
	}
}

// ── /api/nodes: значок реально доезжает через HTTP-ответ ────────────────────────────────

// Значение verify_badge для узла, добавленного через живой путь AddNodeFromLink, недетерминировано
// (фоновая TCP-проверка может успеть отработать до ответа сервера) — поэтому здесь проверяется
// только форма: ключ есть, и он — одна из шести известных констант, а не что-то придуманное на JS.
func TestApiNodes_IncludesVerifyBadgeField(t *testing.T) {
	s := newTestServer(t)
	addTestNode(t, s, "10.20.0.1", "badge1")

	w := httptest.NewRecorder()
	s.apiNodes(w, httptest.NewRequest(http.MethodGet, "/api/nodes", nil))
	if w.Code != 200 {
		t.Fatalf("apiNodes status %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Nodes []map[string]interface{} `json:"nodes"`
		Total int                      `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if len(resp.Nodes) == 0 {
		t.Fatal("ожидался хотя бы один узел в ответе")
	}

	valid := map[string]bool{
		models.BadgeProvenFresh: true, models.BadgeProvenStale: true, models.BadgeProvenFailed: true,
		models.BadgeTCPAlive: true, models.BadgeDead: true, models.BadgeUnchecked: true,
	}
	for _, n := range resp.Nodes {
		badge, ok := n["verify_badge"]
		if !ok {
			t.Fatalf("узел без verify_badge: %+v", n)
		}
		s, ok := badge.(string)
		if !ok || !valid[s] {
			t.Errorf("verify_badge = %v — не одна из шести известных констант", badge)
		}
	}
}

// ── /api/state: verified остаётся, verify_state не ломает форму ответа ──────────────────

// Verified — bool без omitempty, обязан присутствовать всегда. VerifyState — omitempty,
// заполняется движком (LOT-04, параллельный лот); пока он пуст, ключ в JSON отсутствует —
// это ожидаемая деградация, ради которой JS в webUI умеет достраивать состояние сам
// (см. TestWebUI_VerifyStateTable_HasAllFourStates и refresh() в встроенном скрипте).
func TestApiState_StillReturnsVerified(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiState)
	if w.Code != 200 {
		t.Fatalf("apiState status %d: %s", w.Code, w.Body.String())
	}
	var m map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if _, ok := m["connected"]; !ok {
		t.Error("apiState: ожидался ключ connected")
	}
	if _, ok := m["verified"]; !ok {
		t.Error("apiState: ожидался ключ verified (без omitempty, обязан быть всегда)")
	}
	// verify_state — omitempty, допустимо отсутствие. Если присутствует — обязан быть одной
	// из четырёх известных констант.
	if vs, ok := m["verify_state"]; ok {
		known := map[string]bool{
			models.VerifyIdle: true, models.VerifyChecking: true,
			models.VerifyVerified: true, models.VerifyFailed: true,
		}
		if s, ok := vs.(string); !ok || !known[s] {
			t.Errorf("verify_state = %v — не одна из четырёх известных констант", vs)
		}
	}
}

// ── встроенный JS: таблицы соответствий не забыли ни одного состояния ───────────────────

// Простой поиск по строке webUI: если когда-нибудь добавится седьмой значок или пятое
// состояние проверки канала в models/node.go, а сюда никто не допишет — тест покраснеет
// раньше, чем пользователь увидит пустую иконку.
func TestWebUI_VerifyBadgeTable_HasAllSixStates(t *testing.T) {
	badges := []string{
		models.BadgeProvenFresh, models.BadgeProvenStale, models.BadgeProvenFailed,
		models.BadgeTCPAlive, models.BadgeDead, models.BadgeUnchecked,
	}
	for _, b := range badges {
		if !strings.Contains(webUI, b) {
			t.Errorf("webUI: значок %q не найден во встроенном JS (таблица VERIFY_BADGE_UI)", b)
		}
	}
	// Жёлтое состояние обязано быть подписано как «не проверялось», а не «нет трафика» —
	// ключевой смысловой инвариант лота (см. бриф LOT-05).
	if !strings.Contains(webUI, "трафик не проверялся") {
		t.Error("webUI: подпись tcp_alive должна честно говорить «трафик не проверялся», а не «нет трафика»")
	}
	if strings.Contains(webUI, "нет трафика") {
		t.Error("webUI: запрещённая формулировка «нет трафика» найдена — путает tcp_alive с dead")
	}
}

func TestWebUI_VerifyStateTable_HasAllFourStates(t *testing.T) {
	texts := []string{
		"Отключено",
		"Проверяю канал…",
		"Подключено",
		"Туннель поднят, но трафик не идёт",
	}
	for _, txt := range texts {
		if !strings.Contains(webUI, txt) {
			t.Errorf("webUI: текст состояния %q не найден во встроенном JS (таблица VERIFY_STATE_UI)", txt)
		}
	}
	for _, c := range []string{models.VerifyIdle, models.VerifyChecking, models.VerifyVerified, models.VerifyFailed} {
		if !strings.Contains(webUI, c+":") {
			t.Errorf("webUI: константа состояния %q не найдена как ключ таблицы VERIFY_STATE_UI", c)
		}
	}
}

// Новые вставки узловых/пользовательских строк в HTML обязаны идти через esc() (P0-3, XSS).
// Явная защита от регрессии: имя узла и user_note должны попадать в разметку исключительно
// через esc(...), не голым +n.name+ / +n.user_note+.
func TestWebUI_RenderNodes_UsesEscForUserStrings(t *testing.T) {
	if !strings.Contains(webUI, "esc(n.name)") {
		t.Error("webUI: n.name должен вставляться в HTML через esc()")
	}
	if !strings.Contains(webUI, "esc(n.user_note)") {
		t.Error("webUI: n.user_note должен вставляться в HTML через esc()")
	}
}
