// server_node_check_test.go — ТЗ v1.5 N-3 (лот L2-WEB): HTTP-контракт «Собрать список рабочих
// узлов» (проба РЕАЛЬНОГО трафика, N-1) — POST /api/nodes/check-all|check-cancel, GET
// /api/nodes/check-status. Мирроит стиль существующих тестов Stage-1 TCP-обхода
// (server_scenarios_v3_test.go: TestApiScanStart_*/TestApiScanCancel_*/TestApiScanProgress_*),
// включая приём для 409 — см. комментарий у TestApiScanStart_SecondCallWhileRunning_Returns409
// там (полный разбор гонки): та же логика применима к engine.StartNodeCheck, потому что
// checkRunning выставляется СИНХРОННО под checkMu ДО возврата из StartNodeCheck (node_check.go) —
// второй вызов в ТОЙ ЖЕ горутине без единой точки уступки процессора между вызовами гарантированно
// застаёт "уже true", без реальной гонки разных горутин.
//
// Тестовый движок (newTestServer, cfg.Sources=nil) не подключён к сети: под `go test` боевой
// probeNodeReal короткозамкнут netguard.UnderTest() (AC-2, node_check.go) ДО сборки конфига,
// подъёма процесса или сетевого вызова, а с пустым пулом (нет источников, ни одного узла не
// добавлено) rankCandidatesForStrategy() возвращает 0 кандидатов — runNodeCheck переходит прямо в
// фазу "done" с Total=0. Тесты ниже используют именно эту безопасную, детерминированную ветку.
package web

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestApiNodeCheckStatus_InitialState_Empty(t *testing.T) {
	s := newTestServer(t)
	w := testGET(s, s.apiNodeCheckStatus)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp) //nolint
	// NodeCheckStatusSnapshot до первого запуска — нулевое значение: Phase="" (node_check.go,
	// комментарий поля: "" | "probing" | "done" | "cancelled"), Running=false.
	if resp["phase"] != "" {
		t.Errorf("ожидалась пустая фаза до первого запуска пробы, получено %v", resp["phase"])
	}
	if running, _ := resp["running"].(bool); running {
		t.Errorf("running=true до первого запуска пробы")
	}
}

func TestApiNodeCheckStart_Success(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiNodeCheckStart, "")
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp) //nolint
	if resp["status"] != "started" {
		t.Errorf("expected status=started, got %q", resp["status"])
	}
	// Не оставляем висящий прогон после теста (симметрично TestApiScanStart_Success).
	s.eng.CancelNodeCheck()
}

func TestApiNodeCheckCancel_WithoutRunningCheck_Idempotent(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiNodeCheckCancel, "")
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp) //nolint
	if resp["status"] != "cancelling" {
		t.Errorf("expected status=cancelling, got %q", resp["status"])
	}
}

// TestApiNodeCheckStart_SecondCallWhileRunning_Returns409 — регрессия-двойник
// TestApiScanStart_SecondCallWhileRunning_Returns409 (server_scenarios_v3_test.go): второй вызов
// СРАЗУ вслед за первым в ОДНОЙ горутине, без точки уступки процессора между ними — фоновая
// горутина runNodeCheck (запущена первым вызовом через e.goTracked) физически не может выполниться
// раньше второго вызова этой же горутины, поэтому e.checkRunning гарантированно "уже true".
func TestApiNodeCheckStart_SecondCallWhileRunning_Returns409(t *testing.T) {
	s := newTestServer(t)

	w1 := testPOST(s, s.apiNodeCheckStart, "")
	if w1.Code != 200 {
		t.Fatalf("первый вызов: expected 200, got %d (%s)", w1.Code, w1.Body.String())
	}
	w2 := testPOST(s, s.apiNodeCheckStart, "")
	if w2.Code != http.StatusConflict {
		t.Errorf("второй вызов вслед за первым: expected 409, got %d (%s)", w2.Code, w2.Body.String())
	}
	var resp map[string]string
	json.Unmarshal(w2.Body.Bytes(), &resp) //nolint
	if resp["error"] == "" {
		t.Error("409 без текста ошибки — пользователю нечего показать")
	}
	s.eng.CancelNodeCheck()
}

// TestApiNodeCheckStatus_ReflectsEngineProgress_EmptyPool — сквозная проверка проводки
// HTTP-эндпоинта до движка и обратно. Тестовый движок без источников имеет пустой пул, поэтому
// runNodeCheck (node_check.go) видит len(ranked)==0 и сразу переходит в терминальную фазу "done" с
// Total=0 — без единого реального сетевого вызова, TCP-соединения или подъёма sing-box. Опрос
// /api/nodes/check-status обязан рано или поздно увидеть Running=false/Phase="done" — иначе
// HTTP-обёртка расходится с движком (например, кэширует старый снимок вместо чтения текущего).
func TestApiNodeCheckStatus_ReflectsEngineProgress_EmptyPool(t *testing.T) {
	s := newTestServer(t)
	if w := testPOST(s, s.apiNodeCheckStart, ""); w.Code != 200 {
		t.Fatalf("start: expected 200, got %d (%s)", w.Code, w.Body.String())
	}

	deadline := time.Now().Add(2 * time.Second)
	var resp map[string]interface{}
	for time.Now().Before(deadline) {
		w := testGET(s, s.apiNodeCheckStatus)
		json.Unmarshal(w.Body.Bytes(), &resp) //nolint
		if running, _ := resp["running"].(bool); !running {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if running, _ := resp["running"].(bool); running {
		t.Fatalf("проба не завершилась за 2с на пустом пуле (снимок: %v)", resp)
	}
	if resp["phase"] != "done" {
		t.Errorf("ожидалась фаза done на пустом пуле, получено %v", resp["phase"])
	}
	if total, _ := resp["total"].(float64); total != 0 {
		t.Errorf("ожидался total=0 на пустом пуле, получено %v", resp["total"])
	}
}
