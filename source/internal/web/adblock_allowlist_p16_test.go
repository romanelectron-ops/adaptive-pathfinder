package web

import (
	"encoding/json"
	"testing"
)

// P1-6 (аудит 2026-09-01): эндпоинт обязан отличать принятый домен от отброшенного.
// Раньше ответ был "status":"ok" в обоих случаях, и UI рапортовал успех на вводе, который
// движок молча выбросил.

func decodeAllowlistResp(t *testing.T, raw []byte) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("ответ не JSON: %v (тело: %s)", err, raw)
	}
	return m
}

func TestAdBlockAllowlist_ValidDomain_OK(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiAdBlockAllowlist, `{"domain":"example.com","add":true}`)
	if w.Code != 200 {
		t.Fatalf("код %d, ожидалось 200 (тело: %s)", w.Code, w.Body.String())
	}
	if got := decodeAllowlistResp(t, w.Body.Bytes())["status"]; got != "ok" {
		t.Errorf("status = %v, ожидалось \"ok\"", got)
	}
}

// Ввод, который движок не может принять как домен. Самый частый в жизни случай — человек
// копирует адрес из адресной строки браузера целиком.
func TestAdBlockAllowlist_NotADomain_Rejected(t *testing.T) {
	for _, bad := range []string{"localhost", "*.ads.com", "не домен"} {
		s := newTestServer(t)
		w := testPOST(s, s.apiAdBlockAllowlist, `{"domain":`+jsonStr(bad)+`,"add":true}`)
		if w.Code != 400 {
			t.Errorf("domain=%q: код %d, ожидалось 400 (тело: %s)", bad, w.Code, w.Body.String())
			continue
		}
		m := decodeAllowlistResp(t, w.Body.Bytes())
		if m["status"] != "error" {
			t.Errorf("domain=%q: status = %v, ожидалось \"error\"", bad, m["status"])
		}
		if msg, _ := m["error"].(string); msg == "" {
			t.Errorf("domain=%q: пустое поле error — пользователю нечего показать", bad)
		}
	}
}

// Повторное добавление того же домена — тоже «ничего не изменилось». Тихий 200 здесь
// означал бы, что UI очистит поле ввода и покажет успех на пустом действии.
func TestAdBlockAllowlist_DuplicateAdd_Rejected(t *testing.T) {
	s := newTestServer(t)
	if w := testPOST(s, s.apiAdBlockAllowlist, `{"domain":"dup.com","add":true}`); w.Code != 200 {
		t.Fatalf("первое добавление: код %d", w.Code)
	}
	w := testPOST(s, s.apiAdBlockAllowlist, `{"domain":"dup.com","add":true}`)
	if w.Code != 400 {
		t.Fatalf("повторное добавление: код %d, ожидалось 400 (тело: %s)", w.Code, w.Body.String())
	}
}

// Удаление домена, которого в списке нет.
func TestAdBlockAllowlist_RemoveAbsent_Rejected(t *testing.T) {
	s := newTestServer(t)
	w := testPOST(s, s.apiAdBlockAllowlist, `{"domain":"absent.com","add":false}`)
	if w.Code != 400 {
		t.Fatalf("код %d, ожидалось 400 (тело: %s)", w.Code, w.Body.String())
	}
}

// Успешно добавленный домен обязан быть виден в статусе — иначе UI не сможет его отрисовать.
func TestAdBlockAllowlist_AppearsInStatus(t *testing.T) {
	s := newTestServer(t)
	if w := testPOST(s, s.apiAdBlockAllowlist, `{"domain":"Visible.COM","add":true}`); w.Code != 200 {
		t.Fatalf("код %d (тело: %s)", w.Code, w.Body.String())
	}
	list, _ := s.eng.GetAdBlockStatus()["allowlist"].([]string)
	found := false
	for _, d := range list {
		if d == "visible.com" { // нормализованный вид, не тот, что ввёл пользователь
			found = true
		}
	}
	if !found {
		t.Errorf("allowlist = %v, ожидался нормализованный \"visible.com\"", list)
	}
}

func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
