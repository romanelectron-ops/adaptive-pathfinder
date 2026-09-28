// server_v13_f3_test.go — ТЗ v1.3 F3: HTTP-контракт управления узлами.
package web

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestAPINodeActions_BanUpdateRemoveRestore(t *testing.T) {
	s := newTestServer(t)
	if w := testPOST(s, s.apiNodeRemove, `{"node_id":"ghost"}`); w.Code != 400 {
		t.Errorf("remove unknown → 400, got %d", w.Code)
	}
	if err := s.eng.AddNodeFromLink("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@10.0.0.7:8388#f3"); err != nil {
		t.Fatal(err)
	}
	id := s.eng.GetNodes()[0].ID

	if w := testPOST(s, s.apiNodeBan, `{"node_id":"`+id+`","banned":true}`); w.Code != 200 {
		t.Errorf("ban → 200, got %d (%s)", w.Code, w.Body.String())
	}
	w := httptest.NewRecorder()
	s.apiNodes(w, httptest.NewRequest("GET", "/api/nodes?view=banned", nil))
	var list struct {
		Total int `json:"total"`
	}
	json.Unmarshal(w.Body.Bytes(), &list)
	if list.Total != 1 {
		t.Errorf("view=banned total=%d want 1", list.Total)
	}

	if w := testPOST(s, s.apiNodeUpdate, `{"node_id":"`+id+`","name":"Renamed","user_note":"note"}`); w.Code != 200 {
		t.Errorf("update → 200, got %d", w.Code)
	}
	if n := s.eng.GetNodes()[0]; n.Name != "Renamed" || n.UserNote != "note" {
		t.Errorf("update не применился: %+v", n)
	}
	if w := testPOST(s, s.apiNodeReset, `{"node_id":"`+id+`"}`); w.Code != 200 {
		t.Errorf("reset → 200, got %d", w.Code)
	}

	if w := testPOST(s, s.apiNodeRemove, `{"node_id":"`+id+`"}`); w.Code != 200 {
		t.Errorf("remove → 200, got %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.apiNodes(w, httptest.NewRequest("GET", "/api/nodes?view=removed", nil))
	var removed struct {
		RemovedIDs []string `json:"removed_ids"`
	}
	json.Unmarshal(w.Body.Bytes(), &removed)
	if len(removed.RemovedIDs) != 1 || removed.RemovedIDs[0] != id {
		t.Errorf("view=removed: %v", removed.RemovedIDs)
	}
	w = testPOST(s, s.apiNodesRestoreRemoved, `{}`)
	var rest struct {
		Restored int `json:"restored"`
	}
	json.Unmarshal(w.Body.Bytes(), &rest)
	if w.Code != 200 || rest.Restored != 1 {
		t.Errorf("restore: code=%d restored=%d", w.Code, rest.Restored)
	}
}
