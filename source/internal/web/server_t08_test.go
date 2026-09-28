package web

import (
	"encoding/json"
	"testing"
)

// B-08.5 — /api/connect-node: негатив-контракт (плохой ID / битый JSON → 400).
func TestAPIConnectNode_BadID(t *testing.T) {
	s := newTestServer(t)

	w := testPOST(s, s.apiConnectNode, `{"node_id":"ghost"}`)
	if w.Code != 400 {
		t.Errorf("unknown node_id → 400, got %d", w.Code)
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] == "" {
		t.Error("expected error message for unknown node")
	}

	if w := testPOST(s, s.apiConnectNode, `{"node_id":""}`); w.Code != 400 {
		t.Errorf("empty node_id → 400, got %d", w.Code)
	}
	if w := testPOST(s, s.apiConnectNode, `{bad`); w.Code != 400 {
		t.Errorf("bad json → 400, got %d", w.Code)
	}
}

// B-08.5 — /api/pin: закрепить и снять. ТЗ v1.3 F2: закрепление с валидацией — неизвестный
// ID → 400 без побочных эффектов (раньше любой строкой можно было «закрепить» несуществующий
// узел, и авто-выбор молча его игнорировал).
func TestAPIPin_SetAndClear(t *testing.T) {
	s := newTestServer(t)

	w := testPOST(s, s.apiPin, `{"node_id":"ghost","pinned":true}`)
	if w.Code != 400 {
		t.Errorf("pin unknown → 400, got %d", w.Code)
	}
	if s.eng.PinnedNodeID() != "" {
		t.Errorf("unknown pin must not stick, got %q", s.eng.PinnedNodeID())
	}

	if err := s.eng.AddNodeFromLink("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@10.0.0.1:8388#abc"); err != nil {
		t.Fatalf("add node: %v", err)
	}
	nodes := s.eng.GetNodes()
	if len(nodes) == 0 {
		t.Fatal("node was not added")
	}
	id := nodes[0].ID

	w = testPOST(s, s.apiPin, `{"node_id":"`+id+`","pinned":true}`)
	if w.Code != 200 {
		t.Errorf("pin → 200, got %d (%s)", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["pinned_node_id"] != id {
		t.Errorf("expected pinned_node_id=%s, got %q", id, resp["pinned_node_id"])
	}

	// GET /api/pinned-node отдаёт и статус (F2 I3).
	w = testGET(s, s.apiPinnedNode)
	resp = map[string]string{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["pinned_node_id"] != id || resp["pinned_status"] == "" {
		t.Errorf("pinned-node: %v", resp)
	}

	w = testPOST(s, s.apiPin, `{"pinned":false}`)
	resp = map[string]string{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["pinned_node_id"] != "" {
		t.Errorf("expected pin cleared, got %q", resp["pinned_node_id"])
	}
}

// ТЗ v1.3 F2 — /api/favorite, /api/favorites, /api/connect-once.
func TestAPIFavoriteAndConnectOnce(t *testing.T) {
	s := newTestServer(t)

	if w := testPOST(s, s.apiFavorite, `{"node_id":"ghost","favorite":true}`); w.Code != 400 {
		t.Errorf("favorite unknown → 400, got %d", w.Code)
	}
	if w := testPOST(s, s.apiConnectOnce, `{"node_id":"ghost"}`); w.Code != 400 {
		t.Errorf("connect-once unknown → 400, got %d", w.Code)
	}
	w := testGET(s, s.apiFavorites)
	var list struct {
		FavoriteIDs []string `json:"favorite_ids"`
	}
	json.Unmarshal(w.Body.Bytes(), &list)
	if list.FavoriteIDs == nil || len(list.FavoriteIDs) != 0 {
		t.Errorf("favorites must be an empty array, got %s", w.Body.String())
	}

	if err := s.eng.AddNodeFromLink("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@10.0.0.2:8388#fav"); err != nil {
		t.Fatalf("add node: %v", err)
	}
	id := s.eng.GetNodes()[0].ID
	if w := testPOST(s, s.apiFavorite, `{"node_id":"`+id+`","favorite":true}`); w.Code != 200 {
		t.Errorf("favorite → 200, got %d (%s)", w.Code, w.Body.String())
	}
	w = testGET(s, s.apiFavorites)
	json.Unmarshal(w.Body.Bytes(), &list)
	if len(list.FavoriteIDs) != 1 || list.FavoriteIDs[0] != id {
		t.Errorf("favorites after add: %v", list.FavoriteIDs)
	}
	if w := testPOST(s, s.apiFavorite, `{"node_id":"`+id+`","favorite":false}`); w.Code != 200 {
		t.Errorf("unfavorite → 200, got %d", w.Code)
	}
	if got := s.eng.FavoriteIDs(); len(got) != 0 {
		t.Errorf("favorites after remove: %v", got)
	}
}
