package web

// B-29: endpoint /api/add-node-manual должен существовать и проксировать в engine.AddNodeManual.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestApiAddNodeManual_MethodAndValidation(t *testing.T) {
	s := newTestServer(t)

	// GET → 405
	w := httptest.NewRecorder()
	s.apiAddNodeManual(w, httptest.NewRequest("GET", "/api/add-node-manual", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET должен давать 405, получено %d", w.Code)
	}

	// POST невалидный JSON → 400
	w = httptest.NewRecorder()
	s.apiAddNodeManual(w, httptest.NewRequest("POST", "/api/add-node-manual", strings.NewReader("{bad")))
	if w.Code != http.StatusBadRequest {
		t.Errorf("битый JSON должен давать 400, получено %d", w.Code)
	}

	// POST синтаксически валидный, но невалидный узел → error в ответе
	// (проходит через AddNodeManual → models.ValidateNode).
	w = httptest.NewRecorder()
	s.apiAddNodeManual(w, httptest.NewRequest("POST", "/api/add-node-manual", strings.NewReader(`{"protocol":"vless"}`)))
	if !strings.Contains(w.Body.String(), "error") {
		t.Errorf("невалидный узел должен возвращать error, получено %q", w.Body.String())
	}
}
