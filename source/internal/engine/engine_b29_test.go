package engine

import (
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// B-29 — AddNodeManual: ручное добавление узла из редактора продвинутых полей,
// с валидацией через models.ValidateNode.

// (1) Позитив: валидный VLESS+Reality добавляется, получает ID и попадает в пул.
func TestAddNodeManual_ValidRealityNode(t *testing.T) {
	e := newTestEngine()
	before := len(e.GetNodes())
	n := &models.Node{
		Protocol: models.ProtoVLESS,
		Address:  "reality.example.com",
		Port:     443,
		UUID:     "11111111-2222-3333-4444-555555555555",
		TLS:      &models.TLSConfig{Enabled: true, Reality: &models.RealityConfig{PublicKey: "somepbk", ShortID: "0a1b"}},
	}
	if err := e.AddNodeManual(n); err != nil {
		t.Fatalf("валидный узел должен добавиться: %v", err)
	}
	if n.ID == "" {
		t.Error("ID должен быть сгенерирован")
	}
	if len(e.GetNodes()) != before+1 {
		t.Errorf("узел не попал в пул: было %d, стало %d", before, len(e.GetNodes()))
	}
}

// (2) Негатив: невалидный узел отвергается БЕЗ добавления в пул.
func TestAddNodeManual_InvalidRejected(t *testing.T) {
	e := newTestEngine()
	before := len(e.GetNodes())
	n := &models.Node{Protocol: models.ProtoVLESS, Address: "", Port: 0} // нет адреса/порта/uuid
	if err := e.AddNodeManual(n); err == nil {
		t.Fatal("невалидный узел должен быть отвергнут")
	}
	if len(e.GetNodes()) != before {
		t.Error("невалидный узел не должен попадать в пул (side-effect)")
	}
}

// (3) Дубликат: повторное добавление того же узла → ошибка.
func TestAddNodeManual_Duplicate(t *testing.T) {
	e := newTestEngine()
	mk := func() *models.Node {
		return &models.Node{
			Protocol: models.ProtoTrojan,
			Address:  "dup.example.com",
			Port:     8443,
			Password: "pw",
		}
	}
	if err := e.AddNodeManual(mk()); err != nil {
		t.Fatalf("первое добавление: %v", err)
	}
	if err := e.AddNodeManual(mk()); err == nil {
		t.Error("дубликат должен отвергаться")
	}
}
