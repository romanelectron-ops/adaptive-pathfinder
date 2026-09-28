package engine

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// engineWithNodes собирает минимальный Engine для unit-проверки чистых ящиков
// (findNodeByID / pin-state / ConnectByID-негатив) без запуска sing-box.
func engineWithNodes(nodes ...*models.Node) *Engine {
	return &Engine{nodes: nodes, state: &models.ConnectionState{}}
}

// ─── B-08.1 findNodeByID ─────────────────────────────────────────────────────

// (1) Позитив: существующий ID + trim.
func TestFindNodeByID_Positive(t *testing.T) {
	n1 := &models.Node{ID: "a", Name: "A"}
	n2 := &models.Node{ID: "b", Name: "B"}
	e := engineWithNodes(n1, n2)

	if got, err := e.findNodeByID("b"); err != nil || got != n2 {
		t.Fatalf("expected n2, got %v err %v", got, err)
	}
	if got, err := e.findNodeByID("  a  "); err != nil || got != n1 {
		t.Fatalf("trim lookup failed: %v %v", got, err)
	}
}

// (1) Позитив-граница: при дублирующемся ID возвращается первый.
func TestFindNodeByID_FirstOnDuplicate(t *testing.T) {
	first := &models.Node{ID: "dup", Name: "first"}
	second := &models.Node{ID: "dup", Name: "second"}
	e := engineWithNodes(first, second)
	if got, _ := e.findNodeByID("dup"); got != first {
		t.Error("expected first node on duplicate id")
	}
}

// (2) Негатив: пустой/пробельный/неизвестный.
func TestFindNodeByID_Negative(t *testing.T) {
	e := engineWithNodes(&models.Node{ID: "x"})
	if _, err := e.findNodeByID(""); !errors.Is(err, ErrEmptyNodeID) {
		t.Errorf("empty id → ErrEmptyNodeID, got %v", err)
	}
	if _, err := e.findNodeByID("   "); !errors.Is(err, ErrEmptyNodeID) {
		t.Errorf("blank id → ErrEmptyNodeID, got %v", err)
	}
	_, err := e.findNodeByID("nope")
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Errorf("unknown id → error mentioning id, got %v", err)
	}
}

// (3) Fail-safe: пустой пул → ошибка, не паника.
func TestFindNodeByID_FailSafe_EmptyPool(t *testing.T) {
	e := engineWithNodes()
	if _, err := e.findNodeByID("a"); err == nil {
		t.Error("empty pool → not-found error expected")
	}
}

// (4) Стойкость: посторонние узлы не влияют на результат.
func TestFindNodeByID_Robust_NoiseIgnored(t *testing.T) {
	target := &models.Node{ID: "target", Name: "T"}
	e := engineWithNodes(
		&models.Node{ID: "noise1"}, target, &models.Node{ID: "noise2"},
	)
	if got, err := e.findNodeByID("target"); err != nil || got != target {
		t.Errorf("noise must not affect lookup, got %v err %v", got, err)
	}
}

// ─── B-08.3 pin-state ────────────────────────────────────────────────────────

func TestPinState(t *testing.T) {
	e := engineWithNodes()
	if e.IsPinned() {
		t.Error("initially must not be pinned")
	}
	e.PinNode("  n1  ")
	if !e.IsPinned() || e.PinnedNodeID() != "n1" {
		t.Errorf("PinNode trim/set failed: %q", e.PinnedNodeID())
	}
	if e.GetState().PinnedNodeID != "n1" {
		t.Error("GetState must expose pinned id")
	}
	e.UnpinNode()
	if e.IsPinned() || e.PinnedNodeID() != "" {
		t.Error("UnpinNode must clear pin")
	}
}

// ─── B-08.2 ConnectByID — негатив-контракт (нет side effects на плохом ID) ───

func TestConnectByID_Negative_NoSideEffects(t *testing.T) {
	e := engineWithNodes(&models.Node{ID: "real", Name: "Real"})

	if err := e.ConnectByID(""); !errors.Is(err, ErrEmptyNodeID) {
		t.Errorf("empty id → ErrEmptyNodeID, got %v", err)
	}
	if e.IsPinned() {
		t.Error("empty id must NOT set pin (no side effects)")
	}
	if err := e.ConnectByID("ghost"); err == nil {
		t.Error("unknown id → error expected")
	}
	if e.IsPinned() {
		t.Error("unknown id must NOT set pin (no side effects)")
	}
}

// TestConnectByID_StampsManualConnectAt — P0.2 (docs/TZ_APF_ROADMAP_v1.2.md): sticky-окно в
// emergencySwitch() читает именно это поле, стемп обязан произойти СИНХРОННО до возврата из
// ConnectByID (гонка иначе не закрывается — health-check из async connectNode может успеть
// сработать раньше, чем стемп).
func TestConnectByID_StampsManualConnectAt(t *testing.T) {
	e := New(models.DefaultConfig())
	e.mu.Lock()
	e.nodes = []*models.Node{{ID: "n1", Name: "N1", Address: "127.0.0.1", Port: 1}}
	e.mu.Unlock()

	before := time.Now()
	if err := e.ConnectByID("n1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	e.manualConnectMu.Lock()
	stamped := e.manualConnectAt
	e.manualConnectMu.Unlock()
	if stamped.Before(before) {
		t.Errorf("expected manualConnectAt stamped synchronously during ConnectByID, got %v before test start %v", stamped, before)
	}
}
