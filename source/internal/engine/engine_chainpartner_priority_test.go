package engine

// engine_chainpartner_priority_test.go — §3 (плавающий приоритет) и §4 (изоляция партнёра
// цепочки Вход-Выход от публичного пула), docs/PLAN_2026-08-28_stubs_and_realfunc.md.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── §4: getActiveCandidates исключает партнёров цепочки ─────────────────────

func TestGetActiveCandidates_ExcludesChainPartner(t *testing.T) {
	e := newTestEngine()
	e.mu.Lock()
	e.nodes = []*models.Node{
		{ID: "pub-1", Name: "Public1", Score: 0.9},
		{ID: "partner-1", Name: "Partner1", Score: 0.95, IsChainPartner: true},
		{ID: "pub-2", Name: "Public2", Score: 0.5},
	}
	e.mu.Unlock()

	cands := e.getActiveCandidates(0)
	for _, n := range cands {
		if n.IsChainPartner {
			t.Fatalf("getActiveCandidates вернул партнёра цепочки %s — должен быть исключён", n.Name)
		}
	}
	if len(cands) != 2 {
		t.Fatalf("ожидалось 2 публичных узла (партнёр исключён), получено %d", len(cands))
	}
}

// ─── §4: emergencySwitch на партнёре цепочки не уходит в публичный пул ───────

func TestEmergencySwitch_ChainPartner_RetriesSameNode_NotPublicPool(t *testing.T) {
	e := newTestEngine()
	e.cfg.SwitchOnlyOnFail = false

	partner := &models.Node{ID: "partner-1", Name: "МойПартнёр", Address: "203.0.113.9", Port: 1234, IsChainPartner: true}
	e.mu.Lock()
	e.nodes = []*models.Node{
		partner,
		{ID: "pub-1", Name: "PublicHighScore", Address: "203.0.113.1", Port: 443, Score: 0.99},
	}
	e.mu.Unlock()

	e.stateMu.Lock()
	e.state.Since = time.Now().Add(-2 * time.Hour)
	e.state.ActiveNode = partner
	e.stateMu.Unlock()

	var logMu sync.Mutex
	var lines []string
	e.OnLog = func(msg string) {
		logMu.Lock()
		lines = append(lines, msg)
		logMu.Unlock()
	}

	// Короткий ctx — connectNode неизбежно провалится (нет реального sing-box в тест-среде),
	// нас интересует не успех подключения, а КУДА движок попытался подключиться.
	e.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	e.ctx = ctx
	e.cancel = cancel
	defer cancel()

	e.emergencySwitch()

	logMu.Lock()
	defer logMu.Unlock()
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "МойПартнёр") {
		t.Fatalf("emergencySwitch не упомянул партнёра в логе — похоже, пошёл другим путём. Лог:\n%s", joined)
	}
	if strings.Contains(joined, "PublicHighScore") {
		t.Fatalf("emergencySwitch тронул публичный узел вместо повтора на партнёре. Лог:\n%s", joined)
	}
	if strings.Contains(joined, "Switching to:") {
		t.Fatalf("emergencySwitch пошёл путём обычной подмены (Switching to:), а не веткой партнёра цепочки. Лог:\n%s", joined)
	}
}

// ─── §3: tryPreferredNodesFirst — граничные случаи без сети ──────────────────

func TestTryLastActiveNodeFirst_EmptyLastActiveID_ReturnsNil(t *testing.T) {
	e := newTestEngine()
	e.mu.Lock()
	e.cfg.LastActiveNodeID = ""
	e.nodes = []*models.Node{{ID: "n1", Name: "N1"}}
	e.mu.Unlock()

	if got := e.tryPreferredNodesFirst(); got != nil {
		t.Fatalf("ожидался nil при пустом LastActiveNodeID, получено %v", got)
	}
}

func TestTryLastActiveNodeFirst_UnknownID_ReturnsNil(t *testing.T) {
	e := newTestEngine()
	e.mu.Lock()
	e.cfg.LastActiveNodeID = "does-not-exist"
	e.nodes = []*models.Node{{ID: "n1", Name: "N1"}}
	e.mu.Unlock()

	if got := e.tryPreferredNodesFirst(); got != nil {
		t.Fatalf("ожидался nil для неизвестного LastActiveNodeID, получено %v", got)
	}
}

func TestTryLastActiveNodeFirst_SkipsBlacklistedNode(t *testing.T) {
	e := newTestEngine()
	e.mu.Lock()
	e.cfg.LastActiveNodeID = "n1"
	e.nodes = []*models.Node{{ID: "n1", Name: "N1", BlacklistedUntil: time.Now().Add(time.Hour)}}
	e.mu.Unlock()

	if got := e.tryPreferredNodesFirst(); got != nil {
		t.Fatalf("ожидался nil для зачернённого узла, получено %v", got)
	}
}

func TestTryLastActiveNodeFirst_SkipsChainPartner(t *testing.T) {
	e := newTestEngine()
	e.mu.Lock()
	e.cfg.LastActiveNodeID = "n1"
	e.nodes = []*models.Node{{ID: "n1", Name: "N1", IsChainPartner: true}}
	e.mu.Unlock()

	// Партнёр цепочки не участвует в плавающем приоритете холодного старта пула — у него
	// свой отдельный путь подключения (AddChainPartnerFromLink/ConnectByID).
	if got := e.tryPreferredNodesFirst(); got != nil {
		t.Fatalf("ожидался nil для партнёра цепочки в §3-приоритете, получено %v", got)
	}
}

// ─── §3: recordLastActiveNode персистирует через saveConfig ──────────────────

func TestRecordLastActiveNode_PersistsViaSaveConfig(t *testing.T) {
	e := newTestEngine()
	var saved *models.AppConfig
	var calls int
	e.saveConfig = func(cfg *models.AppConfig) error {
		calls++
		saved = cfg
		return nil
	}

	e.recordLastActiveNode("node-xyz")

	if calls != 1 {
		t.Fatalf("ожидался 1 вызов saveConfig, получено %d", calls)
	}
	if saved == nil || saved.LastActiveNodeID != "node-xyz" {
		t.Fatalf("LastActiveNodeID не сохранён корректно: %+v", saved)
	}

	// Повторная запись ТОГО ЖЕ id не должна снова писать на диск.
	e.recordLastActiveNode("node-xyz")
	if calls != 1 {
		t.Fatalf("recordLastActiveNode вызвал saveConfig повторно для неизменившегося id (calls=%d)", calls)
	}

	e.recordLastActiveNode("node-different")
	if calls != 2 {
		t.Fatalf("ожидался повторный вызов saveConfig при смене id, calls=%d", calls)
	}
}

// ─── §4: AddChainPartnerFromLink — контракт (IsChainPartner, валидация, дедуп) ────────

func TestAddChainPartnerFromLink_InvalidLink_NoSideEffects(t *testing.T) {
	e := newTestEngine()
	e.mu.Lock()
	before := len(e.nodes)
	e.mu.Unlock()

	node, err := e.AddChainPartnerFromLink("not-a-valid-link")
	if err == nil {
		t.Fatal("ожидалась ошибка для некорректной ссылки")
	}
	if node != nil {
		t.Errorf("node должен быть nil при ошибке разбора, получено %+v", node)
	}
	e.mu.Lock()
	after := len(e.nodes)
	e.mu.Unlock()
	if after != before {
		t.Errorf("некорректная ссылка не должна менять пул узлов: было %d, стало %d", before, after)
	}
}

func TestAddChainPartnerFromLink_SetsIsChainPartner(t *testing.T) {
	e := newTestEngine()
	// Короткий ctx — connectNode неизбежно провалится (нет реального sing-box в тест-среде),
	// нас интересует только состояние пула узлов после вызова, не успех подключения.
	e.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	e.ctx = ctx
	e.cancel = cancel
	defer cancel()

	link := "vless://00000000-0000-0000-0000-0000000000cp@203.0.113.55:443?type=tcp&security=none#PartnerLink"
	node, _ := e.AddChainPartnerFromLink(link) // err ожидаема (connectNode провалится) — не проверяем

	if node == nil {
		t.Fatal("node не должен быть nil — ссылка валидна, ошибка (если есть) только от connectNode")
	}
	if !node.IsChainPartner {
		t.Error("IsChainPartner должен быть true для узла, добавленного через AddChainPartnerFromLink")
	}
	if node.Source != "chain_partner" {
		t.Errorf("Source = %q, ожидался chain_partner", node.Source)
	}

	e.mu.Lock()
	found := false
	for _, n := range e.nodes {
		if n.ID == node.ID && n.IsChainPartner {
			found = true
		}
	}
	e.mu.Unlock()
	if !found {
		t.Error("узел-партнёр не найден в пуле e.nodes с IsChainPartner=true")
	}
}

func TestRecordLastActiveNode_EmptyID_NoOp(t *testing.T) {
	e := newTestEngine()
	calls := 0
	e.saveConfig = func(cfg *models.AppConfig) error {
		calls++
		return nil
	}
	e.recordLastActiveNode("")
	if calls != 0 {
		t.Fatalf("recordLastActiveNode('') не должен писать конфиг, calls=%d", calls)
	}
}
