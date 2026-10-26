package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/parser"
)

// Лоты L1 и L2 на уровне движка. Данные синтетические (RFC 5737, выдуманные UUID и ключи).

const l12PBK = "SYNTHETICPUBLICKEYSYNTHETICPUBLICKEY000"

func l12Link(host string, fp, typ string) string {
	return fmt.Sprintf("vless://00000000-0000-4000-8000-0000000000aa@%s:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=example.org&fp=%s&pbk=%s&sid=ab12&type=%s#n", host, fp, l12PBK, typ)
}

func l12Parse(t *testing.T, lines ...string) []*models.Node {
	t.Helper()
	nodes, err := parser.ParseSubscription([]byte(strings.Join(lines, "\n")))
	if err != nil || len(nodes) != len(lines) {
		t.Fatalf("разобрано %d из %d строк, err=%v", len(nodes), len(lines), err)
	}
	return nodes
}

// l12LogCapture собирает строки журнала движка.
type l12LogCapture struct {
	mu    sync.Mutex
	lines []string
}

func (c *l12LogCapture) add(s string) { c.mu.Lock(); c.lines = append(c.lines, s); c.mu.Unlock() }
func (c *l12LogCapture) has(sub string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, l := range c.lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

func newL12Engine(t *testing.T) (*Engine, *l12LogCapture) {
	t.Helper()
	e, _ := newL5Engine(t, nil)
	lc := &l12LogCapture{}
	e.OnLog = lc.add
	e.mu.Lock()
	e.nodes = nil
	e.mu.Unlock()
	return e, lc
}

// Критерий приёмки L2 на уровне пула: 11 серверов x 5 fp = 55 строк -> 11 узлов, у каждого 5 отпечатков;
// ссылки с type=raw принимаются (L1), xhttp/kcp отсеиваются с названием причины в журнале.
func TestL12_FiftyFiveLinesGiveElevenPoolNodes(t *testing.T) {
	e, lc := newL12Engine(t)
	var lines []string
	for s := 1; s <= 11; s++ {
		for _, fp := range []string{"chrome", "firefox", "safari", "ios", "android"} {
			lines = append(lines, l12Link(fmt.Sprintf("192.0.2.%d", s), fp, "raw"))
		}
	}
	for i := 0; i < 3; i++ {
		lines = append(lines, l12Link(fmt.Sprintf("198.51.100.%d", i+1), "chrome", "xhttp"))
	}
	for i := 0; i < 2; i++ {
		lines = append(lines, l12Link(fmt.Sprintf("198.51.100.%d", i+10), "chrome", "kcp"))
	}

	added := e.mergeFetchedNodes(l12Parse(t, lines...), "Тест")
	if added != 11 {
		t.Fatalf("добавлено %d узлов, ожидалось 11", added)
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.nodes) != 11 {
		t.Fatalf("в пуле %d узлов, ожидалось 11", len(e.nodes))
	}
	for _, n := range e.nodes {
		if len(n.FPCandidates) != 5 {
			t.Errorf("%s: отпечатков %d, ожидалось 5 (%v)", n.Address, len(n.FPCandidates), n.FPCandidates)
		}
	}
	if !lc.has("XHTTP: 3, mKCP: 2") {
		t.Errorf("в журнале нет причины отсева транспортов; журнал: %v", lc.lines)
	}
	if !lc.has("ещё варианты отпечатка") {
		t.Errorf("в журнале нет записи о схлопнутых вариантах fp; журнал: %v", lc.lines)
	}
}

// Повторная выдача с новым вариантом fp того же сервера не плодит узел, а дописывает запасной.
func TestL2_NewFingerprintVariantExtendsExistingNode(t *testing.T) {
	e, _ := newL12Engine(t)
	e.mergeFetchedNodes(l12Parse(t, l12Link("192.0.2.1", "chrome", "tcp")), "Тест")
	added := e.mergeFetchedNodes(l12Parse(t, l12Link("192.0.2.1", "edge", "tcp")), "Тест")
	if added != 0 {
		t.Fatalf("новый вариант fp создал узел (added=%d)", added)
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.nodes) != 1 || len(e.nodes[0].FPCandidates) != 2 || e.nodes[0].TLS.Fingerprint != "chrome" {
		t.Fatalf("ожидался один узел с основным chrome и двумя отпечатками: %+v", e.nodes[0])
	}
}

// L1: ручное добавление ссылки с неподдерживаемым транспортом даёт понятную причину.
func TestL1_AddNodeFromLinkExplainsUnsupportedTransport(t *testing.T) {
	e, _ := newL12Engine(t)
	err := e.AddNodeFromLink(l12Link("192.0.2.40", "chrome", "xhttp"))
	if err == nil || !strings.Contains(err.Error(), "not supported by this build") {
		t.Fatalf("ожидалась причина отказа, получено %v", err)
	}
	if len(e.nodes) != 0 {
		t.Error("узел с xhttp попал в пул")
	}
}

// Каталог и платные провайдеры тоже не принимают неподдерживаемый транспорт (раньше - без проверки).
func TestL1_AbsorbRejectsUnsupportedTransport(t *testing.T) {
	e, _ := newL12Engine(t)
	n := l12Parse(t, l12Link("192.0.2.41", "chrome", "xhttp"))[0]
	e.mu.Lock()
	res := e.absorbNodeLocked(e.nodesByIDLocked(), n)
	e.mu.Unlock()
	if res != absorbUnsupported {
		t.Fatalf("absorbNodeLocked = %v, ожидалось absorbUnsupported", res)
	}
}

// writeLegacyCache пишет nodes_cache.json так, как его писала сборка до лота L2: ID со старой схемой.
func writeLegacyCache(t *testing.T, nodes []*models.Node) {
	t.Helper()
	path := filepath.Join(config.DataDir(), "nodes_cache.json")
	data, err := json.Marshal(nodes)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
}

// Миграция старого кэша: три записи одного сервера (старые ID, разные fp) схлопываются в один узел,
// история не теряется (макс. подтверждений, бан по ИЛИ, заметка), отпечатки собираются в список.
func TestL2_LoadNodesMigratesLegacyIDsAndKeepsHistory(t *testing.T) {
	e, _ := newL12Engine(t)
	variants := l12Parse(t,
		l12Link("192.0.2.50", "chrome", "tcp"), l12Link("192.0.2.50", "firefox", "tcp"), l12Link("192.0.2.50", "safari", "tcp"))
	for _, n := range variants {
		n.ID = parser.LegacyNodeID(n) // как в кэше старой сборки
		n.FPCandidates = nil
	}
	variants[0].VerifiedCount = 2
	variants[1].UserBanned = true
	variants[1].UserNote = "моя заметка"
	variants[2].VerifiedCount = 5
	variants[2].LastVerifiedAt = time.Now().Unix()
	if variants[0].ID == variants[1].ID {
		t.Fatal("старая схема должна была различать варианты fp")
	}
	writeLegacyCache(t, variants)

	if err := e.loadNodes(); err != nil {
		t.Fatalf("loadNodes: %v", err)
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.nodes) != 1 {
		t.Fatalf("после миграции %d узлов, ожидался 1", len(e.nodes))
	}
	n := e.nodes[0]
	if n.ID != parser.GenerateNodeID(n) || n.ID == variants[0].ID {
		t.Errorf("ID не пересчитан по новой схеме: %s", n.ID)
	}
	if n.VerifiedCount != 5 || !n.UserBanned || n.UserNote != "моя заметка" {
		t.Errorf("история потеряна: verified=%d banned=%v note=%q", n.VerifiedCount, n.UserBanned, n.UserNote)
	}
	if len(n.FPCandidates) != 3 {
		t.Errorf("отпечатков %d, ожидалось 3: %v", len(n.FPCandidates), n.FPCandidates)
	}
}

// Закреплённый узел и избранное, сохранённые под СТАРЫМ ID, находят узел по адресу и получают новый ID.
func TestL2_PinAndFavoritesSurviveIDMigration(t *testing.T) {
	e, _ := newL12Engine(t)
	n := l12Parse(t, l12Link("192.0.2.51", "chrome", "tcp"))[0]
	legacy := parser.LegacyNodeID(n)
	ref := models.NodeRef{ID: legacy, Address: n.Address, Port: n.Port, Protocol: n.Protocol, Name: "n"}

	n.ID = legacy
	n.FPCandidates = nil
	writeLegacyCache(t, []*models.Node{n})
	if err := e.loadNodes(); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	e.cfg.PinnedNode = &ref
	e.cfg.Favorites = []models.NodeRef{ref}
	e.mu.Unlock()
	e.restorePinAndFavorites()

	newID := e.nodes[0].ID
	if newID == legacy {
		t.Fatal("ID узла не изменился - тест ничего не проверяет")
	}
	if got := e.PinnedNodeID(); got != newID {
		t.Errorf("закреплённый узел указывает на %q, ожидался новый ID %q", got, newID)
	}
	if !e.IsFavorite(newID) || e.IsFavorite(legacy) {
		t.Errorf("избранное не переехало на новый ID (new=%v old=%v)", e.IsFavorite(newID), e.IsFavorite(legacy))
	}
}

// Удалённый пользователем узел не возвращается: ни под старым ID, ни через другой вариант fp.
func TestL2_TombstoneOfLegacyIDBlocksAllFingerprintVariants(t *testing.T) {
	e, _ := newL12Engine(t)
	chrome := l12Parse(t, l12Link("192.0.2.52", "chrome", "tcp"))[0]
	e.tombs.add(parser.LegacyNodeID(chrome)) // надгробие, поставленное старой сборкой

	added := e.mergeFetchedNodes(l12Parse(t,
		l12Link("192.0.2.52", "firefox", "tcp"), l12Link("192.0.2.52", "chrome", "tcp"), l12Link("192.0.2.52", "safari", "tcp")), "Тест")
	if added != 0 {
		t.Fatalf("удалённый пользователем сервер вернулся (added=%d)", added)
	}
	if !e.tombs.has(chrome.ID) {
		t.Error("надгробие не повышено до нового ID - сервер вернётся при следующем обновлении")
	}
}

// Удаление под новым ID блокирует сервер целиком (все варианты fp - один ID).
func TestL2_TombstoneOfNewIDBlocksServer(t *testing.T) {
	e, _ := newL12Engine(t)
	chrome := l12Parse(t, l12Link("192.0.2.53", "chrome", "tcp"))[0]
	e.tombs.add(chrome.ID)
	added := e.mergeFetchedNodes(l12Parse(t,
		l12Link("192.0.2.53", "firefox", "tcp"), l12Link("192.0.2.53", "ios", "tcp")), "Тест")
	if added != 0 {
		t.Fatalf("сервер вернулся через другой вариант fp (added=%d)", added)
	}
}
