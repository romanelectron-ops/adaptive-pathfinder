// nodes_manage.go — ТЗ v1.3 F3 (консилиум 2026-09-03, NL-7/NL-9/NL-10, UI-A-17, NEW-2):
// управление узлами пользователем — удаление с надгробиями, бан, правка имени/заметки, сброс
// статистики, представления списка. До этого узел нельзя было ни удалить, ни исправить ни на
// одной платформе (жалоба 2026-09-02), а удалённое подписка вернула бы через час — поэтому
// надгробия (nodes_tombstones.json): updateSources/каталог пропускают удалённые ID.
package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// tombstoneCap — потолок набора надгробий: старейшие вытесняются (FIFO), файл не растёт вечно.
const tombstoneCap = 10000

// tombstoneSet — набор ID удалённых узлов. Leaf-мьютекс: берётся ПОД e.mu (mergeFetchedNodes)
// и никогда не берёт e.mu сам.
type tombstoneSet struct {
	mu    sync.Mutex
	ids   map[string]bool
	order []string
}

func tombstonesPath() string { return filepath.Join(config.DataDir(), "nodes_tombstones.json") }

func (t *tombstoneSet) has(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ids[id]
}

// add возвращает true, если ID был новым.
func (t *tombstoneSet) add(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ids == nil {
		t.ids = make(map[string]bool)
	}
	if t.ids[id] {
		return false
	}
	t.ids[id] = true
	t.order = append(t.order, id)
	for len(t.order) > tombstoneCap {
		delete(t.ids, t.order[0])
		t.order = t.order[1:]
	}
	return true
}

func (t *tombstoneSet) remove(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.ids[id] {
		return false
	}
	delete(t.ids, id)
	kept := t.order[:0]
	for _, x := range t.order {
		if x != id {
			kept = append(kept, x)
		}
	}
	t.order = kept
	return true
}

func (t *tombstoneSet) list() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.order...)
}

func (t *tombstoneSet) clear() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := len(t.order)
	t.ids = make(map[string]bool)
	t.order = nil
	return n
}

func (t *tombstoneSet) load(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var ids []string
	if json.Unmarshal(data, &ids) != nil {
		return
	}
	t.mu.Lock()
	t.ids = make(map[string]bool, len(ids))
	t.order = t.order[:0]
	for _, id := range ids {
		if id == "" || t.ids[id] {
			continue
		}
		t.ids[id] = true
		t.order = append(t.order, id)
	}
	for len(t.order) > tombstoneCap {
		delete(t.ids, t.order[0])
		t.order = t.order[1:]
	}
	t.mu.Unlock()
}

func (t *tombstoneSet) save(path string) error {
	ids := t.list()
	data, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return writeFileAtomic(path, data)
}

// ─── Engine: надгробия ────────────────────────────────────────────────────────────────────

func (e *Engine) isTombstoned(id string) bool { return e.tombs.has(id) }

func (e *Engine) loadTombstones() {
	e.tombs.load(tombstonesPath())
	if n := len(e.tombs.list()); n > 0 {
		e.log(fmt.Sprintf("Удалённых пользователем узлов (надгробий): %d — подписки их не вернут", n))
	}
}

func (e *Engine) saveTombstones() {
	if err := e.tombs.save(tombstonesPath()); err != nil {
		e.log(fmt.Sprintf("Надгробия: ошибка сохранения: %v", err))
	}
}

// clearTombstone — явное добавление узла пользователем (ссылка/ручной ввод/партнёр цепочки)
// снимает надгробие: пользователь сказал «хочу этот узел», это сильнее прошлого удаления.
func (e *Engine) clearTombstone(id string) {
	if e.tombs.remove(id) {
		e.saveTombstones()
	}
}

// RemovedNodeIDs — ID удалённых узлов (представление «removed»).
func (e *Engine) RemovedNodeIDs() []string { return e.tombs.list() }

// RestoreRemovedNodes очищает надгробия; узлы вернутся при следующем обновлении источников.
func (e *Engine) RestoreRemovedNodes() int {
	n := e.tombs.clear()
	e.saveTombstones()
	if n > 0 {
		e.log(fmt.Sprintf("Надгробия сняты (%d) — удалённые узлы вернутся при следующем обновлении источников", n))
	}
	return n
}

// mergeFetchedNodes — единственная точка добавления узлов из источников/каталога в пул:
// отсев неподдерживаемых протоколов, узлов, не проходящих ValidateNode (NL-10: Tor-заглушки и
// битые записи раньше попадали в пул и «висели» красными), удалённых пользователем (F3) и
// дубликатов ВНУТРИ одной выдачи (NL-9: раньше ids не пополнялась в цикле). Возвращает число
// добавленных.
func (e *Engine) mergeFetchedNodes(newNodes []*models.Node, source string) int {
	e.mu.Lock()
	ids := make(map[string]bool, len(e.nodes))
	for _, n := range e.nodes {
		if n != nil {
			ids[n.ID] = true
		}
	}
	added, skippedUnsupported, skippedInvalid, skippedRemoved := 0, 0, 0, 0
	for _, n := range newNodes {
		if n == nil {
			continue
		}
		if isUnsupportedProtocol(n.Protocol) {
			skippedUnsupported++
			continue
		}
		if err := models.ValidateNode(n); err != nil {
			skippedInvalid++
			continue
		}
		if e.isTombstoned(n.ID) {
			skippedRemoved++
			continue
		}
		if ids[n.ID] {
			continue
		}
		ids[n.ID] = true
		e.nodes = append(e.nodes, n)
		added++
	}
	total := len(e.nodes)
	e.mu.Unlock()

	if skippedUnsupported > 0 {
		e.log(fmt.Sprintf("%s: пропущено %d узлов WireGuard/AmneziaWG (протокол не поддерживается этой сборкой)",
			source, skippedUnsupported))
	}
	if skippedInvalid > 0 {
		e.log(fmt.Sprintf("%s: пропущено %d некорректных записей (не проходят проверку узла)", source, skippedInvalid))
	}
	if skippedRemoved > 0 {
		e.log(fmt.Sprintf("%s: пропущено %d узлов, удалённых пользователем", source, skippedRemoved))
	}
	if added > 0 {
		e.log(fmt.Sprintf("%s: +%d nodes (total %d)", source, added, total))
		e.saveNodes()
	}
	return added
}

// ─── Engine: действия пользователя над узлом ──────────────────────────────────────────────

// detachFromActive — узел перестаёт быть пригодным (удалён/забанен), а он активен: переключаемся
// (или отключаемся, если автопереключение выключено пользователем).
func (e *Engine) detachFromActive(node *models.Node, why string) {
	e.stateMu.RLock()
	active := e.state.Connected && e.state.ActiveNode != nil && e.state.ActiveNode.ID == node.ID
	e.stateMu.RUnlock()
	if !active {
		return
	}
	e.markNodeFailed(node.ID)
	if e.cfg.NodeAutoSwitchEnabled {
		e.log(fmt.Sprintf("Узел «%s» %s, он был активен — переключаюсь на другой", node.Name, why))
		e.goTracked(e.emergencySwitch)
		return
	}
	e.log(fmt.Sprintf("Узел «%s» %s, он был активен, автопереключение выключено — отключаюсь", node.Name, why))
	// НЕ goTracked: Stop() сам ждёт e.wg.Wait() — отслеживаемая горутина ждала бы саму себя
	// до wgWaitTimeout (15 с), найдено тестом TestRemoveNode_ActiveNode_SwitchesOrStops.
	go e.Stop()
}

// RemoveNode удаляет узел из пула с надгробием (подписки не вернут его), снимает его из
// pin/избранного/LastActive/гонки, останавливает мост партнёра цепочки, при активности —
// переключается. Неизвестный ID — ошибка без побочных эффектов.
func (e *Engine) RemoveNode(id string) error {
	node, err := e.findNodeByID(id)
	if err != nil {
		return err
	}
	e.mu.Lock()
	kept := e.nodes[:0:0]
	for _, n := range e.nodes {
		if n != nil && n.ID != id {
			kept = append(kept, n)
		}
	}
	e.nodes = kept
	cfgChanged := false
	if e.cfg != nil && e.cfg.LastActiveNodeID == id {
		e.cfg.LastActiveNodeID = ""
		cfgChanged = true
	}
	if e.raceNodes != nil {
		race := e.raceNodes[:0:0]
		for _, n := range e.raceNodes {
			if n != nil && n.ID != id {
				race = append(race, n)
			}
		}
		e.raceNodes = race
	}
	e.mu.Unlock()

	e.tombs.add(id)
	e.saveTombstones()
	if e.PinnedNodeID() == id {
		e.UnpinNode() // персистирует cfg (включая уже сброшенный LastActiveNodeID)
		cfgChanged = false
	}
	if e.IsFavorite(id) {
		_ = e.RemoveFavorite(id)
		cfgChanged = false
	}
	if cfgChanged && e.saveConfig != nil {
		e.mu.Lock()
		_ = e.saveConfig(e.cfg)
		e.mu.Unlock()
	}
	if node.IsChainPartner {
		e.chainBridgeMu.Lock()
		if b, ok := e.chainBridges[id]; ok {
			b.Stop()
			delete(e.chainBridges, id)
		}
		e.chainBridgeMu.Unlock()
	}
	e.saveNodes()
	e.log(fmt.Sprintf("Узел удалён пользователем: %s", node.Name))
	e.detachFromActive(node, "удалён")
	return nil
}

// BanNode ставит/снимает ручной чёрный список: забаненный узел не выбирается никогда (все
// селекторы читают UserBanned через getActiveCandidates/filterSelectable/preferredCandidates).
func (e *Engine) BanNode(id string, banned bool) error {
	node, err := e.findNodeByID(id)
	if err != nil {
		return err
	}
	e.mu.Lock()
	changed := node.UserBanned != banned
	node.UserBanned = banned
	if banned {
		node.Score = 0
	}
	e.mu.Unlock()
	if !changed {
		return nil
	}
	e.saveNodes()
	if banned {
		e.log(fmt.Sprintf("Узел забанен пользователем: %s", node.Name))
		e.detachFromActive(node, "забанен")
	} else {
		e.log(fmt.Sprintf("Бан снят: %s", node.Name))
	}
	return nil
}

// UpdateNode меняет имя и/или заметку (nil — не трогать; пустая заметка — убрать).
func (e *Engine) UpdateNode(id string, patch models.NodePatch) error {
	node, err := e.findNodeByID(id)
	if err != nil {
		return err
	}
	e.mu.Lock()
	if patch.Name != nil {
		if name := strings.TrimSpace(*patch.Name); name != "" {
			node.Name = name
		}
	}
	if patch.UserNote != nil {
		node.UserNote = strings.TrimSpace(*patch.UserNote)
	}
	e.mu.Unlock()
	e.saveNodes()
	return nil
}

// ResetNodeStats обнуляет накопленную статистику узла (TCP-метрики, сбои, чёрный список,
// историю подтверждений) — «дать узлу второй шанс с чистого листа». Бан и заметка остаются.
func (e *Engine) ResetNodeStats(id string) error {
	node, err := e.findNodeByID(id)
	if err != nil {
		return err
	}
	e.mu.Lock()
	node.Score, node.Latency, node.Jitter, node.Loss, node.Speed = 0, 0, 0, 0, 0
	node.FailCount, node.SuccessCount = 0, 0
	node.Status = models.StatusUnknown
	node.LastChecked = time.Time{}
	node.BlacklistedUntil = time.Time{}
	node.LastVerifiedAt, node.VerifiedCount, node.LastVerifiedLatencyMs = 0, 0, 0
	node.LastVerifiedCountry, node.LastVerifiedExitIP = "", ""
	node.LastFailedAt, node.LastFailReason, node.FailStreak = 0, "", 0
	e.mu.Unlock()
	e.recentFailuresMu.Lock()
	delete(e.recentFailures, id)
	e.recentFailuresMu.Unlock()
	e.saveNodes()
	e.log(fmt.Sprintf("Статистика узла сброшена: %s", node.Name))
	return nil
}

// Представления списка узлов (HTTP `?view=`, UI-вкладки).
const (
	NodeViewAll       = "all"
	NodeViewProven    = "proven"
	NodeViewManual    = "manual"
	NodeViewBanned    = "banned"
	NodeViewFavorites = "favorites"
	NodeViewRemoved   = "removed"
)

// GetNodesView — копии узлов выбранного представления (removed — см. RemovedNodeIDs).
func (e *Engine) GetNodesView(view string) []*models.Node {
	all := e.GetNodes()
	switch view {
	case NodeViewProven:
		return filterNodes(all, func(n *models.Node) bool { return n.IsProven() })
	case NodeViewManual:
		return filterNodes(all, func(n *models.Node) bool { return n.Source == "manual" })
	case NodeViewBanned:
		return filterNodes(all, func(n *models.Node) bool { return n.UserBanned })
	case NodeViewFavorites:
		return filterNodes(all, func(n *models.Node) bool { return e.IsFavorite(n.ID) })
	default:
		return all
	}
}

func filterNodes(in []*models.Node, keep func(*models.Node) bool) []*models.Node {
	out := make([]*models.Node, 0, len(in))
	for _, n := range in {
		if n != nil && keep(n) {
			out = append(out, n)
		}
	}
	return out
}
