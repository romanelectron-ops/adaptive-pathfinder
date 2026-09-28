// engine_v13_f3_test.go — ТЗ v1.3 F3: удаление с надгробиями (подписка не воскрешает, рестарт
// переживает, cap), бан исключает из всех селекторов, удаление активного переключает,
// правка/сброс статистики, дедуп и отсев внутри выдачи источника (NL-9/NL-10).
package engine

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/parser"
)

// validNode — узел, проходящий models.ValidateNode (как из подписки): ss с методом и паролем.
func validNode(t *testing.T, host, name string) *models.Node {
	t.Helper()
	n, err := parser.ParseLink(fmt.Sprintf("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@%s:8388#%s", host, name))
	if err != nil {
		t.Fatal(err)
	}
	n.Status = models.StatusOK
	n.Score = 0.5
	return n
}

func TestRemoveNode_TombstoneBlocksRefetch_SurvivesRestart_Restore(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	a, b := validNode(t, "10.0.0.1", "a"), validNode(t, "10.0.0.2", "b")
	setNodes(e, a, b)

	if err := e.RemoveNode("ghost"); err == nil {
		t.Error("неизвестный ID — ошибка")
	}
	if err := e.RemoveNode(a.ID); err != nil {
		t.Fatal(err)
	}
	if got := ids(e.GetNodes()); strings.Join(got, ",") != b.ID {
		t.Fatalf("после удаления в пуле должен остаться только b: %v", got)
	}
	// Подписка «возвращает» a вместе с новым c: a не воскресает, c добавляется, b — дубликат.
	a2 := validNode(t, "10.0.0.1", "a-again")
	c := validNode(t, "10.0.0.3", "c")
	if added := e.mergeFetchedNodes([]*models.Node{a2, b, c}, "test"); added != 1 {
		t.Errorf("добавиться должен только c: added=%d", added)
	}
	if e.findNodeByIDOK(a.ID) {
		t.Error("удалённый узел не должен возвращаться из источника (КТ-12)")
	}

	// Рестарт: новый движок читает надгробия с диска.
	e2 := newTestEngine()
	e2.loadTombstones()
	if !e2.isTombstoned(a.ID) {
		t.Error("надгробие должно пережить перезапуск")
	}
	if got := e2.RemovedNodeIDs(); len(got) != 1 || got[0] != a.ID {
		t.Errorf("RemovedNodeIDs=%v", got)
	}

	// Восстановление снимает надгробия — источник снова может вернуть узел.
	if n := e2.RestoreRemovedNodes(); n != 1 {
		t.Errorf("restored=%d want 1", n)
	}
	if e2.isTombstoned(a.ID) {
		t.Error("после восстановления надгробия быть не должно")
	}
	if added := e2.mergeFetchedNodes([]*models.Node{a2}, "test"); added != 1 {
		t.Errorf("после восстановления узел должен вернуться: added=%d", added)
	}

	// Явное добавление пользователем снимает надгробие само.
	e3 := newTestEngine()
	e3.tombs.add(a.ID)
	if err := e3.AddNodeFromLink("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@10.0.0.1:8388#manual"); err != nil {
		t.Fatal(err)
	}
	if e3.isTombstoned(a.ID) || !e3.findNodeByIDOK(a.ID) {
		t.Error("ручное добавление должно снять надгробие и вернуть узел")
	}
}

func (e *Engine) findNodeByIDOK(id string) bool { _, err := e.findNodeByID(id); return err == nil }

func TestRemoveNode_ClearsPinFavoriteLastActiveAndRace(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	a, b := validNode(t, "10.0.0.1", "a"), validNode(t, "10.0.0.2", "b")
	setNodes(e, a, b)
	if err := e.Pin(a.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.AddFavorite(a.ID); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	e.cfg.LastActiveNodeID = a.ID
	e.raceNodes = []*models.Node{a, b}
	e.mu.Unlock()

	if err := e.RemoveNode(a.ID); err != nil {
		t.Fatal(err)
	}
	if e.PinnedNodeID() != "" || len(e.FavoriteIDs()) != 0 || e.cfg.LastActiveNodeID != "" || e.cfg.PinnedNode != nil {
		t.Errorf("pin/избранное/LastActive должны очиститься: pin=%q favs=%v last=%q cfgPin=%v",
			e.PinnedNodeID(), e.FavoriteIDs(), e.cfg.LastActiveNodeID, e.cfg.PinnedNode)
	}
	if len(e.raceNodes) != 1 || e.raceNodes[0] != b {
		t.Errorf("raceNodes должен потерять удалённый: %v", ids(e.raceNodes))
	}
}

func TestRemoveNode_ActiveNode_SwitchesOrStops(t *testing.T) {
	withTempDataDir(t)
	for _, autoSwitch := range []bool{true, false} {
		e := newTestEngine()
		e.cfg.NodeAutoSwitchEnabled = autoSwitch
		logs := captureLogs(e)
		a, b := validNode(t, "10.0.0.1", "a"), validNode(t, "10.0.0.2", "b")
		setNodes(e, a, b)
		e.stateMu.Lock()
		e.state.Connected, e.state.ActiveNode = true, a
		e.stateMu.Unlock()

		if err := e.RemoveNode(a.ID); err != nil {
			t.Fatal(err)
		}
		want := "переключаюсь"
		if !autoSwitch {
			want = "отключаюсь"
		}
		if !logs.has(want) {
			t.Errorf("autoSwitch=%v: ожидался лог %q: %v", autoSwitch, want, logs.all())
		}
		if !e.isRecentlyFailed(a.ID) {
			t.Errorf("autoSwitch=%v: удалённый активный должен попасть в recentFailures", autoSwitch)
		}
		e.cancelCurrentCtx() // обрываем фоновое переключение/ре-арминг
		e.wg.Wait()
	}
}

func TestBanNode_ExcludedFromAllSelectors(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	a, b := okNode("a", 0.9), okNode("b", 0.5)
	setNodes(e, a, b)
	if err := e.AddFavorite(a.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.BanNode(a.ID, true); err != nil {
		t.Fatal(err)
	}
	if !a.UserBanned || a.Score != 0 {
		t.Errorf("бан должен выставить UserBanned и обнулить Score: %+v", *a)
	}
	e.mu.RLock()
	cands := ids(e.getActiveCandidates(0))
	e.mu.RUnlock()
	if strings.Join(cands, ",") != "b" {
		t.Errorf("getActiveCandidates: %v want [b]", cands)
	}
	if got := e.selectBestExcluding(nil); got != b {
		t.Errorf("selectBestExcluding: %v want b", got)
	}
	if got := ids(e.rankCandidatesForStrategy()); strings.Join(got, ",") != "b" {
		t.Errorf("rankCandidatesForStrategy: %v want [b]", got)
	}
	for _, c := range e.preferredCandidates() {
		if c.node == a {
			t.Error("preferredCandidates: забаненный избранный не должен предлагаться")
		}
	}
	for i := 0; i < 4; i++ {
		if n := e.selectNextCyclic(nil); n == a {
			t.Error("selectNextCyclic не должен возвращать забаненный")
		}
	}
	if got := ids(e.GetNodesView(NodeViewBanned)); strings.Join(got, ",") != "a" {
		t.Errorf("view=banned: %v", got)
	}
	if err := e.BanNode(a.ID, false); err != nil || a.UserBanned {
		t.Errorf("снятие бана: err=%v banned=%v", err, a.UserBanned)
	}
	if err := e.BanNode("ghost", true); err == nil {
		t.Error("неизвестный ID — ошибка")
	}
}

func TestUpdateNode_AndResetNodeStats(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	a := okNode("a", 0.9)
	a.Latency, a.FailStreak, a.LastFailedAt, a.VerifiedCount, a.LastVerifiedAt = 120, 3, 1, 2, 1
	a.BlacklistedUntil = time.Now().Add(time.Hour)
	setNodes(e, a)
	e.markNodeFailed(a.ID)

	name, note := "  Мой узел ", " быстрый "
	if err := e.UpdateNode(a.ID, models.NodePatch{Name: &name, UserNote: &note}); err != nil {
		t.Fatal(err)
	}
	if a.Name != "Мой узел" || a.UserNote != "быстрый" {
		t.Errorf("правка: name=%q note=%q", a.Name, a.UserNote)
	}
	empty := ""
	if err := e.UpdateNode(a.ID, models.NodePatch{Name: &empty, UserNote: &empty}); err != nil {
		t.Fatal(err)
	}
	if a.Name != "Мой узел" || a.UserNote != "" {
		t.Errorf("пустое имя — не менять, пустая заметка — убрать: name=%q note=%q", a.Name, a.UserNote)
	}
	if err := e.ResetNodeStats(a.ID); err != nil {
		t.Fatal(err)
	}
	if a.Score != 0 || a.Latency != 0 || a.FailStreak != 0 || a.VerifiedCount != 0 || !a.BlacklistedUntil.IsZero() || a.Status != models.StatusUnknown || e.isRecentlyFailed(a.ID) {
		t.Errorf("сброс статистики неполный: %+v recentlyFailed=%v", *a, e.isRecentlyFailed(a.ID))
	}
	if a.Name != "Мой узел" {
		t.Error("сброс статистики не должен трогать имя")
	}
}

func TestTombstoneSet_CapAndOrder(t *testing.T) {
	var ts tombstoneSet
	for i := 0; i < tombstoneCap+5; i++ {
		ts.add(fmt.Sprintf("id-%d", i))
	}
	if got := len(ts.list()); got != tombstoneCap {
		t.Fatalf("cap: %d want %d", got, tombstoneCap)
	}
	if ts.has("id-0") || ts.has("id-4") || !ts.has("id-5") || !ts.has(fmt.Sprintf("id-%d", tombstoneCap+4)) {
		t.Error("вытесняться должны старейшие")
	}
	if ts.add("id-5") {
		t.Error("повторное добавление — не новое")
	}
	if !ts.remove("id-5") || ts.has("id-5") || ts.remove("id-5") {
		t.Error("remove")
	}
}

func TestMergeFetchedNodes_DedupWithinBatchAndValidate(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	x := validNode(t, "10.0.0.9", "x")
	xDup := validNode(t, "10.0.0.9", "x-dup")
	invalid := &models.Node{ID: "inv", Name: "inv", Protocol: models.ProtoVLESS} // без адреса/порта
	wg := &models.Node{ID: "wg", Name: "wg", Protocol: models.ProtoWireGuard, Address: "10.0.0.8", Port: 51820}
	if added := e.mergeFetchedNodes([]*models.Node{x, xDup, invalid, wg, nil}, "test"); added != 1 {
		t.Errorf("added=%d want 1 (дубликат внутри выдачи, некорректный и WireGuard отсеяны)", added)
	}
	if got := ids(e.GetNodes()); strings.Join(got, ",") != x.ID {
		t.Errorf("пул: %v", got)
	}
}
