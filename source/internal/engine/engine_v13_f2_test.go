// engine_v13_f2_test.go — ТЗ v1.3 F2 (консилиум 2026-09-03, R4/PIN-1…11): закрепление и
// избранное персистентны, переживают перезапуск, не обходятся LastActiveNodeID и не
// снимаются «Сменить сервер»; каждый пропуск pin виден в статусе.
package engine

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

func okNode(id string, score float64) *models.Node {
	return &models.Node{ID: id, Name: id, Address: "10.0.0." + id, Port: 443, Protocol: models.ProtoVLESS,
		Status: models.StatusOK, Score: score}
}

// (3) Fail-safe: Pin/AddFavorite с неизвестным ID — ошибка БЕЗ побочных эффектов.
func TestPin_UnknownID_NoSideEffects(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	setNodes(e, okNode("1", 0.5))
	if err := e.Pin("ghost"); err == nil {
		t.Fatal("Pin(ghost) должен вернуть ошибку")
	}
	if e.PinnedNodeID() != "" || e.cfg.PinnedNode != nil {
		t.Errorf("pin не должен ставиться: id=%q cfg=%+v", e.PinnedNodeID(), e.cfg.PinnedNode)
	}
	if err := e.AddFavorite("ghost"); err == nil || len(e.FavoriteIDs()) != 0 {
		t.Errorf("AddFavorite(ghost): err=%v favs=%v", err, e.FavoriteIDs())
	}
	if err := e.ConnectOnce("ghost"); err == nil {
		t.Error("ConnectOnce(ghost) должен вернуть ошибку")
	}
	if err := e.ConnectAndPin("ghost"); err == nil || e.PinnedNodeID() != "" {
		t.Errorf("ConnectAndPin(ghost): err=%v pin=%q", err, e.PinnedNodeID())
	}
}

// (1)+(2) Позитив + стойкость: pin/избранное пишутся в config.json и восстанавливаются новым
// движком, причём ссылка переразрешается по адресу, если ID узла изменился (миграция схемы).
func TestPinAndFavorites_PersistAndRestoreAcrossRestart(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	a, b := okNode("1", 0.5), okNode("2", 0.4)
	setNodes(e, a, b)

	if err := e.Pin(a.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.AddFavorite(b.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.AddFavorite(b.ID); err != nil || len(e.FavoriteIDs()) != 1 {
		t.Errorf("AddFavorite идемпотентен: err=%v favs=%v", err, e.FavoriteIDs())
	}
	if e.cfg.PinnedNode == nil || e.cfg.PinnedNode.ID != a.ID || e.cfg.PinnedNode.Address != a.Address {
		t.Fatalf("cfg.PinnedNode не записан: %+v", e.cfg.PinnedNode)
	}
	if len(e.cfg.Favorites) != 1 || e.cfg.Favorites[0].ID != b.ID {
		t.Fatalf("cfg.Favorites не записан: %+v", e.cfg.Favorites)
	}

	// «Перезапуск»: конфиг читается с диска, у узлов НОВЫЕ ID (та же конфигурация подключения).
	cfg2 := models.DefaultConfig()
	if found, err := config.LoadInto(cfg2); err != nil || !found {
		t.Fatalf("config.json не прочитан: found=%v err=%v", found, err)
	}
	if cfg2.PinnedNode == nil || cfg2.PinnedNode.ID != a.ID {
		t.Fatalf("pinned_node не пережил запись/чтение: %+v", cfg2.PinnedNode)
	}
	e2 := New(cfg2)
	a2, b2 := *a, *b
	a2.ID, b2.ID = "new-1", "new-2"
	setNodes(e2, &a2, &b2)
	e2.restorePinAndFavorites()
	if e2.PinnedNodeID() != "new-1" {
		t.Errorf("pin должен переразрешиться по адресу: got %q", e2.PinnedNodeID())
	}
	if got := e2.FavoriteIDs(); len(got) != 1 || got[0] != "new-2" {
		t.Errorf("избранное должно переразрешиться по адресу: got %v", got)
	}
	if st := e2.GetState(); st.PinnedStatus != pinStatusStandby || len(st.FavoriteIDs) != 1 {
		t.Errorf("GetState: pinned_status=%q favorite_ids=%v", st.PinnedStatus, st.FavoriteIDs)
	}

	// Unpin/RemoveFavorite — тоже персистентны.
	e2.Unpin()
	if err := e2.RemoveFavorite("new-2"); err != nil {
		t.Fatal(err)
	}
	cfg3 := models.DefaultConfig()
	if _, err := config.LoadInto(cfg3); err != nil {
		t.Fatal(err)
	}
	if cfg3.PinnedNode != nil || len(cfg3.Favorites) != 0 {
		t.Errorf("после Unpin/RemoveFavorite конфиг должен быть пуст: pin=%+v favs=%v", cfg3.PinnedNode, cfg3.Favorites)
	}
}

// Pin, которого нет в пуле при старте, остаётся закреплённым со статусом missing.
func TestRestorePin_MissingNode_StaysPinnedWithStatusMissing(t *testing.T) {
	withTempDataDir(t)
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	cfg.EnableKillSwitch = false
	cfg.PinnedNode = &models.NodeRef{ID: "gone", Address: "203.0.113.1", Port: 443}
	e := New(cfg)
	e.restorePinAndFavorites()
	if e.PinnedNodeID() != "gone" {
		t.Fatalf("pin должен сохраниться: %q", e.PinnedNodeID())
	}
	if st := e.GetState(); st.PinnedStatus != pinStatusMissing {
		t.Errorf("pinned_status=%q want missing", st.PinnedStatus)
	}
}

// I5/B-08.4: «Сменить сервер» pin НЕ снимает — подавляет на recentFailureTTL; выбор в окне
// подавления идёт мимо pin, статус suppressed; после окна pin снова в приоритете.
func TestSuppressPin_KeepsPin_SkipsSelection_StatusSuppressed(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	pinned, other := okNode("1", 0.9), okNode("2", 0.5)
	setNodes(e, pinned, other)
	if err := e.Pin(pinned.ID); err != nil {
		t.Fatal(err)
	}
	if got := e.selectBestExcluding(nil); got != pinned {
		t.Fatalf("до подавления должен выбираться pin, got %v", got)
	}

	e.suppressPin(recentFailureTTL)
	if e.PinnedNodeID() != pinned.ID {
		t.Fatalf("suppressPin не должен снимать pin: %q", e.PinnedNodeID())
	}
	if got := e.selectBestExcluding(nil); got != other {
		t.Fatalf("в окне подавления pin должен пропускаться, got %v", got)
	}
	if st := e.GetState(); st.PinnedStatus != pinStatusSuppressed {
		t.Errorf("pinned_status=%q want suppressed", st.PinnedStatus)
	}

	e.stateMu.Lock()
	e.pinSuppressedUntil = time.Now().Add(-time.Second) // окно истекло
	e.stateMu.Unlock()
	if got := e.selectBestExcluding(nil); got != pinned {
		t.Fatalf("после окна pin должен вернуться, got %v", got)
	}
}

// ConnectOnce не меняет закрепление и ставит manualConnectAt; ConnectAndPin — меняет.
func TestConnectOnce_DoesNotChangePin_ConnectAndPinDoes(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	a, b := okNode("1", 0.5), okNode("2", 0.4)
	setNodes(e, a, b)
	if err := e.Pin(a.ID); err != nil {
		t.Fatal(err)
	}
	before := time.Now().Add(-time.Millisecond)
	if err := e.ConnectOnce(b.ID); err != nil {
		t.Fatal(err)
	}
	if e.PinnedNodeID() != a.ID {
		t.Errorf("ConnectOnce изменил pin: %q", e.PinnedNodeID())
	}
	e.manualConnectMu.Lock()
	at := e.manualConnectAt
	e.manualConnectMu.Unlock()
	if !at.After(before) {
		t.Errorf("ConnectOnce должен ставить manualConnectAt, got %v", at)
	}
	if err := e.ConnectAndPin(b.ID); err != nil {
		t.Fatal(err)
	}
	if e.PinnedNodeID() != b.ID {
		t.Errorf("ConnectAndPin должен закрепить b: %q", e.PinnedNodeID())
	}
}

// I6: порядок предпочтительных кандидатов — pinned → favorites по Score → LastActive (только
// если pin пуст или совпадает) → proven по свежести; чёрный список/партнёры цепочки/бан — вон;
// не более preferredTryLimit.
func TestPreferredCandidates_Order(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	pinned := okNode("pin", 0.1)
	fav1, fav2 := okNode("fav1", 0.3), okNode("fav2", 0.8)
	last := okNode("last", 0.9)
	proven := okNode("proven", 0.2)
	proven.VerifiedCount, proven.LastVerifiedAt = 1, time.Now().Unix()
	banned := okNode("banned", 0.99)
	banned.UserBanned = true
	partner := okNode("partner", 0.99)
	partner.IsChainPartner = true
	pool := okNode("pool", 0.95)
	setNodes(e, pool, banned, partner, proven, last, fav1, fav2, pinned)
	e.mu.Lock()
	e.cfg.LastActiveNodeID = last.ID
	e.mu.Unlock()
	if err := e.Pin(pinned.ID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{fav1.ID, fav2.ID, banned.ID} {
		if err := e.AddFavorite(id); err != nil {
			t.Fatal(err)
		}
	}

	names := func(cands []preferredCand) string {
		out := make([]string, 0, len(cands))
		for _, c := range cands {
			out = append(out, c.node.ID)
		}
		return strings.Join(out, ",")
	}
	// pin ≠ LastActive → LastActive НЕ пробуется (I6: LastActive не перекрывает pin).
	if got := names(e.preferredCandidates()); got != "pin,fav2,fav1,proven" {
		t.Errorf("с pin: %q, want pin,fav2,fav1,proven", got)
	}
	e.Unpin()
	if got := names(e.preferredCandidates()); got != "fav2,fav1,last,proven" {
		t.Errorf("без pin: %q, want fav2,fav1,last,proven", got)
	}
	// pin со свежим сбоем — пропуск со статусом unreachable.
	pinned.LastFailedAt, pinned.LastFailReason = time.Now().Unix(), failReasonWatchdog
	if err := e.Pin(pinned.ID); err != nil {
		t.Fatal(err)
	}
	if got := names(e.preferredCandidates()); strings.HasPrefix(got, "pin,") {
		t.Errorf("pin со свежим сбоем не должен пробоваться первым: %q", got)
	}
	if st := e.GetState(); st.PinnedStatus != pinStatusUnreachable {
		t.Errorf("pinned_status=%q want unreachable", st.PinnedStatus)
	}
	// Лимит.
	pinned.LastFailedAt = 0
	for i := 0; i < 10; i++ {
		p := okNode("p"+strconv.Itoa(i), 0.1)
		p.VerifiedCount, p.LastVerifiedAt = 1, time.Now().Unix()-int64(i)
		e.mu.Lock()
		e.nodes = append(e.nodes, p)
		e.mu.Unlock()
	}
	if got := e.preferredCandidates(); len(got) != preferredTryLimit || got[0].node != pinned {
		t.Errorf("лимит %d и pin первым: got %d, first=%v", preferredTryLimit, len(got), got[0].node.ID)
	}
}

// Интеграция без сети «наружу»: живой локальный слушатель = закреплённый узел отвечает на
// TCP-пробу → tryPreferredNodesFirst возвращает его, минуя полный скан; мёртвый избранный
// (закрытый порт) пропускается.
func TestTryPreferredNodesFirst_PicksLivePinnedSkipsDeadFavorite(t *testing.T) {
	withTempDataDir(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// Принятые соединения держим открытыми до конца теста: немедленный Close на стороне
	// сервера в некоторых окружениях (особенно под -race) даёт клиенту RST раньше, чем
	// завершится его dial, и «живой» узел выглядит мёртвым.
	var held []net.Conn
	var heldMu sync.Mutex
	defer func() {
		heldMu.Lock()
		for _, c := range held {
			c.Close()
		}
		heldMu.Unlock()
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			heldMu.Lock()
			held = append(held, c)
			heldMu.Unlock()
		}
	}()
	livePort := ln.Addr().(*net.TCPAddr).Port
	deadLn, _ := net.Listen("tcp", "127.0.0.1:0")
	deadPort := deadLn.Addr().(*net.TCPAddr).Port
	deadLn.Close()

	e := newTestEngine()
	e.mu.Lock()
	e.cfg.Sources = nil // фоновый runPoolScan после успеха не должен ходить в сеть
	e.mu.Unlock()
	pinned := &models.Node{ID: "live", Name: "live", Address: "127.0.0.1", Port: livePort,
		Protocol: models.ProtoVLESS, Status: models.StatusOK}
	dead := &models.Node{ID: "dead", Name: "dead", Address: "127.0.0.1", Port: deadPort,
		Protocol: models.ProtoVLESS, Status: models.StatusOK, Score: 0.9}
	setNodes(e, dead, pinned)
	if err := e.AddFavorite(dead.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.Pin(pinned.ID); err != nil {
		t.Fatal(err)
	}
	if got := e.tryPreferredNodesFirst(); got != pinned {
		t.Fatalf("живой pin должен вернуться первым, got %v", got)
	}
	// Успех запускает фоновый runPoolScan (CheckAll по тем же узлам) — дожидаемся его, иначе
	// его записи в поля узлов гонятся с CheckOne второго вызова ниже (checker пишет поля узла
	// без лока — известное свойство, см. addNodeCheckMu).
	e.wg.Wait()

	// Только мёртвый избранный → nil (обычный полный скан), статус pin не трогается.
	e.Unpin()
	if got := e.tryPreferredNodesFirst(); got != nil {
		t.Fatalf("мёртвый избранный не должен возвращаться, got %v", got)
	}
}

// PatchConfig отвергает pinned_node/favorites (I1: единственный писатель — API pin/избранного).
func TestValidatePatch_RejectsPinnedNodeAndFavorites(t *testing.T) {
	if err := validatePatch(map[string]interface{}{"pinned_node": map[string]interface{}{"id": "x"}}); err == nil {
		t.Error("pinned_node должен отвергаться")
	}
	if err := validatePatch(map[string]interface{}{"favorites": []interface{}{}}); err == nil {
		t.Error("favorites должен отвергаться")
	}
	if err := validatePatch(map[string]interface{}{"selection_mode": "speed"}); err != nil {
		t.Errorf("обычный ключ не должен отвергаться: %v", err)
	}
}

// I3: GetState отдаёт active, когда подключены именно к закреплённому узлу.
func TestGetState_PinnedStatusActiveWhenConnectedToPin(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	pinned := okNode("1", 0.5)
	setNodes(e, pinned)
	if err := e.Pin(pinned.ID); err != nil {
		t.Fatal(err)
	}
	e.stateMu.Lock()
	e.state.Connected = true
	e.state.ActiveNode = pinned
	e.stateMu.Unlock()
	if st := e.GetState(); st.PinnedStatus != pinStatusActive {
		t.Errorf("pinned_status=%q want active", st.PinnedStatus)
	}
	e.stateMu.Lock()
	e.state.Connected = false
	e.state.ActiveNode = nil
	e.stateMu.Unlock()
	if st := e.GetState(); st.PinnedStatus != pinStatusStandby {
		t.Errorf("pinned_status=%q want standby", st.PinnedStatus)
	}
}

// Избранное — перед остальным пулом при равных прочих (после proven-first).
func TestFavoritesFirst_InSelection(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	fav, top := okNode("fav", 0.2), okNode("top", 0.9)
	setNodes(e, top, fav)
	if err := e.AddFavorite(fav.ID); err != nil {
		t.Fatal(err)
	}
	if got := e.selectBestExcluding(nil); got != fav {
		t.Errorf("избранный должен выбираться раньше лучшего по Score, got %v", got)
	}
	if got := e.selectBestExcluding(fav); got != top {
		t.Errorf("исключённый избранный → лучший другой, got %v", got)
	}
}
