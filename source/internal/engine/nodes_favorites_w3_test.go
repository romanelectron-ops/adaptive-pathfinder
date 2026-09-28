// nodes_favorites_w3_test.go — W3 (ТЗ v1.5 §2-§5, TZ_v1.5_NODE_CATALOG_2026-09-14): двухклассовое
// избранное (NodeRef.Origin) + ограниченное удержание проверенных узлов. Покрывает design points
// 1-5 брифа L1-ENG-C и все 6 safeguards консилиума (см. комментарий над каждым тестом).
package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── Design point 1/2: класс избранного, AddSystemFavorite, star-promotion, RemoveFavorite ──────

// TestFavoriteOrigin_AddPromoteRemove — AddFavorite всегда даёт "user"; AddSystemFavorite — "system";
// звезда пользователя на уже системном фаворите ПОВЫШАЕТ его до "user" (sticky) и повторный
// AddSystemFavorite после этого не может понизить обратно; RemoveFavorite работает для обоих
// классов одинаково.
func TestFavoriteOrigin_AddPromoteRemove(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	n := okNode("n1", 0.5)
	setNodes(e, n)

	if err := e.AddSystemFavorite(n.ID); err != nil {
		t.Fatalf("AddSystemFavorite: %v", err)
	}
	if got := e.FavoriteOrigin(n.ID); got != models.OriginSystem {
		t.Fatalf("FavoriteOrigin after AddSystemFavorite = %q, want %q", got, models.OriginSystem)
	}
	if ids := e.SystemFavoriteIDs(); len(ids) != 1 || ids[0] != n.ID {
		t.Fatalf("SystemFavoriteIDs = %v, want [%s]", ids, n.ID)
	}
	if ids := e.UserFavoriteIDs(); len(ids) != 0 {
		t.Fatalf("UserFavoriteIDs = %v, want empty", ids)
	}

	if err := e.AddFavorite(n.ID); err != nil {
		t.Fatalf("AddFavorite (promote): %v", err)
	}
	if got := e.FavoriteOrigin(n.ID); got != models.OriginUser {
		t.Fatalf("FavoriteOrigin after star promotion = %q, want %q", got, models.OriginUser)
	}
	if ids := e.SystemFavoriteIDs(); len(ids) != 0 {
		t.Fatalf("SystemFavoriteIDs after promotion = %v, want empty", ids)
	}

	if err := e.AddSystemFavorite(n.ID); err != nil {
		t.Fatalf("AddSystemFavorite (no-op on existing user fav): %v", err)
	}
	if got := e.FavoriteOrigin(n.ID); got != models.OriginUser {
		t.Fatalf("AddSystemFavorite must never demote user->system, got %q", got)
	}

	if err := e.RemoveFavorite(n.ID); err != nil {
		t.Fatalf("RemoveFavorite: %v", err)
	}
	if e.IsFavorite(n.ID) {
		t.Fatal("RemoveFavorite did not remove the favorite")
	}
}

// ─── Safeguard #2: потолок ТОЛЬКО системного класса ──────────────────────────────────────────

// TestSystemFavoriteCap_UserUnboundedSystemCappedAt30 — ровно формулировка safeguard #2 брифа:
// 40 user + 40 system → 40 user + SystemFavoriteCap(30) system, выживают лучшие по Score.
func TestSystemFavoriteCap_UserUnboundedSystemCappedAt30(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()

	var nodes []*models.Node
	for i := 0; i < 40; i++ {
		nodes = append(nodes, okNode(fmt.Sprintf("user-%02d", i), 0.5))
	}
	for i := 0; i < 40; i++ {
		// Score растёт с i — предсказуемо знаем, какие 30 переживут потолок (наибольший Score).
		nodes = append(nodes, okNode(fmt.Sprintf("sys-%02d", i), float64(i)))
	}
	setNodes(e, nodes...)

	for _, n := range nodes {
		if strings.HasPrefix(n.ID, "user-") {
			if err := e.AddFavorite(n.ID); err != nil {
				t.Fatalf("AddFavorite(%s): %v", n.ID, err)
			}
		} else {
			if err := e.AddSystemFavorite(n.ID); err != nil {
				t.Fatalf("AddSystemFavorite(%s): %v", n.ID, err)
			}
		}
	}

	// Потолок применяется явно (в реальном прогоне — из reconcileFavoritesFromNodeCheck).
	e.enforceSystemFavoriteCap()

	if got := e.UserFavoriteIDs(); len(got) != 40 {
		t.Fatalf("UserFavoriteIDs len=%d, want 40 (пользовательский класс никогда не капается)", len(got))
	}
	sysIDs := e.SystemFavoriteIDs()
	if len(sysIDs) != SystemFavoriteCap {
		t.Fatalf("SystemFavoriteIDs len=%d, want %d (SystemFavoriteCap)", len(sysIDs), SystemFavoriteCap)
	}
	kept := map[string]bool{}
	for _, id := range sysIDs {
		kept[id] = true
	}
	dropCount := 40 - SystemFavoriteCap
	for i := 0; i < 40; i++ {
		id := fmt.Sprintf("sys-%02d", i)
		wantKept := i >= dropCount // лучшие по Score — самые большие i
		if kept[id] != wantKept {
			t.Errorf("sys-%02d (score=%d) kept=%v, want %v", i, i, kept[id], wantKept)
		}
	}
}

// ─── Design point 5: CatalogReviewInterval getter/setter ─────────────────────────────────────

// TestCatalogReviewInterval_GetSetValidatesAndDefaults — дефолт each_scan; допустимые значения
// (регистр/пробелы прощаются) принимаются и читаются обратно; неизвестное — ошибка БЕЗ побочных
// эффектов; мусор, попавший в cfg в обход сеттера (руками отредактированный config.json), не
// паникует и читается как each_scan (Normalize() вне зоны этого лота, см. result.md).
func TestCatalogReviewInterval_GetSetValidatesAndDefaults(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	if got := e.CatalogReviewInterval(); got != models.ReviewIntervalEachScan {
		t.Fatalf("default CatalogReviewInterval = %q, want %q", got, models.ReviewIntervalEachScan)
	}

	for _, v := range []string{models.ReviewIntervalEachScan, models.ReviewIntervalWeekly, models.ReviewIntervalMonthly, "  DAILY  "} {
		if err := e.SetCatalogReviewInterval(v); err != nil {
			t.Fatalf("SetCatalogReviewInterval(%q): %v", v, err)
		}
	}
	if got := e.CatalogReviewInterval(); got != models.ReviewIntervalDaily {
		t.Fatalf("after SetCatalogReviewInterval(%q) got %q, want %q", "  DAILY  ", got, models.ReviewIntervalDaily)
	}

	if err := e.SetCatalogReviewInterval("hourly"); err == nil {
		t.Fatal("SetCatalogReviewInterval(hourly) should be rejected — not in the allowed set")
	}
	if got := e.CatalogReviewInterval(); got != models.ReviewIntervalDaily {
		t.Fatalf("rejected SetCatalogReviewInterval must not change state: got %q, want unchanged %q", got, models.ReviewIntervalDaily)
	}

	e.mu.Lock()
	e.cfg.CatalogReviewInterval = "garbage-from-hand-edited-config"
	e.mu.Unlock()
	if got := e.CatalogReviewInterval(); got != models.ReviewIntervalEachScan {
		t.Fatalf("garbage cfg value: CatalogReviewInterval() = %q, want defensive fallback %q", got, models.ReviewIntervalEachScan)
	}
}

// ─── Design point 3: реконсиляция избранного внутри runNodeCheck (ручная сборка) ─────────────

// TestNodeCheck_ReconcileAddsPassingAsSystemFavorites — интеграционный путь целиком
// (StartNodeCheck → probeFn → реконсиляция): узлы, прошедшие пробу, автоматически становятся
// СИСТЕМНЫМИ фаворитами; провалившие пробу — нет.
func TestNodeCheck_ReconcileAddsPassingAsSystemFavorites(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.cfg.Sources = nil

	nodes := []*models.Node{tcpAliveNode("rc-a"), tcpAliveNode("rc-b"), tcpAliveNode("rc-c")}
	setProbePool(e, nodes)
	pass := map[string]bool{"rc-a": true, "rc-c": true}
	e.probeFn = func(ctx context.Context, node *models.Node, slot int) (int64, string, string, error) {
		if pass[node.ID] {
			return 10, "US", "203.0.113.9", nil
		}
		return 0, "", "", errors.New("fake fail")
	}

	if err := e.StartNodeCheck(NodeCheckOptions{TopN: 30, TargetK: 100, Concurrency: 2, PerNode: time.Second}); err != nil {
		t.Fatalf("StartNodeCheck: %v", err)
	}
	waitNodeCheckDone(t, e, 5*time.Second)

	if !e.IsFavorite("rc-a") || e.FavoriteOrigin("rc-a") != models.OriginSystem {
		t.Errorf("rc-a passed its probe — should have been auto-added as a system favorite, origin=%q", e.FavoriteOrigin("rc-a"))
	}
	if !e.IsFavorite("rc-c") || e.FavoriteOrigin("rc-c") != models.OriginSystem {
		t.Errorf("rc-c passed its probe — should have been auto-added as a system favorite, origin=%q", e.FavoriteOrigin("rc-c"))
	}
	if e.IsFavorite("rc-b") {
		t.Errorf("rc-b failed its probe and must not become a favorite")
	}
}

// TestNodeCheck_ReconcileEvictsFailingSystemFavoriteEachScan — под each_scan (потолок давности=0)
// системный фаворит, провалившийся в этом прогоне, вытесняется НЕМЕДЛЕННО.
func TestNodeCheck_ReconcileEvictsFailingSystemFavoriteEachScan(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	n := okNode("evict-1", 0.5)
	n.VerifiedCount, n.LastVerifiedAt = 1, time.Now().Unix()
	setNodes(e, n)
	if err := e.AddSystemFavorite(n.ID); err != nil {
		t.Fatalf("AddSystemFavorite: %v", err)
	}
	if err := e.SetCatalogReviewInterval(models.ReviewIntervalEachScan); err != nil {
		t.Fatal(err)
	}

	e.reconcileFavoritesFromNodeCheck([]nodeCheckOutcome{{node: n, passed: false}})

	if e.IsFavorite(n.ID) {
		t.Fatalf("system favorite %s should be evicted immediately under each_scan after a failed probe", n.ID)
	}
}

// TestNodeCheck_ReconcileKeepsFailingSystemFavoriteWithinReviewWindow — design point 3(b): под
// "daily", провал не вытесняет, пока последнее подтверждение (LastVerifiedAt) моложе окна; как
// только давность превышает окно, следующий провал вытесняет.
func TestNodeCheck_ReconcileKeepsFailingSystemFavoriteWithinReviewWindow(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	n := okNode("evict-2", 0.5)
	n.VerifiedCount, n.LastVerifiedAt = 1, time.Now().Add(-1*time.Hour).Unix()
	setNodes(e, n)
	if err := e.AddSystemFavorite(n.ID); err != nil {
		t.Fatalf("AddSystemFavorite: %v", err)
	}
	if err := e.SetCatalogReviewInterval(models.ReviewIntervalDaily); err != nil {
		t.Fatal(err)
	}

	e.reconcileFavoritesFromNodeCheck([]nodeCheckOutcome{{node: n, passed: false}})
	if !e.IsFavorite(n.ID) {
		t.Fatalf("system favorite %s proven only 1h ago must survive a single failed probe under a daily review window", n.ID)
	}
	if got := e.FavoriteOrigin(n.ID); got != models.OriginSystem {
		t.Fatalf("FavoriteOrigin = %q, want still %q (kept, not promoted)", got, models.OriginSystem)
	}

	n.LastVerifiedAt = time.Now().Add(-48 * time.Hour).Unix()
	e.reconcileFavoritesFromNodeCheck([]nodeCheckOutcome{{node: n, passed: false}})
	if e.IsFavorite(n.ID) {
		t.Fatalf("system favorite %s with a stale (48h) proof must be evicted after a failed probe under a daily review window", n.ID)
	}
}

// TestFavoriteOrigin_UserFavoriteNeverEvictedByReconcile — design point 3(c): класс "user" не
// вытесняется реконсиляцией НИКОГДА, независимо от исхода пробы или настройки интервала.
func TestFavoriteOrigin_UserFavoriteNeverEvictedByReconcile(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	n := okNode("user-keep", 0.5)
	setNodes(e, n)
	if err := e.AddFavorite(n.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.SetCatalogReviewInterval(models.ReviewIntervalEachScan); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		e.reconcileFavoritesFromNodeCheck([]nodeCheckOutcome{{node: n, passed: false}})
	}
	if !e.IsFavorite(n.ID) || e.FavoriteOrigin(n.ID) != models.OriginUser {
		t.Fatalf("user favorite must never be evicted by catalog reconciliation regardless of probe outcome (origin=%q, favorite=%v)",
			e.FavoriteOrigin(n.ID), e.IsFavorite(n.ID))
	}
}

// ─── Safeguard #1 (DATA-LOSS BLOCKER): миграция — Origin=="" никогда не реклассифицируется ───

// TestMigration_LegacyFavoriteWithoutOriginNeverAutoEvicted — ровно сценарий брифа: избранное,
// загруженное из cfg.Favorites БЕЗ Origin (пре-W3 config.json), после restorePinAndFavorites
// классифицируется как "user" и переживает прогон реконсиляции, который вытеснил бы ЛЮБОЙ
// системный фаворит (each_scan + провал пробы у обоих узлов).
func TestMigration_LegacyFavoriteWithoutOriginNeverAutoEvicted(t *testing.T) {
	withTempDataDir(t)
	cfg := models.DefaultConfig()
	cfg.AutoConnect = false
	cfg.EnableKillSwitch = false
	// Пре-W3 избранное: НИ ОДНОЙ ссылки с заполненным Origin — ровно то, во что распаковывается
	// старый config.json (поля просто не было).
	cfg.Favorites = []models.NodeRef{{ID: "legacy-1"}, {ID: "legacy-2"}}
	e := New(cfg)
	n1 := okNode("legacy-1", 0.5)
	n2 := okNode("legacy-2", 0.4)
	setNodes(e, n1, n2)
	e.restorePinAndFavorites()

	if got := e.FavoriteOrigin("legacy-1"); got != models.OriginUser {
		t.Fatalf("legacy favorite Origin=%q after restore, want normalized %q", got, models.OriginUser)
	}
	if got := e.FavoriteOrigin("legacy-2"); got != models.OriginUser {
		t.Fatalf("legacy favorite Origin=%q after restore, want normalized %q", got, models.OriginUser)
	}

	if err := e.SetCatalogReviewInterval(models.ReviewIntervalEachScan); err != nil {
		t.Fatal(err)
	}
	e.reconcileFavoritesFromNodeCheck([]nodeCheckOutcome{
		{node: n1, passed: false},
		{node: n2, passed: false},
	})

	if !e.IsFavorite("legacy-1") || !e.IsFavorite("legacy-2") {
		t.Fatalf("pre-W3 favorites (Origin==\"\") must NEVER be auto-evicted by catalog reconciliation — got favorites=%v",
			e.FavoriteIDs())
	}

	// Нормализация обязана закрепиться и в персисте — следующий рестарт не должен снова видеть
	// Origin=="".
	e.persistPinAndFavorites()
	for _, ref := range e.cfg.Favorites {
		if ref.Origin != models.OriginUser {
			t.Errorf("persisted favorite %+v: Origin=%q, want explicit %q (normalization must stick)", ref, ref.Origin, models.OriginUser)
		}
	}
}

// TestRetention_FavoriteRetentionSetTreatsEmptyOriginAsUnboundedUser — то же самое safeguard,
// проверенное на уровне чистой функции удержания (nodes_retention.go): Origin=="" не должен
// попасть под потолок системного класса.
func TestRetention_FavoriteRetentionSetTreatsEmptyOriginAsUnboundedUser(t *testing.T) {
	origCap := SystemFavoriteCap
	SystemFavoriteCap = 1
	defer func() { SystemFavoriteCap = origCap }()

	nodes := []*models.Node{{ID: "legacy-a"}, {ID: "legacy-b"}, {ID: "legacy-c"}}
	favRefs := []models.NodeRef{{ID: "legacy-a"}, {ID: "legacy-b"}, {ID: "legacy-c"}} // Origin=="" везде

	set := favoriteRetentionSet(nodes, favRefs)
	for _, id := range []string{"legacy-a", "legacy-b", "legacy-c"} {
		if !set[id] {
			t.Errorf("legacy favorite %s (Origin==\"\") must be treated as unbounded user, dropped by cap=%d", id, SystemFavoriteCap)
		}
	}
}

// ─── Safeguard #3: гонка звезда↔эвикшен — звезда побеждает ───────────────────────────────────

// TestFavoriteRace_StarBeforeEvictionAttemptWins — детерминированный порядок, доказывающий сам
// механизм: если промоушен пользователя (AddFavorite) успевает ДО вызова evictSystemFavorite,
// повторная проверка класса под тем же favMu внутри evictSystemFavorite видит уже "user" и
// отказывается от удаления — какая бы сторона ни выиграла реальную гонку потоков, свежая
// проверка класса непосредственно перед мутацией — это и есть гарантия (см. её комментарий).
func TestFavoriteRace_StarBeforeEvictionAttemptWins(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	n := okNode("race-1", 0.5)
	n.VerifiedCount, n.LastVerifiedAt = 1, time.Now().Unix()
	setNodes(e, n)
	if err := e.AddSystemFavorite(n.ID); err != nil {
		t.Fatal(err)
	}

	if err := e.AddFavorite(n.ID); err != nil { // "звезда" пользователя приходит первой
		t.Fatal(err)
	}
	e.evictSystemFavorite(n.ID) // то, что вызвала бы реконсиляция для провалившего пробу системного фаворита

	if !e.IsFavorite(n.ID) {
		t.Fatal("a user star that lands before the evict call must win — favorite must survive")
	}
	if got := e.FavoriteOrigin(n.ID); got != models.OriginUser {
		t.Fatalf("FavoriteOrigin = %q, want %q (star promotion must stick)", got, models.OriginUser)
	}
}

// TestFavoriteRace_ConcurrentStarAndEvictStaysConsistent — go test -race: звезда и эвикшен на
// ОДНОМ И ТОМ ЖЕ узле из конкурентных горутин не должны гонять данные (race detector) и не должны
// рассинхронизировать favIDs/favRefs, каким бы ни было переплетение. saveConfig подменён на no-op
// — тест изолирован от того, потокобезопасна ли сама config.SaveConfig (вне зоны этого лота).
func TestFavoriteRace_ConcurrentStarAndEvictStaysConsistent(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	e.saveConfig = func(cfg *models.AppConfig) error { return nil }

	var nodes []*models.Node
	for i := 0; i < 20; i++ {
		nodes = append(nodes, okNode(fmt.Sprintf("race-%02d", i), 0.5))
	}
	setNodes(e, nodes...)
	for _, n := range nodes {
		if err := e.AddSystemFavorite(n.ID); err != nil {
			t.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	for _, n := range nodes {
		n := n
		wg.Add(2)
		go func() { defer wg.Done(); _ = e.AddFavorite(n.ID) }()
		go func() { defer wg.Done(); e.evictSystemFavorite(n.ID) }()
	}
	wg.Wait()

	e.favMu.RLock()
	defer e.favMu.RUnlock()
	if len(e.favIDs) != len(e.favRefs) {
		t.Fatalf("favIDs/favRefs diverged under concurrent star/evict: %d vs %d", len(e.favIDs), len(e.favRefs))
	}
	seen := map[string]bool{}
	for _, r := range e.favRefs {
		if seen[r.ID] {
			t.Fatalf("duplicate favRefs entry for %s under concurrent star/evict", r.ID)
		}
		seen[r.ID] = true
		if !e.favIDs[r.ID] {
			t.Fatalf("favRefs entry %s missing from favIDs", r.ID)
		}
	}
}

// ─── Safeguard #4: закреплённый узел переживает вытеснение из фаворитов ──────────────────────

// TestEvictSystemFavorite_PinnedNodeStaysPinnedAndRetained — узел одновременно закреплён и
// является системным фаворитом; после вытеснения избранного pin остаётся, и узел всё ещё
// удерживается на диске — уже по критерию pin, независимому от избранного.
func TestEvictSystemFavorite_PinnedNodeStaysPinnedAndRetained(t *testing.T) {
	dir := withTempDataDir(t)
	e := newTestEngine()
	n := okNode("pin-sys-1", 0.5)
	setNodes(e, n)
	e.PinNode(n.ID)
	if err := e.AddSystemFavorite(n.ID); err != nil {
		t.Fatal(err)
	}

	e.evictSystemFavorite(n.ID)

	if e.IsFavorite(n.ID) {
		t.Fatal("evictSystemFavorite should have removed the favorite mark")
	}
	if e.PinnedNodeID() != n.ID {
		t.Fatalf("PinnedNodeID = %q, want unchanged %q (eviction must not touch pin)", e.PinnedNodeID(), n.ID)
	}

	if err := e.saveNodesToDisk(); err != nil {
		t.Fatalf("saveNodesToDisk: %v", err)
	}
	saved := readNodesCache(t, dir)
	if saved[n.ID] == nil {
		t.Fatalf("pinned node %s must still be retained on disk after losing its (system) favorite status", n.ID)
	}
}

// ─── Safeguard #5: эвикшен ≠ бан ──────────────────────────────────────────────────────────────

// TestEvictSystemFavorite_NodeStaysInPoolNotBanned — вытеснение из избранного НЕ трогает пул/бан;
// узел может свободно вернуться в системное избранное позже.
func TestEvictSystemFavorite_NodeStaysInPoolNotBanned(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	n := okNode("evict-notban", 0.5)
	setNodes(e, n)
	if err := e.AddSystemFavorite(n.ID); err != nil {
		t.Fatal(err)
	}

	e.evictSystemFavorite(n.ID)

	e.mu.RLock()
	stillInPool := false
	for _, x := range e.nodes {
		if x.ID == n.ID {
			stillInPool = true
		}
	}
	e.mu.RUnlock()
	if !stillInPool {
		t.Fatal("eviction from favorites must not remove the node from the pool")
	}
	if n.UserBanned {
		t.Fatal("eviction from favorites must not ban the node")
	}
	if n.IsBlacklisted() {
		t.Fatal("eviction from favorites must not blacklist the node")
	}

	if err := e.AddSystemFavorite(n.ID); err != nil {
		t.Fatalf("re-adding an evicted node as a system favorite should work: %v", err)
	}
	if !e.IsFavorite(n.ID) {
		t.Fatal("re-added node should be a favorite again")
	}
}

// ─── Safeguard #6: нет двойного счёта у потолка ───────────────────────────────────────────────

// TestRetention_SystemFavoriteCapNoDoubleCountWithPinnedOrManual — узел, удерживаемый на диске по
// ДРУГОМУ независимому критерию (pin), но НЕ являющийся избранным, не отнимает место у потолка
// системного класса и retainNodeForDisk всё равно его удерживает — своим отдельным критерием.
func TestRetention_SystemFavoriteCapNoDoubleCountWithPinnedOrManual(t *testing.T) {
	origCap := SystemFavoriteCap
	SystemFavoriteCap = 2
	defer func() { SystemFavoriteCap = origCap }()

	now := time.Now().Unix()
	pinned := &models.Node{ID: "pin-1", Source: "manual"} // тоже user-owned, отдельный критерий
	sys1 := &models.Node{ID: "sys-1", Score: 0.9}
	sys2 := &models.Node{ID: "sys-2", Score: 0.8}
	sys3 := &models.Node{ID: "sys-3", Score: 0.1} // должен вылететь по потолку=2
	nodes := []*models.Node{pinned, sys1, sys2, sys3}

	favRefs := []models.NodeRef{
		{ID: sys1.ID, Origin: models.OriginSystem},
		{ID: sys2.ID, Origin: models.OriginSystem},
		{ID: sys3.ID, Origin: models.OriginSystem},
		// "pinned" НАМЕРЕННО не в favRefs — удерживается ЧИСТО критерием pin и не должен
		// потреблять ни одного слота потолка системного избранного.
	}

	retained := filterNodesForRetention(nodes, now, pinned.ID, favRefs)
	byID := map[string]bool{}
	for _, n := range retained {
		byID[n.ID] = true
	}
	if !byID[pinned.ID] {
		t.Errorf("pinned node must be retained even though it holds none of the %d system-favorite cap slots", SystemFavoriteCap)
	}
	if !byID[sys1.ID] || !byID[sys2.ID] {
		t.Errorf("the %d best system favorites must be retained, got %v", SystemFavoriteCap, byID)
	}
	if byID[sys3.ID] {
		t.Errorf("sys-3 (lowest score, beyond the cap of %d) must be dropped", SystemFavoriteCap)
	}
	if len(retained) != 3 {
		t.Errorf("retained count = %d, want 3 (pinned + top-%d system favorites), got %v",
			len(retained), SystemFavoriteCap, byID)
	}
}
