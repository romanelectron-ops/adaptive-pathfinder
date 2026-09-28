// engine_v13_f1_test.go — ТЗ v1.3 F1.2–F1.5 (консилиум 2026-09-03): история узла пишется из
// реальных событий (health-check/Watchdog/monitor), переживает перезапуск, а выбор идёт
// «проверенные — впереди, непроверенные — вон». Контракты B2–B5 из G_blackbox_contracts.md.
package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/detector"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// withTempDataDir — свой каталог данных на один тест (поверх пакетной изоляции TestMain),
// чтобы nodes_cache.json этого теста не пересекался с чужими записями.
func withTempDataDir(t *testing.T) string {
	t.Helper()
	prev := config.DataDir()
	dir := t.TempDir()
	config.SetDataDirOverride(dir)
	t.Cleanup(func() { config.SetDataDirOverride(prev) })
	return dir
}

func readNodesCache(t *testing.T, dir string) map[string]*models.Node {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "nodes_cache.json"))
	if err != nil {
		t.Fatalf("nodes_cache.json не записан: %v", err)
	}
	var nodes []*models.Node
	if err := json.Unmarshal(data, &nodes); err != nil {
		t.Fatalf("nodes_cache.json не разбирается: %v", err)
	}
	byID := make(map[string]*models.Node, len(nodes))
	for _, n := range nodes {
		if n != nil {
			byID[n.ID] = n
		}
	}
	return byID
}

func setNodes(e *Engine, nodes ...*models.Node) {
	e.mu.Lock()
	e.nodes = nodes
	e.mu.Unlock()
}

func ids(nodes []*models.Node) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.ID)
	}
	return out
}

// ─── F1.2: запись подтверждения/сбоя в узел ─────────────────────────────────────────────

// (1) Позитив: подтверждение пишет всё, что вернула проверка, сбрасывает FailStreak и
// сохраняет кэш; повтор без страны/IP не затирает прежние значения пустотой.
func TestRecordNodeVerified_WritesHistoryAndPersists(t *testing.T) {
	dir := withTempDataDir(t)
	e := newTestEngine()
	n := &models.Node{ID: "n1", Name: "n1", FailStreak: 2}
	setNodes(e, n)

	e.recordNodeVerified(n, 123, "NL", "203.0.113.7")
	if n.LastVerifiedAt == 0 || n.VerifiedCount != 1 || n.LastVerifiedLatencyMs != 123 ||
		n.LastVerifiedCountry != "NL" || n.LastVerifiedExitIP != "203.0.113.7" || n.FailStreak != 0 {
		t.Fatalf("после подтверждения: %+v", *n)
	}
	if !n.IsProven() || n.IsUnchecked() || n.LastOutcomeIsFailure() {
		t.Errorf("proven=%v unchecked=%v lastFailure=%v, want true/false/false",
			n.IsProven(), n.IsUnchecked(), n.LastOutcomeIsFailure())
	}
	if saved := readNodesCache(t, dir)["n1"]; saved == nil || saved.VerifiedCount != 1 || saved.LastVerifiedExitIP != "203.0.113.7" {
		t.Errorf("подтверждение не дошло до nodes_cache.json: %+v", saved)
	}

	e.recordNodeVerified(n, 90, "", "")
	if n.VerifiedCount != 2 || n.LastVerifiedLatencyMs != 90 || n.LastVerifiedCountry != "NL" || n.LastVerifiedExitIP != "203.0.113.7" {
		t.Errorf("повтор без страны/IP затёр прежние значения: %+v", *n)
	}
	e.recordNodeVerified(nil, 1, "", "") // nil-safe
}

// (2) Fail-safe: во время гонки узлов победитель неизвестен — подтверждение НЕ приписывается.
func TestRecordNodeVerified_SkippedDuringRace(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	n := &models.Node{ID: "n1"}
	setNodes(e, n)
	e.mu.Lock()
	e.raceNodes = []*models.Node{n}
	e.mu.Unlock()

	e.recordNodeVerified(n, 1, "NL", "1.2.3.4")
	if n.LastVerifiedAt != 0 || n.VerifiedCount != 0 || n.LastVerifiedCountry != "" {
		t.Errorf("при активной гонке узел не должен получать подтверждение: %+v", *n)
	}
}

// (2b) FIX-2 (консилиум L1-ENG-A, CONSILIUM_L1-ENG-A.md п.3, node_check.go): в отличие от
// recordNodeVerified/recordNodeVerifiedVia выше (гейт гонки для post-connect ПО-ПРЕЖНЕМУ
// применяется — предыдущая проверка это доказывает), recordNodeVerifiedViaProbe пишет ДАЖЕ когда
// e.raceNodes != nil: каталожная проба однозначна (свой SOCKS-инстанс ИМЕННО на этом узле), гонка
// urltest автоподключения к этому пути не относится вовсе. Возвращает true, когда штамп реально
// лёг — nil-safe возвращает false.
func TestRecordNodeVerifiedViaProbe_BypassesRaceGate(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	n := &models.Node{ID: "n1"}
	setNodes(e, n)
	e.mu.Lock()
	e.raceNodes = []*models.Node{{ID: "someone-else"}}
	e.mu.Unlock()

	landed := e.recordNodeVerifiedViaProbe(n, 42, "US", "203.0.113.9", models.VerifiedViaSOCKS)
	if !landed {
		t.Fatal("recordNodeVerifiedViaProbe вернул false несмотря на не-nil узел — штамп должен был лечь")
	}
	if n.LastVerifiedAt == 0 || n.VerifiedCount != 1 || n.LastVerifiedCountry != "US" || n.LastVerifiedExitIP != "203.0.113.9" {
		t.Errorf("узел не получил штамп при активной гонке (гейт не должен применяться к каталожной пробе): %+v", *n)
	}

	if landed := e.recordNodeVerifiedViaProbe(nil, 1, "", "", ""); landed {
		t.Error("recordNodeVerifiedViaProbe(nil, ...) должен вернуть false")
	}
}

// (3) Негатив: сбой обнуляет Score, ведёт FailStreak/причину, но историю подтверждений не
// стирает — узел остаётся «проверенным», просто уходит в конец очереди.
func TestRecordNodeFailure_ZeroesScoreKeepsProvenHistory(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	n := &models.Node{ID: "n1", Score: 0.9, LastVerifiedAt: time.Now().Add(-time.Hour).Unix(), VerifiedCount: 3}
	setNodes(e, n)

	e.recordNodeFailure(n, failReasonHealthCheck)
	if n.Score != 0 || n.LastFailedAt == 0 || n.LastFailReason != failReasonHealthCheck || n.FailStreak != 1 {
		t.Fatalf("после сбоя: %+v", *n)
	}
	if !n.LastOutcomeIsFailure() || !n.IsProven() || n.VerifiedCount != 3 {
		t.Errorf("lastFailure=%v proven=%v verified=%d, want true/true/3",
			n.LastOutcomeIsFailure(), n.IsProven(), n.VerifiedCount)
	}
	e.recordNodeFailure(n, failReasonWatchdog)
	if n.FailStreak != 2 || n.LastFailReason != failReasonWatchdog {
		t.Errorf("второй сбой: streak=%d reason=%q", n.FailStreak, n.LastFailReason)
	}
	e.recordNodeFailure(nil, "x") // nil-safe
}

// (4) Стойкость: события внутри окна debounce не теряются — «грязный» кэш сбрасывается по
// таймеру, а не ждёт следующего события или Stop().
func TestSaveNodesDebounced_FlushesDirtyByTimer(t *testing.T) {
	dir := withTempDataDir(t)
	prev := nodesSaveDebounce
	nodesSaveDebounce = 80 * time.Millisecond
	t.Cleanup(func() { nodesSaveDebounce = prev })

	e := newTestEngine()
	// N-5 (ТЗ APF v1.5): saveNodesToDisk теперь фильтрует на запись (nodes_retention.go) — узел
	// без Verified*/pin/favorite и не manual/chain-partner на диск просто не попал бы, и
	// readNodesCache ниже всегда видел бы nil независимо от debounce. Этот тест проверяет ТАЙМИНГ
	// сброса (немедленно / по таймеру), а не политику удержания, поэтому узел помечен manual —
	// тест остаётся про debounce, а не начинает молча проверять N-5.
	n := &models.Node{ID: "n1", Status: models.StatusOK, Source: "manual"}
	setNodes(e, n)

	e.recordNodeFailure(n, "a") // первое событие — немедленная запись
	e.recordNodeFailure(n, "b") // внутри окна — только флаг + таймер
	if saved := readNodesCache(t, dir)["n1"]; saved == nil || saved.FailStreak != 1 {
		t.Fatalf("сразу после второго события на диске должен быть streak=1 (debounce), got %+v", saved)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if saved := readNodesCache(t, dir)["n1"]; saved != nil && saved.FailStreak == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("отложенный сброс по таймеру не записал streak=2 за 2 с")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ─── F1.3: история переживает перезапуск ────────────────────────────────────────────────

// (1)+(2)+(3): Score/LastChecked/Verified*/FailStreak сохраняются; истёкший бан снимается с
// починкой Status, действующий — остаётся; дубликаты по ID сливаются с максимумом истории;
// nil-элементы пропускаются. Раньше каждый старт превращал все узлы в «никогда не проверенные».
func TestLoadNodes_PreservesHistory_MergesDuplicates_ClearsExpiredBan(t *testing.T) {
	dir := withTempDataDir(t)
	now := time.Now()
	nodes := []*models.Node{
		{ID: "a", Name: "A", Address: "1.1.1.1", Port: 443, Score: 0.7, Status: models.StatusOK, Latency: 120,
			LastChecked: now.Add(-time.Hour), FailCount: 3,
			LastVerifiedAt: now.Add(-2 * time.Hour).Unix(), VerifiedCount: 2,
			LastFailedAt: now.Add(-3 * time.Hour).Unix(), FailStreak: 1},
		{ID: "b", Name: "B", Address: "2.2.2.2", Port: 443, Status: models.StatusBlacklist, Score: 0.1,
			BlacklistedUntil: now.Add(-time.Hour)},
		{ID: "c", Name: "C", Address: "3.3.3.3", Port: 443, Status: models.StatusBlacklist,
			BlacklistedUntil: now.Add(time.Hour)},
		{ID: "d", Name: "D", Address: "4.4.4.4", Port: 443, VerifiedCount: 1,
			LastVerifiedAt: now.Add(-5 * time.Hour).Unix(), LastVerifiedCountry: "DE"},
		nil,
		{ID: "d", Name: "D-dup", Address: "4.4.4.4", Port: 443, VerifiedCount: 4,
			LastVerifiedAt: now.Add(-time.Hour).Unix(), LastVerifiedCountry: "NL", UserBanned: true},
	}
	data, _ := json.Marshal(nodes)
	if err := os.WriteFile(filepath.Join(dir, "nodes_cache.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	e := newTestEngine()
	if err := e.loadNodes(); err != nil {
		t.Fatalf("loadNodes: %v", err)
	}
	// loadNodes пересчитывает ID по параметрам подключения (миграция схемы 2026-08-24) —
	// ищем по имени; D и D-dup совпадают по адресу/порту и потому схлопываются в один ID.
	e.mu.RLock()
	got := make(map[string]*models.Node)
	for _, n := range e.nodes {
		got[n.Name] = n
	}
	total := len(e.nodes)
	e.mu.RUnlock()

	if total != 4 {
		t.Fatalf("узлов после загрузки %d, want 4 (дубликат и nil убраны): %v", total, ids(e.nodes))
	}
	a := got["A"]
	if a == nil || a.Score != 0.7 || a.LastChecked.IsZero() || a.VerifiedCount != 2 || a.FailStreak != 1 || a.LastVerifiedAt == 0 {
		t.Fatalf("история узла A не сохранена: %+v", a)
	}
	if a.FailCount != 0 {
		t.Errorf("FailCount — сессионный счётчик, должен обнуляться: %d", a.FailCount)
	}
	if b := got["B"]; b == nil || !b.BlacklistedUntil.IsZero() || b.Status != models.StatusUnknown {
		t.Errorf("истёкший бан должен сниматься с починкой Status: %+v", b)
	}
	if c := got["C"]; c == nil || c.BlacklistedUntil.IsZero() || c.Status != models.StatusBlacklist {
		t.Errorf("действующий бан должен остаться: %+v", c)
	}
	if d := got["D"]; d == nil || d.VerifiedCount != 4 || d.LastVerifiedCountry != "NL" || !d.UserBanned {
		t.Errorf("дубликаты должны слиться с максимумом истории: %+v", d)
	}
}

// ─── F1.4: единая шкала и вес протокола при SNI-блокировке ──────────────────────────────

// Инвариант из аудита (BB-2/F-1): при SNI-блокировке VLESS+Reality 200 мс обязан обойти
// plain-VLESS 50 мс; без блокировки быстрый plain-узел выигрывает (веса режима «balanced»).
func TestSelectBestForStrategy_SNIBlockage_PrefersRealityOverFasterPlain(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	now := time.Now()
	reality := &models.Node{ID: "reality", Name: "reality", Protocol: models.ProtoVLESS, Latency: 200,
		Status: models.StatusOK, LastChecked: now,
		TLS: &models.TLSConfig{Enabled: true, Reality: &models.RealityConfig{PublicKey: "pk", ShortID: "s"}}}
	plain := &models.Node{ID: "plain", Name: "plain", Protocol: models.ProtoVLESS, Latency: 50,
		Status: models.StatusOK, LastChecked: now}
	setNodes(e, reality, plain)

	e.setBlockageType(detector.BlockageNone)
	if got := e.selectBestForStrategy(); got == nil || got.ID != "plain" {
		t.Fatalf("без блокировки должен выиграть быстрый plain-узел, got %v", got)
	}
	e.setBlockageType(detector.BlockageSNI)
	if got := e.selectBestForStrategy(); got == nil || got.ID != "reality" {
		t.Fatalf("при SNI-блокировке должен выиграть Reality, got %v (scores: reality=%.3f plain=%.3f)",
			got, reality.Score, plain.Score)
	}
	if reality.Score > 1 || plain.Score > 1 || reality.Score < 0 || plain.Score < 0 {
		t.Errorf("Score вне [0,1]: reality=%.3f plain=%.3f", reality.Score, plain.Score)
	}
}

// ─── F1.5: проверенные — впереди, непроверенные — вон ───────────────────────────────────

// Порядок: proven без последнего сбоя — по свежести×скорости; затем остальные по Score;
// proven с последним сбоем и Score=0 — последним.
func TestSortCandidatesProvenFirst_Ordering(t *testing.T) {
	now := time.Now().Unix()
	unproven := &models.Node{ID: "unproven", Score: 0.95, Status: models.StatusOK}
	fresh := &models.Node{ID: "fresh", Score: 0.2, VerifiedCount: 1, LastVerifiedAt: now - 600, LastVerifiedLatencyMs: 300}
	older := &models.Node{ID: "older", Score: 0.3, VerifiedCount: 5, LastVerifiedAt: now - 30*3600, LastVerifiedLatencyMs: 100}
	failed := &models.Node{ID: "failed", Score: 0, VerifiedCount: 2, LastVerifiedAt: now - 7200, LastFailedAt: now - 60}

	cands := []*models.Node{failed, unproven, fresh, older}
	sortCandidatesProvenFirst(cands, now)
	// older: 0.5 (30 ч) × 1000/100 = 5.0; fresh: 1.0 × 1000/300 = 3.3 → older впереди.
	want := []string{"older", "fresh", "unproven", "failed"}
	if got := ids(cands); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("порядок %v, want %v", got, want)
	}
}

// Фильтр годности: ex, UserBanned, IsUnchecked, recentFailures — вон; мягкий проход возвращает
// недавно отказавшие (для случая «все годные отказали»), но не бан и не непроверенные.
func TestFilterSelectable_ExcludesBannedUncheckedRecentlyFailed(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	ok := &models.Node{ID: "ok", Status: models.StatusOK, Score: 0.5}
	banned := &models.Node{ID: "banned", Status: models.StatusOK, Score: 0.9, UserBanned: true}
	unchecked := &models.Node{ID: "unchecked", Score: 0.9}
	recent := &models.Node{ID: "recent", Status: models.StatusOK, Score: 0.9}
	ex := &models.Node{ID: "ex", Status: models.StatusOK, Score: 0.9}
	all := []*models.Node{banned, unchecked, recent, ex, ok, nil}
	e.markNodeFailed("recent")

	if got := ids(e.filterSelectable(all, ex)); strings.Join(got, ",") != "ok" {
		t.Errorf("строгий фильтр: %v, want [ok]", got)
	}
	if got := ids(e.filterCandidates(all, ex, false)); strings.Join(got, ",") != "recent,ok" {
		t.Errorf("мягкий фильтр: %v, want [recent ok]", got)
	}
}

// Непроверенный узел не выбирается вообще, даже если он единственный (слепое подключение
// запрещено — ND-2); проверенный с нулевым TCP-Score — выбирается.
func TestSelectBest_UncheckedNeverSelected_ProvenWithZeroScoreIs(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	unchecked := &models.Node{ID: "unchecked", Name: "unchecked", Score: 0.9}
	setNodes(e, unchecked)
	if got := e.selectBestExcluding(nil); got != nil {
		t.Fatalf("непроверенный узел не должен выбираться, got %v", got)
	}
	if got := e.selectBestForStrategy(); got != nil {
		t.Fatalf("selectBestForStrategy: непроверенный узел не должен выбираться, got %v", got)
	}

	proven := &models.Node{ID: "proven", Name: "proven", Score: 0, VerifiedCount: 1, LastVerifiedAt: time.Now().Unix()}
	setNodes(e, unchecked, proven)
	if got := e.selectBestExcluding(nil); got == nil || got.ID != "proven" {
		t.Fatalf("проверенный с Score=0 должен выбираться, got %v", got)
	}
}

// Закреплённый узел: пропускается с логом, пока его последнее реальное событие — свежий
// сбой; после окна recentFailureTTL или нового подтверждения — снова выбирается.
func TestSelectBestExcluding_PinSkippedAfterFreshFailure_ReturnsAfterVerify(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	now := time.Now()
	pinned := &models.Node{ID: "pinned", Name: "pinned", Status: models.StatusOK, Score: 0,
		VerifiedCount: 1, LastVerifiedAt: now.Add(-2 * time.Hour).Unix(),
		LastFailedAt: now.Add(-time.Minute).Unix(), LastFailReason: failReasonWatchdog}
	other := &models.Node{ID: "other", Name: "other", Status: models.StatusOK, Score: 0.5}
	setNodes(e, pinned, other)
	e.PinNode("pinned")

	var logs []string
	e.OnLog = func(msg string) { logs = append(logs, msg) }
	if got := e.selectBestExcluding(nil); got == nil || got.ID != "other" {
		t.Fatalf("pin со свежим сбоем должен пропускаться, got %v", got)
	}
	found := false
	for _, l := range logs {
		if strings.Contains(l, "Закреплённый узел") && strings.Contains(l, failReasonWatchdog) {
			found = true
		}
	}
	if !found {
		t.Errorf("пропуск pin должен логироваться с причиной, logs=%v", logs)
	}

	// Сбой старше окна — pin снова в приоритете (иначе он никогда не подтвердился бы заново).
	pinned.LastFailedAt = now.Add(-recentFailureTTL - time.Minute).Unix()
	if got := e.selectBestExcluding(nil); got == nil || got.ID != "pinned" {
		t.Fatalf("pin со старым сбоем должен вернуться, got %v", got)
	}

	// Новое подтверждение — тем более.
	pinned.LastFailedAt = now.Unix()
	e.recordNodeVerified(pinned, 100, "", "")
	if got := e.selectBestExcluding(nil); got == nil || got.ID != "pinned" {
		t.Fatalf("pin после подтверждения должен вернуться, got %v", got)
	}
}
