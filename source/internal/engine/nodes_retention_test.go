// nodes_retention_test.go — N-5 (ТЗ APF v1.5 §3, C9/C10/C11) тесты политики удержания пула.
// Матрица кейсов соответствует result.json.retention_edge_cases и брифу лота L1-ENG-B: ноль
// proven (удерживает manual); proven-stale (дропается); pinned-TCP-only (удерживается);
// favorite-TCP-only (удерживается); manual-dead (удерживается); chain-partner (удерживается);
// шифрование ПОСЛЕ фильтра; отсутствие tombstone у отфильтрованных.
package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apfcrypto "github.com/apf/adaptive-pathfinder/internal/crypto"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── retainNodeForDisk / filterNodesForRetention — чистая функция, табличный тест ───────────

// TestRetention_FilterMatrix — исчерпывающая матрица retainNodeForDisk (N-5 §3): каждая строка —
// один из независимых критериев ИЛИ их отсутствие. now фиксировано, чтобы VerifyStale считался
// детерминированно (models.VerifyStaleAfter = 24h, node.go:260).
func TestRetention_FilterMatrix(t *testing.T) {
	now := time.Now().Unix()
	fresh := now - int64(2*time.Hour/time.Second)                      // подтверждён 2ч назад — свежо
	stale := now - int64((models.VerifyStaleAfter+time.Hour)/time.Second) // подтверждён 25ч назад — протухло

	tests := []struct {
		name        string
		node        *models.Node
		pinnedID    string
		favoriteIDs map[string]bool
		want        bool
	}{
		{
			name: "zero-proven keeps manual",
			node: &models.Node{ID: "m1", Source: "manual"},
			want: true,
		},
		{
			name: "manual-dead kept (провалившийся ручной узел всё равно удерживается)",
			node: &models.Node{ID: "m2", Source: "manual", LastFailedAt: now, LastFailReason: "probe", FailStreak: 5},
			want: true,
		},
		{
			name: "chain-partner kept",
			node: &models.Node{ID: "cp1", IsChainPartner: true},
			want: true,
		},
		{
			name: "proven-fresh kept",
			node: &models.Node{ID: "pf1", VerifiedCount: 1, LastVerifiedAt: fresh},
			want: true,
		},
		{
			name: "proven-stale dropped (протухло, не manual/pin/favorite)",
			node: &models.Node{ID: "ps1", VerifiedCount: 1, LastVerifiedAt: stale},
			want: false,
		},
		{
			name:     "pinned-TCP-only kept (не proven, но закреплён)",
			node:     &models.Node{ID: "pin1", Status: models.StatusOK, Latency: 20},
			pinnedID: "pin1",
			want:     true,
		},
		{
			name:        "favorite-TCP-only kept (не proven, но избранный)",
			node:        &models.Node{ID: "fav1", Status: models.StatusOK, Latency: 20},
			favoriteIDs: map[string]bool{"fav1": true},
			want:        true,
		},
		{
			name: "plain TCP-only, ничем не отмечен — dropped",
			node: &models.Node{ID: "plain1", Status: models.StatusOK, Latency: 20},
			want: false,
		},
		{
			name: "proven-fresh но UserBanned — IsProven()=false, ничем другим не отмечен — dropped",
			node: &models.Node{ID: "banned1", VerifiedCount: 1, LastVerifiedAt: fresh, UserBanned: true},
			want: false,
		},
		{
			name: "pin по ДРУГОМУ id — не совпадает — dropped",
			node: &models.Node{ID: "notpinned1", Status: models.StatusOK},
			pinnedID: "someone-else",
			want:     false,
		},
		{
			name: "nil node — false, не паникует",
			node: nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fav := tt.favoriteIDs
			if fav == nil {
				fav = map[string]bool{}
			}
			got := retainNodeForDisk(tt.node, now, tt.pinnedID, fav)
			if got != tt.want {
				t.Errorf("retainNodeForDisk(%+v) = %v, want %v", tt.node, got, tt.want)
			}
		})
	}
}

// TestRetention_FilterNodesForRetention_EmptyIsNonNil — filterNodesForRetention всегда
// возвращает НЕ nil (даже для пустого входа/результата), чтобы json.MarshalIndent дал "[]", а не
// "null" (§3 N-5 крайний случай: пустой удерживаемый набор → пустой массив, не null).
func TestRetention_FilterNodesForRetention_EmptyIsNonNil(t *testing.T) {
	got := filterNodesForRetention(nil, time.Now().Unix(), "", nil)
	if got == nil {
		t.Fatal("filterNodesForRetention(nil, ...) вернул nil — MarshalIndent даст null, не []")
	}
	if len(got) != 0 {
		t.Fatalf("len=%d, want 0", len(got))
	}

	dropped := []*models.Node{{ID: "x", Status: models.StatusOK}}
	got2 := filterNodesForRetention(dropped, time.Now().Unix(), "", nil)
	if got2 == nil || len(got2) != 0 {
		t.Fatalf("filterNodesForRetention с одним droppable узлом: got=%v, want non-nil empty slice", got2)
	}
}

// ─── saveNodesToDisk — интеграционные тесты через Engine ────────────────────────────────────

// mixedRetentionPool строит пул со ВСЕМИ категориями N-5 сразу: manual (a), chain-partner (b),
// pinned-TCP-only (c), favorite-TCP-only (d), proven-fresh (e), proven-stale (f, ДОЛЖЕН быть
// отфильтрован), plain-TCP-only без отметок (g, ДОЛЖЕН быть отфильтрован). Возвращает пул и ID
// закреплённого/избранного узла для настройки движка вызывающим.
func mixedRetentionPool(now time.Time) (nodes []*models.Node, pinID, favID string) {
	nowUnix := now.Unix()
	stale := nowUnix - int64((models.VerifyStaleAfter+time.Hour)/time.Second)
	fresh := nowUnix - int64(time.Hour/time.Second)
	a := &models.Node{ID: "manual-a", Name: "manual-a", Source: "manual", Status: models.StatusOK}
	b := &models.Node{ID: "chain-b", Name: "chain-b", IsChainPartner: true, Status: models.StatusOK}
	c := &models.Node{ID: "pinned-c", Name: "pinned-c", Status: models.StatusOK, Latency: 20}
	d := &models.Node{ID: "favorite-d", Name: "favorite-d", Status: models.StatusOK, Latency: 20}
	e := &models.Node{ID: "proven-e", Name: "proven-e", VerifiedCount: 2, LastVerifiedAt: fresh, Status: models.StatusOK}
	f := &models.Node{ID: "stale-f", Name: "stale-f", VerifiedCount: 1, LastVerifiedAt: stale, Status: models.StatusOK}
	g := &models.Node{ID: "plain-g", Name: "plain-g", Status: models.StatusOK, Latency: 20}
	return []*models.Node{a, b, c, d, e, f, g}, c.ID, d.ID
}

// TestRetention_SaveNodesToDiskAppliesFilterAndKeepsMemoryFull — AC-3: после saveNodesToDisk на
// диске остаются РОВНО узлы N-5 (manual/chain-partner/pinned/favorite/proven-fresh); proven-stale
// и plain-TCP-only отсутствуют. In-memory e.nodes (§3 "e.nodes остаётся ПОЛНЫМ") — не тронут,
// длина и состав те же, что до сохранения (сканирование/выбор пула не должны терять узлов).
func TestRetention_SaveNodesToDiskAppliesFilterAndKeepsMemoryFull(t *testing.T) {
	dir := withTempDataDir(t)
	e := newTestEngine()
	now := time.Now()
	nodes, pinID, favID := mixedRetentionPool(now)
	setNodes(e, nodes...)
	e.PinNode(pinID)
	if err := e.AddFavorite(favID); err != nil {
		t.Fatalf("AddFavorite: %v", err)
	}

	beforeLen := len(nodes)
	if err := e.saveNodesToDisk(); err != nil {
		t.Fatalf("saveNodesToDisk: %v", err)
	}

	// In-memory пул НЕ пострадал.
	e.mu.RLock()
	afterLen := len(e.nodes)
	e.mu.RUnlock()
	if afterLen != beforeLen {
		t.Fatalf("e.nodes в памяти изменился после saveNodesToDisk: было %d, стало %d (фильтр обязан быть write-only)",
			beforeLen, afterLen)
	}

	saved := readNodesCache(t, dir)
	wantKept := []string{"manual-a", "chain-b", "pinned-c", "favorite-d", "proven-e"}
	wantDropped := []string{"stale-f", "plain-g"}
	for _, id := range wantKept {
		if saved[id] == nil {
			t.Errorf("узел %q должен быть удержан (N-5), но отсутствует на диске: %v", id, keysOf(saved))
		}
	}
	for _, id := range wantDropped {
		if saved[id] != nil {
			t.Errorf("узел %q должен быть отфильтрован (N-5), но найден на диске", id)
		}
	}
	if len(saved) != len(wantKept) {
		t.Errorf("на диске %d узлов, want %d (%v): %v", len(saved), len(wantKept), wantKept, keysOf(saved))
	}
}

// TestRetention_NoTombstoneForDropped — C11/O10: отфильтрованным узлам НЕ ставится надгробие.
// Проверяем НАПРЯМУЮ по сырым байтам файла: ID отфильтрованного узла не встречается вообще нигде
// (ни как полноценная запись, ни как маркер вида {"id":"stale-f","deleted":true} или похожий) —
// он просто отсутствует, а не отмечен удалённым.
func TestRetention_NoTombstoneForDropped(t *testing.T) {
	dir := withTempDataDir(t)
	e := newTestEngine()
	now := time.Now()
	nodes, pinID, favID := mixedRetentionPool(now)
	setNodes(e, nodes...)
	e.PinNode(pinID)
	if err := e.AddFavorite(favID); err != nil {
		t.Fatalf("AddFavorite: %v", err)
	}
	if err := e.saveNodesToDisk(); err != nil {
		t.Fatalf("saveNodesToDisk: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "nodes_cache.json"))
	if err != nil {
		t.Fatalf("чтение кэша: %v", err)
	}
	for _, id := range []string{"stale-f", "plain-g"} {
		if strings.Contains(string(raw), id) {
			t.Errorf("ID отфильтрованного узла %q встречается в сыром файле — похоже на надгробие вместо чистого отсутствия", id)
		}
	}
}

// TestRetention_EmptyRetainedWritesEmptyArray — крайний случай §3 N-5: удерживаемый набор пуст →
// пишется ПУСТОЙ МАССИВ (не отказ записи, не null) — следующий старт корректно ведёт себя как
// первый запуск (N-6, re-fetch путь).
func TestRetention_EmptyRetainedWritesEmptyArray(t *testing.T) {
	dir := withTempDataDir(t)
	e := newTestEngine()
	// Только droppable узлы: ни proven-fresh, ни manual/chain-partner, ни pin/favorite.
	setNodes(e,
		&models.Node{ID: "d1", Status: models.StatusOK, Latency: 20},
		&models.Node{ID: "d2", Status: models.StatusOK, Latency: 30},
	)

	if err := e.saveNodesToDisk(); err != nil {
		t.Fatalf("saveNodesToDisk: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "nodes_cache.json"))
	if err != nil {
		t.Fatalf("чтение кэша: %v", err)
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed != "[]" {
		t.Fatalf("содержимое файла = %q, want \"[]\" (пустой массив, не null/отказ)", trimmed)
	}

	// Контроль: loadNodes на пустом массиве не ошибается и даёт пустой пул — ведёт себя как
	// первый запуск (N-6).
	e2 := newTestEngine()
	if err := e2.loadNodes(); err != nil {
		t.Fatalf("loadNodes на пустом массиве вернул ошибку: %v (должен вести себя как первый запуск)", err)
	}
	e2.mu.RLock()
	n := len(e2.nodes)
	e2.mu.RUnlock()
	if n != 0 {
		t.Fatalf("после загрузки пустого массива в пуле %d узлов, want 0", n)
	}
}

// TestRetention_EncryptionAppliesAfterFilter — фильтр применяется ДО шифрования (порядок в
// saveNodesToDisk: filterNodesForRetention → MarshalIndent → Encrypt). Расшифровав файл, должны
// увидеть РОВНО удержанный набор — ни больше (отфильтрованные не "просочились" в шифртекст), ни
// меньше.
func TestRetention_EncryptionAppliesAfterFilter(t *testing.T) {
	dir := withTempDataDir(t)
	e := newTestEngine()
	e.SetMasterPassword("retention-test-pw")
	if e.cryptoStore == nil {
		t.Skip("cryptoStore is nil — cannot exercise encrypted path")
	}
	now := time.Now()
	nodes, pinID, favID := mixedRetentionPool(now)
	setNodes(e, nodes...)
	e.PinNode(pinID)
	if err := e.AddFavorite(favID); err != nil {
		t.Fatalf("AddFavorite: %v", err)
	}

	if err := e.saveNodesToDisk(); err != nil {
		t.Fatalf("saveNodesToDisk: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "nodes_cache.json"))
	if err != nil {
		t.Fatalf("чтение кэша: %v", err)
	}
	if !apfcrypto.IsEncrypted(raw) {
		t.Fatal("файл не зашифрован, хотя мастер-пароль установлен")
	}
	plain, err := e.cryptoStore.Decrypt(raw)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	var got []*models.Node
	if err := json.Unmarshal(plain, &got); err != nil {
		t.Fatalf("расшифрованное содержимое не разбирается: %v", err)
	}
	byID := make(map[string]bool, len(got))
	for _, n := range got {
		if n != nil {
			byID[n.ID] = true
		}
	}
	for _, id := range []string{"manual-a", "chain-b", "pinned-c", "favorite-d", "proven-e"} {
		if !byID[id] {
			t.Errorf("зашифрованный кэш должен содержать удержанный узел %q, не нашёл среди %v", id, got)
		}
	}
	for _, id := range []string{"stale-f", "plain-g"} {
		if byID[id] {
			t.Errorf("зашифрованный кэш содержит отфильтрованный узел %q — фильтр применился ПОСЛЕ шифрования?", id)
		}
	}
}

// keysOf — вспомогательное для читаемых сообщений об ошибке.
func keysOf(m map[string]*models.Node) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
