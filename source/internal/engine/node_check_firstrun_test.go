// node_check_firstrun_test.go — N-6 (ТЗ APF v1.5 §3): первый запуск vs повторный. Детектор —
// СУЩЕСТВУЮЩИЙ (пустой пул → StartNodeCheck Stage 1 синхронно тянет источники, node_check.go);
// новый флаг не вводится (по брифу лота). Тест доказывает интеграцию целиком: fetch → N-2
// (Stage 1 populate + Stage 2 probe) → save-by-N-5, на РЕАЛЬНОЙ (но целиком loopback,
// netguard-safe) подписке + fake-пробере трафика (N-1 seam, тест-безопасно).
package engine

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// TestFirstRun_CatalogBuild_FetchesProbesAndSavesRetained — сценарий N-6 «первый запуск»:
// e.nodes пуст (loadNodes ещё не вызывался — свежий Engine, как после первого старта без кэша),
// cfg.Sources указывает на источник. StartNodeCheck обязан: (1) Stage 1 — увидеть пустой пул и
// синхронно вызвать updateSources (реальный HTTP GET на ЛОКАЛЬНЫЙ httptest-сервер — петля
// разрешена netguard'ом даже под go test); (2) т.к. свежедобавленный узел ещё НЕ проверен по TCP
// (IsUnchecked ⇒ Score=0, не ранжируется), Stage 1 обязан переиспользовать runSweep — и он делает
// РЕАЛЬНЫЙ TCP-connect на другой локальный listener (тоже петля, тоже безопасно); (3) Stage 2 —
// пробует узел через fake e.probeFn (N-1 тест-шов, реального sing-box/сети здесь уже нет); (4)
// итог сохраняется на диск, и подтверждённый узел переживает запись (N-5).
func TestFirstRun_CatalogBuild_FetchesProbesAndSavesRetained(t *testing.T) {
	dir := withTempDataDir(t)
	e := newTestEngine()
	// e.nodes остаётся nil — ровно состояние "первый запуск, loadNodes ещё не было" (N-6).

	// "Живой" TCP-слушатель на петле: checker/runSweep делает ГОЛЫЙ TCP-connect (не VLESS-
	// рукопожатие) — принять и сразу закрыть соединение достаточно, чтобы узел стал "TCP alive".
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi(%q): %v", portStr, err)
	}

	link := fmt.Sprintf("vless://00000000-0000-0000-0000-0000000000f1@%s:%d?security=none&type=tcp#FirstRunNode", host, port)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, link)
	}))
	defer srv.Close()

	e.cfg.Sources = []models.SourceConfig{
		{ID: "first-run-src", Name: "FirstRun", Type: "subscription", Enabled: true, URL: srv.URL},
	}

	e.probeFn = func(ctx context.Context, node *models.Node, slot int) (int64, string, string, error) {
		return 33, "US", "203.0.113.9", nil
	}

	if err := e.StartNodeCheck(NodeCheckOptions{TopN: 30, TargetK: 8, Concurrency: 2, PerNode: 3 * time.Second}); err != nil {
		t.Fatalf("StartNodeCheck: %v", err)
	}
	st := waitNodeCheckDone(t, e, 15*time.Second)

	if st.Phase != "done" {
		t.Fatalf("phase=%q, want done", st.Phase)
	}
	e.mu.RLock()
	poolLen := len(e.nodes)
	e.mu.RUnlock()
	if poolLen == 0 {
		t.Fatal("Stage 1 не подтянул узел из источника — пул остался пуст (N-6 fetch не сработал)")
	}
	if st.Verified == 0 {
		t.Fatalf("verified=0 (probed=%d) — первый запуск не довёл узел из источника до пробы N-2/N-1", st.Probed)
	}

	// N-5: подтверждённый пробой узел обязан пережить запись на диск (первый успешный прогон
	// каталога — это как раз момент, когда proven-набор впервые появляется).
	saved := readNodesCache(t, dir)
	verifiedOnDisk := false
	for _, n := range saved {
		if n.LastVerifiedAt != 0 && n.LastVerifiedVia == models.VerifiedViaSOCKS {
			verifiedOnDisk = true
		}
	}
	if !verifiedOnDisk {
		t.Fatalf("подтверждённый первым запуском узел не найден на диске (N-5): %v", keysOf(saved))
	}
}

// TestFirstRun_EmptyCacheFileBehavesAsFirstRun — N-6 «пользователь удалил кэш вручную»: файл
// nodes_cache.json существует, но это пустой массив (ровно то, что пишет N-5 в крайнем случае) —
// loadNodes не должен ошибаться, а пул после загрузки пуст, что и есть корректное поведение
// первого запуска (детектор в runPoolScan/StartNodeCheck сработает на пустой пул естественно).
func TestFirstRun_EmptyCacheFileBehavesAsFirstRun(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	setNodes(e) // пул пуст
	if err := e.saveNodesToDisk(); err != nil {
		t.Fatalf("saveNodesToDisk: %v", err)
	}

	e2 := newTestEngine()
	if err := e2.loadNodes(); err != nil {
		t.Fatalf("loadNodes на пустом кэше вернул ошибку: %v (должен вести себя как первый запуск)", err)
	}
	e2.mu.RLock()
	n := len(e2.nodes)
	e2.mu.RUnlock()
	if n != 0 {
		t.Fatalf("пул после загрузки пустого кэша = %d, want 0", n)
	}
}
