package catalog

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// B-11 (дефект D9) — метаданные провайдера вычисляются из факта загрузки, а не
// захардкожены. TrustScore зависит от числа узлов; SpeedClass — от протоколов.

// trustFromNodeCount: монотонность и границы.
func TestTrustFromNodeCount(t *testing.T) {
	if trustFromNodeCount(0) != 0 {
		t.Error("0 узлов → trust 0")
	}
	if got := trustFromNodeCount(5); got < 0.2 {
		t.Errorf("непустой источник → trust >= 0.2, got %v", got)
	}
	if got := trustFromNodeCount(1000); got != 1.0 {
		t.Errorf("много узлов → trust насыщается до 1.0, got %v", got)
	}
	// монотонность
	if trustFromNodeCount(10) >= trustFromNodeCount(150) {
		t.Error("trust должен расти с числом узлов")
	}
}

// speedClassFromNodes: классификация по доминирующему протоколу.
func TestSpeedClassFromNodes(t *testing.T) {
	if speedClassFromNodes(nil) != "unknown" {
		t.Error("пустой список → unknown")
	}
}

// Интеграция: после реальной загрузки (mock HTTP) метаданные отражают факт,
// а не стартовые константы (Region=global/Speed=variable/Trust=0.5).
func TestFreeProvider_MetaReflectsFetch(t *testing.T) {
	// отдаём подписку из 3 vless-ссылок
	body := strings.Join([]string{
		"vless://11111111-1111-1111-1111-111111111111@1.1.1.1:443?security=reality&pbk=a#n1",
		"vless://22222222-2222-2222-2222-222222222222@2.2.2.2:443?security=reality&pbk=b#n2",
		"vless://33333333-3333-3333-3333-333333333333@3.3.3.3:443?security=reality&pbk=c#n3",
	}, "\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	p := NewFreeProvider("test", "Test", srv.URL)
	before := p.Meta()
	if before.TrustScore != 0.5 {
		t.Logf("стартовый TrustScore=%v", before.TrustScore)
	}

	nodes, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(nodes) != 3 {
		t.Fatalf("ожидалось 3 узла, got %d", len(nodes))
	}

	after := p.Meta()
	if after.NodeCount != 3 {
		t.Errorf("NodeCount=%d, want 3", after.NodeCount)
	}
	if after.LastUpdated.IsZero() {
		t.Error("LastUpdated должен быть выставлен")
	}
	if after.TrustScore <= 0 {
		t.Errorf("TrustScore должен вычисляться из факта (>0), got %v", after.TrustScore)
	}
	if after.SpeedClass == "" || after.SpeedClass == "variable" {
		// 3 reality-узла → fast
		if after.SpeedClass != "fast" {
			t.Errorf("SpeedClass для reality-узлов ожидался fast, got %q", after.SpeedClass)
		}
	}
}

// -race: параллельный Fetch (пишет meta) и Meta() (читает) не должны давать гонку.
func TestFreeProvider_ConcurrentMetaAccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "vless://44444444-4444-4444-4444-444444444444@4.4.4.4:443?security=reality&pbk=d#n")
	}))
	defer srv.Close()

	p := NewFreeProvider("test", "Test", srv.URL)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = p.Fetch(context.Background()) }()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = p.Meta()
			}
		}()
	}
	wg.Wait()
}
