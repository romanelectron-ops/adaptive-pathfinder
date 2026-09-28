// sources_k2e_torbridges_test.go — К2-E П8 (свод C, трек 1 №8; A4 + F1, два независимых
// подтверждения).
//
// Дефект: fetchTorBridges ВСЕГДА возвращала err=nil и НЕ разбирала тело ответа. На каждый URL
// (успешный запрос — любой, включая 500) создавался один узел-заглушка "Tor Bridge" без
// Address и Port, который ValidateNode отвергает (models/validate.go:86, NL-10). То есть
// источник, включённый в конфигурации по умолчанию, не мог дать ни одного пригодного узла ни
// при каком ответе сервера — и при этом никогда не сообщал об ошибке.
package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

func withTorURLs(t *testing.T, urls ...string) {
	t.Helper()
	orig := torBridgeURLs
	torBridgeURLs = urls
	t.Cleanup(func() { torBridgeURLs = orig })
}

// TestK2E_FetchTorBridges_HTTP500_ReturnsError — отказ HTTP больше не выглядит успехом.
func TestK2E_FetchTorBridges_HTTP500_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	withTorURLs(t, srv.URL)

	nodes, err := New(&models.AppConfig{}).fetchTorBridges(context.Background())
	if err == nil {
		t.Fatalf("HTTP 500 — ожидалась ошибка, получено err=nil, nodes=%d", len(nodes))
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("ошибка должна называть код ответа: %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("при отказе узлы возвращаться не должны, получено %d", len(nodes))
	}
	t.Logf("OK: 500 → %v", err)
}

// TestK2E_FetchTorBridges_EmptyBody_ReturnsError — пустой ответ 200 тоже отказ: мостов нет.
func TestK2E_FetchTorBridges_EmptyBody_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	withTorURLs(t, srv.URL)

	nodes, err := New(&models.AppConfig{}).fetchTorBridges(context.Background())
	if err == nil {
		t.Fatalf("пустое тело — ожидалась ошибка, получено err=nil, nodes=%d", len(nodes))
	}
	if len(nodes) != 0 {
		t.Errorf("при пустом ответе узлы возвращаться не должны, получено %d", len(nodes))
	}
	t.Logf("OK: пустое тело → %v", err)
}

// TestK2E_FetchTorBridges_GarbageBody_ReturnsError — 200 с текстом, где нет ни одной
// bridge-строки (страница капчи, HTML-заглушка), — это тоже «мостов не получено».
func TestK2E_FetchTorBridges_GarbageBody_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>Please solve the captcha</body></html>"))
	}))
	defer srv.Close()
	withTorURLs(t, srv.URL)

	if _, err := New(&models.AppConfig{}).fetchTorBridges(context.Background()); err == nil {
		t.Fatal("тело без bridge-строк — ожидалась ошибка")
	} else {
		t.Logf("OK: мусорное тело → %v", err)
	}
}

// TestK2E_FetchTorBridges_ParsesBody — тело РАЗБИРАЕТСЯ: сколько мостов в ответе, столько и
// узлов, с настоящими адресом и портом (иначе ValidateNode отвергнет узел, NL-10).
func TestK2E_FetchTorBridges_ParsesBody(t *testing.T) {
	body := strings.Join([]string{
		"# комментарий брокера",
		"",
		"obfs4 1.2.3.4:1234 2B280B23E1107BB62ABFC40DDCC8824814F80A72 cert=abc iat-mode=0",
		"obfs4 5.6.7.8:5678 AAAABBBBCCCCDDDDEEEEFFFF0000111122223333 cert=def iat-mode=0",
		"9.9.9.9:9001 FFFFEEEEDDDDCCCCBBBBAAAA9999888877776666",
		"не мост вовсе",
	}, "\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()
	withTorURLs(t, srv.URL)

	nodes, err := New(&models.AppConfig{}).fetchTorBridges(context.Background())
	if err != nil {
		t.Fatalf("корректный ответ — ошибки быть не должно: %v", err)
	}
	if len(nodes) != 3 {
		t.Fatalf("ожидалось 3 разобранных моста, получено %d", len(nodes))
	}
	for _, n := range nodes {
		if n.Address == "" || n.Port == 0 {
			t.Fatalf("узел без адреса/порта — ValidateNode его отвергнет (NL-10): %+v", n)
		}
		if n.Protocol != models.ProtoTor {
			t.Errorf("Protocol = %q, want %q", n.Protocol, models.ProtoTor)
		}
		if n.Source != "tor-bridges" {
			t.Errorf("Source = %q, want %q", n.Source, "tor-bridges")
		}
		if err := models.ValidateNode(n); err != nil {
			t.Errorf("разобранный мост не проходит ValidateNode: %v (%+v)", err, n)
		}
	}
	if nodes[0].Address != "1.2.3.4" || nodes[0].Port != 1234 {
		t.Errorf("первый мост разобран неверно: %s:%d", nodes[0].Address, nodes[0].Port)
	}
	if nodes[2].Address != "9.9.9.9" || nodes[2].Port != 9001 {
		t.Errorf("vanilla-мост разобран неверно: %s:%d", nodes[2].Address, nodes[2].Port)
	}
	t.Logf("OK: разобрано %d мостов", len(nodes))
}

// TestK2E_FetchTorBridges_IDsStable — ID моста выводится из адреса, а не из time.Now():
// повторная загрузка того же источника не должна плодить дубликаты в пуле.
func TestK2E_FetchTorBridges_IDsStable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("obfs4 1.2.3.4:1234 2B280B23E1107BB62ABFC40DDCC8824814F80A72 cert=abc\n"))
	}))
	defer srv.Close()
	withTorURLs(t, srv.URL)

	mgr := New(&models.AppConfig{})
	first, err := mgr.fetchTorBridges(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := mgr.fetchTorBridges(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("ожидалось по одному мосту, получено %d и %d", len(first), len(second))
	}
	if first[0].ID != second[0].ID {
		t.Fatalf("ID моста нестабилен между загрузками: %q vs %q", first[0].ID, second[0].ID)
	}
	t.Logf("OK: стабильный ID %q", first[0].ID)
}

// TestK2E_FetchTorBridges_PartialSuccess — один источник упал, второй отдал мост: это успех,
// ошибка не поднимается, мост возвращается.
func TestK2E_FetchTorBridges_PartialSuccess(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("snowflake 2.2.2.2:222 AAAABBBBCCCCDDDDEEEEFFFF0000111122223333 url=x\n"))
	}))
	defer good.Close()
	withTorURLs(t, bad.URL, good.URL)

	nodes, err := New(&models.AppConfig{}).fetchTorBridges(context.Background())
	if err != nil {
		t.Fatalf("частичный успех не должен быть ошибкой: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("ожидался 1 мост от живого источника, получено %d", len(nodes))
	}
	t.Log("OK: частичный успех")
}
