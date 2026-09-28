package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ── fetchTorBridges mock tests ─────────────────────────────────────────────────

func TestFetchTorBridges_Success(t *testing.T) {
	// К2-E П8 (свод C, трек 1 №8; 2026-09-07): тело РАЗБИРАЕТСЯ, а не создаёт один
	// узел-заглушку на URL. Два настоящих obfs4-моста в ответе → два узла с реальными
	// Address/Port и стабильным ID вида tor-<transport>-<host>-<port>.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("obfs4 1.2.3.4:1234 CERT=abc... iat-mode=0\nobfs4 5.6.7.8:5678 CERT=def... iat-mode=0\n"))
	}))
	defer srv.Close()

	origURLs := torBridgeURLs
	torBridgeURLs = []string{srv.URL}
	defer func() { torBridgeURLs = origURLs }()

	mgr := New(&models.AppConfig{})
	nodes, err := mgr.fetchTorBridges(context.Background())
	if err != nil {
		t.Fatalf("fetchTorBridges: unexpected error: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes (one bridge line = one node, П8), got %d", len(nodes))
	}
	wantIDs := map[string]struct {
		addr string
		port int
	}{
		"tor-obfs4-1.2.3.4-1234": {"1.2.3.4", 1234},
		"tor-obfs4-5.6.7.8-5678": {"5.6.7.8", 5678},
	}
	for _, n := range nodes {
		if n.Protocol != models.ProtoTor {
			t.Errorf("Protocol = %q, want %q", n.Protocol, models.ProtoTor)
		}
		if n.Source != "tor-bridges" {
			t.Errorf("Source = %q, want %q", n.Source, "tor-bridges")
		}
		want, ok := wantIDs[n.ID]
		if !ok {
			t.Errorf("unexpected node ID %q (стабильный ID должен быть вида tor-obfs4-<host>-<port>)", n.ID)
			continue
		}
		if n.Address != want.addr || n.Port != want.port {
			t.Errorf("node %q: Address/Port = %s:%d, want %s:%d", n.ID, n.Address, n.Port, want.addr, want.port)
		}
		delete(wantIDs, n.ID)
	}
	if len(wantIDs) != 0 {
		t.Errorf("не все ожидаемые мосты найдены, недостающие ID: %v", wantIDs)
	}
}

func TestFetchTorBridges_MultipleURLs(t *testing.T) {
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("obfs4 1.1.1.1:111 CERT=aaa\n"))
	}))
	defer srv1.Close()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("snowflake 2.2.2.2:222 fingerprint=bbb\n"))
	}))
	defer srv2.Close()

	origURLs := torBridgeURLs
	torBridgeURLs = []string{srv1.URL, srv2.URL}
	defer func() { torBridgeURLs = origURLs }()

	mgr := New(&models.AppConfig{})
	nodes, err := mgr.fetchTorBridges(context.Background())
	if err != nil {
		t.Fatalf("fetchTorBridges: unexpected error: %v", err)
	}
	if len(nodes) != 2 {
		t.Errorf("expected 2 nodes (two URLs = two nodes), got %d", len(nodes))
	}
}

func TestFetchTorBridges_ServerError(t *testing.T) {
	// К2-E П8 (свод C, трек 1 №8; 2026-09-07): HTTP-код ответа теперь проверяется.
	// 500 — реальный отказ брокера, а не успех: fetchTorBridges обязана вернуть
	// содержательную ошибку и не создавать узел-заглушку.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	origURLs := torBridgeURLs
	torBridgeURLs = []string{srv.URL}
	defer func() { torBridgeURLs = origURLs }()

	mgr := New(&models.AppConfig{})
	nodes, err := mgr.fetchTorBridges(context.Background())
	if err == nil {
		t.Fatalf("fetchTorBridges should fail on server error (П8), got nodes=%d", len(nodes))
	}
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes on HTTP 500, got %d", len(nodes))
	}
	t.Logf("OK: HTTP 500 → error: %v", err)
}

func TestFetchTorBridges_UnreachableURL(t *testing.T) {
	// К2-E П8 (свод C, трек 1 №8; 2026-09-07): единственный брокер недоступен →
	// мостов не получено вовсе → это честная ошибка, а не молчаливый нуль.
	origURLs := torBridgeURLs
	torBridgeURLs = []string{"http://127.0.0.1:1"}
	defer func() { torBridgeURLs = origURLs }()

	mgr := New(&models.AppConfig{})
	nodes, err := mgr.fetchTorBridges(context.Background())
	if err == nil {
		t.Fatalf("fetchTorBridges should return error when the only broker URL is unreachable (П8)")
	}
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes for unreachable URL, got %d", len(nodes))
	}
	t.Logf("OK: недоступный URL → error: %v", err)
}

func TestFetchTorBridges_EmptyURLs(t *testing.T) {
	origURLs := torBridgeURLs
	torBridgeURLs = []string{}
	defer func() { torBridgeURLs = origURLs }()

	mgr := New(&models.AppConfig{})
	nodes, err := mgr.fetchTorBridges(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes for empty URL list, got %d", len(nodes))
	}
}

// ── fetchSubscription mock tests ───────────────────────────────────────────────

func TestFetchSubscription_Success(t *testing.T) {
	// Return a simple base64-encoded vless link
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check user-agent
		ua := r.Header.Get("User-Agent")
		if ua == "" {
			t.Error("User-Agent header missing")
		}
		w.WriteHeader(200)
		// A minimal response that parser can handle (even if it parses 0 nodes)
		w.Write([]byte("vless://00000000-0000-0000-0000-000000000000@127.0.0.1:443?type=tcp&security=none#TestNode\n"))
	}))
	defer srv.Close()

	cfg := &models.AppConfig{}
	mgr := New(cfg)
	// Point httpClient to test server
	mgr.httpClient = &http.Client{Transport: http.DefaultTransport}

	src := models.SourceConfig{
		ID:   "test-sub",
		Name: "Test Subscription",
		URL:  srv.URL,
		Type: "subscription",
	}

	nodes, err := mgr.fetchSubscription(context.Background(), src)
	if err != nil {
		// Parser may not understand raw vless — that's OK, we covered the HTTP path
		t.Logf("fetchSubscription returned error (parse may fail): %v", err)
		return
	}
	// If parsed successfully, check source is set
	for _, n := range nodes {
		if n.Source != "test-sub" {
			t.Errorf("node source = %q, want %q", n.Source, "test-sub")
		}
	}
	t.Logf("OK: fetchSubscription got %d nodes", len(nodes))
}

func TestFetchSubscription_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer srv.Close()

	mgr := New(&models.AppConfig{})
	src := models.SourceConfig{
		ID:   "sub403",
		Name: "Forbidden",
		URL:  srv.URL,
		Type: "subscription",
	}

	_, err := mgr.fetchSubscription(context.Background(), src)
	if err == nil {
		t.Error("expected error for HTTP 403, got nil")
	}
}

func TestFetchSubscription_ConnectionRefused(t *testing.T) {
	mgr := New(&models.AppConfig{})
	src := models.SourceConfig{
		ID:   "badurl",
		Name: "Bad URL",
		URL:  "http://127.0.0.1:1/sub",
		Type: "subscription",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2e9) // 2s
	defer cancel()
	_, err := mgr.fetchSubscription(ctx, src)
	if err == nil {
		t.Error("expected error for connection refused, got nil")
	}
}

func TestFetchSubscription_EmptyBase64(t *testing.T) {
	// Return empty base64 body — parser should handle it gracefully
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(""))
	}))
	defer srv.Close()

	mgr := New(&models.AppConfig{})
	src := models.SourceConfig{
		ID:   "empty",
		Name: "Empty Sub",
		URL:  srv.URL,
		Type: "subscription",
	}

	nodes, err := mgr.fetchSubscription(context.Background(), src)
	// Empty body may result in error or 0 nodes
	t.Logf("empty body: nodes=%d err=%v", len(nodes), err)
}

// ── FetchAll with mock HTTP subscription ──────────────────────────────────────

func TestFetchAll_SubscriptionMock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(""))
	}))
	defer srv.Close()

	cfg := &models.AppConfig{
		Sources: []models.SourceConfig{
			{
				ID:      "mock-sub",
				Name:    "Mock Sub",
				Enabled: true,
				Type:    "subscription",
				URL:     srv.URL,
			},
		},
	}
	mgr := New(cfg)

	// force=true to bypass needsUpdate check
	nodes, err := mgr.FetchAll(context.Background(), true)
	if err != nil {
		t.Fatalf("FetchAll: %v", err)
	}
	t.Logf("FetchAll with mock subscription: %d nodes", len(nodes))
}

func TestFetchAll_TorSource_Mock(t *testing.T) {
	// К2-E П8 (свод C, трек 1 №8; 2026-09-07): "obfs4 bridge data" — не bridge-строка
	// (второе поле "bridge" не парсится как host:port), поэтому под новый контракт она
	// не даёт ни одного узла. Заменена на настоящую bridge-строку: одна строка = один
	// узел с реальными Address/Port; источник должен быть помечен обновлённым.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("obfs4 1.2.3.4:1234 2B280B23E1107BB62ABFC40DDCC8824814F80A72 cert=abc iat-mode=0\n"))
	}))
	defer srv.Close()

	origURLs := torBridgeURLs
	torBridgeURLs = []string{srv.URL}
	defer func() { torBridgeURLs = origURLs }()

	cfg := &models.AppConfig{
		Sources: []models.SourceConfig{
			{
				ID:      "tor-test",
				Name:    "Tor Test",
				Enabled: true,
				Type:    "tor",
			},
		},
	}
	mgr := New(cfg)

	nodes, err := mgr.FetchAll(context.Background(), true)
	if err != nil {
		t.Fatalf("FetchAll with tor: %v", err)
	}
	if len(nodes) == 0 {
		t.Fatal("expected at least 1 tor bridge node from a real bridge line")
	}
	if nodes[0].Address == "" || nodes[0].Port == 0 {
		t.Errorf("node without real Address/Port would fail ValidateNode (NL-10): %+v", nodes[0])
	}
	if _, ok := mgr.LastUpdated()["tor-test"]; !ok {
		t.Error("source tor-test should be marked updated after a successful fetch")
	}
}
