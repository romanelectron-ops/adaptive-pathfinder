// sources_v14_test.go — лот L1b-ENG2 ТЗ v1.4: C-7.
//
// Канал поставки узлов — два семейства хостов, и оба тянутся МИМО туннеля даже в
// proxy-режиме. В «худший день» пул мёртв, и обновить его неоткуда: по вердикту эксперта по
// DPI это острее, чем отсутствие Tor.
package sources

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// v14Subscription — локальная подписка с одной валидной ссылкой (петля: netguard пропускает).
func v14Subscription(t *testing.T) (string, models.SourceConfig) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=reality&pbk=k&sni=a.b#N1\n"))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, models.SourceConfig{ID: "v14", Name: "v14", Type: "subscription", URL: srv.URL, Enabled: true}
}

// ─── C-7 п.2: подписки в proxy-режиме идут через локальный SOCKS движка ──────

// TestV14_C7_SubscriptionUsesTunnelDialerWhenConnected — главный тест пункта.
func TestV14_C7_SubscriptionUsesTunnelDialerWhenConnected(t *testing.T) {
	_, src := v14Subscription(t)
	m := New(&models.AppConfig{Sources: []models.SourceConfig{src}})

	var calls int
	m.SetTunnelProxy(func() (string, bool) { return "127.0.0.1:10808", true })
	m.socksDial = func(ctx context.Context, proxyAddr, targetAddr string, timeout time.Duration) (net.Conn, error) {
		calls++
		if proxyAddr != "127.0.0.1:10808" {
			t.Errorf("диалер получил чужой адрес прокси: %q", proxyAddr)
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", targetAddr) // «туннель» ведёт прямо в httptest
	}

	nodes, err := m.FetchAll(context.Background(), true)
	if err != nil {
		t.Fatalf("FetchAll: %v", err)
	}
	if calls == 0 {
		t.Fatal("подписка ушла МИМО туннеля при активном подключении в proxy-режиме: " +
			"ровно то, из-за чего в «худший день» пул нечем обновить")
	}
	if len(nodes) != 1 {
		t.Fatalf("узлов получено %d, ожидался 1", len(nodes))
	}
}

// TestV14_C7_DirectWhenNotConnected — без подключения (и в VPN-режиме) диалер не используется:
// в TUN весь трафик и так в туннеле, а без подключения SOCKS движка попросту нет.
func TestV14_C7_DirectWhenNotConnected(t *testing.T) {
	_, src := v14Subscription(t)
	m := New(&models.AppConfig{Sources: []models.SourceConfig{src}})

	var calls int
	m.SetTunnelProxy(func() (string, bool) { return "", false })
	m.socksDial = func(ctx context.Context, proxyAddr, targetAddr string, timeout time.Duration) (net.Conn, error) {
		calls++
		return nil, errors.New("не должно вызываться")
	}

	nodes, err := m.FetchAll(context.Background(), true)
	if err != nil {
		t.Fatalf("FetchAll: %v", err)
	}
	if calls != 0 {
		t.Fatalf("SOCKS-диалер использован без подключения (%d вызовов)", calls)
	}
	if len(nodes) != 1 {
		t.Fatalf("узлов получено %d, ожидался 1", len(nodes))
	}
}

// TestV14_C7_FallsBackToDirectWithLog — обязательный фолбэк из ТЗ: «через туннель не вышло →
// напрямую + запись в лог». Без него неверный диалер = «источники перестали обновляться».
func TestV14_C7_FallsBackToDirectWithLog(t *testing.T) {
	_, src := v14Subscription(t)
	m := New(&models.AppConfig{Sources: []models.SourceConfig{src}})

	var lines []string
	m.OnLog = func(s string) { lines = append(lines, s) }
	m.SetTunnelProxy(func() (string, bool) { return "127.0.0.1:10808", true })
	m.socksDial = func(ctx context.Context, proxyAddr, targetAddr string, timeout time.Duration) (net.Conn, error) {
		return nil, errors.New("socks5: dial proxy: connection refused")
	}

	nodes, err := m.FetchAll(context.Background(), true)
	if err != nil {
		t.Fatalf("FetchAll: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("фолбэк напрямую не сработал: узлов %d", len(nodes))
	}
	found := false
	for _, l := range lines {
		if strings.Contains(l, "напрямую") {
			found = true
		}
	}
	if !found {
		t.Fatalf("фолбэк прошёл молча, лог: %v", lines)
	}
}

// ─── C-7 п.1: третий источник на другом семействе хостов ─────────────────────

// TestV14_C7_ThirdSourceParsesSavedSample — сохранённый образец страницы «raw»-источника
// (произвольный текст/HTML на стороннем хостинге), разбор без сети.
func TestV14_C7_ThirdSourceParsesSavedSample(t *testing.T) {
	sample := `<html><body><p>Свежие ключи на сегодня:</p>
<code>vless://11111111-2222-3333-4444-555555555555@5.6.7.8:443?security=reality&amp;pbk=abc&amp;sni=www.google.com#RAW-1</code>
<br>мусор, не ссылка, http://example.org/page
<code>ss://YWVzLTI1Ni1nY206cGFzcw==@9.10.11.12:8388#RAW-2</code>
</body></html>`

	nodes := parseRawTextSource([]byte(sample), "raw-src")
	if len(nodes) != 2 {
		t.Fatalf("на сохранённом образце разобрано %d узлов, ожидалось 2", len(nodes))
	}
	for _, n := range nodes {
		if n.Source != "raw-src" {
			t.Errorf("узел %q не помечен источником: %q", n.Name, n.Source)
		}
	}
	if nodes[0].Address != "5.6.7.8" {
		t.Errorf("первый узел разобран неверно: %+v", nodes[0])
	}
}

// TestV14_C7_RawSourceTypeIsRoutable — тип "raw" доходит до своего обработчика, а не падает
// в «unknown source type».
func TestV14_C7_RawSourceTypeIsRoutable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("текст ... vless://11111111-2222-3333-4444-555555555555@2.3.4.5:443?security=reality&pbk=k&sni=a.b#RAW ... хвост"))
	}))
	defer srv.Close()

	m := New(&models.AppConfig{})
	nodes, err := m.fetchSource(context.Background(),
		models.SourceConfig{ID: "raw", Name: "raw", Type: "raw", URL: srv.URL, Enabled: true})
	if err != nil {
		t.Fatalf("источник типа raw не обслуживается: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("узлов %d, ожидался 1", len(nodes))
	}
}
