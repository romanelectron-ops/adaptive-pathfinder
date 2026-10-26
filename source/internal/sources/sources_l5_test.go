package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/contentage"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// Лот L5. Данные синтетические (адреса RFC 5737, выдуманные UUID).
const l5Body = "# заголовок\n" +
	"vless://00000000-0000-4000-8000-000000000001@192.0.2.10:443?security=none&type=tcp#one\n" +
	"vless://00000000-0000-4000-8000-000000000002@192.0.2.11:443?security=none&type=tcp#two\n"

func l5Server(t *testing.T, body *atomic.Value, hits *int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchAll_TracksContentAgeOfSubscriptions(t *testing.T) {
	var body atomic.Value
	body.Store(l5Body)
	var hits int32
	srv := l5Server(t, &body, &hits)

	cfg := &models.AppConfig{Sources: []models.SourceConfig{
		{ID: "sub-on", Name: "on", URL: srv.URL, Type: "subscription", Enabled: true},
	}}
	tr := contentage.New()
	m := New(cfg)
	m.SetContentTracker(tr)

	nodes, err := m.FetchAll(context.Background(), true)
	if err != nil || len(nodes) != 2 {
		t.Fatalf("узлов %d, err=%v", len(nodes), err)
	}
	s1, ok := tr.Get("sub-on")
	if !ok || s1.FirstSeenAt == 0 || s1.ChangedAt != 0 {
		t.Fatalf("после первой загрузки: %+v ok=%v", s1, ok)
	}

	body.Store(strings.Replace(l5Body, "192.0.2.11", "192.0.2.77", 1))
	if _, err := m.FetchAll(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if s2, _ := tr.Get("sub-on"); s2.ChangedAt == 0 || s2.Hash == s1.Hash {
		t.Fatalf("замена узла не замечена: %+v", s2)
	}
}

// Выключенный источник (в том числе встроенный необязательный) не скачивается и не учитывается.
func TestFetchAll_DisabledSourceNotFetchedNotTracked(t *testing.T) {
	var body atomic.Value
	body.Store(l5Body)
	var hits int32
	srv := l5Server(t, &body, &hits)

	cfg := &models.AppConfig{Sources: []models.SourceConfig{
		{ID: "igareck-off", Name: "off", URL: srv.URL, Type: "subscription", Enabled: false},
	}}
	tr := contentage.New()
	m := New(cfg)
	m.SetContentTracker(tr)

	nodes, _ := m.FetchAll(context.Background(), true)
	if len(nodes) != 0 || atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("выключенный источник скачан: узлов %d, запросов %d", len(nodes), hits)
	}
	if _, ok := tr.Get("igareck-off"); ok {
		t.Fatal("для выключенного источника создана отметка содержимого")
	}
}

// Без трекера менеджер работает как раньше.
func TestFetchAll_WithoutTrackerStillWorks(t *testing.T) {
	var body atomic.Value
	body.Store(l5Body)
	var hits int32
	srv := l5Server(t, &body, &hits)
	m := New(&models.AppConfig{Sources: []models.SourceConfig{
		{ID: "s", Name: "s", URL: srv.URL, Type: "subscription", Enabled: true},
	}})
	if nodes, err := m.FetchAll(context.Background(), true); err != nil || len(nodes) != 2 {
		t.Fatalf("узлов %d, err=%v", len(nodes), err)
	}
}
