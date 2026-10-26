package catalog

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/contentage"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// Лот L5. Фикстура СИНТЕТИЧЕСКАЯ: формат подражает спискам igareck (строки-комментарии с «#»,
// имена с флагом-эмодзи и меткой «[*CIDR]»/«[BL]»), но адреса взяты из документационных
// диапазонов RFC 5737, UUID и ключ — выдуманные. Настоящие списки в тестах не используются.
func igareckLikeFixture() string {
	ss := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:synthetic-password"))
	return "#profile-title: synthetic fixture\n" +
		"#profile-update-interval: 2\n" +
		"# Обновлено: 2026-10-21 12:00 UTC\n" +
		"\n" +
		"vless://00000000-0000-4000-8000-000000000001@192.0.2.10:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=example.org&fp=chrome&pbk=SYNTHETICPUBLICKEYSYNTHETICPUBLICKEY000&sid=ab12&type=tcp#🇩🇪 Germany | [*CIDR]\n" +
		"vless://00000000-0000-4000-8000-000000000002@192.0.2.11:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=example.org&fp=chrome&pbk=SYNTHETICPUBLICKEYSYNTHETICPUBLICKEY000&sid=cd34&type=tcp#🇳🇱 Netherlands | [BL]\n" +
		"ss://" + ss + "@192.0.2.20:8388#🇪🇬 Egypt\n" +
		"trojan://synthetic-password@192.0.2.30:443?security=tls&sni=example.org&type=tcp#🇫🇮 Finland | [*CIDR]\r\n" +
		"это не ссылка, а мусорная строка\n"
}

func newFixtureServer(t *testing.T, body *atomic.Value, hits *int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func optionalForServer(srv *httptest.Server) *FreeSubscriptionProvider {
	return NewOptionalFreeProvider(models.OptionalSource{
		ID: "igareck-test", Name: "igareck: тест", URL: srv.URL, Note: "пояснение",
	})
}

// Критерий приёмки L5, часть 1: парсер даёт ожидаемое число узлов на фикстуре формата igareck.
func TestOptionalProvider_ParsesIgareckLikeFixture(t *testing.T) {
	var body atomic.Value
	body.Store(igareckLikeFixture())
	var hits int32
	p := optionalForServer(newFixtureServer(t, &body, &hits))

	nodes, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(nodes) != 4 {
		t.Fatalf("узлов %d, ожидалось 4 (2 VLESS + SS + Trojan; комментарии и мусор пропущены)", len(nodes))
	}
	var withFlagAndLabel int
	for _, n := range nodes {
		if n.Source != "igareck-test" {
			t.Errorf("узел %q помечен источником %q", n.Name, n.Source)
		}
		if strings.Contains(n.Name, "🇩🇪 Germany") && strings.Contains(n.Name, "[*CIDR]") {
			withFlagAndLabel++
		}
	}
	if withFlagAndLabel != 1 {
		t.Errorf("имя с флагом и меткой не сохранилось (нашёл %d): %+v", withFlagAndLabel, nodes[0])
	}
	if m := p.Meta(); m.NodeCount != 4 || m.LastUpdated.IsZero() {
		t.Errorf("Meta после загрузки: %+v", m)
	}
}

func TestOptionalProviders_RegisteredButDisabled(t *testing.T) {
	r := NewRegistry()
	for _, o := range models.OptionalSources() {
		p, ok := r.Get(o.ID)
		if !ok {
			t.Fatalf("%s не зарегистрирован в каталоге", o.ID)
		}
		if p.IsEnabled() {
			t.Errorf("%s включён по умолчанию", o.ID)
		}
		for _, en := range r.Enabled() {
			if en.ID() == o.ID {
				t.Errorf("%s попал в Enabled()", o.ID)
			}
		}
	}
	// Прежние встроенные провайдеры остались включёнными.
	for _, id := range []string{"v2ray-aggregator", "freefq", "nomore-walls", "awesome-vpn"} {
		p, ok := r.Get(id)
		if !ok || !p.IsEnabled() {
			t.Errorf("встроенный провайдер %s пропал или выключен", id)
		}
	}
}

func TestStatus_MarksOptionalProvidersOnly(t *testing.T) {
	r := NewRegistry()
	var optional, plain int
	for _, row := range r.Status() {
		id := row["id"].(string)
		_, isOpt := models.OptionalSourceByID(id)
		_, hasFlag := row["optional"]
		note, hasNote := row["note"].(string)
		switch {
		case isOpt && (!hasFlag || !hasNote || note == ""):
			t.Errorf("%s: нет пометки optional/note в статусе: %v", id, row)
		case !isOpt && (hasFlag || hasNote):
			t.Errorf("%s: у обычного провайдера не должно быть optional/note: %v", id, row)
		}
		if isOpt {
			optional++
		} else {
			plain++
		}
	}
	if optional != len(models.OptionalSources()) || plain == 0 {
		t.Errorf("optional=%d plain=%d", optional, plain)
	}
}

// Выключенный провайдер не ходит в сеть; включённый — ходит.
func TestFetchAll_SkipsDisabledOptionalUntilEnabled(t *testing.T) {
	var body atomic.Value
	body.Store(igareckLikeFixture())
	var hits int32
	r := &Registry{providers: map[string]Provider{}}
	r.Register(optionalForServer(newFixtureServer(t, &body, &hits)))
	f := NewFetcher(r)

	nodes, _ := f.FetchAll(context.Background())
	if len(nodes) != 0 || atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("выключенный источник скачан: узлов %d, запросов %d", len(nodes), hits)
	}
	if !r.SetEnabled("igareck-test", true) {
		t.Fatal("SetEnabled вернул false")
	}
	nodes, results := f.FetchAll(context.Background())
	if len(nodes) != 4 || atomic.LoadInt32(&hits) != 1 || len(results) != 1 || results[0].Error != nil {
		t.Fatalf("после включения: узлов %d, запросов %d, результаты %+v", len(nodes), hits, results)
	}
}

// Критерий приёмки L5, часть 2: данные для «возраста содержимого» появляются у карточки.
func TestOptionalProvider_ContentAgeTracked(t *testing.T) {
	var body atomic.Value
	body.Store(igareckLikeFixture())
	var hits int32
	p := optionalForServer(newFixtureServer(t, &body, &hits))
	tr := contentage.New()
	r := &Registry{providers: map[string]Provider{}}
	r.Register(p)
	r.SetContentTracker(tr)

	if _, err := p.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	s1, ok := tr.Get("igareck-test")
	if !ok || s1.FirstSeenAt == 0 || s1.ChangedAt != 0 {
		t.Fatalf("после первой загрузки: %+v ok=%v", s1, ok)
	}
	// Тот же набор узлов, другой заголовок-комментарий — не изменение.
	body.Store(strings.Replace(igareckLikeFixture(), "12:00 UTC", "13:30 UTC", 1))
	if _, err := p.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s2, _ := tr.Get("igareck-test"); s2.ChangedAt != 0 || s2.Hash != s1.Hash {
		t.Fatalf("смена заголовка принята за изменение содержимого: %+v", s2)
	}
	// Заменили узел — изменение.
	body.Store(strings.Replace(igareckLikeFixture(), "192.0.2.30", "192.0.2.99", 1))
	if _, err := p.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s3, _ := tr.Get("igareck-test"); s3.ChangedAt == 0 || s3.Hash == s1.Hash {
		t.Fatalf("замена узла не замечена: %+v", s3)
	}
}

// Без трекера загрузка работает как раньше.
func TestFreeProvider_FetchWithoutTracker(t *testing.T) {
	var body atomic.Value
	body.Store(igareckLikeFixture())
	var hits int32
	p := optionalForServer(newFixtureServer(t, &body, &hits))
	if n, err := p.Fetch(context.Background()); err != nil || len(n) != 4 {
		t.Fatalf("nodes=%d err=%v", len(n), err)
	}
}

// Переключатель из UI и обновление каталога идут из разных горутин (go test -race).
func TestFreeProvider_EnabledIsRaceFree(t *testing.T) {
	p := NewFreeProvider("race", "Race", "https://example.invalid")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func(v bool) { defer wg.Done(); p.SetEnabled(v) }(i%2 == 0)
		go func() { defer wg.Done(); _ = p.IsEnabled(); _ = p.Meta() }()
	}
	wg.Wait()
}
