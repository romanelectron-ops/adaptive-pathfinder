package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/catalog"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// Лот L5 (решение владельца 2026-10-21): источники igareck выключены по умолчанию, включаются
// переключателем в «Каталоге серверов», выбор сохраняется. Данные — синтетические.

// newL5Engine — движок без сети и с перехватом сохранения конфига (в профиль не пишем).
func newL5Engine(t *testing.T, cfg *models.AppConfig) (*Engine, *[]*models.AppConfig) {
	t.Helper()
	if cfg == nil {
		cfg = models.DefaultConfig()
	}
	cfg.AutoConnect = false
	cfg.EnableKillSwitch = false
	e := New(cfg)
	saves := &[]*models.AppConfig{}
	e.saveConfig = func(c *models.AppConfig) error {
		cp := *c
		cp.Sources = append([]models.SourceConfig(nil), c.Sources...)
		*saves = append(*saves, &cp)
		return nil
	}
	return e, saves
}

func statusRow(t *testing.T, e *Engine, id string) map[string]interface{} {
	t.Helper()
	for _, row := range e.GetCatalogStatus() {
		if row["id"] == id {
			return row
		}
	}
	t.Fatalf("в статусе каталога нет %s", id)
	return nil
}

func sourceByID(c *models.AppConfig, id string) (models.SourceConfig, bool) {
	for _, s := range c.Sources {
		if s.ID == id {
			return s, true
		}
	}
	return models.SourceConfig{}, false
}

func TestL5_OptionalSourcesAreDisabledByDefault(t *testing.T) {
	e, _ := newL5Engine(t, nil)
	n := 0
	for _, o := range models.OptionalSources() {
		row := statusRow(t, e, o.ID)
		if row["enabled"] != false {
			t.Errorf("%s включён по умолчанию: %v", o.ID, row["enabled"])
		}
		if row["optional"] != true || row["note"] == nil || row["note"] == "" {
			t.Errorf("%s: нет пометки optional/note: %v", o.ID, row)
		}
		n++
	}
	if n != 7 {
		t.Fatalf("проверено %d источников, ожидалось 7", n)
	}
	if row := statusRow(t, e, "freefq"); row["enabled"] != true {
		t.Errorf("прежний встроенный источник freefq должен остаться включённым: %v", row)
	}
}

func TestL5_SetProviderEnabled_PersistsToConfig(t *testing.T) {
	e, saves := newL5Engine(t, nil)
	const id = "igareck-black-vless"

	if !e.SetProviderEnabled(id, true) {
		t.Fatal("SetProviderEnabled(on) вернул false")
	}
	if len(*saves) != 1 {
		t.Fatalf("после включения config.json сохранён %d раз, ожидалось 1", len(*saves))
	}
	if s, ok := sourceByID((*saves)[0], id); !ok || !s.Enabled {
		t.Fatalf("в сохранённом конфиге источник не включён: %+v ok=%v", s, ok)
	}
	if row := statusRow(t, e, id); row["enabled"] != true {
		t.Errorf("статус после включения: %v", row["enabled"])
	}

	// То же состояние повторно — лишней записи на диск нет.
	e.SetProviderEnabled(id, true)
	if len(*saves) != 1 {
		t.Errorf("повторное включение переписало конфиг (%d записей)", len(*saves))
	}

	e.SetProviderEnabled(id, false)
	if len(*saves) != 2 {
		t.Fatalf("после выключения записей %d, ожидалось 2", len(*saves))
	}
	if s, _ := sourceByID((*saves)[1], id); s.Enabled {
		t.Error("выключение не дошло до сохранённого конфига")
	}
}

// Переключатель встроенного обязательного источника теперь управляет и фоновым обновлением пула
// (раньше менялся только реестр в памяти, а sources.Manager продолжал качать).
func TestL5_ToggleOfSharedIDStopsBackgroundSource(t *testing.T) {
	e, saves := newL5Engine(t, nil)
	if !e.SetProviderEnabled("freefq", false) {
		t.Fatal("SetProviderEnabled(freefq) вернул false")
	}
	if len(*saves) != 1 {
		t.Fatalf("записей конфига %d, ожидалась 1", len(*saves))
	}
	if s, _ := sourceByID((*saves)[0], "freefq"); s.Enabled {
		t.Error("freefq остался включённым в cfg.Sources — фоновое обновление продолжит его качать")
	}
}

// Выбор из config.json применяется к реестру на старте.
func TestL5_ConfiguredStateAppliedOnNew(t *testing.T) {
	cfg := models.DefaultConfig()
	for i := range cfg.Sources {
		switch cfg.Sources[i].ID {
		case "igareck-white-cidr-all":
			cfg.Sources[i].Enabled = true
		case "freefq":
			cfg.Sources[i].Enabled = false
		}
	}
	e, _ := newL5Engine(t, cfg)
	if row := statusRow(t, e, "igareck-white-cidr-all"); row["enabled"] != true {
		t.Errorf("включённый в конфиге igareck-white-cidr-all в реестре выключен: %v", row["enabled"])
	}
	if row := statusRow(t, e, "freefq"); row["enabled"] != false {
		t.Errorf("выключенный в конфиге freefq в реестре включён: %v", row["enabled"])
	}
	if row := statusRow(t, e, "igareck-black-ss"); row["enabled"] != false {
		t.Errorf("не тронутый igareck-black-ss должен остаться выключенным: %v", row["enabled"])
	}
}

// Конфиг мог не пройти Normalize — записи источника нет: создаём её при включении.
func TestL5_EnableCreatesMissingOptionalSource(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.Sources = nil
	e, saves := newL5Engine(t, cfg)

	if !e.SetProviderEnabled("igareck-black-ss", true) {
		t.Fatal("SetProviderEnabled вернул false")
	}
	if len(*saves) != 1 {
		t.Fatalf("записей %d, ожидалась 1", len(*saves))
	}
	if s, ok := sourceByID((*saves)[0], "igareck-black-ss"); !ok || !s.Enabled || s.Type != "subscription" || s.URL == "" {
		t.Fatalf("запись источника не создана как надо: %+v ok=%v", s, ok)
	}

	// Обязательный провайдер без записи в cfg.Sources (как в тестовых конфигурациях): запись в Sources
	// не выдумывается, но выбор сохраняется отдельной картой и переживает перезапуск.
	before := len(*saves)
	if !e.SetProviderEnabled("v2ray-aggregator", false) {
		t.Fatal("SetProviderEnabled(v2ray-aggregator) вернул false")
	}
	if len(*saves) != before+1 {
		t.Errorf("выбор провайдера без записи в cfg.Sources не сохранён (записей %d → %d)", before, len(*saves))
	}
	if _, ok := sourceByID(e.cfg, "v2ray-aggregator"); ok {
		t.Error("для обязательного провайдера выдумана запись в cfg.Sources")
	}
	if en, ok := e.cfg.CatalogProviderStates["v2ray-aggregator"]; !ok || en {
		t.Errorf("выбор не попал в CatalogProviderStates: %v", e.cfg.CatalogProviderStates)
	}
}

func TestL5_UnknownProviderChangesNothing(t *testing.T) {
	e, saves := newL5Engine(t, nil)
	if e.SetProviderEnabled("no-such-provider", true) {
		t.Fatal("неизвестный провайдер принят")
	}
	if len(*saves) != 0 {
		t.Error("неизвестный провайдер вызвал запись конфига")
	}
}

// Возраст содержимого: хранится в cfg.Sources, переживает «перезапуск» (новый движок на том же
// конфиге) и показывается в статусе каталога.
func TestL5_ContentAge_PersistsAndShowsInStatus(t *testing.T) {
	e, saves := newL5Engine(t, nil)
	const id = "igareck-black-vless"
	body := []byte("vless://00000000-0000-4000-8000-000000000001@192.0.2.10:443?type=tcp#a\n")

	if _, ok := e.contentTracker.Get(id); ok {
		t.Fatal("отметка есть у ни разу не загружавшегося источника")
	}
	if row := statusRow(t, e, id); row["content_age_text"] != nil {
		t.Errorf("у не загружавшегося источника не должно быть возраста: %v", row)
	}

	now := time.Now()
	e.contentTracker.Observe(id, body, now.Add(-30*time.Hour))
	e.persistSourceContent()
	if len(*saves) != 1 {
		t.Fatalf("отметки не сохранены: записей %d", len(*saves))
	}
	s, _ := sourceByID(e.cfg, id)
	if s.ContentHash == "" || s.ContentFirstSeenAt == 0 || s.ContentChangedAt != 0 {
		t.Fatalf("в cfg.Sources неверные отметки: %+v", s)
	}
	e.persistSourceContent() // ничего не изменилось — лишней записи нет
	if len(*saves) != 1 {
		t.Errorf("повторное сохранение без изменений переписало конфиг (%d)", len(*saves))
	}

	row := statusRow(t, e, id)
	hours, _ := row["content_age_hours"].(int)
	if hours < 29 || hours > 31 || row["content_age_exact"] != false || row["content_stale"] != false {
		t.Errorf("статус возраста: hours=%v exact=%v stale=%v", row["content_age_hours"], row["content_age_exact"], row["content_stale"])
	}
	if txt, _ := row["content_age_text"].(string); !strings.Contains(txt, "не менялось") {
		t.Errorf("текст возраста %q", txt)
	}

	// «Перезапуск»: новый движок поверх сохранённого конфига помнит возраст.
	e2, _ := newL5Engine(t, e.cfg)
	row2 := statusRow(t, e2, id)
	if h2, _ := row2["content_age_hours"].(int); h2 < 29 {
		t.Errorf("после перезапуска возраст потерян: %v", row2)
	}
}

// Сквозной сценарий ручного «Обновить каталог»: включили источник, нажали «Обновить» — узлы
// пришли, возраст содержимого появился и сохранён. Сеть — loopback-сервер с синтетическим списком.
func TestL5_RefreshCatalog_EnabledOptionalSourceFeedsPool(t *testing.T) {
	const id = "igareck-black-vless"
	body := "# синтетический список\n" +
		"vless://00000000-0000-4000-8000-0000000000a1@192.0.2.41:443?encryption=none&security=none&type=tcp#🇩🇪 Germany | [*CIDR]\n" +
		"vless://00000000-0000-4000-8000-0000000000a2@192.0.2.42:443?encryption=none&security=none&type=tcp#🇳🇱 Netherlands | [BL]\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	e, saves := newL5Engine(t, nil)
	e.nodes = nil
	// Остальные встроенные провайдеры выключаем: боевые URL в тесте не нужны.
	for _, p := range e.catalogRegistry.All() {
		e.catalogRegistry.SetEnabled(p.ID(), false)
	}
	opt := catalog.NewOptionalFreeProvider(models.OptionalSource{ID: id, Name: "igareck: тест", URL: srv.URL, Note: "n"})
	e.catalogRegistry.Register(opt) // заменяет боевого провайдера с тем же ID
	e.catalogRegistry.SetContentTracker(e.contentTracker)

	// Tor-мосты и ручной провайдер выключить нельзя и они могут добавлять свои узлы, поэтому
	// считаем узлы именно этого источника.
	fromSource := func() int {
		e.mu.Lock()
		defer e.mu.Unlock()
		n := 0
		for _, nd := range e.nodes {
			if nd.Source == id {
				n++
			}
		}
		return n
	}
	if _, err := e.RefreshCatalog(context.Background()); err != nil {
		t.Fatalf("RefreshCatalog: %v", err)
	}
	if got := fromSource(); got != 0 {
		t.Fatalf("выключенный источник дал %d узлов", got)
	}
	if !e.SetProviderEnabled(id, true) {
		t.Fatal("включение не удалось")
	}
	if _, err := e.RefreshCatalog(context.Background()); err != nil {
		t.Fatalf("RefreshCatalog: %v", err)
	}
	if got := fromSource(); got != 2 {
		t.Fatalf("узлов от включённого источника %d, ожидалось 2", got)
	}
	row := statusRow(t, e, id)
	if row["node_count"] != 2 || row["enabled"] != true {
		t.Errorf("статус после обновления: node_count=%v enabled=%v", row["node_count"], row["enabled"])
	}
	if txt, _ := row["content_age_text"].(string); txt == "" {
		t.Errorf("в карточке нет возраста содержимого: %v", row)
	}
	s, _ := sourceByID(e.cfg, id)
	if s.ContentHash == "" || !s.Enabled {
		t.Errorf("в cfg.Sources не сохранены включённость и отметка содержимого: %+v", s)
	}
	if len(*saves) < 2 {
		t.Errorf("config.json сохранён %d раз(а), ожидалось не меньше 2", len(*saves))
	}
}

// ─── Правки по итогам независимой проверки лота ───────────────────────────────

func addTestNodes(e *Engine, nodes ...*models.Node) {
	e.mu.Lock()
	e.nodes = append(e.nodes, nodes...)
	e.mu.Unlock()
}

func poolNodeIDs(e *Engine) map[string]bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make(map[string]bool, len(e.nodes))
	for _, n := range e.nodes {
		out[n.ID] = true
	}
	return out
}

func l5Node(id, source string) *models.Node {
	return &models.Node{ID: id, Source: source, Protocol: models.ProtoVLESS, Address: "192.0.2.1", Port: 443}
}

// Выключили igareck — его узлы уходят из пула (иначе автовыбор продолжал бы ими пользоваться),
// кроме закреплённого, избранного и принадлежащих пользователю; чужие источники не трогаются.
func TestL5_DisableOptionalSource_RemovesItsNodesExceptProtected(t *testing.T) {
	e, _ := newL5Engine(t, nil)
	const igareck = "igareck-black-vless"
	manualFromIgareck := l5Node("partner", igareck)
	manualFromIgareck.IsChainPartner = true
	addTestNodes(e,
		l5Node("plain", igareck),
		l5Node("pinned", igareck),
		l5Node("fav", igareck),
		l5Node("other-optional", "igareck-black-ss"),
		l5Node("core", "freefq"),
		l5Node("mine", "manual"),
		manualFromIgareck,
	)
	e.PinNode("pinned")
	if err := e.AddFavorite("fav"); err != nil {
		t.Fatalf("AddFavorite: %v", err)
	}

	if !e.SetProviderEnabled(igareck, true) {
		t.Fatal("включение не удалось")
	}
	if got := poolNodeIDs(e); !got["plain"] {
		t.Fatal("включение источника убрало его узлы")
	}

	if !e.SetProviderEnabled(igareck, false) {
		t.Fatal("выключение не удалось")
	}
	got := poolNodeIDs(e)
	for _, id := range []string{"plain", "other-optional"} {
		if got[id] {
			t.Errorf("узел %s выключенного источника остался в пуле", id)
		}
	}
	for _, id := range []string{"pinned", "fav", "partner", "core", "mine"} {
		if !got[id] {
			t.Errorf("узел %s не должен удаляться при выключении igareck", id)
		}
	}
}

// Выключение ОБЯЗАТЕЛЬНОГО источника (freefq) узлы не трогает — прежнее поведение.
func TestL5_DisableCoreSource_KeepsItsNodes(t *testing.T) {
	e, _ := newL5Engine(t, nil)
	addTestNodes(e, l5Node("core", "freefq"))
	e.SetProviderEnabled("freefq", false)
	if !poolNodeIDs(e)["core"] {
		t.Fatal("выключение обязательного источника убрало его узлы")
	}
}

// Вкладка «Источники» шлёт массив sources целиком: реестр каталога обязан за ним следовать.
func TestL5_PatchSources_SyncsCatalogRegistryAndPurges(t *testing.T) {
	e, _ := newL5Engine(t, nil)
	const id = "igareck-black-vless"
	addTestNodes(e, l5Node("from-igareck", id))

	patchWith := func(enabled bool) {
		t.Helper()
		var arr []interface{}
		for _, s := range e.GetConfig().Sources {
			if s.ID == id {
				s.Enabled = enabled
			}
			raw, _ := json.Marshal(s)
			var m map[string]interface{}
			_ = json.Unmarshal(raw, &m)
			arr = append(arr, m)
		}
		if err := e.PatchConfig(map[string]interface{}{"sources": arr}); err != nil {
			t.Fatalf("PatchConfig(sources): %v", err)
		}
	}

	patchWith(true)
	if row := statusRow(t, e, id); row["enabled"] != true {
		t.Errorf("после включения на вкладке «Источники» каталог показывает %v", row["enabled"])
	}
	if !poolNodeIDs(e)["from-igareck"] {
		t.Error("включение через вкладку «Источники» убрало узлы")
	}

	patchWith(false)
	if row := statusRow(t, e, id); row["enabled"] != false {
		t.Errorf("после выключения на вкладке «Источники» каталог показывает %v", row["enabled"])
	}
	if poolNodeIDs(e)["from-igareck"] {
		t.Error("выключение через вкладку «Источники» оставило узлы в пуле")
	}
}

// Гонка, доказанная ревью: sources.Manager читает cfg.Sources, пока движок пишет в те же записи.
// Тест осмыслен только под `go test -race`.
func TestL5_UpdateSourcesDoesNotRaceWithConfigWriters(t *testing.T) {
	var rev atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "vless://00000000-0000-4000-8000-000000000001@192.0.2.%d:443?security=none&type=tcp#n\n", rev.Add(1)%200+1)
	}))
	defer srv.Close()

	cfg := models.DefaultConfig()
	cfg.Sources = []models.SourceConfig{{
		ID: "igareck-black-vless", Name: "t", URL: srv.URL, Type: "subscription",
		Enabled: true, AutoUpdate: true, UpdateIntervalHours: 1,
	}}
	e, _ := newL5Engine(t, cfg)
	e.saveConfig = func(*models.AppConfig) error { return nil } // без общего среза-накопителя

	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				e.updateSources(true)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 40; j++ {
			e.persistSourceContent()
			e.SetProviderEnabled("igareck-black-vless", j%2 == 0)
		}
	}()
	wg.Wait()
}

// Найдено живой проверкой на телефоне (2026-10-21): после ручного «Обновить каталог» и перезапуска
// карточка писала «давно не загружалось (19 сут назад)» — время загрузки бралось из LastUpdatedAt,
// а его пишет только фоновый менеджер, не ручное обновление каталога.
func TestL5_ContentAge_ManualRefreshSurvivesRestart(t *testing.T) {
	const id = "igareck-black-vless"
	body := []byte("vless://00000000-0000-4000-8000-000000000001@192.0.2.10:443?type=tcp#a\n")

	cfg := models.DefaultConfig()
	for i := range cfg.Sources {
		if cfg.Sources[i].ID == id {
			cfg.Sources[i].Enabled = true
			cfg.Sources[i].LastUpdatedAt = time.Now().Add(-19 * 24 * time.Hour).Unix() // фоновый менеджер давно не работал
		}
	}
	e1, _ := newL5Engine(t, cfg)
	e1.contentTracker.Observe(id, body, time.Now()) // ручное обновление каталога прямо сейчас
	e1.persistSourceContent()

	notIdle := func(label string, e *Engine) {
		t.Helper()
		row := statusRow(t, e, id)
		txt, _ := row["content_age_text"].(string)
		if txt == "" || strings.Contains(txt, "давно не загружалось") {
			t.Errorf("%s: источник только что обновлён вручную, а карточка говорит %q", label, txt)
		}
	}
	// «Перезапуск»: новый движок на том же конфиге.
	e2, _ := newL5Engine(t, e1.cfg)
	notIdle("после перезапуска", e2)

	// Конфиг, записанный прежней сборкой: отметка содержимого есть, content_seen_at нет, а
	// last_updated_at старый — «давно не загружалось» утверждать нельзя (неизвестно).
	for i := range e1.cfg.Sources {
		if e1.cfg.Sources[i].ID == id {
			e1.cfg.Sources[i].ContentSeenAt = 0
		}
	}
	e3, _ := newL5Engine(t, e1.cfg)
	notIdle("конфиг прежней сборки", e3)
}

// awesome-vpn нет в cfg.Sources: раньше его переключатель после перезапуска возвращался к «включён».
func TestL5_ProviderWithoutSourceEntry_ChoiceSurvivesRestart(t *testing.T) {
	e1, _ := newL5Engine(t, nil)
	if !e1.SetProviderEnabled("awesome-vpn", false) {
		t.Fatal("SetProviderEnabled(awesome-vpn) вернул false")
	}
	e2, _ := newL5Engine(t, e1.cfg) // «перезапуск»: новый движок на сохранённом конфиге
	if row := statusRow(t, e2, "awesome-vpn"); row["enabled"] != false {
		t.Fatalf("после перезапуска awesome-vpn снова включён: %v", row["enabled"])
	}
	if row := statusRow(t, e2, "freefq"); row["enabled"] != true {
		t.Errorf("соседний источник freefq не должен был измениться: %v", row["enabled"])
	}
}
