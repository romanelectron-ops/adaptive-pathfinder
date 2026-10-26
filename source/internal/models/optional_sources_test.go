package models

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// L5: встроенные необязательные источники лежат в дефолтном конфиге ВЫКЛЮЧЕННЫМИ.
func TestOptionalSources_DefaultConfigHasThemDisabled(t *testing.T) {
	byID := map[string]SourceConfig{}
	for _, s := range DefaultConfig().Sources {
		byID[s.ID] = s
	}
	for _, o := range OptionalSources() {
		s, ok := byID[o.ID]
		if !ok {
			t.Fatalf("необязательный источник %s отсутствует в DefaultConfig().Sources", o.ID)
		}
		if s.Enabled {
			t.Errorf("%s включён по умолчанию — решение владельца: выключен", o.ID)
		}
		if s.Type != "subscription" || !s.AutoUpdate || s.UpdateIntervalHours <= 0 {
			t.Errorf("%s: тип/автообновление заданы неверно: %+v", o.ID, s)
		}
	}
}

func TestOptionalSources_DescriptorsAreSane(t *testing.T) {
	seen := map[string]bool{}
	core := map[string]bool{}
	for _, s := range defaultConfigBase().Sources {
		core[s.ID] = true
	}
	for _, o := range OptionalSources() {
		if o.ID == "" || o.Name == "" || o.Note == "" {
			t.Errorf("пустые поля у %+v", o)
		}
		if seen[o.ID] {
			t.Errorf("повтор ID %s", o.ID)
		}
		seen[o.ID] = true
		if core[o.ID] {
			t.Errorf("ID %s совпадает с обязательным источником", o.ID)
		}
		u, err := url.Parse(o.URL)
		if err != nil || u.Scheme != "https" || u.Host != "raw.githubusercontent.com" {
			t.Errorf("%s: URL %q должен быть https на raw.githubusercontent.com", o.ID, o.URL)
		}
		if strings.ContainsAny(o.URL, " \t\r\n") {
			t.Errorf("%s: пробелы в URL %q", o.ID, o.URL)
		}
	}
	if len(seen) != 7 {
		t.Errorf("ожидалось 7 источников igareck, получено %d", len(seen))
	}
	// WHITE-SNI-RU-all пуст (0 узлов) — подключать его нельзя.
	for _, o := range OptionalSources() {
		if strings.Contains(o.URL, "WHITE-SNI") {
			t.Errorf("пустой список WHITE-SNI не должен быть подключён: %s", o.URL)
		}
	}
}

func TestOptionalSources_ReturnsCopy(t *testing.T) {
	a := OptionalSources()
	a[0].ID = "испорчено"
	if OptionalSources()[0].ID == "испорчено" {
		t.Fatal("OptionalSources отдал внутренний срез, а не копию")
	}
}

func TestOptionalSourceByID(t *testing.T) {
	if o, ok := OptionalSourceByID("  IGARECK-white-cidr-all "); !ok || o.ID != "igareck-white-cidr-all" {
		t.Fatalf("поиск без учёта регистра/пробелов не сработал: %+v %v", o, ok)
	}
	if _, ok := OptionalSourceByID("freefq"); ok {
		t.Fatal("обязательный источник не должен находиться как необязательный")
	}
	if _, ok := OptionalSourceByID(""); ok {
		t.Fatal("пустой ID не должен находиться")
	}
}

// Миграция: config.json старой установки хранит свой массив sources без igareck.
func TestOptionalSources_NormalizeMigratesLegacyConfig(t *testing.T) {
	c := DefaultConfig()
	kept := c.Sources[:0]
	for _, s := range c.Sources {
		if _, opt := OptionalSourceByID(s.ID); !opt {
			kept = append(kept, s)
		}
	}
	c.Sources = kept
	legacy := len(c.Sources)

	c.Normalize()
	if len(c.Sources) != legacy+len(OptionalSources()) {
		t.Fatalf("после Normalize источников %d, ожидалось %d", len(c.Sources), legacy+len(OptionalSources()))
	}
	for _, s := range c.Sources[legacy:] {
		if s.Enabled {
			t.Errorf("дописанный источник %s включён", s.ID)
		}
	}
	// Идемпотентность: второй вызов ничего не дописывает.
	c.Normalize()
	if len(c.Sources) != legacy+len(OptionalSources()) {
		t.Fatalf("повторный Normalize размножил источники: %d", len(c.Sources))
	}
}

// Выбор пользователя нельзя перезаписывать: включённый источник остаётся включённым,
// а старые обязательные не трогаются.
func TestOptionalSources_NormalizeKeepsUserChoice(t *testing.T) {
	c := DefaultConfig()
	for i := range c.Sources {
		if c.Sources[i].ID == "igareck-black-vless" {
			c.Sources[i].Enabled = true
			c.Sources[i].LastUpdatedAt = 12345
		}
	}
	before := len(c.Sources)
	c.Normalize()
	if len(c.Sources) != before {
		t.Fatalf("Normalize изменил число источников: %d → %d", before, len(c.Sources))
	}
	for _, s := range c.Sources {
		if s.ID == "igareck-black-vless" && (!s.Enabled || s.LastUpdatedAt != 12345) {
			t.Fatalf("выбор пользователя потерян: %+v", s)
		}
	}
}

// Автор igareck переименовывает файлы: записанный в config.json старый адрес под тем же raw-корнем
// обновляется из кода, адрес-зеркало пользователя — нет. Выбор и отметки сохраняются.
func TestOptionalSources_NormalizeRefreshesURLButKeepsUserState(t *testing.T) {
	c := DefaultConfig()
	var oldIdx, mirrorIdx, caseIdx = -1, -1, -1
	for i := range c.Sources {
		switch c.Sources[i].ID {
		case "igareck-black-vless":
			oldIdx = i
			c.Sources[i].URL = igareckRawBase + "OLD_NAME_BEFORE_RENAME.txt"
			c.Sources[i].Name = "старое имя"
			c.Sources[i].Enabled = true
			c.Sources[i].AutoUpdate = false
			c.Sources[i].UpdateIntervalHours = 12
			c.Sources[i].ContentHash = "abc"
			c.Sources[i].LastUpdatedAt = 777
		case "igareck-black-ss":
			mirrorIdx = i
			c.Sources[i].URL = "https://mirror.example.invalid/ss.txt"
		case "igareck-white-cidr-all":
			caseIdx = i
			c.Sources[i].ID = "  IGARECK-White-CIDR-All "
			c.Sources[i].Enabled = true
		}
	}
	before := len(c.Sources)
	c.Normalize()
	if len(c.Sources) != before {
		t.Fatalf("Normalize размножил или потерял источники: %d → %d", before, len(c.Sources))
	}

	want, _ := OptionalSourceByID("igareck-black-vless")
	got := c.Sources[oldIdx]
	if got.URL != want.URL || got.Name != want.Name {
		t.Errorf("URL/имя не обновлены из кода: %+v", got)
	}
	if !got.Enabled || got.AutoUpdate || got.UpdateIntervalHours != 12 || got.ContentHash != "abc" || got.LastUpdatedAt != 777 {
		t.Errorf("выбор пользователя или отметки пострадали: %+v", got)
	}
	if c.Sources[mirrorIdx].URL != "https://mirror.example.invalid/ss.txt" {
		t.Errorf("зеркало пользователя перезаписано: %q", c.Sources[mirrorIdx].URL)
	}
	if c.Sources[caseIdx].ID != "igareck-white-cidr-all" || !c.Sources[caseIdx].Enabled {
		t.Errorf("ID не приведён к каноничному виду или выбор потерян: %+v", c.Sources[caseIdx])
	}
}

func TestOptionalSources_NilConfigIsSafe(t *testing.T) {
	var c *AppConfig
	if c.ensureOptionalSources() {
		t.Fatal("nil-конфиг не может ничего дописать")
	}
}

// Отметки содержимого переживают запись/чтение config.json и не раздувают файл, пока пусты.
func TestSourceConfig_ContentFieldsJSON(t *testing.T) {
	empty, _ := json.Marshal(SourceConfig{ID: "x"})
	for _, k := range []string{"content_hash", "content_first_seen_at", "content_changed_at", "content_seen_at"} {
		if strings.Contains(string(empty), k) {
			t.Errorf("пустое поле %s попало в JSON: %s", k, empty)
		}
	}
	in := SourceConfig{ID: "x", ContentHash: "abc", ContentFirstSeenAt: 10, ContentChangedAt: 20, ContentSeenAt: 30}
	raw, _ := json.Marshal(in)
	var out SourceConfig
	if err := json.Unmarshal(raw, &out); err != nil || out != in {
		t.Fatalf("круговой обмен потерял поля: %+v err=%v", out, err)
	}
}
