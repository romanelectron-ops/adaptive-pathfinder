package models

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/config"
)

// json.Unmarshal раскладывает массив sources поэлементно ПОВЕРХ дефолтных слотов: рукописная запись,
// в которой нет auto_update, унаследовала бы значение дефолтного слота. PrepareForJSON сбрасывает
// дефолтный срез, если sources есть в файле.
func TestLoadInto_SourcesAreNotInheritedFromDefaultSlots(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	// Шесть записей: шестая и дальше раньше попадали на слот igareck (auto_update=true, интервал 3).
	body := `{"sources":[` +
		`{"id":"a","url":"https://example.org/a","type":"subscription","enabled":true},` +
		`{"id":"b","url":"https://example.org/b","type":"subscription","enabled":true},` +
		`{"id":"c","url":"https://example.org/c","type":"subscription","enabled":true},` +
		`{"id":"d","url":"https://example.org/d","type":"subscription","enabled":true},` +
		`{"id":"e","url":"https://example.org/e","type":"subscription","enabled":true},` +
		`{"id":"f","url":"https://example.org/f","type":"subscription","enabled":true}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	found, err := config.LoadIntoFrom(path, cfg)
	if err != nil || !found {
		t.Fatalf("LoadIntoFrom: found=%v err=%v", found, err)
	}
	if len(cfg.Sources) != 6 {
		t.Fatalf("источников %d, ожидалось 6 из файла (без дефолтных)", len(cfg.Sources))
	}
	for _, s := range cfg.Sources {
		if s.AutoUpdate || s.UpdateIntervalHours != 0 {
			t.Errorf("запись %s унаследовала значения дефолтного слота: %+v", s.ID, s)
		}
	}
	// Нормализация дописывает недостающие встроенные igareck выключенными.
	cfg.Normalize()
	if len(cfg.Sources) != 6+len(OptionalSources()) {
		t.Errorf("после Normalize источников %d, ожидалось %d", len(cfg.Sources), 6+len(OptionalSources()))
	}
}

// Файл без ключа sources не должен лишать пользователя встроенных источников.
func TestLoadInto_NoSourcesKeepsDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"listen_port":10808}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	want := len(cfg.Sources)
	if _, err := config.LoadIntoFrom(path, cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Sources) != want {
		t.Errorf("без ключа sources источники по умолчанию потеряны: %d -> %d", want, len(cfg.Sources))
	}
}
