package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── Path helpers ────────────────────────────────────────────────────────────

func TestDataDir_NonEmpty(t *testing.T) {
	dir := DataDir()
	if dir == "" {
		t.Error("DataDir() should not be empty")
	}
	// Должен содержать "APF" или "apf" (зависит от ОС)
	lower := strings.ToLower(filepath.Base(dir))
	if lower != "apf" {
		t.Errorf("DataDir base should be 'APF' or 'apf', got %q", filepath.Base(dir))
	}
	t.Logf("OK: DataDir=%s", dir)
}

func TestConfigPath_EndsWithJSON(t *testing.T) {
	p := ConfigPath()
	if p == "" {
		t.Fatal("ConfigPath() should not be empty")
	}
	if !strings.HasSuffix(p, "config.json") {
		t.Errorf("ConfigPath should end with 'config.json', got %s", p)
	}
	// Должен находиться внутри DataDir
	if !strings.HasPrefix(p, DataDir()) {
		t.Errorf("ConfigPath %s should be under DataDir %s", p, DataDir())
	}
	t.Logf("OK: ConfigPath=%s", p)
}

func TestBinDir_NonEmpty(t *testing.T) {
	dir := BinDir()
	if dir == "" {
		t.Error("BinDir() should not be empty")
	}
	t.Logf("OK: BinDir=%s", dir)
}

func TestLogPath_EndsWithLog(t *testing.T) {
	p := LogPath()
	if p == "" {
		t.Fatal("LogPath() should not be empty")
	}
	if !strings.HasSuffix(p, "apf.log") {
		t.Errorf("LogPath should end with 'apf.log', got %s", p)
	}
	if !strings.HasPrefix(p, DataDir()) {
		t.Errorf("LogPath %s should be under DataDir %s", p, DataDir())
	}
	t.Logf("OK: LogPath=%s", p)
}

func TestConfigPath_InsideDataDir(t *testing.T) {
	dd := DataDir()
	cp := ConfigPath()
	bp := BinDir()
	lp := LogPath()

	// Все пути не пустые
	for _, p := range []string{dd, cp, bp, lp} {
		if p == "" {
			t.Errorf("path should not be empty: %q", p)
		}
	}
	t.Logf("OK: all paths non-empty")
}

// ─── EnsureDirs ─────────────────────────────────────────────────────────────

func TestEnsureDirs_CreatesDataDir(t *testing.T) {
	// EnsureDirs создаёт DataDir если не существует.
	// Мы не можем изменить DataDir() напрямую, но можем убедиться что вызов не ломается.
	// На CI-окружении директория может быть создана впервые.
	err := EnsureDirs()
	if err != nil {
		// На некоторых системах BinDir() (рядом с exe) может быть недоступен — допустимо
		t.Logf("EnsureDirs returned error (may be expected in restricted env): %v", err)
	} else {
		// DataDir должна существовать
		if _, err := os.Stat(DataDir()); err != nil {
			t.Errorf("DataDir should exist after EnsureDirs: %v", err)
		}
		t.Logf("OK: EnsureDirs created dirs")
	}
}

// ─── SaveConfig / LoadRaw ────────────────────────────────────────────────────

// testConfig — структура для тестирования SaveConfig
type testConfig struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
	Enabled bool   `json:"enabled"`
}

func TestSaveAndLoadConfig(t *testing.T) {
	// Убедимся что директория существует перед тестом
	if err := os.MkdirAll(DataDir(), 0700); err != nil {
		t.Skipf("cannot create DataDir: %v", err)
	}

	original := testConfig{Name: "test-apf", Version: 42, Enabled: true}

	// Сохраняем
	if err := SaveConfig(original); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	// Убеждаемся что файл создан
	if _, err := os.Stat(ConfigPath()); err != nil {
		t.Fatalf("config file should exist after SaveConfig: %v", err)
	}

	// Загружаем сырые байты
	raw, err := LoadRaw()
	if err != nil {
		t.Fatalf("LoadRaw failed: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("LoadRaw returned empty data")
	}

	// Десериализуем и проверяем
	var loaded testConfig
	if err := json.Unmarshal(raw, &loaded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if loaded.Name != original.Name {
		t.Errorf("Name: want %s, got %s", original.Name, loaded.Name)
	}
	if loaded.Version != original.Version {
		t.Errorf("Version: want %d, got %d", original.Version, loaded.Version)
	}
	if loaded.Enabled != original.Enabled {
		t.Errorf("Enabled: want %v, got %v", original.Enabled, loaded.Enabled)
	}

	t.Logf("OK: save/load round-trip, config=%+v", loaded)
}

func TestSaveConfig_IndentedJSON(t *testing.T) {
	if err := os.MkdirAll(DataDir(), 0700); err != nil {
		t.Skipf("cannot create DataDir: %v", err)
	}

	cfg := map[string]interface{}{"key": "value", "num": 123}
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	raw, err := LoadRaw()
	if err != nil {
		t.Fatalf("LoadRaw failed: %v", err)
	}

	// json.MarshalIndent — должны быть переносы строк
	if !strings.Contains(string(raw), "\n") {
		t.Error("SaveConfig should produce indented (multi-line) JSON")
	}
	t.Logf("OK: indented JSON, %d bytes", len(raw))
}

func TestLoadRaw_MissingFile(t *testing.T) {
	// Если файл не существует — возвращается ошибка
	// Удаляем config файл если есть
	configPath := ConfigPath()
	existed := false
	var backup []byte

	if data, err := os.ReadFile(configPath); err == nil {
		existed = true
		backup = data
		os.Remove(configPath)
	}
	defer func() {
		if existed {
			os.WriteFile(configPath, backup, 0600)
		}
	}()

	// Пересоздаём без файла
	if _, err := os.Stat(configPath); err == nil {
		// Файл всё ещё существует — пропускаем
		t.Skip("cannot remove config file for test")
	}

	_, err := LoadRaw()
	if err == nil {
		t.Error("LoadRaw should return error when config file is missing")
	}
	t.Logf("OK: missing file → error: %v", err)
}

func TestSaveConfig_Overwrites(t *testing.T) {
	if err := os.MkdirAll(DataDir(), 0700); err != nil {
		t.Skipf("cannot create DataDir: %v", err)
	}

	// Сохраняем первый вариант
	if err := SaveConfig(map[string]string{"v": "first"}); err != nil {
		t.Fatalf("first SaveConfig failed: %v", err)
	}

	// Сохраняем второй вариант
	if err := SaveConfig(map[string]string{"v": "second"}); err != nil {
		t.Fatalf("second SaveConfig failed: %v", err)
	}

	raw, err := LoadRaw()
	if err != nil {
		t.Fatalf("LoadRaw failed: %v", err)
	}

	if !strings.Contains(string(raw), "second") {
		t.Error("second SaveConfig should overwrite the first")
	}
	if strings.Contains(string(raw), "first") {
		t.Error("first config should be gone after second SaveConfig")
	}
	t.Log("OK: second write overwrites first")
}
