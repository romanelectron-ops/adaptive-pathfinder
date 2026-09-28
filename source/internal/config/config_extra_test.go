package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// DataDir — APPDATA empty -> falls back to UserHomeDir (Windows branch)
func TestDataDir_AppDataEmptyFallback(t *testing.T) {
	t.Setenv("APPDATA", "")
	dir := DataDir()
	if dir == "" {
		t.Error("DataDir() must not be empty even when APPDATA is empty")
	}
	t.Logf("OK: APPDATA empty -> DataDir=%s", dir)
}

// Регрессия (консилиум 2026-08-10, low): APPDATA И UserHomeDir оба пусты (служебная
// учётка Windows без загруженного профиля, например Windows-служба через SCM) — раньше
// filepath.Join("", "APF") давал ОТНОСИТЕЛЬНЫЙ путь "APF", нарушая заявленный инвариант
// «Path — ВСЕГДА абсолютный». Проверяем обе ветки (windows и default), где встречается
// тот же паттерн base,_ := os.UserHomeDir(); filepath.Join(base, ...).
func TestDataDir_BothEmpty_StaysAbsolute(t *testing.T) {
	oldGOOS, oldHome, oldTemp := runtimeGOOS, osUserHomeDirFn, osTempDirFn
	defer func() { runtimeGOOS, osUserHomeDirFn, osTempDirFn = oldGOOS, oldHome, oldTemp }()

	osUserHomeDirFn = func() (string, error) { return "", fmt.Errorf("no home dir") }
	osTempDirFn = func() string { return `C:\Windows\Temp` }
	t.Setenv("APPDATA", "")

	for _, goos := range []string{"windows", "linux"} {
		runtimeGOOS = goos
		dir := DataDir()
		if dir == "" {
			t.Errorf("GOOS=%s: DataDir() пуст при пустых APPDATA и UserHomeDir", goos)
		}
		if !filepath.IsAbs(dir) {
			t.Errorf("GOOS=%s: DataDir() = %q — относительный путь при пустых "+
				"APPDATA и UserHomeDir, нарушает заявленный инвариант", goos, dir)
		}
	}
}

// EnsureDirs — error path: DataDir() inside a file -> MkdirAll fails -> return err
// F-31: форсируем windows-ветку DataDir() через инъекцию runtimeGOOS, чтобы тест
// был кросс-платформенным. Иначе на Linux DataDir() игнорирует APPDATA (ветка default
// → ~/.config/apf), MkdirAll успешно создаёт каталог, и тест ложно-падает.
func TestEnsureDirs_Error(t *testing.T) {
	oldGOOS := runtimeGOOS
	runtimeGOOS = "windows"
	defer func() { runtimeGOOS = oldGOOS }()

	tmp := t.TempDir()
	blockFile := filepath.Join(tmp, "notadir")
	if err := os.WriteFile(blockFile, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	// APPDATA = blockFile -> DataDir() = blockFile\APF
	// os.MkdirAll("blockFile\APF") fails because blockFile is a regular file
	t.Setenv("APPDATA", blockFile)

	err := EnsureDirs()
	if err == nil {
		t.Error("EnsureDirs should return error when MkdirAll fails")
	}
	t.Logf("OK: EnsureDirs error path: %v", err)
}

// SaveConfig — MkdirAll error path: ConfigPath parent is a file
// F-31: см. TestEnsureDirs_Error — форсируем windows-ветку для кросс-платформенности.
func TestSaveConfig_MkdirAllError(t *testing.T) {
	oldGOOS := runtimeGOOS
	runtimeGOOS = "windows"
	defer func() { runtimeGOOS = oldGOOS }()

	tmp := t.TempDir()
	blockFile := filepath.Join(tmp, "notadir")
	if err := os.WriteFile(blockFile, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	// APPDATA = blockFile -> ConfigPath() = blockFile\APF\config.json
	t.Setenv("APPDATA", blockFile)

	err := SaveConfig(map[string]string{"key": "val"})
	if err == nil {
		t.Error("SaveConfig should return error when MkdirAll fails")
	}
	t.Logf("OK: SaveConfig MkdirAll error: %v", err)
}

// errMarshaler — triggers json.MarshalIndent error in SaveConfig
type errMarshaler struct{}

func (errMarshaler) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("intentional marshal error")
}

// SaveConfig — json.MarshalIndent error path
func TestSaveConfig_MarshalError(t *testing.T) {
	// Ensure DataDir exists so MkdirAll succeeds, reaching the marshal step
	if err := os.MkdirAll(DataDir(), 0700); err != nil {
		t.Skipf("cannot create DataDir: %v", err)
	}

	err := SaveConfig(errMarshaler{})
	if err == nil {
		t.Error("SaveConfig should return error when json.MarshalIndent fails")
	}
	t.Logf("OK: SaveConfig marshal error: %v", err)
}
