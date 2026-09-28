package emergency

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── helpers ────────────────────────────────────────────────────────────────

// makeFile создаёт файл с заданным содержимым внутри dir.
func makeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("makeFile %s: %v", name, err)
	}
	return path
}

// ─── Wiper.Wipe ─────────────────────────────────────────────────────────────

func TestWipe_NonExistentDir(t *testing.T) {
	w := New()
	res := w.Wipe("/no/such/path/abcxyz", "/also/missing", WipeOptions{ShredPasses: 1})
	if res == nil {
		t.Fatal("expected non-nil result")
	}
	// Несуществующая директория не должна добавлять ошибки (IsNotExist игнорируется)
	if len(res.Errors) > 0 {
		t.Errorf("unexpected errors for missing dir: %v", res.Errors)
	}
	if res.FilesDeleted != 0 {
		t.Errorf("expected 0 files deleted, got %d", res.FilesDeleted)
	}
	t.Logf("OK: non-existent dir → no errors, 0 files, duration=%s", res.Duration)
}

func TestWipe_EmptyDataDir(t *testing.T) {
	dataDir := t.TempDir()
	w := New()
	res := w.Wipe(dataDir, "", WipeOptions{ShredPasses: 1})
	if res == nil {
		t.Fatal("expected non-nil result")
	}
	if len(res.Errors) > 0 {
		t.Errorf("unexpected errors: %v", res.Errors)
	}
	t.Logf("OK: empty dir, files=%d duration=%s", res.FilesDeleted, res.Duration)
}

func TestWipe_DeletesFiles(t *testing.T) {
	dataDir := t.TempDir()
	makeFile(t, dataDir, "secret.json", `{"key":"value"}`)
	makeFile(t, dataDir, "config.dat", "binary data here")

	w := New()
	res := w.Wipe(dataDir, "", WipeOptions{ShredPasses: 1})

	if res.FilesDeleted != 2 {
		t.Errorf("expected 2 files deleted, got %d (errors: %v)", res.FilesDeleted, res.Errors)
	}
	if res.BytesDeleted == 0 {
		t.Error("BytesDeleted should be > 0")
	}
	// Файлы должны быть удалены
	entries, _ := os.ReadDir(dataDir)
	if len(entries) != 0 {
		t.Errorf("directory should be empty after wipe, still has %d entries", len(entries))
	}
	t.Logf("OK: deleted=%d bytes=%d duration=%s", res.FilesDeleted, res.BytesDeleted, res.Duration)
}

func TestWipe_ShredMultiplePasses(t *testing.T) {
	dataDir := t.TempDir()
	makeFile(t, dataDir, "data.bin", strings.Repeat("SENSITIVE", 100))

	w := New()
	res := w.Wipe(dataDir, "", WipeOptions{ShredPasses: 3})

	if res.FilesDeleted != 1 {
		t.Errorf("expected 1 file deleted, got %d (errors: %v)", res.FilesDeleted, res.Errors)
	}
	t.Logf("OK: 3-pass shred, deleted=%d bytes=%d", res.FilesDeleted, res.BytesDeleted)
}

func TestWipe_ShredPassesDefault(t *testing.T) {
	// ShredPasses=0 должен быть исправлен до 1
	dataDir := t.TempDir()
	makeFile(t, dataDir, "f.txt", "hello")

	w := New()
	res := w.Wipe(dataDir, "", WipeOptions{ShredPasses: 0})

	if res.FilesDeleted != 1 {
		t.Errorf("expected 1 file deleted, got %d", res.FilesDeleted)
	}
	t.Log("OK: ShredPasses=0 normalized to 1")
}

func TestWipe_WithProgress(t *testing.T) {
	dataDir := t.TempDir()
	binDir := t.TempDir()
	makeFile(t, dataDir, "a.dat", "aaa")

	var steps []string
	opts := WipeOptions{
		ShredPasses: 1,
		WipeSelf:    true,
		OnProgress: func(step, total int, msg string) {
			steps = append(steps, msg)
		},
	}

	w := New()
	w.Wipe(dataDir, binDir, opts)

	if len(steps) == 0 {
		t.Error("OnProgress should have been called at least once")
	}
	t.Logf("OK: progress steps=%v", steps)
}

func TestWipe_WipeSingBoxSkipped(t *testing.T) {
	dataDir := t.TempDir()
	// файл со "sing-box" в имени
	makeFile(t, dataDir, "sing-box.exe", "binary")
	// обычный файл
	makeFile(t, dataDir, "config.json", `{}`)

	w := New()
	// WipeSingBox=false → sing-box файлы должны быть пропущены
	res := w.Wipe(dataDir, "", WipeOptions{ShredPasses: 1, WipeSingBox: false})

	// config.json должен быть удалён, sing-box.exe — нет
	if res.FilesDeleted != 1 {
		t.Errorf("expected 1 file deleted (sing-box skipped), got %d", res.FilesDeleted)
	}
	// sing-box.exe должен остаться
	if _, err := os.Stat(filepath.Join(dataDir, "sing-box.exe")); os.IsNotExist(err) {
		t.Error("sing-box.exe should NOT be deleted when WipeSingBox=false")
	}
	t.Logf("OK: sing-box preserved, deleted=%d", res.FilesDeleted)
}

func TestWipe_WipeSingBoxEnabled(t *testing.T) {
	dataDir := t.TempDir()
	makeFile(t, dataDir, "sing-box.exe", "binary")
	makeFile(t, dataDir, "config.json", `{}`)

	w := New()
	res := w.Wipe(dataDir, "", WipeOptions{ShredPasses: 1, WipeSingBox: true})

	if res.FilesDeleted != 2 {
		t.Errorf("expected 2 files deleted (WipeSingBox=true), got %d (errors=%v)", res.FilesDeleted, res.Errors)
	}
	t.Logf("OK: both files wiped, deleted=%d", res.FilesDeleted)
}

func TestWipe_BinDirSeparate(t *testing.T) {
	dataDir := t.TempDir()
	binDir := t.TempDir()
	makeFile(t, dataDir, "data.json", "data")
	makeFile(t, binDir, "apf.exe", "binary")

	w := New()
	res := w.Wipe(dataDir, binDir, WipeOptions{ShredPasses: 1, WipeSelf: true})

	if res.FilesDeleted != 2 {
		t.Errorf("expected 2 files deleted from both dirs, got %d (errors=%v)", res.FilesDeleted, res.Errors)
	}
	t.Logf("OK: data+bin wiped, deleted=%d bytes=%d", res.FilesDeleted, res.BytesDeleted)
}

func TestWipe_SingleFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "wipe_test_*.bin")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.WriteString(strings.Repeat("X", 512))
	tmpFile.Close()
	path := tmpFile.Name()
	defer os.Remove(path) // на случай если wipe не сработает

	w := New()
	// wipePath напрямую вызывает removeFile для единственного файла
	res := &WipeResult{}
	w.wipePath(path, WipeOptions{ShredPasses: 2}, res)

	if res.FilesDeleted != 1 {
		t.Errorf("expected 1 file deleted, got %d (errors=%v)", res.FilesDeleted, res.Errors)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("file should be deleted after wipe")
	}
	t.Logf("OK: single file wipe, bytes=%d", res.BytesDeleted)
}

func TestOverwriteWithZeros_EmptyFile(t *testing.T) {
	f, err := os.CreateTemp("", "zero_test_*.bin")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	// Пустой файл — не должно быть ошибки
	if err := overwriteWithZeros(f.Name(), 1); err != nil {
		t.Errorf("unexpected error on empty file: %v", err)
	}
	t.Log("OK: empty file → no error")
}

func TestOverwriteWithZeros_NonExistent(t *testing.T) {
	err := overwriteWithZeros("/no/such/file.bin", 1)
	if err == nil {
		t.Error("expected error for non-existent file")
	}
	t.Logf("OK: non-existent file → error: %v", err)
}

func TestOverwriteWithZeros_Directory(t *testing.T) {
	dir := t.TempDir()
	// Директория — функция должна вернуть nil (пропускает директории)
	if err := overwriteWithZeros(dir, 1); err != nil {
		t.Errorf("unexpected error for directory: %v", err)
	}
	t.Log("OK: directory → nil (skipped)")
}

func TestWipe_DurationTracked(t *testing.T) {
	dir := t.TempDir()
	// Create a real file so the wipe has measurable work to do
	makeFile(t, dir, "dummy.dat", "some secret data to wipe cleanly")
	w := New()
	res := w.Wipe(dir, "", WipeOptions{ShredPasses: 1})
	if res.Duration < 0 {
		t.Error("Duration should be >= 0")
	}
	t.Logf("OK: duration=%s", res.Duration)
}
