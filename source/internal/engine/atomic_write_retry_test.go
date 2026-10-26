package engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Запись пула не теряется, если файл в этот момент кто-то читает: на Windows rename поверх
// открытого файла отказывает, и writeFileAtomic обязан повторить попытку, а не вернуть ошибку.
func TestWriteFileAtomic_RetriesWhileTargetIsHeldOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodes_cache.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path) // читатель держит файл
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(120 * time.Millisecond)
		f.Close()
	}()
	if err := writeFileAtomic(path, []byte("new")); err != nil {
		t.Fatalf("запись не пережила кратковременного читателя: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "new" {
		t.Fatalf("содержимое %q, err=%v", got, err)
	}
	if _, err := os.Stat(path + ".tmp"); err == nil {
		t.Error("остался временный файл")
	}
}
