package singbox

import (
	"path/filepath"
	"strings"
	"testing"
)

// Контракт binaryName (дефект D-A4).
//
// Вход:      GOOS.
// Тело:      выбор имени файла sing-box.
// Выход:     windows → sing-box.exe; android → libsingbox.so; иначе → sing-box.
// Fail-safe: неизвестный GOOS даёт обычное имя, а не пустую строку.
// Инвариант: на Android имя ВСЕГДА соответствует шаблону lib*.so — иначе упаковщик Android
//            не положит файл в nativeLibraryDir, и запустить его будет неоткуда:
//            выполнение из каталога данных запрещено с Android 10 (W^X).

func TestBinaryName_PerPlatform(t *testing.T) {
	cases := map[string]string{
		"windows": "sing-box.exe",
		"android": "libsingbox.so",
		"linux":   "sing-box",
		"darwin":  "sing-box",
		"":        "sing-box",
	}
	for goos, want := range cases {
		if got := binaryName(goos); got != want {
			t.Errorf("binaryName(%q) = %q, ожидалось %q", goos, got, want)
		}
	}
}

func TestBinaryName_AndroidMatchesNativeLibPattern(t *testing.T) {
	name := binaryName("android")
	if !strings.HasPrefix(name, "lib") || !strings.HasSuffix(name, ".so") {
		t.Fatalf("имя %q не подходит под lib*.so — упаковщик Android не положит файл "+
			"в nativeLibraryDir, и выполнить его будет невозможно", name)
	}
}

// NewProcess обязан брать имя через ту же точку принятия решения, иначе на Android
// он будет искать несуществующий файл «sing-box».
func TestNewProcess_UsesPlatformBinaryName(t *testing.T) {
	oldGOOS := processGOOS
	processGOOS = func() string { return "android" }
	defer func() { processGOOS = oldGOOS }()

	binDir := filepath.Join("/data", "app", "lib", "arm64")
	p := NewProcess(binDir, "/data/data/com.apf.app/files")

	want := filepath.Join(binDir, "libsingbox.so")
	if p.binPath != want {
		t.Fatalf("binPath = %q, ожидалось %q", p.binPath, want)
	}
}
