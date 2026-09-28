package config

import (
	"path/filepath"
	"testing"
)

// Контракт BinDir на Android (дефект D-A11).
//
// Вход:      runtimeGOOS == "android"; переменные APF_BIN_DIR и APF_DATA_DIR.
// Тело:      выбор каталога, откуда запускается sing-box.
// Выход:     APF_BIN_DIR, если задан; иначе DataDir()/bin.
// Игнорирует: os.Executable() — на Android он указывает на /system/bin/app_process64,
//             и путь «рядом с исполняемым файлом» ведёт в чужой системный каталог.
// Fail-safe: пустой APF_BIN_DIR не приводит к системному пути — только к каталогу данных.
// Инвариант: BinDir() на Android НИКОГДА не возвращает путь внутри /system.

func TestBinDir_Android_UsesExplicitBinDir(t *testing.T) {
	oldGOOS := runtimeGOOS
	runtimeGOOS = "android"
	defer func() { runtimeGOOS = oldGOOS }()

	want := "/data/app/com.apf.app-1/lib/arm64"
	t.Setenv("APF_BIN_DIR", want)

	if got := BinDir(); got != want {
		t.Fatalf("BinDir() = %q, ожидалось %q (значение APF_BIN_DIR)", got, want)
	}
}

func TestBinDir_Android_FallsBackToDataDir(t *testing.T) {
	oldGOOS := runtimeGOOS
	runtimeGOOS = "android"
	defer func() { runtimeGOOS = oldGOOS }()

	t.Setenv("APF_BIN_DIR", "")
	t.Setenv("APF_DATA_DIR", "/data/data/com.apf.app/files")

	want := filepath.Join("/data/data/com.apf.app/files", "bin")
	if got := BinDir(); got != want {
		t.Fatalf("BinDir() = %q, ожидалось %q", got, want)
	}
}

// Главный инвариант: что бы ни было в окружении, на Android мы не уходим в /system.
// Именно этот путь ломал EnsureDirs() и не давал androidbridge.Init дойти до движка.
func TestBinDir_Android_NeverPointsIntoSystem(t *testing.T) {
	oldGOOS := runtimeGOOS
	runtimeGOOS = "android"
	defer func() { runtimeGOOS = oldGOOS }()

	for _, binEnv := range []string{"", "/data/app/x/lib/arm64"} {
		t.Setenv("APF_BIN_DIR", binEnv)
		t.Setenv("APF_DATA_DIR", "")
		got := BinDir()
		if len(got) >= 7 && got[:7] == "/system" {
			t.Fatalf("BinDir() = %q — системный каталог, запуск и запись там невозможны", got)
		}
	}
}

// Регрессия: на остальных платформах поведение не изменилось.
func TestBinDir_NonAndroid_StillNextToExecutable(t *testing.T) {
	oldGOOS := runtimeGOOS
	runtimeGOOS = "windows"
	defer func() { runtimeGOOS = oldGOOS }()

	oldExe := osExecutableFn
	osExecutableFn = func() (string, error) { return filepath.Join("C:", "apf", "apf.exe"), nil }
	defer func() { osExecutableFn = oldExe }()

	want := filepath.Join("C:", "apf", "bin")
	if got := BinDir(); got != want {
		t.Fatalf("BinDir() = %q, ожидалось %q", got, want)
	}
}
