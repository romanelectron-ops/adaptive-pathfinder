package config

import (
	"os"
	"testing"
	"time"
)

// TestFindInteractiveUserConfigPath — обход "служба под SYSTEM не видит config.json
// реального пользователя" (docs/TZ_CONFIG_RELOAD_AND_KS_SAFETY_v1.0.md, найдено живым
// инцидентом 2026-08-19: LoadInto() отработал без ошибки, но искал не там).

type fakeFileInfo struct {
	os.FileInfo
	modTime time.Time
}

func (f fakeFileInfo) ModTime() time.Time { return f.modTime }

func TestFindInteractiveUserConfigPath_NonWindows(t *testing.T) {
	oldGOOS := runtimeGOOS
	defer func() { runtimeGOOS = oldGOOS }()
	runtimeGOOS = "linux"

	if _, ok := FindInteractiveUserConfigPath(); ok {
		t.Error("на не-Windows платформе поиск не должен запускаться вообще")
	}
}

func TestFindInteractiveUserConfigPath_NoMatches(t *testing.T) {
	oldGOOS, oldGlob := runtimeGOOS, globFn
	defer func() { runtimeGOOS, globFn = oldGOOS, oldGlob }()

	runtimeGOOS = "windows"
	globFn = func(pattern string) ([]string, error) { return nil, nil }

	if _, ok := FindInteractiveUserConfigPath(); ok {
		t.Error("пустой список совпадений должен давать found=false")
	}
}

func TestFindInteractiveUserConfigPath_PicksNewest(t *testing.T) {
	oldGOOS, oldGlob, oldStat := runtimeGOOS, globFn, statFn
	defer func() { runtimeGOOS, globFn, statFn = oldGOOS, oldGlob, oldStat }()

	runtimeGOOS = "windows"
	matches := []string{
		`C:\Users\old\AppData\Roaming\APF\config.json`,
		`C:\Users\real\AppData\Roaming\APF\config.json`,
	}
	globFn = func(pattern string) ([]string, error) { return matches, nil }
	statFn = func(name string) (os.FileInfo, error) {
		switch name {
		case `C:\Users\old\AppData\Roaming\APF\config.json`:
			return fakeFileInfo{modTime: time.Now().Add(-48 * time.Hour)}, nil
		case `C:\Users\real\AppData\Roaming\APF\config.json`:
			return fakeFileInfo{modTime: time.Now()}, nil
		}
		return nil, os.ErrNotExist
	}

	path, ok := FindInteractiveUserConfigPath()
	if !ok {
		t.Fatal("ожидался found=true")
	}
	if path != `C:\Users\real\AppData\Roaming\APF\config.json` {
		t.Errorf("должен выбрать самый свежий файл, получили %q", path)
	}
}
