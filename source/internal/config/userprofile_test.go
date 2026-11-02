package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFindInteractiveUserProfileConfigPath_PicksNewestRealProfile(t *testing.T) {
	root := t.TempDir()
	mk := func(user string, age time.Duration) {
		p := filepath.Join(root, user)
		if err := os.MkdirAll(filepath.Join(p, "AppData", "Roaming"), 0o755); err != nil {
			t.Fatal(err)
		}
		nt := filepath.Join(p, "NTUSER.DAT")
		if err := os.WriteFile(nt, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		ts := time.Now().Add(-age)
		_ = os.Chtimes(nt, ts, ts)
	}
	mk("Old", 48*time.Hour)
	mk("Real", time.Hour)
	mk("Public", 0)
	mk("Default", 0)
	oldRoot, oldOS := winUsersRoot, runtimeGOOS
	winUsersRoot, runtimeGOOS = root, "windows"
	defer func() { winUsersRoot, runtimeGOOS = oldRoot, oldOS }()

	got, ok := FindInteractiveUserProfileConfigPath()
	if !ok {
		t.Fatal("профиль не найден")
	}
	want := filepath.Join(root, "Real", "AppData", "Roaming", "APF", "config.json")
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	if _, err := os.Stat(filepath.Dir(got)); err != nil {
		t.Error("каталог APF не создан")
	}
}

func TestFindInteractiveUserProfileConfigPath_NoProfiles(t *testing.T) {
	oldRoot, oldOS := winUsersRoot, runtimeGOOS
	winUsersRoot, runtimeGOOS = t.TempDir(), "windows"
	defer func() { winUsersRoot, runtimeGOOS = oldRoot, oldOS }()
	if _, ok := FindInteractiveUserProfileConfigPath(); ok {
		t.Error("профилей нет — ожидалось false")
	}
}
