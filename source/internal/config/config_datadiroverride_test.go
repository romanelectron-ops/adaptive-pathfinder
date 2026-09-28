package config

import "testing"

// ── SetDataDirOverride (P1.1, docs/TZ_WINDOWS_CONSILIUM_FINDINGS_v1.0.md) ────────────────────
//
// Служба apf-svc.exe (LocalSystem) резолвит нативный DataDir() в профиль SYSTEM, отдельный от
// профиля реального пользователя — nodes_cache.json и другие файлы данных расходятся с тем, что
// видит интерактивный GUI. SetDataDirOverride даёт cmd/apf-svc/main.go способ подставить каталог
// найденного пользовательского config.json (тот же, что уже резолвит FindInteractiveUserConfigPath)
// ДО engine.New()/NewServiceHost().

func TestSetDataDirOverride_TakesPrecedence(t *testing.T) {
	t.Cleanup(func() { SetDataDirOverride("") })

	orig := runtimeGOOS
	defer func() { runtimeGOOS = orig }()
	runtimeGOOS = "windows"
	t.Setenv("APPDATA", `C:\Windows\System32\config\systemprofile\AppData\Roaming`)

	SetDataDirOverride(`C:\Users\real-user\AppData\Roaming\APF`)

	if got := DataDir(); got != `C:\Users\real-user\AppData\Roaming\APF` {
		t.Errorf("DataDir() = %q, want override path", got)
	}
}

func TestSetDataDirOverride_EmptyRestoresNative(t *testing.T) {
	orig := runtimeGOOS
	defer func() { runtimeGOOS = orig }()
	runtimeGOOS = "windows"
	t.Setenv("APPDATA", `C:\Users\alice\AppData\Roaming`)

	SetDataDirOverride(`C:\somewhere\else`)
	SetDataDirOverride("") // как в t.Cleanup — сброс должен вернуть нативное поведение

	want := `C:\Users\alice\AppData\Roaming\APF`
	if got := DataDir(); got != want {
		t.Errorf("DataDir() after clearing override = %q, want %q", got, want)
	}
}
