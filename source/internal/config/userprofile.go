package config

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FindInteractiveUserProfileConfigPath — путь config.json в профиле реального пользователя,
// даже если самого файла ещё нет. Нужен службе (SYSTEM) на ЧИСТОЙ установке: FindInteractiveUser-
// ConfigPath ищет только существующий config.json, и служба оставалась в профиле SYSTEM — токен
// веб-API писался в C:\Windows\System32\config\systemprofile\..., окно читало
// %APPDATA%\APF\webui_token пользователя, не находило его и получало 401 на каждый запрос
// (заказчик, установка с нуля, 2026-11-02). Берётся профиль с самым свежим NTUSER.DAT.
func FindInteractiveUserProfileConfigPath() (string, bool) {
	if runtimeGOOS != "windows" {
		return "", false
	}
	dirs, err := globFn(filepath.Join(winUsersRoot, "*", "AppData", "Roaming"))
	if err != nil || len(dirs) == 0 {
		return "", false
	}
	type cand struct {
		roaming string
		mod     int64
	}
	var cands []cand
	for _, d := range dirs {
		user := strings.ToLower(filepath.Base(filepath.Dir(filepath.Dir(d))))
		switch user {
		case "public", "default", "default user", "all users", "defaultuser0":
			continue
		}
		fi, err := statFn(filepath.Join(filepath.Dir(filepath.Dir(d)), "NTUSER.DAT"))
		if err != nil {
			continue
		}
		cands = append(cands, cand{d, fi.ModTime().UnixNano()})
	}
	if len(cands) == 0 {
		return "", false
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].mod > cands[j].mod })
	dir := filepath.Join(cands[0].roaming, "APF")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", false
	}
	return filepath.Join(dir, "config.json"), true
}
