//go:build windows

package config

import (
	"golang.org/x/sys/windows"
)

// S-4 (TZ v1.4, лот L1-KS) — реализация hardenPortFileACLFn для Windows.
//
// НЕ в config.go: golang.org/x/sys/windows физически не компилируется на других GOOS (это не
// вопрос стиля — пакет использует Windows-специфичные типы синтаксически), а config.go —
// кросс-платформенный файл без build-тега (его импортируют Android/Linux сборки). Поэтому сама
// реализация живёт в отдельном файле с `//go:build windows`, а config.go знает о ней только
// через var hardenPortFileACLFn.
func init() {
	hardenPortFileACLFn = hardenPortFileACLWindows
}

// hardenPortFileACLWindows строит PROTECTED (без наследования от родительского каталога) DACL,
// разрешающий полный доступ ТОЛЬКО:
//   - Local System (SY)           — apf-svc.exe обычно пишет файл под учёткой SYSTEM;
//   - Builtin Administrators (BA) — администратор может продиагностировать;
//   - фактический владелец процесса — на случай, если файл пишет НЕ SYSTEM (например, apf.exe,
//     запущенный интерактивным пользователем напрямую, без службы).
//
// НЕ входят Everyone/Users/Authenticated Users — именно они делали файл мировочитаемым через
// унаследованный от %ProgramData%\APF DACL каталога (S-4, TB-подобная находка консилиума).
//
// Реализация — чистый Go (SetNamedSecurityInfo + SDDL из уже vendored golang.org/x/sys/windows),
// без cgo и без внешних утилит (icacls и т.п.).
func hardenPortFileACLWindows(path string) error {
	// "OW" (SDDL_OWNER_RIGHTS, S-1-3-4) — безопасный fallback-владелец в SDDL: разрешает доступ
	// ТЕКУЩЕМУ владельцу объекта на момент проверки прав, что бы ни случилось с определением
	// реального SID процесса ниже. Не используется в 100% случаев — только если GetTokenUser
	// по какой-то причине не сработал (у процесса всегда есть собственный токен, поэтому это
	// практически недостижимая ветка, но fail-safe важнее лаконичности).
	ownerSID := "OW"
	if tok := windows.GetCurrentProcessToken(); tok != 0 {
		if tu, err := tok.GetTokenUser(); err == nil && tu.User.Sid != nil {
			ownerSID = tu.User.Sid.String()
		}
	}

	// D:P            — DACL, PROTECTED (не наследуется от каталога, тот самый источник S-4).
	// (A;;FA;;;SY)   — Local System: полный доступ.
	// (A;;FA;;;BA)   — Builtin Administrators: полный доступ.
	// (A;;FA;;;<SID>)— фактический владелец процесса (или OW-fallback): полный доступ.
	sddl := "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + ownerSID + ")"

	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
}
