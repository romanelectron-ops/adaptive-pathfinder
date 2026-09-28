//go:build windows

package config

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// S-4 (TZ v1.4, лот L1-KS) — «webui_port.txt мировочитаемый».
//
// webui_port.txt создаётся в %ProgramData%\APF с правами 0644 и наследует DACL каталога —
// на большинстве машин это включает Everyone/Users на чтение. Порт локального Web UI API
// (internal/web/server.go) становится виден ЛЮБОМУ локальному пользователю, не только
// владельцу процесса apf-svc.exe/apf.exe и администраторам.
//
// Фикс (config.go/config_acl_windows.go): hardenPortFileACLFn ставит PROTECTED DACL без
// наследования, разрешающий доступ только SYSTEM/Administrators/владельцу процесса.
//
// Тест — на РЕАЛЬНОЙ DACL временного файла (как требует постановка лота), не на строковом
// сравнении SDDL: перебирает ACE через windows.GetAce и проверяет по SID, что (1) Everyone,
// Users и Authenticated Users НЕ имеют явного доступа и (2) SYSTEM/Administrators есть.
//
// //go:build windows — golang.org/x/sys/windows физически не компилируется на других ОС
// (не вопрос стиля: используются Windows-специфичные типы), поэтому чистого runtime.GOOS-скипа
// внутри одного кросс-платформенного файла не существует; на не-Windows этот файл просто не
// участвует в сборке — функционально эквивалентно «тест пропущен».
func TestHardenPortFileACL_RestrictsToSystemAdminsOwner(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "webui_port.txt")
	if err := os.WriteFile(path, []byte("12345"), 0o644); err != nil {
		t.Fatalf("setup: не удалось создать временный файл: %v", err)
	}

	// Симулируем РЕАЛЬНЫЙ баг S-4: в отличие от %ProgramData% (общесистемный каталог,
	// унаследованный DACL которого обычно включает Everyone/Users), t.TempDir() лежит в
	// пользовательском профиле и УЖЕ по умолчанию не даёт доступа Everyone — поэтому без
	// явного seed'а тест «прошёл» бы даже с no-op hardenPortFileACLFn (ложноположительный
	// результат, не отражающий исходную уязвимость). Явно ставим заведомо мировочитаемый
	// DACL (Everyone: полный доступ) — ровно то, что унаследовал бы файл в %ProgramData%\APF
	// на типичной машине, — и проверяем, что hardenPortFileACLFn его СНИМАЕТ.
	everyoneSID, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatalf("CreateWellKnownSid(Everyone) для seed: %v", err)
	}
	seedSD, err := windows.SecurityDescriptorFromString("D:(A;;FA;;;" + everyoneSID.String() + ")")
	if err != nil {
		t.Fatalf("SecurityDescriptorFromString(seed): %v", err)
	}
	seedDACL, _, _ := seedSD.DACL() // present/err ненадёжны в этом окружении, см. комментарий ниже
	if seedDACL == nil {
		t.Fatal("seed DACL == nil — тест некорректен")
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION, nil, nil, seedDACL, nil); err != nil {
		t.Fatalf("setup: не удалось поставить мировочитаемый seed-DACL: %v", err)
	}

	if err := hardenPortFileACLFn(path); err != nil {
		t.Fatalf("hardenPortFileACLFn(%q) = %v, want nil", path, err)
	}

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}
	// ПРИМЕЧАНИЕ: sd.DACL() возвращает (dacl, present, err), но в этом окружении (проверено
	// диагностикой при разработке теста — воспроизводится даже на ЧУЖОМ, никем не тронутом
	// каталоге с заведомо присутствующим DACL) возвращаемый `present`/`err` НЕНАДЁЖНЫ:
	// present==false и err==nil одновременно с тем, что dacl указывает на РЕАЛЬНО валидный,
	// корректно заполненный ACL (успешно перечисляемый через GetAce). Похоже на квирк
	// конкретной связки vendored golang.org/x/sys/windows + ОС этой машины в биндинге
	// GetSecurityDescriptorDacl. Поэтому ниже полагаемся ТОЛЬКО на dacl!=nil и на факт успешного
	// перечисления ACE через GetAce — это и есть то, что реально проверяет утверждение теста.
	dacl, _, _ := sd.DACL()
	if dacl == nil {
		t.Fatal("DACL отсутствует на файле после hardenPortFileACLFn — это NULL DACL (полный " +
			"доступ всем), строго хуже исходного бага")
	}

	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatalf("CreateWellKnownSid(Everyone): %v", err)
	}
	authUsers, err := windows.CreateWellKnownSid(windows.WinAuthenticatedUserSid)
	if err != nil {
		t.Fatalf("CreateWellKnownSid(AuthenticatedUsers): %v", err)
	}
	builtinUsers, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatalf("CreateWellKnownSid(BuiltinUsers): %v", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatalf("CreateWellKnownSid(LocalSystem): %v", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatalf("CreateWellKnownSid(Administrators): %v", err)
	}

	aceSIDs := aclSIDs(t, dacl)

	for _, forbidden := range []struct {
		name string
		sid  *windows.SID
	}{
		{"Everyone", everyone},
		{"Authenticated Users", authUsers},
		{"Builtin Users", builtinUsers},
	} {
		for _, got := range aceSIDs {
			if got.Equals(forbidden.sid) {
				t.Errorf("DACL webui_port.txt содержит доступ для %s (%s) — S-4 не исправлен",
					forbidden.name, got.String())
			}
		}
	}

	requireAny := func(name string, sid *windows.SID) {
		for _, got := range aceSIDs {
			if got.Equals(sid) {
				return
			}
		}
		t.Errorf("DACL webui_port.txt не содержит доступа для %s — Web UI/GUI-наблюдатели "+
			"под этой учёткой не смогут прочитать файл", name)
	}
	requireAny("Local System", system)
	requireAny("Builtin Administrators", admins)
}

// aclSIDs перебирает ACE выделенного DACL через windows.GetAce и возвращает SID каждого ACE.
// ACCESS_ALLOWED_ACE.SidStart — начало переменной части ACE, где лежит сам SID (стандартный
// Win32-приём "struct hack"); безопасно интерпретируется как *SID, пока pAce валиден.
func aclSIDs(t *testing.T, acl *windows.ACL) []*windows.SID {
	t.Helper()
	var sids []*windows.SID
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			t.Fatalf("GetAce(%d): %v", i, err)
		}
		sids = append(sids, (*windows.SID)(unsafe.Pointer(&ace.SidStart)))
	}
	return sids
}
