//go:build windows

package killswitch

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// ─── B-0403 · R-5.2 · политика доступа ───────────────────────────────────────

func TestAuthorizeClient(t *testing.T) {
	noConsole := errors.New("активной консольной сессии нет")

	cases := []struct {
		name       string
		id         clientIdentity
		console    uint32
		consoleErr error
		wantAllow  bool
	}{
		// SYSTEM и админы и без нас могут менять фаервол — отказ им ничего бы не защитил.
		{"SYSTEM из чужой сессии", clientIdentity{UserSID: sidLocalSystem, IsSystem: true, SessionID: 0}, 1, nil, true},
		{"админ из чужой сессии", clientIdentity{IsAdmin: true, SessionID: 7}, 1, nil, true},
		{"SYSTEM при неизвестной консоли", clientIdentity{IsSystem: true}, 0, noConsole, true},

		// Обычный пользователь — только из сессии, владеющей консолью.
		{"пользователь из консольной сессии", clientIdentity{SessionID: 1}, 1, nil, true},
		{"пользователь из чужой сессии (RDP/смена пользователя)", clientIdentity{SessionID: 3}, 1, nil, false},

		// Fail-closed: не знаем, кто владеет консолью — не пускаем.
		{"пользователь при неизвестной консоли", clientIdentity{SessionID: 1}, 0, noConsole, false},

		// Сессия 0 — служебная; обычного пользователя там быть не может, но если консоль тоже 0
		// (никто не вошёл), совпадение не должно случайно открывать доступ.
		{"пользователь в сессии 0 при неизвестной консоли", clientIdentity{SessionID: 0}, 0, noConsole, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := authorizeClient(tc.id, tc.console, tc.consoleErr)
			if tc.wantAllow && err != nil {
				t.Fatalf("ожидался допуск, got %v", err)
			}
			if !tc.wantAllow && err == nil {
				t.Fatal("ожидался отказ, доступ разрешён")
			}
		})
	}
}

// Fail-closed на верхнем уровне: не смогли снять личность клиента ⇒ отказ, а не «ну ладно».
func TestAuthorizePipeClient_IdentityFailureIsDenial(t *testing.T) {
	oldID, oldSess := pipeClientIdentityFn, activeConsoleSessionFn
	defer func() { pipeClientIdentityFn, activeConsoleSessionFn = oldID, oldSess }()

	pipeClientIdentityFn = func(windows.Handle) (clientIdentity, error) {
		return clientIdentity{}, errors.New("ImpersonateNamedPipeClient: отказано")
	}
	activeConsoleSessionFn = func() (uint32, error) { return 1, nil }

	if err := authorizePipeClient(0); err == nil {
		t.Fatal("клиент с неустановленной личностью допущен")
	}
}

func TestAuthorizePipeClient_ConsoleOwnerAllowed(t *testing.T) {
	oldID, oldSess := pipeClientIdentityFn, activeConsoleSessionFn
	defer func() { pipeClientIdentityFn, activeConsoleSessionFn = oldID, oldSess }()

	pipeClientIdentityFn = func(windows.Handle) (clientIdentity, error) {
		return clientIdentity{UserSID: "S-1-5-21-1-2-3-1001", SessionID: 2}, nil
	}
	activeConsoleSessionFn = func() (uint32, error) { return 2, nil }

	if err := authorizePipeClient(0); err != nil {
		t.Fatalf("владелец консоли отклонён: %v", err)
	}
}

func TestAuthorizePipeClient_ForeignSessionDenied(t *testing.T) {
	oldID, oldSess := pipeClientIdentityFn, activeConsoleSessionFn
	defer func() { pipeClientIdentityFn, activeConsoleSessionFn = oldID, oldSess }()

	pipeClientIdentityFn = func(windows.Handle) (clientIdentity, error) {
		return clientIdentity{UserSID: "S-1-5-21-9-9-9-1002", SessionID: 5}, nil
	}
	activeConsoleSessionFn = func() (uint32, error) { return 2, nil }

	err := authorizePipeClient(0)
	if err == nil {
		t.Fatal("пользователь из чужой сессии допущен к управлению Kill Switch")
	}
	if !strings.Contains(err.Error(), "5") {
		t.Errorf("в сообщении нет номера сессии клиента: %v", err)
	}
}

// ─── R-5.2 · DACL ────────────────────────────────────────────────────────────

func TestPipeSDDLFor_NarrowsToUserAndStaysValid(t *testing.T) {
	const sid = "S-1-5-21-1111111111-2222222222-3333333333-1001"
	sddl := pipeSDDLFor(sid)

	if !strings.Contains(sddl, sid) {
		t.Errorf("SID не попал в DACL: %s", sddl)
	}
	if strings.Contains(sddl, ";IU)") {
		t.Errorf("остался широкий IU при известном SID: %s", sddl)
	}
	if _, err := windows.SecurityDescriptorFromString(sddl); err != nil {
		t.Fatalf("построенный DACL невалиден (%s): %v", sddl, err)
	}
}

func TestPipeSDDLFor_FallsBackToInteractiveUsers(t *testing.T) {
	for _, bad := range []string{"", "не-SID", "S-2-5-21-1", "administrator"} {
		sddl := pipeSDDLFor(bad)
		if !strings.Contains(sddl, ";IU)") {
			t.Errorf("для %q ожидался фолбэк на IU, got %s", bad, sddl)
		}
		if _, err := windows.SecurityDescriptorFromString(sddl); err != nil {
			t.Fatalf("фолбэчный DACL невалиден: %v", err)
		}
	}
}

// SYSTEM и администраторы обязаны сохранять полный доступ в любом варианте DACL — иначе служба
// не сможет открыть собственный пайп после смены пользователя.
func TestPipeSDDLFor_AlwaysKeepsSystemAndAdmins(t *testing.T) {
	for _, sid := range []string{"", "S-1-5-21-1-2-3-1001"} {
		sddl := pipeSDDLFor(sid)
		if !strings.Contains(sddl, "(A;;GA;;;SY)") || !strings.Contains(sddl, "(A;;GA;;;BA)") {
			t.Errorf("потерян доступ SY/BA: %s", sddl)
		}
	}
}

// Атрибуты безопасности обязаны собираться даже когда SID консольного пользователя недоступен
// (у тест-процесса нет SE_TCB_PRIVILEGE) — иначе служба не поднимет канал вообще.
func TestPipeSecurityAttributes_BuildsWithoutConsoleSID(t *testing.T) {
	sa, err := pipeSecurityAttributes()
	if err != nil {
		t.Fatalf("pipeSecurityAttributes: %v", err)
	}
	if sa == nil || sa.SecurityDescriptor == nil {
		t.Fatal("пустой дескриптор безопасности")
	}
}

// ─── R-5.3 · анти-сквоттинг ──────────────────────────────────────────────────

func TestPipeOpenMode_FirstInstanceFlag(t *testing.T) {
	first := pipeOpenMode(true)
	rest := pipeOpenMode(false)

	if first&windows.FILE_FLAG_FIRST_PIPE_INSTANCE == 0 {
		t.Error("на первом экземпляре нет FILE_FLAG_FIRST_PIPE_INSTANCE — имя канала можно перехватить")
	}
	if rest&windows.FILE_FLAG_FIRST_PIPE_INSTANCE != 0 {
		t.Error("флаг «первый экземпляр» на последующих экземплярах — создание будет падать")
	}
	for _, m := range []uint32{first, rest} {
		if m&windows.PIPE_ACCESS_DUPLEX != windows.PIPE_ACCESS_DUPLEX {
			t.Errorf("режим %#x не двунаправленный", m)
		}
	}
}
