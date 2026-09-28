//go:build windows

// B-0403 · R-5.2 (C-9) — кто именно вправе управлять Kill Switch через служебный канал.
//
// Прежняя защита была только на DACL пайпа, и в ней стояло `IU` (Interactive Users) — это ЛЮБОЙ
// интерактивно вошедший пользователь. На машине с несколькими учётками (быстрое переключение
// пользователей, RDP) посторонний пользователь мог подключиться к каналу службы и включать/снимать
// Kill Switch, применённый для другого. DACL к тому же вычисляется в момент создания экземпляра
// пайпа и устаревает при смене пользователя.
//
// Поэтому защиты теперь две: DACL сужен до SID владельца консольной сессии (когда его удаётся
// узнать), а РЕШАЮЩАЯ проверка выполняется на сервере для КАЖДОГО соединения — по личности
// клиента, снятой через ImpersonateNamedPipeClient.
package killswitch

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ImpersonateNamedPipeClient нет в vendored x/sys/windows — биндим сами (как fwpuclnt.dll в WFP).
var (
	modadvapi32                    = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateNamedPipeClient = modadvapi32.NewProc("ImpersonateNamedPipeClient")
)

// sidLocalSystem — S-1-5-18, учётная запись, под которой работает сама служба.
const sidLocalSystem = "S-1-5-18"

// clientIdentity — всё, что сервер узнаёт о клиенте пайпа.
type clientIdentity struct {
	UserSID   string
	SessionID uint32
	IsSystem  bool
	IsAdmin   bool
}

// Швы: обе системные операции требуют настоящего пайпа и настоящей сессии — без них политика
// была бы непроверяемой.
var (
	pipeClientIdentityFn   = pipeClientIdentity
	activeConsoleSessionFn = activeConsoleSession
)

// authorizePipeClient — авторизация клиента текущего соединения.
func authorizePipeClient(h windows.Handle) error {
	id, err := pipeClientIdentityFn(h)
	if err != nil {
		// Не смогли установить личность — не пускаем (fail-closed): «неизвестный» здесь опаснее,
		// чем отказ, потому что у движка остаётся честный путь через UAC.
		return fmt.Errorf("killswitch pipe: личность клиента не установлена: %w", err)
	}
	console, cerr := activeConsoleSessionFn()
	return authorizeClient(id, console, cerr)
}

// authorizeClient — ЧИСТАЯ политика доступа (без Win32, тестируется таблицей).
//
//	Вход:      личность клиента, id активной консольной сессии и ошибка её получения.
//	Тело:      SYSTEM и администраторы допускаются всегда — они и без нас могут менять фаервол,
//	           так что отказ им ничего не защитил бы. Обычный пользователь допускается, только
//	           если он работает в той сессии, которая ВЛАДЕЕТ КОНСОЛЬЮ.
//	Выход:     nil — можно исполнять; error — отказ.
//	Fail-safe: активная сессия неизвестна ⇒ ОТКАЗ обычному пользователю.
//	Инвариант: пользователь из чужой сессии не может управлять Kill Switch через службу.
func authorizeClient(id clientIdentity, consoleSession uint32, consoleErr error) error {
	if id.IsSystem || id.IsAdmin {
		return nil
	}
	if consoleErr != nil {
		return fmt.Errorf("killswitch pipe: активная консольная сессия неизвестна (%v); "+
			"клиент из сессии %d отклонён", consoleErr, id.SessionID)
	}
	if id.SessionID == consoleSession {
		return nil
	}
	return fmt.Errorf("killswitch pipe: клиент из сессии %d не владеет консолью (активна %d)",
		id.SessionID, consoleSession)
}

// pipeClientIdentity снимает личность клиента через олицетворение.
//
// Олицетворение — свойство ПОТОКА, а Go свободно переносит горутину между потоками ОС. Без
// LockOSThread токен мог бы остаться висеть на чужом потоке, и следующая операция службы
// выполнилась бы правами клиента вместо SYSTEM.
func pipeClientIdentity(h windows.Handle) (clientIdentity, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := impersonateNamedPipeClient(h); err != nil {
		return clientIdentity{}, err
	}
	defer func() { _ = windows.RevertToSelf() }()

	thread, err := windows.GetCurrentThread()
	if err != nil {
		return clientIdentity{}, err
	}
	var tok windows.Token
	// openAsSelf=true: токен потока открываем правами САМОЙ СЛУЖБЫ, а не правами клиента,
	// которого мы только что олицетворили (иначе непривилегированный клиент не даст его открыть).
	if err := windows.OpenThreadToken(thread, windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, true, &tok); err != nil {
		return clientIdentity{}, err
	}
	defer tok.Close()

	user, err := tok.GetTokenUser()
	if err != nil {
		return clientIdentity{}, err
	}
	id := clientIdentity{UserSID: user.User.Sid.String()}
	id.IsSystem = id.UserSID == sidLocalSystem

	if sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid); err == nil {
		if member, err := tok.IsMember(sid); err == nil {
			id.IsAdmin = member
		}
	}
	if sess, err := tokenSessionID(tok); err == nil {
		id.SessionID = sess
	} else {
		return id, err
	}
	return id, nil
}

func impersonateNamedPipeClient(h windows.Handle) error {
	r1, _, e1 := procImpersonateNamedPipeClient.Call(uintptr(h))
	if r1 == 0 {
		if e1 != nil {
			return e1
		}
		return errors.New("ImpersonateNamedPipeClient: неизвестная ошибка")
	}
	return nil
}

func tokenSessionID(tok windows.Token) (uint32, error) {
	var sess uint32
	var n uint32
	err := windows.GetTokenInformation(tok, windows.TokenSessionId,
		(*byte)(unsafe.Pointer(&sess)), uint32(unsafe.Sizeof(sess)), &n)
	if err != nil {
		return 0, err
	}
	return sess, nil
}

// activeConsoleSession — id сессии, которая физически владеет клавиатурой и экраном.
func activeConsoleSession() (uint32, error) {
	sess := windows.WTSGetActiveConsoleSessionId()
	if sess == 0xFFFFFFFF {
		return 0, errors.New("активной консольной сессии нет")
	}
	return sess, nil
}

// ─── DACL пайпа ──────────────────────────────────────────────────────────────

// pipeSDDLBase — полный доступ SYSTEM (SY) и администраторам (BA).
const pipeSDDLBase = "D:(A;;GA;;;SY)(A;;GA;;;BA)"

// pipeSDDLFor строит DACL, разрешая чтение/запись КОНКРЕТНОМУ пользователю.
//
//	Вход:      строковый SID владельца консольной сессии; "" или мусор — недопустимы.
//	Выход:     SDDL. При непригодном SID — фолбэк на `IU` (Interactive Users).
//	Fail-safe: фолбэк СЛАБЕЕ (пускает любого интерактивного пользователя), поэтому решающей
//	           защитой остаётся серверная проверка authorizeClient — она выполняется всегда.
func pipeSDDLFor(userSID string) string {
	if !strings.HasPrefix(userSID, "S-1-") {
		return pipeSDDLBase + "(A;;GRGW;;;IU)"
	}
	return pipeSDDLBase + "(A;;GRGW;;;" + userSID + ")"
}

// consoleUserSID — SID пользователя, вошедшего в активную консольную сессию.
// Требует SE_TCB_PRIVILEGE, то есть работает только под SYSTEM (служба). При прямом отладочном
// запуске вернёт ошибку — и DACL честно уйдёт в фолбэк.
func consoleUserSID() (string, error) {
	sess, err := activeConsoleSessionFn()
	if err != nil {
		return "", err
	}
	var tok windows.Token
	if err := windows.WTSQueryUserToken(sess, &tok); err != nil {
		return "", err
	}
	defer tok.Close()
	user, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
}
