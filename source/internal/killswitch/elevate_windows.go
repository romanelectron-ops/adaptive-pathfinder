//go:build windows

// Package killswitch — UAC-повышение прав для выполнения netsh команд.
//
// При включении Kill Switch требуются права администратора.
// Этот файл реализует механизм запроса UAC-прав через ShellExecuteEx
// с verb="runas". Пользователь видит стандартный диалог Windows:
//
//	"Разрешить этому приложению вносить изменения на вашем устройстве?"
//
// При нажатии "Да" — операция выполняется.
// При нажатии "Нет" — возвращается ErrUACCancelled.
package killswitch

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrElevateTimeout — дочерний netsh (UAC) не завершился за отведённое время (D-35: вместо
// WaitForSingleObject INFINITE, из-за которого зависший UAC-диалог держал горутину вечно, T-25).
var ErrElevateTimeout = fmt.Errorf("killswitch: netsh (UAC) не завершился за отведённое время")

// elevateWaitTimeout — предел ожидания завершения дочернего netsh. Инжектируется в тестах.
// 90 c с запасом на медленную реакцию пользователя в UAC-диалоге и на большой набор netsh-правил.
var elevateWaitTimeout = 90 * time.Second

// waitTimeoutEvent — WAIT_TIMEOUT из WaitForSingleObject (не всегда экспортируется в x/sys/windows).
const waitTimeoutEvent = 0x00000102

// waitNetshProcessFn — ожидание завершения дочернего процесса (шов для тестов).
var waitNetshProcessFn = waitNetshProcess

// terminateProcessFn — шов: снятие зависшего дочернего netsh (B-0403 · R-9/C-17).
var terminateProcessFn = func(h windows.Handle) error { return windows.TerminateProcess(h, 1) }

// waitNetshProcess ждёт handle не дольше elevateWaitTimeout. Возвращает: nil (код выхода 0);
// ErrElevateTimeout (истёк таймаут — диалог/процесс завис); error (ненулевой код или сбой ожидания).
func waitNetshProcess(handle windows.Handle) error {
	ms := uint32(elevateWaitTimeout / time.Millisecond)
	event, err := windows.WaitForSingleObject(handle, ms)
	if err != nil {
		return fmt.Errorf("killswitch: ожидание netsh: %w", err)
	}
	if event == waitTimeoutEvent {
		// R-9 (C-17): мы перестали ждать, но процесс жив. Оставить его — значит допустить, что
		// он доработает ПОЗЖЕ и применит часть правил уже после того, как движок откатил попытку
		// (D-34 «всё или ничего» тогда нарушается: набор окажется полуприменённым).
		//
		// Честная оговорка: на UAC-пути родитель не элевирован, и handle от ShellExecuteEx обычно
		// не имеет PROCESS_TERMINATE — вызов вернёт «отказано в доступе». Это best-effort; основной
		// защитой остаётся сам таймаут (мы не висим вечно) и откат на стороне вызывающего.
		if terr := terminateProcessFn(handle); terr != nil {
			return fmt.Errorf("%w (снять процесс не удалось: %v)", ErrElevateTimeout, terr)
		}
		return ErrElevateTimeout
	}
	var exitCode uint32
	if e := windows.GetExitCodeProcess(handle, &exitCode); e == nil && exitCode != 0 {
		return fmt.Errorf("killswitch: netsh завершился с кодом %d (возможно, нет прав)", exitCode)
	}
	return nil
}

var (
	modShell32          = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteExW = modShell32.NewProc("ShellExecuteExW")
)

// shellExecuteInfo — структура для ShellExecuteExW.
// https://learn.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-shellexecuteinfow
type shellExecuteInfo struct {
	cbSize         uint32
	fMask          uint32
	hwnd           uintptr
	lpVerb         uintptr
	lpFile         uintptr
	lpParameters   uintptr
	lpDirectory    uintptr
	nShow          int32
	hInstApp       uintptr
	lpIDList       uintptr
	lpClass        uintptr
	hkeyClass      uintptr
	dwHotKey       uint32
	hIconOrMonitor uintptr
	hProcess       uintptr
}

const (
	seeMaskNoAsync        = 0x00000100
	seeMaskNoCloseProcess = 0x00000040
	swHide                = 0
)

// ErrUACCancelled возвращается когда пользователь нажал "Нет" в UAC-диалоге.
var ErrUACCancelled = fmt.Errorf("Kill Switch: пользователь отклонил запрос прав администратора (UAC)")

// Injection vars — overridden in tests.
var (
	isAdminFn        = func() bool { return IsAdmin() }
	runNetshDirectFn = runNetshDirect
	shellExecNetshFn = shellExecuteNetsh
	// shellExecExWFn wraps the ShellExecuteExW syscall so tests can inject it.
	// Accepts *shellExecuteInfo so tests can write back fields (e.g. hProcess)
	// without unsafe uintptr→Pointer casts.
	shellExecExWFn = func(sei *shellExecuteInfo) (uintptr, uintptr, error) {
		return procShellExecuteExW.Call(uintptr(unsafe.Pointer(sei)))
	}
	// netshCombinedOutputFn wraps cmd.CombinedOutput so tests can inject failures.
	netshCombinedOutputFn = func(cmd *exec.Cmd) ([]byte, error) {
		return cmd.CombinedOutput()
	}
)

// IsAdmin проверяет, запущен ли текущий процесс с правами администратора.
func IsAdmin() bool {
	token := windows.Token(0)
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()
	var isElevated uint32
	var returnedLen uint32
	if err := windows.GetTokenInformation(
		token,
		windows.TokenElevation,
		(*byte)(unsafe.Pointer(&isElevated)),
		uint32(unsafe.Sizeof(isElevated)),
		&returnedLen,
	); err != nil {
		return false
	}
	return isElevated != 0
}

// RunElevatedNetsh выполняет команду netsh с повышением прав через UAC.
//
// Если приложение уже запущено от администратора — выполняет напрямую через exec.
// Если нет — показывает стандартный UAC-диалог Windows.
// Функция блокирует поток до завершения netsh.exe.
//
// args — строка аргументов для netsh (например: "advfirewall firewall add rule ...")
// Возвращает nil при успехе, ErrUACCancelled при отмене, другую ошибку при сбое.
func RunElevatedNetsh(args string) error {
	if isAdminFn() {
		return runNetshDirectFn(args)
	}
	return shellExecNetshFn(args)
}

// runNetshDirect выполняет netsh напрямую (процесс уже запущен от admin).
func runNetshDirect(args string) error {
	fields := strings.Fields(args)
	if len(fields) == 0 {
		return fmt.Errorf("netsh: пустые аргументы")
	}
	cmd := exec.Command("netsh", fields...)
	out, err := netshCombinedOutputFn(cmd)
	if err != nil {
		return fmt.Errorf("netsh: %w\n%s", err, string(out))
	}
	return nil
}

// shellExecuteNetsh запускает netsh через ShellExecuteExW с verb="runas".
// Это стандартный механизм Windows для запроса UAC-повышения прав.
// Ждёт завершения дочернего процесса.
func shellExecuteNetsh(args string) error {
	netshPath := findNetsh()

	verb, err := syscall.UTF16PtrFromString("runas")
	if err != nil {
		return fmt.Errorf("utf16 verb: %w", err)
	}
	file, err := syscall.UTF16PtrFromString(netshPath)
	if err != nil {
		return fmt.Errorf("utf16 file: %w", err)
	}
	params, err := syscall.UTF16PtrFromString(args)
	if err != nil {
		return fmt.Errorf("utf16 params: %w", err)
	}

	sei := shellExecuteInfo{
		fMask:        seeMaskNoAsync | seeMaskNoCloseProcess,
		lpVerb:       uintptr(unsafe.Pointer(verb)),
		lpFile:       uintptr(unsafe.Pointer(file)),
		lpParameters: uintptr(unsafe.Pointer(params)),
		nShow:        swHide,
	}
	sei.cbSize = uint32(unsafe.Sizeof(sei))

	ret, _, callErr := shellExecExWFn(&sei)
	if ret == 0 {
		// Проверяем: пользователь нажал "Нет" (ERROR_CANCELLED = 1223)
		if errno, ok := callErr.(syscall.Errno); ok && errno == 1223 {
			return ErrUACCancelled
		}
		return fmt.Errorf("killswitch UAC: ShellExecuteEx failed: %w", callErr)
	}

	// Ждём завершения netsh.exe с ТАЙМАУТОМ (D-35) и проверяем exit code.
	if sei.hProcess != 0 {
		handle := windows.Handle(sei.hProcess)
		defer windows.CloseHandle(handle)
		return waitNetshProcessFn(handle)
	}

	return nil
}

// findNetsh возвращает полный путь к netsh.exe.
func findNetsh() string {
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	path := sysRoot + `\System32\netsh.exe`
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return "netsh.exe"
}
