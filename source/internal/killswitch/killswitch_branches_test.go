//go:build windows

package killswitch

import (
	"errors"
	"os/exec"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

// ── New(): OS-branch injection ────────────────────────────────────────────────

func TestNew_Linux(t *testing.T) {
	orig := newKSGOOS
	defer func() { newKSGOOS = orig }()
	newKSGOOS = func() string { return "linux" }
	ks := New()
	if _, ok := ks.(*linuxKS); !ok {
		t.Errorf("expected *linuxKS, got %T", ks)
	}
}

func TestNew_Android(t *testing.T) {
	orig := newKSGOOS
	defer func() { newKSGOOS = orig }()
	newKSGOOS = func() string { return "android" }
	ks := New()
	if _, ok := ks.(*androidKS); !ok {
		t.Errorf("expected *androidKS, got %T", ks)
	}
}

func TestNew_Default(t *testing.T) {
	orig := newKSGOOS
	defer func() { newKSGOOS = orig }()
	newKSGOOS = func() string { return "freebsd" }
	ks := New()
	if _, ok := ks.(*noopKS); !ok {
		t.Errorf("expected *noopKS, got %T", ks)
	}
}

// ── linuxKS.Enable: success path (all commands succeed via injection) ─────────

func TestLinuxKS_Enable_Success(t *testing.T) {
	// DEF-01: linuxKS.Enable ходит через iptablesRunFn/ip6tablesRunFn (B-04.2),
	// а НЕ через execCmdFn (шов windowsKS). Инжектируем правильный шов фейковым
	// движком netfilter (как в killswitch_b0402_test.go), иначе зовётся реальный
	// iptables и тест падает на не-Linux хостах.
	defer installFake(newFakeNetfilter())()

	ks := &linuxKS{}
	err := ks.Enable("tun0", []int{})
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
	if !ks.IsEnabled() {
		t.Error("expected IsEnabled() == true after successful Enable")
	}
}

func TestLinuxKS_Enable_ErrorPath(t *testing.T) {
	// DEF-01: первый вызов iptables (создание/наполнение APF_KS) падает →
	// fail-safe Disable() + возврат ошибки. Инжектируем правильный шов.
	origV4, origV6 := iptablesRunFn, ip6tablesRunFn
	defer func() { iptablesRunFn, ip6tablesRunFn = origV4, origV6 }()
	iptablesRunFn = func(args ...string) (string, error) {
		return "", errors.New("injected iptables error")
	}
	ip6tablesRunFn = func(args ...string) (string, error) { return "", nil }

	ks := &linuxKS{}
	err := ks.Enable("tun0", nil)
	if err == nil {
		t.Error("expected error from iptables failure")
	}
	if ks.IsEnabled() {
		t.Error("expected disabled after fail-safe rollback")
	}
}

// ── RunElevatedNetsh: admin path (inject isAdminFn + runNetshDirectFn) ────────

func TestRunElevatedNetsh_AdminPath(t *testing.T) {
	origAdmin := isAdminFn
	origRun := runNetshDirectFn
	defer func() {
		isAdminFn = origAdmin
		runNetshDirectFn = origRun
	}()
	isAdminFn = func() bool { return true }
	runNetshDirectFn = func(args string) error { return nil }

	err := RunElevatedNetsh("advfirewall show allprofiles")
	if err != nil {
		t.Errorf("RunElevatedNetsh (admin) expected nil, got: %v", err)
	}
}

// ── RunElevatedNetsh: non-admin path (inject isAdminFn + shellExecNetshFn) ───

func TestRunElevatedNetsh_NonAdminPath(t *testing.T) {
	origAdmin := isAdminFn
	origShell := shellExecNetshFn
	defer func() {
		isAdminFn = origAdmin
		shellExecNetshFn = origShell
	}()
	isAdminFn = func() bool { return false }
	shellExecNetshFn = func(args string) error { return nil }

	err := RunElevatedNetsh("version")
	if err != nil {
		t.Errorf("RunElevatedNetsh (non-admin) expected nil, got: %v", err)
	}
}

// ── shellExecuteNetsh: ShellExecuteExW injection ──────────────────────────────

func TestShellExecuteNetsh_UACCancelled(t *testing.T) {
	orig := shellExecExWFn
	defer func() { shellExecExWFn = orig }()
	shellExecExWFn = func(_ *shellExecuteInfo) (uintptr, uintptr, error) {
		return 0, 0, syscall.Errno(1223) // ERROR_CANCELLED
	}

	err := shellExecuteNetsh("/?")
	if !errors.Is(err, ErrUACCancelled) {
		t.Errorf("expected ErrUACCancelled, got: %v", err)
	}
}

func TestShellExecuteNetsh_OtherSysError(t *testing.T) {
	orig := shellExecExWFn
	defer func() { shellExecExWFn = orig }()
	shellExecExWFn = func(_ *shellExecuteInfo) (uintptr, uintptr, error) {
		return 0, 0, syscall.Errno(5) // ERROR_ACCESS_DENIED
	}

	err := shellExecuteNetsh("/?")
	if err == nil {
		t.Error("expected error from ShellExecuteEx failure")
	}
	t.Logf("shellExecuteNetsh other error: %v", err)
}

func TestShellExecuteNetsh_SuccessNoProcess(t *testing.T) {
	// ret=1 (success), hProcess field stays 0 → skip WaitForSingleObject
	orig := shellExecExWFn
	defer func() { shellExecExWFn = orig }()
	shellExecExWFn = func(_ *shellExecuteInfo) (uintptr, uintptr, error) {
		return 1, 0, nil
	}

	err := shellExecuteNetsh("/?")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// ── ResetAll: Linux and default branches ──────────────────────────────────────

func TestResetAll_Linux(t *testing.T) {
	orig := resetGOOS
	defer func() { resetGOOS = orig }()
	resetGOOS = func() string { return "linux" }

	err := ResetAll()
	// iptables/ip6tables commands will fail on Windows but resetLinux ignores errors.
	t.Logf("ResetAll(linux): %v", err)
}

func TestResetAll_Default(t *testing.T) {
	orig := resetGOOS
	defer func() { resetGOOS = orig }()
	resetGOOS = func() string { return "freebsd" }

	err := ResetAll()
	if err != nil {
		t.Errorf("ResetAll(default) expected nil, got: %v", err)
	}
}

// ── ResetAll(windows): критическая команда обязана быть видна наверх ──────────
//
// Регрессия к P0-4 (см. комментарий в resetWindows()/reset.go): раньше ошибка команды
// восстановления политики файрвола отбрасывалась (`_ = runCmd(...)`), из-за чего
// resetWindows() — а значит и ResetAll() — возвращал nil ДАЖЕ когда критическая
// команда падала без прав администратора. RecoverIfNeeded() (sentinel.go) снимает
// sentinel-маркер, только если ResetAll() вернул nil, — то есть маркер снимался
// всегда, даже если сеть фактически осталась заблокированной.
func TestResetAll_Windows_PolicyRestoreFailure_PropagatesError(t *testing.T) {
	origGOOS := resetGOOS
	origExec := execCmdFn
	origShow := showInterfacesFn
	defer func() {
		resetGOOS = origGOOS
		execCmdFn = origExec
		showInterfacesFn = origShow
	}()

	resetGOOS = func() string { return "windows" }
	// Нейтрализуем resetDNSSafe — она не имеет отношения к проверяемому пути
	// и не должна давать ложных срабатываний через реальный netsh.
	showInterfacesFn = func() ([]byte, error) { return nil, nil }

	execCmdFn = func(name string, args ...string) error {
		for _, a := range args {
			if a == "firewallpolicy" {
				return errors.New("access is denied")
			}
		}
		return nil
	}

	err := ResetAll()
	if err == nil {
		t.Fatal("ResetAll() должен вернуть ошибку, когда команда восстановления " +
			"политики брандмауэра падает без прав администратора")
	}
}

// Позитивный сценарий-зеркало: все команды успешны → ResetAll(windows) возвращает nil.
func TestResetAll_Windows_Success(t *testing.T) {
	origGOOS := resetGOOS
	origExec := execCmdFn
	origShow := showInterfacesFn
	defer func() {
		resetGOOS = origGOOS
		execCmdFn = origExec
		showInterfacesFn = origShow
	}()

	resetGOOS = func() string { return "windows" }
	showInterfacesFn = func() ([]byte, error) { return nil, nil }
	execCmdFn = func(name string, args ...string) error { return nil }

	if err := ResetAll(); err != nil {
		t.Errorf("ResetAll(windows) при успешных командах должен вернуть nil, получено: %v", err)
	}
}

// ── QuickReset: Linux branch ──────────────────────────────────────────────────

func TestQuickReset_Linux(t *testing.T) {
	orig := quickResetGOOS
	defer func() { quickResetGOOS = orig }()
	quickResetGOOS = func() string { return "linux" }

	QuickReset() // should not panic; iptables failures are silently ignored
}

// ── runNetshDirect: error path via injected CombinedOutput ───────────────────

func TestRunNetshDirect_ExecError(t *testing.T) {
	orig := netshCombinedOutputFn
	defer func() { netshCombinedOutputFn = orig }()
	netshCombinedOutputFn = func(_ *exec.Cmd) ([]byte, error) {
		return []byte("injected output"), errors.New("injected netsh failure")
	}

	err := runNetshDirect("advfirewall show allprofiles")
	if err == nil {
		t.Error("expected error from injected netsh failure")
	}
}

// ── runNetshDirect: success path (return nil) via injected CombinedOutput ────

func TestRunNetshDirect_SuccessPath(t *testing.T) {
	orig := netshCombinedOutputFn
	defer func() { netshCombinedOutputFn = orig }()
	netshCombinedOutputFn = func(_ *exec.Cmd) ([]byte, error) {
		return []byte("OK"), nil // inject success so return nil is always reached
	}

	err := runNetshDirect("advfirewall show allprofiles")
	if err != nil {
		t.Errorf("expected nil from injected success, got: %v", err)
	}
}

// ── shellExecuteNetsh: hProcess path (exit 0 — no error) ─────────────────────

func TestShellExecuteNetsh_WithProcessExitZero(t *testing.T) {
	// Start a real process that exits immediately with code 0.
	cmd := exec.Command("cmd", "/c", "exit", "0")
	if err := cmd.Start(); err != nil {
		t.Skip("cannot start helper process:", err)
	}
	pid := uint32(cmd.Process.Pid)
	// Grab OUR handle BEFORE Wait() so the process object stays alive.
	h, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		t.Skip("OpenProcess failed:", err)
	}
	cmd.Wait() //nolint:errcheck — process has exited; our handle (h) keeps object alive

	orig := shellExecExWFn
	defer func() { shellExecExWFn = orig }()
	shellExecExWFn = func(sei *shellExecuteInfo) (uintptr, uintptr, error) {
		// Write the real process handle into sei.hProcess so the hProcess
		// branch is taken; shellExecuteNetsh will CloseHandle it via defer.
		sei.hProcess = uintptr(h)
		return 1, 0, nil
	}

	if err := shellExecuteNetsh("/?"); err != nil {
		t.Errorf("expected nil for exit-0 process, got: %v", err)
	}
}

// ── shellExecuteNetsh: hProcess path (exit 1 — returns error) ────────────────

func TestShellExecuteNetsh_WithProcessExitNonZero(t *testing.T) {
	// Start a real process that exits with code 1.
	cmd := exec.Command("cmd", "/c", "exit", "1")
	if err := cmd.Start(); err != nil {
		t.Skip("cannot start helper process:", err)
	}
	pid := uint32(cmd.Process.Pid)
	// Grab OUR handle BEFORE Wait() so the process object stays alive.
	h, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		t.Skip("OpenProcess failed:", err)
	}
	cmd.Wait() //nolint:errcheck

	orig := shellExecExWFn
	defer func() { shellExecExWFn = orig }()
	shellExecExWFn = func(sei *shellExecuteInfo) (uintptr, uintptr, error) {
		sei.hProcess = uintptr(h)
		return 1, 0, nil
	}

	if err := shellExecuteNetsh("/?"); err == nil {
		t.Error("expected error from process exit code 1")
	}
}

// ── resetDNSSafe: showInterfaces error → early return ────────────────────────

func TestResetDNSSafe_ShowInterfacesError(t *testing.T) {
	orig := showInterfacesFn
	defer func() { showInterfacesFn = orig }()
	showInterfacesFn = func() ([]byte, error) {
		return nil, errors.New("injected interface list error")
	}

	resetDNSSafe() // must not panic — returns early on error
}

// ── resetDNSSafe: getDNSInfo error → adapter skipped; short line → skipped ───

func TestResetDNSSafe_GetDNSError(t *testing.T) {
	origShow := showInterfacesFn
	origGet := getDNSInfoFn
	defer func() {
		showInterfacesFn = origShow
		getDNSInfoFn = origGet
	}()
	showInterfacesFn = func() ([]byte, error) {
		// Two lines: first has only 3 fields (covers len<4 continue),
		// second has 4 fields but DNS query fails (covers getDNSInfo error continue).
		return []byte("Connected Enabled Short\nConnected  Enabled  Dedicated  Ethernet\n"), nil
	}
	getDNSInfoFn = func(_ string) ([]byte, error) {
		return nil, errors.New("injected DNS query error")
	}

	resetDNSSafe() // must not panic — both paths end in continue
}

// ── resetDNSSafe: APF static DNS detected → setDNSDHCPFn called ──────────────

func TestResetDNSSafe_StaticAPFDNS(t *testing.T) {
	origShow := showInterfacesFn
	origGet := getDNSInfoFn
	origSet := setDNSDHCPFn
	defer func() {
		showInterfacesFn = origShow
		getDNSInfoFn = origGet
		setDNSDHCPFn = origSet
	}()

	showInterfacesFn = func() ([]byte, error) {
		return []byte("Connected  Enabled  Dedicated  Ethernet\n"), nil
	}
	getDNSInfoFn = func(_ string) ([]byte, error) {
		// Simulate an adapter with APF-set static DNS 8.8.8.8
		return []byte("Statically Configured DNS Servers: 8.8.8.8"), nil
	}
	setCalled := false
	setDNSDHCPFn = func(_ string) { setCalled = true }

	resetDNSSafe()

	if !setCalled {
		t.Error("expected setDNSDHCPFn to be called for APF-static DNS adapter")
	}
}
