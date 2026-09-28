//go:build windows

package killswitch

import "os/exec"

// DEF-08 (windows) — под `go test` нейтрализуем UAC/netsh-пути, чтобы EnableWithUAC
// и elevated-netsh не трогали реальный системный фаервол хоста.
//   - isAdminFn → false: EnableWithUAC пойдёт по shell-пути (а он тоже no-op);
//   - shellExecNetshFn → no-op: реальный ShellExecuteEx(runas)/netsh не запускается;
//   - netshCombinedOutputFn → no-op: прямой netsh (admin-путь) не выполняется.
func init() {
	if !underTest() {
		return
	}
	isAdminFn = func() bool { return false }
	shellExecNetshFn = func(string) error { return nil }
	netshCombinedOutputFn = func(*exec.Cmd) ([]byte, error) { return []byte{}, nil }
}
