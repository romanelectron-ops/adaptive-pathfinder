//go:build windows

package killswitch

import (
	"os"
	"testing"
)

// F-31: netsh-зависимые тесты (findNetsh/runNetshDirect объявлены только в
// elevate_windows.go). Вынесены сюда с тегом //go:build windows, иначе на
// не-Windows пакет killswitch не компилируется ("undefined: findNetsh").
// Кросс-платформенные тесты остаются в killswitch_test.go / killswitch_extra_test.go.

func TestFindNetsh_ReturnsNonEmpty(t *testing.T) {
	path := findNetsh()
	if path == "" {
		t.Error("findNetsh returned empty string")
	}
}

func TestRunNetshDirect_EmptyArgs(t *testing.T) {
	err := runNetshDirect("")
	if err == nil {
		t.Error("expected error for empty args")
	}
}

func TestRunNetshDirect_HelpCmd(t *testing.T) {
	err := runNetshDirect("/?")
	t.Logf("runNetshDirect /?  result: %v", err)
}

func TestFindNetsh_EmptySystemRoot(t *testing.T) {
	orig := os.Getenv("SystemRoot")
	defer os.Setenv("SystemRoot", orig) //nolint:errcheck
	os.Setenv("SystemRoot", "")         //nolint:errcheck
	path := findNetsh()
	if path == "" {
		t.Error("findNetsh with empty SystemRoot returned empty string")
	}
	t.Logf("findNetsh (empty SystemRoot) = %q", path)
}

func TestFindNetsh_NonexistentSystemRoot(t *testing.T) {
	orig := os.Getenv("SystemRoot")
	defer os.Setenv("SystemRoot", orig)                                      //nolint:errcheck
	os.Setenv("SystemRoot", `C:\ThisDirectoryDefinitelyDoesNotExistAPFTest`) //nolint:errcheck
	path := findNetsh()
	if path != "netsh.exe" {
		t.Errorf("findNetsh with nonexistent SystemRoot = %q, want %q", path, "netsh.exe")
	}
}
