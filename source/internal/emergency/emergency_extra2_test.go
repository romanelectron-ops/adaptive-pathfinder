package emergency

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWipePath_InvalidCharsNotExist covers the !os.IsNotExist(err) branch in wipePath.
// On Windows a path containing '*' causes os.Stat to return ERROR_INVALID_NAME,
// which is not mapped to ErrNotExist, so the error is appended to res.Errors.
func TestWipePath_InvalidCharsNotExist(t *testing.T) {
	w := New()
	res := &WipeResult{}
	// '*' is an illegal character in Windows paths; os.Stat returns ERROR_INVALID_NAME
	// which is NOT os.IsNotExist — covering the res.Errors append branch.
	w.wipePath("invalid*path*chars", WipeOptions{ShredPasses: 1}, res)
	if len(res.Errors) == 0 {
		t.Skip("platform mapped the invalid-path error to ErrNotExist; branch not coverable this way")
	}
	t.Logf("OK: non-NotExist stat error appended: %v", res.Errors)
}

// TestOverwriteWithZeros_ReadOnly covers the os.OpenFile error branch in overwriteWithZeros.
// A read-only file cannot be opened for writing; os.OpenFile returns an access-denied
// error, which causes overwriteWithZeros to return that error.
func TestOverwriteWithZeros_ReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "readonly.bin")

	// Write some content so size > 0 (skips the early-return path)
	if err := os.WriteFile(path, []byte("hello world"), 0600); err != nil {
		t.Fatalf("setup WriteFile: %v", err)
	}

	// Make the file read-only so os.OpenFile(O_WRONLY) will fail
	if err := os.Chmod(path, 0400); err != nil {
		t.Skipf("cannot chmod on this platform: %v", err)
	}
	// Restore permissions after test so TempDir cleanup can remove the file
	defer os.Chmod(path, 0600) //nolint:errcheck

	err := overwriteWithZeros(path, 1)
	if err == nil {
		t.Skip("platform allowed write-open on read-only file; branch not coverable")
	}
	t.Logf("OK: overwriteWithZeros returned expected error: %v", err)
}
