package emergency

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWipePath_StatNonNotExist triggers the !os.IsNotExist(err) branch in wipePath.
// On Windows, a null byte in the path causes EINVAL (not ErrNotExist), which
// should cause wipePath to append an error to res.Errors.
func TestWipePath_StatNonNotExist(t *testing.T) {
	w := New()
	res := &WipeResult{}
	// "\x00" is invalid on Windows (EINVAL) and Linux (ENOENT-mapped but try)
	w.wipePath("\x00invalid\x00path", WipeOptions{ShredPasses: 1}, res)
	if len(res.Errors) == 0 {
		t.Skip("platform did not return non-NotExist stat error for invalid path — cannot cover this branch here")
	}
	t.Logf("OK: non-NotExist stat error recorded: %v", res.Errors)
}

// TestRemoveFile_OnNonEmptyDir triggers the os.Remove error branch in removeFile.
// os.Remove on a non-empty directory returns "directory not empty" (ENOTEMPTY),
// which is NOT os.IsNotExist, so res.Errors gets the error appended and the
// function returns early without incrementing FilesDeleted.
func TestRemoveFile_OnNonEmptyDir(t *testing.T) {
	dir := t.TempDir()
	// Put a child file inside so the directory is non-empty
	childPath := filepath.Join(dir, "child.txt")
	if err := os.WriteFile(childPath, []byte("x"), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	w := New()
	res := &WipeResult{}
	// removeFile on a non-empty directory: os.Remove will return ENOTEMPTY
	w.removeFile(dir, WipeOptions{ShredPasses: 1}, res)

	if len(res.Errors) == 0 {
		t.Error("expected error when removing non-empty directory, got none")
	}
	// FilesDeleted must NOT have been incremented (early return)
	if res.FilesDeleted != 0 {
		t.Errorf("FilesDeleted should be 0 after failed remove, got %d", res.FilesDeleted)
	}
	t.Logf("OK: remove error recorded: %v", res.Errors)
}

// TestWipePath_WalkError triggers the walkErr != nil branch in the filepath.Walk callback.
// We create a symlink pointing at a non-existent target; on some platforms Walk
// calls the callback with a non-nil walkErr for such entries.
// If the platform doesn't produce a walk error this way, the test is skipped.
func TestWipePath_WalkError(t *testing.T) {
	dir := t.TempDir()

	// Create a broken symlink inside dir
	linkPath := filepath.Join(dir, "broken_link")
	// os.Symlink may fail on Windows without SeCreateSymbolicLinkPrivilege
	if err := os.Symlink(filepath.Join(dir, "nonexistent_target"), linkPath); err != nil {
		t.Skipf("cannot create symlink on this platform: %v", err)
	}

	w := New()
	res := &WipeResult{}
	w.wipePath(dir, WipeOptions{ShredPasses: 1}, res)

	// The broken symlink itself may or may not cause a walkErr depending on OS/fs.
	// We just verify no panic and log what happened.
	t.Logf("OK: WalkError test done, errors=%v filesDeleted=%d", res.Errors, res.FilesDeleted)
}
