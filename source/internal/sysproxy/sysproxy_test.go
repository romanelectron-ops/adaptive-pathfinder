package sysproxy

import (
	"testing"
)

// TestDisable verifies that Disable() completes without error.
// On Windows it writes ProxyEnable=0 to HKCU Internet Settings (safe to run).
// On other platforms the stub always returns nil.
func TestDisable_NoError(t *testing.T) {
	err := Disable()
	if err != nil {
		t.Errorf("Disable() returned unexpected error: %v", err)
	}
}

// TestSetHTTPProxy verifies that SetHTTPProxy completes and
// restores state via Disable() afterwards.
func TestSetHTTPProxy_NoError(t *testing.T) {
	err := SetHTTPProxy("127.0.0.1", 10808)
	if err != nil {
		t.Errorf("SetHTTPProxy() returned unexpected error: %v", err)
	}
	// Restore: disable the proxy we just set
	_ = Disable()
}

// TestSetHTTPProxy_EmptyHost tests with an empty host string.
// The function should still succeed (no format error) and produce a proxy
// string like ":10808". Actual validation is OS-level.
func TestSetHTTPProxy_EmptyHost(t *testing.T) {
	err := SetHTTPProxy("", 0)
	// On non-Windows stubs this is always nil; on Windows it may succeed or fail
	// based on registry access — just ensure no panic.
	_ = err
	// Restore
	_ = Disable()
}
