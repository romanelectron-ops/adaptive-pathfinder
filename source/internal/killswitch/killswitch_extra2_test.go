package killswitch

import "testing"

// ─── setDNSDHCPFn default body ───────────────────────────────────────────────

// TestSetDNSDHCPFn_DefaultBody covers reset.go lines 22-25
// (the body of the default setDNSDHCPFn lambda).
//
// The lambda calls exec.Command("netsh", ...).Run() with a nonexistent adapter
// name; Run() fails silently (the error is discarded), but the lambda body is
// fully executed — covering that source block.
func TestSetDNSDHCPFn_DefaultBody(t *testing.T) {
	orig := setDNSDHCPFn
	defer func() { setDNSDHCPFn = orig }()

	// Invoking orig() exercises the default lambda body directly.
	// The netsh command will fail on any platform (adapter doesn't exist),
	// but its return value is intentionally discarded — no panic, no error.
	orig("FakeAdapterThatDoesNotExist_Coverage")
}

// ─── resetDNSSafe: setDNSDHCPFn trigger path ─────────────────────────────────

// TestResetDNSSafe_SetsDHCP exercises the path in resetDNSSafe() where
// a "Connected" adapter has a statically configured APF DNS address,
// causing setDNSDHCPFn to be called.  We inject all three injection vars
// so the test is fully hermetic and never touches the real network stack.
func TestResetDNSSafe_SetsDHCP(t *testing.T) {
	// Track whether setDNSDHCPFn was called.
	called := false

	origShow := showInterfacesFn
	origGetDNS := getDNSInfoFn
	origSetDHCP := setDNSDHCPFn
	defer func() {
		showInterfacesFn = origShow
		getDNSInfoFn = origGetDNS
		setDNSDHCPFn = origSetDHCP
	}()

	// Inject a fake netsh interface list with one Connected adapter.
	showInterfacesFn = func() ([]byte, error) {
		// Real netsh output format: "Admin State   State     Type         Interface Name"
		// Fields: [Admin, State, Type, Name...]
		// We need len(fields) >= 4 and the line to contain "Connected".
		line := "Enabled   Connected   Dedicated   Wi-Fi\r\n"
		return []byte(line), nil
	}

	// Inject fake DNS info showing APF's static 8.8.8.8 entry.
	getDNSInfoFn = func(iface string) ([]byte, error) {
		return []byte("Statically Configured DNS Servers: 8.8.8.8"), nil
	}

	// Inject our setDNSDHCP tracker.
	setDNSDHCPFn = func(iface string) {
		called = true
	}

	resetDNSSafe()

	if !called {
		t.Error("expected setDNSDHCPFn to be called for a Connected adapter with static APF DNS")
	}
}
