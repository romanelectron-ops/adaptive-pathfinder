package killswitch

import "testing"

// ─── findNetsh branches ───────────────────────────────────────────────────────

// ─── IsAdmin (additional call) ────────────────────────────────────────────────

func TestIsAdmin_ReturnsBool(t *testing.T) {
	result := IsAdmin()
	t.Logf("IsAdmin = %v", result)
}
