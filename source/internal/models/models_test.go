package models

import (
	"testing"
	"time"
)

// ── IsBlacklisted ────────────────────────────────────────────────────────────

func TestIsBlacklisted_True(t *testing.T) {
	n := &Node{BlacklistedUntil: time.Now().Add(1 * time.Hour)}
	if !n.IsBlacklisted() {
		t.Error("expected IsBlacklisted=true for future BlacklistedUntil")
	}
}

func TestIsBlacklisted_False(t *testing.T) {
	n := &Node{BlacklistedUntil: time.Now().Add(-1 * time.Hour)}
	if n.IsBlacklisted() {
		t.Error("expected IsBlacklisted=false for past BlacklistedUntil")
	}
}

func TestIsBlacklisted_ZeroTime(t *testing.T) {
	n := &Node{} // zero value: BlacklistedUntil is zero time (past)
	if n.IsBlacklisted() {
		t.Error("expected IsBlacklisted=false for zero BlacklistedUntil")
	}
}

// ── AgeSeconds ───────────────────────────────────────────────────────────────

func TestAgeSeconds_NotChecked(t *testing.T) {
	n := &Node{} // zero LastChecked
	age := n.AgeSeconds()
	if age != 99999 {
		t.Errorf("AgeSeconds for zero LastChecked = %v, want 99999", age)
	}
}

func TestAgeSeconds_RecentCheck(t *testing.T) {
	n := &Node{LastChecked: time.Now().Add(-5 * time.Second)}
	age := n.AgeSeconds()
	if age < 4 || age > 10 {
		t.Errorf("AgeSeconds for 5s ago = %v, want ~5", age)
	}
}

// ── DefaultConfig ────────────────────────────────────────────────────────────

func TestDefaultConfig_NotNil(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}
}

func TestDefaultConfig_Values(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.CheckInterval <= 0 {
		t.Errorf("CheckInterval = %d, want > 0", cfg.CheckInterval)
	}
	if cfg.ListenPort <= 0 {
		t.Errorf("ListenPort = %d, want > 0", cfg.ListenPort)
	}
	if cfg.MaxLatency <= 0 {
		t.Errorf("MaxLatency = %d, want > 0", cfg.MaxLatency)
	}
	if cfg.WebUIPort <= 0 {
		t.Errorf("WebUIPort = %d, want > 0", cfg.WebUIPort)
	}
}

func TestDefaultConfig_DNSOverTLS(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.DNSOverTLS == "" {
		t.Error("DNSOverTLS should have a default value")
	}
}
