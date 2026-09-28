package leakguard

import (
	"context"
	"strings"
	"testing"
	"time"
)

// ── WebRTCGuard ───────────────────────────────────────────────────────────────

func TestWebRTCGuard_NewDisabled(t *testing.T) {
	g := NewWebRTCGuard()
	if g.IsEnabled() {
		t.Error("new WebRTCGuard should be disabled")
	}
}

func TestWebRTCGuard_Enable(t *testing.T) {
	g := NewWebRTCGuard()
	if err := g.Enable(); err != nil {
		t.Fatalf("Enable() error: %v", err)
	}
	if !g.IsEnabled() {
		t.Error("after Enable, IsEnabled() should be true")
	}
}

func TestWebRTCGuard_Disable(t *testing.T) {
	g := NewWebRTCGuard()
	g.Enable()
	if err := g.Disable(); err != nil {
		t.Fatalf("Disable() error: %v", err)
	}
	if g.IsEnabled() {
		t.Error("after Disable, IsEnabled() should be false")
	}
}

func TestWebRTCGuard_Toggle(t *testing.T) {
	g := NewWebRTCGuard()
	g.Enable()
	g.Disable()
	g.Enable()
	if !g.IsEnabled() {
		t.Error("after Enable/Disable/Enable, should be enabled")
	}
}

// ── GetBrowserInstructions ────────────────────────────────────────────────────

func TestGetBrowserInstructions_HasBrowsers(t *testing.T) {
	inst := GetBrowserInstructions()
	required := []string{"chrome", "firefox", "brave", "edge"}
	for _, br := range required {
		if _, ok := inst[br]; !ok {
			t.Errorf("missing browser instructions for: %s", br)
		}
	}
}

func TestGetBrowserInstructions_NotEmpty(t *testing.T) {
	inst := GetBrowserInstructions()
	for name, b := range inst {
		if b.Name == "" {
			t.Errorf("browser %s has empty Name", name)
		}
		if b.Method == "" {
			t.Errorf("browser %s has empty Method", name)
		}
		if len(b.Steps) == 0 {
			t.Errorf("browser %s has no steps", name)
		}
	}
}

// ── GenerateFirefoxUserJS ─────────────────────────────────────────────────────

func TestGenerateFirefoxUserJS_NotEmpty(t *testing.T) {
	js := GenerateFirefoxUserJS()
	if js == "" {
		t.Error("GenerateFirefoxUserJS() should not be empty")
	}
	if !strings.Contains(js, "user_pref") {
		t.Error("Firefox user.js should contain user_pref declarations")
	}
	if !strings.Contains(js, "peerconnection") {
		t.Error("Firefox user.js should disable WebRTC peerconnection")
	}
}

// ── DNSLeakTester ─────────────────────────────────────────────────────────────

func TestNewDNSLeakTester_NotNil(t *testing.T) {
	d := NewDNSLeakTester("127.0.0.1:1080")
	if d == nil {
		t.Fatal("NewDNSLeakTester returned nil")
	}
}

func TestDNSLeakTester_QuickCheck_NoSocks(t *testing.T) {
	// SOCKS не слушает — QuickCheck не должен паниковать
	d := NewDNSLeakTester("127.0.0.1:19999") // порт не слушает
	leaked, serverIP := d.QuickCheck(context.Background())
	// QuickCheck возвращает false, "" или true, ip — главное не паника
	_ = leaked
	_ = serverIP
}

func TestDNSLeakTester_Test_NoSocks(t *testing.T) {
	// SOCKS не слушает → ожидаем leaked=true (туннель недоступен)
	d := NewDNSLeakTester("127.0.0.1:19999")
	result, err := d.Test(context.Background())
	if err != nil {
		t.Fatalf("Test() returned error: %v", err)
	}
	if result == nil {
		t.Fatal("Test() returned nil result")
	}
	// При недоступном SOCKS — Leaked=true и есть диагноз
	if result.Leaked && result.Diagnosis == "" {
		t.Error("leaked result should have diagnosis")
	}
}

func TestDNSLeakTester_Test_EmptySocks(t *testing.T) {
	// Пустой SOCKS адрес — не должно падать
	d := NewDNSLeakTester("")
	result, err := d.Test(context.Background())
	if err != nil {
		t.Fatalf("Test() with empty socks should not error: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
}

func TestDNSLeakResult_Fields(t *testing.T) {
	d := NewDNSLeakTester("127.0.0.1:19999")
	result, _ := d.Test(context.Background())
	if result == nil {
		t.Fatal("result should not be nil")
	}
	// Проверяем что все строковые поля непустые
	// (хотя бы Diagnosis и Recommendation должны быть заполнены)
	if result.Diagnosis == "" {
		t.Error("DNSLeakResult.Diagnosis should not be empty")
	}
	if result.Recommendation == "" {
		t.Error("DNSLeakResult.Recommendation should not be empty")
	}
}

// ── portReachable ─────────────────────────────────────────────────────────────

func TestPortReachable_ClosedPort(t *testing.T) {
	// Порт 1 никогда не должен быть открыт
	result := portReachable("127.0.0.1:1", 200*time.Millisecond)
	if result {
		t.Error("port 1 should not be reachable")
	}
}

// ─── Additional leakguard coverage ────────────────────────────────────────────

func TestParseAddr(t *testing.T) {
	cases := []struct {
		input    string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{"127.0.0.1:10808", "127.0.0.1", 10808, false},
		{"localhost:9090", "localhost", 9090, false},
		{"host.example.com:443", "host.example.com", 443, false},
		{"[::1]:8080", "::1", 8080, false},
		{"no-port", "", 0, true},
		{"", "", 0, true},
	}
	for _, c := range cases {
		host, port, err := parseAddr(c.input)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseAddr(%q): expected error", c.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseAddr(%q): unexpected error: %v", c.input, err)
			continue
		}
		if host != c.wantHost {
			t.Errorf("parseAddr(%q): host want %q, got %q", c.input, c.wantHost, host)
		}
		if port != c.wantPort {
			t.Errorf("parseAddr(%q): port want %d, got %d", c.input, c.wantPort, port)
		}
	}
	t.Log("OK: parseAddr all cases")
}

func TestIPv6GuardCycle(t *testing.T) {
	g := NewIPv6Guard()
	if g == nil {
		t.Fatal("NewIPv6Guard returned nil")
	}
	if g.IsEnabled() {
		t.Error("should start disabled")
	}

	// Enable — на CI может не работать (нет прав), но не должно паниковать
	err := g.Enable("lo")
	if err != nil {
		t.Logf("IPv6Guard.Enable warning (may need root): %v", err)
	}

	// Disable — тоже
	err = g.Disable()
	if err != nil {
		t.Logf("IPv6Guard.Disable warning: %v", err)
	}
	t.Log("OK: IPv6Guard lifecycle no panic")
}

func TestIPv6LeakTestNoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("TestIPv6Leak panicked: %v", r)
		}
	}()
	leaked, msg := TestIPv6Leak()
	t.Logf("OK: TestIPv6Leak() = leaked=%v msg=%q", leaked, msg)
}

func TestWebRTCGuardNewAPI(t *testing.T) {
	g := NewWebRTCGuard()
	if g == nil {
		t.Fatal("nil")
	}
	if g.IsEnabled() {
		t.Error("should start disabled")
	}
	// Enable/Disable cycle
	g.Enable()
	if !g.IsEnabled() {
		t.Error("should be enabled after Enable()")
	}
	g.Disable()
	if g.IsEnabled() {
		t.Error("should be disabled after Disable()")
	}
	t.Log("OK: WebRTCGuard full cycle")
}

func TestSystemDNSServersNoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("systemDNSServers panicked: %v", r)
		}
	}()
	servers := systemDNSServers()
	t.Logf("OK: systemDNSServers() = %v (platform-specific)", servers)
}
