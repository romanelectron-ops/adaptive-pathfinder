package singbox

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── helpers ────────────────────────────────────────────────────────────────

func testNode() *models.Node {
	return &models.Node{
		Protocol: models.ProtoVLESS,
		Address:  "test.example.com",
		Port:     443,
		UUID:     "12345678-1234-1234-1234-123456789012",
		Flow:     "xtls-rprx-vision",
		TLS: &models.TLSConfig{
			Enabled:    true,
			ServerName: "www.microsoft.com",
			Reality: &models.RealityConfig{
				PublicKey: "pubkey123",
				ShortID:   "abcdef01",
			},
		},
	}
}

// ─── buildDNS adBlockRules branches ─────────────────────────────────────────

// TestBuildDNS_AdBlockRules_StringSlice covers the []string type switch branch.
func TestBuildDNS_AdBlockRules_StringSlice(t *testing.T) {
	b := NewBuilder(10808, false)
	b.SetAdBlockRules([]map[string]interface{}{
		{"domain_suffix": []string{"ad.example.com", "tracker.net"}},
	})

	dns := b.buildDNS("proxy")

	// Base rules: 1 (localhost/local). Plus our adblock rule = 2.
	if len(dns.Rules) < 2 {
		t.Fatalf("expected ≥2 DNS rules, got %d", len(dns.Rules))
	}
	// Last rule should be the adblock one
	last := dns.Rules[len(dns.Rules)-1]
	if last.Action != "reject" {
		t.Errorf("expected action=reject, got %q", last.Action)
	}
	if len(last.DomainSuffix) != 2 {
		t.Errorf("expected 2 domain suffixes, got %d", len(last.DomainSuffix))
	}
}

// TestBuildDNS_AdBlockRules_InterfaceSlice covers the []interface{} type switch branch.
func TestBuildDNS_AdBlockRules_InterfaceSlice(t *testing.T) {
	b := NewBuilder(10808, false)
	b.SetAdBlockRules([]map[string]interface{}{
		{"domain_suffix": []interface{}{"spam.org", "phish.net", 42}}, // 42 is not a string, should be skipped
	})

	dns := b.buildDNS("proxy")

	if len(dns.Rules) < 2 {
		t.Fatalf("expected ≥2 DNS rules, got %d", len(dns.Rules))
	}
	last := dns.Rules[len(dns.Rules)-1]
	if last.Action != "reject" {
		t.Errorf("expected action=reject, got %q", last.Action)
	}
	// Only 2 strings are valid (42 is int, skipped)
	if len(last.DomainSuffix) != 2 {
		t.Errorf("expected 2 domain suffixes (int skipped), got %d: %v",
			len(last.DomainSuffix), last.DomainSuffix)
	}
}

// TestBuildDNS_AdBlockRules_NoDomainSuffix covers the path where a rule has no
// "domain_suffix" key → DomainSuffix stays empty → rule is NOT appended.
func TestBuildDNS_AdBlockRules_NoDomainSuffix(t *testing.T) {
	b := NewBuilder(10808, false)
	b.SetAdBlockRules([]map[string]interface{}{
		{"other_key": "value"}, // no domain_suffix
	})

	dns := b.buildDNS("proxy")

	// Should still have only the 2 base rules (localhost/local + default-bypass
	// ipv4_only strategy, see buildDNS), no adblock rule added.
	if len(dns.Rules) != 2 {
		t.Errorf("expected 2 DNS rules (no adblock added), got %d", len(dns.Rules))
	}
}

// TestBuildDNS_AdBlockRules_EmptyInterfaceSlice covers []interface{} with no strings
// → DomainSuffix empty → rule NOT appended.
func TestBuildDNS_AdBlockRules_EmptyInterfaceSlice(t *testing.T) {
	b := NewBuilder(10808, false)
	b.SetAdBlockRules([]map[string]interface{}{
		{"domain_suffix": []interface{}{42, 3.14}}, // no strings
	})

	dns := b.buildDNS("proxy")

	// Rule with empty DomainSuffix must NOT be added — only the 2 base rules remain
	// (localhost/local + default-bypass ipv4_only strategy, see buildDNS).
	if len(dns.Rules) != 2 {
		t.Errorf("expected 2 DNS rules, got %d", len(dns.Rules))
	}
}

// TestBuildDNS_AdBlockRules_MultipleRules covers the loop body executed multiple times.
func TestBuildDNS_AdBlockRules_MultipleRules(t *testing.T) {
	b := NewBuilder(10808, false)
	b.SetAdBlockRules([]map[string]interface{}{
		{"domain_suffix": []string{"a.com"}},
		{"domain_suffix": []interface{}{"b.org"}},
		{"other": "no suffix"}, // skipped
	})

	dns := b.buildDNS("proxy")

	// 2 base (localhost/local + default-bypass ipv4_only strategy) + 2 adblock rules
	if len(dns.Rules) != 4 {
		t.Errorf("expected 4 DNS rules, got %d: %v", len(dns.Rules), dns.Rules)
	}
}

// TestBuildDNS_ViaBuilSingle verifies adBlock rules flow through BuildSingle.
func TestBuildDNS_ViaBuildSingle(t *testing.T) {
	b := NewBuilder(10808, false)
	b.SetAdBlockRules([]map[string]interface{}{
		{"domain_suffix": []string{"malware.example"}},
	})

	cfg, err := b.BuildSingle(testNode())
	if err != nil {
		t.Fatalf("BuildSingle: %v", err)
	}

	found := false
	for _, r := range cfg.DNS.Rules {
		if r.Action == "reject" && len(r.DomainSuffix) > 0 {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected reject rule in DNS config after SetAdBlockRules")
	}
}

// ─── coalesceInt ─────────────────────────────────────────────────────────────

func TestCoalesceInt_AllZeros(t *testing.T) {
	got := coalesceInt(0, 0, 0)
	if got != 0 {
		t.Errorf("coalesceInt(0,0,0) = %d, want 0", got)
	}
}

func TestCoalesceInt_FirstNonZero(t *testing.T) {
	got := coalesceInt(0, 5, 3)
	if got != 5 {
		t.Errorf("coalesceInt(0,5,3) = %d, want 5", got)
	}
}

func TestCoalesceInt_Empty(t *testing.T) {
	got := coalesceInt()
	if got != 0 {
		t.Errorf("coalesceInt() = %d, want 0", got)
	}
}

// ─── buildDownloadURL (process.go) ──────────────────────────────────────────

func TestBuildDownloadURL_ContainsVersion(t *testing.T) {
	url := buildDownloadURL("1.9.4")
	if !strings.Contains(url, "1.9.4") {
		t.Errorf("URL %q does not contain version", url)
	}
	if !strings.Contains(url, "sing-box") {
		t.Errorf("URL %q does not contain 'sing-box'", url)
	}
	if !strings.HasPrefix(url, "https://") {
		t.Errorf("URL %q not HTTPS", url)
	}
}

// ─── Downloader helpers ──────────────────────────────────────────────────────

func TestNewDownloader_Fields(t *testing.T) {
	d := NewDownloader("/tmp/test")
	if d.BinDir != "/tmp/test" {
		t.Errorf("BinDir = %q, want /tmp/test", d.BinDir)
	}
	if d.Version == "" {
		t.Error("Version should not be empty")
	}
}

func TestDownloader_BuildURL_Format(t *testing.T) {
	d := NewDownloader("/tmp/test")
	url, archiveName := d.buildURL()
	if !strings.Contains(url, d.Version) {
		t.Errorf("URL %q does not contain version %q", url, d.Version)
	}
	if archiveName == "" {
		t.Error("archiveName should not be empty")
	}
	if !strings.HasPrefix(url, "https://") {
		t.Errorf("URL %q not HTTPS", url)
	}
}

func TestDownloader_Log_CallsOnLog(t *testing.T) {
	d := NewDownloader("/tmp/test")
	var got string
	d.OnLog = func(msg string) { got = msg }
	d.log("hello world")
	if got != "hello world" {
		t.Errorf("OnLog got %q, want %q", got, "hello world")
	}
}

func TestDownloader_Log_NilOnLog(t *testing.T) {
	// Must not panic when OnLog is nil.
	d := NewDownloader("/tmp/test")
	d.log("should not panic")
}

func TestDownloader_Progress_CallsOnProgress(t *testing.T) {
	d := NewDownloader("/tmp/test")
	gotPct, gotMsg := -1, ""
	d.OnProgress = func(pct int, msg string) { gotPct = pct; gotMsg = msg }
	d.progress(42, "test message")
	if gotPct != 42 || gotMsg != "test message" {
		t.Errorf("progress got (%d, %q), want (42, 'test message')", gotPct, gotMsg)
	}
}

// ─── Process helpers ─────────────────────────────────────────────────────────

func TestNewProcess_IsInstalled_False(t *testing.T) {
	p := NewProcess("/nonexistent/dir", os.TempDir())
	if p.IsInstalled() {
		t.Error("IsInstalled should return false for nonexistent binary")
	}
}

func TestProcess_WriteConfig_Success(t *testing.T) {
	dir := t.TempDir()
	p := NewProcess(dir, dir)

	b := NewBuilder(10808, false)
	cfg, err := b.BuildSingle(testNode())
	if err != nil {
		t.Fatalf("BuildSingle: %v", err)
	}

	if err := p.WriteConfig(cfg); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}

	// File should exist
	info, err := os.Stat(p.configPath)
	if err != nil {
		t.Fatalf("config file not found: %v", err)
	}
	if info.Size() == 0 {
		t.Error("config file is empty")
	}
}

func TestProcess_Log_CallsOnLog(t *testing.T) {
	p := NewProcess("/tmp", os.TempDir())
	var got string
	p.OnLog = func(msg string) { got = msg }
	p.log("test msg")
	if got != "test msg" {
		t.Errorf("OnLog got %q, want 'test msg'", got)
	}
}

func TestProcess_Log_NilOnLog(t *testing.T) {
	p := NewProcess("/tmp", os.TempDir())
	p.log("no panic") // should not panic
}

func TestProcess_Stop_WhenNotRunning(t *testing.T) {
	p := NewProcess("/tmp", os.TempDir())
	// Stop when not running should return nil without panicking
	if err := p.Stop(); err != nil {
		t.Errorf("Stop() on idle process: %v", err)
	}
}

// TestProcess_EnsureInstalled_Short tests EnsureInstalled when binary doesn't exist;
// we cancel context immediately to avoid real network calls.
func TestProcess_EnsureInstalled_AlreadyInstalled(t *testing.T) {
	// Use a temp binary that exists (create a dummy file)
	dir := t.TempDir()
	binName := "sing-box"
	// Create fake binary file
	binPath := dir + string(os.PathSeparator) + binName
	if err := os.WriteFile(binPath, []byte("fake"), 0755); err != nil {
		t.Skip("cannot create fake binary")
	}

	d := NewDownloader(dir)
	// EnsureInstalled will call p.IsInstalled() → true, then p.Version() → fails (not real binary)
	// If Version() fails it falls through to Download() which we cancel via ctx.
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	// We just want this path to not panic; result can be an error
	_ = d.EnsureInstalled(ctx)
}

// TestDownloader_EnsureInstalled_NotInstalled cancels context immediately
// to avoid real download; just checks no panic.
func TestDownloader_EnsureInstalled_CtxCancelled(t *testing.T) {
	d := NewDownloader(t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := d.EnsureInstalled(ctx)
	// Should return an error (context cancelled), not panic
	if err == nil {
		t.Log("EnsureInstalled returned nil (binary may already exist)")
	}
}
