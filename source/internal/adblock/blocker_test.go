package adblock

import (
	"strings"
	"testing"
)

// ── parseDomains ──────────────────────────────────────────────────────────────

func TestParseDomains_Hosts(t *testing.T) {
	input := `
# Comment line
0.0.0.0 ads.example.com
127.0.0.1 tracker.example.com
0.0.0.0 localhost
192.168.1.1 internal.example.com

# Another comment
0.0.0.0 valid-domain.com
`
	domains, err := parseBlocklist(strings.NewReader(input), "hosts")
	if err != nil {
		t.Fatalf("parseDomains error: %v", err)
	}

	want := map[string]bool{
		"ads.example.com":     true,
		"tracker.example.com": true,
		"valid-domain.com":    true,
	}

	for d := range want {
		found := false
		for _, got := range domains {
			if got == d {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected domain %q not found in parsed results", d)
		}
	}

	for _, d := range domains {
		if d == "localhost" {
			t.Error("localhost should be filtered out (no dot)")
		}
	}
}

func TestParseDomains_AdBlock(t *testing.T) {
	input := `
! Comment
||ads.example.com^
||tracker.net^$important
||another-ad.org^
||invalid
`
	domains, err := parseBlocklist(strings.NewReader(input), "adblock")
	if err != nil {
		t.Fatalf("parseDomains error: %v", err)
	}

	want := []string{"ads.example.com", "tracker.net", "another-ad.org"}
	for _, w := range want {
		found := false
		for _, d := range domains {
			if d == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %q in adblock parsed domains", w)
		}
	}
}

func TestParseDomains_Domains(t *testing.T) {
	input := `
# header
ads.example.com
tracker.example.org
invalid domain with space
another-tracker.net
`
	domains, err := parseBlocklist(strings.NewReader(input), "domains")
	if err != nil {
		t.Fatalf("parseDomains error: %v", err)
	}

	want := []string{"ads.example.com", "tracker.example.org", "another-tracker.net"}
	for _, w := range want {
		found := false
		for _, d := range domains {
			if d == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %q in domains parsed output", w)
		}
	}

	for _, d := range domains {
		if strings.Contains(d, " ") {
			t.Errorf("domain with space should not be parsed: %q", d)
		}
	}
}

func TestParseDomains_Empty(t *testing.T) {
	domains, err := parseBlocklist(strings.NewReader(""), "hosts")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(domains) != 0 {
		t.Errorf("expected empty result for empty input, got %d", len(domains))
	}
}

// ── isValidDomain ─────────────────────────────────────────────────────────────

func TestIsValidDomain(t *testing.T) {
	valid := []string{
		"example.com",
		"sub.example.com",
		"ads.tracker.net",
		"a-b.c-d.com",
		"123.example.com",
	}
	// Примечание: isValidDomain проверяет только запрещённые символы (пробел, спецсимволы),
	// начало/конец с точки, отсутствие точки и длину. Двойные точки не проверяются.
	invalid := []string{
		"",
		"localhost",     // нет точки
		".example.com",  // начинается с точки
		"example.com.",  // оканчивается на точку
		"ex ample.com",  // пробел
		"example",       // нет точки
		"UPPERCASE.COM", // заглавные — функция ожидает строчные
	}

	for _, d := range valid {
		if !isValidDomain(d) {
			t.Errorf("expected %q to be valid domain", d)
		}
	}
	for _, d := range invalid {
		if isValidDomain(d) {
			t.Errorf("expected %q to be invalid domain", d)
		}
	}
}

// ── profileIncludes ──────────────────────────────────────────────────────────

func TestProfileIncludes(t *testing.T) {
	tests := []struct {
		current  Profile
		required Profile
		want     bool
	}{
		{ProfileStrict, ProfileLight, true},
		{ProfileStrict, ProfileStandard, true},
		{ProfileStrict, ProfileStrict, true},
		{ProfileStandard, ProfileLight, true},
		{ProfileStandard, ProfileStandard, true},
		{ProfileStandard, ProfileStrict, false},
		{ProfileLight, ProfileLight, true},
		{ProfileLight, ProfileStandard, false},
		{ProfileLight, ProfileStrict, false},
		{ProfileDisabled, ProfileLight, false},
	}

	for _, tt := range tests {
		got := profileIncludes(tt.current, tt.required)
		if got != tt.want {
			t.Errorf("profileIncludes(%s, %s) = %v, want %v",
				tt.current, tt.required, got, tt.want)
		}
	}
}

// ── Blocker методы ────────────────────────────────────────────────────────────

func TestBlocker_NewBlocker(t *testing.T) {
	b := NewBlocker(nil)
	if b == nil {
		t.Fatal("NewBlocker returned nil")
	}
	if b.GetProfile() != ProfileDisabled {
		t.Errorf("default profile = %q, want disabled", b.GetProfile())
	}
}

func TestBlocker_GetProfile(t *testing.T) {
	b := NewBlocker(nil)
	if b.GetProfile() != ProfileDisabled {
		t.Error("expected disabled profile initially")
	}
	b.mu.Lock()
	b.profile = ProfileStandard
	b.mu.Unlock()
	if b.GetProfile() != ProfileStandard {
		t.Error("expected standard profile after set")
	}
}

func TestBlocker_IsBlocked(t *testing.T) {
	b := NewBlocker(nil)
	b.mu.Lock()
	b.domains["ads.example.com"] = true
	b.profile = ProfileStandard
	b.mu.Unlock()

	if !b.IsBlocked("ads.example.com") {
		t.Error("ads.example.com should be blocked")
	}
	if b.IsBlocked("example.com") {
		t.Error("example.com should not be blocked")
	}
}

func TestBlocker_IsBlocked_Disabled(t *testing.T) {
	b := NewBlocker(nil)
	b.mu.Lock()
	b.domains["ads.example.com"] = true
	b.mu.Unlock()

	if b.IsBlocked("ads.example.com") {
		t.Error("nothing should be blocked when profile is disabled")
	}
}

func TestBlocker_Allowlist(t *testing.T) {
	b := NewBlocker(nil)
	b.mu.Lock()
	b.domains["ads.example.com"] = true
	b.profile = ProfileStandard
	b.mu.Unlock()

	b.AddToAllowlist("ads.example.com")
	if b.IsBlocked("ads.example.com") {
		t.Error("allowlisted domain should not be blocked")
	}

	b.RemoveFromAllowlist("ads.example.com")
	if !b.IsBlocked("ads.example.com") {
		t.Error("domain should be blocked again after removing from allowlist")
	}
}

func TestBlocker_GetAllowlist(t *testing.T) {
	b := NewBlocker(nil)
	b.AddToAllowlist("site1.com")
	b.AddToAllowlist("site2.com")

	list := b.GetAllowlist()
	if len(list) != 2 {
		t.Errorf("allowlist size = %d, want 2", len(list))
	}
}

func TestBlocker_GetStats(t *testing.T) {
	b := NewBlocker(nil)
	b.mu.Lock()
	b.domains["a.com"] = true
	b.domains["b.com"] = true
	b.profile = ProfileLight
	b.stats.TotalDomains = 2
	b.mu.Unlock()
	b.AddToAllowlist("safe.com")

	stats := b.GetStats()
	if stats.TotalDomains != 2 {
		t.Errorf("TotalDomains = %d, want 2", stats.TotalDomains)
	}
	if stats.AllowlistSize != 1 {
		t.Errorf("AllowlistSize = %d, want 1", stats.AllowlistSize)
	}
}

func TestBlocker_GetSingBoxDNSRules_Empty(t *testing.T) {
	b := NewBlocker(nil)
	rules := b.GetSingBoxDNSRules()
	if rules != nil && len(rules) != 0 {
		t.Errorf("expected empty rules for empty domain list, got %d", len(rules))
	}
}

func TestBlocker_GetSingBoxDNSRules_WithDomains(t *testing.T) {
	b := NewBlocker(nil)
	b.mu.Lock()
	b.profile = ProfileLight
	for i := 0; i < 200; i++ {
		b.domains[strings.Repeat("a", i%20+1)+".com"] = true
	}
	b.mu.Unlock()

	rules := b.GetSingBoxDNSRules()
	if len(rules) == 0 {
		t.Error("expected sing-box DNS rules for non-empty domain list")
	}
}
