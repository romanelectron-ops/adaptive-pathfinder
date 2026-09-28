package adblock

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ── fetchBlocklist mock tests ──────────────────────────────────────────────────

func TestFetchBlocklist_Hosts(t *testing.T) {
	body := "# comment\n0.0.0.0 ads.example.com\n0.0.0.0 tracker.evil.net\n127.0.0.1 bad.domain.org\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(body))
	}))
	defer srv.Close()

	client := &http.Client{}
	src := BlocklistSource{
		ID:      "test-hosts",
		Name:    "Test Hosts",
		URL:     srv.URL,
		Profile: ProfileLight,
		Format:  "hosts",
	}

	domains, err := fetchBlocklist(context.Background(), client, src)
	if err != nil {
		t.Fatalf("fetchBlocklist: %v", err)
	}
	if len(domains) < 2 {
		t.Errorf("expected >= 2 domains, got %d: %v", len(domains), domains)
	}
	found := false
	for _, d := range domains {
		if d == "ads.example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected ads.example.com in domains, got: %v", domains)
	}
}

func TestFetchBlocklist_Domains(t *testing.T) {
	body := "# header\nads.example.com\ntracker.example.net\n! adblock comment\n\nbad.domain.org\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(body))
	}))
	defer srv.Close()

	client := &http.Client{}
	src := BlocklistSource{
		URL:    srv.URL,
		Format: "domains",
	}

	domains, err := fetchBlocklist(context.Background(), client, src)
	if err != nil {
		t.Fatalf("fetchBlocklist domains: %v", err)
	}
	if len(domains) == 0 {
		t.Error("expected at least 1 domain from domains format")
	}
}

func TestFetchBlocklist_Adblock(t *testing.T) {
	body := "! Adblock filter list\n||ads.example.com^\n||tracker.example.net^\n@@||safe.example.com^\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(body))
	}))
	defer srv.Close()

	client := &http.Client{}
	src := BlocklistSource{
		URL:    srv.URL,
		Format: "adblock",
	}

	domains, err := fetchBlocklist(context.Background(), client, src)
	if err != nil {
		t.Fatalf("fetchBlocklist adblock: %v", err)
	}
	if len(domains) == 0 {
		t.Error("expected at least 1 domain from adblock format")
	}
}

func TestFetchBlocklist_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()

	client := &http.Client{}
	src := BlocklistSource{URL: srv.URL, Format: "domains"}

	_, err := fetchBlocklist(context.Background(), client, src)
	if err == nil {
		t.Error("expected error for HTTP 404, got nil")
	}
}

func TestFetchBlocklist_ConnectionRefused(t *testing.T) {
	client := &http.Client{}
	src := BlocklistSource{URL: "http://127.0.0.1:1/list.txt", Format: "domains"}

	ctx, cancel := context.WithTimeout(context.Background(), 2e9)
	defer cancel()
	_, err := fetchBlocklist(ctx, client, src)
	if err == nil {
		t.Error("expected error for connection refused, got nil")
	}
}

// ── SetProfile mock tests ──────────────────────────────────────────────────────

func TestSetProfile_Disabled(t *testing.T) {
	b := NewBlocker(nil)
	// Manually add some domains
	b.mu.Lock()
	b.domains["ads.example.com"] = true
	b.mu.Unlock()

	err := b.SetProfile(context.Background(), ProfileDisabled)
	if err != nil {
		t.Fatalf("SetProfile disabled: %v", err)
	}
	if b.GetProfile() != ProfileDisabled {
		t.Errorf("profile = %q, want %q", b.GetProfile(), ProfileDisabled)
	}
	// Domains should be cleared
	b.mu.RLock()
	count := len(b.domains)
	b.mu.RUnlock()
	if count != 0 {
		t.Errorf("domains not cleared after disable, got %d", count)
	}
}

func TestSetProfile_LightWithMock(t *testing.T) {
	// Create mock servers for the blocklist sources
	hostsBody := "0.0.0.0 ads.test.com\n0.0.0.0 tracker.test.net\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(hostsBody))
	}))
	defer srv.Close()

	// Override DefaultSources for test
	origSources := DefaultSources
	DefaultSources = []BlocklistSource{
		{ID: "test", Name: "Test", URL: srv.URL, Profile: ProfileLight, Format: "hosts"},
	}
	defer func() { DefaultSources = origSources }()

	b := NewBlocker(nil)
	err := b.SetProfile(context.Background(), ProfileLight)
	if err != nil {
		t.Fatalf("SetProfile light: %v", err)
	}
	if b.GetProfile() != ProfileLight {
		t.Errorf("profile = %q, want %q", b.GetProfile(), ProfileLight)
	}
	stats := b.GetStats()
	if stats.SourcesLoaded < 1 {
		t.Errorf("SourcesLoaded = %d, want >= 1", stats.SourcesLoaded)
	}
}

// ── UpdateLists mock tests ─────────────────────────────────────────────────────

func TestUpdateLists_ProfileDisabled(t *testing.T) {
	b := NewBlocker(nil)
	// profile is already disabled by default
	err := b.UpdateLists(context.Background())
	if err != nil {
		t.Fatalf("UpdateLists disabled: %v", err)
	}
}

func TestUpdateLists_LightProfile_WithMock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("0.0.0.0 block-me.com\n0.0.0.0 also-blocked.net\n"))
	}))
	defer srv.Close()

	origSources := DefaultSources
	DefaultSources = []BlocklistSource{
		{ID: "mock-light", Name: "Mock Light", URL: srv.URL, Profile: ProfileLight, Format: "hosts"},
	}
	defer func() { DefaultSources = origSources }()

	b := NewBlocker(nil)
	b.mu.Lock()
	b.profile = ProfileLight
	b.mu.Unlock()

	err := b.UpdateLists(context.Background())
	if err != nil {
		t.Fatalf("UpdateLists: %v", err)
	}

	if !b.IsBlocked("block-me.com") {
		t.Error("expected block-me.com to be blocked after UpdateLists")
	}
	if !b.IsBlocked("sub.block-me.com") {
		t.Error("expected sub.block-me.com to be blocked (subdomain)")
	}

	stats := b.GetStats()
	if stats.TotalDomains < 1 {
		t.Errorf("TotalDomains = %d, want >= 1", stats.TotalDomains)
	}
	if stats.SourcesLoaded < 1 {
		t.Errorf("SourcesLoaded = %d, want >= 1", stats.SourcesLoaded)
	}
}

func TestUpdateLists_SourceFailed(t *testing.T) {
	// Server fails — source should be counted as failed
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	origSources := DefaultSources
	DefaultSources = []BlocklistSource{
		{ID: "fail-src", Name: "Fail", URL: srv.URL, Profile: ProfileLight, Format: "hosts"},
	}
	defer func() { DefaultSources = origSources }()

	b := NewBlocker(nil)
	b.mu.Lock()
	b.profile = ProfileLight
	b.mu.Unlock()

	err := b.UpdateLists(context.Background())
	if err != nil {
		t.Fatalf("UpdateLists should succeed even when sources fail: %v", err)
	}

	stats := b.GetStats()
	if stats.SourcesFailed < 1 {
		t.Errorf("SourcesFailed = %d, want >= 1", stats.SourcesFailed)
	}
}

func TestUpdateLists_ProfileFiltering(t *testing.T) {
	// Standard source should be excluded for Light profile
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(200)
		w.Write([]byte("0.0.0.0 example.com\n"))
	}))
	defer srv.Close()

	origSources := DefaultSources
	DefaultSources = []BlocklistSource{
		{ID: "light-src", Name: "Light", URL: srv.URL, Profile: ProfileLight, Format: "hosts"},
		{ID: "strict-src", Name: "Strict", URL: srv.URL, Profile: ProfileStrict, Format: "hosts"},
	}
	defer func() { DefaultSources = origSources }()

	b := NewBlocker(nil)
	b.mu.Lock()
	b.profile = ProfileLight
	b.mu.Unlock()

	_ = b.UpdateLists(context.Background())

	// Only the light source should be fetched
	if callCount != 1 {
		t.Errorf("expected 1 fetch (light only), got %d", callCount)
	}
}

func TestUpdateLists_StandardIncludesLightSources(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(200)
		w.Write([]byte("0.0.0.0 example.com\n"))
	}))
	defer srv.Close()

	origSources := DefaultSources
	DefaultSources = []BlocklistSource{
		{ID: "light-src", Name: "Light", URL: srv.URL, Profile: ProfileLight, Format: "hosts"},
		{ID: "standard-src", Name: "Standard", URL: srv.URL, Profile: ProfileStandard, Format: "hosts"},
		{ID: "strict-src", Name: "Strict", URL: srv.URL, Profile: ProfileStrict, Format: "hosts"},
	}
	defer func() { DefaultSources = origSources }()

	b := NewBlocker(nil)
	b.mu.Lock()
	b.profile = ProfileStandard
	b.mu.Unlock()

	_ = b.UpdateLists(context.Background())

	// Standard profile includes light and standard, but not strict
	if callCount != 2 {
		t.Errorf("expected 2 fetches (light + standard), got %d", callCount)
	}
}

// TestUpdateLists_AllSourcesFail_KeepsOldDomains покрывает сценарий из комментария в
// UpdateLists (живой инцидент 2026-08-27): если ВСЕ источники профиля недоступны
// (loaded==0), защита не должна схлопываться до пустого списка — старые домены остаются
// как есть до следующего успешного обновления. До этого теста ветка "else" (loaded==0)
// в UpdateLists не была покрыта ни одним тестом пакета.
func TestUpdateLists_AllSourcesFail_KeepsOldDomains(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	origSources := DefaultSources
	DefaultSources = []BlocklistSource{
		{ID: "always-fails", Name: "AlwaysFails", URL: srv.URL, Profile: ProfileLight, Format: "hosts"},
	}
	defer func() { DefaultSources = origSources }()

	b := NewBlocker(nil)
	b.mu.Lock()
	b.profile = ProfileLight
	// Симулируем ранее успешно загруженный список — то самое состояние, которое инцидент
	// требовал сохранить при полном отказе сети.
	b.domains = map[string]bool{"previously-loaded.example": true}
	b.mu.Unlock()

	if err := b.UpdateLists(context.Background()); err != nil {
		t.Fatalf("UpdateLists must not return an error on total source failure: %v", err)
	}

	stats := b.GetStats()
	if stats.SourcesLoaded != 0 {
		t.Errorf("SourcesLoaded = %d, want 0 (all sources failed)", stats.SourcesLoaded)
	}
	if stats.SourcesFailed != 1 {
		t.Errorf("SourcesFailed = %d, want 1", stats.SourcesFailed)
	}
	if !b.IsBlocked("previously-loaded.example") {
		t.Error("previous domain list must be kept intact when every source fails, but it was wiped")
	}
}

// TestUpdateLists_PartialSuccess_ReplacesOldDomains — контраст с тестом выше: если хотя бы
// один источник загрузился (loaded>0), список ЗАМЕНЯЕТСЯ новым (даже если новый не содержит
// прежних доменов) — частичный отказ не смешивает старые данные упавшего источника с новыми.
func TestUpdateLists_PartialSuccess_ReplacesOldDomains(t *testing.T) {
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("0.0.0.0 fresh.example\n"))
	}))
	defer okSrv.Close()
	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer failSrv.Close()

	origSources := DefaultSources
	DefaultSources = []BlocklistSource{
		{ID: "ok-src", Name: "OK", URL: okSrv.URL, Profile: ProfileLight, Format: "hosts"},
		{ID: "fail-src", Name: "Fail", URL: failSrv.URL, Profile: ProfileLight, Format: "hosts"},
	}
	defer func() { DefaultSources = origSources }()

	b := NewBlocker(nil)
	b.mu.Lock()
	b.profile = ProfileLight
	b.domains = map[string]bool{"stale.example": true}
	b.mu.Unlock()

	if err := b.UpdateLists(context.Background()); err != nil {
		t.Fatalf("UpdateLists: %v", err)
	}

	if b.IsBlocked("stale.example") {
		t.Error("stale domain from a fully-replaced list must not survive a partial-success update")
	}
	if !b.IsBlocked("fresh.example") {
		t.Error("freshly loaded domain must be present after a partial-success update")
	}
}
