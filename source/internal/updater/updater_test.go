package updater

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ─── New ─────────────────────────────────────────────────────────────────────

func TestNew_ReturnsNonNil(t *testing.T) {
	u := New("1.0.5")
	if u == nil {
		t.Fatal("New() returned nil")
	}
}

func TestNew_TrimsV(t *testing.T) {
	u := New("v1.2.3")
	if u.currentVersion != "1.2.3" {
		t.Errorf("expected currentVersion=1.2.3, got %s", u.currentVersion)
	}
}

func TestNew_NoV(t *testing.T) {
	u := New("2.0.0")
	if u.currentVersion != "2.0.0" {
		t.Errorf("expected currentVersion=2.0.0, got %s", u.currentVersion)
	}
}

func TestNew_EmptyVersion(t *testing.T) {
	u := New("")
	if u == nil {
		t.Fatal("New() returned nil")
	}
}

// ─── GetLastStatus ────────────────────────────────────────────────────────────

func TestGetLastStatus_Default(t *testing.T) {
	u := New("1.0.0")
	s := u.GetLastStatus()
	if s == nil {
		t.Fatal("GetLastStatus returned nil")
	}
	if s.CurrentVersion != "1.0.0" {
		t.Errorf("expected CurrentVersion=1.0.0, got %s", s.CurrentVersion)
	}
	if s.UpdateAvailable {
		t.Error("default status should not have UpdateAvailable=true")
	}
}

func TestGetLastStatus_AfterSet(t *testing.T) {
	u := New("1.0.0")
	u.mu.Lock()
	u.lastStatus = &UpdateStatus{
		CurrentVersion:  "1.0.0",
		LatestVersion:   "1.1.0",
		UpdateAvailable: true,
	}
	u.mu.Unlock()

	s := u.GetLastStatus()
	if s.LatestVersion != "1.1.0" {
		t.Errorf("expected LatestVersion=1.1.0, got %s", s.LatestVersion)
	}
	if !s.UpdateAvailable {
		t.Error("expected UpdateAvailable=true")
	}
}

// ─── CheckForUpdate — мок-сервер ─────────────────────────────────────────────

func mockGitHubServer(tagName, body string, statusCode int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if statusCode != http.StatusOK {
			w.WriteHeader(statusCode)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		rel := githubRelease{
			TagName: tagName,
			Body:    body,
			Assets: []struct {
				Name               string `json:"name"`
				BrowserDownloadURL string `json:"browser_download_url"`
			}{
				{Name: "apf-windows.exe", BrowserDownloadURL: "https://example.com/apf.exe"},
				{Name: "apf-linux-amd64", BrowserDownloadURL: "https://example.com/apf-linux"},
			},
		}
		json.NewEncoder(w).Encode(rel)
	}))
}

func TestCheckForUpdate_UpdateAvailable(t *testing.T) {
	ts := mockGitHubServer("v2.0.0", "## Release notes", http.StatusOK)
	defer ts.Close()

	old := githubAPI
	githubAPI = ts.URL
	defer func() { githubAPI = old }()

	u := New("1.0.0")
	var notified bool
	u.OnUpdateAvailable = func(s *UpdateStatus) { notified = true }
	var logged string
	u.OnLog = func(msg string) { logged = msg }

	status, err := u.CheckForUpdate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !status.UpdateAvailable {
		t.Error("expected UpdateAvailable=true")
	}
	if status.LatestVersion != "2.0.0" {
		t.Errorf("expected LatestVersion=2.0.0, got %s", status.LatestVersion)
	}
	if !notified {
		t.Error("OnUpdateAvailable callback was not called")
	}
	if logged == "" {
		t.Error("OnLog callback was not called")
	}
	if status.DownloadURL == "" {
		t.Error("expected non-empty DownloadURL")
	}
}

func TestCheckForUpdate_NoUpdate(t *testing.T) {
	ts := mockGitHubServer("v1.0.0", "", http.StatusOK)
	defer ts.Close()

	old := githubAPI
	githubAPI = ts.URL
	defer func() { githubAPI = old }()

	u := New("1.0.0")
	status, err := u.CheckForUpdate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.UpdateAvailable {
		t.Error("expected UpdateAvailable=false (same version)")
	}
}

func TestCheckForUpdate_ServerError(t *testing.T) {
	ts := mockGitHubServer("", "", http.StatusInternalServerError)
	defer ts.Close()

	old := githubAPI
	githubAPI = ts.URL
	defer func() { githubAPI = old }()

	u := New("1.0.0")
	_, err := u.CheckForUpdate(context.Background())
	if err == nil {
		t.Error("expected error for server 500")
	}
}

func TestCheckForUpdate_CtxCancelled(t *testing.T) {
	u := New("1.0.0")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := u.CheckForUpdate(ctx)
	if err == nil {
		t.Error("expected error with cancelled context")
	}
}

func TestCheckForUpdate_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not-json!!!"))
	}))
	defer ts.Close()

	old := githubAPI
	githubAPI = ts.URL
	defer func() { githubAPI = old }()

	u := New("1.0.0")
	_, err := u.CheckForUpdate(context.Background())
	if err == nil {
		t.Error("expected JSON decode error")
	}
}

// ─── DownloadAndApply ─────────────────────────────────────────────────────────

func TestDownloadAndApply_EmptyURL(t *testing.T) {
	u := New("1.0.0")
	err := u.DownloadAndApply(context.Background(), "", "", nil)
	if err == nil {
		t.Error("expected error for empty download URL")
	}
}

func TestDownloadAndApply_CtxCancelled(t *testing.T) {
	u := New("1.0.0")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := u.DownloadAndApply(ctx, "https://1.2.3.4:9999/fail", "", nil)
	if err == nil {
		t.Error("expected error with cancelled context")
	}
}

func TestDownloadAndApply_DownloadData(t *testing.T) {
	// Мок-сервер возвращает бинарные данные
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := []byte("fake binary data for apf update")
		w.Header().Set("Content-Length", "31")
		w.Write(data)
	}))
	defer ts.Close()

	u := New("1.0.0")
	var progress int
	err := u.DownloadAndApply(context.Background(), ts.URL, "", func(pct int) {
		progress = pct
	})
	// Ожидаем ошибку на стадии rename (нельзя переименовать запущенный бинарник),
	// но при этом код скачивания и записи файла должен выполниться
	t.Logf("DownloadAndApply result: %v, progress=%d", err, progress)
	// Главное — не должно быть паники
}

// ─── compareVersions ──────────────────────────────────────────────────────────

func TestCompareVersions_Equal(t *testing.T) {
	if compareVersions("1.0.0", "1.0.0") != 0 {
		t.Error("equal versions should return 0")
	}
}

func TestCompareVersions_PatchLess(t *testing.T) {
	if compareVersions("1.0.0", "1.0.1") != -1 {
		t.Errorf("1.0.0 < 1.0.1 should return -1")
	}
}

func TestCompareVersions_PatchGreater(t *testing.T) {
	if compareVersions("1.0.2", "1.0.1") != 1 {
		t.Errorf("1.0.2 > 1.0.1 should return 1")
	}
}

func TestCompareVersions_MinorLess(t *testing.T) {
	if compareVersions("1.0.5", "1.1.0") != -1 {
		t.Errorf("1.0.5 < 1.1.0 should return -1")
	}
}

func TestCompareVersions_MajorGreater(t *testing.T) {
	if compareVersions("2.0.0", "1.9.9") != 1 {
		t.Errorf("2.0.0 > 1.9.9 should return 1")
	}
}

func TestCompareVersions_MajorLess(t *testing.T) {
	if compareVersions("1.5.0", "2.0.0") != -1 {
		t.Errorf("1.5.0 < 2.0.0 should return -1")
	}
}

// ─── parseVer ─────────────────────────────────────────────────────────────────

func TestParseVer_Simple(t *testing.T) {
	got := parseVer("1.2.3")
	if got != [3]int{1, 2, 3} {
		t.Errorf("expected [1 2 3], got %v", got)
	}
}

func TestParseVer_WithV(t *testing.T) {
	got := parseVer("v2.10.0")
	if got != [3]int{2, 10, 0} {
		t.Errorf("expected [2 10 0], got %v", got)
	}
}

func TestParseVer_PatchOnly(t *testing.T) {
	got := parseVer("0.0.7")
	if got != [3]int{0, 0, 7} {
		t.Errorf("expected [0 0 7], got %v", got)
	}
}

func TestParseVer_Empty(t *testing.T) {
	got := parseVer("")
	if got != [3]int{0, 0, 0} {
		t.Errorf("expected [0 0 0], got %v", got)
	}
}

// ─── pickAsset ────────────────────────────────────────────────────────────────

type assetEntry = struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

func TestPickAsset_Nil(t *testing.T) {
	if pickAsset(nil) != "" {
		t.Error("expected empty for nil assets")
	}
}

func TestPickAsset_Empty(t *testing.T) {
	if pickAsset([]assetEntry{}) != "" {
		t.Error("expected empty for empty assets")
	}
}

func TestPickAsset_FallbackFirst(t *testing.T) {
	assets := []assetEntry{
		{Name: "apf-unknown-platform", BrowserDownloadURL: "https://example.com/unknown"},
	}
	got := pickAsset(assets)
	if got == "" {
		t.Error("expected non-empty URL (fallback to first)")
	}
}

func TestPickAsset_MultiPlatform(t *testing.T) {
	assets := []assetEntry{
		{Name: "apf-linux-amd64", BrowserDownloadURL: "https://example.com/linux"},
		{Name: "apf-windows-amd64.exe", BrowserDownloadURL: "https://example.com/win.exe"},
		{Name: "apf-darwin-arm64", BrowserDownloadURL: "https://example.com/mac"},
	}
	got := pickAsset(assets)
	if got == "" {
		t.Error("expected non-empty download URL")
	}
}

// ─── StartAutoCheck ───────────────────────────────────────────────────────────

func TestStartAutoCheck_NoPanic(t *testing.T) {
	u := New("1.0.0")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	u.StartAutoCheck(ctx)
}
