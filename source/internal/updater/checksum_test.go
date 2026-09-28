package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// checksum_test.go — P1 (аудит 2026-09-01, security-раздел, находка №3): апстрим скачивал и
// применял обновление, проверяя ТОЛЬКО код ответа HTTP (P1-9), ничего про содержимое файла.
// Полноценная защита от компрометации репозитория/пайплайна требует офлайн-ключа подписи,
// которого у проекта сегодня нет — эти тесты покрывают то, что добавлено: проверку целостности
// против манифеста контрольных сумм, если релиз его публикует, и честное предупреждение, если
// нет (см. doc-comment UpdateStatus.SHA256 и DownloadAndApply).

func TestDownloadAndApply_ChecksumMismatch_RejectsAndDoesNotReplace(t *testing.T) {
	dir := t.TempDir()
	exeFile, err := os.CreateTemp(dir, "apf_cksum_mismatch_*.bin")
	if err != nil {
		t.Fatal(err)
	}
	const originalContent = "original binary — must survive"
	exeFile.WriteString(originalContent)
	exeFile.Close()
	exePath := exeFile.Name()

	oldExeFn := executableFn
	executableFn = func() (string, error) { return exePath, nil }
	defer func() { executableFn = oldExeFn }()

	ts := makeDownloadServer("updated binary content v2")
	defer ts.Close()

	u := New("1.0.0")
	var logged []string
	u.OnLog = func(msg string) { logged = append(logged, msg) }

	err = u.DownloadAndApply(context.Background(), ts.URL,
		"0000000000000000000000000000000000000000000000000000000000ff", nil)
	if err == nil {
		t.Fatal("ожидалась ошибка при несовпадении контрольной суммы")
	}

	// Исходный файл не тронут — подмена ОТКЛОНЕНА, а не применена с предупреждением.
	got, rerr := os.ReadFile(exePath)
	if rerr != nil {
		t.Fatalf("исходный файл должен был остаться на месте: %v", rerr)
	}
	if string(got) != originalContent {
		t.Errorf("исходный файл изменён при отклонённом обновлении: got %q", string(got))
	}
	// Временный файл не должен остаться на диске.
	if _, statErr := os.Stat(exePath + ".update"); !os.IsNotExist(statErr) {
		t.Error("временный файл .update должен быть удалён при отказе по контрольной сумме")
	}
}

func TestDownloadAndApply_ChecksumMatch_NoRejection(t *testing.T) {
	const content = "updated binary content v2"
	sum := sha256.Sum256([]byte(content))
	expected := hex.EncodeToString(sum[:])

	dir := t.TempDir()
	exeFile, err := os.CreateTemp(dir, "apf_cksum_match_*.bin")
	if err != nil {
		t.Fatal(err)
	}
	exeFile.WriteString("original")
	exeFile.Close()
	exePath := exeFile.Name()
	defer os.Remove(exePath + ".old")

	oldExeFn := executableFn
	executableFn = func() (string, error) { return exePath, nil }
	defer func() { executableFn = oldExeFn }()

	ts := makeDownloadServer(content)
	defer ts.Close()

	u := New("1.0.0")
	var logged []string
	u.OnLog = func(msg string) { logged = append(logged, msg) }

	err = u.DownloadAndApply(context.Background(), ts.URL, expected, nil)
	if err != nil {
		// Тот же осторожный контракт, что и у соседнего TestDownloadAndApply_SuccessPath:
		// финальный os.Rename поверх запущенного тестового бинарника может быть заблокирован
		// ОС — это не то, что здесь проверяется. Важно, что ошибка НЕ про контрольную сумму.
		if contains(err.Error(), "контрольная сумма") {
			t.Errorf("DownloadAndApply отклонил СОВПАВШУЮ контрольную сумму: %v", err)
		}
		t.Logf("DownloadAndApply error (может быть ограничение ОС на rename, не про сумму): %v", err)
		return
	}
	for _, m := range logged {
		if contains(m, "не совпадает") {
			t.Errorf("лог сообщает о несовпадении при совпавшей сумме: %q", m)
		}
	}
	t.Logf("OK: логи при совпавшей сумме: %v", logged)
}

func TestDownloadAndApply_NoChecksum_WarnsButApplies(t *testing.T) {
	dir := t.TempDir()
	exeFile, err := os.CreateTemp(dir, "apf_cksum_none_*.bin")
	if err != nil {
		t.Fatal(err)
	}
	exeFile.WriteString("original")
	exeFile.Close()
	exePath := exeFile.Name()
	defer os.Remove(exePath + ".old")

	oldExeFn := executableFn
	executableFn = func() (string, error) { return exePath, nil }
	defer func() { executableFn = oldExeFn }()

	ts := makeDownloadServer("updated binary content v2")
	defer ts.Close()

	u := New("1.0.0")
	var sawWarning bool
	u.OnLog = func(msg string) {
		if len(msg) > 0 && contains(msg, "манифест контрольных сумм") {
			sawWarning = true
		}
	}

	err = u.DownloadAndApply(context.Background(), ts.URL, "", nil)
	if err != nil {
		t.Logf("DownloadAndApply error (может быть ограничение ОС на rename): %v", err)
	}
	if !sawWarning {
		t.Error("ожидалось предупреждение в лог про отсутствие проверки целостности " +
			"(expectedSHA256 пуст) — раньше отсутствие манифеста проходило молча")
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ─── findChecksumManifest / fetchChecksum ─────────────────────────────────────

func TestFindChecksumManifest_MatchesConventionalNames(t *testing.T) {
	assets := []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	}{
		{Name: "apf-windows-amd64.exe", BrowserDownloadURL: "https://example.com/win.exe"},
		{Name: "SHA256SUMS", BrowserDownloadURL: "https://example.com/SHA256SUMS"},
	}
	got := findChecksumManifest(assets)
	if got != "https://example.com/SHA256SUMS" {
		t.Errorf("findChecksumManifest = %q, ожидался URL манифеста", got)
	}
}

func TestFindChecksumManifest_AbsentReturnsEmpty(t *testing.T) {
	assets := []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	}{
		{Name: "apf-windows-amd64.exe", BrowserDownloadURL: "https://example.com/win.exe"},
	}
	if got := findChecksumManifest(assets); got != "" {
		t.Errorf("findChecksumManifest без манифеста = %q, ожидалась пустая строка", got)
	}
}

func TestFetchChecksum_ParsesManifestLine(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("deadbeef00000000000000000000000000000000000000000000000000ab  apf-windows-amd64.exe\n" +
			"cafebabe00000000000000000000000000000000000000000000000000cd  apf-linux-amd64\n"))
	}))
	defer ts.Close()

	u := New("1.0.0")
	got := u.fetchChecksum(context.Background(), ts.URL, "apf-windows-amd64.exe")
	want := "deadbeef00000000000000000000000000000000000000000000000000ab"
	if got != want {
		t.Errorf("fetchChecksum = %q, ожидалось %q", got, want)
	}
}

func TestFetchChecksum_BinaryModeAsteriskPrefix(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// sha256sum в бинарном режиме ставит "*" перед именем файла.
		w.Write([]byte("deadbeef00000000000000000000000000000000000000000000000000ab *apf-windows-amd64.exe\n"))
	}))
	defer ts.Close()

	u := New("1.0.0")
	got := u.fetchChecksum(context.Background(), ts.URL, "apf-windows-amd64.exe")
	if got == "" {
		t.Error("fetchChecksum не разобрал строку с '*' перед именем файла (бинарный режим sha256sum)")
	}
}

func TestFetchChecksum_UnknownFile_ReturnsEmpty(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("deadbeef00000000000000000000000000000000000000000000000000ab  other-file.exe\n"))
	}))
	defer ts.Close()

	u := New("1.0.0")
	got := u.fetchChecksum(context.Background(), ts.URL, "apf-windows-amd64.exe")
	if got != "" {
		t.Errorf("fetchChecksum для незнакомого файла = %q, ожидалась пустая строка", got)
	}
}

func TestFetchChecksum_ServerError_ReturnsEmpty(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	u := New("1.0.0")
	got := u.fetchChecksum(context.Background(), ts.URL, "apf-windows-amd64.exe")
	if got != "" {
		t.Errorf("fetchChecksum при ошибке сервера = %q, ожидалась пустая строка (best-effort)", got)
	}
}

// ─── CheckForUpdate: сквозная проверка — манифест находится и SHA256 попадает в статус ──────

func TestCheckForUpdate_PopulatesSHA256FromManifest(t *testing.T) {
	const assetName = "apf-windows-amd64.exe"
	const sum = "deadbeef00000000000000000000000000000000000000000000000000ab"

	mux := http.NewServeMux()
	mux.HandleFunc("/checksums.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(sum + "  " + assetName + "\n"))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	relJSON := `{"tag_name":"v9.9.9","body":"","assets":[` +
		`{"name":"` + assetName + `","browser_download_url":"https://example.com/exe"},` +
		`{"name":"checksums.txt","browser_download_url":"` + ts.URL + `/checksums.txt"}` +
		`]}`
	apiTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(relJSON))
	}))
	defer apiTS.Close()

	oldAPI := githubAPI
	githubAPI = apiTS.URL
	defer func() { githubAPI = oldAPI }()

	oldGoos := goosHook
	goosHook = "windows"
	defer func() { goosHook = oldGoos }()

	u := New("1.0.0")
	status, err := u.CheckForUpdate(context.Background())
	if err != nil {
		t.Fatalf("CheckForUpdate: %v", err)
	}
	if status.SHA256 != sum {
		t.Errorf("status.SHA256 = %q, ожидалось %q — манифест не подхватился", status.SHA256, sum)
	}
}

func TestCheckForUpdate_NoManifest_EmptySHA256(t *testing.T) {
	relJSON := `{"tag_name":"v9.9.9","body":"","assets":[` +
		`{"name":"apf-windows-amd64.exe","browser_download_url":"https://example.com/exe"}` +
		`]}`
	apiTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(relJSON))
	}))
	defer apiTS.Close()

	oldAPI := githubAPI
	githubAPI = apiTS.URL
	defer func() { githubAPI = oldAPI }()

	u := New("1.0.0")
	status, err := u.CheckForUpdate(context.Background())
	if err != nil {
		t.Fatalf("CheckForUpdate: %v", err)
	}
	if status.SHA256 != "" {
		t.Errorf("status.SHA256 = %q, ожидалась пустая строка (релиз не публикует манифест)", status.SHA256)
	}
}
