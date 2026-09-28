package singbox

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// в”Ђв”Ђв”Ђ helpers в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

func testPort(srv *httptest.Server) int {
	idx := strings.LastIndex(srv.URL, ":")
	port, _ := strconv.Atoi(srv.URL[idx+1:])
	return port
}

// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ
// traffic_monitor.go вЂ” poll success paths
// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ

func TestTrafficMonitorPollSuccess(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/connections", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(clashConnectionsResp{
			UploadTotal:   1000,
			DownloadTotal: 2000,
			Connections: []struct {
				ID string `json:"id"`
			}{{"c1"}, {"c2"}},
		})
	})
	mux.HandleFunc("/traffic", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(clashTrafficResp{Up: 512, Down: 1024})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tm := NewTrafficMonitor(testPort(srv))
	tm.poll()

	s := tm.GetStats()
	if s.UpBytes != 1000 {
		t.Errorf("UpBytes = %d, want 1000", s.UpBytes)
	}
	if s.DownBytes != 2000 {
		t.Errorf("DownBytes = %d, want 2000", s.DownBytes)
	}
	if s.UpSpeed != 512 {
		t.Errorf("UpSpeed = %d, want 512", s.UpSpeed)
	}
	if s.DownSpeed != 1024 {
		t.Errorf("DownSpeed = %d, want 1024", s.DownSpeed)
	}
	if s.Conns != 2 {
		t.Errorf("Conns = %d, want 2", s.Conns)
	}
	if s.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should not be zero after successful poll")
	}
}

func TestTrafficMonitorPollBadConnectionsJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not-valid-json"))
	}))
	defer srv.Close()

	var logs []string
	tm := NewTrafficMonitor(testPort(srv))
	tm.OnLog = func(s string) { logs = append(logs, s) }
	tm.poll()

	if len(logs) == 0 {
		t.Error("expected decode error to be logged")
	}
}

func TestTrafficMonitorPollNoTrafficEndpoint(t *testing.T) {
	// /connections works but /traffic returns 404 вЂ” should still update stats from connections
	mux := http.NewServeMux()
	mux.HandleFunc("/connections", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(clashConnectionsResp{
			UploadTotal:   500,
			DownloadTotal: 900,
		})
	})
	// /traffic not registered в†’ 404
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tm := NewTrafficMonitor(testPort(srv))
	tm.poll()

	s := tm.GetStats()
	if s.UpBytes != 500 {
		t.Errorf("UpBytes = %d, want 500", s.UpBytes)
	}
}

// TestTrafficMonitorPoll_CallsOnStats — StickySessionManager wiring (engine.go,
// wireTrafficMonitorStats) зависит от того, что OnStats действительно получает свежий
// TrafficStats после каждого успешного опроса, а не только обновляет tm.stats.
func TestTrafficMonitorPoll_CallsOnStats(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/connections", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(clashConnectionsResp{
			UploadTotal:   10,
			DownloadTotal: 20,
			Connections: []struct {
				ID string `json:"id"`
			}{{"c1"}},
		})
	})
	mux.HandleFunc("/traffic", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(clashTrafficResp{Up: 5, Down: 7})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tm := NewTrafficMonitor(testPort(srv))
	var got TrafficStats
	called := false
	tm.OnStats = func(st TrafficStats) {
		called = true
		got = st
	}
	tm.poll()

	if !called {
		t.Fatal("OnStats не вызван после успешного poll")
	}
	if got.Conns != 1 || got.UpSpeed != 5 || got.DownSpeed != 7 {
		t.Errorf("OnStats получил %+v, ожидалось Conns=1 UpSpeed=5 DownSpeed=7", got)
	}
}

// TestTrafficMonitorPoll_NilOnStats_NoPanic — OnStats не задан (обычный TrafficMonitor
// без wireTrafficMonitorStats, например тесты остального пакета singbox) — poll не должен
// падать на нулевом колбэке.
func TestTrafficMonitorPoll_NilOnStats_NoPanic(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/connections", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(clashConnectionsResp{})
	})
	mux.HandleFunc("/traffic", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(clashTrafficResp{})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tm := NewTrafficMonitor(testPort(srv))
	tm.poll() // OnStats == nil — не должно паниковать
}

// TestTrafficMonitorPoll_ErrorPath_DoesNotCallOnStats — на ошибке poll выходит ДО расчёта
// newStats (см. её тело) — OnStats не должен получить пустышку/устаревшие данные.
func TestTrafficMonitorPoll_ErrorPath_DoesNotCallOnStats(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not-valid-json"))
	}))
	defer srv.Close()

	tm := NewTrafficMonitor(testPort(srv))
	called := false
	tm.OnStats = func(TrafficStats) { called = true }
	tm.poll()

	if called {
		t.Error("OnStats не должен вызываться на ошибке разбора /connections")
	}
}

// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ
// process.go вЂ” Stop with cmd set but Process nil
// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ

func TestProcessStopWithCmdNilProcess(t *testing.T) {
	p := NewProcess("/tmp/bin", "/tmp/data")
	var stopLog []string
	p.OnLog = func(s string) { stopLog = append(stopLog, s) }

	p.mu.Lock()
	p.running = true
	p.cmd = &exec.Cmd{} // cmd is set, but cmd.Process is nil
	p.mu.Unlock()

	err := p.Stop()
	if err != nil {
		t.Errorf("Stop should return nil when cmd.Process is nil, got %v", err)
	}
	if p.IsRunning() {
		t.Error("should not be running after Stop")
	}
	// Should have logged "Stopping..." and "stopped"
	found := false
	for _, l := range stopLog {
		if strings.Contains(l, "sing-box stopped") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'sing-box stopped' log, got: %v", stopLog)
	}
}

// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ
// downloader.go вЂ” downloadFile
// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ

func TestDownloaderDownloadFileOK(t *testing.T) {
	content := []byte("hello archive content")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		w.Write(content)
	}))
	defer srv.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "output.bin")
	d := NewDownloader(dir)
	var progressPcts []int
	d.OnProgress = func(p int, m string) { progressPcts = append(progressPcts, p) }

	err := d.downloadFile(context.Background(), srv.URL, dest)
	if err != nil {
		t.Fatalf("downloadFile failed: %v", err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != string(content) {
		t.Errorf("content mismatch: got %q", string(got))
	}
	// Content-Length set в†’ progress should fire
	if len(progressPcts) == 0 {
		t.Error("expected at least one progress callback")
	}
}

func TestDownloaderDownloadFileHTTP404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	d := NewDownloader(t.TempDir())
	err := d.downloadFile(context.Background(), srv.URL, filepath.Join(t.TempDir(), "out"))
	if err == nil {
		t.Error("expected error for HTTP 404")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should mention 404: %v", err)
	}
}

func TestDownloaderDownloadFileContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled

	d := NewDownloader(t.TempDir())
	err := d.downloadFile(ctx, "http://127.0.0.1:19997/nonexistent", filepath.Join(t.TempDir(), "out"))
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ
// downloader.go вЂ” extractFromZip
// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ

func makeTestZip(t *testing.T, dir, entryName string, content []byte) string {
	t.Helper()
	zipPath := filepath.Join(dir, "test.zip")
	zf, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	w, err := zw.Create(entryName)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(content)
	zw.Close()
	zf.Close()
	return zipPath
}

func makeTestTarGz(t *testing.T, dir, entryName string, content []byte) string {
	t.Helper()
	archPath := filepath.Join(dir, "test.tar.gz")
	f, err := os.Create(archPath)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	tw.WriteHeader(&tar.Header{Name: entryName, Mode: 0755, Size: int64(len(content))})
	tw.Write(content)
	tw.Close()
	gw.Close()
	f.Close()
	return archPath
}

func TestDownloaderExtractFromZipOK(t *testing.T) {
	dir := t.TempDir()
	binName := "sing-box"
	if runtime.GOOS == "windows" {
		binName = "sing-box.exe"
	}
	content := []byte("fake-sing-box-binary")
	zipPath := makeTestZip(t, dir, "sing-box-1.9.4-windows-amd64/"+binName, content)

	dest := filepath.Join(dir, binName)
	d := NewDownloader(dir)
	if err := d.extractFromZip(zipPath, binName, dest); err != nil {
		t.Fatalf("extractFromZip failed: %v", err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != string(content) {
		t.Errorf("got %q, want %q", string(got), string(content))
	}
}

func TestDownloaderExtractFromZipNotFound(t *testing.T) {
	dir := t.TempDir()
	// zip has a different file name
	zipPath := makeTestZip(t, dir, "something/other-file", []byte("data"))

	d := NewDownloader(dir)
	err := d.extractFromZip(zipPath, "sing-box", filepath.Join(dir, "sing-box"))
	if err == nil {
		t.Error("expected error when binary not in zip")
	}
}

// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ
// downloader.go вЂ” extractFromTarGz
// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ

func TestDownloaderExtractFromTarGzOK(t *testing.T) {
	dir := t.TempDir()
	binName := "sing-box"
	content := []byte("fake-sing-box-binary-linux")
	archPath := makeTestTarGz(t, dir, "sing-box-1.9.4-linux-amd64/"+binName, content)

	dest := filepath.Join(dir, binName)
	d := NewDownloader(dir)
	if err := d.extractFromTarGz(archPath, binName, dest); err != nil {
		t.Fatalf("extractFromTarGz failed: %v", err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != string(content) {
		t.Errorf("got %q, want %q", string(got), string(content))
	}
}

func TestDownloaderExtractFromTarGzNotFound(t *testing.T) {
	dir := t.TempDir()
	archPath := makeTestTarGz(t, dir, "some/other-file", []byte("data"))

	d := NewDownloader(dir)
	err := d.extractFromTarGz(archPath, "sing-box", filepath.Join(dir, "sing-box"))
	if err == nil {
		t.Error("expected error when binary not in archive")
	}
}

func TestDownloaderExtractFromTarGzBadGzip(t *testing.T) {
	dir := t.TempDir()
	archPath := filepath.Join(dir, "bad.tar.gz")
	os.WriteFile(archPath, []byte("not-gzip-data"), 0600)

	d := NewDownloader(dir)
	err := d.extractFromTarGz(archPath, "sing-box", filepath.Join(dir, "sing-box"))
	if err == nil {
		t.Error("expected error for invalid gzip data")
	}
}

// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ
// downloader.go вЂ” extract routing
// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ

func TestDownloaderExtractRoutesZip(t *testing.T) {
	dir := t.TempDir()
	binName := "sing-box"
	if runtime.GOOS == "windows" {
		binName = "sing-box.exe"
	}
	content := []byte("binary-data")
	zipPath := makeTestZip(t, dir, "dir/"+binName, content)

	d := NewDownloader(dir)
	dest := filepath.Join(dir, binName)
	err := d.extract(zipPath, "archive.zip", binName, dest)
	if err != nil {
		t.Fatalf("extract .zip failed: %v", err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != string(content) {
		t.Errorf("content mismatch")
	}
}

func TestDownloaderExtractRoutesTarGz(t *testing.T) {
	dir := t.TempDir()
	binName := "sing-box"
	content := []byte("binary-data-linux")
	archPath := makeTestTarGz(t, dir, "dir/"+binName, content)

	d := NewDownloader(dir)
	dest := filepath.Join(dir, binName)
	err := d.extract(archPath, "archive.tar.gz", binName, dest)
	if err != nil {
		t.Fatalf("extract .tar.gz failed: %v", err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != string(content) {
		t.Errorf("content mismatch")
	}
}

// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ
// downloader.go вЂ” EnsureInstalled (fake binary, ctx cancelled)
// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ

func TestDownloaderEnsureInstalledNotFound(t *testing.T) {
	dir := t.TempDir() // empty dir вЂ” no binary

	d := NewDownloader(dir)
	var logs []string
	d.OnLog = func(s string) { logs = append(logs, s) }

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel so Download fails fast

	err := d.EnsureInstalled(ctx)
	// Download will fail (context cancelled or network error)
	// but we cover the "not found в†’ download" branch
	_ = err

	found := false
	for _, l := range logs {
		if strings.Contains(l, "not found") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'not found' log, got: %v", logs)
	}
}

func TestDownloaderEnsureInstalledFakeBinaryFallsToDownload(t *testing.T) {
	dir := t.TempDir()
	binName := "sing-box"
	if runtime.GOOS == "windows" {
		binName = "sing-box.exe"
	}
	// Write a stub binary (not a real sing-box, Version() will fail)
	os.WriteFile(filepath.Join(dir, binName), []byte("stub"), 0755)

	d := NewDownloader(dir)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := d.EnsureInstalled(ctx)
	// Version() fails on stub в†’ calls Download в†’ context error
	// We just check it doesn't panic
	_ = err
}
