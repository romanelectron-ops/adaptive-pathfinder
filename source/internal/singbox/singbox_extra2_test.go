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
	"path/filepath"
	"testing"
	"time"
)

// ─── extractFromZip: os.Create error ────────────────────────────────────────

// TestDownloader_ExtractFromZip_CreateError covers downloader.go line 176
// (os.Create error when dest directory doesn't exist).
func TestDownloader_ExtractFromZip_CreateError(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "test.zip")

	// Build a valid zip containing "sing-box.exe"
	func() {
		f, err := os.Create(zipPath)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		zw := zip.NewWriter(f)
		defer zw.Close()
		w, err := zw.Create("sing-box.exe")
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte("fake binary content"))
	}()

	d := NewDownloader(dir)
	// Dest path inside a non-existent subdirectory → os.Create fails
	badDest := filepath.Join(dir, "nosuchdir", "sing-box.exe")
	err := d.extractFromZip(zipPath, "sing-box.exe", badDest)
	if err == nil {
		t.Error("expected error from os.Create with missing parent dir, got nil")
	}
}

// ─── extractFromTarGz: os.Open error ────────────────────────────────────────

// TestDownloader_ExtractFromTarGz_OpenError covers downloader.go line 189
// (os.Open error when src file doesn't exist).
func TestDownloader_ExtractFromTarGz_OpenError(t *testing.T) {
	d := NewDownloader(t.TempDir())
	err := d.extractFromTarGz("/nonexistent/path/archive.tar.gz", "sing-box", "/tmp/dest")
	if err == nil {
		t.Error("expected error from os.Open for nonexistent archive, got nil")
	}
}

// ─── extractFromTarGz: os.Create error ──────────────────────────────────────

// TestDownloader_ExtractFromTarGz_CreateError covers downloader.go line 214
// (os.Create error when dest directory doesn't exist).
func TestDownloader_ExtractFromTarGz_CreateError(t *testing.T) {
	dir := t.TempDir()
	tgzPath := filepath.Join(dir, "test.tar.gz")

	// Build a valid tar.gz containing "sing-box"
	func() {
		f, err := os.Create(tgzPath)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		gw := gzip.NewWriter(f)
		tw := tar.NewWriter(gw)

		content := []byte("fake binary content")
		hdr := &tar.Header{
			Name: "sing-box",
			Mode: 0755,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		tw.Write(content)
		tw.Close()
		gw.Close()
	}()

	d := NewDownloader(dir)
	// Dest path inside a non-existent subdirectory → os.Create fails
	badDest := filepath.Join(dir, "nosuchdir", "sing-box")
	err := d.extractFromTarGz(tgzPath, "sing-box", badDest)
	if err == nil {
		t.Error("expected error from os.Create with missing parent dir, got nil")
	}
}

// ─── TrafficMonitor: ticker.C branch ─────────────────────────────────────────

// TestTrafficMonitor_TickerPoll covers traffic_monitor.go line 102-103
// (case <-ticker.C: tm.poll()).  The ticker fires every 2 s; we wait 2.5 s.
//
// Run with -short to skip the 2.5-second sleep:
//
//	go test ./internal/singbox/... -short
func TestTrafficMonitor_TickerPoll(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ticker poll test in -short mode")
	}

	// Mock HTTP server that handles /connections and /traffic
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/connections":
			json.NewEncoder(w).Encode(clashConnectionsResp{
				DownloadTotal: 1024,
				UploadTotal:   512,
				Connections: []struct {
					ID string `json:"id"`
				}{{ID: "conn1"}},
			})
		case "/traffic":
			json.NewEncoder(w).Encode(clashTrafficResp{Up: 10, Down: 20})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// We override baseURL directly (unexported field, accessible in package singbox)
	// so that poll() hits our mock server instead of a real sing-box process.
	tm := NewTrafficMonitor(0)
	tm.baseURL = srv.URL // override so poll() hits our mock server

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tm.Start(ctx)

	// Wait for at least one tick (defaultPollInterval = 2s) plus a safety margin.
	time.Sleep(2*time.Second + 500*time.Millisecond)

	stats := tm.GetStats()
	if stats.DownBytes != 1024 {
		t.Errorf("DownBytes: want 1024, got %d", stats.DownBytes)
	}
	if stats.UpBytes != 512 {
		t.Errorf("UpBytes: want 512, got %d", stats.UpBytes)
	}
	if stats.Conns != 1 {
		t.Errorf("Conns: want 1, got %d", stats.Conns)
	}
}
