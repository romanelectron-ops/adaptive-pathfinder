package sysproxy

import (
	"os"
	"path/filepath"
	"testing"
)

// withTempMarker swaps markerPathFn to a path under t.TempDir() — real marker.go doc
// comment explains why this matters: config.DataDir() on Windows is NOT redirectable by
// env vars, so without this seam these tests would touch the real %APPDATA%.
func withTempMarker(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sysproxy_active.marker")
	orig := markerPathFn
	markerPathFn = func() string { return path }
	t.Cleanup(func() { markerPathFn = orig })
	return path
}

func TestMarker_RoundTrip(t *testing.T) {
	withTempMarker(t)

	if _, _, ok := readMarker(); ok {
		t.Fatal("readMarker() ok=true before any write")
	}

	writeMarker("127.0.0.1", 10809)
	host, port, ok := readMarker()
	if !ok {
		t.Fatal("readMarker() ok=false after writeMarker")
	}
	if host != "127.0.0.1" || port != 10809 {
		t.Errorf("readMarker() = (%q, %d), want (127.0.0.1, 10809)", host, port)
	}

	clearMarker()
	if _, _, ok := readMarker(); ok {
		t.Error("readMarker() ok=true after clearMarker")
	}
}

func TestMarker_Overwrite(t *testing.T) {
	withTempMarker(t)

	writeMarker("127.0.0.1", 10809)
	writeMarker("127.0.0.1", 10810)
	host, port, ok := readMarker()
	if !ok || host != "127.0.0.1" || port != 10810 {
		t.Errorf("readMarker() = (%q, %d, %v), want (127.0.0.1, 10810, true) after overwrite", host, port, ok)
	}
}

func TestReadMarker_MalformedContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sysproxy_active.marker")
	orig := markerPathFn
	markerPathFn = func() string { return path }
	t.Cleanup(func() { markerPathFn = orig })

	cases := []string{"", "no-colon-here", "host:not-a-number", ":", "host:"}
	for _, content := range cases {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, _, ok := readMarker(); ok {
			t.Errorf("readMarker() ok=true for malformed content %q", content)
		}
	}
}

func TestClearMarker_MissingFileIsNotError(t *testing.T) {
	withTempMarker(t)
	// Не должно паниковать/падать, если файла и так нет.
	clearMarker()
	clearMarker()
}

// withTempOriginalMarker — тот же приём, что withTempMarker, для второго маркера (П1, аудит
// 2026-09-01, находка №14): "снимок настроек прокси до APF", отдельный файл от markerPathFn
// (см. doc-comment originalMarkerPathFn).
func withTempOriginalMarker(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sysproxy_original.marker")
	orig := originalMarkerPathFn
	originalMarkerPathFn = func() string { return path }
	t.Cleanup(func() { originalMarkerPathFn = orig })
	return path
}

func TestOriginalMarker_RoundTrip(t *testing.T) {
	withTempOriginalMarker(t)

	if _, _, ok := readOriginal(); ok {
		t.Fatal("readOriginal() ok=true before any write")
	}

	writeOriginalIfAbsent(true, "10.0.0.5:8080")
	enabled, server, ok := readOriginal()
	if !ok {
		t.Fatal("readOriginal() ok=false after writeOriginalIfAbsent")
	}
	if !enabled || server != "10.0.0.5:8080" {
		t.Errorf("readOriginal() = (%v, %q), want (true, \"10.0.0.5:8080\")", enabled, server)
	}

	clearOriginalMarker()
	if _, _, ok := readOriginal(); ok {
		t.Error("readOriginal() ok=true after clearOriginalMarker")
	}
}

func TestOriginalMarker_DoesNotOverwriteExisting(t *testing.T) {
	withTempOriginalMarker(t)

	writeOriginalIfAbsent(true, "10.0.0.5:8080") // «настоящий» снимок до APF
	writeOriginalIfAbsent(false, "127.0.0.1:1")  // повторный SetHTTPProxy — НЕ должен затереть

	enabled, server, ok := readOriginal()
	if !ok || !enabled || server != "10.0.0.5:8080" {
		t.Errorf("readOriginal() = (%v, %q, %v), want (true, \"10.0.0.5:8080\", true) — "+
			"второй writeOriginalIfAbsent затёр первый снимок", enabled, server, ok)
	}
}

func TestOriginalMarker_DisabledOriginal_EmptyServer(t *testing.T) {
	withTempOriginalMarker(t)

	writeOriginalIfAbsent(false, "")
	enabled, server, ok := readOriginal()
	if !ok || enabled || server != "" {
		t.Errorf("readOriginal() = (%v, %q, %v), want (false, \"\", true)", enabled, server, ok)
	}
}
