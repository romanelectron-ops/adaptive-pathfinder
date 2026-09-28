package singbox

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ
// format.go вЂ” FormatSpeed, FormatBytes
// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ

func TestFormatSpeed(t *testing.T) {
	cases := []struct {
		input int64
		want  string
	}{
		{0, "0 B/s"},
		{512, "512 B/s"},
		{1023, "1023 B/s"},
		{1 << 10, "1.0 KB/s"},
		{int64(1.5 * float64(1<<10)), "1.5 KB/s"},
		{1 << 20, "1.0 MB/s"},
		{int64(1.5 * float64(1<<20)), "1.5 MB/s"},
		{1 << 30, "1.0 GB/s"},
		{int64(2.0 * float64(1<<30)), "2.0 GB/s"},
	}
	for _, c := range cases {
		got := FormatSpeed(c.input)
		if got != c.want {
			t.Errorf("FormatSpeed(%d) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	cases := []struct {
		input int64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1 << 10, "1.0 KB"},
		{int64(1.5 * float64(1<<10)), "1.5 KB"},
		{1 << 20, "1.0 MB"},
		{int64(1.5 * float64(1<<20)), "1.5 MB"},
		{1 << 30, "1.00 GB"},
		{int64(2.5 * float64(1<<30)), "2.50 GB"},
	}
	for _, c := range cases {
		got := FormatBytes(c.input)
		if got != c.want {
			t.Errorf("FormatBytes(%d) = %q, want %q", c.input, got, c.want)
		}
	}
}

// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ
// traffic_monitor.go
// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ

func TestNewTrafficMonitor(t *testing.T) {
	tm := NewTrafficMonitor(9092)
	if tm.port != 9092 {
		t.Errorf("port = %d, want 9092", tm.port)
	}
	if tm.baseURL != "http://127.0.0.1:9092" {
		t.Errorf("baseURL = %q, want http://127.0.0.1:9092", tm.baseURL)
	}
	if tm.running {
		t.Error("should not be running initially")
	}
	if tm.stopCh == nil {
		t.Error("stopCh must be initialised")
	}
}

func TestTrafficMonitorGetStatsInitial(t *testing.T) {
	tm := NewTrafficMonitor(9092)
	s := tm.GetStats()
	if s.UpBytes != 0 || s.DownBytes != 0 || s.Conns != 0 || s.UpSpeed != 0 || s.DownSpeed != 0 {
		t.Errorf("initial stats should be zero: %+v", s)
	}
}

func TestTrafficMonitorReset(t *testing.T) {
	tm := NewTrafficMonitor(9092)
	tm.mu.Lock()
	tm.stats = TrafficStats{UpBytes: 100, DownBytes: 200, Conns: 5, UpSpeed: 1024}
	tm.mu.Unlock()

	tm.Reset()

	s := tm.GetStats()
	if s.UpBytes != 0 || s.DownBytes != 0 || s.Conns != 0 || s.UpSpeed != 0 {
		t.Errorf("stats should be zero after Reset, got %+v", s)
	}
}

func TestTrafficMonitorStartStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tm := NewTrafficMonitor(19991)
	tm.Start(ctx)
	time.Sleep(30 * time.Millisecond)

	tm.mu.RLock()
	running := tm.running
	tm.mu.RUnlock()
	if !running {
		t.Error("should be running after Start")
	}

	tm.Stop()
	time.Sleep(60 * time.Millisecond)

	tm.mu.RLock()
	running = tm.running
	tm.mu.RUnlock()
	if running {
		t.Error("should not be running after Stop")
	}
}

func TestTrafficMonitorStartIdempotent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tm := NewTrafficMonitor(19992)
	tm.Start(ctx)
	tm.Start(ctx) // second call: must be no-op, must not panic

	time.Sleep(30 * time.Millisecond)
	tm.mu.RLock()
	running := tm.running
	tm.mu.RUnlock()
	if !running {
		t.Error("should still be running after double Start")
	}
}

func TestTrafficMonitorContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tm := NewTrafficMonitor(19993)
	tm.Start(ctx)
	time.Sleep(20 * time.Millisecond)

	cancel()
	time.Sleep(60 * time.Millisecond)

	tm.mu.RLock()
	running := tm.running
	tm.mu.RUnlock()
	if running {
		t.Error("should not be running after context cancel")
	}
}

func TestTrafficMonitorPollLogsOnError(t *testing.T) {
	tm := NewTrafficMonitor(19994) // no server, must log error
	var logs []string
	tm.OnLog = func(s string) { logs = append(logs, s) }
	tm.poll() // synchronous call вЂ” OnLog called synchronously
	if len(logs) == 0 {
		t.Error("expected at least one log from failed poll")
	}
}

func TestTrafficMonitorStopNotRunning(t *testing.T) {
	tm := NewTrafficMonitor(9092)
	// Must not panic when Stop is called without Start
	tm.Stop()
}

// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ
// process.go вЂ” Process struct
// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ

func TestNewProcess(t *testing.T) {
	p := NewProcess("/bin/dir", "/data/dir")
	if !strings.Contains(p.binPath, "sing-box") {
		t.Errorf("binPath %q should contain 'sing-box'", p.binPath)
	}
	if runtime.GOOS == "windows" && !strings.HasSuffix(p.binPath, ".exe") {
		t.Errorf("binPath on Windows must end with .exe: %q", p.binPath)
	}
	if runtime.GOOS != "windows" && strings.HasSuffix(p.binPath, ".exe") {
		t.Errorf("binPath on non-Windows must not end with .exe: %q", p.binPath)
	}
	if !strings.HasSuffix(p.configPath, "current.json") {
		t.Errorf("configPath %q should end with 'current.json'", p.configPath)
	}
	if p.logCh == nil {
		t.Error("logCh must be initialised")
	}
}

func TestProcessIsInstalledFalse(t *testing.T) {
	p := NewProcess("/nonexistent/path/xyz9999", "/tmp")
	if p.IsInstalled() {
		t.Error("IsInstalled should be false for missing binary")
	}
}

func TestProcessIsInstalledTrue(t *testing.T) {
	dir := t.TempDir()
	binName := "sing-box"
	if runtime.GOOS == "windows" {
		binName = "sing-box.exe"
	}
	if err := os.WriteFile(filepath.Join(dir, binName), []byte("stub"), 0755); err != nil {
		t.Fatal(err)
	}
	p := NewProcess(dir, dir)
	if !p.IsInstalled() {
		t.Error("IsInstalled should be true when binary file exists")
	}
}

func TestProcessIsRunningInitial(t *testing.T) {
	p := NewProcess("/tmp/bin", "/tmp/data")
	if p.IsRunning() {
		t.Error("IsRunning should be false before Start")
	}
}

func TestProcessLogNilCallback(t *testing.T) {
	p := NewProcess("/tmp/bin", "/tmp/data")
	// Must not panic when OnLog is nil
	p.log("test message")
}

func TestProcessLogCallback(t *testing.T) {
	var received string
	p := NewProcess("/tmp/bin", "/tmp/data")
	p.OnLog = func(s string) { received = s }
	p.log("hello logger")
	if received != "hello logger" {
		t.Errorf("OnLog got %q, want %q", received, "hello logger")
	}
}

func TestProcessStopIdle(t *testing.T) {
	p := NewProcess("/tmp/bin", "/tmp/data")
	if err := p.Stop(); err != nil {
		t.Errorf("Stop on idle process should return nil, got %v", err)
	}
}

func TestBuildDownloadURL(t *testing.T) {
	url := buildDownloadURL("1.9.4")
	if !strings.HasPrefix(url, "https://github.com/SagerNet/sing-box/releases") {
		t.Errorf("URL has wrong base: %q", url)
	}
	if !strings.Contains(url, "1.9.4") {
		t.Errorf("URL should contain version string: %q", url)
	}
	if runtime.GOOS == "windows" {
		if !strings.HasSuffix(url, ".zip") {
			t.Errorf("Windows URL should end with .zip: %q", url)
		}
	} else {
		if !strings.HasSuffix(url, ".tar.gz") {
			t.Errorf("non-Windows URL should end with .tar.gz: %q", url)
		}
	}
}

func TestBuildDownloadURLContainsSingBox(t *testing.T) {
	url := buildDownloadURL("2.0.0")
	if !strings.Contains(url, "sing-box") {
		t.Errorf("URL should contain 'sing-box': %q", url)
	}
}

func TestProcessWriteConfig(t *testing.T) {
	dir := t.TempDir()
	p := NewProcess(dir, dir)
	cfg := &Config{}
	if err := p.WriteConfig(cfg); err != nil {
		t.Fatalf("WriteConfig failed: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "current.json"))
	if err != nil {
		t.Fatalf("config file not written: %v", err)
	}
	if len(data) == 0 {
		t.Error("written config must not be empty")
	}
}

// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ
// process.go вЂ” logWriter helper
// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ

func TestLogWriterLines(t *testing.T) {
	var lines []string
	lw := &logWriter{
		prefix: "[pfx] ",
		fn:     func(s string) { lines = append(lines, s) },
	}
	lw.Write([]byte("line1\nline2\n"))
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %v", len(lines), lines)
	}
	if lines[0] != "[pfx] line1" {
		t.Errorf("lines[0] = %q", lines[0])
	}
	if lines[1] != "[pfx] line2" {
		t.Errorf("lines[1] = %q", lines[1])
	}
}

func TestLogWriterSkipsBlankLines(t *testing.T) {
	var lines []string
	lw := &logWriter{
		prefix: "[pfx] ",
		fn:     func(s string) { lines = append(lines, s) },
	}
	lw.Write([]byte("hello\n   \nworld\n"))
	if len(lines) != 2 {
		t.Errorf("expected 2 non-blank lines, got %d: %v", len(lines), lines)
	}
}

func TestLogWriterNilFn(t *testing.T) {
	lw := &logWriter{prefix: "[pfx] "}
	// Must not panic when fn is nil
	lw.Write([]byte("line\n"))
}

func TestLogWriterPartialLine(t *testing.T) {
	var lines []string
	lw := &logWriter{fn: func(s string) { lines = append(lines, s) }}
	lw.Write([]byte("part"))  // no newline вЂ” should buffer
	lw.Write([]byte("ial\n")) // flushes buffer
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	if lines[0] != "partial" {
		t.Errorf("got %q", lines[0])
	}
}

// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ
// process.go вЂ” progressReader helper
// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ

func TestProgressReader(t *testing.T) {
	var total int64
	calls := 0
	pr := &progressReader{
		r:     strings.NewReader("hello world"),
		total: 11,
		onProgress: func(n int64) {
			total += n
			calls++
		},
	}
	buf := make([]byte, 5)
	n, err := pr.Read(buf)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if n != 5 {
		t.Errorf("read %d bytes, want 5", n)
	}
	if total != 5 {
		t.Errorf("progress total = %d, want 5", total)
	}
	if calls != 1 {
		t.Errorf("progress calls = %d, want 1", calls)
	}
}

// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ
// downloader.go
// в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђ

func TestNewDownloader(t *testing.T) {
	d := NewDownloader("/tmp/bins")
	if d.Version != SingBoxVersion {
		t.Errorf("Version = %q, want %q", d.Version, SingBoxVersion)
	}
	if d.BinDir != "/tmp/bins" {
		t.Errorf("BinDir = %q, want /tmp/bins", d.BinDir)
	}
	if d.OnProgress != nil {
		t.Error("OnProgress should be nil by default")
	}
	if d.OnLog != nil {
		t.Error("OnLog should be nil by default")
	}
}

func TestDownloaderLogNilCallback(t *testing.T) {
	d := NewDownloader("/tmp/bins")
	d.log("test") // must not panic
}

func TestDownloaderLogCallback(t *testing.T) {
	var received string
	d := NewDownloader("/tmp/bins")
	d.OnLog = func(s string) { received = s }
	d.log("hello downloader")
	if received != "hello downloader" {
		t.Errorf("OnLog got %q", received)
	}
}

func TestDownloaderProgressNilCallback(t *testing.T) {
	d := NewDownloader("/tmp/bins")
	d.progress(50, "halfway") // must not panic
}

func TestDownloaderProgressCallback(t *testing.T) {
	var pct int
	var msg string
	d := NewDownloader("/tmp/bins")
	d.OnProgress = func(p int, m string) { pct = p; msg = m }
	d.progress(75, "extracting")
	if pct != 75 {
		t.Errorf("pct = %d, want 75", pct)
	}
	if msg != "extracting" {
		t.Errorf("msg = %q, want extracting", msg)
	}
}

func TestDownloaderBuildURL(t *testing.T) {
	d := NewDownloader("/tmp/bins")
	d.Version = "1.9.4"
	url, archiveName := d.buildURL()

	if !strings.HasPrefix(url, "https://github.com/SagerNet/sing-box/releases") {
		t.Errorf("URL has wrong base: %q", url)
	}
	if !strings.Contains(url, "1.9.4") {
		t.Errorf("URL should contain version: %q", url)
	}
	if !strings.Contains(archiveName, "sing-box") {
		t.Errorf("archiveName should contain 'sing-box': %q", archiveName)
	}
	if runtime.GOOS == "windows" {
		if !strings.HasSuffix(archiveName, ".zip") {
			t.Errorf("Windows archiveName must end with .zip: %q", archiveName)
		}
	} else {
		if !strings.HasSuffix(archiveName, ".tar.gz") {
			t.Errorf("non-Windows archiveName must end with .tar.gz: %q", archiveName)
		}
	}
}

func TestDownloaderBuildURLMatchesProcess(t *testing.T) {
	// buildURL on Downloader and buildDownloadURL on Process must agree on format
	d := NewDownloader("/tmp/bins")
	d.Version = SingBoxVersion
	du, _ := d.buildURL()
	pu := buildDownloadURL(SingBoxVersion)
	if du != pu {
		t.Errorf("Downloader URL %q != Process URL %q", du, pu)
	}
}
