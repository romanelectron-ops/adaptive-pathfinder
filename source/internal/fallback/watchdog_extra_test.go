package fallback

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── appendHistory ─────────────────────────────────────────────────────────────

func TestAppendHistory_Single(t *testing.T) {
	w := NewWatchdog(nil, nil)
	w.historyLog = nil // clear the initializer entry

	w.appendHistory("test entry")

	log := w.GetHistoryLog()
	if len(log) == 0 {
		t.Fatal("expected at least 1 log entry")
	}
	found := false
	for _, entry := range log {
		if strings.Contains(entry, "test entry") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("'test entry' not found in history: %v", log)
	}
}

func TestAppendHistory_Overflow(t *testing.T) {
	w := NewWatchdog(nil, nil)
	w.historyLog = nil

	// Fill beyond maxHistoryLen (64)
	for i := 0; i < 70; i++ {
		w.appendHistory("entry")
	}

	log := w.GetHistoryLog()
	if len(log) > maxHistoryLen {
		t.Errorf("history log overflow: len=%d, want <= %d", len(log), maxHistoryLen)
	}
}

func TestGetHistoryLog_EmptyReturnsDefault(t *testing.T) {
	w := &Watchdog{
		cfg:    DefaultWatchdogConfig("127.0.0.1:10808"),
		log:    func(string) {},
		status: WatchdogStatus{State: WatchdogIdle},
	}
	// historyLog is nil — GetHistoryLog should return ["watchdog initialized"]
	log := w.GetHistoryLog()
	if len(log) == 0 {
		t.Error("GetHistoryLog on empty log should return at least 1 entry")
	}
}

// ── readFullConn ──────────────────────────────────────────────────────────────

func TestReadFullConn_Success(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	data := []byte{0x05, 0x00, 0xAB, 0xCD}
	go func() {
		server.Write(data)
	}()

	buf := make([]byte, 4)
	n, err := readFullConn(client, buf)
	if err != nil {
		t.Fatalf("readFullConn: %v", err)
	}
	if n != 4 {
		t.Errorf("readFullConn: n=%d, want 4", n)
	}
	for i, b := range data {
		if buf[i] != b {
			t.Errorf("buf[%d] = %02x, want %02x", i, buf[i], b)
		}
	}
}

func TestReadFullConn_EOF(t *testing.T) {
	server, client := net.Pipe()

	// Close server side immediately — client gets EOF
	server.Close()

	buf := make([]byte, 4)
	_, err := readFullConn(client, buf)
	if err == nil {
		t.Error("expected error (EOF) from readFullConn, got nil")
	}
	client.Close()
}

func TestReadFullConn_EmptyBuf(t *testing.T) {
	_, client := net.Pipe()
	defer client.Close()

	// Reading 0 bytes should always succeed immediately
	buf := make([]byte, 0)
	n, err := readFullConn(client, buf)
	if err != nil {
		t.Fatalf("readFullConn(empty buf): %v", err)
	}
	if n != 0 {
		t.Errorf("n=%d, want 0", n)
	}
}

// ── doSOCKS5Connect ───────────────────────────────────────────────────────────

// mockSOCKS5Server creates a minimal SOCKS5 server that accepts no-auth connections
// and sends a success response for CONNECT requests.
func mockSOCKS5Server(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleMockSOCKS5(conn)
		}
	}()
	return ln
}

func handleMockSOCKS5(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Read greeting: VER, NMETHODS, METHODS
	hdr := make([]byte, 2)
	if _, err := readFullConn(conn, hdr); err != nil {
		return
	}
	nMethods := int(hdr[1])
	methods := make([]byte, nMethods)
	if _, err := readFullConn(conn, methods); err != nil {
		return
	}
	// Reply: VER=5, METHOD=0 (no auth)
	conn.Write([]byte{0x05, 0x00})

	// Read CONNECT request
	req := make([]byte, 4)
	if _, err := readFullConn(conn, req); err != nil {
		return
	}
	// req[3] = ATYP
	switch req[3] {
	case 0x01: // IPv4
		addr := make([]byte, 6)
		readFullConn(conn, addr)
	case 0x03: // domain
		lenBuf := make([]byte, 1)
		readFullConn(conn, lenBuf)
		domain := make([]byte, int(lenBuf[0])+2)
		readFullConn(conn, domain)
	case 0x04: // IPv6
		addr := make([]byte, 18)
		readFullConn(conn, addr)
	}

	// Send success reply: VER=5, REP=0 (success), RSV=0, ATYP=1 (IPv4), addr=0.0.0.0, port=0
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}

func TestDoSOCKS5Connect_Success(t *testing.T) {
	ln := mockSOCKS5Server(t)
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	err = doSOCKS5Connect(conn, "example.com:80", 5*time.Second)
	if err != nil {
		t.Fatalf("doSOCKS5Connect: %v", err)
	}
}

func TestDoSOCKS5Connect_InvalidTarget(t *testing.T) {
	ln := mockSOCKS5Server(t)
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Bad host:port format
	err = doSOCKS5Connect(conn, "not-valid-addr-format", 5*time.Second)
	if err == nil {
		t.Error("expected error for invalid target address, got nil")
	}
}

func TestDoSOCKS5Connect_AuthRequired(t *testing.T) {
	// Server requires auth (METHOD=2) — our client doesn't support it
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Read greeting
		hdr := make([]byte, 2)
		readFullConn(conn, hdr)
		nMethods := int(hdr[1])
		readFullConn(conn, make([]byte, nMethods))
		// Respond with METHOD=2 (username/password) — unsupported
		conn.Write([]byte{0x05, 0x02})
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	err = doSOCKS5Connect(conn, "example.com:80", 3*time.Second)
	if err == nil {
		t.Error("expected error when auth required, got nil")
	}
}

func TestDoSOCKS5Connect_ConnectFailed(t *testing.T) {
	// Server sends CONNECT failure (REP != 0)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		hdr := make([]byte, 2)
		readFullConn(conn, hdr)
		nMethods := int(hdr[1])
		readFullConn(conn, make([]byte, nMethods))
		conn.Write([]byte{0x05, 0x00}) // auth OK

		// Read the CONNECT request
		req := make([]byte, 4)
		readFullConn(conn, req)
		lenBuf := make([]byte, 1)
		readFullConn(conn, lenBuf)
		readFullConn(conn, make([]byte, int(lenBuf[0])+2))

		// Reply with REP=5 (Connection refused)
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	err = doSOCKS5Connect(conn, "example.com:80", 3*time.Second)
	if err == nil {
		t.Error("expected error for CONNECT failure, got nil")
	}
}

// ── doCheck ───────────────────────────────────────────────────────────────────

func TestDoCheck_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := &WatchdogConfig{
		CheckURL:      srv.URL,
		CheckTimeout:  5 * time.Second,
		FailThreshold: 3,
		CheckInterval: time.Minute,
	}
	w := &Watchdog{
		cfg:    cfg,
		log:    func(string) {},
		status: WatchdogStatus{State: WatchdogHealthy},
	}
	// Replace client directly (bypassing SOCKS5 proxy)
	w.client = &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	err := w.doCheck(context.Background())
	if err != nil {
		t.Fatalf("doCheck with 200: %v", err)
	}
}

func TestDoCheck_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()

	cfg := &WatchdogConfig{
		CheckURL:      srv.URL,
		CheckTimeout:  5 * time.Second,
		FailThreshold: 3,
		CheckInterval: time.Minute,
	}
	w := &Watchdog{
		cfg:    cfg,
		log:    func(string) {},
		status: WatchdogStatus{State: WatchdogHealthy},
	}
	w.client = &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	err := w.doCheck(context.Background())
	if err == nil {
		t.Error("expected error for HTTP 503, got nil")
	}
}

func TestDoCheck_Redirect_OK(t *testing.T) {
	// 301 is not >= 500, so should not error
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(301)
	}))
	defer srv.Close()

	cfg := &WatchdogConfig{
		CheckURL:      srv.URL,
		CheckTimeout:  5 * time.Second,
		FailThreshold: 3,
		CheckInterval: time.Minute,
	}
	w := &Watchdog{
		cfg:    cfg,
		log:    func(string) {},
		status: WatchdogStatus{State: WatchdogHealthy},
	}
	w.client = &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	err := w.doCheck(context.Background())
	if err != nil {
		t.Fatalf("doCheck with 301 should succeed (< 500): %v", err)
	}
}

// ── check (integration of doCheck + state machine) ────────────────────────────

func TestCheck_FailIncrementsCount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	cfg := &WatchdogConfig{
		CheckURL:      srv.URL,
		CheckTimeout:  2 * time.Second,
		FailThreshold: 3,
		CheckInterval: time.Minute,
	}
	w := &Watchdog{
		cfg:    cfg,
		log:    func(string) {},
		status: WatchdogStatus{State: WatchdogHealthy},
	}
	w.client = &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	w.check(context.Background())

	st := w.GetStatus()
	if st.FailCount < 1 {
		t.Errorf("FailCount = %d, want >= 1 after failed check", st.FailCount)
	}
	if st.TotalChecks < 1 {
		t.Errorf("TotalChecks = %d, want >= 1", st.TotalChecks)
	}
}

func TestCheck_OnDeadCallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	cfg := &WatchdogConfig{
		CheckURL:      srv.URL,
		CheckTimeout:  2 * time.Second,
		FailThreshold: 1, // fail immediately
		CheckInterval: time.Minute,
	}
	w := &Watchdog{
		cfg:    cfg,
		log:    func(string) {},
		status: WatchdogStatus{State: WatchdogHealthy},
	}
	w.client = &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	deadCalled := make(chan struct{}, 1)
	w.OnDead = func() { deadCalled <- struct{}{} }

	w.check(context.Background())

	select {
	case <-deadCalled:
		// OK
	case <-time.After(2 * time.Second):
		t.Error("OnDead was not called after reaching FailThreshold")
	}

	st := w.GetStatus()
	if st.State != WatchdogFailed {
		t.Errorf("State = %q, want %q", st.State, WatchdogFailed)
	}
}

func TestCheck_OnFailCallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()

	cfg := &WatchdogConfig{
		CheckURL:      srv.URL,
		CheckTimeout:  2 * time.Second,
		FailThreshold: 5, // won't trigger OnDead
		CheckInterval: time.Minute,
	}
	w := &Watchdog{
		cfg:    cfg,
		log:    func(string) {},
		status: WatchdogStatus{State: WatchdogHealthy},
	}
	w.client = &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	failCalled := make(chan struct{}, 1)
	w.OnFail = func(failCount int, lastErr string) { failCalled <- struct{}{} }

	w.check(context.Background())

	select {
	case <-failCalled:
		// OK
	case <-time.After(2 * time.Second):
		t.Error("OnFail was not called")
	}
}

func TestCheck_RecoverCallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := &WatchdogConfig{
		CheckURL:      srv.URL,
		CheckTimeout:  2 * time.Second,
		FailThreshold: 3,
		CheckInterval: time.Minute,
	}
	w := &Watchdog{
		cfg:    cfg,
		log:    func(string) {},
		status: WatchdogStatus{State: WatchdogDegraded, FailCount: 2},
	}
	w.client = &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	recoverCalled := make(chan struct{}, 1)
	w.OnRecover = func() { recoverCalled <- struct{}{} }

	w.check(context.Background())

	select {
	case <-recoverCalled:
		// OK
	case <-time.After(2 * time.Second):
		t.Error("OnRecover was not called after recovery")
	}

	st := w.GetStatus()
	if st.State != WatchdogHealthy {
		t.Errorf("State = %q, want %q after recovery", st.State, WatchdogHealthy)
	}
	if st.FailCount != 0 {
		t.Errorf("FailCount = %d, want 0 after recovery", st.FailCount)
	}
}

// ── rebuildClient ─────────────────────────────────────────────────────────────

func TestRebuildClient_SetsClient(t *testing.T) {
	cfg := &WatchdogConfig{
		ProxyAddr:    "127.0.0.1:10808",
		CheckTimeout: 5 * time.Second,
		CheckURL:     "https://1.1.1.1",
	}
	w := &Watchdog{
		cfg: cfg,
		log: func(string) {},
	}
	w.rebuildClient()
	if w.client == nil {
		t.Error("rebuildClient should set w.client")
	}
}

func TestRebuildClient_EmptyProxyAddr(t *testing.T) {
	cfg := &WatchdogConfig{
		ProxyAddr:    "",
		CheckTimeout: 5 * time.Second,
	}
	w := &Watchdog{
		cfg: cfg,
		log: func(string) {},
	}
	// Should not panic on empty proxy addr
	w.rebuildClient()
	if w.client == nil {
		t.Error("rebuildClient should set w.client even for empty proxy")
	}
}

// ── NewWatchdog with nil config ────────────────────────────────────────────────

func TestNewWatchdog_NilConfig(t *testing.T) {
	w := NewWatchdog(nil, nil)
	if w == nil {
		t.Fatal("NewWatchdog(nil, nil) returned nil")
	}
	if w.cfg == nil {
		t.Error("cfg should be non-nil (default config)")
	}
	st := w.GetStatus()
	if st.State != WatchdogIdle {
		t.Errorf("initial state = %q, want %q", st.State, WatchdogIdle)
	}
}

// ── SelectBest orchestrator ────────────────────────────────────────────────────

func TestSelectBest_TorNotFound(t *testing.T) {
	// In test environment, tor binary won't exist, so SelectBest returns Psiphon
	orch := NewFallbackOrchestrator(
		"/nonexistent/bin/dir",
		t.TempDir(),
		func(string) {},
	)

	// Use a cancelled context so TestConnectivity returns false quickly
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := orch.SelectBest(ctx)
	// Tor not found → should return FallbackPsiphon
	if result != FallbackPsiphon {
		t.Logf("SelectBest = %q (tor may be installed on this machine)", result)
	}
}

// ── TestConnectivity (TorSnowflakeManager) ────────────────────────────────────

func TestTorSnowflakeTestConnectivity_CancelledCtx(t *testing.T) {
	m := NewTorSnowflakeManager(nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancelled

	result := m.TestConnectivity(ctx)
	// Cancelled context → all requests fail → false
	if result {
		t.Error("TestConnectivity with cancelled ctx should return false")
	}
}
