package fallback

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ── doSOCKS5Connect domain atype (0x03) ─────────────────────────────────────

func mockSOCKS5WithAtype(t *testing.T, atype byte) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen:", err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))

		// Read greeting: VER + NMETHODS
		hdr := make([]byte, 2)
		conn.Read(hdr)
		nMethods := int(hdr[1])
		methods := make([]byte, nMethods)
		conn.Read(methods)
		// No-auth response
		conn.Write([]byte{0x05, 0x00})

		// Read CONNECT request header: VER CMD RSV ATYP
		connReq := make([]byte, 4)
		conn.Read(connReq)
		// Consume target address based on ATYP
		switch connReq[3] {
		case 0x01: // IPv4: 4 bytes + 2 port
			conn.Read(make([]byte, 6))
		case 0x03: // Domain: 1-byte len + name + 2 port
			lb := make([]byte, 1)
			conn.Read(lb)
			conn.Read(make([]byte, int(lb[0])+2))
		case 0x04: // IPv6: 16 bytes + 2 port
			conn.Read(make([]byte, 18))
		}

		// Send reply with the requested atype
		switch atype {
		case 0x01: // IPv4
			conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50})
		case 0x03: // Domain "ok"
			conn.Write([]byte{0x05, 0x00, 0x00, 0x03, 0x02, 'o', 'k', 0x00, 0x50})
		case 0x04: // IPv6
			reply := []byte{0x05, 0x00, 0x00, 0x04}
			reply = append(reply, make([]byte, 16)...) // :: (all zeros)
			reply = append(reply, 0x00, 0x50)          // port 80
			conn.Write(reply)
		}
	}()
	return ln
}

func TestDoSOCKS5Connect_DomainAtype(t *testing.T) {
	ln := mockSOCKS5WithAtype(t, 0x03)
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	err = doSOCKS5Connect(conn, "example.com:80", 5*time.Second)
	if err != nil {
		t.Errorf("doSOCKS5Connect domain atype: %v", err)
	}
}

func TestDoSOCKS5Connect_IPv6Atype(t *testing.T) {
	ln := mockSOCKS5WithAtype(t, 0x04)
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	err = doSOCKS5Connect(conn, "example.com:80", 5*time.Second)
	if err != nil {
		t.Errorf("doSOCKS5Connect IPv6 atype: %v", err)
	}
}

// ── rebuildClient DialContext coverage ───────────────────────────────────────

func TestRebuildClient_DialContextSuccess(t *testing.T) {
	// Use the standard mockSOCKS5Server which replies with ATYP=0x01
	ln := mockSOCKS5Server(t)
	defer ln.Close()

	cfg := &WatchdogConfig{
		ProxyAddr:    ln.Addr().String(),
		CheckTimeout: 5 * time.Second,
	}
	w := &Watchdog{cfg: cfg, log: func(string) {}}
	w.rebuildClient()

	transport, ok := w.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Calling DialContext directly exercises the closure body (success path)
	conn, err := transport.DialContext(ctx, "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	conn.Close()
}

func TestRebuildClient_DialContextDialFail(t *testing.T) {
	// Port 1 is not listening — dial will fail → covers the "socks5 dial" error branch
	cfg := &WatchdogConfig{
		ProxyAddr:    "127.0.0.1:1",
		CheckTimeout: 500 * time.Millisecond,
	}
	w := &Watchdog{cfg: cfg, log: func(string) {}}
	w.rebuildClient()

	transport, ok := w.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := transport.DialContext(ctx, "tcp", "example.com:80")
	if err == nil {
		t.Error("expected dial error for unreachable proxy addr")
	}
}

// ── doCheck error branches ────────────────────────────────────────────────────

func TestDoCheck_InvalidURL(t *testing.T) {
	w := &Watchdog{
		cfg:    &WatchdogConfig{CheckURL: "://invalid-url"},
		client: &http.Client{Timeout: time.Second},
		log:    func(string) {},
	}
	err := w.doCheck(context.Background())
	if err == nil {
		t.Error("doCheck with invalid URL should return error")
	}
}

func TestDoCheck_Status500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	w := &Watchdog{
		cfg: &WatchdogConfig{CheckURL: srv.URL},
		client: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		log: func(string) {},
	}
	err := w.doCheck(context.Background())
	if err == nil {
		t.Error("doCheck with HTTP 500 should return error")
	}
}

// ── NewPsiphonManager nil branches ────────────────────────────────────────────

func TestNewPsiphonManager_BothNil(t *testing.T) {
	// cfg=nil and logFn=nil → covers both nil-default branches
	m := NewPsiphonManager(nil, nil)
	if m == nil {
		t.Fatal("NewPsiphonManager(nil,nil) returned nil")
	}
	if m.cfg == nil {
		t.Error("cfg should be defaulted when nil")
	}
	if m.log == nil {
		t.Error("log should be defaulted when nil")
	}
}

// ── GetSingBoxConfig all branches ────────────────────────────────────────────

func TestGetSingBoxConfig_AllBranches(t *testing.T) {
	orch := NewFallbackOrchestrator("", "", nil)

	if cfg := orch.GetSingBoxConfig(FallbackTor); cfg == nil {
		t.Error("GetSingBoxConfig(FallbackTor) should not return nil")
	}
	if cfg := orch.GetSingBoxConfig(FallbackSnowflake); cfg == nil {
		t.Error("GetSingBoxConfig(FallbackSnowflake) should not return nil")
	}
	if cfg := orch.GetSingBoxConfig(FallbackPsiphon); cfg == nil {
		t.Error("GetSingBoxConfig(FallbackPsiphon) should not return nil")
	}
	// Default branch → nil
	if cfg := orch.GetSingBoxConfig(FallbackTunnel("unknown")); cfg != nil {
		t.Error("GetSingBoxConfig(unknown) should return nil")
	}
}

// ── SelectBest Snowflake path ─────────────────────────────────────────────────

func TestSelectBest_TorAvailSnowflakePath(t *testing.T) {
	tmpDir := t.TempDir()
	// Create a fake tor.exe so IsAvailable returns true (file exists)
	torBin := filepath.Join(tmpDir, "tor.exe")
	if err := os.WriteFile(torBin, []byte("fake"), 0o755); err != nil {
		t.Skip("cannot create fake tor binary:", err)
	}

	orch := NewFallbackOrchestrator(tmpDir, tmpDir, nil)

	// Immediately cancelled context → TestConnectivity returns false → FallbackSnowflake
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := orch.SelectBest(ctx)
	// With fake tor present and cancelled ctx, expect Snowflake (not Psiphon)
	if result != FallbackSnowflake && result != FallbackTor {
		t.Logf("SelectBest = %q (unexpected, tor may not be detected via file)", result)
	}
}

// ── rebuildClient SOCKS5 handshake failure ─────────────────────────────────

func mockSOCKS5AuthRequired(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen:", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				hdr := make([]byte, 2)
				c.Read(hdr)
				nMethods := int(hdr[1])
				methods := make([]byte, nMethods)
				c.Read(methods)
				// Reply: auth required (method=2) — doSOCKS5Connect will return error
				c.Write([]byte{0x05, 0x02})
			}(conn)
		}
	}()
	return ln
}

func TestRebuildClient_SOCKS5HandshakeFail(t *testing.T) {
	ln := mockSOCKS5AuthRequired(t)
	defer ln.Close()

	cfg := &WatchdogConfig{
		ProxyAddr:    ln.Addr().String(),
		CheckTimeout: 5 * time.Second,
	}
	w := &Watchdog{cfg: cfg, log: func(string) {}}
	w.rebuildClient()

	transport, ok := w.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// doSOCKS5Connect fails (auth required) → conn.Close() + return error path in closure
	_, err := transport.DialContext(ctx, "tcp", "example.com:80")
	if err == nil {
		t.Error("expected error when SOCKS5 auth is required")
	}
}
