package checker

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// startMockSOCKS5 запускает мок-SOCKS5 прокси (метод no-auth), который после
// корректного CONNECT-хендшейка прозрачно проксирует TCP к dialTarget
// (адрес реального origin-сервера). Возвращает адрес прокси.
// Используется для семантической проверки checker.dialViaSOCKS5 / HTTPHealthCheck.
func startMockSOCKS5(t *testing.T, dialTarget string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mock socks5 listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			go serveMockSOCKS5(client, dialTarget)
		}
	}()
	return ln.Addr().String()
}

func serveMockSOCKS5(client net.Conn, dialTarget string) {
	defer client.Close()

	// Приветствие: VER, NMETHODS, METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(client, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	if _, err := io.ReadFull(client, make([]byte, int(hdr[1]))); err != nil {
		return
	}
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// CONNECT: VER, CMD, RSV, ATYP, ADDR, PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(client, req); err != nil {
		return
	}
	switch req[3] {
	case 0x01:
		io.ReadFull(client, make([]byte, 4+2))
	case 0x04:
		io.ReadFull(client, make([]byte, 16+2))
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(client, l); err != nil {
			return
		}
		io.ReadFull(client, make([]byte, int(l[0])+2))
	default:
		return
	}
	// Успех, BND.ADDR = 0.0.0.0:0
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// Прозрачный мост к origin.
	up, err := net.Dial("tcp", dialTarget)
	if err != nil {
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, client); done <- struct{}{} }()
	go func() { io.Copy(client, up); done <- struct{}{} }()
	<-done
}

// TestHTTPHealthCheck_ThroughSOCKS5_EndToEnd — семантическая проверка:
// запрос реально проходит SOCKS5-хендшейк и доходит до origin через туннель,
// страна корректно парсится. Это и есть контракт T-01.
func TestHTTPHealthCheck_ThroughSOCKS5_EndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "fl=abc\nloc=DE\nip=9.9.9.9\n")
	}))
	defer srv.Close()

	oldURL := cfTraceURL
	cfTraceURL = srv.URL
	defer func() { cfTraceURL = oldURL }()

	proxyAddr := startMockSOCKS5(t, srv.Listener.Addr().String())
	c := New(2, 5)

	latency, country, err := c.HTTPHealthCheck(context.Background(), proxyAddr)
	if err != nil {
		t.Fatalf("expected success through SOCKS5, got: %v", err)
	}
	if country != "DE" {
		t.Errorf("expected country=DE, got %q", country)
	}
	if latency < 0 {
		t.Errorf("latency should be >= 0, got %d", latency)
	}
	t.Logf("OK: through-tunnel SOCKS5 health check: latency=%dms country=%s", latency, country)
}

// TestDialViaSOCKS5_RejectsNonSOCKS — если на proxyAddr не SOCKS5-сервер,
// dialViaSOCKS5 обязан вернуть ошибку (а не молча отдать сырой коннект).
func TestDialViaSOCKS5_RejectsNonSOCKS(t *testing.T) {
	// origin отвечает мусором вместо SOCKS5-рукопожатия
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
		conn.Write([]byte{0xFF, 0xFF}) // не SOCKS5
	}()

	ctx := context.Background()
	conn, err := dialViaSOCKS5(ctx, ln.Addr().String(), "1.1.1.1:443", 3e9)
	if err == nil {
		conn.Close()
		t.Fatal("expected error against non-SOCKS5 server, got nil")
	}
	t.Logf("OK: non-SOCKS5 server rejected: %v", err)
}
