package leakguard

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// listeningAddr поднимает TCP-listener, чтобы portReachable() видел «туннель» живым.
func listeningAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c
		}
	}()
	return ln.Addr().String()
}

// ── Логика решения (resolveTunnel/resolveDirect подменены) ───────────────────

func TestDNSLeak_TunnelResolves_NoLeak(t *testing.T) {
	d := NewDNSLeakTester(listeningAddr(t))
	d.resolveTunnel = func(ctx context.Context, dom string) (int, error) { return 2, nil }
	d.resolveDirect = func(ctx context.Context, dom string) (int, error) { return 2, nil }
	res, err := d.Test(context.Background())
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if res.Leaked {
		t.Errorf("expected no leak when tunnel resolves, got Leaked=true: %s", res.Diagnosis)
	}
}

func TestDNSLeak_TunnelFails_Leak(t *testing.T) {
	d := NewDNSLeakTester(listeningAddr(t))
	d.resolveTunnel = func(ctx context.Context, dom string) (int, error) { return 0, errors.New("boom") }
	d.resolveDirect = func(ctx context.Context, dom string) (int, error) { return 1, nil }
	res, _ := d.Test(context.Background())
	if !res.Leaked {
		t.Error("expected Leaked=true when tunnel DNS query fails")
	}
	if res.Diagnosis == "" {
		t.Error("leak result must carry diagnosis")
	}
}

func TestDNSLeak_TunnelZeroAnswers_Leak(t *testing.T) {
	d := NewDNSLeakTester(listeningAddr(t))
	d.resolveTunnel = func(ctx context.Context, dom string) (int, error) { return 0, nil }
	d.resolveDirect = func(ctx context.Context, dom string) (int, error) { return 1, nil }
	res, _ := d.Test(context.Background())
	if !res.Leaked {
		t.Error("expected Leaked=true when tunnel returns 0 answers")
	}
}

// ── Реальный путь: DNS-over-TCP через мок-SOCKS5 ─────────────────────────────

func TestDefaultResolveTunnel_DNSOverSOCKS5(t *testing.T) {
	dnsAddr := startMockDNSTCP(t) // отвечает ANCOUNT=1
	socks := startMockSOCKS5Bridge(t, dnsAddr)

	d := NewDNSLeakTester(socks)
	d.dnsServer = dnsAddr // гоним «туннельный» DNS на наш мок-резолвер

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	n, err := d.defaultResolveTunnel(ctx, "cloudflare.com")
	if err != nil {
		t.Fatalf("defaultResolveTunnel through SOCKS5: %v", err)
	}
	if n != 1 {
		t.Errorf("expected ANCOUNT=1 from mock resolver, got %d", n)
	}
	t.Logf("OK: DNS-over-TCP через SOCKS5 вернул ANCOUNT=%d", n)
}

// startMockDNSTCP — мок DNS-over-TCP сервера: читает запрос, отвечает с ANCOUNT=1.
func startMockDNSTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dns listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				lb := make([]byte, 2)
				if _, e := readFull(conn, lb); e != nil {
					return
				}
				q := make([]byte, int(binary.BigEndian.Uint16(lb)))
				if _, e := readFull(conn, q); e != nil || len(q) < 12 {
					return
				}
				resp := make([]byte, 12)
				copy(resp[0:2], q[0:2])                      // эхо ID
				binary.BigEndian.PutUint16(resp[2:], 0x8180) // QR+RD+RA
				binary.BigEndian.PutUint16(resp[4:], 1)      // QDCOUNT
				binary.BigEndian.PutUint16(resp[6:], 1)      // ANCOUNT
				resp = append(resp, q[12:]...)               // эхо вопроса
				resp = append(resp,
					0xC0, 0x0C, // указатель на имя
					0x00, 0x01, // TYPE A
					0x00, 0x01, // CLASS IN
					0x00, 0x00, 0x00, 0x3C, // TTL
					0x00, 0x04, // RDLENGTH
					1, 2, 3, 4) // RDATA
				out := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(out[0:], uint16(len(resp)))
				copy(out[2:], resp)
				_, _ = conn.Write(out)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// startMockSOCKS5Bridge — мок-SOCKS5 (no-auth), прозрачно проксирует к target.
func startMockSOCKS5Bridge(t *testing.T, target string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(client net.Conn) {
				defer client.Close()
				hdr := make([]byte, 2)
				if _, e := readFull(client, hdr); e != nil {
					return
				}
				if _, e := readFull(client, make([]byte, int(hdr[1]))); e != nil {
					return
				}
				client.Write([]byte{0x05, 0x00})
				req := make([]byte, 4)
				if _, e := readFull(client, req); e != nil {
					return
				}
				switch req[3] {
				case 0x01:
					readFull(client, make([]byte, 4+2))
				case 0x04:
					readFull(client, make([]byte, 16+2))
				case 0x03:
					l := make([]byte, 1)
					readFull(client, l)
					readFull(client, make([]byte, int(l[0])+2))
				default:
					return
				}
				client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				up, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer up.Close()
				done := make(chan struct{}, 2)
				go func() { io.Copy(up, client); done <- struct{}{} }()
				go func() { io.Copy(client, up); done <- struct{}{} }()
				<-done
			}(c)
		}
	}()
	return ln.Addr().String()
}
