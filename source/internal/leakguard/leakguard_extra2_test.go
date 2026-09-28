package leakguard

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// ─── portReachable — success path ────────────────────────────────────────────

func TestPortReachable_Success(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind local listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	if !portReachable(ln.Addr().String(), 2*time.Second) {
		t.Error("portReachable should return true for a listening server")
	}
	t.Logf("OK: portReachable success at %s", ln.Addr())
}

// ─── parseAddr — error paths ──────────────────────────────────────────────────

func TestParseAddr_InvalidAddr(t *testing.T) {
	_, _, err := parseAddr("no-colon-here")
	if err == nil {
		t.Error("expected error for addr with no port separator")
	}
	t.Logf("OK: parseAddr no-colon → %v", err)
}

func TestParseAddr_NonDigitPort(t *testing.T) {
	_, _, err := parseAddr("example.com:abc")
	if err == nil {
		t.Error("expected error for non-digit port")
	}
	t.Logf("OK: parseAddr non-digit port → %v", err)
}

// ─── dialSOCKS5 — domain name reply (atyp 0x03) ──────────────────────────────

func serveSocks5Domain(ln net.Listener) {
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	greet := make([]byte, 3)
	io.ReadFull(conn, greet)
	conn.Write([]byte{0x05, 0x00}) // auth OK

	// Read CONNECT request
	hdr := make([]byte, 4)
	io.ReadFull(conn, hdr)
	lb := make([]byte, 1)
	io.ReadFull(conn, lb)
	dom := make([]byte, int(lb[0]))
	io.ReadFull(conn, dom)
	port := make([]byte, 2)
	io.ReadFull(conn, port)

	// Reply: success, bound address is a domain name (atyp=0x03)
	// Format: ver=5, rep=0, rsv=0, atyp=3, len, domain, port_hi, port_lo
	boundDomain := []byte("localhost")
	reply := []byte{0x05, 0x00, 0x00, 0x03, byte(len(boundDomain))}
	reply = append(reply, boundDomain...)
	reply = append(reply, 0x00, 0x50) // port 80
	conn.Write(reply)
}

func TestDialSOCKS5_DomainReply(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind: %v", err)
	}
	defer ln.Close()
	go serveSocks5Domain(ln)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := dialSOCKS5(ctx, ln.Addr().String(), "example.com:80")
	if err != nil {
		t.Fatalf("dialSOCKS5 domain reply: %v", err)
	}
	conn.Close()
	t.Log("OK: dialSOCKS5 domain reply (atyp=0x03)")
}

// ─── dialSOCKS5 — IPv6 bound address reply (atyp 0x04) ───────────────────────

func serveSocks5IPv6(ln net.Listener) {
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	greet := make([]byte, 3)
	io.ReadFull(conn, greet)
	conn.Write([]byte{0x05, 0x00})

	hdr := make([]byte, 4)
	io.ReadFull(conn, hdr)
	lb := make([]byte, 1)
	io.ReadFull(conn, lb)
	dom := make([]byte, int(lb[0]))
	io.ReadFull(conn, dom)
	port := make([]byte, 2)
	io.ReadFull(conn, port)

	// Reply: success, bound address is IPv6 (atyp=0x04)
	// Format: ver=5, rep=0, rsv=0, atyp=4, ipv6_addr(16 bytes), port(2 bytes)
	reply := []byte{0x05, 0x00, 0x00, 0x04}
	reply = append(reply, make([]byte, 16)...) // :: (all zeros IPv6)
	reply = append(reply, 0x00, 0x50)          // port 80
	conn.Write(reply)
}

func TestDialSOCKS5_IPv6Reply(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind: %v", err)
	}
	defer ln.Close()
	go serveSocks5IPv6(ln)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := dialSOCKS5(ctx, ln.Addr().String(), "example.com:80")
	if err != nil {
		t.Fatalf("dialSOCKS5 IPv6 reply: %v", err)
	}
	conn.Close()
	t.Log("OK: dialSOCKS5 IPv6 reply (atyp=0x04)")
}

// ─── dialSOCKS5 — parseAddr error (invalid target) ───────────────────────────

func TestDialSOCKS5_InvalidTargetAddr(t *testing.T) {
	// Server that accepts connection and handles auth, then closes before
	// we send the CONNECT request (so parseAddr failure is the first error).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		greet := make([]byte, 3)
		io.ReadFull(conn, greet)
		conn.Write([]byte{0x05, 0x00}) // auth OK — then wait for CONNECT
		// dialSOCKS5 will call parseAddr("noport") → error before writing CONNECT
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// "noport" has no ':' → parseAddr → net.SplitHostPort fails → error returned
	_, err = dialSOCKS5(ctx, ln.Addr().String(), "noport")
	if err == nil {
		t.Error("expected error for target addr without port")
	}
	t.Logf("OK: dialSOCKS5 invalid target → %v", err)
}
