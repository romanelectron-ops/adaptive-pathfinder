package leakguard

// Extra tests covering readFull and dialSOCKS5 (helpers.go).
// Both functions were at 0 % coverage.

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// ─── readFull ─────────────────────────────────────────────────────────────────

func TestReadFull_ExactBuffer(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c2.Write([]byte{1, 2, 3, 4, 5})
		c2.Close()
	}()
	buf := make([]byte, 5)
	n, err := readFull(c1, buf)
	<-done
	if n != 5 {
		t.Errorf("readFull: n=%d, want 5", n)
	}
	if err != nil && err != io.EOF {
		t.Errorf("readFull: unexpected err %v", err)
	}
	for i, b := range buf {
		if b != byte(i+1) {
			t.Errorf("buf[%d]=%d, want %d", i, b, i+1)
		}
	}
}

func TestReadFull_MultipleWrites(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	go func() {
		c2.Write([]byte{10, 20})
		c2.Write([]byte{30, 40})
		c2.Close()
	}()
	buf := make([]byte, 4)
	n, _ := readFull(c1, buf)
	if n != 4 {
		t.Errorf("readFull multi-write: n=%d, want 4", n)
	}
}

func TestReadFull_ConnectionClosed(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	go func() {
		c2.Write([]byte{1, 2}) // only 2 bytes, then close
		c2.Close()
	}()
	buf := make([]byte, 5) // want 5 but only 2 available
	_, err := readFull(c1, buf)
	if err == nil {
		t.Error("readFull: expected error when connection closed before buffer full")
	}
}

// ─── dialSOCKS5 — connection refused ─────────────────────────────────────────

func TestDialSOCKS5_ConnectionRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, err := dialSOCKS5(ctx, "127.0.0.1:19997", "example.com:80")
	if err == nil {
		t.Error("expected error for non-listening SOCKS5 address")
	}
}

// ─── dialSOCKS5 — mock SOCKS5 server (IPv4 reply) ────────────────────────────

// serveSocks5Once accepts one connection and performs a minimal SOCKS5 handshake.
// Sends an IPv4 bound address in the reply so dialSOCKS5 reads the correct amount.
func serveSocks5Once(ln net.Listener) {
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// 1. greeting: [05 01 00]
	greet := make([]byte, 3)
	io.ReadFull(conn, greet)

	// 2. auth reply: [05 00] (no-auth accepted)
	conn.Write([]byte{0x05, 0x00})

	// 3. CONNECT request: [05 01 00 03 <len> <host> <port_hi> <port_lo>]
	hdr := make([]byte, 4) // ver, cmd, rsv, atyp
	io.ReadFull(conn, hdr)
	// domain name: read length byte then name
	lb := make([]byte, 1)
	io.ReadFull(conn, lb)
	dom := make([]byte, int(lb[0]))
	io.ReadFull(conn, dom)
	port := make([]byte, 2)
	io.ReadFull(conn, port)

	// 4. Success reply: [05 00 00 01 bnd_ip(4) bnd_port(2)] = 10 bytes
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func TestDialSOCKS5_MockServer_Success(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind: %v", err)
	}
	defer ln.Close()

	go serveSocks5Once(ln)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := dialSOCKS5(ctx, ln.Addr().String(), "example.com:80")
	if err != nil {
		t.Fatalf("dialSOCKS5 with mock server: %v", err)
	}
	conn.Close()
}

// ─── dialSOCKS5 — server rejects auth (resp[1] != 0x00) ──────────────────────

func TestDialSOCKS5_AuthRejected(t *testing.T) {
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
		// Reply: auth required (method = 0xFF = no acceptable method)
		conn.Write([]byte{0x05, 0xFF})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = dialSOCKS5(ctx, ln.Addr().String(), "example.com:80")
	if err == nil {
		t.Error("expected error when server rejects auth method")
	}
}

// ─── dialSOCKS5 — server sends CONNECT failure (rep != 0x00) ─────────────────

func TestDialSOCKS5_ConnectRefused(t *testing.T) {
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
		// Reply: connection refused (rep=05)
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = dialSOCKS5(ctx, ln.Addr().String(), "example.com:80")
	if err == nil {
		t.Error("expected error when server sends CONNECT failure")
	}
}
