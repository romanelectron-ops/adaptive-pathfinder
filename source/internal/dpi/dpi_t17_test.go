package dpi

import (
	"net"
	"sync"
	"testing"
)

// T-17 (F-17): PaddedConn.Write больше НЕ добавляет «мусорные» padding-байты
// отдельным Write в установленный поток — это разрушало фреймирование протокола
// (VLESS/VMess/Trojan/SS). Контракт: на нижний Conn уходит РОВНО len(b) байт.
// Этот тест КРАСНЫЙ на старом коде (писалось len(b)+padding) и ЗЕЛЁНЫЙ на новом.

type countingConn struct {
	net.Conn
	mu      sync.Mutex
	written int
}

func (c *countingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.written += len(b)
	c.mu.Unlock()
	return len(b), nil
}
func (c *countingConn) Close() error { return nil }

func TestPaddedConn_Write_NoFramingCorruption(t *testing.T) {
	cfg := &PaddingConfig{
		Enabled:         true,
		JitterMinMs:     0,
		JitterMaxMs:     0,
		PaddingMinBytes: 256, // на старом коде → второй Write 256..512 сырых байт
		PaddingMaxBytes: 512,
	}
	cc := &countingConn{}
	pc := NewPaddedConn(cc, cfg)

	payload := []byte("application-frame-payload")
	n, err := pc.Write(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write returned n=%d, want %d", n, len(payload))
	}

	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cc.written != len(payload) {
		t.Fatalf("framing corruption: wrote %d bytes to stream, want exactly %d (no raw padding)",
			cc.written, len(payload))
	}
}
