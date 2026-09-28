// traffic_padding.go — маскировка трафика через jitter и padding пакетов. Фаза 6.
// bypass-engineer: timing analysis обход через рандомизацию задержек и размеров пакетов.
package dpi

import (
	"context"
	"crypto/rand"
	"io"
	"math/big"
	"net"
	"sync"
	"time"
)

// PaddingConfig — настройки Traffic Padding
type PaddingConfig struct {
	// JitterMin/Max — диапазон случайной задержки в миллисекундах
	// bypass-engineer: ±50-200ms скрывает timing fingerprint
	JitterMinMs int `json:"jitter_min_ms"` // 50
	JitterMaxMs int `json:"jitter_max_ms"` // 200

	// PaddingMin/Max — размер padding-байт добавляемых к пакетам (байт)
	// bypass-engineer: выравнивает размеры пакетов → скрывает паттерн
	PaddingMinBytes int `json:"padding_min_bytes"` // 0
	PaddingMaxBytes int `json:"padding_max_bytes"` // 512

	// Enabled — включить padding
	Enabled bool `json:"enabled"`

	// AggressiveMode — агрессивная маскировка (больше jitter, больше padding)
	// Используется при BlockageDeep
	AggressiveMode bool `json:"aggressive_mode"`
}

// DefaultPaddingConfig — настройки по умолчанию
func DefaultPaddingConfig() *PaddingConfig {
	return &PaddingConfig{
		JitterMinMs:     50,
		JitterMaxMs:     200,
		PaddingMinBytes: 16,
		PaddingMaxBytes: 256,
		Enabled:         false, // выключен по умолчанию (включается при DPI детекции)
	}
}

// AggressivePaddingConfig — для случаев BlockageDeep
func AggressivePaddingConfig() *PaddingConfig {
	return &PaddingConfig{
		JitterMinMs:     100,
		JitterMaxMs:     500,
		PaddingMinBytes: 128,
		PaddingMaxBytes: 1024,
		Enabled:         true,
		AggressiveMode:  true,
	}
}

// PaddedConn — обёртка над net.Conn, добавляющая jitter и padding.
// bypass-engineer: перехватываем Write() чтобы добавить задержку и мусорные байты.
type PaddedConn struct {
	net.Conn
	cfg  *PaddingConfig
	mu   sync.Mutex
	done chan struct{}
}

// NewPaddedConn оборачивает соединение с traffic padding
func NewPaddedConn(conn net.Conn, cfg *PaddingConfig) *PaddedConn {
	if cfg == nil {
		cfg = DefaultPaddingConfig()
	}
	return &PaddedConn{
		Conn: conn,
		cfg:  cfg,
		done: make(chan struct{}),
	}
}

// Write — перехватываем запись, добавляем jitter перед отправкой.
// bypass-engineer: случайная задержка разрушает timing fingerprint VPN handshake.
func (c *PaddedConn) Write(b []byte) (int, error) {
	if !c.cfg.Enabled {
		return c.Conn.Write(b)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Jitter — случайная задержка (легитимная маскировка timing-fingerprint,
	// не затрагивает байтовый поток).
	jitterMs := randInt(c.cfg.JitterMinMs, c.cfg.JitterMaxMs)
	if jitterMs > 0 {
		time.Sleep(time.Duration(jitterMs) * time.Millisecond)
	}

	// F-17 (T-17): НЕ пишем «мусорные» padding-байты вторым Write.
	// Раньше здесь шёл c.Conn.Write(padding) сырыми байтами в уже установленный
	// поток к прокси — это разрушало фреймирование протокола (VLESS/VMess/Trojan/SS):
	// получатель трактовал случайные байты как часть следующего кадра. Padding на
	// уровне протокола — задача sing-box (он умеет это нативно), а не TCP-обёртки.
	// Здесь оставляем только jitter; размер-маскировку выполняет sing-box.
	n, err := c.Conn.Write(b)
	if err != nil {
		return n, err
	}
	return n, nil
}

// TrafficPadder — управляет padding для sing-box через конфигурацию.
// bypass-engineer: добавляем padding параметры в sing-box outbound конфиги.
type TrafficPadder struct {
	cfg *PaddingConfig
	mu  sync.RWMutex
}

// NewTrafficPadder создаёт padder
func NewTrafficPadder(cfg *PaddingConfig) *TrafficPadder {
	if cfg == nil {
		cfg = DefaultPaddingConfig()
	}
	return &TrafficPadder{cfg: cfg}
}

// SetConfig обновляет конфигурацию padding (thread-safe)
func (p *TrafficPadder) SetConfig(cfg *PaddingConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg = cfg
}

// IsEnabled возвращает статус padding
func (p *TrafficPadder) IsEnabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cfg.Enabled
}

// Enable включает padding с заданным уровнем агрессивности
func (p *TrafficPadder) Enable(aggressive bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if aggressive {
		p.cfg = AggressivePaddingConfig()
	} else {
		cfg := DefaultPaddingConfig()
		cfg.Enabled = true
		p.cfg = cfg
	}
}

// Disable выключает padding
func (p *TrafficPadder) Disable() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg.Enabled = false
}

// GetConfig возвращает текущую конфигурацию (thread-safe)
func (p *TrafficPadder) GetConfig() *PaddingConfig {
	p.mu.RLock()
	defer p.mu.RUnlock()
	cp := *p.cfg
	return &cp
}

// ApplyJitter применяет jitter к произвольной операции.
// Используется в engine для задержки reconnect и прочих операций.
func (p *TrafficPadder) ApplyJitter() {
	p.mu.RLock()
	cfg := p.cfg
	p.mu.RUnlock()

	if !cfg.Enabled {
		return
	}

	ms := randInt(cfg.JitterMinMs, cfg.JitterMaxMs)
	if ms > 0 {
		time.Sleep(time.Duration(ms) * time.Millisecond)
	}
}

// JitteredDial — dial с jitter (для маскировки timing подключения)
// bypass-engineer: случайная задержка перед TCP connect скрывает timing fingerprint.
func (p *TrafficPadder) JitteredDial(ctx context.Context, network, addr string) (net.Conn, error) {
	p.mu.RLock()
	cfg := p.cfg
	p.mu.RUnlock()

	if cfg.Enabled {
		jitterMs := randInt(cfg.JitterMinMs/2, cfg.JitterMaxMs/2)
		if jitterMs > 0 {
			select {
			case <-time.After(time.Duration(jitterMs) * time.Millisecond):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

// WrapConn оборачивает соединение в PaddedConn если padding включён
func (p *TrafficPadder) WrapConn(conn net.Conn) net.Conn {
	p.mu.RLock()
	cfg := p.cfg
	p.mu.RUnlock()

	if !cfg.Enabled {
		return conn
	}
	return NewPaddedConn(conn, cfg)
}

// NullPaddingReader — reader который «поглощает» padding байты от сервера.
// Используется на стороне получателя для strip-а padding.
type NullPaddingReader struct {
	r          io.Reader
	paddingLen int // сколько байт padding ожидаем
}

func NewNullPaddingReader(r io.Reader, paddingLen int) *NullPaddingReader {
	return &NullPaddingReader{r: r, paddingLen: paddingLen}
}

func (n *NullPaddingReader) Read(p []byte) (int, error) {
	// Сначала skip padding если есть
	if n.paddingLen > 0 {
		skip := make([]byte, n.paddingLen)
		io.ReadFull(n.r, skip)
		n.paddingLen = 0
	}
	return n.r.Read(p)
}

// ── Хелперы ──────────────────────────────────────────────────────────────────

// randInt возвращает случайное число в диапазоне [min, max]
func randInt(min, max int) int {
	if min >= max {
		return min
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return min
	}
	return min + int(n.Int64())
}
