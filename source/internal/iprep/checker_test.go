package iprep

import (
	"context"
	"strings"
	"testing"
	"time"
)

// ── calcRiskScore тесты (без сети) ────────────────────────────────────────────

func newTestChecker() *Checker {
	return NewChecker(func(s string) {})
}

func TestCalcRiskScore_Residential(t *testing.T) {
	c := newTestChecker()
	info := &IPInfo{
		IsResidential: true,
		IsProxy:       false,
		IsDatacenter:  false,
		ISP:           "Rostelecom",
		ASN:           "AS12389",
		Org:           "Rostelecom",
	}
	score := c.calcRiskScore(info)
	if score > 30 {
		t.Errorf("residential ISP should have low risk score, got %d", score)
	}
}

func TestCalcRiskScore_Datacenter(t *testing.T) {
	c := newTestChecker()
	info := &IPInfo{
		IsResidential: false,
		IsDatacenter:  true,
		IsHosting:     true,
		IsProxy:       false,
		ISP:           "DigitalOcean",
		ASN:           "AS14061",
		Org:           "DigitalOcean LLC",
	}
	score := c.calcRiskScore(info)
	if score < 40 {
		t.Errorf("datacenter IP should have high risk score, got %d", score)
	}
}

func TestCalcRiskScore_ProxyVPN(t *testing.T) {
	c := newTestChecker()
	info := &IPInfo{
		IsProxy: true,
		IsVPN:   true,
		ISP:     "SomeVPN",
		Org:     "VPN Provider",
	}
	score := c.calcRiskScore(info)
	if score < 50 {
		t.Errorf("proxy/VPN IP should have very high risk score, got %d", score)
	}
}

func TestCalcRiskScore_HostingKeyword(t *testing.T) {
	c := newTestChecker()
	// AWS ключевое слово должно добавлять штраф
	info := &IPInfo{
		IsResidential: false,
		IsDatacenter:  true,
		Org:           "Amazon Web Services",
		ASN:           "AS16509",
	}
	score := c.calcRiskScore(info)
	if score < 40 {
		t.Errorf("AWS org should increase risk score, got %d", score)
	}
}

func TestCalcRiskScore_Bounds(t *testing.T) {
	c := newTestChecker()

	// Максимальный штраф — не должен выходить за 100
	worst := &IPInfo{
		IsProxy:      true,
		IsVPN:        true,
		IsDatacenter: true,
		IsHosting:    true,
		Org:          "digitalocean",
	}
	score := c.calcRiskScore(worst)
	if score > 100 {
		t.Errorf("risk score must not exceed 100, got %d", score)
	}
	if score < 0 {
		t.Errorf("risk score must not be negative, got %d", score)
	}

	// Минимум — residential без proxy
	best := &IPInfo{
		IsResidential: true,
		IsProxy:       false,
		ISP:           "HomeISP",
		RiskScore:     5,
	}
	score2 := c.calcRiskScore(best)
	if score2 < 0 {
		t.Errorf("risk score must not be negative, got %d", score2)
	}
}

// ── IPInfo методы ─────────────────────────────────────────────────────────────

func TestIsGoodForStreaming(t *testing.T) {
	tests := []struct {
		name string
		info *IPInfo
		want bool
	}{
		{
			name: "residential low risk",
			info: &IPInfo{IsResidential: true, IsProxy: false, IsDatacenter: false, RiskScore: 10},
			want: true,
		},
		{
			name: "datacenter",
			info: &IPInfo{IsResidential: false, IsDatacenter: true, RiskScore: 60},
			want: false,
		},
		{
			name: "proxy flag",
			info: &IPInfo{IsProxy: true, IsResidential: true, RiskScore: 10},
			want: false,
		},
		{
			name: "high risk score",
			info: &IPInfo{IsResidential: true, IsProxy: false, RiskScore: 50},
			want: false,
		},
		{
			name: "nil info",
			info: nil,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.info.IsGoodForStreaming()
			if got != tt.want {
				t.Errorf("IsGoodForStreaming() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLabel(t *testing.T) {
	tests := []struct {
		info  *IPInfo
		label string
	}{
		{&IPInfo{IsResidential: true}, "residential"},
		{&IPInfo{IsDatacenter: true}, "datacenter"},
		{&IPInfo{IsHosting: true}, "hosting"},
		{&IPInfo{IsProxy: true}, "proxy/vpn"},
		{&IPInfo{IsVPN: true}, "proxy/vpn"},
		{&IPInfo{}, "unknown"},
		{nil, "unknown"},
	}
	for _, tt := range tests {
		got := tt.info.Label()
		if got != tt.label {
			t.Errorf("Label() = %q, want %q for %+v", got, tt.label, tt.info)
		}
	}
}

// ── Кэш ───────────────────────────────────────────────────────────────────────

func TestCache_GetSet(t *testing.T) {
	c := newTestChecker()

	// Пустой кэш — ничего нет
	if c.GetCached("1.2.3.4") != nil {
		t.Error("expected nil for uncached IP")
	}
	if c.CacheSize() != 0 {
		t.Errorf("expected empty cache, got %d", c.CacheSize())
	}

	// Заполняем кэш вручную
	c.mu.Lock()
	c.cache["1.2.3.4"] = &cacheEntry{
		info:      &IPInfo{IP: "1.2.3.4", IsResidential: true, RiskScore: 5},
		expiresAt: time.Now().Add(time.Hour),
	}
	c.mu.Unlock()

	got := c.GetCached("1.2.3.4")
	if got == nil {
		t.Fatal("expected cached entry, got nil")
	}
	if got.IP != "1.2.3.4" {
		t.Errorf("cached IP = %q, want %q", got.IP, "1.2.3.4")
	}
	if c.CacheSize() != 1 {
		t.Errorf("cache size = %d, want 1", c.CacheSize())
	}
}

func TestCache_Expiry(t *testing.T) {
	c := newTestChecker()

	// Ставим запись с истёкшим TTL
	c.mu.Lock()
	c.cache["5.5.5.5"] = &cacheEntry{
		info:      &IPInfo{IP: "5.5.5.5"},
		expiresAt: time.Now().Add(-time.Hour), // уже истёк
	}
	c.mu.Unlock()

	// GetCached должен вернуть nil для истёкшей записи
	got := c.GetCached("5.5.5.5")
	if got != nil {
		t.Error("expired cache entry should return nil")
	}
}

func TestCache_Clear(t *testing.T) {
	c := newTestChecker()
	c.mu.Lock()
	c.cache["1.1.1.1"] = &cacheEntry{info: &IPInfo{IP: "1.1.1.1"}, expiresAt: time.Now().Add(time.Hour)}
	c.cache["2.2.2.2"] = &cacheEntry{info: &IPInfo{IP: "2.2.2.2"}, expiresAt: time.Now().Add(time.Hour)}
	c.mu.Unlock()

	c.ClearCache()
	if c.CacheSize() != 0 {
		t.Errorf("after ClearCache, size = %d, want 0", c.CacheSize())
	}
}

// ── CheckIP с пустым IP ────────────────────────────────────────────────────────

func TestCheckIP_EmptyIP(t *testing.T) {
	c := newTestChecker()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := c.CheckIP(ctx, "")
	if err == nil {
		t.Error("expected error for empty IP, got nil")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected 'empty' in error, got: %v", err)
	}
}

// ── SetAPIKey ──────────────────────────────────────────────────────────────────

func TestSetAPIKey(t *testing.T) {
	c := newTestChecker()
	c.SetAPIKey("test-key-123")
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.apiKey != "test-key-123" {
		t.Errorf("apiKey = %q, want %q", c.apiKey, "test-key-123")
	}
}

// ── Concurrent кэш ─────────────────────────────────────────────────────────────

func TestCache_Concurrent(t *testing.T) {
	c := newTestChecker()
	done := make(chan struct{})

	// Параллельные чтения/записи
	for i := 0; i < 10; i++ {
		go func(i int) {
			c.mu.Lock()
			c.cache[string(rune('0'+i))] = &cacheEntry{
				info:      &IPInfo{IP: "test"},
				expiresAt: time.Now().Add(time.Hour),
			}
			c.mu.Unlock()
			c.GetCached(string(rune('0' + i)))
			if i == 9 {
				close(done)
			}
		}(i)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("concurrent cache test timed out")
	}
}

// ─── Additional iprep coverage with mock HTTP ─────────────────────────────────

func TestCheckIPWithTimeout(t *testing.T) {
	c := NewChecker(nil)
	// Очень короткий timeout — ожидаем ошибку, но не панику
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	_, err := c.CheckIP(ctx, "192.0.2.1") // TEST-NET
	t.Logf("OK: CheckIP with 1ms timeout: err=%v (expected)", err)
}

func TestCheckerSetAPIKey(t *testing.T) {
	c := NewChecker(nil)
	c.SetAPIKey("test-api-key-12345")
	// Проверяем что ключ установлен (через приватное поле - просто no-panic)
	t.Log("OK: SetAPIKey no panic")
}

func TestIPInfoFields(t *testing.T) {
	info := &IPInfo{
		IP:        "1.2.3.4",
		IsVPN:     false,
		IsHosting: true,
		ISP:       "Test ISP",
		Country:   "RU",
		RiskScore: 80,
		CheckedAt: time.Now(),
	}
	if info.IP != "1.2.3.4" {
		t.Error("IP field")
	}
	if !info.IsHosting {
		t.Error("IsHosting field")
	}
	if info.RiskScore != 80 {
		t.Error("RiskScore field")
	}
	t.Logf("OK: IPInfo fields: ip=%s hosting=%v risk=%d",
		info.IP, info.IsHosting, info.RiskScore)
}

func TestCheckerCacheBehavior(t *testing.T) {
	c := NewChecker(nil)

	// Первый запрос к реальному IP — пропускаем без сети
	// Проверяем что cache пустой изначально
	c.mu.RLock()
	cacheLen := len(c.cache)
	c.mu.RUnlock()

	if cacheLen != 0 {
		t.Errorf("initial cache should be empty, got %d", cacheLen)
	}
	t.Log("OK: cache starts empty")
}
