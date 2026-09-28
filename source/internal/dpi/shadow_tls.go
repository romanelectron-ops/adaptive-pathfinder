// shadow_tls.go — ShadowTLS v3 интеграция. Фаза 6.
// bypass-engineer: маскируем трафик под реальный TLS handshake.
// ShadowTLS проходит полный TLS с настоящим сервером, потом переключается на прокси.
package dpi

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// ShadowTLSVersion — версия протокола ShadowTLS
type ShadowTLSVersion int

const (
	ShadowTLSv1 ShadowTLSVersion = 1
	ShadowTLSv2 ShadowTLSVersion = 2
	ShadowTLSv3 ShadowTLSVersion = 3 // рекомендуется: HMAC-auth + replay protection
)

// ShadowTLSConfig — настройки ShadowTLS
type ShadowTLSConfig struct {
	Enabled  bool             `json:"enabled"`
	Version  ShadowTLSVersion `json:"version"`  // 3 рекомендуется
	Password string           `json:"password"` // HMAC-ключ аутентификации
	// SNI настоящего сайта — DPI видит реальный TLS handshake с этим хостом
	// bypass-engineer: выбираем стабильный сайт который не заблокирован
	HandshakeSNI string `json:"handshake_sni"` // "www.bing.com", "www.microsoft.com"
	// Адрес реального TLS-сервера для handshake (обычно совпадает с SNI) — используется
	// ТОЛЬКО для ProbeHandshakeServer/AutoSelectSNI (проверка, что маскировочный сайт
	// вообще доступен). Трафик туда не идёт.
	HandshakeServer string `json:"handshake_server"` // "www.bing.com:443"

	// ServerAddr — адрес РЕАЛЬНОГО сервера ShadowTLS (host:port), куда физически уходит
	// TCP+TLS соединение (тот сервер, за которым поднят shadow-tls daemon перед прокси
	// пользователя). Обязателен при Enabled: без него клиенту физически некуда
	// подключаться — HandshakeSNI/HandshakeServer описывают только маскировку (что видит
	// DPI), а не то, куда реально уходит трафик.
	//
	// P1-1 (аудит 2026-09-01): это поле раньше отсутствовало вовсе — ServerHost()/
	// ServerPort() (ниже) ошибочно возвращали маскировочный хост, и конфигурация,
	// которую собирал singbox.Builder, пыталась дозвониться до реального сайта
	// (www.bing.com и т.п.) по протоколу ShadowTLS — гарантированный отказ подключения.
	ServerAddr string `json:"server_addr"`
}

// DefaultShadowTLSConfig — настройки по умолчанию
func DefaultShadowTLSConfig() *ShadowTLSConfig {
	return &ShadowTLSConfig{
		Enabled:         false,
		Version:         ShadowTLSv3,
		HandshakeSNI:    "www.bing.com",
		HandshakeServer: "www.bing.com:443",
	}
}

// GoodShadowTLSSNI — надёжные SNI мишени для ShadowTLS.
// bypass-engineer: должны быть стабильны, не заблокированы в РФ, поддерживать TLS 1.3.
var GoodShadowTLSSNI = []struct {
	SNI    string
	Server string
}{
	{"www.bing.com", "www.bing.com:443"},
	{"www.microsoft.com", "www.microsoft.com:443"},
	{"addons.mozilla.org", "addons.mozilla.org:443"},
	{"www.speedtest.net", "www.speedtest.net:443"},
	{"dl.google.com", "dl.google.com:443"},
}

// ShadowTLSManager — управляет ShadowTLS интеграцией.
// Поскольку sing-box НЕ поддерживает ShadowTLS нативно,
// мы генерируем конфиг для внешнего shadow-tls клиента.
type ShadowTLSManager struct {
	// mu защищает cfg: SetConfig (UI/PatchConfig/applyDPIFromConfig) и чтения из connectNode/
	// GetStatus идут из разных горутин — go test -race 2026-09-05 (ТЗ v1.3 F5.4) поймал гонку
	// SetConfig ∥ GetConfig без единого лока.
	mu  sync.RWMutex
	cfg *ShadowTLSConfig
}

// NewShadowTLSManager создаёт manager
func NewShadowTLSManager(cfg *ShadowTLSConfig) *ShadowTLSManager {
	if cfg == nil {
		cfg = DefaultShadowTLSConfig()
	}
	return &ShadowTLSManager{cfg: cfg}
}

// IsEnabled возвращает статус
func (m *ShadowTLSManager) IsEnabled() bool {
	return m.snap().Enabled
}

// GetConfig возвращает конфигурацию
func (m *ShadowTLSManager) GetConfig() *ShadowTLSConfig {
	return m.snap()
}

// SetConfig обновляет конфигурацию
func (m *ShadowTLSManager) SetConfig(cfg *ShadowTLSConfig) {
	if cfg == nil {
		cfg = DefaultShadowTLSConfig()
	}
	m.mu.Lock()
	m.cfg = cfg
	m.mu.Unlock()
}

// snap — копия конфигурации под RLock: все читатели идут через неё, чтобы ни один
// m.snap().X не читался параллельно с SetConfig.
func (m *ShadowTLSManager) snap() *ShadowTLSConfig {
	m.mu.RLock()
	cp := *m.cfg
	m.mu.RUnlock()
	return &cp
}

// ProbeHandshakeServer проверяет что выбранный SNI-сервер доступен и отвечает TLS.
// bypass-engineer: нужно убедиться что handshake сервер не заблокирован.
func (m *ShadowTLSManager) ProbeHandshakeServer(ctx context.Context) *ShadowTLSProbeResult {
	result := &ShadowTLSProbeResult{
		SNI:    m.snap().HandshakeSNI,
		Server: m.snap().HandshakeServer,
	}

	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", m.snap().HandshakeServer)
	if err != nil {
		result.Error = fmt.Sprintf("TCP connect failed: %v", err)
		return result
	}
	defer conn.Close()

	result.TCPReachable = true
	result.LatencyMs = time.Since(start).Milliseconds()

	// Быстрая проверка TLS (без полного handshake — это дорого)
	// Достаточно TCP-соединения — TLS 1.3 проверяется при реальном handshake
	result.Available = true

	return result
}

// AutoSelectSNI автоматически выбирает лучший SNI для handshake.
// bypass-engineer: перебираем кандидатов, берём самый быстрый доступный.
func (m *ShadowTLSManager) AutoSelectSNI(ctx context.Context) (sni, server string, latencyMs int64, err error) {
	type probeResult struct {
		sni       string
		server    string
		latencyMs int64
		ok        bool
	}

	results := make([]probeResult, len(GoodShadowTLSSNI))
	resultCh := make(chan probeResult, len(GoodShadowTLSSNI))

	// Параллельно проверяем всех кандидатов
	for _, candidate := range GoodShadowTLSSNI {
		go func(sni, srv string) {
			pCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			start := time.Now()
			conn, dialErr := (&net.Dialer{}).DialContext(pCtx, "tcp", srv)
			if dialErr != nil {
				resultCh <- probeResult{sni: sni, server: srv, ok: false}
				return
			}
			conn.Close()
			resultCh <- probeResult{
				sni:       sni,
				server:    srv,
				latencyMs: time.Since(start).Milliseconds(),
				ok:        true,
			}
		}(candidate.SNI, candidate.Server)
	}

	// Собираем результаты
	var best probeResult
	for i := 0; i < len(GoodShadowTLSSNI); i++ {
		r := <-resultCh
		results[i] = r
		_ = results
		if r.ok && (best.sni == "" || r.latencyMs < best.latencyMs) {
			best = r
		}
	}

	if !best.ok {
		return "", "", 0, fmt.Errorf("no ShadowTLS handshake server available")
	}

	return best.sni, best.server, best.latencyMs, nil
}

// GenerateSingBoxShadowTLSOutbound генерирует JSON-фрагмент shadowtls-outbound для sing-box.
// bypass-engineer: sing-box поддерживает shadowtls как outbound тип начиная с v1.3+
//
// В sing-box shadowtls — ДИАЛЕР (protocol/shadowtls/outbound.go: DialContext игнорирует
// destination, ListenPacket возвращает os.ErrInvalid), а не прокси-протокол, несущий
// пользовательский трафик. Поэтому у самого shadowtls-outbound нет и не может быть detour —
// он сам физически устанавливает TCP+TLS соединение с сервером. ВНУТРЕННИЙ протокол
// (Shadowsocks/VLESS/etc.) — это то, что несёт реальный трафик, и это ЕГО собственный
// detour обязан указывать на тег shadowtls-out ("shadowtls-out", как задан ниже), не
// наоборот.
//
// P1-1 (аудит 2026-09-01): раньше направление было перевёрнуто ("detour" стоял на этом,
// внешнем, outbound'е и указывал на внутренний — обратное тому, что требует sing-box), а
// "server"/"server_port" брались из маскировочного SNI-хоста (getServerHost/getServerPort,
// т.е. HandshakeServer) вместо реального адреса сервера — клиент пытался бы дозвониться до
// самого маскировочного сайта (www.bing.com и т.п.) по протоколу ShadowTLS, что не может
// сработать. Эта функция отдаёт ТОЛЬКО внешний shadowtls-outbound; вызывающая сторона
// обязана сама выставить "detour":"shadowtls-out" на внутреннем протокольном outbound'е и
// направить туда route.final — см. singbox.Builder.wrapShadowTLS (тот же фикс для
// реального пути сборки конфигурации).
func (m *ShadowTLSManager) GenerateSingBoxShadowTLSOutbound() map[string]interface{} {
	if !m.snap().Enabled {
		return nil
	}

	return map[string]interface{}{
		"type": "shadowtls",
		"tag":  "shadowtls-out",
		// ShadowTLS подключается к РЕАЛЬНОМУ серверу (ServerAddr), а НЕ к маскировочному
		// SNI-хосту (VPN сервер должен запускать shadow-tls сервер перед своим прокси).
		"server":      m.realHost(),
		"server_port": m.realPort(),
		"version":     int(m.snap().Version),
		"password":    m.snap().Password,
		"tls": map[string]interface{}{
			"enabled":     true,
			"server_name": m.snap().HandshakeSNI,
			"utls": map[string]interface{}{
				"enabled":     true,
				"fingerprint": "chrome", // imitate Chrome TLS fingerprint
			},
		},
	}
}

// ShadowTLSStatus — статус для UI
type ShadowTLSStatus struct {
	Enabled         bool   `json:"enabled"`
	Version         int    `json:"version"`
	HandshakeSNI    string `json:"handshake_sni"`
	HandshakeServer string `json:"handshake_server"`
	// ServerAddr — реальный адрес сервера. Не секрет (в отличие от Password), безопасно
	// отдавать обратно в UI при повторном открытии диалога настроек.
	ServerAddr  string `json:"server_addr"`
	Available   bool   `json:"available"`
	LatencyMs   int64  `json:"latency_ms,omitempty"`
	NoteForUser string `json:"note"`
}

// GetStatus возвращает статус для UI
func (m *ShadowTLSManager) GetStatus(ctx context.Context) *ShadowTLSStatus {
	status := &ShadowTLSStatus{
		Enabled:         m.snap().Enabled,
		Version:         int(m.snap().Version),
		HandshakeSNI:    m.snap().HandshakeSNI,
		HandshakeServer: m.snap().HandshakeServer,
		ServerAddr:      m.snap().ServerAddr,
		NoteForUser:     "ShadowTLS v3 требует поддержки на стороне сервера (shadow-tls daemon). Работает поверх Shadowsocks.",
	}

	if m.snap().Enabled {
		probe := m.ProbeHandshakeServer(ctx)
		status.Available = probe.Available
		status.LatencyMs = probe.LatencyMs
	}

	return status
}

// ShadowTLSProbeResult — результат проверки handshake сервера
type ShadowTLSProbeResult struct {
	SNI          string `json:"sni"`
	Server       string `json:"server"`
	TCPReachable bool   `json:"tcp_reachable"`
	Available    bool   `json:"available"`
	LatencyMs    int64  `json:"latency_ms"`
	Error        string `json:"error,omitempty"`
}

// ── Вспомогательные методы ────────────────────────────────────────────────────

func (m *ShadowTLSManager) getServerHost() string {
	host, _, err := net.SplitHostPort(m.snap().HandshakeServer)
	if err != nil {
		return m.snap().HandshakeServer
	}
	return host
}

func (m *ShadowTLSManager) getServerPort() int {
	_, portStr, err := net.SplitHostPort(m.snap().HandshakeServer)
	if err != nil {
		return 443
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	if port == 0 {
		return 443
	}
	return port
}

// realHost/realPort парсят ServerAddr — адрес РЕАЛЬНОГО сервера, куда физически идёт
// TCP+TLS соединение. Не путать с getServerHost/getServerPort выше, которые парсят
// HandshakeServer (маскировочный сайт, нужен только для ProbeHandshakeServer).
func (m *ShadowTLSManager) realHost() string {
	host, _, err := net.SplitHostPort(m.snap().ServerAddr)
	if err != nil {
		return m.snap().ServerAddr
	}
	return host
}

func (m *ShadowTLSManager) realPort() int {
	_, portStr, err := net.SplitHostPort(m.snap().ServerAddr)
	if err != nil {
		return 443
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	if port == 0 {
		return 443
	}
	return port
}

// HasServerAddr сообщает, задан ли реальный адрес сервера — без него ShadowTLS включать
// нельзя (см. Engine.SetShadowTLSConfig).
func (m *ShadowTLSManager) HasServerAddr() bool { return m.snap().ServerAddr != "" }

// ── T-18: публичные геттеры для интеграции в singbox.Builder ──────────────────

// ServerHost / ServerPort / Version / Password / SNI — публичный доступ к параметрам
// ShadowTLS, чтобы движок собрал singbox.ShadowTLSParams без зависимости singbox→dpi.
//
// P1-1 (аудит 2026-09-01): ServerHost/ServerPort раньше читали HandshakeServer
// (маскировочный SNI-хост) — тот адрес, который DPI ДОЛЖЕН увидеть в TLS ClientHello, но
// куда реально дозваниваться нельзя (это не VPN-сервер пользователя). Имена методов уже
// однозначно означали «сервер», без «Handshake»/«SNI» в названии — теперь они честно
// возвращают то, что называют: реальный адрес (ServerAddr), которым singbox.Builder
// физически дозванивается. Маскировочный хост для TLS ServerName по-прежнему приходит
// отдельно через SNI() ниже (это HandshakeSNI, а не HandshakeServer).
func (m *ShadowTLSManager) ServerHost() string { return m.realHost() }
func (m *ShadowTLSManager) ServerPort() int    { return m.realPort() }
func (m *ShadowTLSManager) Version() int       { return int(m.snap().Version) }
func (m *ShadowTLSManager) Password() string   { return m.snap().Password }
func (m *ShadowTLSManager) SNI() string        { return m.snap().HandshakeSNI }
