// cdn_fronting.go — CDN Fronting через Cloudflare Workers. Фаза 6.
// bypass-engineer: трафик выглядит как обращение к Cloudflare → DPI не блокирует.
package dpi

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/netguard"
)

// CDNProvider — провайдер CDN для fronting
type CDNProvider struct {
	Name        string   // "Cloudflare"
	FrontDomain string   // домен в SNI: "cloudflare.com"
	CDNIPs      []string // IP-адреса CDN (Cloudflare anycast)
	WorkerPath  string   // путь к Worker endpoint
}

// CloudflareProvider — Cloudflare CDN fronting
// bypass-engineer: Cloudflare IP не блокируются в РФ (Cloudflare = CDN для тысяч сайтов)
var CloudflareProvider = &CDNProvider{
	Name:        "Cloudflare",
	FrontDomain: "cloudflare.com",
	CDNIPs: []string{
		"104.16.0.0", // Cloudflare anycast диапазон
		"104.17.0.0",
		"172.64.0.0",
		"162.158.0.0",
	},
	WorkerPath: "/cdn-cgi/trace",
}

// CDNFrontingConfig — настройки CDN fronting
type CDNFrontingConfig struct {
	Enabled       bool         `json:"enabled"`
	Provider      *CDNProvider `json:"provider"`
	WorkerDomain  string       `json:"worker_domain"`   // ваш worker: my-app.workers.dev
	BackendHost   string       `json:"backend_host"`    // реальный VPN-хост внутри Worker
	BackendPort   int          `json:"backend_port"`    // порт VPN-сервера
	TestBeforeUse bool         `json:"test_before_use"` // проверять доступность перед использованием
}

// DefaultCDNConfig — конфиг по умолчанию
func DefaultCDNConfig() *CDNFrontingConfig {
	return &CDNFrontingConfig{
		Enabled:       false,
		Provider:      CloudflareProvider,
		TestBeforeUse: true,
	}
}

// CDNFronter — управляет CDN fronting стратегией.
// bypass-engineer: подменяем SNI на CDN домен, Host header — на реальный backend.
type CDNFronter struct {
	cfg    *CDNFrontingConfig
	client *http.Client
}

// NewCDNFronter создаёт CDN fronter
func NewCDNFronter(cfg *CDNFrontingConfig) *CDNFronter {
	if cfg == nil {
		cfg = DefaultCDNConfig()
	}

	// Transport с кастомным DNS resolver:
	// bypass-engineer: резолвим CDN домен, подключаемся к его IP
	// но в Host header передаём реальный backend
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	transport := &http.Transport{
		// netguard.Guard: под `go test` выход за пределы петли отвергается (Т-5).
		DialContext:         netguard.Guard(dialer.DialContext),
		TLSHandshakeTimeout: 10 * time.Second,
		// DisableCompression: false (сжатие как у браузера)
	}

	return &CDNFronter{
		cfg: cfg,
		client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
	}
}

// IsAvailable проверяет доступность CDN (Cloudflare IP доступны из RU)
// IsEnabled сообщает, включён ли CDN-fronting (T-18 пара).
func (f *CDNFronter) IsEnabled() bool {
	return f.cfg != nil && f.cfg.Enabled && f.cfg.WorkerDomain != ""
}

func (f *CDNFronter) IsAvailable(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Пробуем подключиться к Cloudflare anycast IP
	for _, ip := range f.cfg.Provider.CDNIPs[:2] {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", ip+":443")
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// TestConnectivity проверяет полный CDN-путь
func (f *CDNFronter) TestConnectivity(ctx context.Context) *CDNTestResult {
	result := &CDNTestResult{
		Provider: f.cfg.Provider.Name,
		TestedAt: time.Now(),
	}

	// Шаг 1: Доступен ли CDN
	result.CDNReachable = f.IsAvailable(ctx)
	if !result.CDNReachable {
		result.Error = "CDN недоступен"
		return result
	}

	// Шаг 2: Тест через CDN trace endpoint
	ctx2, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx2, "GET",
		"https://"+f.cfg.Provider.FrontDomain+f.cfg.Provider.WorkerPath, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	// bypass-engineer: User-Agent как у реального браузера
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")

	start := time.Now()
	resp, err := f.client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("CDN trace failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.LatencyMs = time.Since(start).Milliseconds()
	result.HTTPStatus = resp.StatusCode
	result.Success = resp.StatusCode == 200

	return result
}

// BuildFrontedOutbound строит параметры sing-box outbound для CDN fronting.
// bypass-engineer: в sing-box настраиваем WebSocket с Host=CDN, server=CDN_IP.
//
// Схема:
//
//	Клиент → (SNI: cloudflare.com) → Cloudflare CDN → (Worker перенаправляет) → VPN Backend
//
// В sing-box это реализуется через WS транспорт + кастомный Host header.
func (f *CDNFronter) BuildFrontedOutbound() *FrontedOutboundParams {
	if !f.cfg.Enabled || f.cfg.WorkerDomain == "" {
		return nil
	}

	return &FrontedOutboundParams{
		// Подключаемся к CDN IP (не к реальному серверу)
		Server:     f.cfg.Provider.CDNIPs[0],
		ServerPort: 443,
		// SNI = CDN домен (DPI видит легитимный Cloudflare)
		SNI: f.cfg.Provider.FrontDomain,
		// WebSocket путь и Host header → Worker маршрутизирует к backend
		WSPath: "/ws",
		WSHost: f.cfg.WorkerDomain,
		// TLS обязательно (порт 443)
		TLSEnabled: true,
	}
}

// FrontedOutboundParams — параметры для построения fronted outbound в sing-box
type FrontedOutboundParams struct {
	Server     string
	ServerPort int
	SNI        string
	WSPath     string
	WSHost     string
	TLSEnabled bool
}

// CDNTestResult — результат теста CDN fronting
type CDNTestResult struct {
	Provider     string    `json:"provider"`
	CDNReachable bool      `json:"cdn_reachable"`
	Success      bool      `json:"success"`
	LatencyMs    int64     `json:"latency_ms"`
	HTTPStatus   int       `json:"http_status"`
	Error        string    `json:"error,omitempty"`
	TestedAt     time.Time `json:"tested_at"`
}

// CDNFronterStatus — статус CDN fronting для UI
type CDNFronterStatus struct {
	Enabled        bool           `json:"enabled"`
	Provider       string         `json:"provider"`
	WorkerDomain   string         `json:"worker_domain"`
	BackendHost    string         `json:"backend_host"`
	BackendPort    int            `json:"backend_port"`
	Available      bool           `json:"available"`
	LastTestResult *CDNTestResult `json:"last_test,omitempty"`
}

// GetStatus возвращает статус CDN fronting.
//
// BackendHost/BackendPort — задача #29, QA 2026-08-18: ни то, ни другое не секрет (в отличие
// от ShadowTLS-пароля), но раньше не попадало в статус вообще — диалог на Android не мог
// подставить сохранённые значения при повторном открытии, пользователь видел пустые поля,
// хотя конфиг реально был сохранён (подтверждаемо только логом/десктопной Диагностикой).
func (f *CDNFronter) GetStatus(ctx context.Context) *CDNFronterStatus {
	status := &CDNFronterStatus{
		Enabled:      f.cfg.Enabled,
		Provider:     f.cfg.Provider.Name,
		WorkerDomain: f.cfg.WorkerDomain,
		BackendHost:  f.cfg.BackendHost,
		BackendPort:  f.cfg.BackendPort,
	}

	if f.cfg.Enabled {
		status.Available = f.IsAvailable(ctx)
	}

	return status
}

// WorkerSetupInstructions возвращает инструкции для настройки Cloudflare Worker
// bypass-engineer: Worker проксирует WebSocket соединение к реальному серверу.
func WorkerSetupInstructions(backendHost string, backendPort int) string {
	return fmt.Sprintf(`// Cloudflare Worker для APF CDN Fronting
// Разверни на: https://workers.cloudflare.com

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const upgradeHeader = request.headers.get('Upgrade')
  if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
    // Проксируем WebSocket к VPN серверу
    return fetch('https://%s:%d' + new URL(request.url).pathname, {
      headers: request.headers,
      method: request.method,
    })
  }
  return new Response('OK', { status: 200 })
}

// После деплоя Worker:
// 1. Скопируй домен Worker (xxx.workers.dev)
// 2. Вставь в APF настройки → Защита → CDN Fronting → Worker Domain
// 3. Нажми "Проверить"
`, backendHost, backendPort)
}
