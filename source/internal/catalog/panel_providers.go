package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/parser"
	"github.com/apf/adaptive-pathfinder/internal/version"
)

// defaultPanelMeta returns a sensible ProviderMeta for paid panel providers
// when the meta field has not been explicitly initialised (e.g. in tests).
func defaultPanelMeta() ProviderMeta {
	return ProviderMeta{Region: "global", SpeedClass: "high", TrustScore: 0.9, Free: false, Price: "paid"}
}

// ── ThreeXUIProvider ──────────────────────────────────────────────────────────

// ThreeXUIProvider fetches nodes from a self-hosted 3X-UI panel.
type ThreeXUIProvider struct {
	cfg     PaidProviderConfig
	client  *http.Client
	meta    ProviderMeta
	enabled bool
}

func (p *ThreeXUIProvider) ID() string        { return p.cfg.ID }
func (p *ThreeXUIProvider) Name() string      { return p.cfg.Name }
func (p *ThreeXUIProvider) Type() string      { return "paid" }
func (p *ThreeXUIProvider) IsEnabled() bool   { return p.enabled }
func (p *ThreeXUIProvider) SetEnabled(v bool) { p.enabled = v }
func (p *ThreeXUIProvider) Meta() ProviderMeta {
	if p.meta.TrustScore <= 0 {
		return defaultPanelMeta()
	}
	return p.meta
}

// Fetch logs into the 3X-UI panel, retrieves inbounds, and returns enabled ones
// as nodes. Disabled inbounds (Enable==false) are silently skipped.
func (p *ThreeXUIProvider) Fetch(ctx context.Context) ([]*models.Node, error) {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Timeout: p.client.Timeout, Transport: p.client.Transport, Jar: jar}
	base := strings.TrimRight(p.cfg.URL, "/")

	// Login — stores session cookie in jar.
	form := url.Values{"username": {p.cfg.Username}, "password": {p.cfg.Password}}
	req, err := http.NewRequestWithContext(ctx, "POST", base+"/login",
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("3xui: login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("3xui: login: %w", err)
	}
	resp.Body.Close()

	// Fetch inbounds list.
	req2, err := http.NewRequestWithContext(ctx, "GET", base+"/panel/api/inbounds/list", nil)
	if err != nil {
		return nil, fmt.Errorf("3xui: list request: %w", err)
	}
	resp2, err := c.Do(req2)
	if err != nil {
		return nil, fmt.Errorf("3xui: list: %w", err)
	}
	defer resp2.Body.Close()
	// S-12 (ТЗ v1.4): тело читается с потолком, как образец на HiddifyProvider.Fetch
	// (10 МиБ), и ошибка чтения не проглатывается.
	body, err := io.ReadAll(io.LimitReader(resp2.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("3xui: read: %w", err)
	}

	var result struct {
		Obj []threeXInbound `json:"obj"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("3xui: parse: %w", err)
	}

	host := extractHost(p.cfg.URL)
	var nodes []*models.Node
	for _, ib := range result.Obj {
		if !ib.Enable {
			continue
		}
		if n := threeXInboundToNode(ib, host, p.cfg.Name, PaidSourceTag(p.cfg.ID)); n != nil {
			nodes = append(nodes, n)
		}
	}
	p.meta.NodeCount = len(nodes)
	p.meta.LastUpdated = time.Now()
	return nodes, nil
}

// ── MarzbanProvider ───────────────────────────────────────────────────────────

type MarzbanProvider struct {
	cfg     PaidProviderConfig
	client  *http.Client
	meta    ProviderMeta
	enabled bool
}

func (p *MarzbanProvider) ID() string        { return p.cfg.ID }
func (p *MarzbanProvider) Name() string      { return p.cfg.Name }
func (p *MarzbanProvider) Type() string      { return "paid" }
func (p *MarzbanProvider) IsEnabled() bool   { return p.enabled }
func (p *MarzbanProvider) SetEnabled(v bool) { p.enabled = v }
func (p *MarzbanProvider) Meta() ProviderMeta {
	if p.meta.TrustScore <= 0 {
		return defaultPanelMeta()
	}
	return p.meta
}

func (p *MarzbanProvider) Fetch(ctx context.Context) ([]*models.Node, error) {
	base := strings.TrimRight(p.cfg.URL, "/")

	// 1. POST /api/admin/token — obtain bearer token.
	form := url.Values{
		"grant_type": {"password"},
		"username":   {p.cfg.Username},
		"password":   {p.cfg.Password},
	}
	req, err := http.NewRequestWithContext(ctx, "POST", base+"/api/admin/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("marzban: token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("marzban: token: %w", err)
	}
	// S-12 (ТЗ v1.4): тело читается с потолком (10 МиБ), ошибка чтения не проглатывается.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("marzban: read token: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("marzban: auth HTTP %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil || tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("marzban: parse token: %w", err)
	}
	bearer := "Bearer " + tokenResp.AccessToken

	// 2. GET /api/inbounds — inbound configurations.
	req2, err := http.NewRequestWithContext(ctx, "GET", base+"/api/inbounds", nil)
	if err != nil {
		return nil, fmt.Errorf("marzban: inbounds request: %w", err)
	}
	req2.Header.Set("Authorization", bearer)

	resp2, err := p.client.Do(req2)
	if err != nil {
		return nil, fmt.Errorf("marzban: inbounds: %w", err)
	}
	// S-12 (ТЗ v1.4): тело читается с потолком (10 МиБ), ошибка чтения не проглатывается.
	body2, err := io.ReadAll(io.LimitReader(resp2.Body, 10*1024*1024))
	resp2.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("marzban: read inbounds: %w", err)
	}
	if resp2.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("marzban: inbounds HTTP %d", resp2.StatusCode)
	}

	// Marzban returns: map[protocol_name][]inbound_config
	var inbounds map[string][]marzbanInbound
	if err := json.Unmarshal(body2, &inbounds); err != nil {
		return nil, fmt.Errorf("marzban: parse inbounds: %w", err)
	}

	host := extractHost(p.cfg.URL)
	var nodes []*models.Node
	for protoStr, ibs := range inbounds {
		proto := mapXProtocol(protoStr)
		if proto == "" {
			continue
		}
		for _, ib := range ibs {
			if n := marzbanInboundToNode(ib, proto, host, p.cfg.Name, PaidSourceTag(p.cfg.ID)); n != nil {
				nodes = append(nodes, n)
			}
		}
	}

	p.meta.NodeCount = len(nodes)
	p.meta.LastUpdated = time.Now()
	return nodes, nil
}

// ── HiddifyProvider ───────────────────────────────────────────────────────────

type HiddifyProvider struct {
	cfg     PaidProviderConfig
	client  *http.Client
	meta    ProviderMeta
	enabled bool
}

func (p *HiddifyProvider) ID() string        { return p.cfg.ID }
func (p *HiddifyProvider) Name() string      { return p.cfg.Name }
func (p *HiddifyProvider) Type() string      { return "paid" }
func (p *HiddifyProvider) IsEnabled() bool   { return p.enabled }
func (p *HiddifyProvider) SetEnabled(v bool) { p.enabled = v }
func (p *HiddifyProvider) Meta() ProviderMeta {
	if p.meta.TrustScore <= 0 {
		return defaultPanelMeta()
	}
	return p.meta
}

func (p *HiddifyProvider) Fetch(ctx context.Context) ([]*models.Node, error) {
	// Build subscription URL: prefer explicit SubscriptionURL, otherwise
	// compose from URL + Token + "/sub/".
	subURL := p.cfg.SubscriptionURL
	if subURL == "" {
		base := strings.TrimRight(p.cfg.URL, "/")
		token := strings.Trim(p.cfg.Token, "/")
		subURL = base + "/" + token + "/sub/"
	}

	req, err := http.NewRequestWithContext(ctx, "GET", subURL, nil)
	if err != nil {
		// P1-8 (аудит 2026-09-01): ошибку НЕ оборачиваем через %w — её текст содержит
		// полный URL, а в URL Hiddify токен подписки лежит прямо в пути
		// (base + "/" + token + "/sub/"). Выше по стеку это уходит в лог движка
		// ("Catalog: provider %s FAILED ...: %v"), а на Android — в постоянный файл,
		// который пользователь отправляет в поддержку кнопкой «Выгрузить лог».
		return nil, fmt.Errorf("hiddify: некорректный адрес подписки")
	}
	req.Header.Set("User-Agent", version.UserAgent())

	resp, err := p.client.Do(req)
	if err != nil {
		// P1-8: то же — *url.Error несёт полный URL с токеном.
		return nil, fmt.Errorf("hiddify: подписка недоступна")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hiddify: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("hiddify: read: %w", err)
	}

	// Response is base64-encoded subscription (same format as FreeSubscriptionProvider).
	content := string(body)
	if decoded, decErr := tryBase64Decode(content); decErr == nil {
		content = decoded
	}

	nodes, err := parser.ParseCatalogContent([]byte(content)) // F-12: + Clash YAML
	if err != nil {
		return nil, fmt.Errorf("hiddify: parse: %w", err)
	}

	for _, n := range nodes {
		n.Source = PaidSourceTag(p.cfg.ID)
	}
	p.meta.NodeCount = len(nodes)
	p.meta.LastUpdated = time.Now()
	return nodes, nil
}

// ── Marzban JSON structures ───────────────────────────────────────────────────

// marzbanInbound represents one entry from GET /api/inbounds (per-protocol slice).
type marzbanInbound struct {
	Tag        string `json:"tag"`
	Protocol   string `json:"protocol"`
	Port       int    `json:"port"`
	Network    string `json:"network"` // "tcp", "ws", "grpc", "h2"
	TLSType    string `json:"tls"`     // "none", "tls", "reality"
	SNI        string `json:"sni"`
	Host       string `json:"host"`
	Path       string `json:"path"`
	HeaderType string `json:"header_type,omitempty"`
}

// marzbanInboundToNode converts a Marzban inbound config to a *models.Node.
// host is the panel hostname. Returns nil if the port is 0 (invalid).
func marzbanInboundToNode(ib marzbanInbound, proto models.Protocol, host, panelName, sourceTag string) *models.Node {
	if ib.Port == 0 {
		return nil
	}
	tag := ib.Tag
	if tag == "" {
		tag = string(proto)
	}
	n := &models.Node{
		Name:     fmt.Sprintf("[%s] %s", panelName, tag),
		Protocol: proto,
		Address:  host,
		Port:     ib.Port,
		Source:   sourceTag,
		Status:   models.StatusUnknown,
		AddedAt:  time.Now(),
	}

	// Transport layer.
	switch strings.ToLower(ib.Network) {
	case "ws", "websocket":
		n.Transport = &models.TransportConfig{
			Type: "ws",
			Path: ib.Path,
			Host: ib.Host,
		}
	case "grpc":
		n.Transport = &models.TransportConfig{
			Type: "grpc",
			Path: ib.Path,
		}
	}

	// TLS / Reality.
	switch strings.ToLower(ib.TLSType) {
	case "tls":
		n.TLS = &models.TLSConfig{Enabled: true, ServerName: ib.SNI}
	case "reality":
		n.TLS = &models.TLSConfig{
			Enabled:    true,
			ServerName: ib.SNI,
			Reality:    &models.RealityConfig{},
		}
	}

	n.ID = generateNodeID(n)
	return n
}

// ── Marzban JSON structures ───────────────────────────────────────────────────

// threeXInbound represents one entry from /panel/api/inbounds/list .obj[].
type threeXInbound struct {
	ID             int    `json:"id"`
	Remark         string `json:"remark"`
	Protocol       string `json:"protocol"`
	Port           int    `json:"port"`
	Enable         bool   `json:"enable"`
	Settings       string `json:"settings"`       // JSON-encoded string
	StreamSettings string `json:"streamSettings"` // JSON-encoded string
}

type xSettings struct {
	Method  string    `json:"method,omitempty"` // Shadowsocks cipher
	Clients []xClient `json:"clients"`
}
type xClient struct {
	ID       string `json:"id"`       // VLESS / VMess UUID
	Password string `json:"password"` // Trojan / SS password
}
type xStreamSettings struct {
	Network  string            `json:"network"`
	Security string            `json:"security"`
	TLS      *xTLSSettings     `json:"tlsSettings,omitempty"`
	Reality  *xRealitySettings `json:"realitySettings,omitempty"`
	WS       *xWSSettings      `json:"wsSettings,omitempty"`
	GRPC     *xGRPCSettings    `json:"grpcSettings,omitempty"`
}
type xTLSSettings struct {
	ServerName string `json:"serverName"`
}
type xRealitySettings struct {
	ServerNames []string `json:"serverNames"`
	PublicKey   string   `json:"publicKey"`
	ShortIDs    []string `json:"shortIds"`
}
type xWSSettings struct {
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
}
type xGRPCSettings struct {
	ServiceName string `json:"serviceName"`
}

// ── threeXInboundToNode ───────────────────────────────────────────────────────

// threeXInboundToNode converts a 3X-UI inbound to a *models.Node.
// host is the panel hostname (port already stripped). Returns nil if the
// protocol is unrecognised or has no usable clients.
func threeXInboundToNode(ib threeXInbound, host, panelName, sourceTag string) *models.Node {
	proto := mapXProtocol(ib.Protocol)
	if proto == "" {
		return nil
	}

	var settings xSettings
	_ = json.Unmarshal([]byte(ib.Settings), &settings)

	var stream xStreamSettings
	_ = json.Unmarshal([]byte(ib.StreamSettings), &stream)

	node := &models.Node{
		Name:     fmt.Sprintf("[%s] %s", panelName, ib.Remark),
		Protocol: proto,
		Address:  host,
		Port:     ib.Port,
		Source:   sourceTag,
		Status:   models.StatusUnknown,
		AddedAt:  time.Now(),
	}

	// Credentials: use first client entry.
	if len(settings.Clients) > 0 {
		cl := settings.Clients[0]
		switch proto {
		case models.ProtoVLESS, models.ProtoVMess:
			node.UUID = cl.ID
		case models.ProtoTrojan:
			node.Password = cl.Password
		case models.ProtoShadowsocks:
			node.Method = settings.Method
			node.Password = cl.Password
		}
	}

	// Transport (ws / grpc; tcp needs nothing).
	switch stream.Network {
	case "ws":
		node.Transport = &models.TransportConfig{Type: "ws"}
		if stream.WS != nil {
			node.Transport.Path = stream.WS.Path
			if h, ok := stream.WS.Headers["Host"]; ok {
				node.Transport.Host = h
			}
		}
	case "grpc":
		node.Transport = &models.TransportConfig{Type: "grpc"}
		if stream.GRPC != nil {
			node.Transport.Path = stream.GRPC.ServiceName
		}
	}

	// TLS / Reality security.
	switch stream.Security {
	case "tls":
		node.TLS = &models.TLSConfig{Enabled: true}
		if stream.TLS != nil {
			node.TLS.ServerName = stream.TLS.ServerName
		}
	case "reality":
		node.TLS = &models.TLSConfig{Enabled: true}
		if stream.Reality != nil {
			shortID := ""
			if len(stream.Reality.ShortIDs) > 0 {
				shortID = stream.Reality.ShortIDs[0]
			}
			node.TLS.Reality = &models.RealityConfig{
				PublicKey: stream.Reality.PublicKey,
				ShortID:   shortID,
			}
			if len(stream.Reality.ServerNames) > 0 {
				node.TLS.ServerName = stream.Reality.ServerNames[0]
			}
		}
	}

	node.ID = generateNodeID(node)
	return node
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// mapXProtocol converts a 3X-UI protocol string to models.Protocol.
// Returns "" for protocols APF does not support yet.
func mapXProtocol(proto string) models.Protocol {
	switch strings.ToLower(proto) {
	case "vless":
		return models.ProtoVLESS
	case "vmess":
		return models.ProtoVMess
	case "trojan":
		return models.ProtoTrojan
	case "shadowsocks":
		return models.ProtoShadowsocks
	case "wireguard":
		return models.ProtoWireGuard
	default:
		return ""
	}
}

// extractHost parses rawURL and returns the hostname without port or path.
// Examples:
//
//	"https://panel.example.com:8080/x" → "panel.example.com"
//	"http://192.168.1.1:8080/path"     → "192.168.1.1"
func extractHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Hostname() // Hostname() strips port automatically.
}

// generateNodeID creates a short deterministic ID for a node.
// The ID depends on protocol, address, port, UUID, and password —
// same values always produce the same ID.
func generateNodeID(n *models.Node) string {
	key := fmt.Sprintf("%s|%s|%d|%s|%s", n.Protocol, n.Address, n.Port, n.UUID, n.Password)
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:8]) // 16 lowercase hex chars
}
