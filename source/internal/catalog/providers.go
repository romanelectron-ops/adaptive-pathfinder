// Package catalog — фреймворк провайдеров узлов для APF.
//
// Архитектура:
//
//	Provider (интерфейс) — один источник узлов (бесплатный или платный)
//	Registry — реестр всех провайдеров
//	Fetcher — агрегатор, скачивает параллельно из всех активных провайдеров
package catalog

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/netguard"
	"github.com/apf/adaptive-pathfinder/internal/parser"
	"github.com/apf/adaptive-pathfinder/internal/version"
)

// ─── Provider интерфейс ───────────────────────────────────────────────────────

// Provider — единый интерфейс источника узлов.
type Provider interface {
	ID() string
	Name() string
	Type() string // "free", "paid", "manual", "tor"
	Fetch(ctx context.Context) ([]*models.Node, error)
	IsEnabled() bool
	Meta() ProviderMeta
}

// ProviderMeta — метаданные провайдера для UI
type ProviderMeta struct {
	Region      string    `json:"region"`
	SpeedClass  string    `json:"speed_class"`
	TrustScore  float64   `json:"trust_score"`
	Free        bool      `json:"free"`
	Price       string    `json:"price,omitempty"`
	LastUpdated time.Time `json:"last_updated"`
	NodeCount   int       `json:"node_count"`
}

// ─── FreeSubscriptionProvider ─────────────────────────────────────────────────

// FreeSubscriptionProvider загружает узлы из публичных подписок (base64 или plaintext).
type FreeSubscriptionProvider struct {
	id      string
	name    string
	url     string
	enabled bool
	mu      sync.RWMutex // B-11: meta мутируется в Fetch (параллельно в FetchAll) и читается в Meta()
	meta    ProviderMeta
	client  *http.Client
}

func NewFreeProvider(id, name, url string) *FreeSubscriptionProvider {
	return &FreeSubscriptionProvider{
		id:      id,
		name:    name,
		url:     url,
		enabled: true,
		meta: ProviderMeta{
			Region:     "global",
			SpeedClass: "variable",
			TrustScore: 0.5,
			Free:       true,
		},
		// netguard, а не голый http.Client: под `go test` выход за пределы петли
		// отвергается (Т-5). Иначе каждый прогон качал каталоги у сторонних
		// поставщиков — тысячи узлов, время прогона по погоде в интернете.
		client: netguard.Client(30 * time.Second),
	}
}

func (p *FreeSubscriptionProvider) ID() string        { return p.id }
func (p *FreeSubscriptionProvider) Name() string      { return p.name }
func (p *FreeSubscriptionProvider) Type() string      { return "free" }
func (p *FreeSubscriptionProvider) IsEnabled() bool   { return p.enabled }
func (p *FreeSubscriptionProvider) SetEnabled(v bool) { p.enabled = v }
func (p *FreeSubscriptionProvider) Meta() ProviderMeta {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.meta
}

func (p *FreeSubscriptionProvider) Fetch(ctx context.Context) ([]*models.Node, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", version.UserAgent())

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", p.name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: HTTP %d", p.name, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	content := string(body)
	if decoded, err := tryBase64Decode(content); err == nil {
		content = decoded
	}

	// F-12 (T-12): ParseCatalogContent распознаёт и Clash YAML (nomore-walls .yml),
	// не только link/base64-подписки — закрывает «остров» ParseClashYAML и nomore-walls=0.
	nodes, err := parser.ParseCatalogContent([]byte(content))
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", p.name, err)
	}

	for _, n := range nodes {
		n.Source = p.id
	}

	// B-11 (дефект D9): метаданные вычисляются из ФАКТА загрузки, а не захардкожены.
	// Без живых health-проб (их делает checker отдельно) достоверно доступны: число
	// узлов, факт успешной свежей загрузки, разнообразие протоколов. TrustScore растёт
	// с числом узлов (источник, отдавший много рабочих ссылок, надёжнее пустого).
	p.mu.Lock()
	p.meta.NodeCount = len(nodes)
	p.meta.LastUpdated = time.Now()
	p.meta.TrustScore = trustFromNodeCount(len(nodes))
	p.meta.SpeedClass = speedClassFromNodes(nodes)
	p.mu.Unlock()
	return nodes, nil
}

// trustFromNodeCount отображает число загруженных узлов в [0..1]: пустой источник — 0,
// насыщение к 1.0 при ~200 узлах. Это объективная, прослеживаемая к замеру величина,
// а не выдуманная константа (инвариант B-11).
func trustFromNodeCount(n int) float64 {
	if n <= 0 {
		return 0
	}
	score := float64(n) / 200.0
	if score > 1.0 {
		score = 1.0
	}
	// нижняя планка для непустого источника, чтобы его не считали мёртвым
	if score < 0.2 {
		score = 0.2
	}
	return score
}

// speedClassFromNodes грубо классифицирует «класс скорости» по доминирующему протоколу
// среди загруженных узлов (Reality/Trojan/VLESS — fast; Tor/SS-plain — slow; иначе variable).
func speedClassFromNodes(nodes []*models.Node) string {
	if len(nodes) == 0 {
		return "unknown"
	}
	fast, slow := 0, 0
	for _, n := range nodes {
		switch {
		case strings.Contains(string(n.Protocol), "reality"),
			strings.Contains(string(n.Protocol), "trojan"),
			strings.Contains(string(n.Protocol), "vless"):
			fast++
		case strings.Contains(string(n.Protocol), "tor"),
			n.Protocol == "shadowsocks", n.Protocol == "ss":
			slow++
		}
	}
	switch {
	case fast > len(nodes)/2:
		return "fast"
	case slow > len(nodes)/2:
		return "slow"
	default:
		return "variable"
	}
}

func tryBase64Decode(s string) (string, error) {
	s = strings.TrimSpace(s)
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return "", err
		}
	}
	return string(b), nil
}

// ─── TorBridgeProvider ────────────────────────────────────────────────────────

type TorBridgeProvider struct {
	enabled bool
	meta    ProviderMeta
}

func NewTorBridgeProvider() *TorBridgeProvider {
	return &TorBridgeProvider{
		enabled: true,
		meta:    ProviderMeta{Region: "global", SpeedClass: "slow", TrustScore: 0.95, Free: true},
	}
}

func (p *TorBridgeProvider) ID() string         { return "tor-bridges" }
func (p *TorBridgeProvider) Name() string       { return "Tor Bridges" }
func (p *TorBridgeProvider) Type() string       { return "tor" }
func (p *TorBridgeProvider) IsEnabled() bool    { return p.enabled }
func (p *TorBridgeProvider) Meta() ProviderMeta { return p.meta }

func (p *TorBridgeProvider) Fetch(_ context.Context) ([]*models.Node, error) {
	node := &models.Node{
		ID:       fmt.Sprintf("tor-bridge-%d", time.Now().Unix()),
		Name:     "Tor Network (Snowflake)",
		Protocol: models.ProtoTor,
		Source:   "tor-bridges",
		AddedAt:  time.Now(),
		Status:   models.StatusUnknown,
		Score:    0.3,
	}
	return []*models.Node{node}, nil
}

// ─── ManualProvider ───────────────────────────────────────────────────────────

type ManualProvider struct {
	mu    sync.RWMutex
	nodes []*models.Node
}

func NewManualProvider() *ManualProvider { return &ManualProvider{} }

func (p *ManualProvider) ID() string      { return "manual" }
func (p *ManualProvider) Name() string    { return "Ручные узлы" }
func (p *ManualProvider) Type() string    { return "manual" }
func (p *ManualProvider) IsEnabled() bool { return true }
func (p *ManualProvider) Meta() ProviderMeta {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return ProviderMeta{Free: true, NodeCount: len(p.nodes), TrustScore: 1.0}
}

func (p *ManualProvider) Fetch(_ context.Context) ([]*models.Node, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*models.Node, len(p.nodes))
	copy(out, p.nodes)
	return out, nil
}

func (p *ManualProvider) AddNode(n *models.Node) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nodes = append(p.nodes, n)
}

func (p *ManualProvider) RemoveNode(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	filtered := p.nodes[:0]
	for _, n := range p.nodes {
		if n.ID != id {
			filtered = append(filtered, n)
		}
	}
	p.nodes = filtered
}

// ─── Registry ─────────────────────────────────────────────────────────────────

// Registry хранит провайдеры и управляет ими.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
	order     []string
}

func NewRegistry() *Registry {
	r := &Registry{providers: make(map[string]Provider)}
	for _, p := range DefaultFreeProviders() {
		r.Register(p)
	}
	r.Register(NewTorBridgeProvider())
	r.Register(NewManualProvider())
	return r
}

func (r *Registry) Register(p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.providers[p.ID()]; !exists {
		r.order = append(r.order, p.ID())
	}
	r.providers[p.ID()] = p
}

// Unregister убирает провайдера из реестра.
//
// P1-7 (аудит 2026-09-01): метода удаления не существовало вовсе, и Engine.RemovePaidProvider
// его не вызывал. Провайдер, удалённый пользователем из UI и из cfg.PaidProviders, оставался
// в реестре и продолжал опрашиваться при каждом RefreshCatalog — с сохранёнными учётными
// данными (логин/пароль панели), до перезапуска процесса.
//
// Возвращает true, если провайдер был найден и удалён.
func (r *Registry) Unregister(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.providers[id]; !ok {
		return false
	}
	delete(r.providers, id)
	for i, oid := range r.order {
		if oid == id {
			r.order = append(r.order[:i], r.order[i+1:]...)
			break
		}
	}
	return true
}

func (r *Registry) Get(id string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[id]
	return p, ok
}

func (r *Registry) All() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Provider, 0, len(r.order))
	for _, id := range r.order {
		if p, ok := r.providers[id]; ok {
			out = append(out, p)
		}
	}
	return out
}

func (r *Registry) Enabled() []Provider {
	var out []Provider
	for _, p := range r.All() {
		if p.IsEnabled() {
			out = append(out, p)
		}
	}
	return out
}

// Status — для /api/catalog/status
func (r *Registry) Status() []map[string]interface{} {
	out := make([]map[string]interface{}, 0)
	for _, p := range r.All() {
		m := p.Meta()
		out = append(out, map[string]interface{}{
			"id":           p.ID(),
			"name":         p.Name(),
			"type":         p.Type(),
			"enabled":      p.IsEnabled(),
			"trust_score":  m.TrustScore,
			"node_count":   m.NodeCount,
			"last_updated": m.LastUpdated,
			"free":         m.Free,
			"region":       m.Region,
			"speed_class":  m.SpeedClass,
		})
	}
	return out
}

// SetEnabled включает/выключает провайдера по ID
func (r *Registry) SetEnabled(id string, enabled bool) bool {
	r.mu.RLock()
	p, ok := r.providers[id]
	r.mu.RUnlock()
	if !ok {
		return false
	}
	type toggler interface{ SetEnabled(bool) }
	if t, ok := p.(toggler); ok {
		t.SetEnabled(enabled)
		return true
	}
	return false
}

// ─── Fetcher ──────────────────────────────────────────────────────────────────

// FetchResult — результат от одного провайдера
type FetchResult struct {
	ProviderID string
	Nodes      []*models.Node
	Error      error
	Duration   time.Duration
}

// Fetcher параллельно загружает узлы из всех активных провайдеров.
type Fetcher struct {
	registry *Registry
}

func NewFetcher(registry *Registry) *Fetcher {
	return &Fetcher{registry: registry}
}

// FetchAll загружает и дедуплицирует узлы из всех активных провайдеров.
func (f *Fetcher) FetchAll(ctx context.Context) ([]*models.Node, []FetchResult) {
	providers := f.registry.Enabled()
	if len(providers) == 0 {
		return nil, nil
	}

	ch := make(chan FetchResult, len(providers))
	var wg sync.WaitGroup

	for _, p := range providers {
		wg.Add(1)
		go func(prov Provider) {
			defer wg.Done()
			t := time.Now()
			nodes, err := prov.Fetch(ctx)
			ch <- FetchResult{prov.ID(), nodes, err, time.Since(t)}
		}(p)
	}

	go func() { wg.Wait(); close(ch) }()

	seen := make(map[string]bool)
	var allNodes []*models.Node
	var results []FetchResult

	for res := range ch {
		results = append(results, res)
		for _, n := range res.Nodes {
			if !seen[n.ID] {
				seen[n.ID] = true
				allNodes = append(allNodes, n)
			}
		}
	}

	return allNodes, results
}

// DefaultFreeProviders — список дефолтных публичных провайдеров.
//
// ID "v2ray-aggregator" (не короче "v2ray-agg") — намеренно совпадает с ID того же
// источника в models.DefaultConfig().Sources (internal/sources, старая система
// начальной загрузки пула). Узлы, загруженные оттуда при старте, помечаются
// n.Source = "v2ray-aggregator" (providers.go, тот же приём) — до этой правки здесь
// стояло "v2ray-agg", из-за чего Registry.Status() не находил в e.nodes ни одного узла
// с таким Source и «Каталог серверов» показывал 0 узлов даже при тысячах в пуле.
func DefaultFreeProviders() []*FreeSubscriptionProvider {
	return []*FreeSubscriptionProvider{
		NewFreeProvider("v2ray-aggregator", "V2RayAggregator",
			"https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge_base64.txt"),
		NewFreeProvider("freefq", "freefq/free",
			"https://raw.githubusercontent.com/freefq/free/master/v2"),
		NewFreeProvider("nomore-walls", "NoMoreWalls",
			"https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.yml"),
		NewFreeProvider("awesome-vpn", "awesome-vpn",
			"https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all"),
	}
}
