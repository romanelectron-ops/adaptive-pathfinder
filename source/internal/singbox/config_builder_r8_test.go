package singbox

import (
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── B-0403 · R-8 (C-14) · закрепление резолвнутого IP узла ──────────────────

func tlsNode(addr string) *models.Node {
	return &models.Node{
		Protocol: models.ProtoVLESS,
		Address:  addr,
		Port:     443,
		UUID:     "11111111-2222-3333-4444-555555555555",
		TLS:      &models.TLSConfig{Enabled: true},
	}
}

func outboundByTag(t *testing.T, cfg *Config, tag string) Outbound {
	t.Helper()
	for _, o := range cfg.Outbounds {
		if o.Tag == tag {
			return o
		}
	}
	t.Fatalf("outbound %q не найден", tag)
	return Outbound{}
}

// Главный смысл R-8: в конфигурацию уходит IP, а не домен, — иначе sing-box резолвит его сам
// через dns-local (detour: direct), то есть открытым UDP мимо туннеля.
func TestPinServerIP_DomainReplacedByIP(t *testing.T) {
	b := NewBuilder(10808, false)
	b.SetServerIP("203.0.113.10")

	cfg, err := b.BuildSingle(tlsNode("vpn.example.com"))
	if err != nil {
		t.Fatalf("BuildSingle: %v", err)
	}
	out := outboundByTag(t, cfg, "proxy")

	if out.Server != "203.0.113.10" {
		t.Errorf("Server = %q, ожидался закреплённый IP", out.Server)
	}
	// Без переноса домена в SNI сервер отверг бы хендшейк: TLS с SNI, равным IP, невалиден.
	if out.TLS == nil || out.TLS.ServerName != "vpn.example.com" {
		t.Errorf("домен не перенесён в server_name: %+v", out.TLS)
	}
}

// Явно заданный server_name — воля пользователя (домен-маскировка, Reality) и перетираться не должен.
func TestPinServerIP_ExplicitServerNameKept(t *testing.T) {
	node := tlsNode("vpn.example.com")
	node.TLS.ServerName = "www.microsoft.com"

	b := NewBuilder(10808, false)
	b.SetServerIP("203.0.113.10")
	cfg, err := b.BuildSingle(node)
	if err != nil {
		t.Fatalf("BuildSingle: %v", err)
	}
	out := outboundByTag(t, cfg, "proxy")

	if out.TLS.ServerName != "www.microsoft.com" {
		t.Errorf("server_name перетёрт: %q", out.TLS.ServerName)
	}
	if out.Server != "203.0.113.10" {
		t.Errorf("Server = %q, ожидался закреплённый IP", out.Server)
	}
}

// Fail-safe: закрепление пропускается, а не портит конфигурацию.
func TestPinServerIP_FailSafeCases(t *testing.T) {
	cases := []struct {
		name, addr, pin, wantServer string
	}{
		{"пустой IP — домен остаётся", "vpn.example.com", "", "vpn.example.com"},
		{"мусор вместо IP — домен остаётся", "vpn.example.com", "не-IP", "vpn.example.com"},
		{"адрес уже IP — не трогаем", "198.51.100.7", "203.0.113.10", "198.51.100.7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := NewBuilder(10808, false)
			b.SetServerIP(tc.pin)
			cfg, err := b.BuildSingle(tlsNode(tc.addr))
			if err != nil {
				t.Fatalf("BuildSingle: %v", err)
			}
			if got := outboundByTag(t, cfg, "proxy").Server; got != tc.wantServer {
				t.Errorf("Server = %q, want %q", got, tc.wantServer)
			}
		})
	}
}

// Узел без TLS: подмена адреса допустима, но выдумывать TLS-секцию нельзя.
func TestPinServerIP_NoTLSSectionInvented(t *testing.T) {
	node := &models.Node{Protocol: models.ProtoShadowsocks, Address: "vpn.example.com",
		Port: 8388, Password: "p", Method: "aes-256-gcm"}

	b := NewBuilder(10808, false)
	b.SetServerIP("203.0.113.10")
	cfg, err := b.BuildSingle(node)
	if err != nil {
		t.Fatalf("BuildSingle: %v", err)
	}
	out := outboundByTag(t, cfg, "proxy")
	if out.Server != "203.0.113.10" {
		t.Errorf("Server = %q", out.Server)
	}
	if out.TLS != nil {
		t.Errorf("у узла без TLS появилась TLS-секция: %+v", out.TLS)
	}
}

// ─── Точка входа цепочки ────────────────────────────────────────────────────

// Инвариант проверяется ПО ГОТОВОМУ КОНФИГУ, а не по моему прочтению кода: точка входа —
// единственный прокси-outbound без detour, потому что только его соединение хост устанавливает сам.
func TestChainEntryNode_MatchesOutboundWithoutDetour(t *testing.T) {
	chain := &models.Chain{Nodes: []*models.Node{
		tlsNode("exit.example.com"),
		tlsNode("middle.example.com"),
		tlsNode("entry.example.com"),
	}}

	b := NewBuilder(10808, false)
	cfg, err := b.BuildChain(chain)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}

	var entryTag string
	for _, o := range cfg.Outbounds {
		if o.Type == "direct" || o.Detour != "" {
			continue
		}
		if entryTag != "" {
			t.Fatalf("прокси-outbound без detour больше одного: %q и %q", entryTag, o.Tag)
		}
		entryTag = o.Tag
	}
	if entryTag == "" {
		t.Fatal("не найден прокси-outbound без detour")
	}

	entry := ChainEntryNode(chain)
	if entry == nil {
		t.Fatal("ChainEntryNode вернул nil")
	}
	if got := outboundByTag(t, cfg, entryTag).Server; got != entry.Address {
		t.Errorf("ChainEntryNode = %q, а без detour идёт %q — Kill Switch разрешит не тот адрес",
			entry.Address, got)
	}
	// Точка выхода — Route.Final; она не должна совпадать с точкой входа при длине > 1.
	if cfg.Route.Final == entryTag {
		t.Errorf("точка входа %q совпала с Route.Final — цепочка выродилась", entryTag)
	}
}

func TestChainEntryNode_EdgeCases(t *testing.T) {
	if ChainEntryNode(nil) != nil {
		t.Error("nil-цепочка должна давать nil")
	}
	if ChainEntryNode(&models.Chain{}) != nil {
		t.Error("пустая цепочка должна давать nil")
	}
}

// В цепочке закрепляется адрес ТОЛЬКО у точки входа: остальные узлы резолвятся уже внутри туннеля,
// и подмена их адресов сломала бы маршрутизацию, ничего не защитив.
func TestPinServerIP_ChainPinsOnlyEntry(t *testing.T) {
	chain := &models.Chain{Nodes: []*models.Node{
		tlsNode("exit.example.com"),
		tlsNode("entry.example.com"),
	}}

	b := NewBuilder(10808, false)
	b.SetServerIP("203.0.113.10")
	cfg, err := b.BuildChain(chain)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}

	pinned, domains := 0, 0
	for _, o := range cfg.Outbounds {
		if o.Type == "direct" {
			continue
		}
		if o.Server == "203.0.113.10" {
			pinned++
			if o.Detour != "" {
				t.Errorf("закреплён IP у узла с detour (%s) — он достижим только внутри туннеля", o.Tag)
			}
		}
		if strings.HasSuffix(o.Server, ".example.com") {
			domains++
		}
	}
	if pinned != 1 {
		t.Errorf("закреплённых узлов %d, ожидался ровно 1", pinned)
	}
	if domains != 1 {
		t.Errorf("узлов с доменом %d, ожидался ровно 1 (выходной)", domains)
	}
}
