package singbox

import (
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// Инвариант P0-1 (аудит 2026-09-01): каждая ссылка на тег внутри конфигурации обязана
// разрешаться в реально объявленный outbound/endpoint.
//
// Почему этот файл существует отдельно от real_binary_schema_test.go: `sing-box check`
// останавливается на разборе конфигурации и НЕ доходит до Start(), где инициализируется
// detour DNS-сервера. Из-за этого режим цепочки был полностью неработоспособен
// ("outbound detour not found: proxy"), а весь набор тестов оставался зелёным.

func chainTestNodes() []*models.Node {
	return []*models.Node{
		{
			ID: "n1", Name: "entry", Protocol: models.ProtoVLESS,
			Address: "1.1.1.1", Port: 443, UUID: "11111111-1111-1111-1111-111111111111",
		},
		{
			ID: "n2", Name: "exit", Protocol: models.ProtoVLESS,
			Address: "2.2.2.2", Port: 443, UUID: "22222222-2222-2222-2222-222222222222",
		},
	}
}

func singleTestNode() *models.Node {
	return &models.Node{
		ID: "n1", Name: "one", Protocol: models.ProtoVLESS,
		Address: "1.1.1.1", Port: 443, UUID: "11111111-1111-1111-1111-111111111111",
	}
}

// Главный регресс: до фикса BuildChain отдавал конфиг, где dns-remote.detour == "proxy",
// а такого тега в цепочке нет вовсе — sing-box падал на Start().
func TestBuildChain_DNSDetourPointsAtChainEntry(t *testing.T) {
	b := NewBuilder(10808, false)
	cfg, err := b.BuildChain(&models.Chain{Nodes: chainTestNodes()})
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}

	var remote *DNSServer
	for i := range cfg.DNS.Servers {
		if cfg.DNS.Servers[i].Tag == "dns-remote" {
			remote = &cfg.DNS.Servers[i]
		}
	}
	if remote == nil {
		t.Fatal("сервер dns-remote отсутствует в конфигурации")
	}
	if remote.Detour != "chain-0" {
		t.Errorf("dns-remote.detour = %q, ожидалось \"chain-0\" (точка входа цепочки)", remote.Detour)
	}
	if remote.Detour == "proxy" {
		t.Error("регрессия P0-1: detour снова указывает на несуществующий в цепочке тег \"proxy\"")
	}
}

// Все четыре сборщика обязаны выдавать конфигурацию, проходящую инвариант.
func TestAllBuilders_ProduceResolvableTagRefs(t *testing.T) {
	t.Run("BuildSingle", func(t *testing.T) {
		cfg, err := NewBuilder(10808, false).BuildSingle(singleTestNode())
		if err != nil {
			t.Fatalf("BuildSingle: %v", err)
		}
		if err := validateTagRefs(cfg); err != nil {
			t.Errorf("BuildSingle: %v", err)
		}
	})

	t.Run("BuildSingle_TUN", func(t *testing.T) {
		cfg, err := NewBuilder(10808, true).BuildSingle(singleTestNode())
		if err != nil {
			t.Fatalf("BuildSingle(tun): %v", err)
		}
		if err := validateTagRefs(cfg); err != nil {
			t.Errorf("BuildSingle(tun): %v", err)
		}
	})

	t.Run("BuildChain", func(t *testing.T) {
		cfg, err := NewBuilder(10808, false).BuildChain(&models.Chain{Nodes: chainTestNodes()})
		if err != nil {
			t.Fatalf("BuildChain: %v", err)
		}
		if err := validateTagRefs(cfg); err != nil {
			t.Errorf("BuildChain: %v", err)
		}
	})

	t.Run("BuildChain_ThreeHops", func(t *testing.T) {
		nodes := append(chainTestNodes(), &models.Node{
			ID: "n3", Name: "mid", Protocol: models.ProtoVLESS,
			Address: "3.3.3.3", Port: 443, UUID: "33333333-3333-3333-3333-333333333333",
		})
		cfg, err := NewBuilder(10808, false).BuildChain(&models.Chain{Nodes: nodes})
		if err != nil {
			t.Fatalf("BuildChain(3): %v", err)
		}
		if err := validateTagRefs(cfg); err != nil {
			t.Errorf("BuildChain(3): %v", err)
		}
	})

	t.Run("BuildRace", func(t *testing.T) {
		cfg, err := NewBuilder(10808, false).BuildRace(chainTestNodes())
		if err != nil {
			t.Fatalf("BuildRace: %v", err)
		}
		if err := validateTagRefs(cfg); err != nil {
			t.Errorf("BuildRace: %v", err)
		}
	})

	t.Run("BuildTor", func(t *testing.T) {
		cfg := NewBuilder(10808, false).BuildTor()
		if err := validateTagRefs(cfg); err != nil {
			t.Errorf("BuildTor: %v", err)
		}
	})
}

// Инвариант обязан ловить висячие ссылки, а не только пропускать корректные.
func TestValidateTagRefs_RejectsDanglingRefs(t *testing.T) {
	base := func() *Config {
		return &Config{
			Outbounds: []Outbound{
				{Type: "vless", Tag: "proxy"},
				{Type: "direct", Tag: "direct"},
			},
			Route: RouteConfig{Final: "proxy"},
		}
	}

	t.Run("route.final", func(t *testing.T) {
		cfg := base()
		cfg.Route.Final = "chain-0"
		requireTagError(t, validateTagRefs(cfg), "route.final")
	})

	t.Run("dns detour", func(t *testing.T) {
		cfg := base()
		cfg.DNS.Servers = []DNSServer{{Type: "tcp", Tag: "dns-remote", Detour: "nope"}}
		requireTagError(t, validateTagRefs(cfg), "dns.server")
	})

	t.Run("outbound detour", func(t *testing.T) {
		cfg := base()
		cfg.Outbounds[0].Detour = "nope"
		requireTagError(t, validateTagRefs(cfg), "detour")
	})

	t.Run("urltest member", func(t *testing.T) {
		cfg := base()
		cfg.Outbounds[0].Outbounds = []string{"race-9"}
		requireTagError(t, validateTagRefs(cfg), "outbounds")
	})

	t.Run("route rule outbound", func(t *testing.T) {
		cfg := base()
		cfg.Route.Rules = []RouteRule{{Outbound: "nope"}}
		requireTagError(t, validateTagRefs(cfg), "route.rules")
	})

	t.Run("duplicate tag", func(t *testing.T) {
		cfg := base()
		cfg.Outbounds = append(cfg.Outbounds, Outbound{Type: "direct", Tag: "direct"})
		if err := validateTagRefs(cfg); err == nil {
			t.Error("дубликат тега обязан отвергаться (sing-box: duplicate outbound/endpoint tag)")
		}
	})

	t.Run("endpoint tag resolves", func(t *testing.T) {
		cfg := &Config{
			Endpoints: []Endpoint{{Type: "wireguard", Tag: "proxy"}},
			Outbounds: []Outbound{{Type: "direct", Tag: "direct"}},
			Route:     RouteConfig{Final: "proxy"},
			DNS:       DNSConfig{Servers: []DNSServer{{Tag: "dns-remote", Detour: "proxy"}}},
		}
		if err := validateTagRefs(cfg); err != nil {
			t.Errorf("тег endpoint'а должен разрешаться наравне с outbound: %v", err)
		}
	})
}

func requireTagError(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("ожидалась ошибка про %q, получено nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("ошибка %q не упоминает %q", err.Error(), want)
	}
}
