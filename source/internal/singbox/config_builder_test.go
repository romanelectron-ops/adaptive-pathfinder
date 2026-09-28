package singbox

import (
	"encoding/json"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// TestSetBypassDomains — раньше Builder.bypass был захардкожен на defaultBypass()
// (["localhost"]) без единого сеттера: internal/bypass.Manager хранил и персистил
// пользовательские "direct route" домены, но они никогда не попадали в реальный sing-box
// route rule — байпас не влиял на маршрутизацию ни на одной платформе. SetBypassDomains это
// закрывает; тест подтверждает, что домены реально попадают в правило {Outbound:"direct"}, и
// что дефолтный "localhost" не теряется.
func TestSetBypassDomains(t *testing.T) {
	b := NewBuilder(10808, false)
	b.SetBypassDomains([]string{"mybank.example", "*.mybank.example"})

	node := &models.Node{
		Protocol: models.ProtoVLESS,
		Address:  "test.example.com",
		Port:     443,
		UUID:     "12345678-1234-1234-1234-123456789012",
	}
	cfg, err := b.BuildSingle(node)
	if err != nil {
		t.Fatalf("BuildSingle failed: %v", err)
	}

	var found []string
	sawLocalhost := false
	for _, r := range cfg.Route.Rules {
		if r.Outbound != "direct" || len(r.DomainSuffix) == 0 {
			continue
		}
		found = append(found, r.DomainSuffix...)
	}
	for _, d := range found {
		if d == "localhost" {
			sawLocalhost = true
		}
	}
	if !sawLocalhost {
		t.Errorf("default bypass (localhost) should not be lost, got: %v", found)
	}
	hasMyBank := false
	for _, d := range found {
		if d == "mybank.example" {
			hasMyBank = true
		}
	}
	if !hasMyBank {
		t.Errorf("SetBypassDomains domain should reach route rules as direct outbound, got: %v", found)
	}
}

// TestSetBypassDomains_ForcesIPv4OnlyDNS — живой прогон 2026-08-13: маршрутизация direct-
// bypass домена была верной (route(direct)), но сам сокет падал с "network is unreachable" на
// IPv6 после protect() — dns.Strategy=prefer_ipv4 (глобальный) не действует на клиентские
// DNS-запросы, перехваченные в TUN (hijack-dns/Exchange, см. buildDNS). Тест подтверждает, что
// для доменов из байпаса добавляется DNS-правило action:"route-options" strategy:"ipv4_only" —
// это заставляет sing-box отвечать на AAAA "успех, без записей", и клиент откатывается на A.
func TestSetBypassDomains_ForcesIPv4OnlyDNS(t *testing.T) {
	b := NewBuilder(10808, false)
	b.SetBypassDomains([]string{"mybank.example"})

	node := &models.Node{
		Protocol: models.ProtoVLESS,
		Address:  "test.example.com",
		Port:     443,
		UUID:     "12345678-1234-1234-1234-123456789012",
	}
	cfg, err := b.BuildSingle(node)
	if err != nil {
		t.Fatalf("BuildSingle failed: %v", err)
	}

	var found *DNSRule
	for i, r := range cfg.DNS.Rules {
		for _, d := range r.DomainSuffix {
			if d == "mybank.example" {
				found = &cfg.DNS.Rules[i]
			}
		}
	}
	if found == nil {
		t.Fatalf("expected a DNS rule matching mybank.example, got rules: %+v", cfg.DNS.Rules)
	}
	if found.Action != "route-options" {
		t.Errorf("Action = %q, want %q", found.Action, "route-options")
	}
	if found.Strategy != "ipv4_only" {
		t.Errorf("Strategy = %q, want %q", found.Strategy, "ipv4_only")
	}
}

// TestSetBlockIPv6_AddsGlobalIPv4OnlyDNSRule — задача #18, живой QA 2026-08-17: тумблер
// "IPv6 Block" на Android был чистым no-op (leakguard.IPv6Guard.Enable не имеет ветки для
// GOOS=android). Тест подтверждает, что SetBlockIPv6(true) добавляет ГЛОБАЛЬНОЕ (без
// DomainSuffix/Domain) DNS-правило action:"route-options" strategy:"ipv4_only" — тот же
// механизм, что уже работает для bypass-доменов (TestSetBypassDomains_ForcesIPv4OnlyDNS), но
// без ограничения по домену.
func TestSetBlockIPv6_AddsGlobalIPv4OnlyDNSRule(t *testing.T) {
	b := NewBuilder(10808, false)
	b.SetBlockIPv6(true)

	node := &models.Node{
		Protocol: models.ProtoVLESS,
		Address:  "test.example.com",
		Port:     443,
		UUID:     "12345678-1234-1234-1234-123456789012",
	}
	cfg, err := b.BuildSingle(node)
	if err != nil {
		t.Fatalf("BuildSingle failed: %v", err)
	}

	var found *DNSRule
	for i, r := range cfg.DNS.Rules {
		if r.Action == "route-options" && r.Strategy == "ipv4_only" &&
			len(r.DomainSuffix) == 0 && len(r.Domain) == 0 {
			found = &cfg.DNS.Rules[i]
		}
	}
	if found == nil {
		t.Fatalf("expected a global (domain-unrestricted) ipv4_only DNS rule, got rules: %+v", cfg.DNS.Rules)
	}
}

// TestSetBlockIPv6_Disabled_NoGlobalRule — по умолчанию (или явно false) правило не должно
// добавляться: пользователь мог сознательно не включать блокировку IPv6.
func TestSetBlockIPv6_Disabled_NoGlobalRule(t *testing.T) {
	b := NewBuilder(10808, false)

	node := &models.Node{
		Protocol: models.ProtoVLESS,
		Address:  "test.example.com",
		Port:     443,
		UUID:     "12345678-1234-1234-1234-123456789012",
	}
	cfg, err := b.BuildSingle(node)
	if err != nil {
		t.Fatalf("BuildSingle failed: %v", err)
	}

	for _, r := range cfg.DNS.Rules {
		if r.Action == "route-options" && r.Strategy == "ipv4_only" &&
			len(r.DomainSuffix) == 0 && len(r.Domain) == 0 {
			t.Errorf("did not expect a global ipv4_only DNS rule when SetBlockIPv6 was never called, got rules: %+v", cfg.DNS.Rules)
		}
	}
}

func TestBuildSingleVLESS(t *testing.T) {
	b := NewBuilder(10808, false)
	node := &models.Node{
		Protocol: models.ProtoVLESS,
		Address:  "test.example.com",
		Port:     443,
		UUID:     "12345678-1234-1234-1234-123456789012",
		Flow:     "xtls-rprx-vision",
		TLS: &models.TLSConfig{
			Enabled:    true,
			ServerName: "www.microsoft.com",
			Reality: &models.RealityConfig{
				PublicKey: "pubkey123",
				ShortID:   "abcdef01",
			},
		},
	}

	cfg, err := b.BuildSingle(node)
	if err != nil {
		t.Fatalf("BuildSingle failed: %v", err)
	}

	// Проверяем JSON
	data, err := ToJSON(cfg)
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	// Парсим обратно
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("JSON invalid: %v", err)
	}

	// Проверяем структуру
	if cfg.Route.Final != "proxy" {
		t.Errorf("expected final=proxy, got %s", cfg.Route.Final)
	}
	if len(cfg.Inbounds) < 2 {
		t.Errorf("expected at least 2 inbounds, got %d", len(cfg.Inbounds))
	}

	t.Logf("Config OK (%d bytes):\n%s", len(data), string(data[:func() int {
		if len(data) < 500 {
			return len(data)
		}
		return 500
	}()]))
}

func TestBuildChain(t *testing.T) {
	b := NewBuilder(10808, false)
	chain := &models.Chain{
		Nodes: []*models.Node{
			{
				Protocol: models.ProtoVLESS,
				Address:  "vpn.example.com",
				Port:     443,
				UUID:     "uuid-node-1",
				TLS:      &models.TLSConfig{Enabled: true, ServerName: "vpn.example.com"},
			},
			{
				Protocol: models.ProtoShadowsocks,
				Address:  "proxy.example.com",
				Port:     8388,
				Method:   "chacha20-ietf-poly1305",
				Password: "mypassword",
			},
		},
	}

	cfg, err := b.BuildChain(chain)
	if err != nil {
		t.Fatalf("BuildChain failed: %v", err)
	}

	// Находим chain-0 outbound
	var chain0 *Outbound
	for i := range cfg.Outbounds {
		if cfg.Outbounds[i].Tag == "chain-0" {
			chain0 = &cfg.Outbounds[i]
			break
		}
	}
	if chain0 == nil {
		t.Fatal("chain-0 outbound not found")
	}
	// chain-0 должен иметь detour на chain-1
	if chain0.Detour != "chain-1" {
		t.Errorf("chain-0 detour should be chain-1, got: %s", chain0.Detour)
	}

	t.Logf("Chain config OK, %d outbounds, final=%s", len(cfg.Outbounds), cfg.Route.Final)
}

func TestBuildTor(t *testing.T) {
	b := NewBuilder(10808, false)
	cfg := b.BuildTor()

	hastor := false
	for _, out := range cfg.Outbounds {
		if out.Type == "tor" {
			hastor = true
			break
		}
	}
	if !hastor {
		t.Error("Tor outbound not found")
	}
	t.Logf("Tor config OK, final=%s", cfg.Route.Final)
}

func TestDNSLeakProtection(t *testing.T) {
	b := NewBuilder(10808, true)
	cfg := b.baseConfig("proxy")

	// DNS-сервер для внешних запросов должен идти через туннель (detour=proxy)
	// В buildDNS() этот сервер имеет тег "dns-remote"
	hasRemote := false
	for _, srv := range cfg.DNS.Servers {
		if srv.Detour == "proxy" {
			hasRemote = true
			break
		}
	}
	if !hasRemote {
		t.Error("DNS leak protection not configured: no DNS server routes through proxy tunnel")
	}
	t.Log("DNS leak protection OK")
}

func TestTUNMode(t *testing.T) {
	b := NewBuilder(10808, true) // TUN включён
	cfg := b.baseConfig("proxy")

	hasTUN := false
	for _, in := range cfg.Inbounds {
		if in.Type == "tun" {
			hasTUN = true
			if in.TunOptions == nil {
				t.Error("TUN options not set")
			} else {
				if !in.TunOptions.AutoRoute {
					t.Error("AutoRoute should be enabled")
				}
				// Sprint 1 fix: StrictRoute = false предотвращает блокировку всего трафика.
				// Kill Switch реализован через отдельные правила файрвола (netsh/iptables),
				// а не через sing-box strict_route.
				if in.TunOptions.StrictRoute {
					t.Error("StrictRoute should be FALSE — strict_route=true blocks all traffic like a kill switch")
				}
			}
			break
		}
	}
	if !hasTUN {
		t.Error("TUN inbound not found")
	}

	// DNS-перехват в TUN-режиме обеспечивается route-правилом hijack-dns (buildRouteRules),
	// а НЕ полем inbound.tun.dns_hijack — у sing-box 1.13.16 такого поля не существует
	// (option.TunInboundOptions, vendor/.../option/tun.go); с ним sing-box отказывает разбирать
	// ЛЮБУЮ TUN-конфигурацию (находка 2026-08-10, приёмка Э-Выход-1 — "unknown field
	// dns_hijack", каждое подключение в VPN-режиме отказывало на этапе разбора конфигурации).
	hasHijackRule := false
	for _, r := range cfg.Route.Rules {
		if r.Action == "hijack-dns" {
			for _, p := range r.Protocol {
				if p == "dns" {
					hasHijackRule = true
				}
			}
		}
	}
	if !hasHijackRule {
		t.Error("DNS leak protection not configured: no route rule with action=hijack-dns for protocol=dns")
	}
	t.Log("TUN mode OK")
}

// ─── nodeToOutbound coverage tests ───────────────────────────────────────────

func TestNodeToOutboundAllProtocols(t *testing.T) {
	cases := []struct {
		name     string
		node     *models.Node
		wantType string
	}{
		{
			"VLESS basic",
			&models.Node{Protocol: models.ProtoVLESS, UUID: "test-uuid",
				Address: "host.example.com", Port: 443},
			"vless",
		},
		{
			"VMess basic",
			&models.Node{Protocol: models.ProtoVMess, UUID: "vm-uuid",
				Address: "host.example.com", Port: 443},
			"vmess",
		},
		{
			"Shadowsocks",
			&models.Node{Protocol: models.ProtoShadowsocks, Password: "pass",
				Method:  "chacha20-ietf-poly1305",
				Address: "host.example.com", Port: 8388},
			"shadowsocks",
		},
		{
			"Trojan",
			&models.Node{Protocol: models.ProtoTrojan, Password: "trojan-pass",
				Address: "host.example.com", Port: 443},
			"trojan",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := nodeToOutbound(c.node, "test")
			if err != nil {
				t.Fatalf("nodeToOutbound error: %v", err)
			}
			if out.Type != c.wantType {
				t.Errorf("type: want %s, got %s", c.wantType, out.Type)
			}
			if out.Tag != "test" {
				t.Errorf("tag: want test, got %s", out.Tag)
			}
		})
	}
	t.Log("OK: nodeToOutbound all protocols")
}

// Регрессия (консилиум 2026-08-10, CRITICAL): sing-box 1.13.16 (закреплённая версия
// проекта) безусловно регистрирует outbound-тип "wireguard" как заглушку, отвергающую
// ЛЮБОЕ подключение — "removed in sing-box 1.13.0, use WireGuard endpoint instead".
// nodeToOutbound обязан отвергать WireGuard/AmneziaWG явной ошибкой ДО BuildSingle/
// BuildChain, а не молча строить синтаксически валидный, но гарантированно нерабочий
// outbound (который раньше проходил ToJSON и любую JSON-схему без единой ошибки).
func TestNodeToOutbound_RejectsWireGuardOutboundType(t *testing.T) {
	cases := []struct {
		name string
		node *models.Node
	}{
		{
			"WireGuard",
			&models.Node{Protocol: models.ProtoWireGuard,
				WGPrivateKey: "priv", WGPublicKey: "pub",
				Address: "wg.example.com", Port: 51820},
		},
		{
			"AmneziaWG",
			&models.Node{Protocol: models.ProtoAmneziaWG,
				WGPrivateKey: "priv", WGPublicKey: "pub",
				AWGJc: 5, AWGJmin: 50, AWGJmax: 1000,
				Address: "awg.example.com", Port: 51820},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := nodeToOutbound(c.node, "test"); err == nil {
				t.Fatalf("nodeToOutbound(%s) = nil error, ожидался явный отказ "+
					"(outbound-тип wireguard удалён в sing-box 1.13.0)", c.name)
			}
		})
	}
}

// [TZ_TAILS_HARDENING_2026-08-31.md кластер B] Регрессия на прежний контракт: BuildSingle для
// ОБЫЧНОГО WireGuard-узла (не AmneziaWG) больше НЕ отказывает — endpoint-путь (nodeToEndpoint)
// теперь реализован для прямого одиночного подключения. Это ПРОТИВОПОЛОЖНЫЙ контракт тому,
// что проверял этот тест раньше — переписан, а не удалён: старое поведение (fail-fast для
// ЛЮБОГО WireGuard) было честной деградацией на момент находки консилиума, но раз endpoint-путь
// реализован, тест обязан проверять НОВЫЙ, а не старый контракт.
func TestBuildSingle_WireGuardNode_BuildsEndpointConfig(t *testing.T) {
	b := NewBuilder(10808, false)
	node := &models.Node{
		Protocol:       models.ProtoWireGuard,
		WGPrivateKey:   "cHJpdmF0ZWtleWJhc2U2NHBsYWNlaG9sZGVyMzJieXRlcw==",
		WGPublicKey:    "cHVibGlja2V5YmFzZTY0cGxhY2Vob2xkZXIzMmJ5dGVzeHg=",
		WGLocalAddress: "10.0.0.2/32",
		Address:        "wg.example.com",
		Port:           51820,
	}

	cfg, err := b.BuildSingle(node)
	if err != nil {
		t.Fatalf("BuildSingle(валидный WireGuard-узел) = %v, ожидался успех", err)
	}
	if len(cfg.Endpoints) != 1 {
		t.Fatalf("Config.Endpoints = %d записей, ожидалась 1", len(cfg.Endpoints))
	}
	ep := cfg.Endpoints[0]
	if ep.Type != "wireguard" || ep.Tag != "proxy" {
		t.Errorf("endpoint = {Type:%q Tag:%q}, ожидалось {wireguard, proxy}", ep.Type, ep.Tag)
	}
	if ep.PrivateKey != node.WGPrivateKey {
		t.Error("endpoint.PrivateKey не совпадает с узлом")
	}
	if len(ep.Address) != 1 || ep.Address[0] != node.WGLocalAddress {
		t.Errorf("endpoint.Address = %v, ожидался [%q]", ep.Address, node.WGLocalAddress)
	}
	if len(ep.Peers) != 1 || ep.Peers[0].PublicKey != node.WGPublicKey ||
		ep.Peers[0].Address != node.Address || ep.Peers[0].Port != uint16(node.Port) {
		t.Errorf("endpoint.Peers = %+v, не совпадает с узлом", ep.Peers)
	}
	// WireGuard НЕ идёт через Config.Outbounds (кроме служебного "direct") — endpoint-путь
	// принципиально отдельный top-level массив.
	for _, o := range cfg.Outbounds {
		if o.Tag == "proxy" {
			t.Error("тег \"proxy\" не должен встречаться в Outbounds для WireGuard-узла — " +
				"он живёт в Endpoints")
		}
	}
	if cfg.Route.Final != "proxy" {
		t.Errorf("Route.Final = %q, ожидался \"proxy\"", cfg.Route.Final)
	}
	// Сериализуется без паники/ошибки — минимальная гарантия, что структура валидна для JSON.
	if _, err := json.Marshal(cfg); err != nil {
		t.Fatalf("json.Marshal(cfg с WireGuard endpoint) = %v", err)
	}
}

// AmneziaWG остаётся неподдержанным — в вендоренном sing-box нет junk-обфускации ни в одном
// из путей, endpoint-путь для неё сознательно не реализован (nodeToEndpoint отдельно
// проверяет протокол, не полагаясь только на тот факт, что AmneziaWG не прошла бы через
// текущий switch в nodeToOutbound).
func TestBuildSingle_RejectsAmneziaWGNode(t *testing.T) {
	b := NewBuilder(10808, false)
	node := &models.Node{
		Protocol:       models.ProtoAmneziaWG,
		WGPrivateKey:   "priv",
		WGPublicKey:    "pub",
		WGLocalAddress: "10.0.0.2/32",
		AWGJc:          5, AWGJmin: 50, AWGJmax: 1000,
		Address: "awg.example.com", Port: 51820,
	}

	if _, err := b.BuildSingle(node); err == nil {
		t.Fatal("BuildSingle(AmneziaWG node) = nil error, ожидался явный отказ")
	}
}

// [TZ_TAILS_HARDENING_2026-08-31.md кластер B] CDN-фронтинг/ShadowTLS — TLS-специфичные
// обёртки поверх ДРУГОГО outbound'а, WireGuard не использует TLS вовсе — комбинация не должна
// молча игнорироваться (пользователь включил защиту, ожидает что она применяется), только
// честный отказ.
func TestBuildSingle_WireGuardWithCDNOrShadowTLS_Rejected(t *testing.T) {
	node := &models.Node{
		Protocol:       models.ProtoWireGuard,
		WGPrivateKey:   "priv",
		WGPublicKey:    "pub",
		WGLocalAddress: "10.0.0.2/32",
		Address:        "wg.example.com", Port: 51820,
	}

	t.Run("CDN", func(t *testing.T) {
		b := NewBuilder(10808, false)
		b.cdn = &CDNParams{}
		if _, err := b.BuildSingle(node); err == nil {
			t.Fatal("BuildSingle(WireGuard + CDN) = nil error, ожидался явный отказ")
		}
	})
	t.Run("ShadowTLS", func(t *testing.T) {
		b := NewBuilder(10808, false)
		b.shadowTLS = &ShadowTLSParams{}
		if _, err := b.BuildSingle(node); err == nil {
			t.Fatal("BuildSingle(WireGuard + ShadowTLS) = nil error, ожидался явный отказ")
		}
	})
}

// nodeToEndpoint дублирует проверку обязательных полей WireGuard из validate.go — на случай
// прямого вызова BuildSingle мимо валидации пула узлов (см. комментарий у nodeToEndpoint).
// Без WGLocalAddress sing-box отверг бы весь конфиг целиком ("wireguard: missing address"),
// поэтому BuildSingle обязан отказать раньше, с понятной причиной.
func TestBuildSingle_WireGuardNode_MissingLocalAddress_Rejected(t *testing.T) {
	b := NewBuilder(10808, false)
	node := &models.Node{
		Protocol:     models.ProtoWireGuard,
		WGPrivateKey: "priv",
		WGPublicKey:  "pub",
		// WGLocalAddress намеренно пуст.
		Address: "wg.example.com", Port: 51820,
	}
	if _, err := b.BuildSingle(node); err == nil {
		t.Fatal("BuildSingle(WireGuard без WGLocalAddress) = nil error, ожидался явный отказ")
	}
}

func TestBuildSingle_WireGuardNode_MissingKeys_Rejected(t *testing.T) {
	b := NewBuilder(10808, false)
	node := &models.Node{
		Protocol:       models.ProtoWireGuard,
		WGLocalAddress: "10.0.0.2/32",
		// WGPrivateKey/WGPublicKey намеренно пусты.
		Address: "wg.example.com", Port: 51820,
	}
	if _, err := b.BuildSingle(node); err == nil {
		t.Fatal("BuildSingle(WireGuard без ключей) = nil error, ожидался явный отказ")
	}
}

func TestNodeToOutboundWithTLS(t *testing.T) {
	// VLESS + Reality
	node := &models.Node{
		Protocol: models.ProtoVLESS,
		UUID:     "test-uuid",
		Address:  "host.example.com",
		Port:     443,
		Flow:     "xtls-rprx-vision",
		TLS: &models.TLSConfig{
			Enabled:    true,
			ServerName: "www.microsoft.com",
			Reality: &models.RealityConfig{
				PublicKey: "test-pubkey",
				ShortID:   "abcdef",
			},
		},
	}
	out, err := nodeToOutbound(node, "vless-reality")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if out.TLS == nil || !out.TLS.Enabled {
		t.Error("TLS should be enabled")
	}
	if out.TLS.Reality == nil {
		t.Error("Reality config missing")
	}
	if out.TLS.Reality.PublicKey != "test-pubkey" {
		t.Errorf("pubkey: want test-pubkey, got %s", out.TLS.Reality.PublicKey)
	}
	if out.TLS.UTLS == nil || out.TLS.UTLS.Fingerprint != "chrome" {
		t.Error("uTLS chrome fingerprint expected with Reality")
	}
	// ALPN должен быть ["h2", "http/1.1"]
	if len(out.TLS.ALPN) == 0 {
		t.Error("ALPN should not be empty with Reality")
	}
	t.Logf("OK: VLESS+Reality TLS: SNI=%s ALPN=%v", out.TLS.ServerName, out.TLS.ALPN)
}

func TestNodeToOutboundWithTransports(t *testing.T) {
	transports := []struct {
		name      string
		transport *models.TransportConfig
	}{
		{"ws", &models.TransportConfig{Type: "ws", Path: "/ws", Host: "cdn.example.com"}},
		{"grpc", &models.TransportConfig{Type: "grpc", Path: "TunService"}},
		{"http", &models.TransportConfig{Type: "http", Path: "/http"}},
		{"httpupgrade", &models.TransportConfig{Type: "httpupgrade", Path: "/upgrade"}},
		{"splithttp", &models.TransportConfig{Type: "splithttp", Path: "/split"}},
	}
	for _, tt := range transports {
		t.Run(tt.name, func(t *testing.T) {
			node := &models.Node{
				Protocol:  models.ProtoVLESS,
				UUID:      "uuid",
				Address:   "host.example.com",
				Port:      443,
				Transport: tt.transport,
			}
			out, err := nodeToOutbound(node, "tag")
			if err != nil {
				t.Fatalf("%s: error: %v", tt.name, err)
			}
			if out.Transport == nil {
				t.Fatalf("%s: transport should not be nil", tt.name)
			}
			if out.Transport.Type != tt.transport.Type {
				t.Errorf("%s: type: want %s, got %s",
					tt.name, tt.transport.Type, out.Transport.Type)
			}
			t.Logf("OK: %s transport type=%s", tt.name, out.Transport.Type)
		})
	}
}

func TestWebSocketEarlyData(t *testing.T) {
	node := &models.Node{
		Protocol: models.ProtoVLESS,
		UUID:     "uuid",
		Address:  "host.example.com",
		Port:     443,
		Transport: &models.TransportConfig{
			Type: "ws", Path: "/api/stream", Host: "cdn.example.com",
		},
	}
	out, _ := nodeToOutbound(node, "ws-tag")
	if out.Transport == nil {
		t.Fatal("transport nil")
	}
	// WebSocket early data должен быть установлен
	if out.Transport.MaxEarlyData != 2048 {
		t.Errorf("MaxEarlyData: want 2048, got %d", out.Transport.MaxEarlyData)
	}
	if out.Transport.EarlyDataHeaderName != "Sec-WebSocket-Protocol" {
		t.Errorf("EarlyDataHeaderName wrong: %s", out.Transport.EarlyDataHeaderName)
	}
	// Host header
	if out.Transport.Headers["Host"] != "cdn.example.com" {
		t.Errorf("Host header: want cdn.example.com, got %v", out.Transport.Headers["Host"])
	}
	t.Log("OK: WebSocket early data and Host header")
}

func TestBuildURLAllPlatforms(t *testing.T) {
	d := &Downloader{Version: "1.10.7", BinDir: "/tmp"}
	url, archive := d.buildURL()
	if url == "" {
		t.Error("URL should not be empty")
	}
	if archive == "" {
		t.Error("archive name should not be empty")
	}
	if !contains(url, "1.10.7") {
		t.Errorf("URL should contain version: %s", url)
	}
	t.Logf("OK: buildURL: %s (%s)", url, archive)
}

func TestCoalesceHelpers(t *testing.T) {
	if coalesceStr("", "fallback") != "fallback" {
		t.Error("coalesceStr: should return fallback for empty")
	}
	if coalesceStr("first", "second") != "first" {
		t.Error("coalesceStr: should return first non-empty")
	}
	if coalesceStr("", "") != "" {
		t.Error("coalesceStr: all empty should return empty")
	}

	if coalesceInt(0, 42) != 42 {
		t.Error("coalesceInt: should return fallback for 0")
	}
	if coalesceInt(10, 42) != 10 {
		t.Error("coalesceInt: should return first non-zero")
	}
	t.Log("OK: coalesceStr and coalesceInt")
}

func TestSetAdBlockRules(t *testing.T) {
	b := NewBuilder(10808, false)
	rules := []map[string]interface{}{
		{"domain_suffix": []string{"ads.example.com", "tracker.net"}},
		{"domain_suffix": []string{"malware.bad"}},
	}
	b.SetAdBlockRules(rules)
	if len(b.adBlockRules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(b.adBlockRules))
	}
	t.Log("OK: SetAdBlockRules")
}

func TestNewBuilderFromConfig(t *testing.T) {
	type mockCfg struct{}
	// NewBuilderFromConfig requires an interface — test directly with real config
	b := NewBuilder(10808, true)
	if b == nil {
		t.Fatal("Builder nil")
	}
	if !b.tunMode {
		t.Error("tunMode should be true")
	}
	t.Log("OK: NewBuilder with tunMode=true")
}

func TestToJSON(t *testing.T) {
	b := NewBuilder(10808, false)
	node := &models.Node{
		Protocol: models.ProtoVLESS,
		UUID:     "test-uuid",
		Address:  "host.example.com",
		Port:     443,
	}
	cfg, err := b.BuildSingle(node)
	if err != nil {
		t.Fatalf("BuildSingle: %v", err)
	}
	data, err := ToJSON(cfg)
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	if len(data) == 0 {
		t.Error("ToJSON returned empty data")
	}
	// JSON должен содержать ключевые поля
	s := string(data)
	if !contains(s, "inbounds") || !contains(s, "outbounds") || !contains(s, "dns") {
		t.Error("ToJSON missing required sections")
	}
	t.Logf("OK: ToJSON %d bytes", len(data))
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ── nodeToOutbound: Tor protocol ─────────────────────────────────────────────

func TestNodeToOutbound_Tor(t *testing.T) {
	node := &models.Node{
		Protocol: models.ProtoTor,
		Address:  "127.0.0.1",
		Port:     9050,
	}
	out, err := nodeToOutbound(node, "tor-tag")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Type != "tor" {
		t.Errorf("expected type=tor, got %s", out.Type)
	}
	if out.Tag != "tor-tag" {
		t.Errorf("expected tag=tor-tag, got %s", out.Tag)
	}
}

// ── nodeToOutbound: unsupported protocol (default branch) ────────────────────

func TestNodeToOutbound_UnsupportedProtocol(t *testing.T) {
	node := &models.Node{
		Protocol: models.Protocol("unsupported-xyz"),
		Address:  "host.example.com",
		Port:     443,
	}
	_, err := nodeToOutbound(node, "tag")
	if err == nil {
		t.Error("expected error for unsupported protocol")
	}
	if !contains(err.Error(), "unsupported protocol") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// ── BuildSingle: error path from nodeToOutbound ───────────────────────────────

func TestBuildSingle_UnsupportedProtocol(t *testing.T) {
	b := NewBuilder(10808, false)
	node := &models.Node{
		Protocol: models.Protocol("unknown"),
		Address:  "host.example.com",
		Port:     443,
	}
	_, err := b.BuildSingle(node)
	if err == nil {
		t.Error("expected error from BuildSingle with unsupported protocol")
	}
	if !contains(err.Error(), "build outbound") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ── BuildChain: error — too few nodes ────────────────────────────────────────

func TestBuildChain_TooFewNodes(t *testing.T) {
	b := NewBuilder(10808, false)
	chain := &models.Chain{
		Nodes: []*models.Node{
			{Protocol: models.ProtoVLESS, Address: "a.com", Port: 443, UUID: "uuid"},
		},
	}
	_, err := b.BuildChain(chain)
	if err == nil {
		t.Error("expected error for chain with <2 nodes")
	}
}

// ── BuildChain: error from nodeToOutbound inside loop ────────────────────────

func TestBuildChain_NodeError(t *testing.T) {
	b := NewBuilder(10808, false)
	chain := &models.Chain{
		Nodes: []*models.Node{
			{Protocol: models.ProtoVLESS, Address: "a.com", Port: 443, UUID: "uuid"},
			{Protocol: models.Protocol("bad-proto"), Address: "b.com", Port: 443},
		},
	}
	_, err := b.BuildChain(chain)
	if err == nil {
		t.Error("expected error from BuildChain when node has unsupported protocol")
	}
}

// ── buildTransport: http with Host header ────────────────────────────────────

func TestBuildTransport_HTTPWithHost(t *testing.T) {
	node := &models.Node{
		Protocol: models.ProtoVLESS,
		UUID:     "uuid",
		Address:  "host.example.com",
		Port:     443,
		Transport: &models.TransportConfig{
			Type: "http",
			Path: "/api",
			Host: "cdn.example.com",
		},
	}
	out, err := nodeToOutbound(node, "tag")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Transport == nil {
		t.Fatal("transport should not be nil")
	}
	if out.Transport.Headers["Host"] != "cdn.example.com" {
		t.Errorf("expected Host header cdn.example.com, got %v", out.Transport.Headers)
	}
}

// ── nodeToOutbound: Shadowsocks with Transport ────────────────────────────────

// TestNodeToOutbound_ShadowsocksWithTransport_Rejected — аудит 2026-09-01 (раздел D):
// раньше этот тест ТРЕБОВАЛ, чтобы transport был вшит в shadowsocks-outbound — закреплял
// дефект как ожидаемое поведение. vendor/.../sing-box/option/shadowsocks.go:
// ShadowsocksOutboundOptions не содержит поля transport вовсе; sing-box отвергает такую
// конфигурацию целиком (не игнорирует лишнее поле). Узел с transport на Shadowsocks не
// может быть использован этой сборкой — nodeToOutbound обязан отказать явно, а не строить
// заведомо нерабочий конфиг.
func TestNodeToOutbound_ShadowsocksWithTransport_Rejected(t *testing.T) {
	node := &models.Node{
		Protocol: models.ProtoShadowsocks,
		Address:  "ss.example.com",
		Port:     8388,
		Method:   "chacha20-ietf-poly1305",
		Password: "pass",
		Transport: &models.TransportConfig{
			Type: "ws",
			Path: "/ss",
		},
	}
	_, err := nodeToOutbound(node, "ss-tag")
	if err == nil {
		t.Fatal("nodeToOutbound(Shadowsocks+transport) = nil ошибка — ожидался явный отказ " +
			"(sing-box: ShadowsocksOutboundOptions не поддерживает transport)")
	}
}

// Контрольная проверка: обычный Shadowsocks без transport по-прежнему собирается штатно —
// отказ выше специфичен именно к сочетанию с transport, не ко всему протоколу.
func TestNodeToOutbound_Shadowsocks_WithoutTransport_OK(t *testing.T) {
	node := &models.Node{
		Protocol: models.ProtoShadowsocks,
		Address:  "ss.example.com",
		Port:     8388,
		Method:   "chacha20-ietf-poly1305",
		Password: "pass",
	}
	out, err := nodeToOutbound(node, "ss-tag")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Type != "shadowsocks" {
		t.Errorf("expected shadowsocks, got %s", out.Type)
	}
	if out.Transport != nil {
		t.Errorf("transport should be nil, got %+v", out.Transport)
	}
}
