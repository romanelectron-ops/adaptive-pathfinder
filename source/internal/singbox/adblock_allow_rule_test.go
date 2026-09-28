package singbox

import "testing"

// P1-6 (аудит 2026-09-01): строитель обязан (а) понимать разрешающее правило и (б) сохранять
// порядок правил ровно таким, каким его задал источник. Правила DNS в sing-box матчатся
// сверху вниз и терминальное действие останавливает разбор — переставленное или
// переинтерпретированное правило означает, что белый список не работает.

func adBlockRulesFrom(t *testing.T, b *Builder) []DNSRule {
	t.Helper()
	return b.buildDNS("proxy").Rules
}

func TestBuildDNS_AllowRuleBecomesRouteNotReject(t *testing.T) {
	b := NewBuilder(1080, false)
	b.SetAdBlockRules([]map[string]interface{}{
		{"domain_suffix": []string{"good.com"}, "action": "allow"},
		{"domain_suffix": []string{"ads.com"}, "action": "block"},
	})

	rules := adBlockRulesFrom(t, b)

	var allowIdx, blockIdx = -1, -1
	for i, r := range rules {
		if len(r.DomainSuffix) == 1 && r.DomainSuffix[0] == "good.com" {
			allowIdx = i
			if r.Action == "reject" {
				t.Error("разрешающее правило приехало как Action=\"reject\" — " +
					"поле action источника не читается")
			}
			if r.Server != "dns-remote" {
				t.Errorf("allow-правило: Server = %q, ожидалось \"dns-remote\" "+
					"(терминальная маршрутизация, чтобы разбор не дошёл до reject ниже)", r.Server)
			}
		}
		if len(r.DomainSuffix) == 1 && r.DomainSuffix[0] == "ads.com" {
			blockIdx = i
			if r.Action != "reject" {
				t.Errorf("block-правило: Action = %q, ожидалось \"reject\"", r.Action)
			}
		}
	}

	if allowIdx < 0 {
		t.Fatal("разрешающее правило не попало в конфигурацию вовсе")
	}
	if blockIdx < 0 {
		t.Fatal("запрещающее правило не попало в конфигурацию вовсе")
	}
	if allowIdx > blockIdx {
		t.Fatalf("порядок нарушен: allow на позиции %d, block на %d — sing-box отработает "+
			"reject раньше, и белый список не подействует", allowIdx, blockIdx)
	}
}

// Правило без "action" — как и раньше, блокировка. Обратная совместимость: конфигурации и
// вызывающие стороны, не знающие про allow, должны вести себя ровно так же, как до правки.
func TestBuildDNS_RuleWithoutActionStillRejects(t *testing.T) {
	b := NewBuilder(1080, false)
	b.SetAdBlockRules([]map[string]interface{}{
		{"domain_suffix": []string{"ads.com"}},
	})
	for _, r := range adBlockRulesFrom(t, b) {
		if len(r.DomainSuffix) == 1 && r.DomainSuffix[0] == "ads.com" {
			if r.Action != "reject" {
				t.Fatalf("Action = %q, ожидалось \"reject\"", r.Action)
			}
			return
		}
	}
	t.Fatal("правило не попало в конфигурацию")
}

// Конфигурация с allow-правилом обязана оставаться внутренне согласованной: "dns-remote" —
// существующий тег DNS-сервера, а не выдумка. Тот же инвариант, что проверяет validateTagRefs
// для остальной конфигурации (P0-1).
func TestBuildSingle_WithAllowRule_TagsResolve(t *testing.T) {
	b := NewBuilder(1080, false)
	b.SetAdBlockRules([]map[string]interface{}{
		{"domain_suffix": []string{"good.com"}, "action": "allow"},
	})
	cfg, err := b.BuildSingle(testNode())
	if err != nil {
		t.Fatalf("BuildSingle: %v", err)
	}
	tags := map[string]bool{}
	for _, s := range cfg.DNS.Servers {
		tags[s.Tag] = true
	}
	for i, r := range cfg.DNS.Rules {
		if r.Server != "" && !tags[r.Server] {
			t.Errorf("DNS.Rules[%d].Server = %q — такого DNS-сервера в конфигурации нет", i, r.Server)
		}
	}
}
