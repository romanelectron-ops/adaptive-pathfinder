package web

import "testing"

func TestCheckDomainRouting_CorrelatesSniffAndOutboundByID(t *testing.T) {
	logs := []string{
		"[sing-box] [37mDEBUG[0m[0013] [[38;5;121m3671550057[0m 1ms] router: sniffed protocol: tls, domain: www.gosuslugi.ru",
		"[sing-box] [36mINFO[0m[0013] [[38;5;121m3671550057[0m 1ms] outbound/direct[direct]: outbound connection to 198.51.100.7:443",
		"[sing-box] [37mDEBUG[0m[0013] [[38;5;43m30731250[0m 8.88s] router: sniffed protocol: tls, domain: gu-st.ru",
		"[sing-box] [36mINFO[0m[0013] [[38;5;43m30731250[0m 8.88s] outbound/shadowsocks[proxy]: outbound connection to 203.0.113.89:443",
	}
	got := CheckDomainRouting(logs, "")
	if len(got) != 2 {
		t.Fatalf("expected 2 domains, got %d: %+v", len(got), got)
	}
	byDomain := map[string]DomainRouteResult{}
	for _, r := range got {
		byDomain[r.Domain] = r
	}
	if r := byDomain["www.gosuslugi.ru"]; !r.Direct || r.Outbound != "direct" {
		t.Errorf("gosuslugi.ru: expected direct, got %+v", r)
	}
	if r := byDomain["gu-st.ru"]; r.Direct || r.Outbound != "shadowsocks" {
		t.Errorf("gu-st.ru: expected tunnel (shadowsocks), got %+v", r)
	}
}

func TestCheckDomainRouting_FiltersByQuery(t *testing.T) {
	logs := []string{
		"[sing-box] [37mDEBUG[0m[0013] [[38;5;121m111[0m 1ms] router: sniffed protocol: tls, domain: example.com",
		"[sing-box] [36mINFO[0m[0013] [[38;5;121m111[0m 1ms] outbound/direct[direct]: outbound connection to 1.2.3.4:443",
		"[sing-box] [37mDEBUG[0m[0013] [[38;5;43m222[0m 8.88s] router: sniffed protocol: tls, domain: unrelated.org",
		"[sing-box] [36mINFO[0m[0013] [[38;5;43m222[0m 8.88s] outbound/vless[proxy]: outbound connection to 5.6.7.8:443",
	}
	got := CheckDomainRouting(logs, "example")
	if len(got) != 1 || got[0].Domain != "example.com" {
		t.Fatalf("expected only example.com, got %+v", got)
	}
}

func TestCheckDomainRouting_QueryIsCaseInsensitive(t *testing.T) {
	logs := []string{
		"[sing-box] [37mDEBUG[0m[0013] [[38;5;121m111[0m 1ms] router: sniffed protocol: tls, domain: Www.GosUslugi.ru",
		"[sing-box] [36mINFO[0m[0013] [[38;5;121m111[0m 1ms] outbound/direct[direct]: outbound connection to 1.2.3.4:443",
	}
	got := CheckDomainRouting(logs, "GOSUSLUGI")
	if len(got) != 1 {
		t.Fatalf("expected 1 match, got %d", len(got))
	}
}

func TestCheckDomainRouting_NoOutboundLine_Ignored(t *testing.T) {
	logs := []string{
		"[sing-box] [37mDEBUG[0m[0013] [[38;5;121m111[0m 1ms] router: sniffed protocol: tls, domain: orphan.example",
	}
	got := CheckDomainRouting(logs, "")
	if len(got) != 0 {
		t.Fatalf("expected no results for domain never matched to an outbound, got %+v", got)
	}
}

func TestCheckDomainRouting_EmptyLogs(t *testing.T) {
	got := CheckDomainRouting(nil, "")
	if len(got) != 0 {
		t.Fatalf("expected empty result for nil logs, got %+v", got)
	}
}
