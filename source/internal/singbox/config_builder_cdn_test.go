package singbox

import (
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// T-18 (CDN-плечо / разрыв #2) — CDN-fronting накладывается на outbound в итоговом конфиге.

func cdnNode() *models.Node {
	return &models.Node{
		Protocol: models.ProtoVLESS, Address: "real-server.com", Port: 8443,
		UUID: "11111111-2222-3333-4444-555555555555",
	}
}

// (1) Позитив: CDN перенаправляет на CDN IP, ставит TLS(SNI=front) и transport=ws(Host).
func TestBuildSingle_WithCDN_FrontsOutbound(t *testing.T) {
	b := NewBuilder(10808, false)
	b.SetCDNFronting(&CDNParams{
		Server: "104.16.0.1", Port: 443, SNI: "cdn.example.com",
		WSPath: "/ws", WSHost: "my-worker.workers.dev",
	})
	cfg, err := b.BuildSingle(cdnNode())
	if err != nil {
		t.Fatalf("BuildSingle: %v", err)
	}
	var proxy *Outbound
	for i := range cfg.Outbounds {
		if cfg.Outbounds[i].Tag == "proxy" {
			proxy = &cfg.Outbounds[i]
		}
	}
	if proxy == nil {
		t.Fatal("proxy outbound отсутствует")
	}
	if proxy.Server != "104.16.0.1" || proxy.ServerPort != 443 {
		t.Errorf("CDN не перенаправил на CDN IP: server=%s:%d", proxy.Server, proxy.ServerPort)
	}
	if proxy.TLS == nil || proxy.TLS.ServerName != "cdn.example.com" {
		t.Errorf("TLS SNI должен быть front-домен, got %+v", proxy.TLS)
	}
	if proxy.Transport == nil || proxy.Transport.Type != "ws" || proxy.Transport.Path != "/ws" {
		t.Errorf("transport должен быть ws с path /ws, got %+v", proxy.Transport)
	}
	if proxy.Transport.Headers["Host"] != "my-worker.workers.dev" {
		t.Errorf("ws Host header должен указывать на worker, got %v", proxy.Transport.Headers)
	}
}

// (4) Инвариант: без CDN сервер остаётся реальным.
func TestBuildSingle_WithoutCDN_RealServer(t *testing.T) {
	b := NewBuilder(10808, false)
	cfg, _ := b.BuildSingle(cdnNode())
	for _, ob := range cfg.Outbounds {
		if ob.Tag == "proxy" && ob.Server != "real-server.com" {
			t.Errorf("без CDN сервер должен остаться реальным, got %s", ob.Server)
		}
	}
}

// (3) Fail-safe: SetCDNFronting(nil) выключает.
func TestBuildSingle_CDNNil_Disables(t *testing.T) {
	b := NewBuilder(10808, false)
	b.SetCDNFronting(&CDNParams{Server: "1.1.1.1", Port: 443})
	b.SetCDNFronting(nil)
	cfg, _ := b.BuildSingle(cdnNode())
	for _, ob := range cfg.Outbounds {
		if ob.Tag == "proxy" && ob.Server == "1.1.1.1" {
			t.Error("SetCDNFronting(nil) должен выключать фронтинг")
		}
	}
}

// Комбинация: CDN + ShadowTLS — CDN модифицирует inner, ShadowTLS оборачивает.
//
// P1-1 (аудит 2026-09-01): тег внутреннего (CDN-fronted) outbound'а — "proxy" (тот же, что
// и без ShadowTLS вообще), не "proxy-inner". См. doc-comment у вызова wrapShadowTLS в
// BuildSingle: тег "proxy" намеренно остался за внутренним протоколом, а не за диалером.
func TestBuildSingle_CDNplusShadowTLS(t *testing.T) {
	b := NewBuilder(10808, false)
	b.SetCDNFronting(&CDNParams{Server: "104.16.0.1", Port: 443, SNI: "cdn.example.com", WSPath: "/ws", WSHost: "w.dev"})
	b.SetShadowTLS(&ShadowTLSParams{Server: "203.0.113.7", Port: 8443, Version: 3, Password: "p", SNI: "www.bing.com"})
	cfg, err := b.BuildSingle(cdnNode())
	if err != nil {
		t.Fatalf("BuildSingle: %v", err)
	}
	var st, inner *Outbound
	for i := range cfg.Outbounds {
		switch {
		case cfg.Outbounds[i].Type == "shadowtls":
			st = &cfg.Outbounds[i]
		case cfg.Outbounds[i].Tag == "proxy":
			inner = &cfg.Outbounds[i]
		}
	}
	if st == nil {
		t.Fatal("shadowtls обёртка отсутствует при комбинации")
	}
	if inner == nil || inner.Server != "104.16.0.1" {
		t.Errorf("внутренний (CDN-fronted) сервер должен быть CDN IP, got %+v", inner)
	}
	if inner.Detour != st.Tag {
		t.Errorf("внутренний outbound должен детурить в shadowtls-обёртку (tag=%q), got detour=%q",
			st.Tag, inner.Detour)
	}
}
