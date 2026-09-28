package singbox

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// T-18 — ShadowTLS/CDN-фрагмент вшивается в итоговый sing-box конфиг (разрыв #2).

func t18Node() *models.Node {
	return &models.Node{
		Protocol: models.ProtoVLESS,
		Address:  "1.2.3.4",
		Port:     443,
		UUID:     "11111111-2222-3333-4444-555555555555",
	}
}

// (1) Позитив: при заданном ShadowTLS конфиг содержит shadowtls-outbound (диалер, БЕЗ
// detour, с РЕАЛЬНЫМ адресом сервера) и внутренний протокольный outbound с tag=proxy,
// чей detour указывает НА shadowtls-обёртку. route.Final=proxy (внутренний протокол, а
// не диалер) — тот же тег, что и в конфиге без ShadowTLS вообще, поэтому остальной код
// (health-check, статистика, kill switch), знающий узел по тегу "proxy", продолжает
// работать без изменений.
//
// P1-1 (аудит 2026-09-01): раньше тест ТРЕБОВАЛ обратного — shadowtls.Tag=="proxy" и
// shadowtls.Detour=="proxy-inner" — то есть закреплял перевёрнутую топологию как
// ожидаемое поведение. sing-box: shadowtls — диалер (protocol/shadowtls/outbound.go:
// DialContext игнорирует destination), у него не может быть своего detour; это
// протокольный outbound обязан детурить В shadowtls, не наоборот. См. doc-comment
// Builder.wrapShadowTLS.
func TestBuildSingle_WithShadowTLS_WiresOutbound(t *testing.T) {
	b := NewBuilder(10808, false)
	b.SetShadowTLS(&ShadowTLSParams{
		Server: "203.0.113.7", Port: 8443, Version: 3,
		Password: "secret", SNI: "www.bing.com",
	})
	cfg, err := b.BuildSingle(t18Node())
	if err != nil {
		t.Fatalf("BuildSingle: %v", err)
	}

	var st, inner *Outbound
	for i := range cfg.Outbounds {
		switch cfg.Outbounds[i].Type {
		case "shadowtls":
			st = &cfg.Outbounds[i]
		case "vless":
			inner = &cfg.Outbounds[i]
		}
	}
	if st == nil {
		t.Fatal("shadowtls-outbound отсутствует в конфиге (T-18 не сработал)")
	}
	if st.Tag != "shadowtls-out" {
		t.Errorf("shadowtls должен иметь собственный tag=shadowtls-out, got %q", st.Tag)
	}
	if st.Detour != "" {
		t.Errorf("shadowtls — диалер, у него не должно быть detour (got %q); "+
			"detour обязан стоять на внутреннем протоколе, см. inner.Detour ниже", st.Detour)
	}
	if st.Server != "203.0.113.7" || st.ServerPort != 8443 || st.Version != 3 || st.Password != "secret" {
		t.Errorf("shadowtls параметры неверны (сервер обязан быть РЕАЛЬНЫМ адресом, не "+
			"маскировочным SNI-хостом): %+v", st)
	}
	if st.TLS == nil || st.TLS.ServerName != "www.bing.com" || st.TLS.UTLS == nil {
		t.Errorf("shadowtls TLS/uTLS не настроены (server_name обязан быть маскировочным "+
			"SNI, не реальным сервером): %+v", st.TLS)
	}
	if inner == nil {
		t.Fatal("внутренний vless-outbound отсутствует")
	}
	if inner.Tag != "proxy" {
		t.Errorf("внутренний vless должен сохранить tag=proxy (тот же, что и без "+
			"ShadowTLS), got %q", inner.Tag)
	}
	if inner.Detour != "shadowtls-out" {
		t.Errorf("proxy.detour должен указывать на shadowtls-out, got %q — без этого "+
			"соединение уходит в сеть напрямую, минуя TLS-маскировку", inner.Detour)
	}
	if cfg.Route.Final != "proxy" {
		t.Errorf("route.Final должен быть proxy (внутренний протокол, точка входа "+
			"остального кода), got %q", cfg.Route.Final)
	}

	// JSON содержит type:shadowtls
	data, _ := json.Marshal(cfg)
	if !strings.Contains(string(data), "\"shadowtls\"") {
		t.Error("итоговый JSON не содержит shadowtls outbound")
	}
}

// (4) Инвариант: без ShadowTLS конфиг как раньше — нет shadowtls, proxy остаётся vless.
func TestBuildSingle_WithoutShadowTLS_Unchanged(t *testing.T) {
	b := NewBuilder(10808, false)
	cfg, err := b.BuildSingle(t18Node())
	if err != nil {
		t.Fatalf("BuildSingle: %v", err)
	}
	for _, ob := range cfg.Outbounds {
		if ob.Type == "shadowtls" {
			t.Error("без SetShadowTLS не должно быть shadowtls-outbound")
		}
	}
	// proxy-узел остаётся прямым vless с tag=proxy
	found := false
	for _, ob := range cfg.Outbounds {
		if ob.Type == "vless" && ob.Tag == "proxy" {
			found = true
		}
	}
	if !found {
		t.Error("без ShadowTLS proxy должен быть прямым vless с tag=proxy")
	}
}

// (3) Fail-safe: SetShadowTLS(nil) выключает обёртку.
func TestBuildSingle_ShadowTLSNil_Disables(t *testing.T) {
	b := NewBuilder(10808, false)
	b.SetShadowTLS(&ShadowTLSParams{Server: "x", Port: 443})
	b.SetShadowTLS(nil) // выключили
	cfg, _ := b.BuildSingle(t18Node())
	for _, ob := range cfg.Outbounds {
		if ob.Type == "shadowtls" {
			t.Error("SetShadowTLS(nil) должен отключать обёртку")
		}
	}
}
