package parser

import "testing"

// Фаза A.4 (docs/PLAN_APF_RELAY_v1.0.md): нераспознанные query-параметры ссылки должны
// сохраняться в Node.ExtraParams, не теряться молча — общий механизм, нужен для relay-режима
// Вход-Выход (docs/TZ_APF_RELAY_v1.0.md §5), но сам по себе не relay-специфичный.
func TestParseVLESS_UnknownParams_SavedToExtraParams(t *testing.T) {
	link := "vless://00000000-0000-0000-0000-000000000001@1.2.3.4:443" +
		"?type=tcp&security=none&apf_relay=1&apf_exitid=deadbeef#Test"
	node, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if node.ExtraParams == nil {
		t.Fatal("ExtraParams == nil, ожидались apf_relay/apf_exitid")
	}
	if node.ExtraParams["apf_relay"] != "1" {
		t.Errorf("ExtraParams[apf_relay] = %q, ожидалось \"1\"", node.ExtraParams["apf_relay"])
	}
	if node.ExtraParams["apf_exitid"] != "deadbeef" {
		t.Errorf("ExtraParams[apf_exitid] = %q, ожидалось \"deadbeef\"", node.ExtraParams["apf_exitid"])
	}
	// Известные параметры (type/security) НЕ должны просочиться в ExtraParams — они уже
	// обработаны в свои поля (Transport/TLS).
	if _, ok := node.ExtraParams["type"]; ok {
		t.Error("известный параметр 'type' не должен попадать в ExtraParams")
	}
	if _, ok := node.ExtraParams["security"]; ok {
		t.Error("известный параметр 'security' не должен попадать в ExtraParams")
	}
}

// Ссылка без посторонних параметров — ExtraParams остаётся nil, не пустой map (не создаём
// лишние аллокации/JSON-мусор "extra_params":{} для подавляющего большинства обычных ссылок).
func TestParseVLESS_NoUnknownParams_ExtraParamsNil(t *testing.T) {
	link := "vless://00000000-0000-0000-0000-000000000002@1.2.3.4:443" +
		"?type=tcp&security=none#Test"
	node, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if node.ExtraParams != nil {
		t.Errorf("ExtraParams = %v, ожидался nil для ссылки без посторонних параметров", node.ExtraParams)
	}
}

// Известные поля (flow/sni/pbk/sid/fp) продолжают разбираться как раньше — регрессия на то,
// что добавление ExtraParams не задело существующую обработку.
func TestParseVLESS_KnownParams_StillParsedCorrectly(t *testing.T) {
	link := "vless://00000000-0000-0000-0000-000000000003@1.2.3.4:443" +
		"?type=tcp&security=reality&sni=example.com&pbk=abc&sid=def&flow=xtls-rprx-vision#Test"
	node, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if node.Flow != "xtls-rprx-vision" {
		t.Errorf("Flow = %q, ожидался xtls-rprx-vision", node.Flow)
	}
	if node.TLS == nil || node.TLS.Reality == nil {
		t.Fatal("TLS.Reality == nil")
	}
	if node.TLS.Reality.PublicKey != "abc" || node.TLS.Reality.ShortID != "def" {
		t.Errorf("Reality = %+v, ожидались pbk=abc sid=def", node.TLS.Reality)
	}
	if node.ExtraParams != nil {
		t.Errorf("ExtraParams = %v, ожидался nil — все параметры этой ссылки известны", node.ExtraParams)
	}
}
