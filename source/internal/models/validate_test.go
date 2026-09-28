package models

import (
	"strings"
	"testing"
)

// B-29 (D25) — валидатор полей узла.

func validVLESS() *Node {
	return &Node{
		Protocol: ProtoVLESS,
		Address:  "example.com",
		Port:     443,
		UUID:     "11111111-2222-3333-4444-555555555555",
	}
}

// (1) Позитив: корректные узлы проходят.
func TestValidateNode_ValidProtocols(t *testing.T) {
	cases := []*Node{
		validVLESS(),
		{Protocol: ProtoVMess, Address: "1.2.3.4", Port: 443, UUID: "11111111-2222-3333-4444-555555555555"},
		{Protocol: ProtoTrojan, Address: "host.net", Port: 8443, Password: "pw"},
		{Protocol: ProtoShadowsocks, Address: "5.6.7.8", Port: 8388, Password: "pw", Method: "aes-256-gcm"},
	}
	for i, n := range cases {
		if err := ValidateNode(n); err != nil {
			t.Errorf("case %d должен быть валиден, got: %v", i, err)
		}
	}
}

// (2) Негатив по протоколам: пропуск обязательных полей.
func TestValidateNode_MissingRequiredFields(t *testing.T) {
	cases := map[string]*Node{
		"VLESS без uuid":      {Protocol: ProtoVLESS, Address: "a.com", Port: 443},
		"Trojan без password": {Protocol: ProtoTrojan, Address: "a.com", Port: 443},
		"SS без method":       {Protocol: ProtoShadowsocks, Address: "a.com", Port: 443, Password: "p"},
		"пустой protocol":     {Address: "a.com", Port: 443},
		"неизвестный proto":   {Protocol: "magic", Address: "a.com", Port: 443},
	}
	for name, n := range cases {
		if err := ValidateNode(n); err == nil {
			t.Errorf("%s: ожидалась ошибка валидации", name)
		}
	}
}

// (2) Граничные: адрес и порт.
func TestValidateNode_AddressAndPort(t *testing.T) {
	n := validVLESS()
	n.Address = ""
	if err := ValidateNode(n); err == nil {
		t.Error("пустой адрес должен отвергаться")
	}
	n = validVLESS()
	n.Port = 0
	if err := ValidateNode(n); err == nil {
		t.Error("порт 0 должен отвергаться")
	}
	n = validVLESS()
	n.Port = 70000
	if err := ValidateNode(n); err == nil {
		t.Error("порт >65535 должен отвергаться")
	}
	n = validVLESS()
	n.Address = "http://bad space/url"
	if err := ValidateNode(n); err == nil {
		t.Error("адрес со схемой/пробелом должен отвергаться")
	}
}

// (2) Reality pbk/sid.
func TestValidateNode_Reality(t *testing.T) {
	n := validVLESS()
	n.TLS = &TLSConfig{Enabled: true, Reality: &RealityConfig{PublicKey: ""}}
	if err := ValidateNode(n); err == nil || !strings.Contains(err.Error(), "public_key") {
		t.Errorf("Reality без public_key должен отвергаться, got: %v", err)
	}
	n = validVLESS()
	n.TLS = &TLSConfig{Enabled: true, Reality: &RealityConfig{PublicKey: "abc", ShortID: "zzz"}}
	if err := ValidateNode(n); err == nil || !strings.Contains(err.Error(), "short_id") {
		t.Errorf("невалидный short_id должен отвергаться, got: %v", err)
	}
	n = validVLESS()
	n.TLS = &TLSConfig{Enabled: true, Reality: &RealityConfig{PublicKey: "somekey", ShortID: "0a1b"}}
	if err := ValidateNode(n); err != nil {
		t.Errorf("валидный Reality должен проходить, got: %v", err)
	}
}

// (2) Transport.
func TestValidateNode_Transport(t *testing.T) {
	n := validVLESS()
	n.Transport = &TransportConfig{Type: "quic"}
	if err := ValidateNode(n); err == nil {
		t.Error("неизвестный transport type должен отвергаться")
	}
	n = validVLESS()
	n.Transport = &TransportConfig{Type: "ws", Path: "no-slash"}
	if err := ValidateNode(n); err == nil {
		t.Error("ws path без ведущего '/' должен отвергаться")
	}
	n = validVLESS()
	n.Transport = &TransportConfig{Type: "ws", Path: "/ok"}
	if err := ValidateNode(n); err != nil {
		t.Errorf("валидный ws transport должен проходить, got: %v", err)
	}
}

// (3) Fail-safe: nil-узел → ошибка без паники.
func TestValidateNode_Nil(t *testing.T) {
	if err := ValidateNode(nil); err == nil {
		t.Error("nil-узел должен давать ошибку")
	}
}

// Агрегация: несколько нарушений перечислены в одной ошибке.
func TestValidateNode_AggregatesErrors(t *testing.T) {
	n := &Node{Protocol: ProtoVLESS, Address: "", Port: 0}
	err := ValidateNode(n)
	if err == nil {
		t.Fatal("ожидалась ошибка")
	}
	// должны упоминаться и адрес, и порт, и uuid
	for _, want := range []string{"address", "port", "uuid"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ошибка должна упоминать %q: %v", want, err)
		}
	}
}

// Регрессия 2026-09-05: узел-заглушка Tor (Protocol=tor, без Address/Port — именно так его
// создаёт sources.fetchTorBridges, "реальные" obfs4/snowflake bridge-строки не разбираются)
// ДОЛЖЕН отвергаться. Комментарий у case ProtoTor в validate.go раньше утверждал обратное
// («снимаем общие требования к адресу/порту для Tor»), хотя кода для этого не было ни строчки —
// общие проверки безусловно выполняются до switch. engine.mergeFetchedNodes (NL-10) полагается
// именно на текущее (отклоняющее) поведение, чтобы заглушка не «висела» в пуле красной без
// единого шанса подключиться. Тест фиксирует РЕАЛЬНОЕ поведение и защищает NL-10 от случайной
// "починки" по недостоверному комментарию.
func TestValidateNode_TorStubRejected(t *testing.T) {
	stub := &Node{ID: "tor-123", Name: "Tor Bridge", Protocol: ProtoTor}
	err := ValidateNode(stub)
	if err == nil {
		t.Fatal("узел-заглушка Tor без адреса/порта должен отвергаться ValidateNode (NL-10)")
	}
	if !strings.Contains(err.Error(), "address") || !strings.Contains(err.Error(), "port") {
		t.Errorf("ошибка должна упоминать и адрес, и порт: %v", err)
	}

	// Симметрично: Tor-узел С реальными адресом/портом (ручное добавление bridge-строки в виде
	// host:port) проходит валидацию как любой другой протокол — Tor не получает ни поблажек,
	// ни дополнительных ограничений сверх общих проверок.
	real := &Node{Protocol: ProtoTor, Address: "192.0.2.1", Port: 443}
	if err := ValidateNode(real); err != nil {
		t.Errorf("Tor-узел с валидными адресом/портом должен проходить: %v", err)
	}
}

// Вспомогательные предикаты.
func TestIsValidUUID(t *testing.T) {
	if !isValidUUID("11111111-2222-3333-4444-555555555555") {
		t.Error("валидный uuid не распознан")
	}
	// 2026-08-24: неканонические идентификаторы БОЛЬШЕ НЕ мусор — sing-box/Xray
	// отображают любую строку в UUIDv5, и такие конфиги массово встречаются у публичных
	// провайдеров. Раньше строгая проверка отвергала рабочие ссылки (см. isValidUUID).
	if !isValidUUID("not-a-uuid") {
		t.Error("неканонический идентификатор отвергнут, хотя sing-box его принимает")
	}
	// Мусором остаётся пустое значение и строка с пробелами — почти всегда это склеенный
	// кусок чужого текста, а не идентификатор.
	for _, garbage := range []string{"", "   ", "abc def", "id\twith\ttabs"} {
		if isValidUUID(garbage) {
			t.Errorf("мусор %q принят за uuid", garbage)
		}
	}
}
