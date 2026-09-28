package singbox

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/parser"
	"github.com/google/uuid"
)

// GenerateServerIdentity — контракт: поля синтаксически корректны и пригодны для JSON/ссылки
// без дальнейшей обработки (ТЗ §2: ключ звена генерируется один раз при первом запуске).
func TestGenerateServerIdentity_ProducesValidFields(t *testing.T) {
	id, err := GenerateServerIdentity()
	if err != nil {
		t.Fatalf("GenerateServerIdentity: %v", err)
	}

	if _, err := uuid.Parse(id.UUID); err != nil {
		t.Errorf("UUID %q не парсится: %v", id.UUID, err)
	}

	priv, err := base64.RawURLEncoding.DecodeString(id.PrivateKey)
	if err != nil {
		t.Fatalf("PrivateKey не base64.RawURLEncoding: %v", err)
	}
	if len(priv) != 32 {
		t.Errorf("len(PrivateKey) = %d, ожидалось 32 (см. reality_server.go: invalid private key)", len(priv))
	}

	pub, err := base64.RawURLEncoding.DecodeString(id.PublicKey)
	if err != nil {
		t.Fatalf("PublicKey не base64.RawURLEncoding: %v", err)
	}
	if len(pub) != 32 {
		t.Errorf("len(PublicKey) = %d, ожидалось 32", len(pub))
	}

	sid, err := hex.DecodeString(id.ShortID)
	if err != nil {
		t.Fatalf("ShortID не hex: %v", err)
	}
	if len(sid) > 8 {
		t.Errorf("len(ShortID) = %d байт, sing-box отвергает short_id длиннее 8 (reality_server.go)", len(sid))
	}
}

// Два вызова НИКОГДА не совпадают (crypto/rand, не math/rand) — иначе два звена цепочки
// получили бы одинаковые ключи, и компрометация одного отдавала бы оба (ТЗ §2).
func TestGenerateServerIdentity_NeverRepeats(t *testing.T) {
	a, err := GenerateServerIdentity()
	if err != nil {
		t.Fatalf("GenerateServerIdentity #1: %v", err)
	}
	b, err := GenerateServerIdentity()
	if err != nil {
		t.Fatalf("GenerateServerIdentity #2: %v", err)
	}
	if a.UUID == b.UUID || a.PrivateKey == b.PrivateKey || a.ShortID == b.ShortID {
		t.Fatalf("два вызова GenerateServerIdentity совпали: %+v == %+v", a, b)
	}
}

// Регрессия на рассинхронизацию формата: BuildServerLink генерирует ссылку, которую
// internal/parser.ParseLink (тот же путь, что и «Добавить сервер» в UI) обязан разобрать
// РОВНО в те значения, что были в identity — иначе сервер и клиент этого же проекта не
// смогут договориться о формате собственной ссылки.
func TestBuildServerLink_RoundTripsThroughParser(t *testing.T) {
	id, err := GenerateServerIdentity()
	if err != nil {
		t.Fatalf("GenerateServerIdentity: %v", err)
	}

	link := BuildServerLink(id, "203.0.113.10", 8443, "www.microsoft.com", "Звено 1: Тест")

	node, err := parser.ParseLink(link)
	if err != nil {
		t.Fatalf("parser.ParseLink(%q): %v", link, err)
	}

	if node.Protocol != models.ProtoVLESS {
		t.Errorf("Protocol = %v, ожидался VLESS", node.Protocol)
	}
	if node.UUID != id.UUID {
		t.Errorf("UUID = %q, ожидался %q", node.UUID, id.UUID)
	}
	if node.Address != "203.0.113.10" || node.Port != 8443 {
		t.Errorf("Address:Port = %s:%d, ожидалось 203.0.113.10:8443", node.Address, node.Port)
	}
	if node.Flow != "xtls-rprx-vision" {
		t.Errorf("Flow = %q, ожидался xtls-rprx-vision", node.Flow)
	}
	if node.TLS == nil || !node.TLS.Enabled || node.TLS.ServerName != "www.microsoft.com" {
		t.Fatalf("TLS = %+v, ожидался Enabled=true ServerName=www.microsoft.com", node.TLS)
	}
	if node.TLS.Reality == nil {
		t.Fatal("TLS.Reality = nil, ожидалась Reality-конфигурация")
	}
	if node.TLS.Reality.PublicKey != id.PublicKey {
		t.Errorf("Reality.PublicKey = %q, ожидался %q", node.TLS.Reality.PublicKey, id.PublicKey)
	}
	if node.TLS.Reality.ShortID != id.ShortID {
		t.Errorf("Reality.ShortID = %q, ожидался %q", node.TLS.Reality.ShortID, id.ShortID)
	}
}
