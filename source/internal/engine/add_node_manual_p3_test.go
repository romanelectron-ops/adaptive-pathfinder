package engine

import (
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// TestAddNodeManual_RejectsWireGuard — P3 (аудит 2026-09-01). AddNodeManual (редактор
// продвинутых полей, B-29) был единственным из трёх путей добавления узла в пул
// (updateSources, AddNodeFromLink, AddNodeManual), не отсеивающим WireGuard/AmneziaWG —
// см. isUnsupportedProtocol в engine.go. Узел с полным ключевым материалом (то, что
// реально приходит из формы редактора, в отличие от голой ссылки wireguard://, которую
// отсеивает уже ValidateNode раньше, см. TestAddNodeFromLink_RejectsWireGuard) проходил
// валидацию и оседал в пуле, циклически проверяясь и никогда не подключаясь — тот же
// дефект, что и в AddNodeFromLink, только для другого входа.
func TestAddNodeManual_RejectsWireGuard(t *testing.T) {
	e := newTestEngine()
	node := &models.Node{
		Protocol:       models.ProtoWireGuard,
		Address:        "wg.example.com",
		Port:           51820,
		Name:           "My WG",
		WGPrivateKey:   "cHJpdmF0ZWtleXBsYWNlaG9sZGVyMzJieXRlcyEhISE=",
		WGPublicKey:    "cHVibGlja2V5cGxhY2Vob2xkZXIzMmJ5dGVzISEhIQ==",
		WGLocalAddress: "10.0.0.2/32",
	}
	// Подготовка: убедиться, что запрос пройдёт ValidateNode (иначе тест проверял бы не то).
	if err := models.ValidateNode(node); err != nil {
		t.Fatalf("подготовка теста некорректна, узел не проходит ValidateNode: %v", err)
	}

	err := e.AddNodeManual(node)
	if err == nil {
		t.Fatal("AddNodeManual(WireGuard) = nil ошибка — ожидался отказ, " +
			"outbound-тип wireguard удалён в sing-box 1.13.0")
	}
	if len(e.nodes) != 0 {
		t.Errorf("узел всё равно попал в пул: %d узлов, ожидалось 0", len(e.nodes))
	}
}

// AmneziaWG — тот же фильтр, другое значение models.Protocol.
func TestAddNodeManual_RejectsAmneziaWG(t *testing.T) {
	e := newTestEngine()
	node := &models.Node{
		Protocol:       models.ProtoAmneziaWG,
		Address:        "awg.example.com",
		Port:           51820,
		Name:           "My AmneziaWG",
		WGPrivateKey:   "cHJpdmF0ZWtleXBsYWNlaG9sZGVyMzJieXRlcyEhISE=",
		WGPublicKey:    "cHVibGlja2V5cGxhY2Vob2xkZXIzMmJ5dGVzISEhIQ==",
		WGLocalAddress: "10.0.0.3/32",
	}
	if err := models.ValidateNode(node); err != nil {
		t.Fatalf("подготовка теста некорректна: %v", err)
	}
	if err := e.AddNodeManual(node); err == nil {
		t.Fatal("AddNodeManual(AmneziaWG) = nil ошибка — ожидался отказ")
	}
	if len(e.nodes) != 0 {
		t.Errorf("узел всё равно попал в пул: %d узлов, ожидалось 0", len(e.nodes))
	}
}

// Контрольная проверка: поддерживаемый протокол по-прежнему добавляется штатно — фильтр не
// стал отказывать всем подряд.
func TestAddNodeManual_AcceptsSupportedProtocol(t *testing.T) {
	e := newTestEngine()
	node := &models.Node{
		Protocol: models.ProtoShadowsocks,
		Address:  "ss.example.com",
		Port:     8388,
		Password: "secret",
		Method:   "aes-256-gcm",
		Name:     "My SS",
	}
	if err := e.AddNodeManual(node); err != nil {
		t.Fatalf("AddNodeManual(Shadowsocks) вернул ошибку: %v", err)
	}
	if len(e.nodes) != 1 {
		t.Errorf("узлов в пуле: %d, ожидался 1", len(e.nodes))
	}
}
