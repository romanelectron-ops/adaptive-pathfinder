package engine

import (
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// TestChainPartnerUnreachableMessage — живой инцидент 2026-09-29: лог «партнёр недоступен» для
// партнёра с приватным адресом (ссылка из другой сети) обязан объяснять причину, а для
// публичного адреса/имени хоста — остаться прежним, без ложного намёка на топологию сети.
func TestChainPartnerUnreachableMessage(t *testing.T) {
	const base = "⚠ Партнёр цепочки Вход-Выход «Ноут» недоступен — жду восстановления, " +
		"не подменяю случайным узлом из общего пула"

	for _, addr := range []string{"8.8.8.8", "partner.example.com", ""} {
		n := &models.Node{Name: "Ноут", Address: addr, IsChainPartner: true}
		if got := chainPartnerUnreachableMessage(n); got != base {
			t.Errorf("адрес %q: предупреждать не о чем, сообщение должно остаться прежним, получено %q", addr, got)
		}
	}

	got := chainPartnerUnreachableMessage(&models.Node{Name: "Ноут", Address: "10.0.0.37", IsChainPartner: true})
	if !strings.HasPrefix(got, base) {
		t.Errorf("прежняя формулировка должна сохраниться в начале: %q", got)
	}
	if !strings.Contains(got, "10.0.0.37") || !strings.Contains(got, "LAN") {
		t.Errorf("для приватного адреса ожидалось объяснение про LAN с самим адресом: %q", got)
	}
}

// TestChainPartnerUnreachableMessage_RelayPartnerHasNoAddressWarning — ревью 1.1.10 (F1):
// у партнёра по relay-ссылке AddChainPartnerFromLink подменяет Address на локальный адрес
// EntryBridge (127.0.0.1), реальный путь идёт через apf-relay. Предупреждение «адрес loopback —
// ссылка сработает только на этом устройстве» для него ложно и уводит от настоящей причины.
// Прямой (не relay) партнёр с тем же loopback-адресом предупреждение по-прежнему получает.
func TestChainPartnerUnreachableMessage_RelayPartnerHasNoAddressWarning(t *testing.T) {
	const base = "⚠ Партнёр цепочки Вход-Выход «Ноут» недоступен — жду восстановления, " +
		"не подменяю случайным узлом из общего пула"

	relayPartner := &models.Node{
		Name: "Ноут", Address: "127.0.0.1", Port: 40123, IsChainPartner: true,
		ExtraParams: map[string]string{"apf_relay": "1", "apf_exitid": "deadbeef"},
	}
	got := chainPartnerUnreachableMessage(relayPartner)
	if got != base {
		t.Errorf("relay-партнёр с loopback-адресом моста: адресное предупреждение вводит в заблуждение, "+
			"ожидалось прежнее сообщение без него, получено %q", got)
	}
	if strings.Contains(got, "loopback") || strings.Contains(got, "127.0.0.1") {
		t.Errorf("в сообщении для relay-партнёра не должно быть упоминания loopback/адреса моста: %q", got)
	}

	// То же для приватного адреса: у relay-узла он тоже не путь до партнёра.
	relayPartner.Address = "192.168.1.10"
	if got := chainPartnerUnreachableMessage(relayPartner); got != base {
		t.Errorf("relay-партнёр с приватным адресом: ожидалось прежнее сообщение, получено %q", got)
	}

	// Прямой партнёр (без apf_relay) с loopback — существующее поведение сохраняется.
	direct := &models.Node{Name: "Ноут", Address: "127.0.0.1", Port: 8443, IsChainPartner: true}
	got = chainPartnerUnreachableMessage(direct)
	if !strings.HasPrefix(got, base) {
		t.Errorf("прежняя формулировка должна сохраниться в начале: %q", got)
	}
	if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "loopback") {
		t.Errorf("прямой партнёр с loopback-адресом обязан получить предупреждение: %q", got)
	}

	// apf_relay не равный "1" (например, "0") — не relay-режим.
	notRelay := &models.Node{
		Name: "Ноут", Address: "127.0.0.1", IsChainPartner: true,
		ExtraParams: map[string]string{"apf_relay": "0"},
	}
	if got := chainPartnerUnreachableMessage(notRelay); !strings.Contains(got, "loopback") {
		t.Errorf("apf_relay=0 не relay-режим, предупреждение об адресе должно остаться: %q", got)
	}
}
