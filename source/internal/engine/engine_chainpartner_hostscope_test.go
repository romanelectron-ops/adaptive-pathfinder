package engine

import (
	"strings"
	"testing"
)

// TestChainPartnerUnreachableMessage — живой инцидент 2026-09-29: лог «партнёр недоступен» для
// партнёра с приватным адресом (ссылка из другой сети) обязан объяснять причину, а для
// публичного адреса/имени хоста — остаться прежним, без ложного намёка на топологию сети.
func TestChainPartnerUnreachableMessage(t *testing.T) {
	const base = "⚠ Партнёр цепочки Вход-Выход «Ноут» недоступен — жду восстановления, " +
		"не подменяю случайным узлом из общего пула"

	for _, addr := range []string{"8.8.8.8", "partner.example.com", ""} {
		if got := chainPartnerUnreachableMessage("Ноут", addr); got != base {
			t.Errorf("адрес %q: предупреждать не о чем, сообщение должно остаться прежним, получено %q", addr, got)
		}
	}

	got := chainPartnerUnreachableMessage("Ноут", "10.0.0.37")
	if !strings.HasPrefix(got, base) {
		t.Errorf("прежняя формулировка должна сохраниться в начале: %q", got)
	}
	if !strings.Contains(got, "10.0.0.37") || !strings.Contains(got, "LAN") {
		t.Errorf("для приватного адреса ожидалось объяснение про LAN с самим адресом: %q", got)
	}
}
