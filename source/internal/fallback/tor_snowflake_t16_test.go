package fallback

import (
	"context"
	"testing"
)

// T-16(б) — честный fallback: при отсутствии Tor/psiphond SelectBest не маскирует выбор.
// (Сама подмена на явный Tor с честным сообщением — в engine; здесь проверяем, что
// SelectBest детерминирован и не паникует без бинарей.)

func TestSelectBest_NoBinaries_NoPanic(t *testing.T) {
	orch := NewFallbackOrchestrator("/nonexistent-bindir-apf-test", "", func(string) {})
	// не должно паниковать; при отсутствии Tor вернётся ветка Psiphon (→ Tor в движке)
	got := orch.SelectBest(context.Background())
	if got == "" {
		t.Error("SelectBest должен вернуть непустой туннель даже без бинарей")
	}
}

func TestPsiphonManager_IsAvailable_FalseWhenMissing(t *testing.T) {
	m := NewPsiphonManager(DefaultPsiphonConfig(""), func(string) {})
	if m.IsAvailable("/nonexistent-bindir-apf-test") {
		t.Error("IsAvailable должен быть false, когда psiphond не установлен")
	}
}
