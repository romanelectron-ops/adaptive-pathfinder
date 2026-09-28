package hostguard

import "testing"

// Контракт-ящик hostguard. Категории: позитив / негатив / fail-safe / стойкость.

// (1) Позитив: под `go test` барьер ВЗВЕДЁН — это главный инвариант пакета.
// Если этот тест когда-нибудь упадёт, значит `go test` снова может менять настройки машины.
func TestBarrierArmedUnderTest(t *testing.T) {
	if !UnderTest() {
		t.Fatal("detectTestBinary() не распознал тестовый бинарник — барьер не взведён")
	}
	if Overridden() {
		t.Skip("барьер снят через " + forceEnv + " — это допустимо ТОЛЬКО в изолированной ВМ")
	}
	if Allowed() {
		t.Fatal("ИНВАРИАНТ НАРУШЕН: под `go test` мутации хоста разрешены")
	}
}

// (2) Негатив: Allow() отклоняет операцию и регистрирует её.
func TestAllowBlocksAndRecords(t *testing.T) {
	if Overridden() {
		t.Skip("барьер снят через " + forceEnv)
	}
	ResetBlocked()
	defer ResetBlocked()

	if Allow("test.DangerousOp") {
		t.Fatal("Allow вернул true под `go test`")
	}
	ops := BlockedOps()
	if len(ops) != 1 || ops[0] != "test.DangerousOp" {
		t.Fatalf("BlockedOps = %v, want [test.DangerousOp]", ops)
	}
	if BlockedCount() != 1 {
		t.Fatalf("BlockedCount = %d, want 1", BlockedCount())
	}
}

// (3) Fail-safe: значение override намеренно неугадываемое — «1»/«true»/«yes» не снимают барьер.
// Иначе барьер сняли бы случайно, и защита превратилась бы в фикцию.
func TestOverrideRequiresExactAwkwardValue(t *testing.T) {
	for _, v := range []string{"1", "true", "yes", "on", "", "I-KNOW-THIS-IS-AN-ISOLATED-VM"} {
		if v == forceValue {
			t.Fatalf("тест некорректен: %q совпадает с реальным значением override", v)
		}
	}
	if forceValue == "1" || len(forceValue) < 16 {
		t.Fatalf("значение override %q слишком легко выставить случайно", forceValue)
	}
}

// (4) Стойкость: многократные вызовы накапливаются и не теряются; Reset очищает.
func TestBlockedAccumulatesAndResets(t *testing.T) {
	if Overridden() {
		t.Skip("барьер снят через " + forceEnv)
	}
	ResetBlocked()
	defer ResetBlocked()
	for i := 0; i < 50; i++ {
		Allow("op")
	}
	if BlockedCount() != 50 {
		t.Fatalf("BlockedCount = %d, want 50", BlockedCount())
	}
	ResetBlocked()
	if BlockedCount() != 0 {
		t.Fatalf("после ResetBlocked BlockedCount = %d, want 0", BlockedCount())
	}
}
