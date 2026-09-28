package harvester

// Тесты бюджетов и деградации (AI-10).

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDefaultBudgetMatchesTZ(t *testing.T) {
	b := DefaultBudget()
	if b.Timeout != 10*time.Minute {
		t.Errorf("AI-10: время прохода по умолчанию — 10 мин, получено %v", b.Timeout)
	}
	if b.ModelCtxTokens != 4096 {
		t.Errorf("AI-10: n_ctx = 4096, получено %d", b.ModelCtxTokens)
	}
	if b.ModelWindowTokens > 2000 {
		t.Errorf("AI-4: окно ≤ 2000 токенов, получено %d", b.ModelWindowTokens)
	}
	if b.ConfirmK != 10 {
		t.Errorf("C-18: K = 10 подтверждений за проход, получено %d", b.ConfirmK)
	}
	if b.MinFreeMemBytes != MinFreeMemForModel {
		t.Errorf("AI-10: порог памяти 1,8 ГиБ, получено %d", b.MinFreeMemBytes)
	}
	if MinFreeMemForModel < 1_932_000_000 || MinFreeMemForModel > 1_933_000_000 {
		t.Errorf("порог должен быть ровно 1,8 ГиБ, получено %d", MinFreeMemForModel)
	}
	if b.MaxBodyBytes != 10*1024*1024 {
		t.Errorf("лимит тела должен совпадать с лимитом sources.Manager (10 МБ), получено %d", b.MaxBodyBytes)
	}
	if err := b.Validate(); err != nil {
		t.Errorf("бюджет по умолчанию обязан быть валидным: %v", err)
	}
}

func TestZeroBudgetNormalizesToDefaults(t *testing.T) {
	got := Budget{}.Normalize()
	if got != DefaultBudget() {
		t.Errorf("нулевой бюджет должен превращаться в умолчания, получено %+v", got)
	}
	neg := Budget{MaxBodyBytes: -1, MaxSources: -5, MaxCandidates: -7, Timeout: -time.Second,
		MinFreeMemBytes: -1, ModelCtxTokens: -1, ModelWindowTokens: -1, ModelWindowOvlp: -1, ConfirmK: -1}.Normalize()
	if err := neg.Validate(); err != nil {
		t.Errorf("после нормализации бюджет обязан быть валидным: %v", err)
	}
}

// Порог AI-10: ниже 1,8 ГиБ модельный проход не стартует, и текст объясняет, что закрыть.
func TestLowMemoryRefusalHasHumanText(t *testing.T) {
	probe := func() (int64, bool) { return 1_200_000_000, true } // 1,12 ГиБ
	err := CheckModelPreconditions(DefaultBudget(), probe)
	if err == nil {
		t.Fatal("при 1,12 ГиБ свободной памяти модельный проход обязан быть отклонён")
	}
	if !errors.Is(err, ErrLowMemory) {
		t.Fatalf("ожидалась ErrLowMemory, получено %v", err)
	}
	msg := err.Error()
	for _, must := range []string{"1,8 ГиБ", "Закройте", "без", "модели"} {
		if !strings.Contains(msg, must) {
			t.Errorf("текст отказа должен содержать %q: %s", must, msg)
		}
	}
}

func TestEnoughMemoryPasses(t *testing.T) {
	probe := func() (int64, bool) { return 2_400_000_000, true } // 2,23 ГиБ
	if err := CheckModelPreconditions(DefaultBudget(), probe); err != nil {
		t.Fatalf("при 2,23 ГиБ отказа быть не должно: %v", err)
	}
}

// Неизвестная память — тоже отказ модельного пути: цена ошибки (убитое системой приложение
// вместе с активным туннелем) несопоставима с выгодой.
func TestUnknownMemoryRefusesModel(t *testing.T) {
	err := CheckModelPreconditions(DefaultBudget(), func() (int64, bool) { return 0, false })
	if !errors.Is(err, ErrMemUnknown) {
		t.Fatalf("ожидалась ErrMemUnknown, получено %v", err)
	}
}

func TestSystemMemAvailableNeverPanics(t *testing.T) {
	// На Windows /proc/meminfo нет — обязан вернуть «неизвестно», а не упасть.
	if v, ok := SystemMemAvailable(); ok && v <= 0 {
		t.Errorf("замер вернул «известно» с бессмысленным значением %d", v)
	}
}

func TestHumanBytesRussianDecimalComma(t *testing.T) {
	if got := humanBytes(MinFreeMemForModel); got != "1,8 ГиБ" {
		t.Errorf("ожидалось «1,8 ГиБ», получено %q", got)
	}
}
