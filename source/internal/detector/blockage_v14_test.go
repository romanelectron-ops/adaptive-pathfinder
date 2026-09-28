// blockage_v14_test.go — ТЗ v1.4, лот L1-DET, пункт C-1.
//
// Дефект: SelectStrategy(BlockageComplete) (blockage.go:176-182) возвращает
// Primary: "tor+snowflake" и Reason: "Полная блокировка — только Tor Snowflake". Snowflake в
// сборке APF не реализован (нет pluggable-transport клиента, нет проводки в
// internal/singbox/config_builder.go — там для protocol=Tor строится только голый
// {Type:"tor"}, без bridges/ClientTransportPlugin). Строка уходит в пользовательский лог
// (engine.go:1146, "Primary: %s | Fallback: %s") и в диагностику (engine.go:5852,
// "strategy_primary") — пользователь видит обещание функции, которой нет.
//
// buildReport (blockage.go, ветка BlockageComplete) тоже говорит "APF пробует Tor Snowflake —
// работает через WebRTC браузеров" — тот же дефект в человекочитаемом отчёте.
package detector

import (
	"strings"
	"testing"
)

// TestC1_BlockageComplete_PrimaryHasNoSnowflake — основной тест из плана: Primary для
// BlockageComplete не содержит "snowflake" ни в каком регистре.
func TestC1_BlockageComplete_PrimaryHasNoSnowflake(t *testing.T) {
	s := SelectStrategy(BlockageComplete)
	if strings.Contains(strings.ToLower(s.Primary), "snowflake") {
		t.Errorf("Strategy.Primary для BlockageComplete всё ещё обещает snowflake: %q", s.Primary)
	}
}

// TestC1_BlockageComplete_ReasonIsHonest — Reason не должен утверждать, что Snowflake работает;
// должен упоминать Tor (Primary теперь "tor" — обычный Tor без pluggable transport).
func TestC1_BlockageComplete_ReasonIsHonest(t *testing.T) {
	s := SelectStrategy(BlockageComplete)
	if strings.Contains(strings.ToLower(s.Reason), "snowflake") {
		t.Errorf("Strategy.Reason для BlockageComplete всё ещё упоминает snowflake: %q", s.Reason)
	}
	if !strings.Contains(strings.ToLower(s.Reason), "tor") {
		t.Errorf("Strategy.Reason для BlockageComplete должен объяснять, что используется Tor: %q", s.Reason)
	}
}

// TestC1_BlockageComplete_PrimaryIsTor — Primary должен стать честным "tor" (простой Tor —
// единственный реально собираемый outbound для этого случая, см.
// internal/singbox/config_builder.go:791-803, BuildTor()).
func TestC1_BlockageComplete_PrimaryIsTor(t *testing.T) {
	s := SelectStrategy(BlockageComplete)
	if s.Primary != "tor" {
		t.Errorf("Strategy.Primary для BlockageComplete = %q, want \"tor\"", s.Primary)
	}
}

// TestC1_NoStrategy_PromisesSnowflake_AnyBlockageType — тест-страж: ни для какого типа
// блокировки ни Primary, ни Fallback, ни Reason не должны содержать "snowflake" — это гарантия
// уровня пакета detector (лестница FSM и остальные потребители — вне владения этого лота, C-14).
func TestC1_NoStrategy_PromisesSnowflake_AnyBlockageType(t *testing.T) {
	all := []BlockageType{
		BlockageNone, BlockageDNS, BlockageIP, BlockageSNI, BlockageDeep, BlockageComplete,
	}
	for _, bt := range all {
		s := SelectStrategy(bt)
		for field, val := range map[string]string{
			"Primary":  s.Primary,
			"Fallback": s.Fallback,
			"Reason":   s.Reason,
		} {
			if strings.Contains(strings.ToLower(val), "snowflake") {
				t.Errorf("SelectStrategy(%s).%s содержит snowflake: %q", bt, field, val)
			}
		}
	}
}

// TestC1_SelectStrategy_Complete_StillHasNonEmptyFallback — существующий тест
// TestSelectStrategy_Complete (blockage_test.go:82-90) и TestSelectStrategy_AllHaveRequiredFields
// (blockage_test.go:92-109) требуют НЕПУСТОГО Fallback для ЛЮБОГО типа блокировки, включая
// BlockageComplete. Раз "meek" не реализован (нет проводки в config_builder.go — искали,
// единственное упоминание "meek" в проекте — распознавание строки в парсере ответа BridgeDB,
// internal/sources/sources.go:205, не конфигурация реального клиента) и оставить Fallback
// пустым нельзя (сломает два протестированных выше кейса), фиксируем здесь, что фактическое
// решение — честный, реально собираемый outbound. Дублирует часть предыдущего теста намеренно,
// чтобы сам факт "Fallback не пуст и не meek" был виден в отчёте C-1, а не терялся в общем тесте.
func TestC1_SelectStrategy_Complete_StillHasNonEmptyFallback(t *testing.T) {
	s := SelectStrategy(BlockageComplete)
	if s.Fallback == "" {
		t.Error("Strategy.Fallback для BlockageComplete не должен быть пустым (см. blockage_test.go " +
			"TestSelectStrategy_Complete/TestSelectStrategy_AllHaveRequiredFields — трогать нельзя)")
	}
	if strings.Contains(strings.ToLower(s.Fallback), "meek") {
		t.Errorf("Strategy.Fallback для BlockageComplete всё ещё \"meek\" — транспорт нигде не "+
			"реализован (нет в config_builder.go), по ТЗ C-1 нереализуемый fallback нужно было "+
			"убрать/заменить: %q", s.Fallback)
	}
}

// TestC1_BuildReport_Complete_NoSnowflake — человекочитаемый отчёт (buildReport, вызывается из
// DiagnoseAndRecommend) для полной блокировки тоже не должен упоминать Snowflake.
func TestC1_BuildReport_Complete_NoSnowflake(t *testing.T) {
	d := New()
	s := SelectStrategy(BlockageComplete)
	report := d.buildReport(BlockageComplete, s)
	if strings.Contains(strings.ToLower(report), "snowflake") {
		t.Errorf("buildReport(BlockageComplete) всё ещё упоминает snowflake: %q", report)
	}
}
