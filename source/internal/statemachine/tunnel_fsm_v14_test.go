// tunnel_fsm_v14_test.go — лот L1b-ENG2 ТЗ v1.4: C-14.
//
// FAIL C2 живого прогона K8-LIVE: в пользовательском логе телефона стояло
// «FSM: escalating to level L4-LastResort (proto: tor-snowflake)» и следом
// «FSM: switching proto tor-snowflake → direct». Протокола tor-snowflake в сборке нет
// (см. C-6): имя нереализованного резерва попадало в лог из таблицы уровней.
package statemachine

import (
	"errors"
	"strings"
	"testing"
)

// TestV14_C14_Hierarchy_HasNoUnimplementedProtocol — табличный сторож лестницы.
func TestV14_C14_Hierarchy_HasNoUnimplementedProtocol(t *testing.T) {
	for _, lv := range DefaultFallbackHierarchy {
		for _, p := range lv.Protocols {
			if strings.Contains(strings.ToLower(p), "snowflake") {
				t.Fatalf("уровень %s предлагает протокол %q, которого нет в этой сборке: "+
					"его имя уходит в пользовательский лог и в решения автомата", lv.Name, p)
			}
		}
	}
}

// TestV14_C14_LastResortKeepsDirect — не удалять сам уровень: на нём стоит direct,
// последний резерв (предупреждение из ТЗ).
func TestV14_C14_LastResortKeepsDirect(t *testing.T) {
	var last *FallbackLevel
	for i := range DefaultFallbackHierarchy {
		if DefaultFallbackHierarchy[i].Name == "L4-LastResort" {
			last = &DefaultFallbackHierarchy[i]
		}
	}
	if last == nil {
		t.Fatal("уровень L4-LastResort исчез — направление «последнего резерва» потеряно")
	}
	found := false
	for _, p := range last.Protocols {
		if p == "direct" {
			found = true
		}
	}
	if !found {
		t.Fatalf("L4-LastResort без direct: %v", last.Protocols)
	}
}

// TestV14_C14_EscalationNeverNamesSnowflake — прогон автомата до исчерпания уровней:
// ни одна строка, которую он отдаёт наружу через OnLog/OnFallback/OnConnect, не называет
// протокол, которого нет.
func TestV14_C14_EscalationNeverNamesSnowflake(t *testing.T) {
	f := New(nil, 0)
	var lines []string
	f.OnLog = func(s string) { lines = append(lines, s) }
	f.OnFallback = func(from, to string) { lines = append(lines, from+" → "+to) }
	f.OnConnect = func(level, proto string) { lines = append(lines, level+" "+proto) }

	for i := 0; i < 50; i++ {
		f.HandleFailure(errors.New("тестовый сбой"))
	}
	for _, l := range lines {
		if strings.Contains(strings.ToLower(l), "snowflake") {
			t.Fatalf("автомат назвал нереализованный протокол: %q", l)
		}
	}
	if len(lines) == 0 {
		t.Skip("автомат ничего не отдаёт наружу — проверять нечего")
	}
}
