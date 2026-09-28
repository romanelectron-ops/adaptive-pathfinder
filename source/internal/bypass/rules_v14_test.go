// rules_v14_test.go — ТЗ v1.4, лот L1-DET, пункт C-2.
//
// Дефект: MatchDomain (rules.go:66) срезает префикс "www." у ПРОВЕРЯЕМОГО хоста, но правило,
// сохранённое как "www.site.com", хранит домен буквально — сравнение "www." никогда не срезанного
// правила с уже срезанным хостом не совпадает ни в одну сторону. Правило "www.site.com" не
// совпадает НИ С ЧЕМ (см. rules_k2e_validation_test.go:63-65, где это уже зафиксировано как
// известная особенность).
//
// Требование плана (PLAN_LOTS_v1.4_FINAL.json, лот L1-DET, acceptance): правило www.site.com
// совпадает с www.site.com И с site.com, но НЕ совпадает с notwww.site.com (набор label'ов у
// notwww.site.com — это обычный поддомен site.com, а не альтернативная запись www/bare одного и
// того же хоста; расширять до произвольных поддоменов было бы поведением ДРУГОГО, уже
// протестированного и защищённого кейса — TestMatchDomains_PlainEntryCatchesSubdomain в
// rules_extra_test.go, который сознательно НЕ трогаем).
package bypass

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestC2_WWWRule_MatchesWWWAndBare_NotSubdomain — основной тест из плана.
func TestC2_WWWRule_MatchesWWWAndBare_NotSubdomain(t *testing.T) {
	m, _ := k2eManager(t) // helper уже объявлен в rules_k2e_validation_test.go того же пакета

	rule := m.AddUserRule("www.site.com", "WWW Site", false, false)
	if rule == nil {
		t.Fatal("AddUserRule(\"www.site.com\") должно вернуть правило — это валидный домен")
	}

	if got := m.MatchDomain("www.site.com"); got == nil {
		t.Error("MatchDomain(\"www.site.com\") должно найти правило, добавленное как www.site.com")
	}
	if got := m.MatchDomain("site.com"); got == nil {
		t.Error("MatchDomain(\"site.com\") должно найти то же правило (www. — альтернативная запись того же хоста)")
	}
	if got := m.MatchDomain("notwww.site.com"); got != nil {
		t.Errorf("MatchDomain(\"notwww.site.com\") НЕ должно совпасть с правилом www.site.com "+
			"(это обычный поддомен, не www/bare-эквивалент), но нашло: %+v", got)
	}
}

// TestC2_BareRule_MatchesWWW — симметричный случай: правило без www тоже обязано матчить
// хост с www (это уже и раньше работало через MatchDomain-level TrimPrefix, но фиксируем явно
// как часть контракта C-2, чтобы регресс был виден).
func TestC2_BareRule_MatchesWWW(t *testing.T) {
	m, _ := k2eManager(t)
	rule := m.AddUserRule("baresite.com", "Bare Site", false, false)
	if rule == nil {
		t.Fatal("AddUserRule(\"baresite.com\") должно вернуть правило")
	}
	if got := m.MatchDomain("www.baresite.com"); got == nil {
		t.Error("MatchDomain(\"www.baresite.com\") должно найти правило baresite.com")
	}
}

// TestC2_MatchesDomains_WWWBareEquivalence_Direct — та же проверка на уровне чистой функции
// matchesDomains (без Manager), чтобы локализовать фикс именно в матчере.
func TestC2_MatchesDomains_WWWBareEquivalence_Direct(t *testing.T) {
	domains := []string{"www.site.com", "*.www.site.com"}

	tests := []struct {
		host string
		want bool
	}{
		{"www.site.com", true},
		{"site.com", true},
		{"notwww.site.com", false},
		{"evilsite.com", false},
	}
	for _, tt := range tests {
		got := matchesDomains(tt.host, domains)
		if got != tt.want {
			t.Errorf("matchesDomains(%q, %v) = %v, want %v", tt.host, domains, got, tt.want)
		}
	}
}

// TestC2_MigrateSavedWWWRule — файл, сохранённый ДО фикса (правило с буквальным префиксом
// "www." у домена), при загрузке должен: (а) стать рабочим (правило матчится), (б) быть
// нормализован и переписан на диск один раз (P12-подобная гигиена: старый мусор не должен
// висеть в файле вечно, см. комментарий у loadUserRules про "накладываем как переопределения").
func TestC2_MigrateSavedWWWRule(t *testing.T) {
	dir := t.TempDir()
	dataPath := filepath.Join(dir, "bypass_list.json")

	legacy := []*Rule{
		{
			ID:      "user_www_site_com",
			Name:    "WWW Site",
			Domains: []string{"www.legacysite.com", "*.www.legacysite.com"},
			Enabled: true,
			Builtin: false,
		},
	}
	data, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(dataPath)
	if err != nil {
		t.Fatal(err)
	}

	m := NewManager(dir)

	// (а) правило стало рабочим сразу после загрузки, в этом же процессе.
	if got := m.MatchDomain("www.legacysite.com"); got == nil {
		t.Error("мигрированное правило должно матчить www.legacysite.com")
	}
	if got := m.MatchDomain("legacysite.com"); got == nil {
		t.Error("мигрированное правило должно матчить legacysite.com (bare-форма)")
	}

	// (б) файл на диске переписан (нормализован) один раз при загрузке — содержимое изменилось
	// относительно исходного "грязного" файла с буквальным префиксом www.
	after, err := os.ReadFile(dataPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) == string(after) {
		t.Error("ожидалась миграция файла правил (перезапись без буквального префикса www.), " +
			"но содержимое bypass_list.json не изменилось")
	}

	// Повторная загрузка (перезапуск процесса) должна видеть уже мигрированное, рабочее правило.
	m2 := NewManager(dir)
	if got := m2.MatchDomain("www.legacysite.com"); got == nil {
		t.Error("после перезапуска мигрированное правило должно оставаться рабочим")
	}
}
