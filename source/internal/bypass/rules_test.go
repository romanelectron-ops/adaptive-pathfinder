package bypass

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── MatchDomain ────────────────────────────────────────────────────────────────

func TestMatchDomains_Exact(t *testing.T) {
	domains := []string{"netflix.com"}
	if !matchesDomains("netflix.com", domains) {
		t.Error("exact match should succeed")
	}
	if matchesDomains("notnetflix.com", domains) {
		t.Error("non-matching domain should fail")
	}
}

func TestMatchDomains_Wildcard(t *testing.T) {
	domains := []string{"*.netflix.com"}
	tests := []struct {
		host string
		want bool
	}{
		{"www.netflix.com", true},
		{"api.netflix.com", true},
		{"netflix.com", true}, // базовый домен тоже матчится
		{"notnetflix.com", false},
		{"evil.com.netflix.com.evil.com", false},
	}
	for _, tt := range tests {
		got := matchesDomains(tt.host, domains)
		if got != tt.want {
			t.Errorf("matchesDomains(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestMatchDomains_WWWStrip(t *testing.T) {
	domains := []string{"example.com"}
	// www.example.com должен матчить example.com
	if !matchesDomains("example.com", domains) {
		t.Error("bare domain should match")
	}
}

func TestMatchDomains_CaseInsensitive(t *testing.T) {
	domains := []string{"Netflix.COM"}
	if !matchesDomains("netflix.com", domains) {
		t.Error("domain matching should be case-insensitive")
	}
}

// ── builtinRules ──────────────────────────────────────────────────────────────

func TestBuiltinRules_Count(t *testing.T) {
	rules := builtinRules()
	if len(rules) < 5 {
		t.Errorf("expected at least 5 builtin rules, got %d", len(rules))
	}
}

func TestBuiltinRules_Netflix(t *testing.T) {
	rules := builtinRules()
	var netflix *Rule
	for _, r := range rules {
		if r.ID == "netflix" {
			netflix = r
			break
		}
	}
	if netflix == nil {
		t.Fatal("netflix rule not found in builtins")
	}
	if !netflix.RequireResidential {
		t.Error("netflix should require residential IP")
	}
	if !netflix.Enabled {
		t.Error("netflix rule should be enabled by default")
	}
	if !netflix.Builtin {
		t.Error("netflix rule should be marked as builtin")
	}
	if len(netflix.Domains) == 0 {
		t.Error("netflix rule should have domains")
	}
}

func TestBuiltinRules_AllHaveID(t *testing.T) {
	rules := builtinRules()
	ids := map[string]bool{}
	for _, r := range rules {
		if r.ID == "" {
			t.Error("found rule with empty ID")
		}
		if ids[r.ID] {
			t.Errorf("duplicate rule ID: %s", r.ID)
		}
		ids[r.ID] = true
		if r.Name == "" {
			t.Errorf("rule %s has empty name", r.ID)
		}
		if len(r.Domains) == 0 {
			t.Errorf("rule %s has no domains", r.ID)
		}
	}
}

// ── Manager ───────────────────────────────────────────────────────────────────

func tmpManager(t *testing.T) (*Manager, string) {
	dir := t.TempDir()
	return NewManager(dir), dir
}

func TestManager_MatchDomain_Netflix(t *testing.T) {
	m, _ := tmpManager(t)
	rule := m.MatchDomain("www.netflix.com")
	if rule == nil {
		t.Fatal("expected netflix rule to match www.netflix.com")
	}
	if rule.ID != "netflix" {
		t.Errorf("expected netflix, got %s", rule.ID)
	}
}

func TestManager_MatchDomain_Unknown(t *testing.T) {
	m, _ := tmpManager(t)
	rule := m.MatchDomain("randomsite12345.com")
	if rule != nil {
		t.Errorf("unexpected rule match for unknown domain: %s", rule.ID)
	}
}

func TestManager_RequiresResidential(t *testing.T) {
	m, _ := tmpManager(t)
	if !m.RequiresResidential("netflix.com") {
		t.Error("netflix.com should require residential")
	}
	if m.RequiresResidential("unknown-random-site.xyz") {
		t.Error("unknown site should not require residential")
	}
}

func TestManager_Rules_ReturnsAll(t *testing.T) {
	m, _ := tmpManager(t)
	rules := m.Rules()
	if len(rules) == 0 {
		t.Error("expected at least builtin rules")
	}
}

func TestManager_SetRuleEnabled(t *testing.T) {
	m, _ := tmpManager(t)

	// netflix включён по умолчанию
	rule := m.MatchDomain("netflix.com")
	if rule == nil || !rule.Enabled {
		t.Fatal("netflix should be enabled by default")
	}

	// Выключаем
	ok := m.SetRuleEnabled("netflix", false)
	if !ok {
		t.Error("SetRuleEnabled should return true for existing rule")
	}
	rule2 := m.MatchDomain("netflix.com")
	if rule2 != nil {
		t.Error("disabled netflix rule should not match")
	}

	// Включаем обратно
	m.SetRuleEnabled("netflix", true)
	rule3 := m.MatchDomain("netflix.com")
	if rule3 == nil {
		t.Error("re-enabled netflix rule should match again")
	}
}

func TestManager_SetRuleEnabled_NotFound(t *testing.T) {
	m, _ := tmpManager(t)
	ok := m.SetRuleEnabled("nonexistent-rule-xyz", true)
	if ok {
		t.Error("SetRuleEnabled should return false for unknown rule")
	}
}

func TestManager_AddUserRule(t *testing.T) {
	m, dir := tmpManager(t)

	rule := m.AddUserRule("mysite.com", "My Site", true, false)
	if rule == nil {
		t.Fatal("AddUserRule should return created rule")
	}
	if rule.ID == "" {
		t.Error("created rule should have ID")
	}
	if rule.Builtin {
		t.Error("user rule should not be marked as builtin")
	}
	if !rule.Enabled {
		t.Error("user rule should be enabled by default")
	}

	// Проверяем что матчится
	matched := m.MatchDomain("mysite.com")
	if matched == nil {
		t.Error("newly added domain should match")
	}

	// Проверяем файл на диске
	path := filepath.Join(dir, "bypass_list.json")
	if _, err := os.Stat(path); err != nil {
		t.Errorf("bypass_list.json should exist after AddUserRule: %v", err)
	}
}

func TestManager_AddUserRule_Duplicate(t *testing.T) {
	m, _ := tmpManager(t)
	r1 := m.AddUserRule("dupsite.com", "Dup", true, false)
	r2 := m.AddUserRule("dupsite.com", "Dup2", true, false)
	if r1 == nil || r2 == nil {
		t.Fatal("both calls should return non-nil")
	}
	// Второй вызов должен вернуть существующее (не создавать дубль)
	if r1.ID != r2.ID {
		t.Errorf("duplicate domain should return same rule ID: %s vs %s", r1.ID, r2.ID)
	}
}

func TestManager_RemoveUserRule(t *testing.T) {
	m, _ := tmpManager(t)

	rule := m.AddUserRule("removeme.com", "Remove Me", false, false)
	if rule == nil {
		t.Fatal("failed to add rule")
	}

	ok := m.RemoveUserRule(rule.ID)
	if !ok {
		t.Error("RemoveUserRule should return true for existing user rule")
	}

	// Больше не матчится
	matched := m.MatchDomain("removeme.com")
	if matched != nil {
		t.Error("removed rule should no longer match")
	}
}

func TestManager_RemoveBuiltinRule(t *testing.T) {
	m, _ := tmpManager(t)
	// Builtin правила нельзя удалять
	ok := m.RemoveUserRule("netflix")
	if ok {
		t.Error("cannot remove builtin rule")
	}
}

// ── UpdateUserRule ───────────────────────────────────────────────────────────

func TestManager_UpdateUserRule(t *testing.T) {
	m, _ := tmpManager(t)
	rule := m.AddUserRule("editme.com", "Edit Me", false, false)
	if rule == nil {
		t.Fatal("failed to add rule")
	}

	ok := m.UpdateUserRule(rule.ID, "edited.com", "Edited Name", true, true)
	if !ok {
		t.Fatal("UpdateUserRule should succeed for existing user rule")
	}

	rules := m.Rules()
	var found *Rule
	for _, r := range rules {
		if r.ID == rule.ID {
			found = r
		}
	}
	if found == nil {
		t.Fatal("rule should still exist after update")
	}
	if found.Name != "Edited Name" {
		t.Errorf("Name = %q, want %q", found.Name, "Edited Name")
	}
	if !found.RequireResidential || !found.DirectRoute {
		t.Errorf("flags not updated: residential=%v direct_route=%v", found.RequireResidential, found.DirectRoute)
	}
	if m.MatchDomain("edited.com") == nil {
		t.Error("updated domain should match")
	}
	if m.MatchDomain("editme.com") != nil {
		t.Error("old domain should no longer match after edit")
	}
}

func TestManager_UpdateUserRule_BuiltinRejected(t *testing.T) {
	m, _ := tmpManager(t)
	ok := m.UpdateUserRule("netflix", "evil.com", "Evil", false, true)
	if ok {
		t.Error("UpdateUserRule should refuse to edit a builtin rule")
	}
}

func TestManager_UpdateUserRule_Unknown(t *testing.T) {
	m, _ := tmpManager(t)
	ok := m.UpdateUserRule("no-such-id", "x.com", "X", false, false)
	if ok {
		t.Error("UpdateUserRule should return false for unknown id")
	}
}

// ── DirectRouteDomains ───────────────────────────────────────────────────────

func TestManager_DirectRouteDomains(t *testing.T) {
	m, _ := tmpManager(t)
	m.AddUserRule("direct1.com", "Direct1", false, true)
	m.AddUserRule("throughvpn.com", "ThroughVPN", true, false) // residential, NOT direct
	disabled := m.AddUserRule("direct2.com", "Direct2Disabled", false, true)
	if disabled != nil {
		m.SetRuleEnabled(disabled.ID, false) // enabled=false → must be excluded
	}

	domains := m.DirectRouteDomains()
	joined := strings.Join(domains, ",")
	if !strings.Contains(joined, "direct1.com") {
		t.Errorf("DirectRouteDomains() = %v, want to contain direct1.com", domains)
	}
	if strings.Contains(joined, "throughvpn.com") {
		t.Errorf("DirectRouteDomains() = %v, should NOT contain residential-only throughvpn.com", domains)
	}
	if strings.Contains(joined, "direct2.com") {
		t.Errorf("DirectRouteDomains() = %v, should NOT contain disabled direct2.com", domains)
	}
	// Живой прогон 2026-08-13: буквальная "*." в domain_suffix ломает матчинг в sing-box.
	for _, d := range domains {
		if strings.HasPrefix(d, "*.") {
			t.Errorf("DirectRouteDomains() = %v, must not contain wildcard-prefixed entries (sing-box domain_suffix doesn't use \"*.\")", domains)
		}
	}
}

func TestManager_Persistence(t *testing.T) {
	dir := t.TempDir()

	// Создаём первый manager, добавляем правило
	m1 := NewManager(dir)
	m1.AddUserRule("persist-test.com", "Persist Test", true, false)

	// Создаём второй manager из той же директории — должен загрузить сохранённые правила
	m2 := NewManager(dir)
	matched := m2.MatchDomain("persist-test.com")
	if matched == nil {
		t.Error("user rule should persist across Manager restarts")
	}
}

// TestManager_BuiltinRuleToggle_PersistsAcrossRestart — регресс на исторический баг
// (найден ревью 2026-08-24, см. комментарий у loadUserRules): переключатель встроенного
// правила ("Госуслуги" и т.п., Enabled по умолчанию false — opt-in) отрабатывал в текущем
// процессе, но NewManager каждый новый запуск пересоздавал список из builtinRules() и
// пользовательский выбор молча забывался. Правило "Госуслуги" — не выдумка теста: это
// ровно тот сценарий, ради которого добавлен код "накладываем как переопределения" в
// loadUserRules и "сохраняем только если отклонились от заводского" в saveUserRules.
func TestManager_BuiltinRuleToggle_PersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()

	m1 := NewManager(dir)
	// gosuslugi выключен по умолчанию (opt-in) — явно проверяем заводское состояние перед
	// изменением, иначе тест ничего не доказывает.
	if rule := m1.MatchDomain("gosuslugi.ru"); rule != nil {
		t.Fatalf("gosuslugi should be disabled by default, but matched: %+v", rule)
	}
	if ok := m1.SetRuleEnabled("gosuslugi", true); !ok {
		t.Fatal("SetRuleEnabled(gosuslugi, true) should find the builtin rule")
	}
	if rule := m1.MatchDomain("gosuslugi.ru"); rule == nil {
		t.Fatal("gosuslugi should match right after enabling, in the same process")
	}

	// Перезапуск: новый Manager из того же dataDir должен увидеть выбор пользователя, а не
	// заводское Enabled=false.
	m2 := NewManager(dir)
	rule := m2.MatchDomain("gosuslugi.ru")
	if rule == nil {
		t.Fatal("builtin rule toggle must survive a Manager restart, but gosuslugi reverted to disabled")
	}
	if !rule.DirectRoute {
		t.Error("restored builtin rule must keep its DirectRoute=true (factory field), not just Enabled")
	}

	// И обратный переключатель (выключить обратно в заводское состояние) не должен оставлять
	// правило висящим отдельной пользовательской записью навсегда — саму эту деталь
	// TestManager_Persistence не проверяет, добавляем здесь.
	m2.SetRuleEnabled("gosuslugi", false)
	m3 := NewManager(dir)
	if rule := m3.MatchDomain("gosuslugi.ru"); rule != nil {
		t.Error("gosuslugi toggled back to factory-default (disabled) should stay disabled after restart")
	}
}
