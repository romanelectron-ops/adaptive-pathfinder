// rules_k2e_validation_test.go — К2-E П12 (свод C, трек 1 №12; B1 #3, A3).
//
// Дефект: bypass-правила принимались без единой проверки — ни на вводе (AddUserRule делала
// только ToLower+TrimSpace), ни при загрузке bypass_list.json (json.Unmarshal и сразу в
// рабочий список). Цена ошибки здесь выше, чем у блок-листа: правило с DirectRoute=true
// выводит домен ИЗ туннеля целиком, и сайт видит настоящий IP пользователя. Мусорный домен
// («https://x/», строка с пробелами, пустая) либо не совпадает ни с чем и молча не работает,
// при этом исправно отображаясь в интерфейсе как действующее правило, либо (в отредактированном
// руками или повреждённом файле) попадает в маршрутизацию неожиданным образом.
package bypass

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func k2eManager(t *testing.T) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()
	return NewManager(dir), dir
}

// TestK2E_AddUserRuleChecked_RejectsGarbage — мусор отвергается с понятной ошибкой.
func TestK2E_AddUserRuleChecked_RejectsGarbage(t *testing.T) {
	m, _ := k2eManager(t)
	garbage := []string{
		"",
		"   ",
		"\t\n",
		"https://x/",
		"http://localhost/",
		"example .com",
		"two words",
		"*.wildcard",
		"nodot",
		".",
		"...",
		"a,b.com",
	}
	for _, g := range garbage {
		rule, err := m.AddUserRuleChecked(g, "Мусор", false, true)
		if err == nil || rule != nil {
			t.Errorf("ввод %q принят как домен (rule=%v, err=%v)", g, rule, err)
			continue
		}
		if !strings.Contains(err.Error(), "домен") {
			t.Errorf("ошибка для %q должна объяснять причину человеку: %v", g, err)
		}
	}
	if n := len(m.Rules()) - len(builtinRules()); n != 0 {
		t.Fatalf("мусор всё же попал в список правил: +%d", n)
	}
	t.Log("OK: мусорный ввод отвергнут целиком")
}

// TestK2E_AddUserRuleChecked_NormalizesInput — пригодный, но «грязный» ввод нормализуется, а не
// кладётся дословно: иначе правило видно в интерфейсе, но ни с чем не совпадает.
func TestK2E_AddUserRuleChecked_NormalizesInput(t *testing.T) {
	m, _ := k2eManager(t)
	// Не "www.*" сознательно: MatchDomain срезает префикс "www." у ПРОВЕРЯЕМОГО хоста, из-за
	// чего правило, записанное как "www.site.com", не совпадает ни с чем. Это отдельная,
	// более старая особенность матчера, к П12 отношения не имеющая, — не смешиваем её сюда.
	rule, err := m.AddUserRuleChecked("  HTTPS://Shop.Example.COM:443/some/path?q=1  ", "", false, true)
	if err != nil {
		t.Fatalf("нормальный домен со схемой и путём должен приниматься: %v", err)
	}
	if rule == nil {
		t.Fatal("правило не создано")
	}
	if rule.Domains[0] != "shop.example.com" {
		t.Fatalf("домен не нормализован: %q", rule.Domains[0])
	}
	if m.MatchDomain("shop.example.com") == nil {
		t.Error("нормализованное правило должно совпадать со своим доменом")
	}
	for _, d := range m.DirectRouteDomains() {
		if strings.ContainsAny(d, " /:?") {
			t.Errorf("в маршрутизацию ушёл ненормализованный домен: %q", d)
		}
	}
	t.Logf("OK: %q → %v", "HTTPS://Shop.Example.COM:443/some/path?q=1", rule.Domains)
}

// TestK2E_AddUserRule_LegacyContract — старый контракт сохранён: nil при отказе, правило при успехе.
func TestK2E_AddUserRule_LegacyContract(t *testing.T) {
	m, _ := k2eManager(t)
	if r := m.AddUserRule("https://x/", "Мусор", false, false); r != nil {
		t.Error("AddUserRule должна вернуть nil на мусорный ввод")
	}
	if r := m.AddUserRule("good-domain.com", "Хороший", false, false); r == nil {
		t.Error("AddUserRule должна вернуть правило на корректный домен")
	}
	t.Log("OK: контракт AddUserRule сохранён")
}

// TestK2E_UpdateUserRule_RejectsGarbage — редактирование тоже не принимает мусор.
func TestK2E_UpdateUserRule_RejectsGarbage(t *testing.T) {
	m, _ := k2eManager(t)
	rule := m.AddUserRule("editme.com", "Правлю", false, false)
	if rule == nil {
		t.Fatal("подготовка не удалась")
	}
	if m.UpdateUserRule(rule.ID, "https://x/", "Мусор", false, true) {
		t.Error("UpdateUserRule приняла мусорный домен")
	}
	if m.MatchDomain("editme.com") == nil {
		t.Error("прежний домен потерян после отказа — правило испорчено на полпути")
	}
	t.Log("OK: редактирование отвергает мусор и не портит правило")
}

// TestK2E_LoadUserRules_DropsInvalid — файл с правилом DirectRoute на невалидном домене:
// правило отбрасывается, валидные соседи остаются, маршрутизация мусор не получает.
func TestK2E_LoadUserRules_DropsInvalid(t *testing.T) {
	dir := t.TempDir()
	raw := []*Rule{
		{ID: "user_bad", Name: "Мусор", Domains: []string{"https://x/"}, DirectRoute: true, Enabled: true},
		{ID: "user_empty", Name: "Пусто", Domains: []string{}, DirectRoute: true, Enabled: true},
		{ID: "user_spaces", Name: "Пробелы", Domains: []string{"  "}, DirectRoute: true, Enabled: true},
		{ID: "user_good", Name: "Хороший", Domains: []string{"good.example", "*.good.example"},
			DirectRoute: true, Enabled: true},
	}
	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bypass_list.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	m := NewManager(dir)
	byID := map[string]*Rule{}
	for _, r := range m.Rules() {
		byID[r.ID] = r
	}
	for _, bad := range []string{"user_bad", "user_empty", "user_spaces"} {
		if _, ok := byID[bad]; ok {
			t.Errorf("правило %q с невалидным доменом не отброшено при загрузке", bad)
		}
	}
	if _, ok := byID["user_good"]; !ok {
		t.Error("валидное правило потеряно вместе с мусором")
	}
	for _, d := range m.DirectRouteDomains() {
		if d != "good.example" {
			t.Errorf("в обход VPN ушёл невалидный домен из файла: %q", d)
		}
	}
	t.Log("OK: невалидные правила из файла отброшены, валидные сохранены")
}

// TestK2E_LoadUserRules_BuiltinOverridesUnaffected — переопределения встроенных правил из
// файла (только флаги, домены берутся из сборки) валидацией не задеты.
func TestK2E_LoadUserRules_BuiltinOverridesUnaffected(t *testing.T) {
	dir := t.TempDir()
	// У встроенного amazonprime домен "amazon.com/gp/video" — с путём; проверяем, что
	// валидация пользовательского ввода не выкидывает встроенные правила.
	raw := []*Rule{{ID: "gosuslugi", Name: "Госуслуги (RU)", Builtin: true, Enabled: true, DirectRoute: true}}
	data, _ := json.MarshalIndent(raw, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "bypass_list.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	m := NewManager(dir)
	var gos, amazon *Rule
	for _, r := range m.Rules() {
		switch r.ID {
		case "gosuslugi":
			gos = r
		case "amazonprime":
			amazon = r
		}
	}
	if gos == nil || !gos.Enabled {
		t.Fatal("переопределение встроенного правила из файла потеряно")
	}
	if amazon == nil {
		t.Fatal("встроенное правило с путём в домене выброшено валидацией")
	}
	t.Log("OK: встроенные правила и их переопределения не задеты")
}
