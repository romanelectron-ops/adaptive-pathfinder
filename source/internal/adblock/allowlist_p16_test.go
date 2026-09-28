package adblock

import (
	"reflect"
	"testing"
)

// Тесты P1-6 (аудит 2026-09-01). Проверяют то, ради чего белый список существует: домен из
// него не должен блокироваться НА ТОМ ПУТИ, по которому реально ходит трафик — то есть в
// правилах sing-box, а не только во внутрипроцессном IsBlocked().

func loadedBlocker(t *testing.T, domains ...string) *Blocker {
	t.Helper()
	b := NewBlocker(nil)
	b.profile = ProfileStandard
	for _, d := range domains {
		b.domains[d] = true
	}
	return b
}

// Разбор случая из аудита: разрешён поддомен, заблокирован его родитель. Точное вычитание
// (прежняя реализация) здесь не срабатывало, и правило domain_suffix продолжало блокировать
// разрешённый поддомен.
func TestAllowlist_SubdomainAllowed_ParentBlocked(t *testing.T) {
	b := loadedBlocker(t, "tracker.com")
	if !b.AddToAllowlist("cdn.tracker.com") {
		t.Fatal("AddToAllowlist(cdn.tracker.com) = false — домен корректный, ожидалось добавление")
	}

	if b.IsBlocked("cdn.tracker.com") {
		t.Error("IsBlocked(cdn.tracker.com) = true — домен в белом списке")
	}
	if !b.IsBlocked("ads.tracker.com") {
		t.Error("IsBlocked(ads.tracker.com) = false — этот поддомен НЕ разрешали")
	}

	rules := b.GetSingBoxDNSRules()
	if len(rules) < 2 {
		t.Fatalf("правил %d, ожидалось минимум 2 (allow + block)", len(rules))
	}
	if act, _ := rules[0]["action"].(string); act != "allow" {
		t.Fatalf("rules[0].action = %q, ожидалось \"allow\": разрешающее правило обязано "+
			"стоять ПЕРВЫМ, иначе sing-box отработает reject раньше него", act)
	}
	got, _ := rules[0]["domain_suffix"].([]string)
	if !reflect.DeepEqual(got, []string{"cdn.tracker.com"}) {
		t.Errorf("allow.domain_suffix = %v, ожидалось [cdn.tracker.com]", got)
	}
	for i, r := range rules[1:] {
		if act, _ := r["action"].(string); act != "block" {
			t.Errorf("rules[%d].action = %q, ожидалось \"block\"", i+1, act)
		}
	}
}

// Разрешение родителя распространяется на поддомены — симметрично блокировке.
func TestAllowlist_ParentAllows_Subdomains(t *testing.T) {
	b := loadedBlocker(t, "example.com")
	b.AddToAllowlist("example.com")
	for _, d := range []string{"example.com", "cdn.example.com", "a.b.example.com"} {
		if b.IsBlocked(d) {
			t.Errorf("IsBlocked(%s) = true — родитель example.com в белом списке", d)
		}
	}
}

// Пустой белый список не должен порождать разрешающее правило: пустой domain_suffix в
// sing-box матчит НИЧЕГО, но лишнее правило в конфигурации — лишний повод для расхождений.
func TestAllowlist_Empty_NoAllowRule(t *testing.T) {
	b := loadedBlocker(t, "ads.com")
	rules := b.GetSingBoxDNSRules()
	for i, r := range rules {
		if act, _ := r["action"].(string); act == "allow" {
			t.Fatalf("rules[%d] — разрешающее правило при пустом белом списке", i)
		}
	}
}

func TestNormalizeDomain(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Example.COM", "example.com"},
		{"  example.com  ", "example.com"},
		{"example.com.", "example.com"},
		{"https://example.com/path?q=1", "example.com"},
		{"http://user:pass@example.com:8443/x", "example.com"},
		{"example.com:443", "example.com"},
		// Отвергаем: не домены.
		{"", ""},
		{"localhost", ""},
		{"*.example.com", ""},
		{"a b.com", ""},
		{"https:///", ""},
	}
	for _, c := range cases {
		if got := normalizeDomain(c.in); got != c.want {
			t.Errorf("normalizeDomain(%q) = %q, ожидалось %q", c.in, got, c.want)
		}
	}
}

// Некорректный ввод не должен попадать в список и обязан сообщать об этом вызывающей стороне —
// иначе UI рапортует «добавлено», а сайт продолжает блокироваться.
func TestAddToAllowlist_RejectsGarbage(t *testing.T) {
	b := NewBlocker(nil)
	for _, bad := range []string{"", "   ", "localhost", "*.ads.com", "не домен"} {
		if b.AddToAllowlist(bad) {
			t.Errorf("AddToAllowlist(%q) = true — ожидался отказ", bad)
		}
	}
	if got := b.GetAllowlist(); len(got) != 0 {
		t.Errorf("белый список = %v, ожидался пустой", got)
	}
}

// Повторное добавление и удаление отсутствующего — «изменений нет», чтобы движок не
// переподключался впустую.
func TestAllowlist_ReportsNoChange(t *testing.T) {
	b := NewBlocker(nil)
	if !b.AddToAllowlist("example.com") {
		t.Fatal("первое добавление = false")
	}
	if b.AddToAllowlist("EXAMPLE.com.") {
		t.Error("повторное добавление того же домена (в другом написании) = true")
	}
	if b.RemoveFromAllowlist("other.com") {
		t.Error("удаление отсутствующего домена = true")
	}
	if !b.RemoveFromAllowlist("example.com") {
		t.Error("удаление существующего домена = false")
	}
}

// GetAllowlist едет в конфигурацию на диск — порядок обязан быть стабильным, иначе каждое
// сохранение переписывает файл без единого смыслового изменения.
func TestGetAllowlist_StableOrder(t *testing.T) {
	b := NewBlocker(nil)
	for _, d := range []string{"z.com", "a.com", "m.com"} {
		b.AddToAllowlist(d)
	}
	want := []string{"a.com", "m.com", "z.com"}
	for i := 0; i < 5; i++ {
		if got := b.GetAllowlist(); !reflect.DeepEqual(got, want) {
			t.Fatalf("проход %d: GetAllowlist() = %v, ожидалось %v", i, got, want)
		}
	}
}

// SetAllowlist — путь восстановления из конфигурации: нормализует и отбрасывает мусор,
// потому что файл могли отредактировать руками.
func TestSetAllowlist_NormalizesAndDropsGarbage(t *testing.T) {
	b := NewBlocker(nil)
	b.AddToAllowlist("stale.com") // должен исчезнуть — SetAllowlist заменяет, а не дополняет
	b.SetAllowlist([]string{"  B.com ", "https://a.com/x", "localhost", "", "a.com"})
	want := []string{"a.com", "b.com"}
	if got := b.GetAllowlist(); !reflect.DeepEqual(got, want) {
		t.Errorf("GetAllowlist() = %v, ожидалось %v", got, want)
	}
}
