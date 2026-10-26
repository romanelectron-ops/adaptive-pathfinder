package contentage

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

// Данные синтетические: адреса из документационных диапазонов RFC 5737, ключей нет.
const listA = "# заголовок со временем публикации: 2026-10-21 10:00\n" +
	"vless://00000000-0000-0000-0000-000000000001@192.0.2.1:443?type=tcp#one\n" +
	"\n" +
	"vless://00000000-0000-0000-0000-000000000002@192.0.2.2:443?type=tcp#two\n"

func TestDigest_IgnoresCommentsOrderAndBlankLines(t *testing.T) {
	reordered := "# другой заголовок\n\n" +
		"vless://00000000-0000-0000-0000-000000000002@192.0.2.2:443?type=tcp#two\r\n" +
		"vless://00000000-0000-0000-0000-000000000001@192.0.2.1:443?type=tcp#one\n"
	a, b := Digest([]byte(listA)), Digest([]byte(reordered))
	if a == "" || a != b {
		t.Fatalf("отпечаток должен не зависеть от комментариев, порядка и CRLF: %q vs %q", a, b)
	}
}

// Переименование узла (фрагмент «#имя»), BOM и чужой текст — не изменение набора узлов.
func TestDigest_IgnoresRemarksBOMAndForeignText(t *testing.T) {
	base := Digest([]byte(listA))
	renamed := strings.NewReplacer("#one", "#1 renamed", "#two", "#2 renamed").Replace(listA)
	if got := Digest([]byte(renamed)); got != base {
		t.Errorf("переименование узлов сменило отпечаток: %q vs %q", got, base)
	}
	if got := Digest([]byte("\ufeff" + listA)); got != base {
		t.Errorf("BOM в начале сменил отпечаток: %q vs %q", got, base)
	}
	if got := Digest([]byte("\ufeff# заголовок\n" + strings.SplitN(listA, "\n", 2)[1])); got != base {
		t.Errorf("BOM перед комментарием сменил отпечаток: %q vs %q", got, base)
	}
	noisy := listA + "обновлено сегодня\nhttps://example.invalid/not-a-node\n"
	if got := Digest([]byte(noisy)); got != base {
		t.Errorf("постороннийтекст попал в отпечаток: %q vs %q", got, base)
	}
}

// HTML-заглушка оператора с кодом 200 — не источник узлов и не «изменение содержимого».
func TestDigest_HTMLStubIsNotContent(t *testing.T) {
	stub := "<!DOCTYPE html><html><body>\nДоступ ограничен\n<a href=\"http://example.invalid\">Подробнее</a>\n</body></html>"
	if d := Digest([]byte(stub)); d != "" {
		t.Fatalf("HTML-заглушка дала отпечаток %q", d)
	}
	tr := New()
	first := tr.Observe("src", []byte(listA), t0)
	if got := tr.Observe("src", []byte(stub), t0.Add(time.Hour)); got != first {
		t.Fatalf("заглушка затёрла отметку: было %+v, стало %+v", first, got)
	}
}

// У Clash YAML нет ссылок — берутся строки с «server:».
func TestDigest_ClashYAMLFallback(t *testing.T) {
	yamlA := "proxies:\n  - name: a\n    type: vless\n    server: 192.0.2.1\n    port: 443\n"
	yamlB := strings.Replace(yamlA, "192.0.2.1", "192.0.2.2", 1)
	a, b := Digest([]byte(yamlA)), Digest([]byte(yamlB))
	if a == "" || a == b {
		t.Fatalf("YAML: отпечатки %q и %q должны быть непустыми и разными", a, b)
	}
}

func TestDigest_DetectsNodeChange(t *testing.T) {
	changed := strings.Replace(listA, "192.0.2.2", "192.0.2.9", 1)
	if Digest([]byte(listA)) == Digest([]byte(changed)) {
		t.Fatal("замена узла обязана менять отпечаток")
	}
}

func TestDigest_Base64Wrapper(t *testing.T) {
	plain := Digest([]byte(listA))
	wrapped := Digest([]byte(base64.StdEncoding.EncodeToString([]byte(listA))))
	if plain == "" || plain != wrapped {
		t.Fatalf("base64-подписка и тот же текст должны давать один отпечаток: %q vs %q", plain, wrapped)
	}
}

func TestDigest_EmptyBodies(t *testing.T) {
	for _, body := range []string{"", "   \n\t", "# только комментарии\n# ещё"} {
		if d := Digest([]byte(body)); d != "" {
			t.Errorf("тело %q без узлов должно давать пустой отпечаток, получено %q", body, d)
		}
	}
}

func TestObserve_FirstSeenThenSameThenChanged(t *testing.T) {
	tr := New()
	s1 := tr.Observe("src", []byte(listA), t0)
	if s1.FirstSeenAt != t0.Unix() || s1.ChangedAt != 0 {
		t.Fatalf("первая загрузка: нужна только FirstSeenAt, получено %+v", s1)
	}
	s2 := tr.Observe("src", []byte(listA), t0.Add(3*time.Hour))
	if s2.ChangedAt != 0 || s2.SeenAt != t0.Add(3*time.Hour).Unix() || s2.FirstSeenAt != s1.FirstSeenAt {
		t.Fatalf("то же тело: ChangedAt остаётся 0, SeenAt растёт: %+v", s2)
	}
	changed := strings.Replace(listA, "192.0.2.2", "192.0.2.9", 1)
	s3 := tr.Observe("src", []byte(changed), t0.Add(6*time.Hour))
	if s3.ChangedAt != t0.Add(6*time.Hour).Unix() || s3.Hash == s1.Hash {
		t.Fatalf("новое тело: ChangedAt = момент загрузки, хеш новый: %+v", s3)
	}
}

func TestObserve_EmptyBodyDoesNotOverwrite(t *testing.T) {
	tr := New()
	first := tr.Observe("src", []byte(listA), t0)
	after := tr.Observe("src", []byte("# пусто\n"), t0.Add(time.Hour))
	if after != first {
		t.Fatalf("пустое тело затёрло отметку: было %+v, стало %+v", first, after)
	}
	if got := tr.Observe("never", nil, t0); got != (Stamp{}) {
		t.Fatalf("пустое тело нового источника не должно создавать отметку: %+v", got)
	}
}

func TestRestore_ThenUnchangedBodyKeepsChangedAt(t *testing.T) {
	tr := New()
	want := Stamp{Hash: Digest([]byte(listA)), FirstSeenAt: 100, ChangedAt: 200, SeenAt: 300}
	tr.Restore("src", want)
	got := tr.Observe("src", []byte(listA), t0)
	if got.ChangedAt != 200 || got.FirstSeenAt != 100 {
		t.Fatalf("после перезапуска возраст терять нельзя: %+v", got)
	}
	tr.Restore("empty", Stamp{})
	if _, ok := tr.Get("empty"); ok {
		t.Fatal("пустая отметка не должна попадать в трекер")
	}
}

func TestNilTrackerIsSafe(t *testing.T) {
	var tr *Tracker
	tr.Restore("x", Stamp{Hash: "h"})
	if s := tr.Observe("x", []byte(listA), t0); s != (Stamp{}) {
		t.Fatalf("nil-трекер вернул %+v", s)
	}
	if _, ok := tr.Get("x"); ok || tr.Snapshot() != nil {
		t.Fatal("nil-трекер не должен ничего хранить")
	}
}

func TestSnapshot_IsACopy(t *testing.T) {
	tr := New()
	tr.Observe("a", []byte(listA), t0)
	snap := tr.Snapshot()
	delete(snap, "a")
	if _, ok := tr.Get("a"); !ok {
		t.Fatal("правка снимка затронула трекер")
	}
}

func TestDescribe_States(t *testing.T) {
	hash := Digest([]byte(listA))
	cases := []struct {
		name      string
		s         Stamp
		now       time.Time
		wantHours int
		wantExact bool
		wantStale bool
		contains  string
	}{
		{"нет отметки", Stamp{}, t0, -1, false, false, ""},
		{"первая загрузка", Stamp{Hash: hash, FirstSeenAt: t0.Unix()}, t0.Add(10 * time.Minute), 0, false, false, "впервые"},
		{"не менялось за наблюдение", Stamp{Hash: hash, FirstSeenAt: t0.Unix()}, t0.Add(5 * time.Hour), 5, false, false, "не менялось ≥ 5 ч"},
		{"менялось недавно", Stamp{Hash: hash, FirstSeenAt: t0.Add(-100 * time.Hour).Unix(), ChangedAt: t0.Add(-90 * time.Minute).Unix()}, t0, 1, true, false, "менялось 1 ч назад"},
		{"менялось только что", Stamp{Hash: hash, FirstSeenAt: t0.Add(-100 * time.Hour).Unix(), ChangedAt: t0.Add(-20 * time.Minute).Unix()}, t0, 0, true, false, "менялось 20 мин назад"},
		{"заморожен", Stamp{Hash: hash, FirstSeenAt: t0.Unix()}, t0.Add(9 * 24 * time.Hour), 216, false, true, "заморожен"},
		{"менялось давно", Stamp{Hash: hash, FirstSeenAt: t0.Add(-400 * time.Hour).Unix(), ChangedAt: t0.Add(-8 * 24 * time.Hour).Unix()}, t0, 192, true, true, "8 сут назад"},
	}
	for _, c := range cases {
		got := Describe(c.s, c.now)
		if got.Hours != c.wantHours || got.Exact != c.wantExact || got.Stale != c.wantStale {
			t.Errorf("%s: Info=%+v, ожидалось hours=%d exact=%v stale=%v", c.name, got, c.wantHours, c.wantExact, c.wantStale)
		}
		if !strings.Contains(got.Text, c.contains) || (c.contains == "" && got.Text != "") {
			t.Errorf("%s: текст %q не содержит %q", c.name, got.Text, c.contains)
		}
	}
}

// Часы ушли назад: возраст честно неизвестен, а не «0 минут назад».
func TestDescribe_ClockWentBackIsUnknown(t *testing.T) {
	got := Describe(Stamp{Hash: "h", FirstSeenAt: t0.Add(time.Hour).Unix()}, t0)
	if got.Hours != -1 || got.Text != "" || got.Stale || got.Exact {
		t.Fatalf("возраст из будущего должен быть неизвестным: %+v", got)
	}
}

// Источник включали на неделю и выключили: через месяц нельзя утверждать, что он «заморожен».
func TestDescribe_LongIdleSourceIsNotCalledFrozen(t *testing.T) {
	hash := Digest([]byte(listA))
	s := Stamp{
		Hash: hash, FirstSeenAt: t0.Add(-40 * 24 * time.Hour).Unix(),
		ChangedAt: t0.Add(-35 * 24 * time.Hour).Unix(), SeenAt: t0.Add(-30 * 24 * time.Hour).Unix(),
	}
	got := Describe(s, t0)
	if got.Stale || got.Hours != -1 || !strings.Contains(got.Text, "давно не загружалось") {
		t.Fatalf("давно не загружавшийся источник описан неверно: %+v", got)
	}
	if strings.Contains(got.Text, "заморожен") {
		t.Errorf("текст называет незагружаемый источник замороженным: %q", got.Text)
	}
	// А если загружали вчера и содержимое не менялось — это уже признак заморозки.
	s.SeenAt = t0.Add(-24 * time.Hour).Unix()
	if got := Describe(s, t0); !got.Stale {
		t.Errorf("регулярно загружаемый, но неизменный 35 суток источник должен считаться замороженным: %+v", got)
	}
}
