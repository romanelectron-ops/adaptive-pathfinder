package harvester

// Тесты детерминированного экстрактора (AI-3) и инварианта I-2 на сохранённых образцах.
// Образцы составлены вручную (testdata/), из сети ничего не качалось.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readSample(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("образец %s не прочитан: %v", name, err)
	}
	return data
}

func extractSample(t *testing.T, name string) ([]Candidate, []RejectedItem) {
	t.Helper()
	body := readSample(t, name)
	ex := NewDeterministicExtractor()
	cands, rej, err := ex.extractWithRejects(context.Background(), body,
		SourceMeta{ID: "src-" + name, Name: name, Type: "raw", URL: "https://example.invalid/" + name})
	if err != nil {
		t.Fatalf("%s: неожиданная ошибка: %v", name, err)
	}
	// I-2 на каждом кандидате каждого образца.
	for _, c := range cands {
		if !bytes.Contains(body, []byte(c.Raw)) {
			t.Errorf("%s: I-2 нарушен — Raw не является подстрокой тела: %.60q", name, c.Raw)
		}
		if c.Offset < 0 || c.Offset+len(c.Raw) > len(body) ||
			string(body[c.Offset:c.Offset+len(c.Raw)]) != c.Raw {
			t.Errorf("%s: Offset не указывает на Raw (offset=%d)", name, c.Offset)
		}
		if c.FoundBy != OriginRegex {
			t.Errorf("%s: детерминированный кандидат помечен как %q", name, c.FoundBy)
		}
	}
	return cands, rej
}

// Критерий приёмки AI-3: на КАЖДОМ сохранённом образце детерминированный путь даёт
// непустой результат.
func TestSamplesGiveNonEmptyResult(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("testdata не читается: %v", err)
	}
	if len(entries) < 5 {
		t.Fatalf("образцов должно быть не меньше пяти, найдено %d", len(entries))
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			cands, _ := extractSample(t, e.Name())
			if len(cands) == 0 {
				t.Fatalf("на образце %s детерминированный экстрактор не нашёл ничего", e.Name())
			}
		})
	}
}

func countKind(cands []Candidate, k Kind) int {
	n := 0
	for _, c := range cands {
		if c.Kind == k {
			n++
		}
	}
	return n
}

func hasNormalized(cands []Candidate, want string) bool {
	for _, c := range cands {
		if c.Normalized == want {
			return true
		}
	}
	return false
}

func TestSampleTelegramPost(t *testing.T) {
	cands, _ := extractSample(t, "telegram_post.html")
	if got := countKind(cands, KindNodeURI); got != 3 {
		t.Fatalf("ожидались 3 ссылки узлов, получено %d (%+v)", got, cands)
	}
	// &amp; из HTML обязан превратиться в & — иначе распознаётся только первый параметр.
	if !hasNormalized(cands, "vless://11111111-2222-3333-4444-555555555555@node-a.invalid:443?type=tcp&security=reality&pbk=TESTPBKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sni=addons.mozilla.org#RU-A") {
		t.Errorf("&amp; не раскрыт в Normalized: %+v", cands)
	}
	// Дата поста из разметки Telegram (<time datetime=…>) — AI-3.
	for _, c := range cands {
		if c.PostedAt == nil {
			t.Errorf("дата поста не извлечена для %.40q", c.Raw)
			continue
		}
		if got := c.PostedAt.UTC().Format("2006-01-02T15:04:05Z"); got != "2026-09-05T10:15:00Z" {
			t.Errorf("дата поста разобрана неверно: %s", got)
		}
	}
	// Реклама платного VPN и разметка кандидатами не становятся.
	for _, c := range cands {
		if strings.Contains(c.Normalized, "vpn-shop") {
			t.Errorf("реклама попала в кандидаты: %q", c.Normalized)
		}
	}
}

// «Замените XX на @» — случай, который по §5.2 ТЗ детерминированно не решается: ссылка без
// разделителя учётки и адреса отвергается по форме, а соседняя нормальная — берётся.
// Это и есть честная граница детерминированного пути, а не дефект.
func TestSampleXXReplacement(t *testing.T) {
	cands, rej := extractSample(t, "page_xx_at.html")
	if len(cands) != 1 || cands[0].Scheme != "trojan" {
		t.Fatalf("ожидался ровно один кандидат (trojan), получено %+v", cands)
	}
	found := false
	for _, r := range rej {
		if r.Reason == ReasonBadShape && r.Scheme == "vless" {
			found = true
		}
	}
	if !found {
		t.Errorf("ссылка с XX вместо @ должна быть отвергнута по форме, отказы: %+v", rej)
	}
}

func TestSampleZeroWidthAndBrokenScheme(t *testing.T) {
	cands, _ := extractSample(t, "zero_width.txt")
	if len(cands) != 3 {
		t.Fatalf("ожидались 3 кандидата, получено %d: %+v", len(cands), cands)
	}
	want := []string{
		"vless://22222222-3333-4444-5555-666666666666@node-f.invalid:443?security=tls&sni=example.invalid#ZW-F",
		"trojan://TROJANPASS0003@node-g.invalid:8443#BROKEN-G",
	}
	for _, w := range want {
		if !hasNormalized(cands, w) {
			t.Errorf("нормализация не дала %q; получено: %+v", w, cands)
		}
	}
	// Raw остаётся ГРЯЗНЫМ — это и есть I-2: чинится только Normalized.
	for _, c := range cands {
		if c.Raw == c.Normalized && strings.Contains(c.Normalized, "ZW-F") {
			t.Errorf("Raw не должен совпадать с очищенным Normalized для ссылки с zero-width")
		}
	}
}

func TestSampleBase64Subscription(t *testing.T) {
	cands, _ := extractSample(t, "subscription_b64.txt")
	if countKind(cands, KindConfigBlob) != 1 {
		t.Fatalf("ожидался ровно один base64-блок, получено %+v", cands)
	}
}

func TestSampleClashYAML(t *testing.T) {
	cands, _ := extractSample(t, "clash.yaml")
	if countKind(cands, KindConfigBlob) != 1 {
		t.Fatalf("ожидалась ровно одна секция proxies, получено %+v", cands)
	}
	if !strings.HasPrefix(cands[0].Raw, "proxies:") {
		t.Errorf("блок Clash должен начинаться с proxies:, получено %.30q", cands[0].Raw)
	}
}

func TestSampleSubscriptionURLs(t *testing.T) {
	cands, _ := extractSample(t, "sub_urls.html")
	if got := countKind(cands, KindSubscriptionURL); got != 3 {
		t.Fatalf("ожидались 3 ссылки подписок, получено %d: %+v", got, cands)
	}
	if got := countKind(cands, KindNodeURI); got != 1 {
		t.Fatalf("ожидалась 1 ссылка узла, получено %d", got)
	}
	for _, c := range cands {
		if strings.Contains(c.Normalized, "vpn-shop") || strings.Contains(c.Normalized, "/about") {
			t.Errorf("обычная/рекламная ссылка принята за подписку: %q", c.Normalized)
		}
	}
}

// Схемы, известные миру, но не поддержанные internal/parser, не выпускаются наружу —
// иначе движок молча посчитал бы их «невалидными» и никто бы не узнал, что они были.
func TestUnsupportedSchemesRejectedNotEmitted(t *testing.T) {
	body := []byte("hysteria2://pass@h1.invalid:443#a\n" +
		"tuic://uuid:pass@h2.invalid:443#b\n" +
		"ssconf://h3.invalid/conf#c\n" +
		"trojan://GOODPASS0001@h4.invalid:443#d\n")
	ex := NewDeterministicExtractor()
	cands, rej, err := ex.extractWithRejects(context.Background(), body, SourceMeta{ID: "s"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 1 || cands[0].Scheme != "trojan" {
		t.Fatalf("наружу должен выйти только trojan, получено %+v", cands)
	}
	got := map[string]bool{}
	for _, r := range rej {
		if r.Reason == ReasonUnsupportedScheme {
			got[r.Scheme] = true
		}
	}
	for _, s := range []string{"hysteria2", "tuic", "ssconf"} {
		if !got[s] {
			t.Errorf("схема %s должна быть учтена как unsupported_scheme, отказы: %+v", s, rej)
		}
	}
}

// Схема внутри другого слова не должна давать ложных срабатываний: в «vmess://» есть «ss://».
func TestNoFalsePositiveInsideOtherScheme(t *testing.T) {
	body := []byte("vmess://eyJ2IjoiMiIsInBzIjoieCIsImFkZCI6ImguaW52YWxpZCIsInBvcnQiOiI0NDMiLCJpZCI6IjExMTExMTExLTIyMjItMzMzMy00NDQ0LTU1NTU1NTU1NTU1NSIsImFpZCI6IjAiLCJuZXQiOiJ0Y3AifQ==\n")
	ex := NewDeterministicExtractor()
	cands, _, err := ex.extractWithRejects(context.Background(), body, SourceMeta{ID: "s"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cands {
		if c.Scheme == "ss" {
			t.Fatalf("ложное срабатывание ss:// внутри vmess://: %+v", c)
		}
	}
	if countKind(cands, KindNodeURI) != 1 || cands[0].Scheme != "vmess" {
		t.Fatalf("ожидался ровно один vmess, получено %+v", cands)
	}
}

func TestDuplicatesCollapsed(t *testing.T) {
	link := "trojan://SAMEPASS0001@dup.invalid:443#x"
	body := []byte(link + "\n" + link + "\n" + link + "\n")
	ex := NewDeterministicExtractor()
	cands, rej, err := ex.extractWithRejects(context.Background(), body, SourceMeta{ID: "s"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 1 {
		t.Fatalf("повторы должны схлопываться, получено %d", len(cands))
	}
	n := 0
	for _, r := range rej {
		if r.Reason == ReasonDuplicate {
			n++
		}
	}
	if n != 2 {
		t.Errorf("ожидались 2 отказа-дубликата, получено %d", n)
	}
}

func TestEmptyAndGarbageBodies(t *testing.T) {
	ex := NewDeterministicExtractor()
	for _, body := range [][]byte{
		nil, {}, []byte("   \n\t\n"), []byte("обычный текст без единой ссылки"),
		[]byte("http://example.invalid/page"), bytes.Repeat([]byte{0x00, 0xff}, 512),
	} {
		cands, _, err := ex.extractWithRejects(context.Background(), body, SourceMeta{ID: "s"})
		if err != nil {
			t.Errorf("мусорное тело не должно быть ошибкой источника: %v", err)
		}
		for _, c := range cands {
			if !bytes.Contains(body, []byte(c.Raw)) {
				t.Errorf("I-2 нарушен на мусорном теле")
			}
		}
	}
}

func TestExtractRespectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ex := NewDeterministicExtractor()
	_, _, err := ex.extractWithRejects(ctx, readSample(t, "telegram_post.html"), SourceMeta{ID: "s"})
	if err == nil {
		t.Fatal("отменённый контекст обязан прекратить разбор")
	}
}
