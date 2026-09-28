package harvester

// Тесты модельного адаптера (AI-4) и стража его выхода (AI-5, I-2/I-5).
// Ни один тест не поднимает llama.cpp и не ходит в сеть: в v1.4 реализация — заглушка.

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestNoopModelIsUnavailableAndDoesNothing(t *testing.T) {
	m := NewNoopModelExtractor()
	av := m.Availability()
	if av.ModelPresent {
		t.Error("в v1.4 модельного рантайма нет — Availability обязан это признавать")
	}
	if !av.DeterministicOnly {
		t.Error("Availability должен сообщать, что путь только детерминированный")
	}
	if av.Reason == "" {
		t.Error("причина недоступности должна быть человеческой строкой для экрана подтверждения")
	}
	cands, err := m.Extract(context.Background(), []byte("vless://x@h.invalid:443#a"), SourceMeta{ID: "s"})
	if !errors.Is(err, ErrModelUnavailable) {
		t.Fatalf("ожидалась ErrModelUnavailable, получено %v", err)
	}
	if len(cands) != 0 {
		t.Fatalf("заглушка не имеет права ничего возвращать, получено %+v", cands)
	}
}

func TestParseModelJSONStrictSchema(t *testing.T) {
	ok, err := ParseModelJSON([]byte(`[{"raw":"trojan://p@h.invalid:443#a","kind":"node_uri","posted_at":"2026-09-05T10:15:00Z"}]`))
	if err != nil {
		t.Fatalf("корректный ответ модели не разобран: %v", err)
	}
	if len(ok) != 1 || ok[0].Raw != "trojan://p@h.invalid:443#a" {
		t.Fatalf("разбор дал %+v", ok)
	}
	bad := [][]byte{
		[]byte(`не json вовсе`),
		[]byte(`{"raw":"x"}`),                                  // объект вместо массива
		[]byte(`[{"raw":"x","verified":true}]`),                // лишнее поле — жёсткая схема
		[]byte(`[{"raw":123}]`),                                // не та типизация
		[]byte(`[{"raw":"x","kind":"node_uri"}`),               // оборванный JSON
		[]byte(`Вот ссылки: [{"raw":"x","kind":"node_uri"}]`),  // болтовня вокруг JSON
	}
	for i, b := range bad {
		if _, err := ParseModelJSON(b); err == nil {
			t.Errorf("случай %d: невалидный ответ модели принят", i)
		}
	}
}

func TestSplitWindowsCoversTextWithOverlap(t *testing.T) {
	text := strings.Repeat("абвгд ", 4000) // заведомо больше одного окна
	wins := SplitWindows(text, 100, 20)
	if len(wins) < 2 {
		t.Fatalf("длинный текст обязан быть нарезан, окон %d", len(wins))
	}
	for _, w := range wins {
		if w.Offset < 0 || w.Offset+len(w.Text) > len(text) {
			t.Fatalf("окно выходит за пределы текста: offset=%d len=%d", w.Offset, len(w.Text))
		}
		if text[w.Offset:w.Offset+len(w.Text)] != w.Text {
			t.Fatal("окно обязано быть точной подстрокой текста — иначе I-2 не проверить")
		}
	}
	if wins[1].Offset >= wins[0].Offset+len(wins[0].Text) {
		t.Error("окна должны перекрываться, иначе ссылка на стыке потеряется")
	}
	if len(SplitWindows("", 100, 20)) != 0 {
		t.Error("пустой текст не даёт окон")
	}
	short := SplitWindows("короткий текст", 100, 20)
	if len(short) != 1 || short[0].Offset != 0 {
		t.Errorf("короткий текст — одно окно с нулевым смещением, получено %+v", short)
	}
}

func TestBuildPromptStatesTheRules(t *testing.T) {
	p := BuildPrompt("тело окна")
	for _, must := range []string{"дословно", "JSON", "тело окна"} {
		if !strings.Contains(p, must) {
			t.Errorf("промпт должен содержать %q", must)
		}
	}
	// Модель не получает ни одного инструмента и никакого сетевого доступа: в промпте
	// нет ни слова про переходы по ссылкам и запросы.
	for _, mustNot := range []string{"http-запрос", "перейди по ссылке", "скачай"} {
		if strings.Contains(strings.ToLower(p), mustNot) {
			t.Errorf("промпт не должен предлагать модели действий: %q", mustNot)
		}
	}
}

// I-2 на выходе модели: выдуманная ссылка (не подстрока тела) отбрасывается ДО парсера.
func TestGuardRejectsInventedCandidate(t *testing.T) {
	body := []byte("настоящий текст: trojan://REALPASS0001@real.invalid:443#real")
	in := []Candidate{{Raw: "vless://INVENTED@evil.example.com:443#x", Kind: KindNodeURI, FoundBy: OriginModel}}
	kept, rej, notSub := guardModelCandidates(body, SourceMeta{ID: "s"}, in, nil)
	if len(kept) != 0 {
		t.Fatalf("выдуманная ссылка не имеет права пройти: %+v", kept)
	}
	if notSub != 1 || len(rej) != 1 || rej[0].Reason != ReasonNotSubstring {
		t.Fatalf("отказ должен быть учтён как not_substring: notSub=%d rej=%+v", notSub, rej)
	}
}

// I-5: подстрока-кандидат от модели проходит, но помечается OriginModel — что бы модель
// про себя ни написала.
func TestGuardForcesModelOriginAndKeepsSubstring(t *testing.T) {
	link := "trojan://REALPASS0002@real.invalid:443#real"
	body := []byte("пост: " + link)
	in := []Candidate{{Raw: link, Kind: KindNodeURI, FoundBy: OriginRegex, Confidence: 1.0}}
	kept, _, _ := guardModelCandidates(body, SourceMeta{ID: "s"}, in, nil)
	if len(kept) != 1 {
		t.Fatalf("подстрока обязана пройти, получено %+v", kept)
	}
	if kept[0].FoundBy != OriginModel {
		t.Errorf("страж обязан принудительно ставить OriginModel, получено %q", kept[0].FoundBy)
	}
	if kept[0].Confidence > 0.5 {
		t.Errorf("уверенность модели не должна поднимать её кандидата в очереди: %v", kept[0].Confidence)
	}
	if kept[0].Offset != len("пост: ") {
		t.Errorf("смещение должно указывать на реальное место в теле, получено %d", kept[0].Offset)
	}
}

// Кандидат, уже найденный детерминированным экстрактором, считается подтверждённым и в
// ModelOnly не попадает (иначе число «найдено только моделью» врало бы).
func TestGuardDedupWithDeterministic(t *testing.T) {
	link := "trojan://REALPASS0003@real.invalid:443#real"
	body := []byte(link)
	known := map[string]bool{link: true}
	kept, rej, _ := guardModelCandidates(body, SourceMeta{ID: "s"}, []Candidate{{Raw: link, Kind: KindNodeURI}}, known)
	if len(kept) != 0 {
		t.Fatalf("повтор детерминированного кандидата не должен выпускаться отдельно: %+v", kept)
	}
	if len(rej) != 1 || rej[0].Reason != ReasonDuplicate {
		t.Fatalf("ожидался отказ-дубликат, получено %+v", rej)
	}
}

// Выход модели проходит ТЕ ЖЕ проверки, что и текст источника: она не привилегированна (I-5).
func TestGuardAppliesSameShapeChecksAsSourceText(t *testing.T) {
	body := []byte("tuic://uuid:pass@h.invalid:443#a и vless://БЕЗСОБАКИ.invalid:443#b")
	in := []Candidate{
		{Raw: "tuic://uuid:pass@h.invalid:443#a", Kind: KindNodeURI},
		{Raw: "vless://БЕЗСОБАКИ.invalid:443#b", Kind: KindNodeURI},
	}
	kept, rej, _ := guardModelCandidates(body, SourceMeta{ID: "s"}, in, nil)
	if len(kept) != 0 {
		t.Fatalf("неподдерживаемая схема и битая форма не должны проходить: %+v", kept)
	}
	if len(rej) != 2 {
		t.Fatalf("оба кандидата должны быть учтены в отказах: %+v", rej)
	}
}
