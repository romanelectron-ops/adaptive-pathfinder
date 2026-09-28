package harvester

// Тесты оркестрации прохода (AI-2): бюджеты, отмена, деградация, порядок очереди.

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ── подставные экстракторы ───────────────────────────────────────────────────────────────

type fakeExtractor struct {
	name string
	fn   func(ctx context.Context, body []byte, src SourceMeta) ([]Candidate, error)
}

func (f fakeExtractor) Name() string { return f.name }
func (f fakeExtractor) Extract(ctx context.Context, body []byte, src SourceMeta) ([]Candidate, error) {
	return f.fn(ctx, body, src)
}

type fakeModel struct {
	fakeExtractor
	av Availability
}

func (f fakeModel) Availability() Availability { return f.av }

func availableModel(fn func(ctx context.Context, body []byte, src SourceMeta) ([]Candidate, error)) ModelExtractor {
	return fakeModel{
		fakeExtractor: fakeExtractor{name: "fake-model", fn: fn},
		av:            Availability{ModelPresent: true, ModelName: "fake", RequiredMemBytes: MinFreeMemForModel},
	}
}

func plentyOfMemory() (int64, bool) { return 8 * 1024 * 1024 * 1024, true }

func srcCfg(id string) models.SourceConfig {
	return models.SourceConfig{ID: id, Name: id, Type: "raw", URL: "https://example.invalid/" + id, Enabled: true}
}

// ── тесты ────────────────────────────────────────────────────────────────────────────────

func TestRunOnSavedSamplesProducesCandidates(t *testing.T) {
	h := New(Options{MemProbe: plentyOfMemory})
	bodies := map[string][]byte{
		"tg":    readSample(t, "telegram_post.html"),
		"clash": readSample(t, "clash.yaml"),
		"sub":   readSample(t, "subscription_b64.txt"),
	}
	in := RunInput{Sources: []models.SourceConfig{srcCfg("tg"), srcCfg("clash"), srcCfg("sub")}, Bodies: bodies}

	rep, err := h.Run(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("проход по сохранённым образцам не должен падать: %v", err)
	}
	if rep.Found != len(rep.Candidates) || rep.Found == 0 {
		t.Fatalf("Found=%d, кандидатов %d", rep.Found, len(rep.Candidates))
	}
	if rep.SourcesProcessed != 3 || rep.SourcesTotal != 3 {
		t.Errorf("обработано %d из %d источников", rep.SourcesProcessed, rep.SourcesTotal)
	}
	if rep.ByExtractor["deterministic"] == 0 {
		t.Errorf("вклад детерминированного экстрактора не посчитан: %+v", rep.ByExtractor)
	}
	// Границы ответственности: эти поля заполняет движок, не харвестер (I-3, I-4).
	if rep.Verified != 0 || rep.Failed != 0 || rep.Parsed != 0 || rep.Merged != 0 || rep.Invalid != 0 {
		t.Errorf("харвестер не имеет права заполнять поля движка: %+v", rep)
	}
	// I-2 на всём отчёте.
	for _, c := range rep.Candidates {
		if !bytes.Contains(bodies[c.SourceID], []byte(c.Raw)) {
			t.Errorf("I-2 нарушен для источника %s", c.SourceID)
		}
	}
}

func TestRunRequiresBodiesAndSkipsMissingOnes(t *testing.T) {
	h := New(Options{MemProbe: plentyOfMemory})
	if _, err := h.Run(context.Background(), RunInput{Sources: []models.SourceConfig{srcCfg("a")}}, nil); err == nil {
		t.Fatal("непереданные тела — ошибка вызывающего: харвестер не качает сам (I-1)")
	}
	rep, err := h.Run(context.Background(), RunInput{
		Sources: []models.SourceConfig{srcCfg("a"), srcCfg("b")},
		Bodies:  map[string][]byte{"b": []byte("trojan://PASS00001@h.invalid:443#x")},
	}, nil)
	if err != nil {
		t.Fatalf("источник без тела — не ошибка прохода: %v", err)
	}
	if rep.SourcesProcessed != 1 || rep.Found != 1 {
		t.Errorf("обработан должен быть только источник с телом: %+v", rep)
	}
}

func TestRunSkipsDisabledSources(t *testing.T) {
	off := srcCfg("off")
	off.Enabled = false
	h := New(Options{MemProbe: plentyOfMemory})
	rep, err := h.Run(context.Background(), RunInput{
		Sources: []models.SourceConfig{off},
		Bodies:  map[string][]byte{"off": []byte("trojan://PASS00002@h.invalid:443#x")},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Found != 0 {
		t.Errorf("выключенный источник не должен обрабатываться: %+v", rep)
	}
}

func TestRunTruncatesOversizedBody(t *testing.T) {
	big := append([]byte("trojan://PASS00003@h.invalid:443#x\n"), bytes.Repeat([]byte("x"), 4096)...)
	h := New(Options{MemProbe: plentyOfMemory})
	rep, err := h.Run(context.Background(), RunInput{
		Sources: []models.SourceConfig{srcCfg("a")},
		Bodies:  map[string][]byte{"a": big},
		Budget:  Budget{MaxBodyBytes: 64},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Truncated != 1 {
		t.Errorf("обрезка тела должна быть отражена в отчёте: %+v", rep)
	}
}

func TestRunHonorsCandidateBudget(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 50; i++ {
		sb.WriteString("trojan://PASSB")
		sb.WriteString(string(rune('A' + i%26)))
		sb.WriteString(string(rune('a' + i/26)))
		sb.WriteString("@h.invalid:443#x\n")
	}
	h := New(Options{MemProbe: plentyOfMemory})
	rep, err := h.Run(context.Background(), RunInput{
		Sources: []models.SourceConfig{srcCfg("a")},
		Bodies:  map[string][]byte{"a": []byte(sb.String())},
		Budget:  Budget{MaxCandidates: 5},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Found > 5 {
		t.Errorf("лимит кандидатов нарушен: %d", rep.Found)
	}
	if rep.Stopped != "budget" {
		t.Errorf("причина остановки должна быть budget, получено %q", rep.Stopped)
	}
}

// Бюджет времени: проход обязан закончиться сам, а не висеть (тест с таймаутом).
func TestRunStopsOnTimeBudget(t *testing.T) {
	slow := fakeExtractor{name: "slow", fn: func(ctx context.Context, body []byte, src SourceMeta) ([]Candidate, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
			return nil, nil
		}
	}}
	h := New(Options{Deterministic: slow, MemProbe: plentyOfMemory})
	bodies := map[string][]byte{"a": []byte("тело"), "b": []byte("тело")}
	start := time.Now()
	rep, err := h.Run(context.Background(), RunInput{
		Sources: []models.SourceConfig{srcCfg("a"), srcCfg("b")},
		Bodies:  bodies,
		Budget:  Budget{Timeout: 150 * time.Millisecond},
	}, nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("исчерпание времени — не ошибка, а частичный отчёт: %v", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("проход не уложился в бюджет времени: %v", elapsed)
	}
	if rep.Stopped != "timeout" {
		t.Errorf("причина остановки должна быть timeout, получено %q", rep.Stopped)
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	blocking := fakeExtractor{name: "blocking", fn: func(c context.Context, body []byte, src SourceMeta) ([]Candidate, error) {
		cancel()
		<-c.Done()
		return nil, c.Err()
	}}
	h := New(Options{Deterministic: blocking, MemProbe: plentyOfMemory})
	rep, err := h.Run(ctx, RunInput{
		Sources: []models.SourceConfig{srcCfg("a")},
		Bodies:  map[string][]byte{"a": []byte("тело")},
	}, nil)
	if err != nil {
		t.Fatalf("отмена пользователем — не ошибка: %v", err)
	}
	if rep.Stopped != "canceled" {
		t.Errorf("причина остановки должна быть canceled, получено %q", rep.Stopped)
	}
}

func TestRunReportsProgress(t *testing.T) {
	h := New(Options{MemProbe: plentyOfMemory})
	var seen []Progress
	_, err := h.Run(context.Background(), RunInput{
		Sources: []models.SourceConfig{srcCfg("a"), srcCfg("b")},
		Bodies: map[string][]byte{
			"a": []byte("trojan://PASS00004@h.invalid:443#x"),
			"b": []byte("trojan://PASS00005@h.invalid:443#y"),
		},
	}, func(p Progress) { seen = append(seen, p) })
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) < 2 {
		t.Fatalf("прогресс должен приходить по каждому источнику, получено %d", len(seen))
	}
	last := seen[len(seen)-1]
	if last.SourceTotal != 2 || last.Found == 0 || last.Phase == "" {
		t.Errorf("итоговый прогресс неполон: %+v", last)
	}
}

// Деградация AI-10: просьба использовать модель при её отсутствии — не ошибка;
// детерминированный результат выдаётся, причина отказа пишется в отчёт.
func TestRunWithoutModelDegradesGracefully(t *testing.T) {
	h := New(Options{MemProbe: plentyOfMemory})
	rep, err := h.Run(context.Background(), RunInput{
		Sources:  []models.SourceConfig{srcCfg("a")},
		Bodies:   map[string][]byte{"a": readSample(t, "telegram_post.html")},
		UseModel: true,
	}, nil)
	if err != nil {
		t.Fatalf("отсутствие модели не должно ломать проход: %v", err)
	}
	if rep.Found == 0 {
		t.Error("детерминированный путь обязан отработать без модели")
	}
	if rep.ModelSkipped == "" {
		t.Error("в отчёте должна быть причина, почему модель не использовалась")
	}
	if rep.ModelOnly != 0 {
		t.Error("без модели не может быть кандидатов «только от модели»")
	}
}

// Порог памяти на уровне прохода: модель не стартует, детерминированный путь работает.
func TestRunRefusesModelOnLowMemory(t *testing.T) {
	called := false
	model := availableModel(func(ctx context.Context, body []byte, src SourceMeta) ([]Candidate, error) {
		called = true
		return nil, nil
	})
	h := New(Options{Model: model, MemProbe: func() (int64, bool) { return 1_000_000_000, true }})
	rep, err := h.Run(context.Background(), RunInput{
		Sources:  []models.SourceConfig{srcCfg("a")},
		Bodies:   map[string][]byte{"a": readSample(t, "telegram_post.html")},
		UseModel: true,
	}, nil)
	if err != nil {
		t.Fatalf("низкая память не отменяет детерминированный проход: %v", err)
	}
	if called {
		t.Error("модель не имела права запуститься при 0,93 ГиБ свободной памяти")
	}
	if !strings.Contains(rep.ModelSkipped, "памяти") {
		t.Errorf("причина отказа должна быть человеческой: %q", rep.ModelSkipped)
	}
	if rep.Found == 0 {
		t.Error("детерминированный результат обязан остаться")
	}
}

// I-5: кандидат, найденный ТОЛЬКО моделью, идёт в очередь ПОСЛЕ всех остальных и считается
// отдельным полем ModelOnly.
func TestModelOnlyCandidatesGoLast(t *testing.T) {
	tgBody := readSample(t, "telegram_post.html")
	// Случай, где модель действительно полезна и где regex по построению бессилен: двоеточие
	// схемы записано HTML-сущностью, «://» в теле нет вовсе. Подстрокой тела строка при этом
	// остаётся, а после нормализации даёт валидную ссылку.
	entityLink := "vless&#58;//66666666-6666-6666-6666-666666666666@only-model.invalid:443#MODELONLY"
	modelLink := "trojan://TROJANPASS0001@node-b.invalid:8443?sni=example.invalid#NL-B"
	body := append(append([]byte{}, []byte(entityLink+"\n")...), tgBody...)

	model := availableModel(func(ctx context.Context, b []byte, src SourceMeta) ([]Candidate, error) {
		return []Candidate{
			{Raw: modelLink, Kind: KindNodeURI},  // дубликат: regex его уже нашёл
			{Raw: entityLink, Kind: KindNodeURI}, // только модель
			{Raw: "trojan://ATTACKER@evil.example.com:443#PRIORITY", Kind: KindNodeURI}, // выдумка
		}, nil
	})
	h := New(Options{Model: model, MemProbe: plentyOfMemory})
	rep, err := h.Run(context.Background(), RunInput{
		Sources:  []models.SourceConfig{srcCfg("a")},
		Bodies:   map[string][]byte{"a": body},
		UseModel: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.NotSubstring != 1 {
		t.Errorf("выдуманная ссылка должна быть учтена в NotSubstring, получено %d", rep.NotSubstring)
	}
	if rep.ModelOnly != 1 {
		t.Errorf("ожидался ровно один кандидат «только от модели», получено %d", rep.ModelOnly)
	}
	for _, c := range rep.Candidates {
		if strings.Contains(c.Raw, "evil.example.com") {
			t.Fatal("выдуманная моделью ссылка попала в кандидаты — I-2 нарушен")
		}
	}
	// Все кандидаты от модели — строго после детерминированных.
	seenModel := false
	for _, c := range rep.Candidates {
		if c.FoundBy == OriginModel {
			seenModel = true
			continue
		}
		if seenModel {
			t.Fatal("детерминированный кандидат оказался ПОСЛЕ модельного — I-5 нарушен")
		}
	}
}

// Модельные кандидаты, подтверждённые regex, в ModelOnly не считаются.
func TestModelOnlyCountsOnlyUnconfirmed(t *testing.T) {
	body := []byte("пост\ntrojan://CONFIRMED0001@h.invalid:443#a\nхвост поста ss://YWVzLTI1Ni1nY206UEFTUw==@h2.invalid:8388#b\n")
	model := availableModel(func(ctx context.Context, b []byte, src SourceMeta) ([]Candidate, error) {
		return []Candidate{{Raw: "trojan://CONFIRMED0001@h.invalid:443#a", Kind: KindNodeURI}}, nil
	})
	h := New(Options{Model: model, MemProbe: plentyOfMemory})
	rep, err := h.Run(context.Background(), RunInput{
		Sources: []models.SourceConfig{srcCfg("a")}, Bodies: map[string][]byte{"a": body}, UseModel: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.ModelOnly != 0 {
		t.Errorf("подтверждённый regex кандидат не может считаться «найденным только моделью»: %d", rep.ModelOnly)
	}
	if rep.Found != 2 {
		t.Errorf("ожидались 2 кандидата от regex, получено %d", rep.Found)
	}
}

// Ошибка модели — результат детерминированного экстрактора и строка в отчёте, без ошибки
// пользователю (AI-4, fail-safe).
func TestModelFailureFallsBackToDeterministic(t *testing.T) {
	model := availableModel(func(ctx context.Context, b []byte, src SourceMeta) ([]Candidate, error) {
		return nil, errors.New("рантайм упал")
	})
	h := New(Options{Model: model, MemProbe: plentyOfMemory})
	rep, err := h.Run(context.Background(), RunInput{
		Sources:  []models.SourceConfig{srcCfg("a")},
		Bodies:   map[string][]byte{"a": readSample(t, "telegram_post.html")},
		UseModel: true,
	}, nil)
	if err != nil {
		t.Fatalf("падение модели не должно быть ошибкой прохода: %v", err)
	}
	if rep.Found != 3 {
		t.Errorf("детерминированный результат обязан сохраниться, получено %d", rep.Found)
	}
	if rep.ModelSkipped == "" {
		t.Error("причина должна быть видна в отчёте")
	}
}

// Секреты уже известных узлов не уходят в модель (AI-5, тест на подстроки).
func TestModelNeverSeesKnownSecrets(t *testing.T) {
	var seen []byte
	model := availableModel(func(ctx context.Context, b []byte, src SourceMeta) ([]Candidate, error) {
		seen = append(seen, b...)
		return nil, nil
	})
	h := New(Options{Model: model, MemProbe: plentyOfMemory, KnownNodes: knownNodesForTest()})
	_, err := h.Run(context.Background(), RunInput{
		Sources:  []models.SourceConfig{srcCfg("a")},
		Bodies:   map[string][]byte{"a": readSample(t, "telegram_post.html")},
		UseModel: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) == 0 {
		t.Fatal("модель не получила тела вовсе — тест бессмысленен")
	}
	for _, secret := range []string{"11111111-2222-3333-4444-555555555555", "TROJANPASS0001", "TESTPBKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		if bytes.Contains(seen, []byte(secret)) {
			t.Errorf("секрет известного узла ушёл в модель: %q", secret)
		}
	}
}

func TestAvailableReportsDeterministicOnlyInV14(t *testing.T) {
	av := New(Options{MemProbe: plentyOfMemory}).Available()
	if av.ModelPresent {
		t.Error("модельного рантайма в v1.4 нет")
	}
	if !av.DeterministicOnly || av.RequiredMemBytes != MinFreeMemForModel {
		t.Errorf("Availability неполон: %+v", av)
	}
	if !av.MemKnown || av.AvailableMemBytes == 0 {
		t.Errorf("замер памяти должен попадать в Availability: %+v", av)
	}
}
