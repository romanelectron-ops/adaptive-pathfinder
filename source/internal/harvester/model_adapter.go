package harvester

// model_adapter.go — модельный адаптер (AI-4) и страж его выхода (AI-5).
//
// В v1.4 модельного рантайма нет: NewNoopModelExtractor — единственная реализация
// ModelExtractor в этом дереве, и она честно отвечает ErrModelUnavailable. Остальное здесь —
// то, что понадобится РЕАЛЬНОМУ адаптеру, когда он появится (нарезка окон, промпт, разбор
// строгого JSON), и страж guardModelCandidates, который не доверяет выходу модели БОЛЬШЕ, чем
// тексту источника (I-5) — именно он делает будущий рантайм безопасным уже сегодня.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// ErrModelUnavailable — модельного рантайма нет (v1.4). Не ошибка вызывающего.
var ErrModelUnavailable = errors.New("harvester: модельный рантайм недоступен")

// ModelExtractor — Extractor, который вдобавок умеет рассказать о своей доступности (AI-2/AI-10).
type ModelExtractor interface {
	Extractor
	Availability() Availability
}

// noopModelExtractor — заглушка v1.4: DeterministicOnly всегда true, Extract всегда отказывает.
type noopModelExtractor struct{}

// NewNoopModelExtractor — модельный путь, которого в этой сборке нет, но который честно
// объясняет, почему (для экрана подтверждения, AI-8).
func NewNoopModelExtractor() ModelExtractor { return noopModelExtractor{} }

func (noopModelExtractor) Name() string { return "model-noop" }

func (noopModelExtractor) Extract(ctx context.Context, body []byte, src SourceMeta) ([]Candidate, error) {
	return nil, ErrModelUnavailable
}

func (noopModelExtractor) Availability() Availability {
	return Availability{
		ModelPresent:      false,
		DeterministicOnly: true,
		RequiredMemBytes:  MinFreeMemForModel,
		Reason:            "модельного рантайма нет в этой сборке (v1.4); поиск по источникам работает без него",
	}
}

// ── строгий JSON модели (AI-4) ──────────────────────────────────────────────────────────

// modelItem — единственная форма ответа модели. Лишнее поле или другой тип — отказ целиком:
// это proof-of-format, а не "разберём что сможем" (TestParseModelJSONStrictSchema).
type modelItem struct {
	Raw      string `json:"raw"`
	Kind     string `json:"kind"`
	PostedAt string `json:"posted_at,omitempty"`
}

// ParseModelJSON — единственный путь превратить сырой ответ модели в кандидатов. Никакого
// доверия форме: неизвестное поле, не тот тип, обрывок JSON или болтовня вокруг — отказ.
func ParseModelJSON(data []byte) ([]Candidate, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var items []modelItem
	if err := dec.Decode(&items); err != nil {
		return nil, fmt.Errorf("harvester: ответ модели не прошёл строгую схему: %w", err)
	}
	out := make([]Candidate, 0, len(items))
	for _, it := range items {
		c := Candidate{Raw: it.Raw, Kind: Kind(it.Kind)}
		if it.PostedAt != "" {
			if t, err := time.Parse(time.RFC3339, it.PostedAt); err == nil {
				c.PostedAt = &t
			}
		}
		out = append(out, c)
	}
	return out, nil
}

// ── нарезка окон (AI-4) ─────────────────────────────────────────────────────────────────

// Window — кусок текста источника для одного вызова модели. Offset — байтовое смещение в
// исходном тексте (не в рунах): Text обязан быть точной подстрокой (I-2 распространяется и на
// вход модели — иначе проверить его после ответа было бы нечем).
type Window struct {
	Offset int
	Text   string
}

// SplitWindows режет text на окна по windowTokens "токенов" (здесь — рун: настоящего
// токенайзера у нас нет, а для нарезки с перекрытием этого достаточно) с overlapTokens
// перекрытием, чтобы ссылка на стыке двух окон не потерялась целиком ни в одном из них.
func SplitWindows(text string, windowTokens, overlapTokens int) []Window {
	if text == "" {
		return nil
	}
	if windowTokens <= 0 {
		windowTokens = DefaultModelWindowTokens
	}
	if overlapTokens < 0 || overlapTokens >= windowTokens {
		overlapTokens = 0
	}
	runes := []rune(text)
	n := len(runes)
	if n <= windowTokens {
		return []Window{{Offset: 0, Text: text}}
	}

	byteOffset := make([]int, n+1)
	b := 0
	for i, r := range runes {
		byteOffset[i] = b
		b += utf8.RuneLen(r)
	}
	byteOffset[n] = b

	step := windowTokens - overlapTokens
	if step <= 0 {
		step = windowTokens
	}
	var out []Window
	for start := 0; start < n; start += step {
		end := start + windowTokens
		if end > n {
			end = n
		}
		out = append(out, Window{Offset: byteOffset[start], Text: text[byteOffset[start]:byteOffset[end]]})
		if end == n {
			break
		}
	}
	return out
}

// BuildPrompt — промпт одного окна. Формулировка намеренно не даёт модели ни одного глагола
// действия (никаких "перейди"/"скачай"/"запроси") — единственная разрешённая работа: прочитать
// и вернуть JSON по тексту, который уже есть перед ней (TestBuildPromptStatesTheRules).
func BuildPrompt(windowText string) string {
	var b strings.Builder
	b.WriteString("Ты помогаешь найти ссылки VPN-узлов в тексте источника.\n")
	b.WriteString("Верни ответ строго в формате JSON — массив объектов с полями ")
	b.WriteString("raw, kind, posted_at — и ничего кроме этого JSON.\n")
	b.WriteString("Поле raw обязано быть скопировано дословно из текста ниже: не исправляй, ")
	b.WriteString("не дополняй и не придумывай ссылки, которых там нет.\n")
	b.WriteString("У тебя нет инструментов и нет сети: не выполняй никаких действий, ")
	b.WriteString("только прочитай текст окна ниже и верни JSON.\n\n")
	b.WriteString(windowText)
	return b.String()
}

// ── страж (AI-5, I-2/I-5) ───────────────────────────────────────────────────────────────

// modelConfidence — фиксированная (заниженная) уверенность ЛЮБОГО кандидата модели, что бы
// сама модель ни прислала в своём Confidence. Origin=model и так уходит в конец очереди —
// это защита на случай, если очередь когда-нибудь станет сортироваться и по Confidence тоже.
const modelConfidence float32 = 0.3

// guardModelCandidates — единственная дверь, через которую кандидат модели попадает в отчёт.
//
//	Вход:   body — ОРИГИНАЛЬНОЕ (не санитайзированное) тело источника, in — сырой выход модели,
//	        known — Raw кандидатов, уже найденных детерминированным путём в ЭТОМ теле.
//	Тело:   для каждого кандидата — (1) I-2: подстрока body или отказ not_substring; (2) дедуп
//	        по known — совпадение с уже найденным регэкспом не может считаться "только моделью";
//	        (3) те же проверки формы/поддержки схемы, что и у текста источника (validateNodeShape)
//	        — модель не привилегированна; (4) принудительно FoundBy=OriginModel и заниженная
//	        Confidence — что бы кандидат сам о себе ни написал.
//	Выход:  (принятые, отклонённые, сколько из них — по причине not_substring).
func guardModelCandidates(body []byte, src SourceMeta, in []Candidate, known map[string]bool) ([]Candidate, []RejectedItem, int) {
	var kept []Candidate
	var rej []RejectedItem
	notSub := 0

	for _, c := range in {
		if c.Raw == "" {
			continue
		}
		idx := bytes.Index(body, []byte(c.Raw))
		if idx < 0 {
			notSub++
			rej = append(rej, RejectedItem{
				SourceID: src.ID, Kind: c.Kind, FoundBy: OriginModel,
				Scheme: c.Scheme, Length: len(c.Raw), Reason: ReasonNotSubstring,
			})
			continue
		}
		if known != nil && known[c.Raw] {
			rej = append(rej, RejectedItem{
				SourceID: src.ID, Offset: idx, Kind: c.Kind, FoundBy: OriginModel,
				Scheme: c.Scheme, Length: len(c.Raw), Reason: ReasonDuplicate,
			})
			continue
		}

		kind := c.Kind
		if kind == "" {
			kind = KindNodeURI
		}
		norm := normalize(kind, c.Raw)
		scheme, tail, isURI := splitScheme(norm)

		if isURI {
			if reason := validateNodeShape(scheme, tail); reason != "" {
				rej = append(rej, RejectedItem{
					SourceID: src.ID, Offset: idx, Kind: KindNodeURI, FoundBy: OriginModel,
					Scheme: scheme, Length: len(c.Raw), Reason: reason,
				})
				continue
			}
			kind = KindNodeURI
		} else {
			scheme = ""
		}

		kept = append(kept, Candidate{
			Raw: c.Raw, Normalized: norm, Kind: kind, SourceID: src.ID, Offset: idx,
			PostedAt: c.PostedAt, Confidence: modelConfidence, FoundBy: OriginModel, Scheme: scheme,
		})
	}
	return kept, rej, notSub
}
