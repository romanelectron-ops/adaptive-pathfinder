package harvester

// extract_deterministic.go — детерминированный экстрактор (AI-3): единственный путь, который
// обязан работать сам по себе, без всякой модели. Ищет три формы кандидатов в уже скачанном
// теле источника: одиночные ссылки узлов, ссылки подписок и конфигурационные блобы (base64 /
// секция Clash YAML).
//
// Инвариант I-2 достигается КОНСТРУКЦИЕЙ, а не проверкой постфактум: Raw в каждом кандидате —
// это всегда byte-slice исходного тела по найденным границам, никогда не пересобранная строка.

import (
	"bytes"
	"context"
	"encoding/base64"
	"html"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ── схемы ────────────────────────────────────────────────────────────────────────────────

// nodeSchemeOrder — все схемы, которые вообще стоит искать в тексте: и те, что умеет вести
// internal/parser, и те, что мир уже придумал, а парсер — ещё нет (см. ReasonUnsupportedScheme).
var nodeSchemeOrder = []string{"vless", "vmess", "trojan", "ss", "hysteria2", "tuic", "ssconf", "hy2"}

// supportedSchemes — то, что реально ведёт internal/parser.ParseLink. Только эти четыре
// схемы харвестер имеет право выпустить наружу как KindNodeURI.
var supportedSchemes = map[string]bool{"vless": true, "vmess": true, "trojan": true, "ss": true}

// unsupportedSchemes — известные миру схемы, которых парсер пока не понимает. Не молчим:
// считаем их отдельно (ReasonUnsupportedScheme), а не смешиваем с обычным мусором.
var unsupportedSchemes = map[string]bool{"hysteria2": true, "tuic": true, "ssconf": true, "hy2": true}

// userinfoSchemes — схемы формата scheme://учётка@адрес:порт — без "@" ссылка не разбирается,
// это и есть граница §5.2 (см. TestSampleXXReplacement).
var userinfoSchemes = map[string]bool{"vless": true, "trojan": true, "ss": true}

// zwRunes/zwChars — невидимые символы, которые встречаются в реальных постах (случайно или
// намеренно, как приём обхода фильтров): ZERO WIDTH SPACE/NON-JOINER/JOINER и BOM.
//
// Заданы через кодовые точки (rune), а не через "\u..."-литералы: U+FEFF, попав в исходник как
// настоящий байтовый BOM где угодно, кроме самого начала файла, — это ошибка компиляции Go
// ("invalid BOM in the middle of the file"), а не просто символ в строке.
var zwRunes = []rune{0x200b, 0x200c, 0x200d, 0xfeff}
var zwChars = string(zwRunes)

// schemeRegexes — по одному регэкспу на схему, скомпилированы один раз при загрузке пакета.
//
// Разбор шаблона на примере "vless": между КАЖДОЙ буквой схемы и в каждом из трёх мест
// разделителя "://" допускается любое число невидимых символов и (только в разделителе) один
// обычный пробел — это и есть терпимость к "vl​ess://" (TestSampleZeroWidthAndBrokenScheme)
// и к "trojan:/ /..." (разорванная схема, тот же тест). Экранирование каждой буквы через
// regexp.QuoteMeta избыточно для латиницы, но безопасно и дёшево.
//
// \b перед первой буквой — единственная причина, по которой "ss://" не находится ВНУТРИ
// "vmess://" (TestNoFalsePositiveInsideOtherScheme): между 'e' и 's' обе стороны — буквы,
// границы слова там нет, и \b матч запрещает.
var schemeRegexes = buildSchemeRegexes()

func buildSchemeRegexes() map[string]*regexp.Regexp {
	zw := "[" + zwChars + "]*"
	gap := zw + " ?" + zw
	tailClass := `[^\s<>"']*`
	out := make(map[string]*regexp.Regexp, len(nodeSchemeOrder))
	for _, scheme := range nodeSchemeOrder {
		var letters strings.Builder
		for _, r := range scheme {
			letters.WriteString(regexp.QuoteMeta(string(r)))
			letters.WriteString(zw)
		}
		pat := `\b(?i:` + letters.String() + `):` + gap + `/` + gap + `/` + gap + tailClass
		out[scheme] = regexp.MustCompile(pat)
	}
	return out
}

// ── нормализация (AI-3) ─────────────────────────────────────────────────────────────────

var zwReplacer = strings.NewReplacer(
	string(zwRunes[0]), "",
	string(zwRunes[1]), "",
	string(zwRunes[2]), "",
	string(zwRunes[3]), "",
)

// reBrokenSep чинит "scheme:/ /" (и любой другой пробел вокруг слэшей) в "scheme://".
// На уже чистой "://" — no-op: \s* совпадает с пустой строкой.
var reBrokenSep = regexp.MustCompile(`:\s*/\s*/`)

// normalize — Raw → Normalized (AI-3): снять невидимые символы, склеить разорванную схему,
// раскрыть HTML-сущности. Для KindConfigBlob Normalized == Raw (блоб не "ссылка", чинить нечего
// и опасно — это испортило бы base64).
func normalize(kind Kind, raw string) string {
	if kind == KindConfigBlob {
		return raw
	}
	s := zwReplacer.Replace(raw)
	s = reBrokenSep.ReplaceAllString(s, "://")
	s = html.UnescapeString(s)
	return s
}

// splitScheme — вынимает схему (в нижнем регистре) и хвост из УЖЕ нормализованной строки.
// Возвращает ok=false, если "://" не найдено, или то, что перед ним — не голое имя схемы
// (буквы/цифры): так guardModelCandidates не примет случайный текст модели за ссылку.
func splitScheme(s string) (scheme, tail string, ok bool) {
	idx := strings.Index(s, "://")
	if idx <= 0 {
		return "", "", false
	}
	head := s[:idx]
	for _, r := range head {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return "", "", false
		}
	}
	return strings.ToLower(head), s[idx+3:], true
}

// validateNodeShape — "похоже ли это вообще на ссылку узла" (ReasonBadShape) и "умеет ли её
// вести парсер" (ReasonUnsupportedScheme). "" — принято.
//
// Применяется ОДИНАКОВО к находкам регэкспа и к выходу модели (TestGuardAppliesSameShapeChecksAsSourceText)
// — модель не привилегированна (I-5).
const maxTailLen = 4096

func validateNodeShape(scheme, tail string) RejectReason {
	if scheme == "" {
		return ReasonBadShape
	}
	if unsupportedSchemes[scheme] {
		return ReasonUnsupportedScheme
	}
	if !supportedSchemes[scheme] {
		return ReasonBadShape
	}
	if len(tail) == 0 || len(tail) > maxTailLen {
		return ReasonBadShape
	}
	if strings.ContainsAny(tail, " \t\r\n") {
		return ReasonBadShape
	}
	if userinfoSchemes[scheme] && !strings.Contains(tail, "@") {
		return ReasonBadShape
	}
	return ""
}

// ── подписки (http/https) ───────────────────────────────────────────────────────────────

var reHTTPURL = regexp.MustCompile(`\bhttps?://[^\s<>"']+`)

// subscriptionKeywords/subscriptionExts — грубая, но достаточная эвристика: "это не просто
// ссылка на сайт, а похоже на подписку/конфиг". Реклама и "о нас" под неё не попадают
// (TestSampleSubscriptionURLs).
var subscriptionKeywords = []string{"sub", "clash", "config", "token="}
var subscriptionExts = []string{".txt", ".yaml", ".yml"}

func isSubscriptionURL(u string) bool {
	lower := strings.ToLower(u)
	for _, kw := range subscriptionKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	for _, ext := range subscriptionExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// ── Clash YAML ───────────────────────────────────────────────────────────────────────────

// reClashProxies — секция "proxies:" целиком: от самой строки "proxies:" до первой строки
// следующего верхнеуровневого ключа (не начинающейся с пробела/таба).
var reClashProxies = regexp.MustCompile(`(?m)^proxies:[ \t]*\r?\n(?:[ \t]+[^\r\n]*\r?\n?)*`)

// ── base64-подписки ──────────────────────────────────────────────────────────────────────

// reBase64Line — ЦЕЛАЯ строка из символов base64-алфавита (плюс паддинг). Якорение на всю
// строку — намеренная защита от ложных срабатываний: параметр pbk=… внутри vless://-ссылки
// живёт на строке вместе со схемой и остальными параметрами, значит целиком под этот шаблон
// не подходит и вторым кандидатом не станет.
var reBase64Line = regexp.MustCompile(`(?m)^[A-Za-z0-9+/]{32,}={0,2}$`)

func decodeBase64Loose(s string) ([]byte, error) {
	if d, err := base64.StdEncoding.DecodeString(s); err == nil {
		return d, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// ── дата поста ───────────────────────────────────────────────────────────────────────────

var reTimeTag = regexp.MustCompile(`<time\s+datetime="([^"]+)"`)

func extractPostedAt(body []byte) *time.Time {
	m := reTimeTag.FindSubmatch(body)
	if m == nil {
		return nil
	}
	t, err := time.Parse(time.RFC3339, string(m[1]))
	if err != nil {
		return nil
	}
	return &t
}

// ── экстрактор ───────────────────────────────────────────────────────────────────────────

// detConfidence — фиксированная уверенность детерминированного пути. Одна и та же для всех
// кандидатов вне зависимости от окружающего текста — это и есть защита от того, что инъекция
// поднимет приоритет своей ссылки (TestInjectionDoesNotChangeDecision): поднимать нечего.
const detConfidence float32 = 1.0

// DeterministicExtractor — регэксповый путь AI-3. Не хранит состояния между вызовами.
type DeterministicExtractor struct{}

// NewDeterministicExtractor — единственный конструктор; поле Options.Deterministic по
// умолчанию получает именно это значение.
func NewDeterministicExtractor() *DeterministicExtractor { return &DeterministicExtractor{} }

func (e *DeterministicExtractor) Name() string { return "deterministic" }

// Extract — контракт интерфейса Extractor. Внутренние отказы (extractWithRejects) наружу не
// протекают: движку они не нужны, харвестеру — да (AI-8, отчёт).
func (e *DeterministicExtractor) Extract(ctx context.Context, body []byte, src SourceMeta) ([]Candidate, error) {
	cands, _, err := e.extractWithRejects(ctx, body, src)
	return cands, err
}

type find struct {
	offset int
	raw    string
	norm   string
	kind   Kind
	scheme string
}

// extractWithRejects — рабочая лошадь пакета. Порядок действий:
//  1. три независимых прохода по телу (ссылки узлов, ссылки подписок, блобы) — каждый копит
//     И принятое (finds), И отклонённое (rejects) сразу с причиной;
//  2. общая сортировка находок по смещению — отсюда естественный порядок выдачи, тот же самый
//     что и в тексте источника (инъекция не может передвинуть свою ссылку вперёд очереди);
//  3. дедуп по Normalized за один линейный проход.
func (e *DeterministicExtractor) extractWithRejects(ctx context.Context, body []byte, src SourceMeta) ([]Candidate, []RejectedItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	var finds []find
	var rejects []RejectedItem

	// 1. ссылки узлов (поддерживаемые и известные-неподдерживаемые схемы).
	for _, scheme := range nodeSchemeOrder {
		re := schemeRegexes[scheme]
		for _, m := range re.FindAllIndex(body, -1) {
			start, end := m[0], m[1]
			raw := string(body[start:end])
			norm := normalize(KindNodeURI, raw)
			sch, tail, ok := splitScheme(norm)
			if !ok {
				sch, tail = scheme, ""
			}
			if reason := validateNodeShape(sch, tail); reason != "" {
				rejects = append(rejects, RejectedItem{
					SourceID: src.ID, Offset: start, Kind: KindNodeURI, FoundBy: OriginRegex,
					Scheme: sch, Length: end - start, Reason: reason,
				})
				continue
			}
			finds = append(finds, find{offset: start, raw: raw, norm: norm, kind: KindNodeURI, scheme: sch})
		}
	}

	// 2. ссылки подписок.
	for _, m := range reHTTPURL.FindAllIndex(body, -1) {
		raw := string(body[m[0]:m[1]])
		if !isSubscriptionURL(raw) {
			continue
		}
		norm := normalize(KindSubscriptionURL, raw)
		finds = append(finds, find{offset: m[0], raw: raw, norm: norm, kind: KindSubscriptionURL})
	}

	// 3a. секции Clash YAML.
	for _, m := range reClashProxies.FindAllIndex(body, -1) {
		raw := string(body[m[0]:m[1]])
		finds = append(finds, find{offset: m[0], raw: raw, norm: raw, kind: KindConfigBlob})
	}

	// 3b. base64-подписки — целая строка, декодируется, внутри есть хотя бы одна ссылка.
	for _, m := range reBase64Line.FindAllIndex(body, -1) {
		raw := string(body[m[0]:m[1]])
		decoded, err := decodeBase64Loose(raw)
		if err != nil || !bytes.Contains(decoded, []byte("://")) {
			rejects = append(rejects, RejectedItem{
				SourceID: src.ID, Offset: m[0], Kind: KindConfigBlob, FoundBy: OriginRegex,
				Length: len(raw), Reason: ReasonBadBlob,
			})
			continue
		}
		finds = append(finds, find{offset: m[0], raw: raw, norm: raw, kind: KindConfigBlob})
	}

	sort.SliceStable(finds, func(i, j int) bool { return finds[i].offset < finds[j].offset })

	postedAt := extractPostedAt(body)
	seen := make(map[string]bool, len(finds))
	cands := make([]Candidate, 0, len(finds))
	for _, f := range finds {
		if seen[f.norm] {
			rejects = append(rejects, RejectedItem{
				SourceID: src.ID, Offset: f.offset, Kind: f.kind, FoundBy: OriginRegex,
				Scheme: f.scheme, Length: len(f.raw), Reason: ReasonDuplicate,
			})
			continue
		}
		seen[f.norm] = true
		cands = append(cands, Candidate{
			Raw: f.raw, Normalized: f.norm, Kind: f.kind, SourceID: src.ID, Offset: f.offset,
			PostedAt: postedAt, Confidence: detConfidence, FoundBy: OriginRegex, Scheme: f.scheme,
		})
	}
	return cands, rejects, nil
}
