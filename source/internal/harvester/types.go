// Package harvester — подбор и актуализация узлов из уже настроенных источников
// (ТЗ v1.4 §5 «ИИ-подбор узлов», лот L5-CORE, пункты AI-2…AI-5, AI-10).
//
// # Что это и чего это НЕ делает
//
// Харвестер получает УЖЕ СКАЧАННЫЕ тела источников (их приносит sources.Manager) и находит в
// них подстроки, похожие на ссылки узлов, ссылки подписок и конфигурационные блобы. Он
// возвращает []Candidate — и на этом его полномочия заканчиваются.
//
//	Харвестер НЕ ходит в сеть            — инвариант I-1 (в пакете нет сетевого клиента).
//	Харвестер НЕ разбирает ссылки        — это делает internal/parser на стороне движка.
//	Харвестер НЕ пишет в пул узлов       — инвариант I-3 (единственный вход — mergeFetchedNodes).
//	Харвестер НЕ решает «узел рабочий»   — инвариант I-4 (это TUN-проба движка, VerifyState).
//
// # Почему так, а не «модель всё сделает»
//
// Живой замер ГЕЙТА №1 (APF_Audit/AI_NODE_HARVESTER/GATE1_RESULT.md, 2026-09-08): модель
// Bonsai-4B Q1_0 на фрагменте с prompt-injection вернула РОВНО ту ссылку, которую велел
// вернуть злоумышленник в тексте страницы, отбросив три настоящих. Эта строка была дословной
// подстрокой входа, то есть инвариант I-2 её бы пропустил. Отсюда несущая конструкция пакета:
// детерминированный экстрактор обязателен и самодостаточен, модель — необязательный
// адаптер за интерфейсом, её выход проходит те же проверки, что и текст источника (I-5), и
// ни один слой пакета не имеет права назвать узел рабочим.
//
// # Порядок в конвейере (ТЗ §5 AI-6)
//
//	sources.Manager.FetchAll → тела → Harvester.Run → []Candidate
//	  → parser.Parse* → models.ValidateNode → engine.mergeFetchedNodes → пул
//	  → очередь проверки (K из C-18) → runPostConnectHealthCheck/probeDirect → VerifyState
package harvester

import (
	"context"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// Kind — что именно найдено. Разбирать это будет движок, разными функциями парсера.
type Kind string

const (
	// KindNodeURI — одиночная ссылка узла (vless://, vmess://, ss://, trojan://, wireguard://…).
	// Движок ведёт её в parser.ParseLink.
	KindNodeURI Kind = "node_uri"
	// KindSubscriptionURL — http(s)-адрес подписки. Движок НЕ качает его сам из харвестера:
	// адрес предлагается пользователю/добавляется в источники (решение — за L5-ENG/L5-UI).
	KindSubscriptionURL Kind = "subscription_url"
	// KindConfigBlob — кусок конфигурации: base64-подписка или секция Clash YAML.
	// Движок ведёт его в parser.ParseSubscription / parser.ParseClashYAML.
	KindConfigBlob Kind = "config_blob"
)

// Origin — кто нашёл кандидата. Значение OriginModel понижает приоритет очереди (I-5) и
// проставляется принудительно стражем модельного выхода, что бы модель ни прислала.
type Origin string

const (
	OriginRegex Origin = "regex"
	OriginModel Origin = "model"
)

// Candidate — то, что харвестер НАШЁЛ. Это не узел пула и тем более не «рабочий узел».
//
// Расширение относительно черновика ТЗ (AI-2): поле Normalized. Причина в том, что I-2
// требует от Raw быть ТОЧНОЙ подстрокой тела, а AI-3 требует снимать zero-width символы и
// склеивать разорванную схему. Одним полем это несовместимо: очищенная строка подстрокой
// тела уже не является. Поэтому Raw — оригинальный отрезок (по нему и проверяется I-2), а
// Normalized — то, что движок отдаёт в parser.ParseLink.
type Candidate struct {
	// Raw — ТОЧНАЯ подстрока исходного тела (инвариант I-2). Никогда не «чинится».
	Raw string `json:"raw"`
	// Normalized — Raw после снятия zero-width, склейки схемы и html.UnescapeString.
	// Для KindConfigBlob совпадает с Raw.
	Normalized string `json:"normalized"`
	Kind       Kind   `json:"kind"`
	// SourceID — id источника из models.SourceConfig.
	SourceID string `json:"source_id"`
	// Offset — смещение Raw в теле источника (в байтах).
	Offset int `json:"offset"`
	// PostedAt — дата поста, если извлечена из разметки; nil — неизвестно.
	PostedAt *time.Time `json:"posted_at,omitempty"`
	// Confidence — 0..1, ТОЛЬКО для порядка очереди проверки. Ни на что другое не влияет:
	// это прямая компенсация того, что инъекция умеет двигать приоритет (см. AI-5).
	Confidence float32 `json:"confidence"`
	FoundBy    Origin  `json:"found_by"`
	// Scheme — схема ссылки в нижнем регистре ("vless", "ss", …) или "" для блобов.
	Scheme string `json:"scheme,omitempty"`
}

// SourceMeta — то немногое об источнике, что нужно экстрактору. Намеренно не *models.SourceConfig:
// экстрактору нечего делать с полями автообновления, а узкий вход проще испытывать.
type SourceMeta struct {
	ID   string
	Name string
	Type string // subscription | telegram | raw | tor | manual
	URL  string
}

// MetaFromConfig переносит нужные поля из пользовательской конфигурации источника.
func MetaFromConfig(src models.SourceConfig) SourceMeta {
	return SourceMeta{ID: src.ID, Name: src.Name, Type: src.Type, URL: src.URL}
}

// RejectReason — почему кандидат не выпущен наружу. Значения стабильны: они уходят в отчёт,
// который сохраняется в файл рядом с логом (AI-8), и по ним считается статистика.
type RejectReason string

const (
	// ReasonNotSubstring — прямой индикатор инъекции или галлюцинации (I-2).
	ReasonNotSubstring RejectReason = "not_substring"
	// ReasonUnsupportedScheme — схема известна миру, но её не поддерживает internal/parser
	// (ssconf, hysteria2, hy2, tuic). Не молчим: это заявка на расширение парсера.
	ReasonUnsupportedScheme RejectReason = "unsupported_scheme"
	// ReasonBadShape — не похоже на ссылку узла: пустой или чрезмерный хвост, пробелы внутри.
	ReasonBadShape RejectReason = "bad_shape"
	// ReasonDuplicate — уже найден (в этом же проходе).
	ReasonDuplicate RejectReason = "duplicate"
	// ReasonBudget — упёрлись в лимит кандидатов за проход.
	ReasonBudget RejectReason = "budget"
	// ReasonModelBadJSON — модель ответила не тем, что обещала схема.
	ReasonModelBadJSON RejectReason = "model_bad_json"
	// ReasonBadBlob — блок похож на base64, но не декодируется или внутри нет ссылок.
	ReasonBadBlob RejectReason = "bad_blob"
)

// RejectedItem — запись об отказе БЕЗ сырого содержимого.
//
// Сырого текста здесь нет намеренно (AI-5, слой «санитайзер логов»): тела источников содержат
// пароли и UUID, а отчёт сохраняется в файл рядом с логом и уходит через share sheet. В отчёт
// попадают только счётчики, координаты и причины.
type RejectedItem struct {
	SourceID string       `json:"source_id"`
	Offset   int          `json:"offset"`
	Kind     Kind         `json:"kind,omitempty"`
	FoundBy  Origin       `json:"found_by"`
	Scheme   string       `json:"scheme,omitempty"`
	Length   int          `json:"length"`
	Reason   RejectReason `json:"reason"`
}

// Report — итог прохода.
//
// Поля Parsed, Merged, Duplicate (в части пула), Invalid, Verified и Failed харвестер НЕ
// заполняет: их пишет движок после parser → ValidateNode → mergeFetchedNodes и после TUN-пробы.
// Здесь они нули — и это не забывчивость, а граница ответственности (I-3, I-4).
type Report struct {
	Found     int `json:"found"`     // сколько кандидатов выпущено наружу
	Parsed    int `json:"parsed"`    // ← движок
	Merged    int `json:"merged"`    // ← движок
	Duplicate int `json:"duplicate"` // повторы, снятые харвестером (движок добавит свои)
	Invalid   int `json:"invalid"`   // ← движок
	Verified  int `json:"verified"`  // ← движок, ТОЛЬКО после TUN-пробы
	Failed    int `json:"failed"`    // ← движок

	// ModelOnly — найдено только моделью и не подтверждено детерминированным экстрактором (I-5).
	ModelOnly int `json:"model_only"`
	// NotSubstring — отброшено как не-подстрока (I-2). Прямой индикатор инъекции/галлюцинации.
	NotSubstring int `json:"not_substring"`

	Rejected    []RejectedItem `json:"rejected,omitempty"`
	ByExtractor map[string]int `json:"by_extractor,omitempty"`
	Elapsed     time.Duration  `json:"elapsed"`

	// ── Расширения контракта (см. result.md §3); поля ТЗ выше не тронуты ──

	// Candidates — то, что движок поведёт в parser. В AI-2 интерфейс объявлен как
	// (Report, error), а на схеме AI-6 написано «Harvester.Run → []Candidate»; противоречие
	// снято переносом кандидатов в отчёт, сигнатура интерфейса оставлена дословно.
	Candidates []Candidate `json:"candidates,omitempty"`

	SourcesTotal     int `json:"sources_total"`
	SourcesProcessed int `json:"sources_processed"`
	// Truncated — сколько тел обрезано по MaxBodyBytes.
	Truncated int `json:"truncated"`
	// Stopped — "" | "timeout" | "canceled" | "budget". Не ошибка: частичный результат честен.
	Stopped string `json:"stopped,omitempty"`
	// ModelSkipped — почему модельный путь не выполнялся (пусто, если выполнялся или не просили).
	ModelSkipped string `json:"model_skipped,omitempty"`
}

// Progress — состояние прохода для UI (образец — engine.ScanProgress).
type Progress struct {
	Phase       string `json:"phase"` // running | done | cancelled
	SourceIndex int    `json:"source_index"`
	SourceTotal int    `json:"source_total"`
	SourceID    string `json:"source_id"`
	Found       int    `json:"found"`
	ElapsedSec  int    `json:"elapsed_sec"`
	ETASec      int    `json:"eta_sec"`
}

// Availability — есть ли модель, какая, сколько памяти нужно (AI-2, AI-10).
type Availability struct {
	ModelPresent bool   `json:"model_present"`
	ModelName    string `json:"model_name,omitempty"`
	// RequiredMemBytes — порог свободной памяти, ниже которого модельный проход не стартует.
	RequiredMemBytes int64 `json:"required_mem_bytes"`
	// AvailableMemBytes — замер; MemKnown=false означает «определить не удалось».
	AvailableMemBytes int64 `json:"available_mem_bytes"`
	MemKnown          bool  `json:"mem_known"`
	// DeterministicOnly — true, пока модельного рантайма нет (в v1.4 всегда true).
	DeterministicOnly bool `json:"deterministic_only"`
	// Reason — человеческий текст для экрана подтверждения (AI-8).
	Reason string `json:"reason,omitempty"`
}

// Extractor — любой способ достать кандидатов из тела источника.
type Extractor interface {
	Name() string
	Extract(ctx context.Context, body []byte, src SourceMeta) ([]Candidate, error)
}

// RunInput — вход одного прохода.
type RunInput struct {
	// Sources — ТОЛЬКО те, что уже в конфиге пользователя. Харвестер не изобретает источников.
	Sources []models.SourceConfig
	// Bodies — тела, полученные sources.Manager, по SourceConfig.ID. Харвестер не качает сам (I-1).
	Bodies map[string][]byte
	// UseModel — false ⇒ строго детерминированный путь. В v1.4 модельного рантайма нет,
	// поэтому true приводит к записи в Report.ModelSkipped, а не к ошибке.
	UseModel bool
	Budget   Budget
}

// Harvester — контракт AI-2. Ровно два метода: найти и рассказать о доступности.
// Метода, который назначал бы узлу статус, здесь нет и быть не может (I-3, I-4).
type Harvester interface {
	Run(ctx context.Context, in RunInput, progress func(Progress)) (Report, error)
	Available() Availability
}
