// Package contentage — «возраст содержимого» источника узлов (лот L5, идея U-06 из разбора
// внешних репозиториев 2026-10-21).
//
// Зачем. Время последней УСПЕШНОЙ ЗАГРУЗКИ (SourceConfig.LastUpdatedAt, ProviderMeta.LastUpdated)
// говорит только о том, что сервер ответил кодом 200. Источник, у которого апстрим пропал и
// файлы заморожены, отвечает 200 с тем же телом сколько угодно долго — и выглядит «свежим»
// (так у одного из перепаковщиков 26 из 34 списков молча простояли без изменений неделями).
// Здесь возраст считается по СОДЕРЖИМОМУ: когда набор строк-узлов в последний раз отличался.
//
// Честная граница. Мы видим только то, что скачали сами: до первой замеченной перемены
// настоящий возраст файла неизвестен — известна лишь нижняя граница «не менялось за время
// наблюдения». Describe различает эти два случая, а не выдаёт нижнюю границу за точное время.
//
// Пакет не ходит в сеть и не знает о конфиге: трекер получает тела от загрузчиков
// (internal/sources, internal/catalog), а сохранение в config.json — дело движка.
package contentage

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// StaleAfter — через сколько времени без замеченных изменений источник считается возможно
// замороженным. Семь суток: даже редкие публичные списки за неделю обновляются, а заморозка
// апстрима как раз так и выглядит — тело не меняется.
const StaleAfter = 7 * 24 * time.Hour

// Stamp — отметка содержимого одного источника (все времена — unix-секунды, 0 — не было).
type Stamp struct {
	// Hash — отпечаток набора строк-узлов последней загрузки (см. Digest).
	Hash string
	// FirstSeenAt — первая загрузка, которую мы вообще видели.
	FirstSeenAt int64
	// ChangedAt — загрузка, на которой отпечаток в последний раз отличился от прежнего.
	// 0 — мы ни разу не видели перемены (например, источник заморожен или мы только начали).
	ChangedAt int64
	// SeenAt — последняя успешная непустая загрузка.
	SeenAt int64
}

// Tracker хранит отметки по ID источника. Безопасен для параллельных вызовов: загрузчики
// каталога и менеджер источников движка работают одновременно.
type Tracker struct {
	mu sync.Mutex
	m  map[string]Stamp
}

// New создаёт пустой трекер.
func New() *Tracker { return &Tracker{m: make(map[string]Stamp)} }

// Restore кладёт в трекер ранее сохранённую отметку (при старте — из config.json). Пустая
// отметка (без отпечатка) игнорируется: восстанавливать нечего.
func (t *Tracker) Restore(id string, s Stamp) {
	if t == nil || id == "" || s.Hash == "" {
		return
	}
	t.mu.Lock()
	t.m[id] = s
	t.mu.Unlock()
}

// Observe учитывает свежескачанное тело источника id и возвращает его отметку после учёта.
// Пустое (без единой строки-узла) тело ничего не меняет: сбой источника или обрезанный ответ —
// не «изменение содержимого», и затирать им прежний отпечаток нельзя.
func (t *Tracker) Observe(id string, body []byte, now time.Time) Stamp {
	if t == nil || id == "" {
		return Stamp{}
	}
	digest := Digest(body)
	t.mu.Lock()
	defer t.mu.Unlock()
	prev, had := t.m[id]
	if digest == "" {
		return prev
	}
	ts := now.Unix()
	switch {
	case !had || prev.Hash == "":
		prev = Stamp{Hash: digest, FirstSeenAt: ts, SeenAt: ts}
	case prev.Hash != digest:
		prev.Hash = digest
		prev.ChangedAt = ts
		prev.SeenAt = ts
	default:
		prev.SeenAt = ts
	}
	t.m[id] = prev
	return prev
}

// Get возвращает отметку источника id.
func (t *Tracker) Get(id string) (Stamp, bool) {
	if t == nil {
		return Stamp{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.m[id]
	return s, ok
}

// Snapshot — копия всех отметок (для сохранения в конфиг).
func (t *Tracker) Snapshot() map[string]Stamp {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]Stamp, len(t.m))
	for k, v := range t.m {
		out[k] = v
	}
	return out
}

// proxySchemes — схемы ссылок узлов, по которым строка считается «узлом». Любая другая строка
// (HTML-заглушка оператора с кодом 200, служебный текст) в отпечаток не попадает.
var proxySchemes = map[string]bool{
	"vless": true, "vmess": true, "trojan": true, "ss": true, "ssr": true,
	"hysteria": true, "hysteria2": true, "hy2": true, "tuic": true,
	"wireguard": true, "wg": true, "socks": true, "socks5": true, "anytls": true,
}

// isNodeLink — строка начинается со схемы ссылки узла («vless://…»).
func isNodeLink(ln string) bool {
	i := strings.Index(ln, "://")
	if i <= 0 {
		return false
	}
	return proxySchemes[strings.ToLower(ln[:i])]
}

// Digest — отпечаток НАБОРА узлов тела. Снимается BOM и base64-обёртка; учитываются только
// строки-ссылки узлов (vless://, ss://, …), причём БЕЗ фрагмента «#имя»: его издатели нередко
// нумеруют или переименовывают, а сам узел остаётся тем же. Комментарии, пустые строки, порядок
// строк и чужой текст на отпечаток не влияют — поэтому смена только заголовка со временем
// публикации не считается изменением содержимого, а замена или добавление узла считается.
// Для Clash YAML (в нём ссылок нет) берутся строки с «server:». "" — узлов в теле нет.
func Digest(body []byte) string {
	text := strings.TrimSpace(strings.TrimPrefix(string(body), "\ufeff"))
	if text == "" {
		return ""
	}
	// Так же, как делают загрузчики (catalog.tryBase64Decode): сплошной base64 — подписка.
	if b, err := base64.StdEncoding.DecodeString(text); err == nil {
		text = string(b)
	} else if b, err := base64.RawStdEncoding.DecodeString(text); err == nil {
		text = string(b)
	}
	text = strings.TrimPrefix(text, "\ufeff")
	links := make([]string, 0, 64)
	var yaml []string
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if isNodeLink(ln) {
			if i := strings.Index(ln, "#"); i > 0 {
				ln = ln[:i]
			}
			links = append(links, ln)
		} else if strings.Contains(ln, "server:") {
			yaml = append(yaml, ln)
		}
	}
	lines := links
	if len(lines) == 0 {
		lines = yaml
	}
	if len(lines) == 0 {
		return ""
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, ln := range lines {
		h.Write([]byte(ln))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// Info — готовое к показу описание возраста содержимого.
type Info struct {
	// Hours — возраст в часах: с ChangedAt, если перемену видели, иначе с первой загрузки.
	// -1 — отметки нет (источник ещё ни разу не загружался или выключен).
	Hours int
	// Exact — true, если перемену видели своими глазами (возраст — с этого момента), и false,
	// если это лишь нижняя граница «не менялось с первой загрузки».
	Exact bool
	// Stale — возраст не меньше StaleAfter: источник, возможно, заморожен.
	Stale bool
	// Text — короткая строка для карточки источника. "" — показывать нечего.
	Text string
}

// Describe превращает отметку в Info относительно момента now.
func Describe(s Stamp, now time.Time) Info {
	if s.Hash == "" || s.FirstSeenAt == 0 {
		return Info{Hours: -1}
	}
	// Источник давно не загружался (выключен или недоступен): возраст «с последней перемены» тогда
	// описывал бы то, чего мы не наблюдали, и называть его замороженным нельзя.
	if s.SeenAt > 0 {
		if idle := now.Sub(time.Unix(s.SeenAt, 0)); idle > StaleAfter {
			return Info{Hours: -1, Text: "Содержимое давно не загружалось (" + formatAge(idle) + " назад) — возраст неизвестен"}
		}
	}
	var ref int64
	exact := false
	if s.ChangedAt > 0 {
		ref, exact = s.ChangedAt, true
	} else {
		ref = s.FirstSeenAt
	}
	age := now.Sub(time.Unix(ref, 0))
	if age < 0 {
		// Системные часы ушли назад: возраст честно неизвестен, а не «0 минут».
		return Info{Hours: -1}
	}
	info := Info{
		Hours: int(age / time.Hour),
		Exact: exact,
		Stale: age >= StaleAfter,
	}
	ago := formatAge(age)
	switch {
	case exact:
		info.Text = "Содержимое менялось " + ago + " назад"
	case age < time.Hour:
		info.Text = "Содержимое загружено впервые, возраст пока неизвестен"
	default:
		info.Text = "Содержимое не менялось ≥ " + ago + " (за время наблюдения)"
	}
	if info.Stale {
		info.Text += " — возможно, источник заморожен"
	}
	return info
}

// formatAge — «45 мин», «5 ч», «3 сут»: без склонений, чтобы строка не врала в падежах.
func formatAge(d time.Duration) string {
	switch {
	case d < time.Hour:
		m := int(d / time.Minute)
		if m < 1 {
			m = 1
		}
		return fmt.Sprintf("%d мин", m)
	case d < 48*time.Hour:
		return fmt.Sprintf("%d ч", int(d/time.Hour))
	default:
		return fmt.Sprintf("%d сут", int(d/(24*time.Hour)))
	}
}
