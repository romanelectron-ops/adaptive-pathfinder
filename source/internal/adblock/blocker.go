// Package adblock — DNS-based блокировщик рекламы и трекеров для APF.
//
// Принцип работы:
//
//	Перехватывает DNS-запросы через sing-box route rules.
//	Заблокированные домены резолвятся в 0.0.0.0 (rcode://success без ответа).
//
// Профили:
//   - light    — только реклама (10k доменов)
//   - standard — реклама + трекеры (50k доменов)
//   - strict   — реклама + трекеры + телеметрия (100k+ доменов)
//
// Источники блок-листов:
//   - Steven Black's hosts (реклама)
//   - AdGuard DNS filter
//   - EasyList
//   - Disconnect.me tracking list
package adblock

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/netguard"
	"github.com/apf/adaptive-pathfinder/internal/version"
)

// Profile — профиль блокировки
type Profile string

const (
	ProfileDisabled Profile = "disabled"
	ProfileLight    Profile = "light"
	ProfileStandard Profile = "standard"
	ProfileStrict   Profile = "strict"
)

// BlocklistSource — источник блок-листа
type BlocklistSource struct {
	ID      string
	Name    string
	URL     string
	Profile Profile // минимальный профиль для включения
	Format  string  // "hosts", "adblock", "domains"
}

// Дефолтные источники блок-листов
var DefaultSources = []BlocklistSource{
	{
		ID:      "steven-black",
		Name:    "Steven Black's hosts (ads)",
		URL:     "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		Profile: ProfileLight,
		Format:  "hosts",
	},
	{
		ID:      "adguard-dns",
		Name:    "AdGuard DNS filter",
		URL:     "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
		Profile: ProfileStandard,
		Format:  "adblock",
	},
	{
		ID:      "disconnect-tracking",
		Name:    "Disconnect.me Tracking",
		URL:     "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
		Profile: ProfileStandard,
		Format:  "domains",
	},
	{
		ID:      "disconnect-malware",
		Name:    "Disconnect.me Malware",
		URL:     "https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt",
		Profile: ProfileLight,
		Format:  "domains",
	},
	{
		// Живой инцидент 2026-08-27: /domains — устаревший путь, OISD отдаёт на него 404 (100%
		// воспроизведено в 7 разных загрузках за два дня тестирования, оба OISD-источника
		// проваливались КАЖДЫЙ раз). Актуальный путь — без суффикса, но и формат сменился:
		// корень отдаёт Adblock Plus синтаксис (||domain^), не голый домен построчно — Format
		// обязан быть "adblock" (тот же парсер уже проверен на adguard-dns ниже), иначе URL
		// перестанет 404-ить, но парсер молча отбросит все строки как невалидные домены
		// (isValidDomain не пропускает "|"/"^").
		ID:      "oisd-small",
		Name:    "OISD Small (balanced)",
		URL:     "https://small.oisd.nl",
		Profile: ProfileStandard,
		Format:  "adblock",
	},
	{
		ID:      "oisd-big",
		Name:    "OISD Big (comprehensive)",
		URL:     "https://big.oisd.nl",
		Profile: ProfileStrict,
		Format:  "adblock",
	},
}

// Blocker — DNS блокировщик
type Blocker struct {
	mu      sync.RWMutex
	profile Profile
	domains map[string]bool // заблокированные домены
	allow   map[string]bool // белый список (allowlist)
	stats   BlockerStats
	log     func(string)
}

// BlockerStats — статистика блокировщика
type BlockerStats struct {
	TotalDomains   int       `json:"total_domains"`
	AllowlistSize  int       `json:"allowlist_size"`
	LastUpdated    time.Time `json:"last_updated"`
	UpdateDuration int64     `json:"update_duration_ms"`
	SourcesLoaded  int       `json:"sources_loaded"`
	SourcesFailed  int       `json:"sources_failed"`
}

// NewBlocker создаёт блокировщик
func NewBlocker(logFn func(string)) *Blocker {
	if logFn == nil {
		logFn = func(s string) {}
	}
	return &Blocker{
		profile: ProfileDisabled,
		domains: make(map[string]bool),
		allow:   make(map[string]bool),
		log:     logFn,
	}
}

// SetProfile меняет профиль. При смене — перезагружает блок-листы.
func (b *Blocker) SetProfile(ctx context.Context, p Profile) error {
	b.mu.Lock()
	b.profile = p
	b.mu.Unlock()

	if p == ProfileDisabled {
		b.mu.Lock()
		b.domains = make(map[string]bool)
		b.mu.Unlock()
		b.log("AdBlock: disabled")
		return nil
	}

	return b.UpdateLists(ctx)
}

// GetProfile возвращает текущий профиль
func (b *Blocker) GetProfile() Profile {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.profile
}

// IsBlocked проверяет заблокирован ли домен (с учётом субдоменов и allowlist)
func (b *Blocker) IsBlocked(domain string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.profile == ProfileDisabled || len(b.domains) == 0 {
		return false
	}

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	// Allowlist имеет приоритет — и действует на поддомены, как и блок-лист ниже.
	//
	// P1-6 (аудит 2026-09-01): раньше здесь было только точное совпадение `b.allow[domain]`.
	// Пользователь, разрешивший "example.com", ожидал, что разрешён и "cdn.example.com" —
	// ровно так же, как блокировка "example.com" блокирует все его поддомены. Асимметрия
	// работала против пользователя: запретить проще, чем разрешить обратно.
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts)-1; i++ {
		if b.allow[strings.Join(parts[i:], ".")] {
			return false
		}
	}

	// Проверяем домен и все родительские домены
	for i := 0; i < len(parts)-1; i++ {
		candidate := strings.Join(parts[i:], ".")
		if b.domains[candidate] {
			return true
		}
	}
	return false
}

// normalizeDomain приводит пользовательский ввод к виду, в котором домены лежат в блок-листах:
// нижний регистр, без пробелов, без корневой точки, без схемы и без пути. Пустая строка на
// выходе означает «ввод не является доменом» — вызывающая сторона обязана его отвергнуть.
//
// P1-6 (аудит 2026-09-01): раньше нормализации не было вообще — только strings.ToLower. Ввод
// вида "https://example.com/" клался в allowlist дословно, никогда ни с чем не совпадал и
// молча ничего не разрешал, при этом исправно отображаясь в UI как «домен в белом списке».
func normalizeDomain(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	if i := strings.Index(d, "://"); i >= 0 {
		d = d[i+3:]
	}
	if i := strings.IndexAny(d, "/?#"); i >= 0 {
		d = d[:i]
	}
	if i := strings.LastIndex(d, "@"); i >= 0 { // user:pass@host
		d = d[i+1:]
	}
	// host:port — отсекаем порт, но не трогаем IPv6-литералы (там двоеточий много).
	if strings.Count(d, ":") == 1 {
		d = d[:strings.Index(d, ":")]
	}
	d = strings.Trim(d, ".")
	if d == "" || strings.ContainsAny(d, " \t*,") || !strings.Contains(d, ".") {
		return ""
	}
	return d
}

// AddToAllowlist добавляет домен в белый список.
// Возвращает false, если ввод не является доменом или домен уже был в списке — в обоих
// случаях состояние не изменилось и переприменять конфигурацию не нужно.
func (b *Blocker) AddToAllowlist(domain string) bool {
	d := normalizeDomain(domain)
	if d == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.allow[d] {
		return false
	}
	b.allow[d] = true
	return true
}

// RemoveFromAllowlist убирает домен из белого списка.
// Возвращает false, если такого домена в списке не было.
func (b *Blocker) RemoveFromAllowlist(domain string) bool {
	d := normalizeDomain(domain)
	if d == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.allow[d] {
		return false
	}
	delete(b.allow, d)
	return true
}

// SetAllowlist полностью заменяет белый список — путь загрузки из конфигурации при старте.
// Некорректные записи отбрасываются молча: конфигурация могла быть отредактирована руками.
func (b *Blocker) SetAllowlist(domains []string) {
	fresh := make(map[string]bool, len(domains))
	for _, raw := range domains {
		if d := normalizeDomain(raw); d != "" {
			fresh[d] = true
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.allow = fresh
}

// GetAllowlist возвращает белый список в стабильном (отсортированном) порядке.
// Порядок важен: список едет в конфигурацию на диск, и обход map давал бы разный JSON при
// каждом сохранении — бессмысленные записи в файл и шум в диффах у пользователя.
func (b *Blocker) GetAllowlist() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, 0, len(b.allow))
	for d := range b.allow {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// GetStats возвращает статистику
func (b *Blocker) GetStats() BlockerStats {
	b.mu.RLock()
	defer b.mu.RUnlock()
	s := b.stats
	s.TotalDomains = len(b.domains)
	s.AllowlistSize = len(b.allow)
	return s
}

// UpdateLists загружает/обновляет блок-листы для текущего профиля
func (b *Blocker) UpdateLists(ctx context.Context) error {
	b.mu.RLock()
	profile := b.profile
	b.mu.RUnlock()

	if profile == ProfileDisabled {
		return nil
	}

	b.log(fmt.Sprintf("AdBlock: updating lists for profile '%s'...", profile))
	start := time.Now()

	newDomains := make(map[string]bool)
	loaded, failed := 0, 0
	// netguard: под `go test` выход за пределы петли отвергается (Т-5).
	client := netguard.Client(30 * time.Second)

	for _, src := range DefaultSources {
		// Пропускаем источники строже текущего профиля
		if !profileIncludes(profile, src.Profile) {
			continue
		}

		b.log(fmt.Sprintf("AdBlock: loading %s...", src.Name))
		domains, err := fetchBlocklist(ctx, client, src)
		if err != nil {
			b.log(fmt.Sprintf("AdBlock: WARN %s: %v", src.Name, err))
			failed++
			continue
		}

		for _, d := range domains {
			newDomains[d] = true
		}
		b.log(fmt.Sprintf("AdBlock: %s loaded %d domains", src.Name, len(domains)))
		loaded++
	}

	dur := time.Since(start)
	b.mu.Lock()
	// Живой инцидент 2026-08-27: при периодическом обновлении транзитный сбой сети уронил
	// один из источников (Steven Black), и старый код БЕЗУСЛОВНО заменял b.domains на
	// заново собранное множество — активная защита молча схлопнулась с ~254K до ~177K
	// доменов до следующего успешного обновления. Полный отказ (loaded==0, все источники
	// упали, например временная недоступность сети целиком) — оставляем прежний список
	// как есть: пустой newDomains точно хуже старого рабочего, тут выбор однозначен.
	// Частичный отказ (часть источников загрузилась) — по-прежнему принимаем то, что есть:
	// смешивать старые данные упавшего источника с новыми от рабочих неверно определить
	// без знания, что именно изменилось в списке конкретного источника.
	if loaded > 0 {
		b.domains = newDomains
	} else {
		b.log(fmt.Sprintf("AdBlock: WARN все %d источников профиля недоступны — "+
			"оставляю прежний список (%d доменов) без изменений", failed, len(b.domains)))
	}
	b.stats.LastUpdated = time.Now()
	b.stats.UpdateDuration = dur.Milliseconds()
	b.stats.SourcesLoaded = loaded
	b.stats.SourcesFailed = failed
	activeDomains := len(b.domains)
	b.mu.Unlock()

	b.log(fmt.Sprintf("AdBlock: ready — %d domains in %v (%d sources, %d failed)",
		activeDomains, dur.Round(time.Second), loaded, failed))
	return nil
}

// GetSingBoxDNSRules возвращает sing-box DNS rules для блокировки.
// Интегрируется в singbox.Config.DNS.Rules — ПОРЯДОК ЗНАЧИМ.
//
// Первыми идут правила allowlist ("action":"allow"), затем батчи блокировки
// ("action":"block"). Правила DNS в sing-box матчатся сверху вниз, и терминальное действие
// останавливает разбор — поэтому разрешающее правило обязано стоять ВЫШЕ запрещающих.
//
// P1-6 (аудит 2026-09-01). Раньше allowlist применялся здесь единственным способом: домен
// вычитался из блок-списка при ТОЧНОМ совпадении (`if !b.allow[d]`). Для домена, лежащего в
// блок-листе ровно в том виде, в каком его вписал пользователь, это работало; во всех
// остальных случаях — нет. Разбор случая, который ломался чаще всего: пользователь разрешает
// "cdn.tracker.com", а в блок-листе лежит "tracker.com". Точного совпадения нет, "tracker.com"
// остаётся в батче, батч эмитится как domain_suffix — и "cdn.tracker.com" продолжает
// блокироваться по суффиксу. При этом IsBlocked() (внутрипроцессная проверка) отвечал «не
// заблокирован», то есть два пути расходились в ответе, а реальный трафик шёл по тому,
// который allowlist игнорировал. Пользователь видел домен в белом списке и не понимал,
// почему сайт по-прежнему не открывается.
func (b *Blocker) GetSingBoxDNSRules() []map[string]interface{} {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.profile == ProfileDisabled || len(b.domains) == 0 {
		return nil
	}

	var rules []map[string]interface{}

	// Разрешающее правило — одним батчем: allowlist ведёт человек руками, он на порядки
	// меньше лимита в 1000 доменов на правило.
	if len(b.allow) > 0 {
		allowed := make([]string, 0, len(b.allow))
		for d := range b.allow {
			allowed = append(allowed, d)
		}
		sort.Strings(allowed) // детерминированный конфиг: см. GetAllowlist
		rules = append(rules, map[string]interface{}{
			"domain_suffix": allowed,
			"action":        "allow",
		})
	}

	// Собираем домены в батчи по 1000 (sing-box лимит на размер правила).
	// Точное вычитание allowlist оставлено: оно не обязательно (разрешающее правило выше уже
	// перехватывает такие запросы), но уменьшает объём конфигурации на реальных списках.
	allDomains := make([]string, 0, len(b.domains))
	for d := range b.domains {
		if !b.allow[d] {
			allDomains = append(allDomains, d)
		}
	}

	const batchSize = 1000

	for i := 0; i < len(allDomains); i += batchSize {
		end := i + batchSize
		if end > len(allDomains) {
			end = len(allDomains)
		}
		batch := allDomains[i:end]
		rules = append(rules, map[string]interface{}{
			"domain_suffix": batch,
			"server":        "dns-block",
			"action":        "block",
		})
	}

	return rules
}

// ─── Парсинг блок-листов ──────────────────────────────────────────────────────

func fetchBlocklist(ctx context.Context, client *http.Client, src BlocklistSource) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", src.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", version.UserAgent())

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return parseBlocklist(io.LimitReader(resp.Body, 20*1024*1024), src.Format)
}

func parseBlocklist(r io.Reader, format string) ([]string, error) {
	var domains []string
	scanner := bufio.NewScanner(r)
	// Буфер для длинных строк (OISD big имеет длинные строки)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, len(buf))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}

		var domain string
		switch format {
		case "hosts":
			// "0.0.0.0 example.com" или "127.0.0.1 example.com"
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ip := parts[0]
				if ip == "0.0.0.0" || ip == "127.0.0.1" {
					domain = parts[1]
				}
			}
		case "adblock":
			// "||example.com^" или "||example.com^$important"
			if strings.HasPrefix(line, "||") {
				d := strings.TrimPrefix(line, "||")
				if idx := strings.IndexAny(d, "^$/"); idx >= 0 {
					d = d[:idx]
				}
				domain = d
			}
		case "domains":
			// Просто домен, одна строка
			if !strings.ContainsAny(line, " \t/") {
				domain = line
			}
		}

		if domain == "" {
			continue
		}

		domain = strings.ToLower(strings.TrimSuffix(domain, "."))
		// Базовая валидация
		if isValidDomain(domain) {
			domains = append(domains, domain)
		}
	}

	return domains, scanner.Err()
}

func isValidDomain(d string) bool {
	if len(d) < 3 || len(d) > 253 {
		return false
	}
	if strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") {
		return false
	}
	if !strings.Contains(d, ".") {
		return false
	}
	// Нет специальных символов (кроме дефисов и точек)
	for _, c := range d {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// profileIncludes проверяет что текущий профиль включает данный источник
func profileIncludes(current, required Profile) bool {
	order := map[Profile]int{
		ProfileLight:    1,
		ProfileStandard: 2,
		ProfileStrict:   3,
	}
	c, r := order[current], order[required]
	return c > 0 && r > 0 && c >= r
}
