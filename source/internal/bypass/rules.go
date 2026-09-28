// Package bypass хранит правила обхода блокировок по конкретным доменам.
// Sprint S6: Anti-VPN-Block — для каких сайтов нужен residential IP.
package bypass

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Rule описывает правило для конкретного домена/сервиса.
//
// ДВА РАЗНЫХ по смыслу режима в одном правиле (сознательно — переиспользуют одну и ту же
// инфраструктуру CRUD/персистентности/матчинга, но включают РАЗНОЕ поведение):
//   - RequireResidential: домен всё равно идёт ЧЕРЕЗ туннель, но узел для него предпочтительно
//     residential (анти-VPN-блок площадок вроде Netflix/банков). Трафик защищён VPN.
//   - DirectRoute: домен идёт НАПРЯМУЮ, В ОБХОД VPN/туннеля целиком (реальный сплит-туннелинг,
//     через config_builder.Builder.SetBypassDomains). Трафик НЕ защищён VPN — сайт увидит
//     настоящий IP пользователя. Раньше это поле отсутствовало: пользовательский bypass-список
//     существовал (CRUD, персистентность), но нигде не влиял на реальную маршрутизацию.
type Rule struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`                // "Netflix", "Сбербанк"
	Domains            []string `json:"domains"`             // ["netflix.com", "*.nflxvideo.net"]
	RequireResidential bool     `json:"require_residential"` // нужен residential IP (трафик всё ещё через VPN)
	DirectRoute        bool     `json:"direct_route"`        // идёт НАПРЯМУЮ, в обход VPN целиком
	PreferCountry      string   `json:"prefer_country"`      // "US", "RU" — предпочтительная страна
	Notes              string   `json:"notes"`               // пояснение для UI
	Enabled            bool     `json:"enabled"`
	Builtin            bool     `json:"builtin"` // встроенное правило (не удаляется)
}

// Manager управляет правилами bypass.
type Manager struct {
	mu       sync.RWMutex
	rules    []*Rule
	dataPath string // путь к bypass_list.json
}

// NewManager создаёт Manager и загружает встроенные + пользовательские правила.
func NewManager(dataDir string) *Manager {
	m := &Manager{
		dataPath: filepath.Join(dataDir, "bypass_list.json"),
		rules:    builtinRules(),
	}
	m.loadUserRules()
	return m
}

// Rules возвращает все правила (встроенные + пользовательские).
func (m *Manager) Rules() []*Rule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*Rule, len(m.rules))
	copy(result, m.rules)
	return result
}

// MatchDomain ищет правило для заданного хоста.
// Возвращает первое enabled правило, домен которого совпадает.
func (m *Manager) MatchDomain(host string) *Rule {
	host = strings.ToLower(strings.TrimPrefix(host, "www."))
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, r := range m.rules {
		if !r.Enabled {
			continue
		}
		if matchesDomains(host, r.Domains) {
			return r
		}
	}
	return nil
}

// RequiresResidential возвращает true если для хоста нужен residential IP.
func (m *Manager) RequiresResidential(host string) bool {
	rule := m.MatchDomain(host)
	return rule != nil && rule.RequireResidential
}

// SetRuleEnabled включает/выключает правило по ID.
func (m *Manager) SetRuleEnabled(id string, enabled bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rules {
		if r.ID == id {
			r.Enabled = enabled
			m.saveUserRules()
			return true
		}
	}
	return false
}

// normalizeDomain приводит пользовательский ввод к виду, в котором домены реально сравниваются
// (matchesDomains) и уходят в маршрутизацию (DirectRouteDomains → sing-box domain_suffix):
// нижний регистр, без пробелов, без схемы, пути, порта и корневых точек. Пустая строка на
// выходе означает «ввод не является доменом» — вызывающая сторона обязана его отвергнуть.
//
// К2-E П12 (свод C трек 1 №12; B1 #3, A3). Раньше нормализации не было вообще: AddUserRule
// делала только ToLower+TrimSpace, а bypass_list.json уходил в рабочий список прямо из
// json.Unmarshal. Ввод «https://x/» превращался в правило с доменами
// ["https://x/", "*.https://x/"], попадал в DirectRouteDomains и оттуда в конфигурацию
// sing-box. Цена ошибки здесь выше, чем в блок-листе: DirectRoute выводит домен ИЗ туннеля
// целиком — сайт видит настоящий IP пользователя.
//
// Правило написано по образцу adblock.normalizeDomain (P1-6, аудит 2026-09-01) и намеренно НЕ
// вынесено в общий пакет: у списков разные потребители и разная цена ошибки, общая функция
// связала бы их изменения. Совпадение поведения зафиксировано тестами обоих пакетов.
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

// ErrInvalidDomain — текст ошибки для пользователя (показывается в интерфейсе как есть).
var errInvalidDomainText = "это не похоже на домен: нужен адрес вида example.com — " +
	"без схемы, пути, пробелов и звёздочек (поддомены покрываются автоматически)"

// AddUserRuleChecked добавляет пользовательское правило с проверкой ввода.
//
// Вход:      домен в любом виде, отображаемое имя, два независимых флага режима.
// Тело:      нормализация домена → отказ, если это не домен → поиск дубликата → создание.
// Выход:     созданное (или уже существовавшее) правило; ошибка, если ввод не домен.
// Fail-safe: при отказе список правил и файл на диске не меняются вовсе.
func (m *Manager) AddUserRuleChecked(domain, name string, requireResidential, directRoute bool) (*Rule, error) {
	norm := normalizeDomain(domain)
	if norm == "" {
		return nil, errors.New(errInvalidDomainText)
	}
	domain = norm
	if strings.TrimSpace(name) == "" {
		name = domain
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Проверяем что домен уже не в списке
	for _, r := range m.rules {
		for _, d := range r.Domains {
			if d == domain {
				return r, nil // уже есть
			}
		}
	}

	rule := &Rule{
		ID:                 "user_" + strings.ReplaceAll(domain, ".", "_"),
		Name:               name,
		Domains:            []string{domain, "*." + domain},
		RequireResidential: requireResidential,
		DirectRoute:        directRoute,
		Enabled:            true,
		Builtin:            false,
	}
	m.rules = append(m.rules, rule)
	m.saveUserRules()
	return rule, nil
}

// AddUserRule — прежний контракт (nil = отказ) поверх AddUserRuleChecked. Оставлен для
// вызывающих, которым причина отказа не нужна; новым кодом предпочтительна Checked-версия,
// потому что она может ОБЪЯСНИТЬ пользователю, что не так с введённым доменом.
func (m *Manager) AddUserRule(domain, name string, requireResidential, directRoute bool) *Rule {
	rule, err := m.AddUserRuleChecked(domain, name, requireResidential, directRoute)
	if err != nil {
		return nil
	}
	return rule
}

// UpdateUserRule редактирует уже существующее пользовательское правило (builtin — нельзя).
// domain/name пустые — оставляют прежнее значение без изменений.
//
// К2-E П12: непустой, но НЕ являющийся доменом ввод — отказ (false), а не молчаливая запись
// мусора поверх рабочего правила. Отказ происходит ДО любых изменений: правило остаётся тем,
// чем было (частично изменённое правило хуже неизменённого).
func (m *Manager) UpdateUserRule(id, domain, name string, requireResidential, directRoute bool) bool {
	if strings.TrimSpace(domain) != "" {
		norm := normalizeDomain(domain)
		if norm == "" {
			return false
		}
		domain = norm
	} else {
		domain = ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rules {
		if r.ID != id || r.Builtin {
			continue
		}
		if domain != "" {
			r.Domains = []string{domain, "*." + domain}
		}
		if name != "" {
			r.Name = name
		}
		r.RequireResidential = requireResidential
		r.DirectRoute = directRoute
		m.saveUserRules()
		return true
	}
	return false
}

// RemoveUserRule удаляет пользовательское правило по ID (builtin удалять нельзя).
func (m *Manager) RemoveUserRule(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, r := range m.rules {
		if r.ID == id && !r.Builtin {
			m.rules = append(m.rules[:i], m.rules[i+1:]...)
			m.saveUserRules()
			return true
		}
	}
	return false
}

// DirectRouteDomains возвращает домены ВКЛЮЧЁННЫХ правил с DirectRoute=true — то, что должно
// реально маршрутизироваться в обход VPN (см. config_builder.Builder.SetBypassDomains).
//
// Живой прогон 2026-08-13: правило добавлялось (persist ок), но трафик к домену всё равно шёл
// через vmess, не direct. Причина: Rule.Domains хранит ["example.com", "*.example.com"] —
// звёздочка нужна только matchesDomains() (собственный матчер этого пакета, wildcard-семантика
// сравнения строк). sing-box's domain_suffix НЕ понимает "*." — это простое суффиксное
// совпадение, которое и без звёздочки уже покрывает поддомены ("example.com" как suffix уже
// матчит "www.example.com"). Буквальная "*.example.com" в domain_suffix — мусорное значение,
// которое (судя по симптому) валит матчинг всего правила целиком. Отфильтровываем "*."-записи
// здесь, а не трогаем Domains/matchesDomains — тот формат нужен и корректен для СВОЕГО
// потребителя (MatchDomain/RequiresResidential), это ДРУГОЙ потребитель с другим форматом.
func (m *Manager) DirectRouteDomains() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []string
	for _, r := range m.rules {
		if !r.Enabled || !r.DirectRoute {
			continue
		}
		for _, d := range r.Domains {
			if strings.HasPrefix(d, "*.") {
				continue // domain_suffix уже покрывает поддомены без wildcard-синтаксиса
			}
			out = append(out, d)
		}
	}
	return out
}

// defaultBuiltinByID — заводское состояние встроенного правила (nil, если такого нет).
func defaultBuiltinByID(id string) *Rule {
	for _, r := range builtinRules() {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// sameUserSettings — совпадают ли пользователь-изменяемые поля двух правил.
func sameUserSettings(a, b *Rule) bool {
	return a.Enabled == b.Enabled &&
		a.DirectRoute == b.DirectRoute &&
		a.RequireResidential == b.RequireResidential
}

// sanitizeRuleDomains нормализует список доменов правила, СОХРАНЯЯ форму "*.host" (её ждёт
// matchesDomains — это собственный матчер пакета, а не sing-box). Мусорные записи выбрасывает,
// дубликаты схлопывает. Пустой результат означает «правило непригодно целиком».
func sanitizeRuleDomains(domains []string) []string {
	out := make([]string, 0, len(domains))
	seen := make(map[string]bool, len(domains))
	for _, d := range domains {
		wildcard := strings.HasPrefix(strings.TrimSpace(d), "*.")
		bare := strings.TrimPrefix(strings.TrimSpace(d), "*.")
		norm := normalizeDomain(bare)
		if norm == "" {
			continue
		}
		if wildcard {
			norm = "*." + norm
		}
		if seen[norm] {
			continue
		}
		seen[norm] = true
		out = append(out, norm)
	}
	return out
}

// migrateWWWDomainEntry убирает буквальный префикс "www." у ОДНОЙ записи домена, сохраняя
// разметку wildcard "*." если она была ("*.www.site.com" → "*.site.com"). Возвращает
// нормализованное значение и признак того, что оно отличается от исходного.
//
// C-2 (ТЗ v1.4): до фикса matchesDomains правило "www.site.com" не совпадало НИ С ЧЕМ, поэтому
// такие записи в сохранённом bypass_list.json — мёртвый груз с прошлых версий. matchesDomains
// теперь понимает буквальную форму "www.X" сама по себе (см. комментарий там), так что миграция
// не нужна для корректности матчинга — но старый файл приводится к канонической bare-форме при
// первой же загрузке, чтобы на диске не оставалось артефактов уже исправленного дефекта.
func migrateWWWDomainEntry(d string) (string, bool) {
	wildcard := strings.HasPrefix(d, "*.")
	bare := strings.TrimPrefix(d, "*.")
	if !strings.HasPrefix(strings.ToLower(bare), "www.") {
		return d, false
	}
	bare = bare[len("www."):]
	if wildcard {
		return "*." + bare, true
	}
	return bare, true
}

// loadUserRules загружает пользовательские правила из bypass_list.json.
func (m *Manager) loadUserRules() {
	data, err := os.ReadFile(m.dataPath)
	if err != nil {
		return // файла нет — нормально при первом запуске
	}
	var userRules []*Rule
	if err := json.Unmarshal(data, &userRules); err != nil {
		return
	}
	needsMigrationSave := false
	// Пользовательские правила добавляем, встроенные — НАКЛАДЫВАЕМ как переопределения.
	//
	// Раньше записи с Builtin=true просто пропускались и при сохранении, и при загрузке, а
	// NewManager каждый запуск пересоздавал список из builtinRules(). То есть переключатель
	// встроенного правила отрабатывал, возвращал успех и молча забывался при перезапуске
	// (найдено ревью 2026-08-24). Пока встроенные правила ничего не меняли в маршрутизации,
	// это было безобидно; теперь, когда правила для российских сервисов включаются
	// пользователем осознанно (opt-in), потеря выбора означала бы, что настройка просто не
	// работает.
	byID := make(map[string]*Rule, len(m.rules))
	for _, r := range m.rules {
		byID[r.ID] = r
	}
	for _, r := range userRules {
		if !r.Builtin {
			// К2-E П12: файл — такой же недоверенный вход, как поле ввода. Он переживает
			// обновления, редактируется руками и может быть повреждён; правило с
			// DirectRoute=true выводит домен из туннеля целиком. Отбрасываем правила, у
			// которых после нормализации не осталось ни одного домена, и вычищаем мусорные
			// записи внутри правила, сохраняя остальные (частично испорченный файл не должен
			// стоить пользователю всего списка).
			if r == nil {
				continue
			}
			clean := sanitizeRuleDomains(r.Domains)
			if len(clean) == 0 {
				log.Printf("bypass: правило %q (%s) отброшено при загрузке — ни одного корректного домена в %v",
					r.ID, r.Name, r.Domains)
				continue
			}
			if len(clean) != len(r.Domains) {
				log.Printf("bypass: у правила %q отброшены некорректные домены: было %v, стало %v",
					r.ID, r.Domains, clean)
			}
			// C-2 (ТЗ v1.4): миграция записей с буквальным префиксом "www." к bare-форме —
			// файл приводится к канонической форме один раз при первой загрузке после фикса.
			for i, dom := range clean {
				if nd, changed := migrateWWWDomainEntry(dom); changed {
					clean[i] = nd
					needsMigrationSave = true
				}
			}
			r.Domains = clean
			if r.ID == "" {
				r.ID = "user_" + strings.ReplaceAll(clean[0], ".", "_")
			}
			if strings.TrimSpace(r.Name) == "" {
				r.Name = clean[0]
			}
			m.rules = append(m.rules, r)
			continue
		}
		if base, ok := byID[r.ID]; ok {
			base.Enabled = r.Enabled
			base.DirectRoute = r.DirectRoute
			base.RequireResidential = r.RequireResidential
		}
		// Встроенное правило, которого больше нет в сборке, сознательно игнорируем: список
		// builtinRules() — источник истины, файл лишь хранит выбор пользователя.
	}
	if needsMigrationSave {
		log.Printf("bypass: миграция bypass_list.json — убран устаревший буквальный префикс www. у доменов правил")
		m.saveUserRules()
	}
}

// saveUserRules сохраняет только пользовательские правила.
// Вызывается под mu.Lock().
func (m *Manager) saveUserRules() {
	var userRules []*Rule
	for _, r := range m.rules {
		if !r.Builtin {
			userRules = append(userRules, r)
			continue
		}
		// Встроенные правила сохраняем ТОЛЬКО если пользователь отклонил их от заводского
		// состояния — тогда файл хранит именно выбор пользователя, а не копию сборки, и
		// изменения builtinRules() в новых версиях подхватываются без конфликта.
		if def := defaultBuiltinByID(r.ID); def == nil || sameUserSettings(def, r) {
			continue
		}
		userRules = append(userRules, r)
	}

	data, err := json.MarshalIndent(userRules, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(m.dataPath), 0700); err != nil {
		log.Printf("bypass: cannot create data dir: %v", err)
		return
	}
	if err := os.WriteFile(m.dataPath, data, 0600); err != nil {
		log.Printf("bypass: failed to save rules to %s: %v", m.dataPath, err)
	}
}

// stripWWW убирает буквальный префикс "www." у ОДНОЙ строки (хоста или записи домена правила).
// Используется только для проверки эквивалентности "www.X" ⟷ "X" — НЕ для суффиксного
// сопоставления поддоменов (см. matchesDomains и C-2, ТЗ v1.4).
func stripWWW(s string) string {
	return strings.TrimPrefix(s, "www.")
}

// matchesDomains проверяет совпадение хоста с одним из доменов правила.
// Поддерживает wildcard: "*.netflix.com" совпадает с "www.netflix.com".
//
// C-2 (ТЗ v1.4, лот L1-DET): раньше правило, сохранённое буквально как "www.site.com", не
// совпадало НИ С ЧЕМ — MatchDomain срезает "www." у проверяемого хоста ДО вызова этой функции
// (см. ниже), а запись правила "www.site.com" при этом не срезается никогда, поэтому сравнение
// "www.site.com" (правило) с уже срезанным "site.com" (хост) не проходило ни через exact-match,
// ни через suffix-ветки. Фикс — явная проверка эквивалентности "www."-форм: "www.site.com" и
// "site.com" считаются ОДНИМ И ТЕМ ЖЕ хостом (два канонических написания одного адреса), но это
// НЕ расширяется на произвольные поддомены — "notwww.site.com" третьей проверкой не ловится,
// потому что stripWWW убирает префикс только у строк, буквально НАЧИНАЮЩИХСЯ с "www.", а
// "notwww.site.com" с "www." не начинается. Поддомены (любой другой лейбл) по-прежнему матчятся
// только через wildcard "*." или суффиксную ветку ниже — та защищена существующим тестом
// TestMatchDomains_PlainEntryCatchesSubdomain (rules_extra_test.go) и здесь не трогается.
func matchesDomains(host string, domains []string) bool {
	host = strings.ToLower(host)
	hostBare := stripWWW(host)
	for _, d := range domains {
		d = strings.ToLower(d)
		if d == host {
			return true
		}
		if hostBare == stripWWW(d) {
			return true
		}
		if strings.HasPrefix(d, "*.") {
			suffix := d[1:] // ".netflix.com"
			if strings.HasSuffix(host, suffix) || host == d[2:] {
				return true
			}
		}
		// Прямое совпадение без www
		plain := strings.TrimPrefix(d, "*.")
		if host == plain || strings.HasSuffix(host, "."+plain) {
			return true
		}
	}
	return false
}

// builtinRules возвращает встроенные правила для популярных сервисов.
func builtinRules() []*Rule {
	return []*Rule{
		{
			ID:                 "netflix",
			Name:               "Netflix",
			Domains:            []string{"netflix.com", "*.netflix.com", "*.nflxvideo.net", "*.nflximg.net"},
			RequireResidential: true,
			PreferCountry:      "US",
			Notes:              "Netflix блокирует datacenter IP. Нужен residential IP той страны.",
			Enabled:            true,
			Builtin:            true,
		},
		{
			ID:                 "disneyplus",
			Name:               "Disney+",
			Domains:            []string{"disneyplus.com", "*.disneyplus.com", "*.bamgrid.com"},
			RequireResidential: true,
			PreferCountry:      "US",
			Notes:              "Disney+ требует residential IP в лицензионной зоне.",
			Enabled:            true,
			Builtin:            true,
		},
		{
			ID:                 "hulu",
			Name:               "Hulu",
			Domains:            []string{"hulu.com", "*.hulu.com", "*.hulustream.com"},
			RequireResidential: true,
			PreferCountry:      "US",
			Notes:              "Hulu — только для USA, требует residential US IP.",
			Enabled:            true,
			Builtin:            true,
		},
		{
			ID:                 "hbomax",
			Name:               "HBO Max / Max",
			Domains:            []string{"max.com", "*.max.com", "hbomax.com", "*.hbomax.com"},
			RequireResidential: true,
			PreferCountry:      "US",
			Notes:              "HBO Max блокирует VPN/datacenter.",
			Enabled:            true,
			Builtin:            true,
		},
		{
			ID:                 "amazonprime",
			Name:               "Amazon Prime Video",
			Domains:            []string{"primevideo.com", "*.primevideo.com", "amazon.com/gp/video"},
			RequireResidential: true,
			Notes:              "Prime Video имеет региональные ограничения, блокирует datacenter.",
			Enabled:            true,
			Builtin:            true,
		},
		{
			ID:                 "spotify",
			Name:               "Spotify",
			Domains:            []string{"spotify.com", "*.spotify.com", "*.scdn.co"},
			RequireResidential: false, // Spotify более лояльный
			Notes:              "Spotify иногда ограничивает функции при VPN. Residential предпочтителен.",
			Enabled:            false, // выключено по умолчанию
			Builtin:            true,
		},
		{
			ID:                 "steam",
			Name:               "Steam (региональные цены)",
			Domains:            []string{"store.steampowered.com", "checkout.steampowered.com"},
			RequireResidential: true,
			Notes:              "Steam может заблокировать аккаунт за несоответствие региона. Residential IP того же региона.",
			Enabled:            true,
			Builtin:            true,
		},
		// ── Российские сервисы ────────────────────────────────────────────────────
		// У них цель ПРОТИВОПОЛОЖНА стриминговым правилам выше. Для Netflix/ChatGPT нужен
		// зарубежный residential-IP, то есть трафик обязан идти ЧЕРЕЗ туннель, просто через
		// хороший узел. Для Госуслуг/банков пользователь находится в России и хочет, чтобы
		// они работали ровно так, как будто VPN нет вовсе — значит трафик должен идти
		// НАПРЯМУЮ, с настоящим российским адресом.
		//
		// Исправлено 2026-08-24: у этих трёх правил стояло `RequireResidential: true` и
		// не стояло `DirectRoute`. При этом `RequireResidential` не читает НИ ОДИН участок
		// боевого кода (единственное упоминание вне пакета — вывод в JSON для UI), а в
		// маршрутизацию попадают только правила с `DirectRoute` (см. DirectRouteDomains).
		// То есть встроенное правило «Госуслуги» было включено по умолчанию и не делало
		// ничего: пользователь видел активный переключатель, обоснованно считал, что защита
		// работает, и получал ровно ту жалобу, с которой пришёл — «Госуслуги видят VPN даже
		// при включённой антиблокировке».
		//
		// ВАЖНО и честно: DirectRoute означает, что эти домены увидят реальный IP
		// пользователя. Для Госуслуг и банка это именно то, что нужно; текст в UI обязан
		// говорить об этом прямо (см. Notes — он показывается пользователю).
		{
			ID:   "gosuslugi",
			Name: "Госуслуги (RU)",
			// gu-st.ru — отдельный домен статики/инфраструктуры Госуслуг (найдено живым
			// тестом 2026-08-25: основной домен уходил напрямую верно, но браузер отдельно
			// резолвил gu-st.ru и его трафик всё равно шёл через туннель — сайт продолжал
			// видеть VPN, несмотря на включённое правило. Один непокрытый поддомен рушит
			// весь смысл DirectRoute для этого сайта).
			Domains:       []string{"gosuslugi.ru", "*.gosuslugi.ru", "esia.gosuslugi.ru", "gu-st.ru", "*.gu-st.ru"},
			DirectRoute:   true,
			PreferCountry: "RU",
			Notes: "Идёт напрямую, в обход VPN — сайт видит ваш настоящий IP. " +
				"Именно это и нужно: Госуслуги отказываются работать через VPN.",
			Enabled: false, // opt-in: включение раскрывает реальный IP этим доменам
			Builtin: true,
		},
		{
			ID:            "sberbank",
			Name:          "Сбер Онлайн",
			Domains:       []string{"sberbank.ru", "*.sberbank.ru", "online.sberbank.ru"},
			DirectRoute:   true,
			PreferCountry: "RU",
			Notes: "Идёт напрямую, в обход VPN — банк видит ваш настоящий IP. " +
				"Антифрод банка блокирует вход через VPN.",
			Enabled: false, // opt-in: включение раскрывает реальный IP этим доменам
			Builtin: true,
		},
		{
			ID:            "tinkoff",
			Name:          "Т-Банк (Тинькофф)",
			Domains:       []string{"tinkoff.ru", "*.tinkoff.ru", "tbank.ru", "*.tbank.ru"},
			DirectRoute:   true,
			PreferCountry: "RU",
			Notes: "Идёт напрямую, в обход VPN — банк видит ваш настоящий IP. " +
				"Антифрод банка блокирует вход через VPN.",
			Enabled: false, // opt-in: включение раскрывает реальный IP этим доменам
			Builtin: true,
		},
		{
			ID:                 "chatgpt",
			Name:               "ChatGPT / OpenAI",
			Domains:            []string{"chat.openai.com", "*.openai.com"},
			RequireResidential: true,
			Notes:              "OpenAI блокирует ряд стран и многие VPN. Residential IP другой разрешённой страны.",
			Enabled:            true,
			Builtin:            true,
		},
	}
}
