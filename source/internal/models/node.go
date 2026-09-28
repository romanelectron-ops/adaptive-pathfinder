package models

import (
	"strings"
	"time"
)

// Константы режима подключения (ConnectionMode)
const (
	ModeVPN    = "vpn"
	ModeProxy  = "proxy"
	ModeHybrid = "hybrid"
)

// ─── W3 (ТЗ v1.5 §2): двухклассовое избранное ────────────────────────────────────────────
//
// Константы класса избранного (NodeRef.Origin). "user" ставит звезда пользователя
// (Engine.AddFavorite) — без потолка, снимается ТОЛЬКО пользователем. "system" ставит сборка
// каталога по кнопке (Engine.AddSystemFavorite, вызывается из runNodeCheck на прошедшей пробе) —
// потолок SystemFavoriteCap (internal/engine/nodes_retention.go), авто-вытеснение при провале
// пробы на СЛЕДУЮЩЕЙ ручной сборке. См. EffectiveOrigin() — миграционная защита для записей,
// сохранённых ДО появления этого поля.
const (
	OriginUser   = "user"
	OriginSystem = "system"
)

// Константы AppConfig.CatalogReviewInterval — см. комментарий у самого поля.
const (
	ReviewIntervalEachScan = "each_scan"
	ReviewIntervalDaily    = "daily"
	ReviewIntervalWeekly   = "weekly"
	ReviewIntervalMonthly  = "monthly"
)

// PaidProviderEntry — запись платного провайдера VPN/Proxy.
// Поля должны соответствовать catalog.PaidProviderConfig.
type PaidProviderEntry struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Type            string `json:"type"` // "subscription", "api", "shadowsocks"
	URL             string `json:"url,omitempty"`
	Username        string `json:"username,omitempty"`
	Password        string `json:"password,omitempty"`
	Token           string `json:"token,omitempty"`
	SubscriptionURL string `json:"subscription_url,omitempty"`
	Enabled         bool   `json:"enabled"`
	InsecureTLS     bool   `json:"insecure_tls,omitempty"`
	LastFetched     int64  `json:"last_fetched,omitempty"`
}

// Protocol — тип протокола узла
type Protocol string

const (
	ProtoVLESS       Protocol = "vless"
	ProtoVMess       Protocol = "vmess"
	ProtoShadowsocks Protocol = "ss"
	ProtoTrojan      Protocol = "trojan"
	ProtoWireGuard   Protocol = "wireguard"
	ProtoAmneziaWG   Protocol = "amneziawg"
	ProtoTor         Protocol = "tor"
)

// NodeStatus — текущее состояние узла
type NodeStatus string

const (
	StatusUnknown   NodeStatus = "unknown"
	StatusOK        NodeStatus = "ok"
	StatusSlow      NodeStatus = "slow"
	StatusBlocked   NodeStatus = "blocked"
	StatusBlacklist NodeStatus = "blacklist"
)

// TLSConfig — параметры TLS/Reality
type TLSConfig struct {
	Enabled    bool           `json:"enabled"`
	ServerName string         `json:"server_name,omitempty"`
	Reality    *RealityConfig `json:"reality,omitempty"`
	Insecure   bool           `json:"insecure,omitempty"`
	// Fingerprint — uTLS-отпечаток из параметра `fp` ссылки (chrome, firefox, safari,
	// ios, android, edge, random...). Раньше параметр молча терялся при разборе ссылки, а
	// config_builder всегда подставлял "chrome" — узлы, чей сервер ждёт другой отпечаток
	// (частая практика у Reality-конфигов), не поднимались без единого внятного сообщения.
	// Пусто → builder оставляет прежний дефолт "chrome", поведение не меняется.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// RealityConfig — параметры протокола Reality
type RealityConfig struct {
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id"`
}

// TransportConfig — транспортный слой (ws, grpc, tcp)
type TransportConfig struct {
	Type string `json:"type"` // tcp, ws, grpc, http
	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"`
}

// Node — один прокси/VPN узел
type Node struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Protocol Protocol `json:"protocol"`
	Address  string   `json:"address"`
	Port     int      `json:"port"`
	UUID     string   `json:"uuid,omitempty"`
	Password string   `json:"password,omitempty"`
	Method   string   `json:"method,omitempty"` // для SS
	Flow     string   `json:"flow,omitempty"`   // для VLESS
	AltID    int      `json:"alt_id,omitempty"` // для VMess

	// WireGuard / AmneziaWG поля
	WGPrivateKey string `json:"wg_private_key,omitempty"` // приватный ключ WG
	WGPublicKey  string `json:"wg_public_key,omitempty"`  // публичный ключ сервера
	// WGLocalAddress — [TZ_TAILS_HARDENING_2026-08-31.md кластер B] адрес клиента ВНУТРИ
	// туннеля (CIDR, например "10.0.0.2/32") — назначается оператором WG-сервера, угадать
	// нельзя. Обязателен для sing-box WireGuardEndpointOptions.Address
	// (vendor/.../option/wireguard.go) — без него endpoint-конфигурация не соберётся.
	WGLocalAddress string `json:"wg_local_address,omitempty"`
	// WGReserved — необязательные 3 зарезервированных байта (некоторые генераторы
	// WG-ссылок/клиенты используют их как приём обхода отдельных сетевых фильтров) —
	// vendor WireGuardPeer.Reserved. Пусто = не задавать (обычный WG без этого приёма).
	WGReserved []uint8 `json:"wg_reserved,omitempty"`
	AWGJc      int     `json:"awg_jc,omitempty"`   // AmneziaWG: Junk count
	AWGJmin    int     `json:"awg_jmin,omitempty"` // AmneziaWG: Junk min size
	AWGJmax    int     `json:"awg_jmax,omitempty"` // AmneziaWG: Junk max size

	TLS       *TLSConfig       `json:"tls,omitempty"`
	Transport *TransportConfig `json:"transport,omitempty"`

	// Метрики (заполняются Checker-ом)
	Latency int64   `json:"latency_ms"`
	Jitter  int64   `json:"jitter_ms"`
	Loss    float64 `json:"loss_percent"`
	Speed   float64 `json:"speed_mbps"`
	Score   float64 `json:"score"`

	// Служебные поля
	Status           NodeStatus `json:"status"`
	LastChecked      time.Time  `json:"last_checked"`
	FailCount        int        `json:"fail_count"`
	SuccessCount     int        `json:"success_count"`
	BlacklistedUntil time.Time  `json:"blacklisted_until,omitempty"`
	Source           string     `json:"source"` // откуда взят узел
	AddedAt          time.Time  `json:"added_at"`

	// ExtraParams — нераспознанные query-параметры исходной ссылки (см. parser.parseVLESS),
	// сохранённые как есть. Общий механизм, не relay-специфичный — позволяет расширениям
	// (например, relay-режиму Вход-Выход, см. docs/TZ_APF_RELAY_v1.0.md §5) читать свои
	// параметры без изменения общего парсера ссылок, которым пользуются ВСЕ протоколы и
	// импорт подписок/каталога.
	ExtraParams map[string]string `json:"extra_params,omitempty"`

	// IsChainPartner — узел добавлен как партнёр цепочки Вход-Выход (ссылка получена от
	// роли «Выход», см. Engine.AddChainPartnerFromLink), а не как обычный публичный VPN-
	// узел. Единственный в своём роде — не взаимозаменяем ни с одним другим узлом в пуле,
	// поэтому исключается из обычного авто-выбора/пересканирования (getActiveCandidates) и
	// при сбое НЕ подменяется случайным публичным узлом (emergencySwitch повторяет попытку
	// подключения именно к нему). См. docs/PLAN_2026-08-28_stubs_and_realfunc.md §4.
	IsChainPartner bool `json:"is_chain_partner,omitempty"`

	// ── ТЗ v1.3 F1.2 (консилиум 2026-09-03, NL-1/ND-1): подтверждение РЕАЛЬНЫМ трафиком ──
	//
	// Всё выше (Latency/Score/Status/SuccessCount) пишет checker.CheckOne — TCP-рукопожатие,
	// которое проходит и мёртвый Reality-фронт, и CDN-edge, и узел с отозванным ключом. Поля
	// ниже пишет ТОЛЬКО движок по итогам HTTP-проверки через туннель (runPostConnectHealthCheck,
	// Watchdog, monitor) — единственное, что доказывает «узел реально пропускает трафик».
	// Времена — unix-секунды (int64), а не time.Time: `omitempty` на time.Time в encoding/json
	// не работает (нулевая структура сериализуется), и 4000 узлов кэша получили бы 3 лишних
	// поля каждый (верификатор V3, NEW-1). 0 = «никогда».
	LastVerifiedAt int64 `json:"last_verified_at,omitempty"` // последний успешный health-check через туннель
	VerifiedCount  int   `json:"verified_count,omitempty"`   // сколько раз канал подтверждён за всю историю
	// LastVerifiedLatencyMs — HTTP-замер (не TCP). ЧЕМ именно он получен, говорит
	// LastVerifiedVia: C-20 (ТЗ v1.4) — прежний комментарий «HTTP через туннель» был неточен и
	// прямо породил надпись «N мс через туннель» во всех трёх UI, хотя замер почти всегда идёт
	// через локальный SOCKS5 (проба №1 runPostConnectHealthCheck), а в режиме «Прокси» TUN нет
	// вовсе. «Через туннель» допустимо говорить только про VerifiedViaTUN.
	LastVerifiedLatencyMs int64  `json:"last_verified_latency_ms,omitempty"`
	LastVerifiedVia       string `json:"last_verified_via,omitempty"` // VerifiedViaSOCKS | VerifiedViaTUN
	LastVerifiedCountry   string `json:"last_verified_country,omitempty"`
	LastVerifiedExitIP    string `json:"last_verified_exit_ip,omitempty"`
	LastFailedAt          int64  `json:"last_failed_at,omitempty"`   // последний РЕАЛЬНЫЙ сбой (не TCP)
	LastFailReason        string `json:"last_fail_reason,omitempty"` // health_check | watchdog | monitor | connect_error
	FailStreak            int    `json:"fail_streak,omitempty"`      // подряд реальных сбоев; сбрасывается успешной верификацией
	TCPRTTMs              int64  `json:"tcp_rtt_ms,omitempty"`       // Stage 1 фильтра (F4): один dial, для tie-break, не для ранжирования
	// Управление пользователем (F3).
	UserBanned bool   `json:"user_banned,omitempty"` // ручной чёрный список — не истекает, не выбирается никогда
	UserNote   string `json:"user_note,omitempty"`   // произвольная метка/переименование
}

// ─── C-20 (ТЗ v1.4): чем получен замер подтверждения ─────────────────────────────────────

const (
	// VerifiedViaSOCKS — замер сделан через локальный SOCKS5 самого APF (проба №1
	// post-connect). Доказывает, что исходящий канал sing-box до узла жив, и НЕ доказывает,
	// что трафик сторонних приложений идёт через системный TUN. В режиме «Прокси» это
	// единственный возможный замер и он же — тот путь, которым ходят приложения.
	VerifiedViaSOCKS = "socks5"
	// VerifiedViaTUN — замер сделан прямой пробой мимо SOCKS (probeDirect), тем же путём, что
	// у браузера. Только про такую величину честно говорить «через туннель».
	VerifiedViaTUN = "tun"
)

// LatencyIsThroughTunnel — можно ли подписать LastVerifiedLatencyMs словами «через туннель».
func (n *Node) LatencyIsThroughTunnel() bool {
	return n != nil && n.LastVerifiedVia == VerifiedViaTUN
}

// IsUserOwned — узел «принадлежит пользователю»: добавлен вручную (Source=="manual") ИЛИ является
// партнёром цепочки Вход-Выход (IsChainPartner). N-7 (ТЗ APF v1.5, C8/O7): НЕ новое поле схемы, а
// helper над уже существующими маркерами — оба признака в узле есть (Source пишет AddNode*,
// engine.go:5118/5147/5315; IsChainPartner — AddChainPartnerFromLink). Такие узлы удерживаются в
// кэше при любой политике удержания (N-5) и не теряются при фильтрации на запись: они уникальны и
// невосстановимы из публичных источников.
func (n *Node) IsUserOwned() bool {
	return n != nil && (n.Source == "manual" || n.IsChainPartner)
}

// ─── C-21 (ТЗ v1.4): метка каталога против фактического выхода ───────────────────────────

// CatalogCountry — двухбуквенный код страны из МЕТКИ узла (Name вида "🇬🇧GB-82.38.31.179-0124").
// Это адрес ВХОДА по данным каталога/GeoIP, а не то, где узел выходит в интернет.
// "" — метка не содержит распознаваемого кода.
func (n *Node) CatalogCountry() string {
	if n == nil {
		return ""
	}
	r := []rune(n.Name)
	i := 0
	for i < len(r) && !(r[i] >= 'A' && r[i] <= 'Z') { // пропускаем флаг-эмодзи и пробелы
		i++
	}
	if i+1 >= len(r) {
		return ""
	}
	if !(r[i+1] >= 'A' && r[i+1] <= 'Z') {
		return ""
	}
	if i+2 < len(r) && r[i+2] >= 'A' && r[i+2] <= 'Z' {
		return "" // три буквы подряд — это не код страны, а слово («RELAY», «TOR»)
	}
	return string(r[i : i+2])
}

// ExitCountry — ФАКТИЧЕСКАЯ страна выхода, подтверждённая проверкой ("" — неизвестна).
func (n *Node) ExitCountry() string {
	if n == nil {
		return ""
	}
	return n.LastVerifiedCountry
}

// EffectiveCountry — страна, по которой честно сортировать и фильтровать: фактический выход,
// когда он известен, иначе метка каталога.
//
// Живой прогон K8-LIVE: узел подписан 🇬🇧GB, фактический выход — 193.29.139.147, Нидерланды.
// Пока сортировка шла по метке, выбор «страна выхода» не значил ничего.
func (n *Node) EffectiveCountry() string {
	if c := n.ExitCountry(); c != "" {
		return c
	}
	return n.CatalogCountry()
}

// countryCodeAliases — долг-7 (2026-09-21, честность «фактического выхода»): синонимы кодов
// стран, которые НЕ должны считаться расхождением выхода. Метка каталога берётся из ИМЕНИ узла
// (CatalogCountry) и часто неканонична, тогда как фактический выход (loc= из cdn-cgi/trace,
// LastVerifiedCountry) — всегда ISO-3166. Без нормализации честный выход кричал ложным ⚠
// «фактический выход отличается». Список короткий и обоснованный — каждый левый код это реальный
// НЕ-ISO ярлык, а правый его ISO-эквивалент (одна и та же страна):
//
//	UK → GB — «UK» зарезервирован ISO 3166 как исключительное обозначение GB; в именах VPN-узлов
//	          встречается сплошь и рядом («🇬🇧UK London») — самый частый источник ложного ⚠.
//	EN → GB — «England» в именах узлов; страны с ISO-кодом «EN» не существует.
//	EL → GR — торговый/EU-код Греции против ISO GR (встречается в EU-агрегаторах).
var countryCodeAliases = map[string]string{
	"UK": "GB",
	"EN": "GB",
	"EL": "GR",
}

// normalizeCountryCode приводит код страны к ISO-3166 alpha-2 (верхний регистр + разрешение
// известных не-ISO псевдонимов), чтобы сравнение метки каталога с фактическим выходом было честным.
func normalizeCountryCode(code string) string {
	c := strings.ToUpper(strings.TrimSpace(code))
	if canon, ok := countryCodeAliases[c]; ok {
		return canon
	}
	return c
}

// CountryMismatch — метка каталога расходится с фактическим выходом (обе величины известны).
// Долг-7: сравниваем ПОСЛЕ нормализации псевдонимов (UK≡GB и т.п.), иначе честный выход давал
// ложный ⚠ «фактический выход отличается» и обесценивал сам сигнал расхождения.
func (n *Node) CountryMismatch() bool {
	exit := normalizeCountryCode(n.ExitCountry())
	cat := normalizeCountryCode(n.CatalogCountry())
	return exit != "" && cat != "" && exit != cat
}

// ─── C-18 / V13-4 (ТЗ v1.4): устаревание подтверждения ───────────────────────────────────

// VerifyStaleAfter — через сколько подтверждение трафиком считается устаревшим и требует
// переподтверждения. Переподтверждение делается ПО ФАКТУ следующего подключения к узлу, а не
// отдельным подключением и не таймером: иначе фоновая проверка рвала бы сессию пользователя.
const VerifyStaleAfter = 24 * time.Hour

// VerifyStale — узел когда-то подтверждался трафиком, но подтверждение старше VerifyStaleAfter.
func (n *Node) VerifyStale(nowUnix int64) bool {
	if n == nil || !n.IsProven() {
		return false
	}
	return nowUnix-n.LastVerifiedAt > int64(VerifyStaleAfter.Seconds())
}

// IsBlacklisted — проверяет, находится ли узел в чёрном списке
func (n *Node) IsBlacklisted() bool {
	return time.Now().Before(n.BlacklistedUntil)
}

// IsProven — узел хотя бы раз подтвердил реальный канал и не забанен пользователем (F1.2).
func (n *Node) IsProven() bool {
	return n.VerifiedCount > 0 && n.LastVerifiedAt > 0 && !n.UserBanned
}

// IsUnchecked — узла ещё ни разу не касалась ни TCP-проверка, ни верификация: единственный
// класс узлов, которому F1.5 запрещает участвовать в выборе (только через обход Stage 1).
func (n *Node) IsUnchecked() bool {
	return n.LastChecked.IsZero() && n.Status == "" && n.LastVerifiedAt == 0 && n.LastFailedAt == 0
}

// LastOutcomeIsFailure — последнее РЕАЛЬНОЕ событие по узлу — сбой (последний сбой позже
// последнего подтверждения). Такой узел опускается в конец proven-списка, а закреплённый —
// пропускается с логом (F2 I3/I5).
func (n *Node) LastOutcomeIsFailure() bool {
	return n.LastFailedAt > 0 && n.LastFailedAt >= n.LastVerifiedAt
}

// ProvenFreshness — вес свежести подтверждения в [0,1]: 1.0 при возрасте <1 ч, ≈0.5 при 24 ч,
// ≈0.1 при 7 сутках (экспонента с полураспадом ~24 ч), 0 — если не подтверждался. now — unix.
func (n *Node) ProvenFreshness(nowUnix int64) float64 {
	if n.LastVerifiedAt <= 0 || nowUnix <= n.LastVerifiedAt {
		if n.LastVerifiedAt > 0 {
			return 1.0
		}
		return 0
	}
	ageH := float64(nowUnix-n.LastVerifiedAt) / 3600.0
	if ageH < 1 {
		return 1.0
	}
	// 0.5^(ageH/24): 24 ч → 0.5, 72 ч → 0.125, 168 ч (7 сут) → раскручивается до ~0.008, но
	// документированный контракт функции обещает «≈0.1 при 7 сутках» — округляем снизу до 0.1
	// ВКЛЮЧИТЕЛЬНО на границе (<=168, не <168). Найдено при написании теста на границу 7 суток
	// 2026-09-05: со строгим "<" узел, подтверждённый РОВНО 168ч назад (round-trip через unix-
	// секунды, что для периодических вотчдогов не редкость), получал 0.0078 — на порядок ниже
	// обещанного контрактом значения, и хуже, чем узел, подтверждённый 167ч назад (0.1).
	// Свежесть не должна падать РЕЗЧЕ на границе, чем внутри интервала.
	f := 1.0
	for h := ageH; h >= 24; h -= 24 {
		f *= 0.5
	}
	if ageH <= 168 && f < 0.1 {
		f = 0.1
	}
	return f
}

// Значки проверенности узла для списков во ВСЕХ трёх UI (общий контракт, 2026-09-06).
// Вычисляются здесь один раз, а не тремя разными реализациями в Web/Wails/Kotlin: до этого
// Android и Wails показывали булеву галочку «proven», Web не показывал ничего вовсе, и ни
// один UI не различал «трафик проходил час назад» и «трафик проходил неделю назад».
const (
	BadgeProvenFresh  = "proven_fresh"  // трафик реально проходил, подтверждение свежее
	BadgeProvenStale  = "proven_stale"  // трафик проходил, но подтверждение давнее
	BadgeProvenFailed = "proven_failed" // раньше пропускал трафик, последний исход — сбой
	BadgeTCPAlive     = "tcp_alive"     // отвечает на TCP, трафик через него не проверялся
	BadgeDead         = "dead"          // не отвечает / заблокирован
	BadgeUnchecked    = "unchecked"     // не касалась ни одна проверка
)

// provenFreshThreshold — граница между «свежим» и «давним» подтверждением в терминах
// ProvenFreshness: 0.5 — это ровно возраст полураспада, то есть ~24 часа.
const provenFreshThreshold = 0.5

// VerifyBadge — какое из шести состояний проверенности показывать возле узла в списке.
//
// ВАЖНО про смысл, иначе значок будет прочитан неверно: «проверен трафиком» может быть ТОЛЬКО
// узел, через который движок реально подключался. Обычный обход пула (sweep/циклический поиск/
// runPoolScan) делает лишь TCP-дозвон и Verified*-полей не пишет вовсе — единственный их
// писатель recordNodeVerified вызывается из runPostConnectHealthCheck. Поэтому у подавляющего
// большинства узлов честный ответ — BadgeTCPAlive («порт отвечает, трафик не проверялся»), и
// это НЕ то же самое, что «трафика нет».
//
// Значок отвечает только за проверенность трафиком. Пин, избранное и пользовательский бан —
// отдельные маркеры, они не смешиваются сюда.
func (n *Node) VerifyBadge(nowUnix int64) string {
	if n == nil || n.IsUnchecked() {
		return BadgeUnchecked
	}
	if n.IsProven() {
		if n.LastOutcomeIsFailure() {
			return BadgeProvenFailed
		}
		if n.ProvenFreshness(nowUnix) >= provenFreshThreshold {
			return BadgeProvenFresh
		}
		return BadgeProvenStale
	}
	if n.Status == StatusOK || n.Status == StatusSlow {
		return BadgeTCPAlive
	}
	return BadgeDead
}

// AgeSeconds — возраст последней проверки в секундах
func (n *Node) AgeSeconds() float64 {
	if n.LastChecked.IsZero() {
		return 99999
	}
	return time.Since(n.LastChecked).Seconds()
}

// Chain — цепочка узлов (VPN → Proxy)
type Chain struct {
	Nodes []*Node `json:"nodes"`
	Score float64 `json:"score"`
}

// AppConfig — конфигурация приложения
type AppConfig struct {
	AutoConnect      bool     `json:"auto_connect"`
	CheckInterval    int      `json:"check_interval_sec"`
	MaxLatency       int      `json:"max_latency_ms"`
	EnableChain      bool     `json:"enable_chain"`
	EnableKillSwitch bool     `json:"enable_kill_switch"`
	DNSOverTLS       string   `json:"dns_over_tls"`
	BypassList       []string `json:"bypass_list"`
	ForceList        []string `json:"force_list"`

	// DisallowedApps — пакеты Android-приложений, которые НЕ заворачиваются в VPN на уровне
	// операционной системы (VpnService.Builder.addDisallowedApplication).
	//
	// Это принципиально другой механизм, чем bypass-домены (DirectRoute), и решает другую
	// задачу. DirectRoute — это policy-routing ВНУТРИ туннеля: пакет уже попал в TUN, и
	// sing-box решает отправить его напрямую. Для системы VPN при этом остаётся активным, и
	// приложение через ConnectivityManager.NetworkCapabilities видит TRANSPORT_VPN — из-за
	// чего Госуслуги и банковские приложения отказываются работать, даже когда их трафик
	// фактически идёт мимо туннеля (жалоба пользователя 2026-08-24).
	// addDisallowedApplication исключает приложение из VPN целиком: для него
	// getActiveNetwork() возвращает настоящую сеть без TRANSPORT_VPN.
	//
	// Честная граница: это НЕ делает VPN невидимым полностью. Интерфейс tun0 остаётся
	// виден через NetworkInterface.getNetworkInterfaces(), пакет APF виден PackageManager,
	// иконка VPN остаётся в статус-баре — скрыть это без root невозможно. Но конкретно
	// проверку «активен ли VPN на моей сети», которой пользуется подавляющее большинство
	// приложений, исключение снимает.
	//
	// Только Android. На Windows аналога нет (см. комментарий в APFVpnService.kt).
	DisallowedApps []string       `json:"disallowed_apps,omitempty"`
	Sources        []SourceConfig `json:"sources"`
	SingBoxPath    string         `json:"singbox_path"`
	ListenPort     int            `json:"listen_port"`
	WebUIPort      int            `json:"webui_port"`

	// Wizard настройки
	SetupDone    bool   `json:"setup_done"`
	UserCountry  string `json:"user_country"` // RU, BY, IR, CN...
	Mode         string `json:"mode"`         // "auto", "manual", "chain", "tor"
	SafetyFilter bool   `json:"safety_filter"`

	// Стабильность
	SwitchOnlyOnFail bool `json:"switch_only_on_fail"`
	MinUptimeSec     int  `json:"min_uptime_sec"`

	// NodeAutoSwitchEnabled — разрешить APF самому переключать узел при обнаруженном сбое
	// (Watchdog/emergencySwitch). По умолчанию true — сохраняет прежнее поведение для уже
	// существующих пользователей (LoadInto распаковывает JSON поверх DefaultConfig(), поле,
	// отсутствующее в старом config.json, останется true, а не обнулится).
	// Живой инцидент 2026-08-19: пользователь сообщил, что APF «начал переключаться по
	// узлам, а потом самостоятельно отключился» без возможности восстановиться без
	// переустановки — нужен способ отключить автопереключение целиком. НЕ путать с
	// AntiBlockAutoSwitch — тот управляет узким отдельным механизмом (переключение при
	// плохой IP-репутации через Anti-VPN-Block), этот — общим вотчдогом здоровья туннеля.
	NodeAutoSwitchEnabled bool `json:"node_auto_switch_enabled"`

	// CyclicNodeSearch — при автопереключении (см. NodeAutoSwitchEnabled) продолжать
	// круговой обход ВСЕГО пула узлов, если обычный выбор по Score исчерпан (нет узлов с
	// подтверждённым Score выше порога, либо выбранный узел не подключился), вместо того
	// чтобы сразу переходить на аварийные фаллбэк-туннели (Tor/Snowflake). По умолчанию
	// false — не меняет поведение существующих пользователей без явного включения.
	// Живой запрос пользователя 2026-08-19: «система, дойдя до конца списка узлов, должна
	// идти по второму кругу, а не останавливаться». Без этого тумблера тот же вотчдог мог
	// исчерпать все узлы с ненулевым Score и уйти в tryFallback(), даже когда в пуле ещё
	// остаются непроверенные/низкоскоровые узлы, которые никогда не пробовались.
	CyclicNodeSearch bool `json:"cyclic_node_search"`

	// NodeCheckTopN — ТЗ v1.7 (PROBE-DEPTH-SETTING), запрос владельца 09-14: «Собрать список
	// рабочих узлов» по умолчанию пробует реальным трафиком только top-30 узлов по TCP-рангу
	// (engine/node_check.go, defaultNodeCheckTopN) — владелец хочет находить БОЛЬШЕ
	// подтверждённых узлов и просит регулируемую глубину пробы прямо из «Параметры».
	// 0 = встроенный дефолт (30); иначе — сколько верхних по TCP-рангу узлов проверять
	// реальным трафиком при «Собрать список». DefaultConfig намеренно оставляет 0 — старые
	// config.json без этого поля продолжают получать ровно прежнее поведение (top-30).
	// Особое значение NodeCheckTopNAll (см. config_normalize.go) = режим «Все рабочие»:
	// пробовать ВЕСЬ пул без верхнего среза (запрос владельца 09-15).
	NodeCheckTopN int `json:"node_check_top_n"`

	// NodeRaceEnabled — ЭКСПЕРИМЕНТАЛЬНО, по умолчанию ВЫКЛЮЧЕНО. Подключаться сразу к
	// нескольким кандидатам и пропускать трафик через того, кто первым ответил (sing-box
	// outbound типа urltest, см. singbox.Builder.BuildRace).
	//
	// Почему выключено по умолчанию, хотя задумывалось как решение проблемы «из России узлы
	// не пробивают интернет» (ревью 2026-08-24 показало, что в нынешнем виде фича способна
	// сделать ХУЖЕ, поэтому включать её всем нельзя):
	//
	//  1. urltest судит кандидатов слабее, чем мы сами. Он проверяет только то, что запрос
	//     не завершился ошибкой транспорта, и НЕ смотрит HTTP-статус (vendor,
	//     common/urltest). Узел, отвечающий на всё ошибкой уровня приложения, проходит его
	//     как «здоровый и быстрый» и выигрывает у честных — то есть ровно тот случай, ради
	//     которого фича делалась, ею не закрывается.
	//  2. Отказ приписывается не тому узлу. Трафик ведёт победитель группы, а
	//     markNodeFailed/ActiveNode оперируют инициатором подключения: здоровые узлы уходят
	//     в чёрный список, а негодный победитель туда не попадает никогда.
	//
	// Чтобы включать по умолчанию, нужно сперва отбирать кандидатов собственной проверкой
	// канала и знать реальный выбор группы (Clash API), — этого пока нет. До тех пор
	// основным решением служат быстрый отказ от мёртвого узла и честное состояние «ищу
	// рабочий узел» вместо преждевременного «подключено».
	NodeRaceEnabled bool `json:"node_race_enabled"`

	// Уведомления
	NotifyOnSwitch bool `json:"notify_on_switch"`
	NotifyOnFail   bool `json:"notify_on_fail"`

	// ── Фаза 5: Защита устройства ────────────────────────────────────────────

	// BlockIPv6Leak — блокировать IPv6-трафик мимо VPN.
	// vpn-specialist: предотвращает утечку реального IP через IPv6 канал.
	BlockIPv6Leak bool `json:"block_ipv6_leak"`

	// BlockWebRTC — блокировать STUN-серверы для предотвращения WebRTC-утечек.
	// bypass-engineer: браузер не сможет раскрыть реальный IP через WebRTC.
	BlockWebRTC bool `json:"block_webrtc"`

	// EncryptStorage — шифровать nodes_cache.json мастер-паролем.
	// AES-256-GCM + PBKDF2 (600_000 итераций).
	EncryptStorage bool `json:"encrypt_storage"`

	// EmergencyHotkey — горячая клавиша аварийного удаления.
	// Формат: "ctrl+shift+F12"
	EmergencyHotkey string `json:"emergency_hotkey"`

	// DNSLeakTestInterval — интервал авто-проверки DNS-утечки в секундах.
	// 0 = отключить авто-проверку.
	DNSLeakTestInterval int `json:"dns_leak_test_interval"`

	// ── Фаза 6: DPI обход ────────────────────────────────────────────────────

	// TrafficPaddingEnabled — включить Traffic Padding (jitter).
	TrafficPaddingEnabled bool `json:"traffic_padding_enabled"`

	// TrafficPaddingAggressive — агрессивный режим Padding (больше jitter).
	TrafficPaddingAggressive bool `json:"traffic_padding_aggressive"`

	// CDNWorkerDomain — домен Cloudflare Worker для CDN Fronting.
	// Пустая строка = CDN Fronting выключен.
	CDNWorkerDomain string `json:"cdn_worker_domain"`

	// ShadowTLSEnabled — включить ShadowTLS v3.
	ShadowTLSEnabled bool `json:"shadowtls_enabled"`

	// ShadowTLSSNI — SNI хост для ShadowTLS handshake.
	ShadowTLSSNI string `json:"shadowtls_sni"`

	// ShadowTLSPassword — пароль HMAC для ShadowTLS v3.
	ShadowTLSPassword string `json:"shadowtls_password"`

	// ShadowTLSServerAddr — адрес РЕАЛЬНОГО сервера ShadowTLS (host:port), куда физически
	// идёт TCP+TLS соединение. Обязателен при ShadowTLSEnabled: без него клиенту физически
	// некуда подключаться — ShadowTLSSNI описывает только маскировку (что видит DPI), а не
	// то, куда реально уходит трафик.
	//
	// P1-1 (аудит 2026-09-01): поле раньше отсутствовало — движок собирал ShadowTLS-
	// конфигурацию, пытаясь дозвониться до самого маскировочного SNI-хоста (см.
	// dpi.ShadowTLSConfig.ServerAddr, internal/dpi/shadow_tls.go).
	ShadowTLSServerAddr string `json:"shadowtls_server_addr"`

	// MultiHopEnabled — P2.2 (docs/TZ_APF_ROADMAP_v1.2.md): когда цепочка всё равно строится
	// (EnableChain=true, либо автоматическая эскалация при глубокой блокировке —
	// tryFallback L1), выбирать узлы через MultiHopSelector (протокол-разнообразная выборка
	// entry/middle/exit — internal/dpi/multihop.go), а не наивный buildBestChain (просто два
	// узла с максимальным Score). Не отдельный режим подключения — уточнение уже
	// существующего EnableChain, поэтому не дублирует его семантику.
	MultiHopEnabled bool `json:"multihop_enabled"`

	// MultiHopCount — число хопов при MultiHopEnabled: 2 или 3. Другие значения
	// откатываются на 2 (buildMultiHopChain).
	MultiHopCount int `json:"multihop_count"`

	// StickySessionPolicy — политика Sticky Session: "sticky", "free", "timed".
	StickySessionPolicy string `json:"sticky_session_policy"`

	// AdBlockProfile — профиль блокировки рекламы: "disabled", "light", "standard", "strict".
	// Изменяется через /api/adblock/profile.
	AdBlockProfile string `json:"adblock_profile"`

	// AdBlockAllowlist — домены, которые AdBlock не блокирует, даже если они есть в блок-листе.
	// Изменяется через /api/adblock/allowlist.
	//
	// P1-6 (аудит 2026-09-01): раньше белый список жил ТОЛЬКО в памяти блокировщика и не
	// сохранялся никуда. Профиль рядом сохранялся, поэтому после перезапуска блокировка
	// возвращалась в полном объёме, а все исключения к ней — нет. Для пользователя это
	// выглядело как самопроизвольная поломка сайтов, которые он однажды уже починил.
	AdBlockAllowlist []string `json:"adblock_allowlist,omitempty"`

	// ConnectionMode — режим подключения: ModeVPN, ModeProxy, ModeHybrid.
	ConnectionMode string `json:"connection_mode"`

	// SetSystemProxy — автоматически выставлять системный HTTP-прокси.
	SetSystemProxy bool `json:"set_system_proxy"`

	// SelectionMode — алгоритм выбора узла: "auto", "manual", "balanced".
	SelectionMode string `json:"selection_mode"`

	// PaidProviders — список платных провайдеров.
	PaidProviders []PaidProviderEntry `json:"paid_providers,omitempty"`

	// ── Sprint S6: Anti-VPN-Block ─────────────────────────────────────────────

	// AntiBlockEnabled — включить проверку IP-репутации узлов.
	// При включении APF проверяет является ли IP узла residential или datacenter.
	// Датацентровые IP блокируются стриминговыми сервисами (Netflix, Disney+) и банками.
	AntiBlockEnabled bool `json:"anti_block_enabled"`

	// AntiBlockResidentialOnly — использовать только residential IP.
	// При включении APF никогда не подключится через датацентровый IP.
	// Может уменьшить пул доступных узлов.
	AntiBlockResidentialOnly bool `json:"anti_block_residential_only"`

	// AntiBlockAutoSwitch — автопереключение при плохой репутации текущего IP.
	// APF проверит IP после подключения и переключится если он datacenter.
	AntiBlockAutoSwitch bool `json:"anti_block_auto_switch"`

	// AntiBlockAPIKey — опциональный ключ proxycheck.io для увеличения лимита запросов.
	// Без ключа: 1000 запросов/день бесплатно. С ключом — больше.
	AntiBlockAPIKey string `json:"anti_block_api_key,omitempty"`

	// ── Relay-посредник для Вход-Выход (docs/TZ_APF_RELAY_v1.0.md) ──────────────────────────

	// RelayServerAddr — адрес relay-сервера ("host:port") для роли «Выход» ЭТОГО устройства:
	// используется как запасной путь, когда Reachability.Detect() не подтвердила прямую
	// доступность (UPnP/статический IP/IPv6). Пусто — relay-fallback выключен, прежнее
	// поведение (только прямые пути). См. TZ §1, §5.
	RelayServerAddr string `json:"relay_server_addr,omitempty"`

	// RelayServerFingerprint — hex(sha256(DER-сертификата)) TLS-сертификата relay-сервера
	// (TZ_RELAY_HARDENING_2026-08-29.md кластер B, internal/relay/tunnel_tls.go) — оператор
	// relay показывает это значение один раз при первом запуске apf-relay, владелец роли
	// «Выход» вводит его сюда вместе с RelayServerAddr. Обязателен, если RelayServerAddr
	// задан — pinned-fingerprint TLS без него не работает (ExitClient откажет fail-closed).
	RelayServerFingerprint string `json:"relay_server_fingerprint,omitempty"`

	// MaxConnectedClients — лимит одновременных «Входов» для роли «Выход» на этом
	// устройстве (TZ §10). 0 = использовать дефолт по платформе (Android 2 / ПК 5 /
	// выделенный сервер 20), а НЕ «без ограничений» — безлимит должен быть осознанным явным
	// выбором пользователя, не последствием забытой настройки.
	MaxConnectedClients int `json:"max_connected_clients,omitempty"`

	// ServerRoleWizardCompleted — пройден ли мастер настройки роли «Выход» хотя бы раз
	// (TZ §11.1). false/не задано → кнопка «Роль Выход» открывает мастер с начала; true →
	// открывает экран статуса напрямую, без повторного прохождения шагов проверки.
	ServerRoleWizardCompleted bool `json:"server_role_wizard_completed,omitempty"`

	// LastActiveNodeID — ID узла, который последним подтвердил РЕАЛЬНО рабочий канал
	// (Verified=true, см. ConnectionState) перед отключением/выходом из приложения.
	// «Плавающий приоритет» (запрос пользователя 2026-08-28, docs/PLAN_2026-08-28_
	// stubs_and_realfunc.md §3): при следующем ScanAndConnect этот узел пробуется ПЕРВЫМ,
	// в обход ожидания полного скана пула — если он всё ещё жив, пользователь получает
	// соединение за секунды, а не за 25-30с полного сканирования. Пусто — обычное
	// поведение (полный скан с самого начала), как раньше.
	LastActiveNodeID string `json:"last_active_node_id,omitempty"`

	// ТЗ v1.3 F2 (консилиум 2026-09-03, R4/PIN-1…11): закрепление и избранное живут в
	// config.json, а не только в памяти движка — переживают перезапуск и handoff службе.
	// Раньше pinnedNodeID существовал лишь в Engine: перезапуск, «Сменить сервер» и
	// LastActiveNodeID молча снимали/обходили выбор пользователя («сбрасывается избранный»).
	// NodeRef хранит и параметры подключения: ID узла пересчитывается при миграции схемы
	// (loadNodes), и ссылку можно переразрешить по protocol/address/port. Единственный
	// писатель — Pin/Unpin/AddFavorite/RemoveFavorite движка; PatchConfig эти ключи отвергает.
	PinnedNode *NodeRef  `json:"pinned_node,omitempty"`
	Favorites  []NodeRef `json:"favorites,omitempty"`

	// CatalogReviewInterval — W3 (ТЗ v1.5 §5): ГЕЙТ ДАВНОСТИ для авто-вытеснения СИСТЕМНОГО
	// избранного (см. NodeRef.Origin/OriginSystem), а НЕ триггер автозапуска сборки каталога —
	// сборка идёт ТОЛЬКО по кнопке пользователя (owner-декрет консилиума
	// TZ_v1.5_NODE_CATALOG_2026-09-14: никакого фонового сканирования). Смысл: системный
	// фаворит, проваливший пробу на очередной РУЧНОЙ сборке, вытесняется из избранного, только
	// если с его последнего подтверждения трафиком (LastVerifiedAt) прошло больше этого
	// интервала — "each_scan" означает "сразу же, без отсрочки". Одно из
	// models.ReviewIntervalEachScan/Daily/Weekly/Monthly, по умолчанию ReviewIntervalEachScan
	// (см. DefaultConfig). Валидация значения — Engine.SetCatalogReviewInterval; чтение —
	// Engine.CatalogReviewInterval (обе с защитным откатом на each_scan при пустом/неизвестном
	// значении, так что руками отредактированный/устаревший config.json не может тут ничего
	// сломать).
	CatalogReviewInterval string `json:"catalog_review_interval,omitempty"`
}

// NodeRef — устойчивая ссылка на узел (F2): ID плюс параметры подключения для
// переразрешения, если ID изменился (миграция схемы ID) или узел был перезалит подпиской.
type NodeRef struct {
	ID       string   `json:"id"`
	Protocol Protocol `json:"protocol,omitempty"`
	Address  string   `json:"address,omitempty"`
	Port     int      `json:"port,omitempty"`
	Name     string   `json:"name,omitempty"`

	// Origin — W3 (ТЗ v1.5 §2): класс ЭТОЙ записи, когда ссылка используется внутри
	// AppConfig.Favorites (OriginUser | OriginSystem — см. константы выше). Не используется на
	// PinnedNode — закреп не двухклассовый. "" — запись, сохранённая ДО появления этого поля,
	// ЛИБО не заполненное явно поле литерала в коде: ВСЕГДА читать через EffectiveOrigin(), а
	// не напрямую — data-loss safeguard: пустое значение обязано трактоваться как OriginUser,
	// иначе избранное, добавленное до W3, попало бы под потолок/авто-вытеснение системного
	// класса и терялось бы молча при первой же ручной сборке каталога.
	Origin string `json:"origin,omitempty"`
}

// EffectiveOrigin — класс ссылки с миграционной защитой (W3, safeguard #1 консилиума
// TZ_v1.5_NODE_CATALOG_2026-09-14): ЛЮБОЕ значение, кроме буквального OriginSystem
// (в частности "" — записи до W3, и любой нераспознанный мусор), трактуется как OriginUser.
// Единственный корректный способ читать класс NodeRef — через этот метод, не через поле Origin
// напрямую.
func (r NodeRef) EffectiveOrigin() string {
	if r.Origin == OriginSystem {
		return OriginSystem
	}
	return OriginUser
}

// IsSystemOrigin — сокращение для EffectiveOrigin() == OriginSystem.
func (r NodeRef) IsSystemOrigin() bool { return r.EffectiveOrigin() == OriginSystem }

// NodeRefOf — ссылка на узел из его текущих параметров.
func NodeRefOf(n *Node) NodeRef {
	if n == nil {
		return NodeRef{}
	}
	return NodeRef{ID: n.ID, Protocol: n.Protocol, Address: n.Address, Port: n.Port, Name: n.Name}
}

// Matches — узел соответствует ссылке: по ID либо (если ID устарел) по адресу/порту/протоколу.
func (r NodeRef) Matches(n *Node) bool {
	if n == nil {
		return false
	}
	if r.ID != "" && n.ID == r.ID {
		return true
	}
	return r.Address != "" && n.Address == r.Address && n.Port == r.Port &&
		(r.Protocol == "" || n.Protocol == r.Protocol)
}

// NodePatch — правка узла пользователем (ТЗ v1.3 F3): nil — поле не трогать.
type NodePatch struct {
	Name     *string `json:"name,omitempty"`
	UserNote *string `json:"user_note,omitempty"`
}

// SourceConfig — источник узлов
type SourceConfig struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	URL                 string `json:"url"`
	Type                string `json:"type"` // subscription, tor, manual
	Enabled             bool   `json:"enabled"`
	AutoUpdate          bool   `json:"auto_update"`
	UpdateIntervalHours int    `json:"update_interval_hours"`
	// LastUpdatedAt — unix-время последней успешной загрузки источника (ТЗ v1.3 F4 Stage 0).
	// Раньше время жило только в памяти sources.Manager, который движок пересоздавал на КАЖДЫЙ
	// скан — интервал UpdateIntervalHours никогда не соблюдался, все подписки перекачивались
	// перед каждым подключением (ND-3: секунды-минуты ожидания до первой проверки узла).
	LastUpdatedAt int64 `json:"last_updated_at,omitempty"`
}

// Состояния проверки канала для UI (общий контракт, 2026-09-06). Смысл разделения: туннель
// поднят (Connected) и туннель реально пропускает трафик (Verified) — разные вещи, и между
// ними есть третье состояние «проверка ещё идёт» и четвёртое «проверка провалилась, но
// туннель не снят». Пока их не различали, все UI показывали зелёное «Подключено» во всех
// четырёх случаях.
const (
	VerifyIdle     = "idle"     // не подключено
	VerifyChecking = "checking" // туннель поднят, проверка канала идёт, провала ещё не было
	VerifyVerified = "verified" // канал подтверждён HTTP-проверкой через туннель
	VerifyFailed   = "failed"   // туннель поднят, но канал признан неработающим
)

// ConnectionState — текущее состояние соединения
type ConnectionState struct {
	Connected bool `json:"connected"`
	// Verified — true только после того, как runPostConnectHealthCheck подтвердил, что
	// исходящий канал узла реально пропускает трафик (не просто открыт сокет sing-box).
	// Connected становится true сразу после старта sing-box — задолго до этой проверки;
	// UI должен показывать "подключено" только когда Verified тоже true, а до этого —
	// отдельное состояние "ищу рабочий узел" (см. apf-russia-nodes-no-internet в памяти
	// проекта: пользователь судил о провале и переподключался раньше, чем срабатывал
	// автовыбор рабочего узла — из-за этого разрыва Connected/реальной работоспособности).
	Verified bool `json:"verified"`
	// VerifyState — то же самое, но с различением «ещё проверяю» и «проверка провалилась»
	// (константы Verify* ниже). Введено 2026-09-06 вместе с диагностикой жалобы «пишет ВПН
	// подключен, а зайти на сайт не могу»: голого bool не хватало ни одному UI. Android-экран
	// из-за этого вычислял состояние разбором ПОДСТРОКИ русского текста сообщения
	// (MainActivity: message.contains("не подтверждён")) — любая переформулировка молча ломала
	// статус. Verified оставлен для обратной совместимости и тождественен
	// VerifyState == VerifyVerified.
	VerifyState string    `json:"verify_state,omitempty"`
	ActiveNode  *Node     `json:"active_node,omitempty"`
	ActiveChain *Chain    `json:"active_chain,omitempty"`
	Mode        string    `json:"mode"` // direct, vpn, chain, tor
	Since       time.Time `json:"since,omitempty"`
	BytesSent   int64     `json:"bytes_sent"`
	BytesRecv   int64     `json:"bytes_recv"`

	// Фаза 5: статус защит
	IPv6Blocked   bool `json:"ipv6_blocked"`
	WebRTCBlocked bool `json:"webrtc_blocked"`

	// FR-4: ID закреплённого пользователем узла ("" — не закреплён).
	PinnedNodeID string `json:"pinned_node_id,omitempty"`
	// ТЗ v1.3 F2 I3: статус закреплённого узла — active (подключены к нему) | standby (ждёт
	// следующего события выбора) | unreachable (пропущен: свежий сбой/бан/чёрный список/нет в
	// пуле) | suppressed (подавлен после «Сменить сервер» на recentFailureTTL) | missing (не
	// найден при загрузке). "" — не закреплён. Каждый пропуск pin виден здесь и в логе.
	PinnedStatus string `json:"pinned_status,omitempty"`
	// F2: ID избранных узлов — для маркеров ⭐ в списках всех трёх UI.
	FavoriteIDs []string `json:"favorite_ids,omitempty"`

	// SwitchNotice — краткое объяснение результата ПОСЛЕДНЕГО ручного «Сменить сервер»
	// (C-15, ТЗ v1.4). "" — объяснять нечего. Непустая строка означает, что серия попыток
	// исчерпана и пользователь остался на прежнем узле: раньше движок в этой ситуации молчал,
	// а UI показывал прежний сервер как ни в чём не бывало (живой прогон K8-LIVE D3, семь
	// нажатий подряд). Показ — за UI-лотами.
	SwitchNotice string `json:"switch_notice,omitempty"`

	// SecretsWarning — видимое человеку предупреждение о том, что часть секретов на диске не
	// расшифровывается (перенос профиля на другую машину, пересозданная учётная запись).
	// "" — всё в порядке. Запрос лота L1b-SEC2 (S-5): пакеты crypto/config не вправе править
	// engine.go и models, поэтому поле заведено здесь, а заполняет его Engine.GetState из
	// Engine.SecretsWarning(). Показ — за UI-лотами.
	SecretsWarning string `json:"secrets_warning,omitempty"`

	// LastPersistError — причина, по которой пул узлов НЕ сохранён на диск ("" — сохранён).
	// C-4 (ТЗ v1.4): saveNodes стал fail-closed (K2-E П11), и добавленные пользователем узлы
	// молча не переживали перезапуск. Движок обязан перестать молчать; показ — за UI-лотами
	// (U-17). Дублирует GetDiagnostics()["last_persist_error"] для тех UI, что читают только
	// состояние (запрос лота L1-SEC).
	LastPersistError string `json:"last_persist_error,omitempty"`
}

// CheckOutcome — исход проверки узла (ТЗ v1.3 F1.1, контракт B1 с тремя исходами).
//
// Раньше исходов было два (Success true/false), и отмена контекста (Disconnect/Restart во
// время скана) проваливалась в тот же «false» → markFail для КАЖДОГО ещё не проверенного узла
// батча, включая те, что только ждали семафора (консилиум 2026-09-03, BB-1/ND-8: три отмены
// подряд = бан всего батча на час). Отмена — это отсутствие информации об узле, не отказ узла.
type CheckOutcome string

const (
	// OutcomeOK — узел ответил, метрики обновлены.
	OutcomeOK CheckOutcome = "ok"
	// OutcomeFail — узел проверен и не ответил (markFail применён).
	OutcomeFail CheckOutcome = "fail"
	// OutcomeNotChecked — проверка не состоялась (контекст отменён до/во время пробы);
	// узел НЕ мутировался — ни Score, ни Status, ни счётчики, ни LastChecked.
	OutcomeNotChecked CheckOutcome = "not_checked"
)

// CheckResult — результат проверки узла
type CheckResult struct {
	Node *Node
	// Outcome — трёхзначный исход (см. CheckOutcome). Success сохранён для совместимости:
	// Success == (Outcome == OutcomeOK).
	Outcome CheckOutcome
	Success bool
	Latency int64
	Jitter  int64
	Loss    float64
	Error   string
}

// DefaultConfig — конфигурация по умолчанию
func DefaultConfig() *AppConfig {
	return &AppConfig{
		AutoConnect:      true,
		CheckInterval:    30,
		MaxLatency:       3000,
		EnableChain:      false,
		EnableKillSwitch: true,
		DNSOverTLS:       "tls://1.1.1.1",
		ListenPort:       10808,
		WebUIPort:        9090,
		BypassList: []string{
			"localhost", "127.0.0.1", "192.168.0.0/16", "10.0.0.0/8",
		},
		Sources: []SourceConfig{
			{
				ID:                  "v2ray-aggregator",
				Name:                "V2RayAggregator",
				URL:                 "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge_base64.txt",
				Type:                "subscription",
				Enabled:             true,
				AutoUpdate:          true,
				UpdateIntervalHours: 6,
			},
			{
				ID:                  "freefq",
				Name:                "freefq/free",
				URL:                 "https://raw.githubusercontent.com/freefq/free/master/v2",
				Type:                "subscription",
				Enabled:             true,
				AutoUpdate:          true,
				UpdateIntervalHours: 12,
			},
			{
				ID:                  "nomore-walls",
				Name:                "NoMoreWalls",
				URL:                 "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.yml",
				Type:                "subscription",
				Enabled:             true,
				AutoUpdate:          true,
				UpdateIntervalHours: 8,
			},
			// К2-E П7(в) (свод C трек 1 №7; B3 #3, F1). Здесь стоял фиктивный источник
			// {ID:"tor-snowflake", Type:"tor", URL:""} — удалён. Он не мог дать ни одного
			// пригодного узла: sources.fetchTorBridges создавала заглушку без адреса и порта,
			// которую отвергает ValidateNode (validate.go, NL-10). Зато Manager.FetchAll
			// помечала его успешно обновлённым при КАЖДОМ обновлении источников (обработчик
			// всегда возвращал err=nil) и тем запускала фоновую перезапись config.json — из-за
			// чего плавали тесты пакета web (LOT-F1, см. newTestServer в web/server_test.go).
			// Разбор ответа брокера мостов починен отдельно (П8), но источник остаётся
			// выключенным по умолчанию: мосты Tor полезны только вместе с бинарником tor,
			// которого нет ни в стандартной установке, ни на Android.
			//
			// Живой запрос пользователя 2026-08-28: пополнить пул узлами из этих каналов —
			// БЕЗ параметра ?before= (пагинация к конкретному старому посту), чтобы источник
			// каждый раз подтягивал САМЫЕ СВЕЖИЕ ссылки, а не застывший снимок на день
			// добавления (см. internal/sources/sources.go, fetchTelegramChannel).
			{
				ID:                  "tg-free4allvpn",
				Name:                "Telegram: free4allVPN",
				URL:                 "https://t.me/s/free4allVPN",
				Type:                "telegram",
				Enabled:             true,
				AutoUpdate:          true,
				UpdateIntervalHours: 3,
			},
			{
				ID:                  "tg-vlesskeys",
				Name:                "Telegram: vlesskeys",
				URL:                 "https://t.me/s/vlesskeys",
				Type:                "telegram",
				Enabled:             true,
				AutoUpdate:          true,
				UpdateIntervalHours: 3,
			},
		},
		SingBoxPath:           "./bin/sing-box",
		SetupDone:             false,
		Mode:                  "auto",
		SafetyFilter:          true,
		SwitchOnlyOnFail:      true,
		MinUptimeSec:          120,
		NodeAutoSwitchEnabled: true,
		NodeRaceEnabled:       false, // экспериментально — см. комментарий у поля
		CyclicNodeSearch:      false,
		NotifyOnSwitch:        false,
		NotifyOnFail:          true,

		// Фаза 5: по умолчанию включаем основные защиты
		BlockIPv6Leak:       true,
		BlockWebRTC:         true,
		EncryptStorage:      false, // требует установки мастер-пароля
		EmergencyHotkey:     "ctrl+shift+F12",
		DNSLeakTestInterval: 300, // проверка каждые 5 минут

		// Фаза 6: DPI обход — выключены по умолчанию
		TrafficPaddingEnabled:    false,
		TrafficPaddingAggressive: false,
		CDNWorkerDomain:          "",
		ShadowTLSEnabled:         false,
		ShadowTLSSNI:             "www.bing.com",
		ShadowTLSPassword:        "",
		MultiHopEnabled:          false,
		MultiHopCount:            2,
		StickySessionPolicy:      "sticky",
		AdBlockProfile:           "disabled",
		// W3 (ТЗ v1.5 §5): each_scan — старым config.json (ключ отсутствует) LoadInto
		// оставит именно этот дефолт, JSON поверх DefaultConfig() ничего не тронет.
		CatalogReviewInterval: ReviewIntervalEachScan,

		// Sprint S6: Anti-VPN-Block — выключено по умолчанию
		// (требует сетевых запросов к IP-API, может замедлять подключение)
		AntiBlockEnabled:         false,
		AntiBlockResidentialOnly: false,
		AntiBlockAutoSwitch:      false,
		ConnectionMode:           ModeProxy,
		SetSystemProxy:           false,
		SelectionMode:            "auto",
	}
}
