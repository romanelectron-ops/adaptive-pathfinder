// Package singbox генерирует JSON-конфиги для sing-box и управляет его жизненным циклом.
package singbox

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/models"
)

// MinSingBoxVersion — минимальная версия sing-box, понимающая схему, которую выдаёт этот
// сборщик (дефект D-A27).
//
// Схема здесь новее, чем кажется на первый взгляд:
//   - DNS-серверы с полем "type" вместо legacy "address" — с 1.12.0;
//   - поля TUN инлайном в inbound (без вложенного "tun") — с 1.11.0;
//   - "action": "reject" в правилах DNS — с 1.12.0.
//
// Бинарник старее откажется разбирать конфигурацию ЦЕЛИКОМ, а не проигнорирует лишнее поле:
//
//	FATAL decode config: dns.servers[0].type: json: unknown field "type"
//
// Именно это и произошло: сборщик мигрировали на новую схему, а SingBoxVersion остался
// 1.9.4, и подключение не поднималось ни на телефоне, ни на десктопе.
//
// Константа существует ради TestSingBoxVersion_SatisfiesConfigSchema: он не даёт версии и
// схеме разойтись молча. Поднимая схему, поднимайте и эту константу.
const MinSingBoxVersion = "1.12.0"

// ─── Структуры sing-box JSON ──────────────────────────────────────────────────

type Config struct {
	Log      LogConfig `json:"log"`
	DNS      DNSConfig `json:"dns"`
	Inbounds []Inbound `json:"inbounds"`
	// Endpoints — [TZ_TAILS_HARDENING_2026-08-31.md кластер B] отдельный от Outbounds
	// top-level массив, обязателен для WireGuard: sing-box 1.13.16 убрал outbound-тип
	// "wireguard" (см. nodeToOutbound), единственный рабочий путь — endpoint-конфигурация
	// (vendor/.../option/wireguard.go, option/endpoint.go). Тег endpoint'а живёт в ОБЩЕМ
	// пространстве имён с outbound-тегами (vendor checkOutbounds: "duplicate outbound/endpoint
	// tag") — Route.Final/detour ссылаются на него точно так же, как на обычный outbound-тег,
	// отдельного механизма маршрутизации не требуется.
	Endpoints    []Endpoint          `json:"endpoints,omitempty"`
	Outbounds    []Outbound          `json:"outbounds"`
	Route        RouteConfig         `json:"route"`
	Experimental *ExperimentalConfig `json:"experimental,omitempty"`
}

// ExperimentalConfig — cache_file (см. CacheFileConfig, дефект D-A35) и clash_api (§5,
// docs/PLAN_2026-08-28_stubs_and_realfunc.md — видимость подключений/трафика через
// Clash-compatible API sing-box).
type ExperimentalConfig struct {
	CacheFile *CacheFileConfig `json:"cache_file,omitempty"`
	ClashAPI  *ClashAPIConfig  `json:"clash_api,omitempty"`
}

// ClashAPIConfig — включает встроенный Clash-совместимый HTTP API sing-box
// (/traffic, /connections). ExternalController — "127.0.0.1:PORT", слушает только
// локально: этот API не аутентифицирован, наружу его выставлять нельзя.
type ClashAPIConfig struct {
	ExternalController string `json:"external_controller"`
}

// CacheFileConfig — путь файла кэша sing-box (TLS session resumption, fakeip и т.д.).
//
//	Инвариант: Path — ВСЕГДА абсолютный путь внутри каталога данных APF
//	(internal/config.DataDir()), никогда не пустая строка. Пустая строка — не «умолчание
//	сервера», а cache.db в текущем рабочем каталоге процесса (experimental/cachefile/
//	cache.go: `if options.Path != "" { path = options.Path } else { path = "cache.db" }`),
//	который на Android read-only (дефект D-A35, приёмка Э-Выход-1 на устройстве).
type CacheFileConfig struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
}

type LogConfig struct {
	Level    string `json:"level"`
	Output   string `json:"output,omitempty"`
	Disabled bool   `json:"disabled,omitempty"`
}

// ─── DNS (новый формат sing-box 1.12+) ───────────────────────────────────────

type DNSConfig struct {
	Servers          []DNSServer `json:"servers"`
	Rules            []DNSRule   `json:"rules,omitempty"`
	Final            string      `json:"final,omitempty"`
	Strategy         string      `json:"strategy,omitempty"`
	IndependentCache bool        `json:"independent_cache,omitempty"`
}

// DNSServer — новый формат sing-box 1.12+ (type + server вместо legacy address).
// Документация: https://sing-box.sagernet.org/migration/#migrate-to-new-dns-server-formats
type DNSServer struct {
	Type   string `json:"type"` // udp | tls | https | local | ...
	Tag    string `json:"tag"`
	Server string `json:"server,omitempty"` // адрес DNS-сервера (для udp/tls/https)
	Detour string `json:"detour,omitempty"`
}

type DNSRule struct {
	// Условия (хотя бы одно)
	Outbound     []string `json:"outbound,omitempty"`
	Network      []string `json:"network,omitempty"`
	Domain       []string `json:"domain,omitempty"`
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	ClashMode    string   `json:"clash_mode,omitempty"`
	// Действие (одно из)
	Server string `json:"server,omitempty"`
	Action string `json:"action,omitempty"` // напр. "reject" (sing-box 1.12+) — для adblock
	// Strategy — переопределение domain_strategy для этого правила (напр. "ipv4_only").
	// Действует только с Action: "route-options" (см. buildDNS про direct-route домены).
	Strategy string `json:"strategy,omitempty"`
}

// ─── Inbounds ─────────────────────────────────────────────────────────────────

type Inbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Listen     string `json:"listen,omitempty"`      // только для socks/http; у tun не эмитится
	ListenPort int    `json:"listen_port,omitempty"` // только для socks/http
	// sing-box 1.11+: поля TUN инлайнятся в inbound (нет вложенного "tun").
	// Встраиваем указателем: non-nil → поля промоутятся в JSON; nil → отсутствуют.
	*TunOptions
}

type TunOptions struct {
	InterfaceName    string   `json:"interface_name"`
	Address          []string `json:"address"` // sing-box 1.10+: inet4_address → address
	MTU              int      `json:"mtu,omitempty"`
	AutoRoute        bool     `json:"auto_route"`
	StrictRoute      bool     `json:"strict_route"`
	Stack            string   `json:"stack"` // system, gvisor, mixed
	IncludeInterface []string `json:"include_interface,omitempty"`
	ExcludePackage   []string `json:"exclude_package,omitempty"`
}

// ─── Outbounds ────────────────────────────────────────────────────────────────

type Outbound struct {
	Type string `json:"type"`
	Tag  string `json:"tag"`

	// VLESS / VMess / Trojan / SS — общее
	Server     string `json:"server,omitempty"`
	ServerPort int    `json:"server_port,omitempty"`
	UUID       string `json:"uuid,omitempty"`
	Password   string `json:"password,omitempty"`
	Flow       string `json:"flow,omitempty"`

	// VMess specific
	Security string `json:"security,omitempty"`
	AltID    int    `json:"alter_id,omitempty"`

	// ShadowTLS specific (T-18)
	Version int `json:"version,omitempty"`

	// Shadowsocks
	Method string `json:"method,omitempty"`

	// TLS
	TLS *OutboundTLS `json:"tls,omitempty"`

	// Transport
	Transport *OutboundTransport `json:"transport,omitempty"`

	// Selector / URLTest
	Outbounds []string `json:"outbounds,omitempty"`
	URL       string   `json:"url,omitempty"`
	Interval  string   `json:"interval,omitempty"`
	Tolerance int      `json:"tolerance,omitempty"`

	// Selector-only (ТЗ TZ_SINGBOX_HOTSWITCH_WINDOWS_v1.0: BuildPool). Default — какой из
	// Outbounds активен сразу при старте (без Default sing-box берёт первый в списке — нам
	// нужен именно тот кандидат, которого выбрал Go-код, а не позиция в JSON-массиве).
	// InterruptExistConnections=true при переключении рвёт уже открытые соединения на СТАРОМ
	// узле — сознательно: живой узел, на который они и так не отвечают (иначе бы не
	// переключались), не должен продолжать держать «зомби»-соединения после смены активного
	// члена группы (тот же класс проблемы, что описан у Задачи #11 в TZ_APF_QA_AND_BACKLOG,
	// только там причина была в TUN/gVisor, а здесь — в самом sing-box outbound-группы).
	Default                   string `json:"default,omitempty"`
	InterruptExistConnections bool   `json:"interrupt_exist_connections,omitempty"`

	// Chain (detour)
	Detour string `json:"detour,omitempty"`
}

// Endpoint — [TZ_TAILS_HARDENING_2026-08-31.md кластер B] зеркало
// vendor/github.com/sagernet/sing-box/option/endpoint.go (_Endpoint) +
// option/wireguard.go (WireGuardEndpointOptions), СПЛЮЩЕННОЕ в один плоский JSON-объект — сам
// sing-box собирает это через кастомный MarshalJSON (badjson.MarshallObjectsContext), сливающий
// {type,tag} с полями конкретного типа endpoint'а в одну структуру на выходе; здесь эта же форма
// написана руками, отдельного слоя абстракции под тип endpoint'а не заводим — сейчас нужен
// только один ("wireguard").
type Endpoint struct {
	Type string `json:"type"`
	Tag  string `json:"tag,omitempty"`

	// WireGuard endpoint (WireGuardEndpointOptions) — единственный используемый тип.
	Address    []string        `json:"address"`
	PrivateKey string          `json:"private_key"`
	Peers      []WireGuardPeer `json:"peers,omitempty"`
	MTU        uint32          `json:"mtu,omitempty"`
}

// WireGuardPeer — зеркало option.WireGuardPeer (тот же файл vendor, что и WireGuardEndpointOptions).
type WireGuardPeer struct {
	Address    string   `json:"address,omitempty"`
	Port       uint16   `json:"port,omitempty"`
	PublicKey  string   `json:"public_key,omitempty"`
	AllowedIPs []string `json:"allowed_ips,omitempty"`
	Reserved   []uint8  `json:"reserved,omitempty"`
}

type OutboundTLS struct {
	Enabled    bool            `json:"enabled"`
	ServerName string          `json:"server_name,omitempty"`
	Insecure   bool            `json:"insecure,omitempty"`
	ALPN       []string        `json:"alpn,omitempty"`
	UTLS       *UTLSConfig     `json:"utls,omitempty"`
	Reality    *RealityOptions `json:"reality,omitempty"`
}

type UTLSConfig struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint"` // chrome, firefox, safari, random
}

type RealityOptions struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id"`
}

// GoodRealitySNI — надёжные SNI мишени для Reality (bypass-engineer skill).
// Требования: TLS 1.3 + X25519, стабильный IP, не заблокирован в РФ.
//
// www.microsoft.com специально НЕ первый в списке (было так до 2026-08-25) —
// баг #3 (см. память apf-vyhod2-reality-selfconnect-bug3): живой кросс-девайс
// тест «Выхода» показал, что дозвон REALITY до www.microsoft.com/443
// стабильно, 100% попыток, обрывается на середине Certificate-сообщения
// (получено 8006 из 8273 байт, дальше EOF от Akamai-edge Microsoft) — сервер
// так и не набирает материал для честной имитации хендшейка, клиент AEAD-
// аутентифицируется успешно, но `hs.c.isHandshakeComplete` никогда не
// становится true. addons.mozilla.org (Fastly) в том же тесте, тем же
// клиентом, тем же кодом — отработал 2/2 раз без единой ошибки, с реальным
// XTLS-трафиком после хендшейка. Причина обрыва к microsoft.com не
// установлена (подозрение на Akamai-edge, закрывающий соединение без полного
// TLS-ответа при нестандартном клиенте) — не наш баг, но раз destination не
// работает, использовать его первым по умолчанию нельзя. Не удалён из списка
// целиком (может отрабатывать в других сетях/регионах), просто не default.
var GoodRealitySNI = []string{
	"addons.mozilla.org",
	"www.speedtest.net",
	"gateway.icloud.com",
	"dl.google.com",
	"update.googleapis.com",
	"www.microsoft.com",
}

type OutboundTransport struct {
	Type                string            `json:"type"`
	Path                string            `json:"path,omitempty"`
	Headers             map[string]string `json:"headers,omitempty"`
	MaxEarlyData        int               `json:"max_early_data,omitempty"`
	EarlyDataHeaderName string            `json:"early_data_header_name,omitempty"`
	// gRPC
	ServiceName string `json:"service_name,omitempty"`
}

// ─── Route ────────────────────────────────────────────────────────────────────

type RouteConfig struct {
	Rules                 []RouteRule     `json:"rules"`
	Final                 string          `json:"final"`
	AutoDetectInterface   bool            `json:"auto_detect_interface"`
	DefaultDomainResolver *DomainResolver `json:"default_domain_resolver,omitempty"`
}

// DomainResolver — какой DNS-сервер резолвит доменные имена серверов outbound'ов.
// sing-box 1.12+: без него FATAL "missing route.default_domain_resolver".
type DomainResolver struct {
	Server string `json:"server"`
}

type RouteRule struct {
	// Условия
	Inbound      []string `json:"inbound,omitempty"`
	Network      []string `json:"network,omitempty"`
	Protocol     []string `json:"protocol,omitempty"`
	Domain       []string `json:"domain,omitempty"`
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	IPCIDR       []string `json:"ip_cidr,omitempty"`
	GeoIP        []string `json:"geoip,omitempty"`
	GeoSite      []string `json:"geosite,omitempty"`
	// ProcessName — имена процессов (например "browser.exe"), чей трафик идёт по этому
	// правилу. Windows-аналог Android-исключений приложений из VPN: сервисы, которые
	// отказываются работать при признаках VPN, отправляем мимо туннеля целиком.
	// Работает только в TUN-режиме: sing-box определяет владельца соединения через
	// платформенный process matcher, а в прокси-режиме соединение приходит уже от
	// локального SOCKS-инбаунда, и настоящий процесс-источник неизвестен.
	ProcessName []string `json:"process_name,omitempty"`
	// Действие (одно из): маршрут к outbound ЛИБО action (sniff/hijack-dns/reject).
	Outbound string `json:"outbound,omitempty"`
	Action   string `json:"action,omitempty"`
}

// ─── Builder ──────────────────────────────────────────────────────────────────

// Builder строит sing-box конфигурации
type Builder struct {
	socksPort    int
	tunMode      bool
	tunMTU       int    // Э-4 · Ш-3: MTU реального TUN-интерфейса (0 — умолчание sing-box)
	tunIPv6      bool   // B-0403 · R-6.2: выдавать ли TUN адрес IPv6 (иначе v6 идёт мимо туннеля)
	blockIPv6    bool   // задача #18: форсировать ipv4_only на клиентские DNS-запросы (см. SetBlockIPv6)
	pinnedServer string // B-0403 · R-8: заранее резолвнутый IP узла входа (см. SetServerIP)
	logLevel     string
	bypass       []string
	// directProcesses — имена процессов, чей трафик идёт мимо туннеля (см. SetDirectProcesses).
	directProcesses []string
	// racePinned — заранее резолвнутые IP участников гонки (см. SetRacePinnedIPs).
	racePinned   map[string]string
	adBlockRules []map[string]interface{} // Sprint S4: AdBlock DNS правила
	shadowTLS    *ShadowTLSParams         // T-18: если задан — внутренний outbound оборачивается ShadowTLS
	cdn          *CDNParams               // T-18(CDN): если задан — outbound фронтится через CDN (TLS+ws)
}

// Адреса интерфейса apf0. Значения — из документации sing-box (ULA-подсети, не маршрутизируемые
// в интернет), чтобы не пересечься с реальной адресацией пользователя.
const (
	tunAddressV4 = "172.19.0.1/30"
	tunAddressV6 = "fdfe:dcba:9876::1/126"
)

// SetTunIPv6 — B-0403 · R-6.2 (C-11). Выдавать ли интерфейсу туннеля адрес IPv6.
//
// Почему это вопрос безопасности, а не удобства: `auto_route` перехватывает ТОЛЬКО те семейства,
// адреса которых есть на интерфейсе. Пока у apf0 был один IPv4-адрес, весь IPv6-трафик шёл мимо
// туннеля напрямую — то есть при «поднятом VPN» реальный IPv6-адрес пользователя оставался виден
// любому v6-совместимому сайту. Это и есть C-11.
//
// Выключать имеет смысл, только если пользователь СОЗНАТЕЛЬНО отказался от защиты от утечки IPv6
// (`BlockIPv6Leak=false`): тогда возвращается прежнее поведение.
func (b *Builder) SetTunIPv6(v bool) { b.tunIPv6 = v }

// SetBlockIPv6 — задача #18 (живой QA 2026-08-17): раньше "IPv6 Block" в UI дёргал
// leakguard.IPv6Guard.Enable(), который на Android НЕ делает вообще ничего (нет ветки для
// GOOS=android — только Linux-sysctl и Windows-комментарий про делегирование Kill Switch WFP).
// Тумблер молча ничего не блокировал, и живым прогоном поймали ровно то, что должно было
// произойти: TLS-хендшейк по IPv6 к wikipedia.org/amazon.com падал (нестабильный IPv6-путь
// конкретного узла к конкретному сайту), хотя UI показывал "IPv6 Block: включено".
//
// Настоящая блокировка IPv6 для КЛИЕНТСКИХ DNS-запросов (перехваченных в TUN через hijack-dns)
// возможна только на уровне DNS-правил sing-box — тот же приём уже используется для
// direct-route bypass-доменов (buildDNS: Action="route-options", Strategy="ipv4_only", см.
// комментарий там же про Happy Eyeballs). SetBlockIPv6(true) добавляет то же самое правило БЕЗ
// ограничения по домену — то есть глобально для всех клиентских DNS-запросов, а не только для
// bypass-списка. В отличие от прежнего OS-уровневого guard'а, этот путь одинаково работает на
// всех платформах (чистый Go, часть конфигурации sing-box), а не только там, где есть sysctl
// или WFP.
func (b *Builder) SetBlockIPv6(v bool) { b.blockIPv6 = v }

// SetTunMode переключает генерацию tun-inbound (этап Э-4, Ш-3).
//
// Нужен отдельный сеттер, а не только конструктор NewBuilder(..., tunMode): Android
// подключается к движку, уже созданному в режиме «прокси» (androidbridge.androidConfig
// жёстко ставит ModeProxy), а переключение на VPN происходит поверх уже живого движка
// вызовом StartTun — не пересозданием Engine с нуля.
func (b *Builder) SetTunMode(v bool) { b.tunMode = v }

// TunMode — текущее состояние (для тестов и диагностики).
func (b *Builder) TunMode() bool { return b.tunMode }

// SetTunMTU — MTU, которым фактически пользуется netstack sing-box для буферов пакетов.
//
// На Android интерфейс TUN создаёт не sing-box, а Android VpnService.Builder — если его
// MTU разойдётся с тем, что держит в голове sing-box (иначе — умолчание sing-box, 1500),
// возможна фрагментация. 0 — использовать умолчание sing-box (прежнее поведение, важно
// для внешнего процесса на десктопе, который сам создаёт интерфейс и сам выбирает MTU).
func (b *Builder) SetTunMTU(mtu int) { b.tunMTU = mtu }

// SetServerIP — B-0403 · R-8 (C-14). Закрепляет заранее резолвнутый IP узла, к которому хост
// подключается физически. Пустая строка снимает закрепление.
//
// Зачем: без него в конфигурации оставался ДОМЕН узла, и sing-box резолвил его сам — через
// `dns-local` (223.5.5.5, `detour: direct`), то есть открытым UDP мимо туннеля. Два последствия,
// и второе хуже первого:
//  1. посторонний резолвер узнаёт, каким именно VPN-сервером пользуется человек;
//  2. sing-box мог получить ДРУГОЙ адрес, чем тот, который движок разрешил в Kill Switch
//     (round-robin, GeoDNS, короткий TTL) — и Kill Switch заблокировал бы само подключение
//     к туннелю. При fail-closed (R-2.1) это выглядит как «Kill Switch не применился».
func (b *Builder) SetServerIP(ip string) { b.pinnedServer = ip }

// pinServerIP подставляет закреплённый IP вместо доменного имени сервера.
//
//	Вход:      готовый outbound и IP.
//	Тело:      подменяет Server; домен переезжает в TLS server_name, если тот пуст.
//	Выход:     outbound с адресом-IP.
//	Fail-safe: пустой/непарсящийся IP, адрес уже IP, пустой Server — ничего не меняется.
//	Инвариант: TLS-хендшейк никогда не уходит с SNI, равным IP-адресу (сервер отверг бы его),
//	           и явно заданный server_name никогда не перетирается.
func pinServerIP(out Outbound, ip string) Outbound {
	if ip == "" || out.Server == "" {
		return out
	}
	if net.ParseIP(ip) == nil || net.ParseIP(out.Server) != nil {
		return out
	}
	host := out.Server
	out.Server = ip
	if out.TLS != nil && out.TLS.Enabled && out.TLS.ServerName == "" {
		out.TLS.ServerName = host
	}
	return out
}

// ChainEntryNode — узел, к которому хост подключается ФИЗИЧЕСКИ.
//
// В BuildChain каждый outbound, кроме последнего, идёт через `detour` на следующий; значит
// соединение без detour — последний в списке — и есть точка входа, а `chain-0` (Route.Final) —
// точка выхода. Именно адрес точки входа надо закреплять и разрешать в Kill Switch: остальные
// узлы достигаются уже внутри туннеля. Инвариант проверяется тестом по готовому конфигу.
func ChainEntryNode(chain *models.Chain) *models.Node {
	if chain == nil || len(chain.Nodes) == 0 {
		return nil
	}
	return chain.Nodes[len(chain.Nodes)-1]
}

// tunAddresses — адреса интерфейса туннеля.
//
//	Инвариант: не существует состояния «туннель активен, а IPv6 идёт напрямую», кроме случая,
//	когда пользователь явно отказался от защиты от IPv6-утечки.
func (b *Builder) tunAddresses() []string {
	if b.tunIPv6 {
		return []string{tunAddressV4, tunAddressV6}
	}
	return []string{tunAddressV4}
}

// ShadowTLSParams — параметры ShadowTLS-обёртки для итогового конфига (T-18).
// Передаются движком из dpi.ShadowTLSManager, чтобы пакет singbox не зависел от dpi.
type ShadowTLSParams struct {
	Server   string
	Port     int
	Version  int
	Password string
	SNI      string
}

// SetShadowTLS включает обёртку ShadowTLS в собираемых конфигах (nil — выключено).
func (b *Builder) SetShadowTLS(p *ShadowTLSParams) { b.shadowTLS = p }

// CDNParams — параметры CDN-fronting (T-18 пара / разрыв #2): TLS+WebSocket поверх CDN IP.
// Передаются движком из dpi.CDNFronter, чтобы singbox не зависел от dpi.
type CDNParams struct {
	Server string // CDN IP (подключаемся к нему, не к реальному серверу)
	Port   int
	SNI    string // CDN-домен (DPI видит легитимный фронт-домен)
	WSPath string
	WSHost string // Host-заголовок → Worker маршрутизирует к backend
}

// SetCDNFronting включает CDN-fronting наложение на outbound (nil — выключено).
func (b *Builder) SetCDNFronting(p *CDNParams) { b.cdn = p }

// applyCDNFronting накладывает CDN-fronting на готовый outbound: перенаправляет на CDN IP,
// ставит TLS(server_name=CDN-домен) и transport=ws(path + Host header). Реальный сервер
// скрыт за CDN — DPI видит TLS-хендшейк с фронт-доменом. T-18/разрыв #2 для CDN-плеча.
func (b *Builder) applyCDNFronting(o Outbound) Outbound {
	o.Server = b.cdn.Server
	o.ServerPort = b.cdn.Port
	o.TLS = &OutboundTLS{
		Enabled:    true,
		ServerName: b.cdn.SNI,
		UTLS:       &UTLSConfig{Enabled: true, Fingerprint: "chrome"},
	}
	o.Transport = &OutboundTransport{
		Type:    "ws",
		Path:    b.cdn.WSPath,
		Headers: map[string]string{"Host": b.cdn.WSHost},
	}
	return o
}

// wrapShadowTLS оборачивает внутренний outbound (innerTag) ShadowTLS-обёрткой с тегом outerTag.
// Возвращает shadowtls-outbound (диалер, без detour) и переименованный inner с Detour,
// указывающим НА shadowtls-обёртку. T-18: закрывает «разрыв» — раньше dpi генерировал
// фрагмент, но config_builder его не вшивал.
//
// P1-1 (аудит 2026-09-01): направление было перевёрнуто. sing-box: shadowtls — ДИАЛЕР
// (protocol/shadowtls/outbound.go: DialContext игнорирует destination, ListenPacket
// возвращает os.ErrInvalid) — это не прокси-протокол, несущий пользовательский трафик, а
// транспортная обёртка поверх TCP+TLS. Реальный протокол (shadowsocks/vless/...) обязан
// «детурить» в shadowtls, чтобы его соединение физически устанавливалось через
// TLS-рукопожатие с маскировочным SNI; у самой shadowtls detour'а нет — она замыкает
// цепочку на сеть, используя b.shadowTLS.Server как РЕАЛЬНЫЙ адрес сервера (не
// маскировочный хост — см. dpi.ShadowTLSManager.ServerHost/ServerPort и ShadowTLSConfig.
// ServerAddr).
func (b *Builder) wrapShadowTLS(inner Outbound, innerTag, outerTag string) (Outbound, Outbound) {
	inner.Tag = innerTag
	inner.Detour = outerTag
	st := Outbound{
		Type:       "shadowtls",
		Tag:        outerTag,
		Server:     b.shadowTLS.Server,
		ServerPort: b.shadowTLS.Port,
		Version:    b.shadowTLS.Version,
		Password:   b.shadowTLS.Password,
		TLS: &OutboundTLS{
			Enabled:    true,
			ServerName: b.shadowTLS.SNI,
			UTLS:       &UTLSConfig{Enabled: true, Fingerprint: "chrome"},
		},
	}
	return st, inner
}

// SetAdBlockRules устанавливает DNS правила блокировки рекламы.
// Вызывается из engine перед каждым BuildSingle/BuildChain.
// rules — батчи доменов из adblock.Blocker.GetSingBoxDNSRules()
func (b *Builder) SetAdBlockRules(rules []map[string]interface{}) {
	b.adBlockRules = rules
}

// NewBuilder создаёт Builder с настройками по умолчанию
func NewBuilder(socksPort int, tunMode bool) *Builder {
	// Временно "debug" в TUN-режиме — диагностика D-A37 (Task #25, 2026-08-11):
	// TCP через TUN зависает намертво (curl по IP: timeout, ни данных, ни RST), тогда как
	// тот же узел через SOCKS5-инбаунд отвечает за 161ms — расхождение по инбаунду, не по
	// узлу/protect()/route-правилам (Final у обоих инбаундов один — "proxy"). "debug"
	// покажет, доходит ли TUN-соединение до Router.RouteConnection вообще.
	// Убрать после того, как причина найдена — не для постоянной эксплуатации.
	//
	// P1-8 (аудит 2026-09-01): УБРАНО. Причина D-A37 найдена и исправлена ещё 2026-08-11
	// (Stack=gvisor + DNS .2 + DNS-транспорт tcp), а уровень так и остался «временно» debug
	// больше трёх недель.
	//
	// Почему это не косметика: в debug sing-box печатает КАЖДОЕ исходящее соединение вместе с
	// доменом назначения (формат «router: sniffed protocol: …, domain: …» — его же разбирает
	// internal/web/domain_check.go). Этот поток уходит в eng.OnLog, а на Android — в
	// постоянный файл logs/apf_log.txt с ротацией 72 часа, у которого есть кнопка «Выгрузить
	// лог» через системный share sheet. То есть история посещённых доменов за трое суток
	// оказывалась в файле, который пользователь не глядя пересылает в мессенджер. Для
	// инструмента обхода блокировок это худший из возможных побочных эффектов диагностики.
	//
	// Нужен debug для разбора конкретного инцидента — включается точечно через
	// SetLogLevel(), а не по факту TUN-режима у всех пользователей.
	logLevel := "info"
	return &Builder{
		socksPort: socksPort,
		tunMode:   tunMode,
		// R-6.2: по умолчанию IPv6 идёт В ТУННЕЛЬ. Умолчание выбрано «безопасным»: молчаливая
		// утечка реального v6-адреса хуже, чем недоступность v6-узлов, если у выходного сервера
		// нет v6 (в этом случае приложения уходят на IPv4 по Happy Eyeballs).
		tunIPv6:  true,
		logLevel: logLevel,
		bypass:   defaultBypass(),
	}
}

// RaceProbeURL — что дёргает urltest, проверяя работоспособность каждого кандидата.
// Лёгкий эндпоинт без тела ответа; тот же адрес, что уже используется в health-check.
const RaceProbeURL = "https://1.1.1.1/cdn-cgi/trace"

// BuildRace строит конфиг, в котором НЕСКОЛЬКО узлов конкурируют за право пропускать
// трафик, а выбор делает сам sing-box (outbound типа urltest).
//
// Зачем это нужно. Обычный путь (BuildSingle) выбирает ОДИН «лучший» узел по score и
// latency, а score считается по TCP-пробе: она подтверждает лишь то, что порт открыт, но
// не то, что узел реально пропускает трафик. На бесплатных публичных узлах это расходится
// постоянно. Живой лог пользователя из России (2026-08-20, см. память
// apf-russia-nodes-no-internet) показал ровно это: выбранный «лучший» узел отвечал HTTP 409
// на КАЖДОЕ соединение — 193 раза подряд, — и только через 30-50 секунд watchdog успевал
// найти рабочую замену. Всё это время у пользователя не грузилась ни одна страница, и он
// логично переподключался вручную, сбрасывая уже идущее восстановление.
//
// urltest снимает саму причину: он параллельно дёргает RaceProbeURL через КАЖДЫЙ кандидат
// и направляет трафик через тот, что реально ответил быстрее всех, а мёртвый не выбирает
// вовсе — не нужно ни ждать таймаута, ни переподключаться. Проба повторяется по interval,
// поэтому деградация узла тоже отрабатывается без участия нашего watchdog.
//
// ОГРАНИЧЕНИЯ, из-за которых фича пока экспериментальная и выключена по умолчанию
// (см. models.AppConfig.NodeRaceEnabled):
//
//  1. urltest судит кандидатов СЛАБЕЕ, чем мы сами: он смотрит только на то, что запрос не
//     завершился ошибкой транспорта, и не проверяет HTTP-статус вовсе (vendor,
//     common/urltest). Узел, отвечающий на всё ошибкой уровня приложения, проходит его как
//     здоровый и может выиграть у исправных.
//  2. Какой узел выбран, знает sing-box, а не мы: Clash API в конфиге не включён, читать
//     реальный выбор группы неоткуда. Поэтому Engine показывает пользователю кандидата
//     №0 как ориентир, и на нём же основаны markNodeFailed и проверка репутации IP —
//     то есть отказ может быть приписан не тому узлу.
//
// Конфиг НЕ годится для сценариев, где узел обязан быть строго заданным (ручной выбор,
// закреплённый узел, роль «Выход») — там по-прежнему BuildSingle.
// SetRacePinnedIPs задаёт заранее резолвнутые адреса участников гонки: ключ — Address узла
// (как в models.Node), значение — IP (или список через запятую, берётся первый).
//
// Без этого BuildRace оставлял в конфиге ДОМЕННЫЕ имена всех кандидатов, и они резолвились
// через route.default_domain_resolver — публичный DNS БЕЗ detour, то есть напрямую с
// реального адреса пользователя. Утекал сразу весь список его VPN-узлов. Вдобавок при
// GeoDNS/round-robin sing-box мог получить адрес, которого нет в разрешениях Kill Switch,
// и кандидат молча выпадал из группы (найдено ревью 2026-08-24; для BuildSingle/BuildChain
// закрепление уже делалось — R-8).
func (b *Builder) SetRacePinnedIPs(m map[string]string) {
	b.racePinned = m
}

func (b *Builder) BuildRace(nodes []*models.Node) (*Config, error) {
	if len(nodes) < 2 {
		return nil, fmt.Errorf("race requires at least 2 nodes, got %d", len(nodes))
	}

	cfg := b.baseConfig("proxy")

	// ShadowTLS/CDN оборачивают КОНКРЕТНЫЙ outbound своей парой тегов; в группе кандидатов
	// это дало бы конфликт тегов и молча сломало бы обёртку. Такие сеансы гонку не
	// используют — вызывающая сторона обязана это проверить, здесь же явный отказ, чтобы
	// расхождение не всплыло уже на живом подключении.
	if b.shadowTLS != nil || b.cdn != nil {
		return nil, fmt.Errorf("race is not supported together with ShadowTLS/CDN fronting")
	}

	outbounds := make([]Outbound, 0, len(nodes)+3)
	tags := make([]string, 0, len(nodes))
	for i, node := range nodes {
		tag := fmt.Sprintf("race-%d", i)
		out, err := nodeToOutbound(node, tag)
		if err != nil {
			// Один непригодный кандидат не должен рушить всю группу: просто не берём его.
			continue
		}
		// Закрепляем заранее резолвнутый IP — тот же инвариант R-8, что у BuildSingle:
		// конфиг sing-box и разрешения Kill Switch обязаны строиться по ОДНОМУ ответу
		// резолвера, а доменные имена узлов не должны утекать в открытый DNS.
		if ip := b.racePinned[node.Address]; ip != "" {
			out = pinServerIP(out, strings.SplitN(ip, ",", 2)[0])
		}
		outbounds = append(outbounds, out)
		tags = append(tags, tag)
	}
	if len(tags) < 2 {
		return nil, fmt.Errorf("race: осталось меньше двух пригодных кандидатов")
	}

	// Тег "proxy" сохраняем за группой: на него уже завязаны route-правила, kill switch и
	// health-check — группа подменяет одиночный узел прозрачно для остального кода.
	race := Outbound{
		Type:      "urltest",
		Tag:       "proxy",
		Outbounds: tags,
		URL:       RaceProbeURL,
		Interval:  "3m",
		// Не перескакивать на другой узел из-за разницы в несколько миллисекунд: смена
		// outbound рвёт установленные соединения, а «дребезг» между двумя одинаково
		// хорошими узлами ухудшил бы работу вместо того, чтобы улучшить.
		Tolerance: 100,
	}

	cfg.Outbounds = append(append([]Outbound{race}, outbounds...),
		Outbound{Type: "direct", Tag: "direct"})
	cfg.Route.Final = "proxy"
	if err := validateTagRefs(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// BuildPool строит конфиг с группой-СЕЛЕКТОРОМ (не urltest, как у BuildRace) из пачки
// кандидатов: активный член переключает ВЫЗЫВАЮЩИЙ Go-код через Process.SwitchOutbound
// (Clash API PUT /proxies), а не сам sing-box по собственной пробе.
//
// Зачем это нужно (TZ_SINGBOX_HOTSWITCH_WINDOWS_v1.0, RCA «5 почему»). На Windows обычный
// путь подключения (BuildSingle) пишет конфиг под ОДИН узел, и любое переключение убивает и
// пересоздаёт процесс sing-box.exe — на реальной машине пользователя это давало задержки
// 20-68с при каждом из ~12 переключений за сессию (нет SIGHUP на Windows, см. Process.Reload).
// BuildPool даёт то же самое, для чего BuildRace уже существует (несколько outbound в одном
// процессе) — но с ЯВНЫМ, а не автоматическим выбором: у APF уже есть свой скоринг на
// реальной TCP/трафик-пробе (internal/checker), sing-box'овский urltest ей заведомо слабее
// (см. ограничение №1 в комментарии у BuildRace) — здесь не нужно, чтобы sing-box сам судил.
//
// activeTag ОБЯЗАН входить в число тегов, порождённых из nodes — иначе конфиг был бы
// синтаксически валиден, но переключиться сразу после Start было бы не на что.
//
// Ограничения — ТЕ ЖЕ, что у BuildRace, и по той же причине (ShadowTLS/CDN вешаются на
// конкретный тег, конфликт в группе кандидатов).
func (b *Builder) BuildPool(nodes []*models.Node, activeTag string) (*Config, error) {
	if len(nodes) < 2 {
		return nil, fmt.Errorf("pool requires at least 2 nodes, got %d", len(nodes))
	}
	if b.shadowTLS != nil || b.cdn != nil {
		return nil, fmt.Errorf("pool is not supported together with ShadowTLS/CDN fronting")
	}

	outbounds := make([]Outbound, 0, len(nodes)+3)
	tags := make([]string, 0, len(nodes))
	var activeFound bool
	for i, node := range nodes {
		tag := fmt.Sprintf("pool-%d", i)
		out, err := nodeToOutbound(node, tag)
		if err != nil {
			// Один непригодный кандидат не должен рушить всю группу — тот же приём, что у
			// BuildRace. Если это как раз был activeTag — проверка ниже поймает несовпадение.
			continue
		}
		// Тот же инвариант R-8, что у BuildSingle/BuildRace: конфиг и разрешения Kill Switch
		// строятся по ОДНОМУ заранее резолвнутому ответу, доменные имена кандидатов не
		// уходят в открытый DNS. Пул переиспользует ту же карту, что и гонка — семантика
		// одна и та же («заранее резолвнутые адреса кандидатов пачки»).
		if ip := b.racePinned[node.Address]; ip != "" {
			out = pinServerIP(out, strings.SplitN(ip, ",", 2)[0])
		}
		outbounds = append(outbounds, out)
		tags = append(tags, tag)
		if tag == activeTag {
			activeFound = true
		}
	}
	if len(tags) < 2 {
		return nil, fmt.Errorf("pool: осталось меньше двух пригодных кандидатов")
	}
	if !activeFound {
		return nil, fmt.Errorf("pool: activeTag %q не входит в число пригодных кандидатов", activeTag)
	}

	cfg := b.baseConfig("proxy")

	// Тег "proxy" — тот же якорь, что у BuildRace/BuildSingle: route-правила/Kill
	// Switch/health-check не отличают группу от одиночного узла.
	pool := Outbound{
		Type:      "selector",
		Tag:       "proxy",
		Outbounds: tags,
		Default:   activeTag,
		// Переключение обязано рвать соединения на СТАРОМ узле, а не оставлять их висеть —
		// иначе получили бы тот же класс «зомби»-трафика, что у Задачи #11
		// (TZ_APF_QA_AND_BACKLOG_v2.0.md), только на уровне sing-box outbound-группы, а не
		// TUN/gVisor.
		InterruptExistConnections: true,
	}

	cfg.Outbounds = append(append([]Outbound{pool}, outbounds...),
		Outbound{Type: "direct", Tag: "direct"})
	cfg.Route.Final = "proxy"
	if err := validateTagRefs(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// BuildSingle строит конфиг для одного узла
func (b *Builder) BuildSingle(node *models.Node) (*Config, error) {
	// [TZ_TAILS_HARDENING_2026-08-31.md кластер B] WireGuard — единственный протокол, идущий
	// НЕ через nodeToOutbound/Config.Outbounds, а через отдельный endpoint-путь (см.
	// nodeToEndpoint) — sing-box 1.13.16 не имеет outbound-типа "wireguard" вовсе. CDN-фронтинг
	// и ShadowTLS — TLS-специфичные обёртки поверх ДРУГОГО outbound'а; WireGuard — не
	// TLS-протокол, комбинация не имеет смысла на уровне протокола — честный отказ, а не
	// молчаливое игнорирование включённой пользователем защиты.
	if node.Protocol == models.ProtoWireGuard {
		if b.cdn != nil || b.shadowTLS != nil {
			return nil, fmt.Errorf("CDN-фронтинг/ShadowTLS не применимы к WireGuard: " +
				"это TLS-обёртки поверх другого протокола, WireGuard не использует TLS")
		}
		endpoint, err := nodeToEndpoint(node, "proxy")
		if err != nil {
			return nil, fmt.Errorf("build endpoint: %w", err)
		}
		cfg := b.baseConfig("proxy")
		cfg.Endpoints = []Endpoint{endpoint}
		cfg.Outbounds = append([]Outbound{{Type: "direct", Tag: "direct"}}, cfg.Outbounds...)
		cfg.Route.Final = "proxy"
		if err := validateTagRefs(cfg); err != nil {
			return nil, err
		}
		return cfg, nil
	}

	outbound, err := nodeToOutbound(node, "proxy")
	if err != nil {
		return nil, fmt.Errorf("build outbound: %w", err)
	}
	// R-8: закрепляем заранее резолвнутый IP ДО обёрток (CDN/ShadowTLS ставят свой Server сами).
	outbound = pinServerIP(outbound, b.pinnedServer)

	cfg := b.baseConfig("proxy")

	// T-18(CDN): фронтим outbound через CDN (TLS+ws поверх CDN IP), если включено.
	if b.cdn != nil {
		outbound = b.applyCDNFronting(outbound)
	}

	// T-18: при включённом ShadowTLS внутренний outbound оборачивается shadowtls-обёрткой.
	// Туннель: client → proxy(протокол) → detour → shadowtls-out(диалер, TLS-маскировка) → сервер.
	//
	// P1-1 (аудит 2026-09-01): теги НАМЕРЕННО не совпадают со старым кодом. Тег "proxy"
	// остаётся за ВНУТРЕННИМ протокольным outbound'ом — на него по-прежнему указывает
	// Route.Final, и от него по-прежнему зависит весь остальной код, знающий узел только
	// по тегу "proxy" (health-check, статистика трафика, kill switch). Раньше "proxy"
	// доставался shadowtls-обёртке (диалеру), а протокол уходил под именем "proxy-inner" —
	// то же имя тега, что и сейчас, но у ДРУГОГО outbound'а с ДРУГИМ смыслом. Здесь это
	// исправлено без переименования: "proxy" снова означает то же самое, что и в конфиге
	// без ShadowTLS (реальный протокол пользователя), а внешняя обёртка получила отдельное
	// имя "shadowtls-out".
	if b.shadowTLS != nil {
		st, inner := b.wrapShadowTLS(outbound, "proxy", "shadowtls-out")
		cfg.Outbounds = append([]Outbound{
			st,
			inner,
			{Type: "direct", Tag: "direct"},
		}, cfg.Outbounds...)
		cfg.Route.Final = "proxy"
		if err := validateTagRefs(cfg); err != nil {
			return nil, err
		}
		return cfg, nil
	}

	cfg.Outbounds = append([]Outbound{
		outbound,
		{Type: "direct", Tag: "direct"},
	}, cfg.Outbounds...)

	cfg.Route.Final = "proxy"
	if err := validateTagRefs(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// BuildChain строит конфиг для цепочки VPN→Proxy
// Трафик идёт: клиент → outbound[0] → outbound[1] → интернет
func (b *Builder) BuildChain(chain *models.Chain) (*Config, error) {
	if len(chain.Nodes) < 2 {
		return nil, fmt.Errorf("chain requires at least 2 nodes")
	}

	// Точка входа цепочки — chain-0 (см. Route.Final ниже): именно через неё обязан ходить и
	// DNS-сервер dns-remote, иначе его detour ссылается на несуществующий тег "proxy".
	cfg := b.baseConfig("chain-0")

	// Строим outbounds в обратном порядке с detour-цепочкой
	// Последний узел (exit) — без detour, следующие используют его как detour
	var outbounds []Outbound

	for i := len(chain.Nodes) - 1; i >= 0; i-- {
		node := chain.Nodes[i]
		tag := fmt.Sprintf("chain-%d", i)
		out, err := nodeToOutbound(node, tag)
		if err != nil {
			return nil, err
		}
		// Каждый узел кроме последнего идёт через следующий
		if i < len(chain.Nodes)-1 {
			out.Detour = fmt.Sprintf("chain-%d", i+1)
		} else {
			// R-8: закрепляем IP только у точки входа — только к ней хост подключается
			// напрямую; адреса остальных узлов резолвятся уже внутри туннеля.
			out = pinServerIP(out, b.pinnedServer)
		}
		outbounds = append([]Outbound{out}, outbounds...)
	}

	// chain-0 — это вход в цепочку
	outbounds = append(outbounds,
		Outbound{Type: "direct", Tag: "direct"},
	)

	cfg.Outbounds = outbounds
	cfg.Route.Final = "chain-0"
	if err := validateTagRefs(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// BuildTor строит конфиг с Tor/Snowflake как fallback
func (b *Builder) BuildTor() *Config {
	cfg := b.baseConfig("proxy")
	cfg.Outbounds = []Outbound{
		{
			Type: "tor",
			Tag:  "proxy",
		},
		{Type: "direct", Tag: "direct"},
	}
	cfg.Route.Final = "proxy"
	return cfg
}

// validateTagRefs проверяет, что КАЖДАЯ ссылка на тег внутри конфигурации разрешается в
// реально объявленный outbound или endpoint.
//
// Зачем отдельная проверка, если есть real_binary_schema_test с `sing-box check`: `check`
// по построению останавливается на разборе конфигурации и НЕ доходит до Start(), а detour
// DNS-сервера инициализируется именно на Start() (vendor: dns/transport/tcp.go:57 →
// common/dialer/detour.go:49 → "outbound detour not found"). Из-за этого режим цепочки был
// полностью неработоспособен, а весь набор тестов оставался зелёным (находка P0-1 аудита
// 2026-09-01). Проверка дешёвая, поэтому вызывается в бою на каждой сборке конфигурации, а
// не только в тестах: понятная ошибка на нашей стороне лучше, чем падение sing-box.
//
// Пространство имён у Outbounds и Endpoints ОБЩЕЕ — так же, как в самом sing-box
// (option/options.go: checkOutbounds, "duplicate outbound/endpoint tag").
func validateTagRefs(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("validateTagRefs: nil config")
	}

	defined := make(map[string]struct{}, len(cfg.Outbounds)+len(cfg.Endpoints))
	for _, o := range cfg.Outbounds {
		if o.Tag == "" {
			return fmt.Errorf("validateTagRefs: outbound типа %q без тега", o.Type)
		}
		if _, dup := defined[o.Tag]; dup {
			return fmt.Errorf("validateTagRefs: тег %q объявлен дважды", o.Tag)
		}
		defined[o.Tag] = struct{}{}
	}
	for _, e := range cfg.Endpoints {
		if e.Tag == "" {
			return fmt.Errorf("validateTagRefs: endpoint типа %q без тега", e.Type)
		}
		if _, dup := defined[e.Tag]; dup {
			return fmt.Errorf("validateTagRefs: тег %q объявлен дважды", e.Tag)
		}
		defined[e.Tag] = struct{}{}
	}

	check := func(ref, where string) error {
		if ref == "" {
			return nil
		}
		if _, ok := defined[ref]; !ok {
			return fmt.Errorf("validateTagRefs: %s ссылается на несуществующий тег %q", where, ref)
		}
		return nil
	}

	if err := check(cfg.Route.Final, "route.final"); err != nil {
		return err
	}
	for _, o := range cfg.Outbounds {
		if err := check(o.Detour, fmt.Sprintf("outbound[%s].detour", o.Tag)); err != nil {
			return err
		}
		// urltest/selector ссылаются на участников через outbounds[].
		for _, member := range o.Outbounds {
			if err := check(member, fmt.Sprintf("outbound[%s].outbounds", o.Tag)); err != nil {
				return err
			}
		}
	}
	for _, s := range cfg.DNS.Servers {
		if err := check(s.Detour, fmt.Sprintf("dns.server[%s].detour", s.Tag)); err != nil {
			return err
		}
	}
	for i, r := range cfg.Route.Rules {
		if err := check(r.Outbound, fmt.Sprintf("route.rules[%d].outbound", i)); err != nil {
			return err
		}
	}
	return nil
}

// ToJSON сериализует конфиг в JSON
func ToJSON(cfg *Config) ([]byte, error) {
	return json.MarshalIndent(cfg, "", "  ")
}

// ─── Конвертация узла в outbound ─────────────────────────────────────────────

func nodeToOutbound(node *models.Node, tag string) (Outbound, error) {
	out := Outbound{
		Tag:        tag,
		Server:     node.Address,
		ServerPort: node.Port,
	}

	switch node.Protocol {
	case models.ProtoVLESS:
		out.Type = "vless"
		out.UUID = node.UUID
		out.Flow = node.Flow
		out.TLS = buildTLS(node)
		out.Transport = buildTransport(node)

	case models.ProtoVMess:
		out.Type = "vmess"
		out.UUID = node.UUID
		out.Security = "auto"
		out.AltID = node.AltID
		out.TLS = buildTLS(node)
		out.Transport = buildTransport(node)

	case models.ProtoShadowsocks:
		out.Type = "shadowsocks"
		out.Method = node.Method
		out.Password = node.Password
		// Аудит 2026-09-01 (раздел D, тест-закрепитель дефекта config_builder_test.go:843).
		// vendor/.../sing-box/option/shadowsocks.go: ShadowsocksOutboundOptions НЕ содержит
		// поля transport вовсе (в отличие от VLESS/VMess/Trojan выше) — sing-box отвергает
		// такую конфигурацию ЦЕЛИКОМ, а не просто игнорирует незнакомое поле. Раньше здесь
		// молча писался out.Transport, если у узла был непустой node.Transport — и узел,
		// дошедший сюда с этим полем, гарантированно ронял весь конфиг при сборке (а в
		// режиме гонки — всю группу кандидатов, включая исправные).
		//
		// Путь ss:// уже закрыт на входе (parser.go, parseShadowsocks: ссылка с ?plugin=...
		// отвергается сразу, той же находкой ревью 2026-08-24) — но nodeToOutbound вызывается
		// и для узлов, попавших в пул В ОБХОД парсера (ручной ввод через редактор
		// продвинутых полей, импорт из панели платного провайдера). Без проверки здесь тот
		// же класс дефекта возвращался бы именно этими путями.
		if node.Transport != nil {
			return out, fmt.Errorf("Shadowsocks с transport (%s) не поддерживается этой "+
				"сборкой sing-box — узел не может быть использован", node.Transport.Type)
		}

	case models.ProtoTrojan:
		out.Type = "trojan"
		out.Password = node.Password
		out.TLS = buildTLS(node)
		out.Transport = buildTransport(node)

	case models.ProtoWireGuard, models.ProtoAmneziaWG:
		// Находка консилиума 2026-08-10 (CRITICAL), закрыта частично в
		// TZ_TAILS_HARDENING_2026-08-31.md кластер B: sing-box 1.13.16 (закреплённая версия
		// проекта) безусловно регистрирует outbound-тип "wireguard" как заглушку
		// (registerStubForRemovedOutbounds), которая гарантированно отказывает — outbound-путь
		// для WireGuard больше не существует ни при каких условиях. Прямое подключение к
		// одиночному WireGuard-узлу ТЕПЕРЬ поддержано через отдельный endpoint-путь
		// (nodeToEndpoint, вызывается из BuildSingle ДО того, как дошло бы досюда — см. проверку
		// протокола там). Эта функция (nodeToOutbound) вызывается ЕЩЁ и из BuildChain/BuildRace,
		// которые endpoint-путь пока не поддерживают (WireGuard как звено цепочки или кандидат
		// авто-гонки — отдельная, всё ещё не начатая задача) — здесь отказ остаётся
		// принципиально верным для ЭТИХ двух путей. AmneziaWG (Jc/Jmin/Jmax junk-обфускация) не
		// поддерживается вообще ни в одном из путей — в вендоренном sing-box нет соответствующих
		// полей в WireGuardEndpointOptions.
		reason := "WireGuard как звено цепочки/кандидат авто-гонки узлов не поддерживается " +
			"(поддержан только прямой одиночный коннект, см. BuildSingle)"
		if node.Protocol == models.ProtoAmneziaWG {
			reason = "AmneziaWG (Jc/Jmin/Jmax junk-обфускация) не поддерживается используемой " +
				"сборкой sing-box ни в одном из путей подключения"
		}
		return out, fmt.Errorf("протокол %s не поддерживается: %s", node.Protocol, reason)

	case models.ProtoTor:
		out.Type = "tor"
		out.Tag = tag

	default:
		return out, fmt.Errorf("unsupported protocol: %s", node.Protocol)
	}

	return out, nil
}

// nodeToEndpoint — [TZ_TAILS_HARDENING_2026-08-31.md кластер B] строит sing-box
// endpoint-конфигурацию для ОДИНОЧНОГО WireGuard-узла (не AmneziaWG — та ветка не поддержана,
// см. комментарий у nodeToOutbound). В отличие от остальных протоколов, WireGuard требует
// отдельный top-level массив Config.Endpoints, не Config.Outbounds — вызывающая сторона
// (BuildSingle) обязана положить результат именно туда.
//
// Проверка протокола — обязанность вызывающей стороны (BuildSingle), не этой функции: здесь
// only узкая сборка полей, набор возможных вызывающих мест для endpoint'ов сейчас — ровно один
// (BuildSingle), расширять проверку "на всякий случай" внутри самой функции незачем.
func nodeToEndpoint(node *models.Node, tag string) (Endpoint, error) {
	if node.Protocol != models.ProtoWireGuard {
		return Endpoint{}, fmt.Errorf("nodeToEndpoint: протокол %s не поддержан (только %s)",
			node.Protocol, models.ProtoWireGuard)
	}
	if strings.TrimSpace(node.WGPrivateKey) == "" || strings.TrimSpace(node.WGPublicKey) == "" ||
		strings.TrimSpace(node.WGLocalAddress) == "" {
		// Тот же контракт, что уже проверяет validate.go при добавлении узла в пул — здесь
		// дублируем на случай прямого вызова BuildSingle мимо валидации (например, из тестов
		// или будущего кода) — конфиг без этих полей sing-box откажется разбирать целиком.
		return Endpoint{}, fmt.Errorf("nodeToEndpoint: узел %q не прошёл бы validate.go — "+
			"нужны wg_private_key, wg_public_key, wg_local_address", node.Name)
	}

	return Endpoint{
		Type:       "wireguard",
		Tag:        tag,
		Address:    []string{node.WGLocalAddress},
		PrivateKey: node.WGPrivateKey,
		Peers: []WireGuardPeer{{
			Address:    node.Address,
			Port:       uint16(node.Port),
			PublicKey:  node.WGPublicKey,
			AllowedIPs: []string{"0.0.0.0/0", "::/0"},
			Reserved:   node.WGReserved,
		}},
	}, nil
}

// tlsFingerprint — какой uTLS-отпечаток отдать sing-box для этого узла.
//
// Отпечаток из ссылки (`fp=` → models.TLSConfig.Fingerprint) имеет приоритет: сервер
// Reality/TLS может ЖДАТЬ конкретный отпечаток, и подстановка чужого рвёт рукопожатие.
// Раньше параметр терялся в парсере, а здесь безусловно стоял "chrome" — узел с `fp=firefox`
// не поднимался, и причина ниоткуда не была видна. Пусто/неизвестное значение → прежний
// дефолт "chrome" (HelloChrome_Auto, самый распространённый), чтобы поведение узлов без `fp`
// не менялось.
func tlsFingerprint(node *models.Node) string {
	const def = "chrome"
	if node.TLS == nil {
		return def
	}
	fp := strings.ToLower(strings.TrimSpace(node.TLS.Fingerprint))
	switch fp {
	case "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized":
		return fp
	default:
		// Неизвестный отпечаток не передаём в sing-box: он отвергает конфиг целиком с
		// FATAL, а мы из-за одной опечатки в ссылке потеряли бы весь сеанс.
		return def
	}
}

func buildTLS(node *models.Node) *OutboundTLS {
	if node.TLS == nil || !node.TLS.Enabled {
		return nil
	}
	fp := tlsFingerprint(node)
	tls := &OutboundTLS{
		Enabled:    true,
		ServerName: node.TLS.ServerName,
		// uTLS fingerprint имитирует актуальный браузер (bypass-engineer: chrome или firefox)
		// Это критично для обхода TLS fingerprint детекции (JA3/JA3S)
		UTLS: &UTLSConfig{
			Enabled:     true,
			Fingerprint: fp,
		},
	}
	if node.TLS.Reality != nil {
		// Reality: XTLS Reality из bypass-engineer skill
		// Клиент выполняет реальный TLS handshake с целевым сайтом
		// DPI видит легитимный TLS к microsoft.com/apple.com
		tls.Reality = &RealityOptions{
			Enabled:   true,
			PublicKey: node.TLS.Reality.PublicKey,
			ShortID:   node.TLS.Reality.ShortID,
		}
		// Reality requires h2+http/1.1 ALPN for proper TLS negotiation
		tls.ALPN = []string{"h2", "http/1.1"}
		// uTLS используется ВНУТРИ Reality для fingerprint паррота
		tls.UTLS = &UTLSConfig{
			Enabled:     true,
			Fingerprint: fp,
		}
	}
	return tls
}

func buildTransport(node *models.Node) *OutboundTransport {
	if node.Transport == nil {
		return nil
	}
	t := &OutboundTransport{Type: node.Transport.Type}
	switch node.Transport.Type {
	case "ws":
		t.Path = node.Transport.Path
		t.MaxEarlyData = 2048
		t.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
		if node.Transport.Host != "" {
			// sing-box требует headers как объект, не строку
			t.Headers = map[string]string{"Host": node.Transport.Host}
		}
	case "grpc":
		t.ServiceName = node.Transport.Path
	case "http":
		t.Path = node.Transport.Path
		if node.Transport.Host != "" {
			t.Headers = map[string]string{"Host": node.Transport.Host}
		}
	}
	return t
}

// ─── Базовый конфиг ───────────────────────────────────────────────────────────

// builderGOOS — точка подмены целевой ОС для тестов (тот же приём, что processGOOS
// в process.go: проверять поведение под Android с машины разработчика иначе нечем).
var builderGOOS = func() string { return runtime.GOOS }

// autoDetectInterfaceSupported — можно ли включать route.auto_detect_interface (дефект D-A28).
//
// Вход:      целевая ОС (builderGOOS).
// Тело:      Android отделяется от всех прочих систем.
// Выход:     false на Android, true везде ещё.
// Fail-safe: сомнение трактуется в пользу «выключить» — с выключенным полем sing-box
//
//	работает всюду, с включённым на Android не запускается вовсе.
//
// Инвариант: не существует конфигурации для Android, в которой auto_detect_interface = true.
//
// Что здесь происходит. sing-box реализует auto_detect_interface через netlink-сокет
// (NETLINK_ROUTE): так он узнаёт, через какой интерфейс уходит трафик по умолчанию.
// Android запрещает такие сокеты приложениям (SELinux-домен untrusted_app), и sing-box,
// не сумев его открыть, отказывается стартовать целиком:
//
//	FATAL initialize network manager: create network monitor: netlink socket in Android
//	is banned by Google, use the root or system (ADB) user to run sing-box, or switch to
//	the sing-box Android graphical interface client
//
// Отказ приходит ДО разбора остальной конфигурации, поэтому симптом выглядит как что
// угодно, только не как ошибка одного поля: SOCKS-порт не открывается, watchdog видит
// «connection refused», движок объявляет таймаут подключения и уходит в фаллбэк. Ровно это
// и наблюдалось на устройстве (лог 08-05 15:41–15:42); проверено под UID приложения через
// run-as: с этим полем `sing-box check` падает, без него — проходит и запускается.
//
// Почему выключить безопасно. Поле нужно, чтобы собственные исходящие сокеты sing-box не
// затянуло обратно в его же TUN-интерфейс. APF на Android TUN у sing-box не просит вообще
// (дефект D-A24): sing-box работает локальным SOCKS/HTTP-прокси, трафик в него приносит
// движок, петле взяться неоткуда.
//
// Чего делать НЕ надо, когда на этапе Э-4 появится TUN в том же процессе: возвращать это
// поле в true. Запрет netlink никуда не денется. Правильный путь — отдать sing-box
// platform interface (protect() из VpnService + сведения об интерфейсах из
// ConnectivityManager), как это делает официальный Android-клиент.
func autoDetectInterfaceSupported() bool {
	return builderGOOS() != "android"
}

// baseConfig собирает общий каркас конфигурации.
//
// entryTag — тег outbound'а/endpoint'а, который является ТОЧКОЙ ВХОДА в туннель для этого
// сеанса (то же значение, что уезжает в Route.Final). Параметр, а не константа "proxy",
// потому что у BuildChain точка входа называется "chain-0": DNS-сервер dns-remote обязан
// ходить через тот же вход, иначе его detour ссылается на несуществующий тег и sing-box
// падает на Start() целиком — см. validateTagRefs и находку P0-1 аудита 2026-09-01.
func (b *Builder) baseConfig(entryTag string) *Config {
	cfg := &Config{
		Log: LogConfig{Level: b.logLevel},
		DNS: b.buildDNS(entryTag),
		Route: RouteConfig{
			AutoDetectInterface:   autoDetectInterfaceSupported(),
			Rules:                 b.buildRouteRules(),
			DefaultDomainResolver: &DomainResolver{Server: "dns-local"},
		},
		// Дефект D-A35 (приёмка Э-Выход-1 на устройстве, 2026-08-10): CommandServer
		// (InProcessRunner, VPN-режим) всегда взводит options.PlatformLogWriter, а тот
		// БЕЗУСЛОВНО требует cache-file (box.go: needCacheFile = ... || PlatformLogWriter
		// != nil) — независимо от того, что в этом поле конфигурации. Без явного пути
		// sing-box берёт cache.db в ТЕКУЩЕМ РАБОЧЕМ КАТАЛОГЕ процесса, который на Android —
		// read-only ("initialize cache-file: open cache.db: read-only file system"), и
		// КАЖДОЕ подключение в VPN-режиме отказывало на старте, до попытки дозвониться до
		// узла (тот же класс дефекта, что with_clash_api/with_utls/D-A34). Путь — ВСЕГДА
		// внутри internal/config.DataDir() (уже пишется APF, точно доступен на запись на
		// всех платформах, включая Android через APF_DATA_DIR — см. mobile/androidbridge/
		// bridge.go Init()).
		Experimental: &ExperimentalConfig{
			CacheFile: &CacheFileConfig{
				Enabled: true,
				Path:    filepath.Join(config.DataDir(), "cache.db"),
			},
			// §5: тот же порт, что уже предполагает engine.go (PatchConfig —
			// NewTrafficMonitor(ListenPort+2)) — TrafficMonitor опрашивал этот порт и
			// раньше, но sing-box никогда не открывал на нём сервер, потому что конфиг не
			// объявлял clash_api вовсе (GetTrafficStats тихо возвращал нули/ошибки).
			ClashAPI: &ClashAPIConfig{
				ExternalController: fmt.Sprintf("127.0.0.1:%d", b.socksPort+2),
			},
		},
	}

	// Inbounds
	cfg.Inbounds = []Inbound{
		{
			Type:       "socks",
			Tag:        "socks-in",
			Listen:     "127.0.0.1",
			ListenPort: b.socksPort,
		},
		{
			Type:       "http",
			Tag:        "http-in",
			Listen:     "127.0.0.1",
			ListenPort: b.socksPort + 1,
		},
	}

	// TUN режим (перехват всего трафика ОС)
	if b.tunMode {
		cfg.Inbounds = append(cfg.Inbounds, Inbound{
			Type: "tun",
			Tag:  "tun-in",
			TunOptions: &TunOptions{
				InterfaceName: "apf0",
				Address:       b.tunAddresses(),
				MTU:           b.tunMTU,
				AutoRoute:     true,
				StrictRoute:   false, // Kill Switch via netsh/iptables, not sing-box strict_route
				// DNSHijack (inbound.tun.dns_hijack) намеренно НЕ ставится — находка 2026-08-10
				// (приёмка Э-Выход-1 через собственный тестовый сервер + adb reverse): у
				// sing-box 1.13.16 (option.TunInboundOptions, vendor/.../option/tun.go) этого
				// поля больше нет вообще. С ним sing-box отказывает ЛЮБОЙ TUN-конфигурации:
				// "decode config: inbounds[N].dns_hijack: json: unknown field "dns_hijack"" —
				// то есть КАЖДОЕ подключение в VPN-режиме отказывало на этапе разбора
				// конфигурации, ещё до попытки дозвониться до узла (тот же класс дефекта, что
				// уже был найден и исправлен для with_clash_api/with_utls). DNS-перехват в TUN
				// уже обеспечивается независимо — правилом route.rules
				// {protocol:["dns"], action:"hijack-dns"} (buildRouteRules ниже), которое
				// действует для ВСЕХ режимов, не только TUN; отдельного поля на инбаунде для
				// этого не требуется.
				//
				// "gvisor", не "mixed" — находка D-A37 (Task #25, 2026-08-11, живой прогон +
				// проброшенные внутренние debug-логи sing-box, см. OnInternalLog). "mixed"
				// (vendor/.../sing-tun/stack_mixed.go: Mixed встраивает *System) обрабатывает
				// TCP через System.processIPv4TCP — NAT-трюк: SYN переписывается и пишется
				// ОБРАТНО в TUN, ожидая, что ядро само закольцует его на локальный
				// tcpListener (System.start(), tcpListener на inet4Address:0). Живым прогоном
				// подтверждено: этот кольцевой путь на Android не работает — TCP-пакет реально
				// доходит до tun0 (/proc/net/dev RX растёт), но НИ ОДНОЙ записи от sing-box о
				// нём нет ни на каком уровне логов (включая TRACE), и соединение виснет
				// намертво (curl: timeout, ни данных, ни RST) — то есть кольцо "TUN → ядро →
				// локальный слушатель" не замыкается. UDP при этом работает: у "mixed" он идёт
				// НЕ через этот путь, а через gVisor endpoint.InjectInbound (подтверждено теми
				// же логами — QUIC-трафик исправно доходит до outbound). Чистый "gvisor"
				// (stack_gvisor.go: SetTransportProtocolHandler(tcp.ProtocolNumber, ...))
				// терминирует TCP ЦЕЛИКОМ внутри userspace-стека gVisor, тем же способом, что
				// уже подтверждённо работает для UDP — без кольца через ядро. Тег with_gvisor
				// уже обязателен для обоих значений (см. выше), сборка не меняется.
				Stack: "gvisor",
			},
		})
	}

	return cfg
}

// buildDNS — DNS leak protection, новый формат sing-box 1.12+
// Документация: https://sing-box.sagernet.org/migration/#migrate-to-new-dns-server-formats
func (b *Builder) buildDNS(entryTag string) DNSConfig {
	// sing-box 1.12+: plain UDP DNS - не legacy, максимальная совместимость.
	// "tls://..." - DEPRECATED с 1.12, вызывает FATAL ошибку в 1.13+
	// Используем обычный DNS (8.8.8.8) через туннель для leak protection.
	dns := DNSConfig{
		Final:    "dns-remote",
		Strategy: "prefer_ipv4",
		Servers: []DNSServer{
			// Новый формат 1.12+: type+server. dns-remote через туннель (leak protection).
			//
			// "tcp", не "udp" — находка D-A38 (Task #25, 2026-08-11, живой прогон ПОСЛЕ
			// фиксов Stack=gvisor и DNS-адреса .2): с "udp" запрос к 8.8.8.8 висел
			// (context deadline exceeded, 10-20с) на ДВУХ разных узлах разных протоколов
			// (vmess+CDN И обычный ss) — то есть не особенность одного узла, а общая
			// ненадёжность UDP-relay через прокси у бесплатных узлов пула. Тот же
			// прокси-outbound по TCP УЖЕ подтверждённо работает (curl по IP через TUN,
			// тот же фикс) — "tcp" переиспользует этот путь для DNS вместо UDP-relay.
			// 8.8.8.8 отвечает на DNS-over-TCP:53 штатно (стандарт, не особая опция).
			// Detour — entryTag, а НЕ константа "proxy": у BuildChain точка входа зовётся
			// "chain-0", и захардкоженный "proxy" делал конфигурацию цепочки незапускаемой
			// (sing-box: "start dns/tcp[dns-remote]: outbound detour not found: proxy").
			{Type: "tcp", Tag: "dns-remote", Server: "8.8.8.8", Detour: entryTag},
			// У dns-local detour НЕТ намеренно (дефект D-A30). Раньше здесь стояло
			// Detour: "direct", и sing-box 1.12+ отказывается запускаться целиком:
			//
			//	FATAL start service: start dns/udp[dns-local]:
			//	detour to an empty direct outbound makes no sense
			//
			// Возражение справедливо: outbound direct у нас без единой настройки, а DNS-сервер
			// без detour и так соединяется напрямую — указание ничего не меняло. sing-box
			// отказывается принимать пустое действие вместо того, чтобы молча его проглотить.
			//
			// Обратная сторона: убрать detour у dns-remote НЕЛЬЗЯ — там он выносит запросы в
			// туннель, и без него DNS пойдёт мимо (это и есть защита от утечки DNS).
			//
			// Замечено на Android, но дефект общий: с sing-box 1.13.16 по этой же причине не
			// стартовала бы и десктопная сборка.
			{Type: "udp", Tag: "dns-local", Server: "223.5.5.5"},
		},
		Rules: []DNSRule{
			{
				DomainSuffix: []string{"localhost", "local"},
				Server:       "dns-local",
			},
		},
	}

	// Задача #18: "IPv6 Block" глобально — без ограничения по домену (nil DomainSuffix/Domain
	// матчит любой запрос), action:"route-options" (не терминальный, см. ниже про bypass) —
	// заставляет sing-box вернуть на AAAA "успех, без записей" для ВСЕХ доменов, клиент
	// откатывается на A-запрос. Добавлено до bypass-правила ниже: если оба включены, бypass-
	// правило избыточно, но безвредно (то же действие).
	if b.blockIPv6 {
		dns.Rules = append(dns.Rules, DNSRule{
			Action:   "route-options",
			Strategy: "ipv4_only",
		})
	}

	// Прямой маршрут (direct/bypass) физически дозванивается с самого устройства ПОСЛЕ
	// protect() — в отличие от proxy-outbound'ов, которые дозваниваются с сервера. Найдено
	// 2026-08-13 живым прогоном: dns.Strategy=prefer_ipv4 (выше) НЕ действует на клиентские
	// DNS-запросы, перехваченные в TUN (hijack-dns/Exchange) — только на внутренний sing-box
	// Lookup() (резолвинг адреса самого прокси-сервера). Телефон честно получал реальный IPv6
	// приложения, TUN верно маршрутизировал на direct (см. память apf-bypass-feature-broken),
	// а сам сокет после protect() не мог дозвониться по IPv6 ("network is unreachable") —
	// решение о маршруте было верным, только выход не работал. Правило ниже —
	// action:"route-options" (не терминальный, продолжает матчинг до dns-remote/dns-local) —
	// заставляет sing-box вернуть на AAAA-запрос "успех, без записей" для доменов из байпаса,
	// клиент сам откатывается на A-запрос (обычный Happy Eyeballs) и получает IPv4, который
	// после protect() дозванивается всегда.
	if len(b.bypass) > 0 {
		dns.Rules = append(dns.Rules, DNSRule{
			DomainSuffix: b.bypass,
			Action:       "route-options",
			Strategy:     "ipv4_only",
		})
	}

	// Sprint S4: AdBlock DNS правила.
	//
	// ПОРЯДОК ВНУТРИ СРЕЗА ЗНАЧИМ и задаётся источником (adblock.Blocker.GetSingBoxDNSRules):
	// сначала правило allowlist, затем батчи блокировки. Правила DNS в sing-box матчатся
	// сверху вниз, терминальное действие останавливает разбор — поэтому мы обязаны сохранять
	// порядок, в котором правила пришли, и НЕ вправе их пересортировывать или группировать.
	//
	// P1-6 (аудит 2026-09-01): раньше здесь любое правило безусловно превращалось в
	// Action:"reject" — поле "action" исходного правила не читалось вовсе. Даже если бы
	// источник и эмитил разрешающее правило, оно приехало бы сюда как ещё одно запрещающее.
	if len(b.adBlockRules) > 0 {
		for _, rawRule := range b.adBlockRules {
			// 1.12+: блокировка через action "reject" (dns-block сервер с rcode:// удалён).
			// "allow" из источника → маршрутизация на dns-remote: это терминальное действие,
			// то есть запрос до батчей reject ниже уже не дойдёт.
			rule := DNSRule{Action: "reject"}
			if act, _ := rawRule["action"].(string); act == "allow" {
				rule = DNSRule{Server: "dns-remote"}
			}
			if ds, ok := rawRule["domain_suffix"]; ok {
				switch v := ds.(type) {
				case []string:
					rule.DomainSuffix = v
				case []interface{}:
					for _, s := range v {
						if str, ok := s.(string); ok {
							rule.DomainSuffix = append(rule.DomainSuffix, str)
						}
					}
				}
			}
			if len(rule.DomainSuffix) > 0 {
				dns.Rules = append(dns.Rules, rule)
			}
		}
	}

	return dns
}

func (b *Builder) buildRouteRules() []RouteRule {
	rules := []RouteRule{
		// 1.12+: сниффинг протокола через action (заменяет удалённый inbound.sniff)
		{Action: "sniff"},
		// DNS-трафик: hijack-dns action (заменяет удалённый dns outbound)
		{Protocol: []string{"dns"}, Action: "hijack-dns"},
		// Локальные адреса — напрямую
		{
			IPCIDR: []string{
				"127.0.0.0/8", "::1/128",
				"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
				"fc00::/7", "fe80::/10",
			},
			Outbound: "direct",
		},
	}

	// Приложения, которые пользователь вывел из-под VPN (Windows-аналог Android-исключений).
	// Ставится ВЫШЕ доменных правил: решение принимается по процессу-источнику и не должно
	// зависеть от того, попал ли домен в bypass-список.
	if len(b.directProcesses) > 0 {
		rules = append(rules, RouteRule{
			ProcessName: b.directProcesses,
			Outbound:    "direct",
		})
	}

	// Пользовательские bypass домены
	if len(b.bypass) > 0 {
		rules = append(rules, RouteRule{
			DomainSuffix: b.bypass,
			Outbound:     "direct",
		})
	}

	return rules
}

// SetLogLevel задаёт уровень логирования sing-box ("info" по умолчанию).
//
// P1-8: точечная замена постоянного debug-режима в TUN. Уровень "debug" заставляет sing-box
// печатать каждое соединение вместе с доменом назначения — включать его допустимо только для
// разбора конкретного инцидента и осознанно, а не всем пользователям TUN-режима сразу
// (на Android этот поток попадает в постоянный лог-файл с кнопкой «поделиться»).
//
// Допустимые значения sing-box: trace, debug, info, warn, error, fatal, panic. Пустая строка
// игнорируется, чтобы случайный вызов не сломал конфигурацию.
func (b *Builder) SetLogLevel(level string) {
	switch level {
	case "trace", "debug", "info", "warn", "error", "fatal", "panic":
		b.logLevel = level
	}
}

// SetDirectProcesses задаёт имена процессов, чей трафик идёт мимо туннеля (Windows).
// См. RouteRule.ProcessName — работает только в TUN-режиме.
func (b *Builder) SetDirectProcesses(names []string) {
	b.directProcesses = append([]string(nil), names...)
}

func defaultBypass() []string {
	return []string{
		"localhost",
	}
}

// SetBypassDomains задаёт пользовательские домены прямого маршрута (в обход VPN/туннеля),
// В ДОПОЛНЕНИЕ к дефолтным (localhost) — никогда их не теряет. Раньше b.bypass был
// захардкожен на defaultBypass() без единого сеттера: internal/bypass.Manager хранил и
// персистил пользовательские домены прямого маршрута, но они никогда не попадали сюда —
// добавление "байпас"-домена не влияло на реальную маршрутизацию ни на одной платформе.
// Вызывать перед BuildSingle/BuildChain (см. internal/engine.connectNode, по аналогии с
// SetAdBlockRules).
func (b *Builder) SetBypassDomains(domains []string) {
	b.bypass = append(defaultBypass(), domains...)
}

// coalesceStr returns the first non-empty string from vals.
func coalesceStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// coalesceInt returns the first non-zero int from vals.
func coalesceInt(vals ...int) int {
	for _, v := range vals {
		if v != 0 {
			return v
		}
	}
	return 0
}
