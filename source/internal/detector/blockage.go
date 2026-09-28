// Package detector — определяет тип интернет-блокировки и выбирает стратегию обхода.
// Реализован по паттернам из bypass-engineer skill.
package detector

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/netguard"
)

// BlockageType — тип обнаруженной блокировки
type BlockageType int

const (
	BlockageNone     BlockageType = iota // Блокировок нет
	BlockageDNS                          // DNS подделка / блокировка запросов
	BlockageIP                           // IP адрес заблокирован
	BlockageSNI                          // SNI фильтрация (ТСПУ анализирует TLS ClientHello)
	BlockageDeep                         // DPI глубокая инспекция
	BlockageComplete                     // Полная блокировка интернета
)

func (b BlockageType) String() string {
	switch b {
	case BlockageNone:
		return "none"
	case BlockageDNS:
		return "dns"
	case BlockageIP:
		return "ip"
	case BlockageSNI:
		return "sni"
	case BlockageDeep:
		return "deep_dpi"
	case BlockageComplete:
		return "complete"
	default:
		return "unknown"
	}
}

// Strategy — рекомендуемая стратегия обхода
type Strategy struct {
	Primary    string // первый выбор протокола
	Fallback   string // резервный
	UseCDN     bool   // использовать CDN fronting
	UseReality bool   // использовать Reality
	UseChain   bool   // использовать цепочку туннелей
	Reason     string // объяснение для пользователя
}

// BlockageDetector определяет тип блокировки и рекомендует стратегию
type BlockageDetector struct {
	timeout    time.Duration
	httpClient *http.Client
	// test injection hooks: nil means use real implementation
	tcpDialer   func(ctx context.Context, addr string) bool
	dnsResolver func(ctx context.Context, domain string) bool
}

// New создаёт детектор с таймаутом 5 секунд
func New() *BlockageDetector {
	timeout := 5 * time.Second
	return &BlockageDetector{
		timeout: timeout,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				// netguard.Guard: под `go test` выход за пределы петли отвергается (Т-5).
				DialContext:         netguard.Guard((&net.Dialer{Timeout: timeout}).DialContext),
				TLSHandshakeTimeout: 3 * time.Second,
			},
		},
	}
}

// InvalidateCache сбрасывает кэш последнего результата диагностики.
// Вызывается engine при смене сети или изменении настроек.
// Поскольку BlockageDetector не кэширует результаты, метод является no-op.
func (d *BlockageDetector) InvalidateCache() {}

// Diagnose определяет тип блокировки.
// Алгоритм из bypass-engineer skill:
// 1. Проверяем базовое TCP соединение (1.1.1.1:443)
// 2. Проверяем DNS резолвинг
// 3. Проверяем SNI блокировку
// 4. Делаем вывод о типе
func (d *BlockageDetector) Diagnose(ctx context.Context) (BlockageType, error) {
	// Шаг 1: Базовое TCP подключение к известному IP
	canConnect := d.canTCPConnect(ctx, "1.1.1.1:443")
	if !canConnect {
		// Даже прямое TCP не работает — полная блокировка
		return BlockageComplete, nil
	}

	// Шаг 2: Проверяем DNS
	canDNS := d.canResolveDNS(ctx, "google.com")
	if !canDNS {
		// TCP работает, но DNS нет — DNS блокировка/подделка
		return BlockageDNS, nil
	}

	// Шаг 3: Проверяем SNI — пробуем подключиться к известному заблокированному домену
	// Если TCP к IP работает, но HTTPS по домену нет — SNI фильтрация
	sniBlocked := d.isSNIBlocked(ctx)
	if sniBlocked {
		return BlockageSNI, nil
	}

	// Шаг 4: Проверяем IP блокировку (datecenter IP)
	// Проверяем что публичные DNS IP доступны
	ipBlocked := !d.canTCPConnect(ctx, "8.8.8.8:443")
	if ipBlocked {
		return BlockageIP, nil
	}

	// Если всё работает — нет блокировки
	return BlockageNone, nil
}

// SelectStrategy выбирает оптимальную стратегию обхода по типу блокировки.
// Основана на anti-censorship матрице из bypass-engineer skill.
func SelectStrategy(bt BlockageType) Strategy {
	switch bt {
	case BlockageNone:
		return Strategy{
			Primary:  "direct",
			Fallback: "vless",
			Reason:   "Блокировок не обнаружено",
		}

	case BlockageDNS:
		// DNS подделка — сначала чиним DNS, потом обычный прокси
		return Strategy{
			Primary:  "vless+tls",
			Fallback: "trojan",
			UseCDN:   false,
			Reason:   "DNS блокировка — используем DoH через туннель",
		}

	case BlockageIP:
		// IP заблокирован — нужны CDN IP (Cloudflare не блокируют)
		return Strategy{
			Primary:    "vless+ws+tls",
			Fallback:   "trojan+cdn",
			UseCDN:     true,
			UseReality: false,
			Reason:     "IP блокировка — маршрутизируем через CDN (Cloudflare)",
		}

	case BlockageSNI:
		// SNI фильтрация ТСПУ — Reality главный инструмент
		return Strategy{
			Primary:    "vless+reality",
			Fallback:   "trojan",
			UseReality: true,
			UseCDN:     false,
			Reason:     "SNI фильтрация (ТСПУ) — Reality маскирует под Microsoft/Apple",
		}

	case BlockageDeep:
		// DPI глубокая инспекция — Reality + цепочка
		return Strategy{
			Primary:    "vless+reality",
			Fallback:   "ss+obfs4",
			UseReality: true,
			UseChain:   true,
			Reason:     "DPI фильтрация — Reality + цепочка туннелей",
		}

	case BlockageComplete:
		// Всё заблокировано — прямой Tor как последний шанс.
		//
		// C-1 (ТЗ v1.4, лот L1-DET): раньше здесь стояло Primary "tor+snowflake" — обещание
		// Snowflake pluggable transport, которого в этой сборке НЕТ (нет клиента, нет проводки
		// в internal/singbox/config_builder.go: для protocol=Tor строится голый {Type:"tor"},
		// см. BuildTor()). Primary честно указывает на то, что реально собирается.
		//
		// Fallback "meek" по той же причине снят: "meek" в проекте существует только как имя
		// pluggable-transport, распознаваемое парсером ответа Tor BridgeDB
		// (internal/sources/sources.go:205, bridgeTransports) — сам транспорт нигде не
		// конфигурируется и не запускается. Оставить Fallback пустым нельзя: этого не позволяют
		// существующие тесты TestSelectStrategy_Complete и TestSelectStrategy_AllHaveRequiredFields
		// (internal/detector/blockage_test.go) — трогать их не входит в мандат этого лота.
		// Вместо выдумывания несуществующей возможности берём "direct" — второй outbound,
		// реально присутствующий в том же самом сгенерированном конфиге (BuildTor():
		// {Type:"tor"} + {Type:"direct"}), то есть Fallback описывает то, что фактически будет
		// в конфигурации, а не то, чего в ней нет.
		return Strategy{
			Primary:  "tor",
			Fallback: "direct",
			Reason:   "Полная блокировка — прямой Tor (pluggable transport в этой сборке не реализован)",
		}

	default:
		return Strategy{
			Primary:    "vless+reality",
			Fallback:   "trojan+cdn",
			UseReality: true,
			Reason:     "Неизвестный тип — применяем максимальную защиту",
		}
	}
}

// DiagnoseAndRecommend — полный цикл: диагностика + рекомендация
func (d *BlockageDetector) DiagnoseAndRecommend(ctx context.Context) (BlockageType, Strategy, string) {
	bt, err := d.Diagnose(ctx)
	if err != nil {
		bt = BlockageSNI // безопасный дефолт для России
	}
	strategy := SelectStrategy(bt)
	report := d.buildReport(bt, strategy)
	return bt, strategy, report
}

// buildReport — читаемый отчёт для пользователя
func (d *BlockageDetector) buildReport(bt BlockageType, s Strategy) string {
	var sb strings.Builder
	switch bt {
	case BlockageNone:
		sb.WriteString("Блокировок не обнаружено. APF использует прямое соединение.")
	case BlockageDNS:
		sb.WriteString("Обнаружена блокировка DNS. Провайдер перехватывает запросы к сайтам.\n")
		sb.WriteString("APF активирует DNS-over-HTTPS через туннель.")
	case BlockageIP:
		sb.WriteString("Обнаружена блокировка IP-адресов.\n")
		sb.WriteString("APF перенаправляет трафик через Cloudflare CDN.")
	case BlockageSNI:
		sb.WriteString("Обнаружена SNI-фильтрация (характерно для РКН/ТСПУ).\n")
		sb.WriteString("APF активирует Reality — трафик выглядит как подключение к Microsoft.")
	case BlockageDeep:
		sb.WriteString("Обнаружена глубокая инспекция пакетов (DPI).\n")
		sb.WriteString("APF активирует Reality + цепочку туннелей для максимальной маскировки.")
	case BlockageComplete:
		sb.WriteString("Интернет полностью заблокирован.\n")
		sb.WriteString("APF пробует прямой Tor как последний шанс подключения.")
	}
	sb.WriteString(fmt.Sprintf("\nСтратегия: %s → %s", s.Primary, s.Fallback))
	return sb.String()
}

// ─── Вспомогательные методы ───────────────────────────────────────────────────

func (d *BlockageDetector) canTCPConnect(ctx context.Context, addr string) bool {
	if d.tcpDialer != nil {
		return d.tcpDialer(ctx, addr)
	}
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (d *BlockageDetector) canResolveDNS(ctx context.Context, domain string) bool {
	if d.dnsResolver != nil {
		return d.dnsResolver(ctx, domain)
	}
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}
	addrs, err := resolver.LookupHost(ctx, domain)
	return err == nil && len(addrs) > 0
}

func (d *BlockageDetector) isSNIBlocked(ctx context.Context) bool {
	// Проверяем доступность известного заблокированного домена через HTTPS
	// Если TCP к IP работает, но HTTPS запрос падает с TLS ошибкой — SNI блокировка
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	// instagram.com - заблокирован в РФ через SNI фильтрацию
	req, err := http.NewRequestWithContext(ctx, "HEAD", "https://www.instagram.com", nil)
	if err != nil {
		return false
	}
	resp, err := d.httpClient.Do(req)
	if err != nil {
		// Ошибка подключения — возможно SNI блокировка
		errStr := err.Error()
		return strings.Contains(errStr, "connection reset") ||
			strings.Contains(errStr, "tls") ||
			strings.Contains(errStr, "timeout")
	}
	defer resp.Body.Close()
	// Если получили ответ — SNI не заблокирован (у пользователя нет блокировок)
	return false
}

// GoodRealitySNI — список надёжных SNI мишеней для Reality.
// Из bypass-engineer skill: должны поддерживать TLS 1.3 + X25519, быть стабильными.
// Порядок синхронизирован с singbox.GoodRealitySNI (internal/singbox/config_builder.go) —
// www.microsoft.com не первый, см. комментарий там (живой тест 2026-08-25: обрывается
// на середине Certificate, addons.mozilla.org отработал 2/2 без ошибок).
var GoodRealitySNI = []string{
	"addons.mozilla.org",
	"www.speedtest.net",
	"gateway.icloud.com",
	"dl.google.com",
	"update.googleapis.com",
	"www.microsoft.com",
}
