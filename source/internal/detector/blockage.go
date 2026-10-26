// Package detector — определяет тип интернет-блокировки и выбирает стратегию обхода.
// Реализован по паттернам из bypass-engineer skill.
package detector

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
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
	// BlockageWhitelist — «белые списки» мобильного интернета (лот L3): зарубежные адреса
	// недоступны ВСЕ, а российские сервисы открываются. Это не «полная блокировка»: сеть
	// работает, но пропускает только разрешённые адреса. Значение добавлено В КОНЕЦ, чтобы не
	// сдвигать номера прежних типов.
	BlockageWhitelist
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
	case BlockageWhitelist:
		return "whitelist"
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
	// lookupIP и ipDialer - хуки пути «имя -> публичные адреса -> подключение» (canTCPConnectPublic).
	// Нужны тестам: без lookupIP под `go test` резолв имён не выполняется вовсе (netguard).
	lookupIP func(ctx context.Context, host string) ([]net.IPAddr, error)
	ipDialer func(ctx context.Context, addr string) bool
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
//
// Лот L3: если 1.1.1.1:443 недоступен, перед выводом «полная блокировка» проверяется, не белые ли
// это списки мобильного интернета (probeNetwork: зарубежные цели закрыты, российские открыты).
// Остальные шаги не меняются.
func (d *BlockageDetector) Diagnose(ctx context.Context) (BlockageType, error) {
	// Шаг 1: Базовое TCP подключение к известному IP (при его молчании - и остальные пробы сети,
	// в том же окне времени)
	probe := d.probeNetwork(ctx)
	cloudflareClosed := false
	if !probe.cloudflareOpen {
		// Лот L3: «зарубежное закрыто» ещё не значит «закрыто всё». При белых списках
		// мобильного интернета российские сервисы открываются, и называть такую сеть
		// «полной блокировкой» (с советом идти в Tor) было бы неправдой.
		if !probe.foreignOpen {
			if probe.domesticOpen {
				return BlockageWhitelist, nil
			}
			// Ни один зарубежный адрес не отвечает и российские не открылись — полная блокировка
			return BlockageComplete, nil
		}
		// Закрыт один 1.1.1.1, но другой зарубежный адрес отвечает: сеть жива, закрыт избирательно
		// один адрес. Раньше это тоже называлось «полной блокировкой» (с советом идти в Tor).
		// Дальше проверяем DNS и SNI как обычно.
		cloudflareClosed = true
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
	// Проверяем что публичные DNS IP доступны. Один закрытый адрес блокировкой по IP не считается:
	// «по IP» объявляется, только когда закрыты ДВА независимых адреса (1.1.1.1 и 8.8.8.8), а сеть
	// при этом жива. Иначе выбор режима пользователя подменялся бы весами «против блокировок» на
	// всю сессию из-за одного недоступного адреса (так и было, пока закрытый 1.1.1.1 объявлялся
	// блокировкой по IP сам по себе).
	var googleOpen bool
	if cloudflareClosed {
		googleOpen = probe.googleOpen // уже проверен вместе с остальными зарубежными целями
	} else {
		googleOpen = d.canTCPConnect(ctx, "8.8.8.8:443")
	}
	if !googleOpen {
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
			Reason:     "IP блокировка — рекомендуется маршрут через CDN (Cloudflare; нужен собственный Worker)",
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

	case BlockageWhitelist:
		// Лот L3 («белые списки» мобильного интернета). Пропускаются только разрешённые
		// АДРЕСА (IP/подсети), поэтому ни Tor, ни обычный платный/бесплатный узел с чужим IP
		// не пробьются; подмена SNI тоже не спасает — источники расходятся, зависит от
		// оператора (см. RESEARCH_VPN_CONFIG_REPOS_2026-10-21, U-10). Нужен узел, чей адрес
		// лежит в разрешённых диапазонах: Reality-узлы из списков «белых списков».
		// Fallback "direct": российские сервисы при белых списках открыты напрямую.
		return Strategy{
			Primary:    "vless+reality",
			Fallback:   "direct",
			UseReality: true,
			Reason: "Похоже на белые списки мобильного интернета (по косвенным признакам): зарубежные адреса " +
				"закрыты, российские открыты — нужен узел с адресом из разрешённых диапазонов (включите источники " +
				"«белые списки» в каталоге); Tor и обычные узлы, скорее всего, не помогут",
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
		sb.WriteString("Рекомендуется маршрут через Cloudflare CDN (нужен собственный Cloudflare Worker, см. раздел CDN).")
	case BlockageSNI:
		sb.WriteString("Обнаружена SNI-фильтрация (характерно для РКН/ТСПУ).\n")
		sb.WriteString("APF активирует Reality — трафик выглядит как подключение к Microsoft.")
	case BlockageDeep:
		sb.WriteString("Обнаружена глубокая инспекция пакетов (DPI).\n")
		sb.WriteString("APF активирует Reality + цепочку туннелей для максимальной маскировки.")
	case BlockageComplete:
		sb.WriteString("Интернет полностью заблокирован.\n")
		sb.WriteString("APF пробует прямой Tor как последний шанс подключения.")
	case BlockageWhitelist:
		sb.WriteString("Похоже на «белые списки» мобильного интернета: российские сайты открываются, зарубежные адреса — нет.\n")
		sb.WriteString("Обычные узлы и Tor здесь, скорее всего, не заработают: нужен узел с адресом из разрешённых диапазонов " +
			"(включите источники «белые списки» в каталоге серверов). Определено по косвенным признакам.")
	}
	sb.WriteString(fmt.Sprintf("\nСтратегия: %s → %s", s.Primary, s.Fallback))
	return sb.String()
}

// ─── Распознавание «белых списков» (лот L3) ───────────────────────────────────

// Зарубежные цели, которые при белых списках закрыты вместе с 1.1.1.1:443 (его проверка идёт в
// Diagnose первой). Набор намеренно НЕ состоит из одних публичных DNS-резолверов: их цензоры и
// корпоративные фильтры нередко режут разом (DoH), оставляя остальной интернет, — и такая сеть
// ошибочно считалась бы белыми списками. Поэтому рядом с 8.8.8.8/9.9.9.9 стоят обычный сайт
// (github.com) и IPv6-адреса: в IPv6-only сети IPv4-литералы закрыты, а российские сайты открыты
// по AAAA, и без IPv6-целей это тоже выглядело бы как белые списки.
var whitelistForeignProbes = []string{
	googleProbe, "9.9.9.9:443", "github.com:443",
	"[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:443",
}

// Российские сервисы, которые обычно входят в разрешённые наборы мобильных операторов
// (Яндекс, Госуслуги, ВКонтакте). Адреса — по ИМЕНИ, как их открыл бы пользователь: при белых
// списках работает системный DNS оператора. Для распознавания достаточно, чтобы открылся
// любой один: наборы у операторов разные.
var whitelistDomesticProbes = []string{"ya.ru:443", "gosuslugi.ru:443", "vk.com:443"}

// Первая проба шага 1 - 1.1.1.1:443; остальные зарубежные и российские цели запускаются, только если
// она не ответила за extraProbesGrace или закрыта (при открытом 1.1.1.1 лишних сетевых обращений нет).
const (
	cloudflareProbe = "1.1.1.1:443"
	googleProbe     = "8.8.8.8:443"
)

// extraProbesGrace - сколько 1.1.1.1:443 может молчать, прежде чем стартуют остальные пробы
// (переменная: тесты сокращают).
var extraProbesGrace = 1500 * time.Millisecond

// networkProbe - итог шага 1 Diagnose.
type networkProbe struct {
	cloudflareOpen bool // 1.1.1.1:443 ответил (остальные поля тогда не заполняются)
	foreignOpen    bool // ответила хотя бы одна зарубежная цель из whitelistForeignProbes
	domesticOpen   bool // ответил хотя бы один российский сервис
	googleOpen     bool // 8.8.8.8:443 ответил (значим, только если cloudflareOpen == false)
}

// probeNetwork - шаг 1 Diagnose. 1.1.1.1:443 проверяется первым. Если он ответил - всё, больше
// никаких обращений. Если молчит дольше extraProbesGrace или закрыт - ПАРАЛЛЕЛЬНО запускаются
// остальные зарубежные и российские цели, и ВСЕ пробы делят ОДНО окно d.timeout (общий дедлайн от
// начала шага): худший случай по времени не растёт (раньше 1.1.1.1 получал d.timeout, потом ещё
// 3 с отдельным окном), а на медленном международном канале зарубежные цели получают те же
// d.timeout, что и ближние российские, - иначе медленный канал выглядел бы как «белые списки».
//
// Эвристика, а не доказательство: по косвенным признакам «сеть жива, но выпускает только
// разрешённое». Известные ограничения: (1) если APF уже поднял туннель с правилом «Россия
// напрямую» и он умер, зарубежные пробы упадут, а российские пойдут напрямую — получится «белые
// списки» вместо «полной блокировки»; (2) страница-заглушка провайдера с ПУБЛИЧНЫМ адресом
// (канал-портал) неотличима от настоящего сервиса — частные, CGNAT и локальные адреса отбрасываются
// (canTCPConnectPublic, и для зарубежных целей тоже), публичные нет. Ошибка здесь стоит лишь иного
// текста стратегии, не отключения защит. Критерий основан на описаниях в README открытых источников
// (igareck, hxehex) и на живой проверке при настоящих белых списках пока не подтверждён.
//
// Лишние пробы обрываются досрочно: когда 1.1.1.1 всё же ответил, а также когда уже открыта любая
// зарубежная цель и известен результат 8.8.8.8 (ответ ясен: это не белые списки и не полный обрыв).
func (d *BlockageDetector) probeNetwork(ctx context.Context) networkProbe {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	extraCtx, extraCancel := context.WithCancel(ctx)
	defer extraCancel()

	var (
		mu  sync.Mutex
		res networkProbe
		wg  sync.WaitGroup
	)
	cfDone := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(cfDone)
		if d.canTCPConnect(ctx, cloudflareProbe) {
			mu.Lock()
			res.cloudflareOpen = true
			mu.Unlock()
			extraCancel() // ответ получен - запущенные пробы не нужны
		}
	}()

	grace := time.NewTimer(extraProbesGrace)
	defer grace.Stop()
	select {
	case <-cfDone:
	case <-grace.C:
	}
	mu.Lock()
	cfOpen := res.cloudflareOpen
	mu.Unlock()
	if cfOpen {
		wg.Wait()
		return res
	}

	googleDone := false
	launch := func(addr string, domestic bool) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok := d.canTCPConnectPublic(extraCtx, addr)
			mu.Lock()
			defer mu.Unlock()
			if domestic {
				if ok {
					res.domesticOpen = true
				}
				return
			}
			if ok {
				res.foreignOpen = true
			}
			if addr == googleProbe {
				res.googleOpen, googleDone = ok, true
			}
			if res.foreignOpen && googleDone {
				extraCancel() // ответ ясен - не ждём молчащие цели до конца окна
			}
		}()
	}
	for _, addr := range whitelistForeignProbes {
		launch(addr, false)
	}
	for _, addr := range whitelistDomesticProbes {
		launch(addr, true)
	}
	wg.Wait()
	return res
}

// isPublicIP — адрес, по которому может отвечать настоящий внешний сервис: не частный, не
// loopback, не link-local, не «неопределённый», не multicast и не CGNAT (100.64.0.0/10). Заглушки
// провайдеров и captive-порталы отдают на любое имя именно такие адреса.
func isPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xC0 == 64 {
		return false // 100.64.0.0/10 — CGNAT
	}
	return true
}

// ─── Вспомогательные методы ───────────────────────────────────────────────────

func (d *BlockageDetector) canTCPConnect(ctx context.Context, addr string) bool {
	if d.tcpDialer != nil {
		return d.tcpDialer(ctx, addr)
	}
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	return dialAndClose(ctx, addr)
}

// canTCPConnectPublic — как canTCPConnect, но имя сперва разрешается системным резолвером, а
// подключаться разрешено только к ПУБЛИЧНЫМ адресам (isPublicIP): иначе заглушка провайдера или
// captive-портал, отдающие на любое имя частный адрес, «открывали» бы ya.ru и ложно давали белые
// списки. Пробуются не более двух первых публичных адресов, чтобы не съесть весь таймаут.
func (d *BlockageDetector) canTCPConnectPublic(ctx context.Context, addr string) bool {
	if d.tcpDialer != nil {
		return d.tcpDialer(ctx, addr)
	}
	// Резолв имени - тоже выход в сеть: под `go test` (netguard) его нет, как и подключений.
	if d.lookupIP == nil && netguard.Blocking() {
		return false
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	lookup := d.lookupIP
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}
	ips, err := lookup(ctx, host)
	if err != nil {
		return false
	}
	// IPv4 раньше IPv6: недоступный IPv6 не должен съедать бюджет до первого рабочего IPv4.
	var cands []string
	for pass := 0; pass < 2; pass++ {
		for _, ia := range ips {
			if !isPublicIP(ia.IP) || (ia.IP.To4() != nil) != (pass == 0) {
				continue
			}
			cands = append(cands, net.JoinHostPort(ia.IP.String(), port))
		}
	}
	dial := d.ipDialer
	if dial == nil {
		dial = dialAndClose
	}
	for i, c := range cands {
		if i >= 2 { // не более двух адресов, чтобы не съесть весь таймаут
			break
		}
		if dial(ctx, c) {
			return true
		}
	}
	return false
}

// dialAndClose — TCP-подключение без передачи данных и немедленное закрытие. Идёт через
// netguard.Guard: под `go test` выход за пределы петли отвергается (Т-5), как у остальных
// сетевых вызовов детектора.
func dialAndClose(ctx context.Context, addr string) bool {
	conn, err := netguard.Guard((&net.Dialer{}).DialContext)(ctx, "tcp", addr)
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
