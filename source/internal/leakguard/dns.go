package leakguard

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// tunnelDNSResolver — DNS-резолвер, через который APF гонит запросы внутри туннеля.
const tunnelDNSResolver = "1.1.1.1:53"

type DNSLeakResult struct {
	Leaked         bool     `json:"leaked"`
	SystemDNS      string   `json:"system_dns"`
	TunnelDNS      string   `json:"tunnel_dns"`
	SystemIPs      []string `json:"system_ips"`
	TunnelIPs      []string `json:"tunnel_ips"`
	Diagnosis      string   `json:"diagnosis"`
	Recommendation string   `json:"recommendation"`
}

type DNSLeakTester struct {
	socksAddr string
	dnsServer string
	// resolveDirect / resolveTunnel переопределяемы в тестах.
	// Возвращают число DNS-ответов (ANCOUNT) и ошибку.
	resolveDirect func(ctx context.Context, domain string) (int, error)
	resolveTunnel func(ctx context.Context, domain string) (int, error)
}

func NewDNSLeakTester(socksAddr string) *DNSLeakTester {
	d := &DNSLeakTester{socksAddr: socksAddr, dnsServer: tunnelDNSResolver}
	d.resolveDirect = defaultResolveDirect
	d.resolveTunnel = d.defaultResolveTunnel
	return d
}

// QuickCheck выполняет быстрый локальный чек системных DNS — без сети, только чтение
// конфигурации ОС. Вызывается из Engine перед подключением (enableDeviceProtection):
// "leaked" здесь означает "система прямо сейчас использует видимый DNS-сервер, который НЕ
// защищён туннелем" — до подключения это верно всегда, если система вообще на что-то
// настроена (см. лог-сообщение "DNS сервер %s виден до VPN").
//
// P1 (аудит 2026-09-01, security-раздел, находка №15): раньше возвращался ЛИТЕРАЛЬНЫЙ
// `false` независимо от того, что нашла systemDNSServers() — функция физически не могла
// сообщить "утечка", даже вызванная с реальными системными DNS-серверами на руках. Это не
// "не находит утечку", это "не умеет её находить, но говорит, что не нашла" — тот самый
// класс дефекта, который значительно опаснее отсутствия проверки: пользователь видит
// определённый ответ и доверяет ему.
func (d *DNSLeakTester) QuickCheck(ctx context.Context) (bool, string) {
	_ = ctx
	servers := systemDNSServers()
	if len(servers) == 0 {
		return false, ""
	}
	return true, servers[0]
}

// Test проверяет, что DNS реально резолвится ЧЕРЕЗ туннель.
// Раньше тест всегда возвращал Leaked=false при открытом порту SOCKS, ничего
// не отправляя в туннель. Теперь выполняется настоящий DNS-запрос (DNS-over-TCP)
// через SOCKS5: если он не проходит — DNS идёт мимо туннеля (Leaked=true).
func (d *DNSLeakTester) Test(ctx context.Context) (*DNSLeakResult, error) {
	const probe = "cloudflare.com"
	system := systemDNSServers()
	res := &DNSLeakResult{
		SystemDNS: strings.Join(system, ", "),
		TunnelDNS: d.dnsServer,
		SystemIPs: system,
		TunnelIPs: []string{},
	}

	// Адрес туннеля не задан — проверять нечего.
	if d.socksAddr == "" {
		res.Leaked = false
		res.Diagnosis = "Адрес SOCKS-туннеля не задан — проверка DNS-через-туннель невозможна"
		res.Recommendation = "Подключите туннель APF и повторите тест"
		return res, nil
	}

	// Туннель недоступен — DNS гарантированно идёт в обход.
	if !portReachable(d.socksAddr, 1500*time.Millisecond) {
		res.Leaked = true
		res.Diagnosis = "SOCKS-туннель недоступен — DNS-запросы идут в обход туннеля"
		res.Recommendation = "Подключите туннель APF и повторите тест"
		return res, nil
	}

	// Главная проверка: проходит ли DNS-запрос через туннель.
	tctx, tcancel := context.WithTimeout(ctx, 8*time.Second)
	defer tcancel()
	ancount, terr := d.resolveTunnel(tctx, probe)
	if terr != nil || ancount <= 0 {
		res.Leaked = true
		res.Diagnosis = "DNS-запрос через туннель не прошёл — резолвер не маршрутизируется через туннель"
		if terr != nil {
			res.Diagnosis += ": " + terr.Error()
		}
		res.Recommendation = "Включите принудительный DNS-через-туннель (dns-настройки sing-box) и повторите тест"
		return res, nil
	}
	res.TunnelIPs = []string{d.dnsServer}

	// Информативно: системный (прямой) резолв. Туннель уже подтверждён рабочим.
	dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
	defer dcancel()
	_, _ = d.resolveDirect(dctx, probe)

	res.Leaked = false
	res.Diagnosis = "DNS успешно резолвится через туннель (" + d.dnsServer + ")"
	res.Recommendation = "Оставьте DNS-через-туннель включённым"
	return res, nil
}

// defaultResolveDirect — прямой системный резолв (мимо туннеля).
func defaultResolveDirect(ctx context.Context, domain string) (int, error) {
	ips, err := net.DefaultResolver.LookupHost(ctx, domain)
	if err != nil {
		return 0, err
	}
	return len(ips), nil
}

// defaultResolveTunnel — DNS-over-TCP запрос к d.dnsServer через SOCKS5-туннель.
func (d *DNSLeakTester) defaultResolveTunnel(ctx context.Context, domain string) (int, error) {
	conn, err := dialSOCKS5(ctx, d.socksAddr, d.dnsServer)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	return dnsQueryTCPCount(conn, domain)
}

// buildDNSQuery собирает минимальный DNS-запрос A-записи (RD=1).
func buildDNSQuery(id uint16, domain string) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:], id)
	binary.BigEndian.PutUint16(msg[2:], 0x0100) // flags: RD
	binary.BigEndian.PutUint16(msg[4:], 1)      // QDCOUNT
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			continue
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0x00)       // конец QNAME
	msg = append(msg, 0x00, 0x01) // QTYPE = A
	msg = append(msg, 0x00, 0x01) // QCLASS = IN
	return msg
}

// dnsQueryTCPCount отправляет DNS-запрос по TCP (RFC 7766) и возвращает ANCOUNT.
func dnsQueryTCPCount(conn net.Conn, domain string) (int, error) {
	id := randDNSTransactionID()
	q := buildDNSQuery(id, domain)

	framed := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(framed[0:], uint16(len(q)))
	copy(framed[2:], q)
	if _, err := conn.Write(framed); err != nil {
		return 0, err
	}

	lenBuf := make([]byte, 2)
	if _, err := readFull(conn, lenBuf); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(lenBuf))
	if n < 12 {
		return 0, fmt.Errorf("dns: short response (%d bytes)", n)
	}
	resp := make([]byte, n)
	if _, err := readFull(conn, resp); err != nil {
		return 0, err
	}
	if binary.BigEndian.Uint16(resp[0:]) != id {
		return 0, fmt.Errorf("dns: id mismatch")
	}
	flags := binary.BigEndian.Uint16(resp[2:])
	if flags&0x8000 == 0 {
		return 0, fmt.Errorf("dns: not a response")
	}
	if rcode := flags & 0x000F; rcode != 0 {
		return 0, fmt.Errorf("dns: rcode %d", rcode)
	}
	ancount := int(binary.BigEndian.Uint16(resp[6:]))
	return ancount, nil
}

// randDNSTransactionID — P1 (аудит 2026-09-01, security-раздел, LOW находка №22):
// math/rand вместо crypto/rand для DNS transaction ID. Запрос идёт по TCP через SOCKS5
// (dialSOCKS5), где подмена ответа требует контроля над соединением — практической
// эксплуатации нет, math/rand в этом качестве не был бы уязвимостью сам по себе. Но это
// диагностический код в security-пакете (тестер DNS-утечки), а crypto/rand здесь не стоит
// вообще ничего — переиспользуем стандартный, не самодельный источник случайности, тот же
// принцип, что уже применён в internal/crypto (см. её раздел аудита "замечаний по существу
// нет"). Диапазон 1..65535 сохранён как есть (0 — зарезервированное/невалидное значение ID
// в DNS-заголовке, RFC 1035 §4.1.1 трактует его как обычный ID, но исходная реализация его
// избегала — сохраняем поведение, не меняя диапазон заодно с источником).
func randDNSTransactionID() uint16 {
	var b [2]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		// crypto/rand.Read практически никогда не возвращает ошибку на поддерживаемых
		// платформах (буфер ОС недоступен — это уже фатальная проблема окружения, не эта
		// функция); best-effort откат на детерминированное ненулевое значение, лишь бы не
		// запаниковать — тестер DNS-утечки не должен падать хуже, чем полученный ID
		// оказался не случайным (эксплуатация всё равно упирается в TCP+SOCKS5, см. выше).
		return 1
	}
	id := binary.BigEndian.Uint16(b[:])
	if id == 0 {
		id = 1
	}
	return id
}

func portReachable(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// systemDNSServersFn — швы для тестов; по умолчанию realSystemDNSServers (platform-specific,
// dns_windows.go/dns_other.go).
//
// P1 (аудит 2026-09-01, security-раздел, находка №15): раньше здесь стоял
// lookupLocalHostFn — резолв имени "localhost", возвращавший ЕГО адреса (127.0.0.1/::1), а
// не настроенные DNS-серверы системы. Имя было обманчиво честным: похоже на «системный
// DNS», на деле не имеет к нему отношения.
var systemDNSServersFn = realSystemDNSServers

func systemDNSServers() []string {
	servers := systemDNSServersFn()
	if len(servers) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(servers))
	for _, s := range servers {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
