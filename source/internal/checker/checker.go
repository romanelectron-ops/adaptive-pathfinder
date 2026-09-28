// Package checker тестирует узлы: ping, jitter, потери пакетов, детект блокировок
package checker

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/netguard"
)

const (
	// ScoreKspeed — весовой коэффициент скорости в формуле Score
	ScoreKspeed = 1.5
	// PingTarget — цель для проверки доступности
	PingTarget = "www.google.com"
	// PingCount — количество пингов для усреднения
	PingCount = 5
	// BlacklistThreshold — количество ошибок до внесения в чёрный список
	BlacklistThreshold = 3
	// BlacklistDuration — длительность бана
	BlacklistDuration = 1 * time.Hour
	// RehabilitationSuccesses — успехов для реабилитации
	RehabilitationSuccesses = 3
)

// cfTraceURL is the endpoint used by HTTPHealthCheck. Override in tests.
var cfTraceURL = "https://1.1.1.1/cdn-cgi/trace"

// HealthCheckFallbackTargets — запасные цели для проверок ПОСЛЕ первой неудачной (по
// умолчанию, к cfTraceURL). Живой инцидент 2026-08-27 (пользователь из России, реальный
// прогон): туннель молча отработал ~7 минут (реальный трафик подтверждён), затем
// соединение оборвалось — и ПОСЛЕ этого ни один из следующих 11 узлов/протоколов
// (vless-reality, trojan-tls, vless-ws-cdn, trojan-cdn, vmess-ws, ss-obfs) не смог
// подтвердить канал: все они одинаково не достучались до ОДНОГО И ТОГО ЖЕ 1.1.1.1.
// Правдоподобное объяснение — адресная/временная деградация именно этого IP по пути
// (1.1.1.1 — известная и часто отдельно регулируемая цель), а не отказ реальных узлов.
// Единственная проверочная цель — единая точка отказа самой диагностики. Google и
// Cloudflare-по-домену — другой ASN/путь резолвинга, не гарантия, но не тот же самый
// единственный адрес.
var HealthCheckFallbackTargets = []string{
	"https://www.gstatic.com/generate_204",
	"https://cloudflare.com/cdn-cgi/trace",
}

// Checker — движок проверки узлов
type Checker struct {
	concurrency int
	timeout     time.Duration
	httpClient  *http.Client
	// dialFn is used by measureLatency. Defaults to net.DialTimeout. Override in tests.
	dialFn func(network, addr string, timeout time.Duration) (net.Conn, error)
}

// New создаёт новый Checker
func New(concurrency int, timeoutSec int) *Checker {
	timeout := time.Duration(timeoutSec) * time.Second
	return &Checker{
		concurrency: concurrency,
		timeout:     timeout,
		dialFn:      net.DialTimeout,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				// netguard.Guard: под `go test` выход за пределы петли отвергается (Т-5).
				// Собственный Dialer сохранён — у проверки узлов свои таймауты.
				DialContext: netguard.Guard((&net.Dialer{
					Timeout:   timeout,
					KeepAlive: 30 * time.Second,
				}).DialContext),
				TLSHandshakeTimeout: 5 * time.Second,
			},
		},
	}
}

// CheckAll проверяет список узлов параллельно и возвращает результаты
func (c *Checker) CheckAll(ctx context.Context, nodes []*models.Node) []*models.CheckResult {
	return c.CheckAllWith(ctx, nodes, c.concurrency, PingCount)
}

// CheckAllWith — CheckAll с явными конкурентностью и числом проб (ТЗ v1.3 F4 Stage 1: обход
// всего пула — один DialTimeout на узел при конкурентности 200, а не 5 проб при 10-50; полная
// серия остаётся для переверификации уже живых).
func (c *Checker) CheckAllWith(ctx context.Context, nodes []*models.Node, concurrency, pings int) []*models.CheckResult {
	if concurrency <= 0 {
		concurrency = c.concurrency
	}
	if pings <= 0 {
		pings = PingCount
	}
	sem := make(chan struct{}, concurrency)
	results := make([]*models.CheckResult, len(nodes))
	var wg sync.WaitGroup

	for i, node := range nodes {
		wg.Add(1)
		go func(idx int, n *models.Node) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			results[idx] = c.checkOneN(ctx, n, pings)
		}(i, node)
	}

	wg.Wait()
	return results
}

// CheckOne проверяет один узел и обновляет его метрики
func (c *Checker) CheckOne(ctx context.Context, node *models.Node) *models.CheckResult {
	return c.checkOneN(ctx, node, PingCount)
}

// CheckOneFast — одна TCP-проба (Stage 1 обхода пула): быстрый ответ «жив/мёртв» + RTT.
func (c *Checker) CheckOneFast(ctx context.Context, node *models.Node) *models.CheckResult {
	return c.checkOneN(ctx, node, 1)
}

func (c *Checker) checkOneN(ctx context.Context, node *models.Node, pings int) *models.CheckResult {
	result := &models.CheckResult{Node: node}

	// ТЗ v1.3 F1.1 (консилиум 2026-09-03, BB-1/ND-8): отменённый контекст — это НЕ отказ узла.
	// Раньше measureLatency возвращала ctx.Err() как обычную ошибку, и узел получал markFail
	// (Score=0, Status=blocked, FailCount++), причём для всего батча CheckAll — включая узлы,
	// которые ещё ждали семафора и до которых проба вообще не дошла. Три Disconnect/Restart
	// посреди скана = бан на час всего, что было в очереди. Отмена — отсутствие информации:
	// узел не трогаем ни до пробы, ни если отмена пришла посреди неё.
	if ctx.Err() != nil {
		result.Outcome = models.OutcomeNotChecked
		result.Error = ctx.Err().Error()
		return result
	}

	// Проверяем TCP-доступность
	latencies, err := c.measureLatencyN(ctx, node, pings)
	if ctx.Err() != nil {
		// Отмена во время пробы: даже если часть сэмплов успела собраться, они неполны и не
		// сравнимы с полной серией — честнее не записывать ничего (см. контракт B1).
		result.Outcome = models.OutcomeNotChecked
		result.Error = ctx.Err().Error()
		return result
	}
	if err != nil {
		result.Outcome = models.OutcomeFail
		result.Success = false
		result.Error = err.Error()
		c.markFail(node, err.Error())
		return result
	}

	// Считаем статистику
	avg, jitter, loss := calcStats(latencies)

	result.Outcome = models.OutcomeOK
	result.Success = true
	result.Latency = avg
	result.Jitter = jitter
	result.Loss = loss

	// Обновляем узел
	node.Latency = avg
	node.Jitter = jitter
	node.Loss = loss
	// P1-4 (аудит 2026-09-01): LastChecked обновляется ДО расчёта Score.
	// Раньше порядок был обратный, и calcScore получал возраст ПРЕДЫДУЩЕЙ проверки. Для узла,
	// который проверяется впервые, AgeSeconds() = 99999 (models/node.go), то есть ageFactor
	// ≈ 56.6 — отличный узел со 100 мс получал Score 0.177 вместо 10. На пути ScanAndConnect
	// это маскировалось пересчётом в selectBestForStrategy, но selectBestExcluding (путь
	// аварийного переключения) сортирует по СОХРАНЁННОМУ Score — и свежепроверенные хорошие
	// узлы оказывались внизу списка.
	node.LastChecked = time.Now()
	node.Status = classifyStatus(avg, loss)
	// ТЗ v1.3 F1.4: одна шкала Score на весь проект. Раньше сюда писался сырой calcScore
	// (1000/latency, до 20+), а selectBestForStrategy перезаписывал часть пула взвешенной
	// оценкой в другой шкале — selectBestExcluding сортировал смесь (NL-5). Теперь оба писателя
	// используют CalcScoreWeighted (нормированный base + бонусы протокола/источника), здесь —
	// с весами «balanced»; стратегический выбор пересчитает под свой режим той же формулой.
	node.Score = CalcScoreWeighted(node, WeightsForMode("balanced"), 0)

	if node.Status == models.StatusOK || node.Status == models.StatusSlow {
		node.SuccessCount++
		node.FailCount = 0
		// Реабилитация из чёрного списка
		if node.SuccessCount >= RehabilitationSuccesses {
			node.BlacklistedUntil = time.Time{}
		}
	}

	return result
}

// QuickPing быстро проверяет доступность узла (только один TCP-коннект)
func (c *Checker) QuickPing(ctx context.Context, node *models.Node) (int64, error) {
	addr := net.JoinHostPort(node.Address, fmt.Sprintf("%d", node.Port))
	start := time.Now()

	conn, err := net.DialTimeout("tcp", addr, c.timeout)
	if err != nil {
		return 0, detectBlockType(err)
	}
	conn.Close()
	return time.Since(start).Milliseconds(), nil
}

// HTTPHealthCheck проверяет реальное прохождение HTTP через туннель.
// Из tunnel-architect skill: health-check через HTTP (не только TCP ping).
// Использует Cloudflare trace endpoint который возвращает IP и страну.
func (c *Checker) HTTPHealthCheck(ctx context.Context, proxyAddr string) (latency int64, country string, err error) {
	return c.HTTPHealthCheckAt(ctx, proxyAddr, cfTraceURL)
}

// DefaultHealthCheckURL — цель первой пробы (cdn-cgi/trace; переопределяется в тестах через
// cfTraceURL). Экспорт нужен движку (verifyTunnelHealthInfo), чтобы не дублировать константу.
func DefaultHealthCheckURL() string { return cfTraceURL }

// HTTPHealthCheckAt — то же самое, что HTTPHealthCheck, но с явно заданной целью. См.
// HealthCheckFallbackTargets: runPostConnectHealthCheck (internal/engine/engine.go)
// использует её для повторных проб через ДРУГОЙ адрес вместо повторного удара по тому
// же самому, который мог оказаться именно тем, что сейчас недоступен по пути.
func (c *Checker) HTTPHealthCheckAt(ctx context.Context, proxyAddr, targetURL string) (latency int64, country string, err error) {
	info, err := c.HTTPHealthCheckInfoAt(ctx, proxyAddr, targetURL)
	return info.LatencyMs, info.Country, err
}

// HealthInfo — результат HTTP-проверки через туннель (ТЗ v1.3 F1.2): всё, что нужно, чтобы
// записать подтверждение в узел (models.Node.LastVerified*), а не выбросить (NL-1).
type HealthInfo struct {
	LatencyMs int64
	Country   string // loc= из cdn-cgi/trace; пусто у целей без него
	ExitIP    string // ip= из cdn-cgi/trace; пусто у целей без него
}

// HTTPHealthCheckInfoAt — то же, что HTTPHealthCheckAt, но возвращает и exit-IP (строка `ip=`
// cdn-cgi/trace). Раньше парсилась только `loc=`, и IP выхода терялся (V3 к NL-1).
func (c *Checker) HTTPHealthCheckInfoAt(ctx context.Context, proxyAddr, targetURL string) (HealthInfo, error) {
	var info HealthInfo
	latency, country, exitIP, err := c.httpHealthProbe(ctx, proxyAddr, targetURL)
	info.LatencyMs, info.Country, info.ExitIP = latency, country, exitIP
	return info, err
}

// HTTPHealthCheckDirectInfoAt — ПРЯМАЯ проба той же цели тем же разбором ответа, но БЕЗ
// SOCKS-диалера: обычный транспорт, обычный http.Client, сокет открывается так же, как его
// открыло бы любое приложение на этой машине (LOT-09).
//
// ЗАЧЕМ ОНА ВООБЩЕ НУЖНА. HTTPHealthCheckInfoAt (проба через SOCKS) доказывает ровно одно:
// исходящий канал sing-box до узла жив. Приложения пользователя ходят не туда — они ходят
// через TUN-интерфейс, а socks-in и tun-in в sing-box два НЕЗАВИСИМЫХ inbound-пути. Отсюда
// расхождение, записанное живым прогоном 2026-08-11: проверка зелёная, а Chrome не открывает
// ни одного сайта. Прямая проба уходит именно в TUN — на Android VpnService.protect()
// применяется только к исходящим сокетам самого sing-box (AutoDetectInterfaceControl в
// mobile/androidbridge/platform_adapter.go), а не ко всему процессу, поэтому обычный
// HTTP-запрос из Go-кода приложения перехватывается VpnService ровно как трафик браузера.
// Петли не образуется: приложение → TUN → tun-in → маршрутизация → защищённый исходящий
// сокет → узел.
//
// БАРЬЕР netguard ОБЯЗАТЕЛЕН, в отличие от пробы через SOCKS (там его нет осознанно — тот
// сокет уходит на петлю). Здесь адрес НАСТОЯЩИЙ внешний, и без барьера `go test` полез бы в
// интернет — ровно то, что netguard существует запрещать. Приём тот же, что в
// internal/fallback/watchdog.go.
//
// Прокси НЕ используется: поле Proxy у свежего http.Transport остаётся nil (в отличие от
// http.DefaultTransport с его ProxyFromEnvironment). Это принципиально — проба обязана идти
// тем же путём, что трафик приложений в TUN-режиме, а не через системный/переменных-окружения
// прокси, который в этом режиме APF и не выставляет.
func (c *Checker) HTTPHealthCheckDirectInfoAt(ctx context.Context, targetURL string) (HealthInfo, error) {
	var info HealthInfo
	latency, country, exitIP, err := c.httpHealthProbeDirect(ctx, targetURL)
	info.LatencyMs, info.Country, info.ExitIP = latency, country, exitIP
	return info, err
}

func (c *Checker) httpHealthProbeDirect(ctx context.Context, targetURL string) (latency int64, country, exitIP string, err error) {
	transport := &http.Transport{
		DialContext: netguard.Guard((&net.Dialer{
			Timeout:   c.timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext),
		TLSHandshakeTimeout: 5 * time.Second,
	}
	return c.runHealthProbe(ctx, transport, targetURL)
}

func (c *Checker) httpHealthProbe(ctx context.Context, proxyAddr, targetURL string) (latency int64, country, exitIP string, err error) {
	// Создаём HTTP клиент через SOCKS5 прокси туннеля
	transport := &http.Transport{
		// Барьера netguard здесь НЕТ, и это осознанно: сокет уходит на proxyAddr —
		// SOCKS самого APF на петле. См. подробное объяснение в fallback/watchdog.go.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Подключаемся через локальный SOCKS5 APF
			return dialViaSOCKS5(ctx, proxyAddr, addr, c.timeout)
		},
		TLSHandshakeTimeout: 5 * time.Second,
	}
	return c.runHealthProbe(ctx, transport, targetURL)
}

// runHealthProbe — общее тело обеих проб: запрос, единый критерий «канал живой», разбор
// loc=/ip=. Транспорт (и только он) отличает пробу через SOCKS от прямой — результаты
// обязаны быть сравнимы, поэтому таймауты, трактовка статуса и парсер ровно одни и те же.
func (c *Checker) runHealthProbe(ctx context.Context, transport *http.Transport, targetURL string) (latency int64, country, exitIP string, err error) {
	client := &http.Client{
		Timeout:   c.timeout,
		Transport: transport,
	}

	start := time.Now()
	// Cloudflare trace (или запасная цель) — возвращает IP, страну, протокол (не все
	// запасные цели отдают loc=, тогда country остаётся пустой строкой — не ошибка).
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return 0, "", "", err
	}
	resp, err := client.Do(req)
	latency = time.Since(start).Milliseconds()
	if err != nil {
		return latency, "", "", fmt.Errorf("HTTP health check failed: %w", err)
	}
	defer resp.Body.Close()

	// Единый критерий «канал живой» (введён 2026-08-24 по итогам ревью).
	//
	// Раньше здесь стояло строгое `!= 200`, и один и тот же URL трактовался в проекте ТРЕМЯ
	// разными способами: здесь — только 200, watchdog (fallback/watchdog.go) — провал лишь
	// при >= 500, urltest внутри sing-box — вообще не смотрит статус. Из-за этого возникало
	// состояние «watchdog видит узел здоровым, а верификация — навсегда непройденной», в
	// котором Android через 180 секунд гасил РАБОЧИЙ туннель.
	//
	// Что мы на самом деле проверяем — дошёл ли HTTP-ответ через туннель. Любой ответ от
	// настоящего сервера это доказывает, включая 403/429 (Cloudflare часто отдаёт их на
	// адреса дата-центров — а это как раз обычная ситуация для бесплатных узлов). Провалом
	// считаем ошибку транспорта (её ловит ветка выше) и 5xx — ответ промежуточного звена,
	// а не конечного сервера.
	if resp.StatusCode >= 500 {
		return latency, "", "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Парсим страну и IP выхода из ответа cdn-cgi/trace ("loc=US", "ip=1.2.3.4"); у запасных
	// целей (generate_204) тела нет — оба поля остаются пустыми, это не ошибка.
	body := make([]byte, 512)
	n, _ := io.ReadFull(resp.Body, body)
	bodyStr := string(body[:n])
	for _, line := range strings.Split(bodyStr, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "loc="):
			country = strings.TrimPrefix(line, "loc=")
		case strings.HasPrefix(line, "ip="):
			exitIP = strings.TrimPrefix(line, "ip=")
		}
	}

	return latency, country, exitIP, nil
}

// dialViaSOCKS5 устанавливает TCP-соединение к targetAddr ЧЕРЕЗ локальный
// SOCKS5-прокси proxyAddr, выполняя полноценный SOCKS5 CONNECT-хендшейк
// (метод "без аутентификации", RFC 1928). Без внешних зависимостей.
// Используется HTTPHealthCheck для реальной проверки прохождения трафика
// через туннель (а не сырого TCP-коннекта к порту прокси).
func dialViaSOCKS5(ctx context.Context, proxyAddr, targetAddr string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5: dial proxy %s: %w", proxyAddr, err)
	}

	// Дедлайн только на время хендшейка (минимум из timeout и ctx-дедлайна).
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	// 1) Приветствие: VER=5, NMETHODS=1, METHOD=0x00 (no-auth).
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: write greeting: %w", err)
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(conn, rep); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: read method reply: %w", err)
	}
	if rep[0] != 0x05 || rep[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5: no-auth rejected (ver=%d method=%d)", rep[0], rep[1])
	}

	// 2) Запрос CONNECT: VER, CMD=1, RSV=0, ATYP, ADDR, PORT.
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: split target %q: %w", targetAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		conn.Close()
		return nil, fmt.Errorf("socks5: bad port %q", portStr)
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			conn.Close()
			return nil, fmt.Errorf("socks5: hostname too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port&0xff))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: write connect: %w", err)
	}

	// 3) Ответ: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT.
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: read connect reply: %w", err)
	}
	if head[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("socks5: bad reply version %d", head[0])
	}
	if head[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5: connect failed (rep=%d)", head[1])
	}
	var bndLen int
	switch head[3] {
	case 0x01:
		bndLen = 4
	case 0x04:
		bndLen = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5: read bnd len: %w", err)
		}
		bndLen = int(l[0])
	default:
		conn.Close()
		return nil, fmt.Errorf("socks5: unknown ATYP %d", head[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, bndLen+2)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: read bnd addr: %w", err)
	}

	// Хендшейк завершён — снимаем дедлайн, дальше обычный HTTP/TLS поверх туннеля.
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// DetectDPIBlock проверяет признаки DPI-блокировки
// Возвращает true если соединение сброшено активно (TCP RST)
func (c *Checker) DetectDPIBlock(ctx context.Context, node *models.Node) bool {
	addr := net.JoinHostPort(node.Address, fmt.Sprintf("%d", node.Port))

	// Быстрое подключение
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		errStr := err.Error()
		// RST = активный сброс = признак DPI/файрвола
		return isRSTError(errStr)
	}
	conn.Close()
	return false
}

// --- Внутренние методы ---

func (c *Checker) measureLatency(ctx context.Context, node *models.Node) ([]int64, error) {
	return c.measureLatencyN(ctx, node, PingCount)
}

// measureLatencyN — серия из pings TCP-проб (1 — быстрый обход пула, PingCount — полная статистика).
func (c *Checker) measureLatencyN(ctx context.Context, node *models.Node, pings int) ([]int64, error) {
	if pings <= 0 {
		pings = PingCount
	}
	addr := net.JoinHostPort(node.Address, fmt.Sprintf("%d", node.Port))
	var latencies []int64
	var lastErr error

	// consecutiveFails — живой инцидент 2026-08-27 (жалоба «всё делает очень медленно»):
	// "Testing 50 nodes" стабильно занимало 25-30с. Причина — мёртвый узел (обычная
	// ситуация для собранных агрегаторами бесплатных списков) раньше всегда платил
	// ПОЛНЫЕ PingCount=5 попыток по timeout каждая (до ~26с на один узел), и CheckAll не
	// мог завершиться, пока не отработает самый медленный. Если calcStats/calcScore
	// (вызывающая сторона, CheckOne) ВСЁ РАВНО не смотрят на latencies при полном отказе
	// (successes==0 ⇒ возвращается ошибка, а не сырые сэмплы), нет смысла добирать все 5
	// попыток ради статистики, которую никто не прочитает. Обрываем ПОСЛЕ 2 подряд
	// неудач С НАЧАЛА (не после первой — единичный сетевой всплеск не должен решать
	// судьбу узла) вместо всех 5 — рабочий узел, у которого первая же попытка успешна,
	// этой веткой не задевается вовсе (по нему набираются полные 5 для честной статистики
	// джиттера/потерь).
	sawSuccess := false
	failsSinceStart := 0
	for i := 0; i < pings; i++ {
		select {
		case <-ctx.Done():
			return latencies, ctx.Err()
		default:
		}

		start := time.Now()
		conn, err := c.dialFn("tcp", addr, c.timeout)
		elapsed := time.Since(start).Milliseconds()

		if err != nil {
			lastErr = detectBlockType(err)
			// Считаем это потерей пакета
			latencies = append(latencies, 0) // 0 = потеря
			if !sawSuccess {
				failsSinceStart++
				if failsSinceStart >= 2 {
					break // узел, скорее всего, мёртв — не тратим оставшиеся попытки
				}
			}
			time.Sleep(200 * time.Millisecond)
			continue
		}
		conn.Close()
		// 0 в latencies — сентинел ПОТЕРИ для calcStats. Успешный dial быстрее 1 мс (loopback,
		// LAN, локальный relay/точка входа цепочки) округлялся в 0 и считался потерей: пять
		// удачных проб давали «all pings failed: <nil>» (найдено go test -race 2026-09-05,
		// ТЗ v1.3 F2 — узел на 127.0.0.1 выглядел мёртвым).
		if elapsed <= 0 {
			elapsed = 1
		}
		latencies = append(latencies, elapsed)
		sawSuccess = true
		if i < pings-1 {
			time.Sleep(200 * time.Millisecond) // пауза между пробами; после последней — не нужна
		}
	}

	// Если все 0 — узел недоступен
	successes := 0
	for _, l := range latencies {
		if l > 0 {
			successes++
		}
	}
	if successes == 0 {
		return latencies, fmt.Errorf("all pings failed: %v", lastErr)
	}
	return latencies, nil
}

func (c *Checker) markFail(node *models.Node, reason string) {
	node.FailCount++
	node.SuccessCount = 0
	node.LastChecked = time.Now()
	node.Status = models.StatusBlocked

	// P1-3 (аудит 2026-09-01): Score обнуляется вместе с отметкой об отказе.
	//
	// Раньше markFail обновляла LastChecked, но НЕ трогала Latency и НЕ пересчитывала Score.
	// Механика дефекта: у только что провалившегося узла оставалась старая хорошая задержка
	// (скажем, 50 мс), а возрастной штраф обнулялся свежим LastChecked — и пересчёт в
	// selectBestForStrategy давал ему base = 1000/50 = 20 против 1.25 у живого узла с 800 мс.
	// Мёртвый узел систематически занимал первое место и выигрывал КАЖДЫЙ выбор, пока не
	// наберёт три отказа подряд для чёрного списка. Это и есть механическое объяснение
	// жалобы «первый „лучший“ узел часто мёртв» (память apf-russia-nodes-no-internet).
	//
	// Latency оставляем как есть (это последнее известное ИЗМЕРЕНИЕ, оно информативно для UI),
	// но Score — это оценка пригодности, и для узла, который сейчас не отвечает, она равна нулю.
	node.Score = 0

	if node.FailCount >= BlacklistThreshold {
		node.BlacklistedUntil = time.Now().Add(BlacklistDuration)
		node.Status = models.StatusBlacklist
	}
	_ = reason
}

// --- Формула Score ---
// Score — нормализованная оценка узла в диапазоне 0..1
// Формула: 1000 / (Latency × PenaltyLoss × PenaltyJitter × AgeFactor)
// Нормировка на 1000мс — при latency=100ms, 0% loss, jitter=0 → score=1.0
func calcScore(latencyMs, jitterMs int64, lossPct, speedMbps, ageSeconds float64) float64 {
	if latencyMs <= 0 {
		latencyMs = 9999
	}

	// AgeFactor: свежий тест (0 сек) = 1.0, 30 мин = 2.0
	ageFactor := 1.0 + (ageSeconds / 1800.0)

	// Штраф за потери: 10% loss → ×2, 50% loss → ×6
	penaltyLoss := 1.0 + (lossPct / 10.0)

	// Штраф за джиттер: мягкий — 100мс jitter → ×1.1 (не ×51!)
	penaltyJitter := 1.0 + (float64(jitterMs) / 1000.0)

	denominator := float64(latencyMs) * penaltyLoss * penaltyJitter * ageFactor

	if denominator <= 0 {
		return 0
	}

	// Нормировка: 1000 / denominator
	// Примеры при свежем тесте (ageFactor=1):
	//   latency=50ms,  loss=0%,  jitter=10ms  в†’ score = 1000/50   = 20.0 (РѕС‚Р»РёС‡РЅРѕ)
	//   latency=150ms, loss=0%,  jitter=50ms  в†’ score = 1000/225  = 4.4  (С…РѕСЂРѕС€Рѕ)
	//   latency=300ms, loss=5%,  jitter=100ms в†’ score = 1000/780  = 1.3  (РЅРѕСЂРј)
	//   latency=500ms, loss=20%, jitter=200ms в†’ score = 1000/4500 = 0.2  (РїР»РѕС…Рѕ)
	score := 1000.0 / denominator

	// Если скорость известна — добавляем бонус (не штраф)
	if speedMbps > 1.0 {
		score *= (1.0 + speedMbps/100.0)
	}

	return score
}

// calcStats считает среднее, джиттер и процент потерь из серии измерений
func calcStats(latencies []int64) (avgMs, jitterMs int64, lossPct float64) {
	if len(latencies) == 0 {
		return 9999, 9999, 100.0
	}

	var sum int64
	var valid []int64
	losses := 0

	for _, l := range latencies {
		if l == 0 {
			losses++
		} else {
			valid = append(valid, l)
			sum += l
		}
	}

	lossPct = float64(losses) / float64(len(latencies)) * 100.0

	if len(valid) == 0 {
		return 9999, 9999, lossPct
	}

	avgMs = sum / int64(len(valid))

	// Джиттер = стандартное отклонение задержек
	var variance float64
	for _, l := range valid {
		diff := float64(l - avgMs)
		variance += diff * diff
	}
	variance /= float64(len(valid))
	jitterMs = int64(math.Sqrt(variance))

	return avgMs, jitterMs, lossPct
}

func classifyStatus(latencyMs int64, lossPct float64) models.NodeStatus {
	if lossPct > 50 {
		return models.StatusBlocked
	}
	if latencyMs > 1000 || lossPct > 20 {
		return models.StatusSlow
	}
	return models.StatusOK
}

// detectBlockType анализирует ошибку и определяет тип блокировки
func detectBlockType(err error) error {
	if err == nil {
		return nil
	}
	errStr := err.Error()
	if isRSTError(errStr) {
		return fmt.Errorf("DPI block (TCP RST): %w", err)
	}
	if isTimeoutError(errStr) {
		return fmt.Errorf("timeout (firewall drop): %w", err)
	}
	return err
}

func isRSTError(s string) bool {
	return strings.Contains(s, "connection reset") ||
		strings.Contains(s, "connection refused") ||
		strings.Contains(s, "forcibly closed")
}

func isTimeoutError(s string) bool {
	return strings.Contains(s, "timeout") ||
		strings.Contains(s, "timed out") ||
		strings.Contains(s, "i/o timeout")
}
