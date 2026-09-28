// watchdog.go — Watchdog для APF туннеля. Фаза 7/9.
// Мониторит здоровье туннеля и перезапускает при зависании.
// Отличие от monitorLoop в engine: watchdog работает на уровне HTTP-достижимости,
// а не только TCP ping до узла.
package fallback

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// WatchdogConfig — настройки watchdog
type WatchdogConfig struct {
	CheckInterval time.Duration `json:"check_interval"`
	FailThreshold int           `json:"fail_threshold"`
	CheckURL      string        `json:"check_url"`
	CheckTimeout  time.Duration `json:"check_timeout"`
	ProxyAddr     string        `json:"proxy_addr"`

	// FallbackCheckURLs — цели ДЛЯ ПРОВЕРОК ПОСЛЕ первого подряд идущего провала (см.
	// doCheck). Живой инцидент 2026-08-27 (пользователь из России): 1.1.1.1 (CheckURL по
	// умолчанию) стало недостижимо ПОСРЕДИ рабочей сессии — туннель отработал ~7 минут
	// молча, потом связь с ЭТИМ ОДНИМ адресом оборвалась, и watchdog копил провалы против
	// него же каждые 15с, пока не набрал FailThreshold и не объявил туннель мёртвым, хотя
	// сам туннель мог быть жив. Если все FailThreshold провалов подряд бьют в один и тот
	// же адрес, его адресная блокировка/деградация неотличима от настоящей смерти
	// туннеля. Пустой (nil) — старое поведение, всегда один CheckURL: намеренно НЕ
	// заполняется по умолчанию здесь конструктором с нулевыми полями (только
	// DefaultWatchdogConfig ниже), чтобы тесты, собирающие WatchdogConfig{} вручную
	// (например watchdog_extra_test.go, TestCheck_RecoverCallback — предсеет FailCount
	// без похода через NewWatchdog), не ловили эту ротацию неожиданно.
	FallbackCheckURLs []string `json:"fallback_check_urls,omitempty"`
}

// DefaultWatchdogConfig — рекомендуемые настройки
func DefaultWatchdogConfig(socksAddr string) *WatchdogConfig {
	return &WatchdogConfig{
		CheckInterval: 15 * time.Second,
		FailThreshold: 3,
		CheckURL:      "https://1.1.1.1/cdn-cgi/trace",
		CheckTimeout:  8 * time.Second,
		ProxyAddr:     socksAddr,
		FallbackCheckURLs: []string{
			"https://www.gstatic.com/generate_204",
			"https://cloudflare.com/cdn-cgi/trace",
		},
	}
}

// WatchdogState — состояние watchdog
type WatchdogState string

const (
	WatchdogIdle     WatchdogState = "idle"
	WatchdogHealthy  WatchdogState = "healthy"
	WatchdogDegraded WatchdogState = "degraded"
	WatchdogFailed   WatchdogState = "failed"
)

// WatchdogStatus — текущий статус
type WatchdogStatus struct {
	State       WatchdogState `json:"state"`
	FailCount   int           `json:"fail_count"`
	LastCheckAt time.Time     `json:"last_check_at"`
	LastError   string        `json:"last_error,omitempty"`
	LatencyMs   int64         `json:"latency_ms"`
	TotalChecks int           `json:"total_checks"`
	TotalFails  int           `json:"total_fails"`
}

// Watchdog мониторит туннель APF через HTTP-проверку.
// Вызывает OnDead когда туннель умер — engine реагирует переключением.
type Watchdog struct {
	mu     sync.RWMutex
	cfg    *WatchdogConfig
	status WatchdogStatus
	client *http.Client
	log    func(string)

	// everSucceeded — прошла ли ХОТЯ БЫ ОДНА проверка успешно с момента последнего Reset()
	// (т.е. с момента текущего подключения — Reset() зовётся из applySingBoxConfig на
	// каждый (пере)коннект). Отличается от status.FailCount==0: последнее могло стать
	// нулём просто потому что проверок ещё не было. Нужно engine.emergencySwitch(), чтобы
	// отличить «узел недавно работал, сейчас деградировал» (грация уместна) от «узел не
	// прошёл ни одной проверки с момента подключения» (грация только держит мёртвый узел).
	everSucceeded bool

	OnFail    func(failCount int, lastErr string)
	OnRecover func()
	OnDead    func()

	// OnHealthy — КАЖДАЯ успешная проверка, а не только переход «был провал → снова жив»
	// (для последнего есть OnRecover). Добавлен 2026-09-06: движку нужно продлевать свежесть
	// подтверждения активного узла (Node.LastVerifiedAt). До этого единственным писателем этого
	// поля был пост-коннект health-check — то есть один раз на подключение, — а сторож каждые
	// 15 секунд честно доказывал HTTP-запросом ЧЕРЕЗ туннель, что канал жив, и выбрасывал это
	// знание: «проверенность» узла затухала по экспоненте прямо во время стабильной сессии,
	// когда трафик заведомо шёл. nil — прежнее поведение.
	OnHealthy func(latencyMs int64)

	// ShouldCheck — есть ли сейчас туннель, о здоровье которого можно судить (дефект D-A25).
	//
	// Сторож проверяет достижимость ЧЕРЕЗ SOCKS самого APF. Пока подключения нет, этого
	// SOCKS тоже нет, и каждая проверка обязана провалиться — не потому, что туннель болен,
	// а потому, что туннеля не существует. Раньше предиката не было, и к первому нажатию
	// «Подключить» на телефоне уже накапливалось `Watchdog: DEAD (266 failures)`, а FSM
	// доходил до `all levels exhausted, attempt #33`. То есть первое подключение начиналось
	// в состоянии «всё уже перепробовано и всё мертво».
	//
	// nil означает «проверять всегда» — прежнее поведение для тех, кто предикат не задал.
	ShouldCheck func() bool

	historyLog []string // кольцевой лог событий для диагностики
}

// NewWatchdog создаёт watchdog
func NewWatchdog(cfg *WatchdogConfig, logFn func(string)) *Watchdog {
	if cfg == nil {
		cfg = DefaultWatchdogConfig("127.0.0.1:10808")
	}
	if logFn == nil {
		logFn = func(s string) {}
	}
	w := &Watchdog{
		cfg:        cfg,
		log:        logFn,
		status:     WatchdogStatus{State: WatchdogIdle},
		historyLog: []string{"watchdog initialized"},
	}
	w.rebuildClient()
	return w
}

// rebuildClient создаёт HTTP клиент который ходит через SOCKS5 прокси APF.
// При check — запрос идёт через туннель, значит если туннель мёртв — запрос провалится.
func (w *Watchdog) rebuildClient() {
	proxyAddr := w.cfg.ProxyAddr
	timeout := w.cfg.CheckTimeout
	w.client = &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// Барьера netguard здесь НЕТ, и это осознанно. Сокет отсюда уходит на
			// proxyAddr — SOCKS самого APF на петле; дальше трафик выпускает sing-box,
			// отдельный процесс, до которого этот барьер не достаёт. Обёртка на этом
			// уровне проверяла бы адрес НАЗНАЧЕНИЯ вместо адреса соединения и запрещала
			// бы тесты с фиктивным SOCKS-сервером, которые сеть не трогают вовсе.
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// Подключаемся к SOCKS5 прокси APF, он пробросит к addr
				d := &net.Dialer{Timeout: timeout}
				conn, err := d.DialContext(ctx, "tcp", proxyAddr)
				if err != nil {
					return nil, fmt.Errorf("socks5 dial %s: %w", proxyAddr, err)
				}
				// Минимальный SOCKS5 handshake (no-auth + CONNECT)
				if err := doSOCKS5Connect(conn, addr, timeout); err != nil {
					conn.Close()
					return nil, err
				}
				return conn, nil
			},
			TLSHandshakeTimeout: timeout,
		},
		// Не следуем редиректам — нам достаточно первого ответа
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Run запускает watchdog в фоне. Блокирует до отмены ctx.
func (w *Watchdog) Run(ctx context.Context) {
	w.log("Watchdog: started")
	w.mu.Lock()
	w.status.State = WatchdogHealthy
	w.mu.Unlock()

	ticker := time.NewTicker(w.cfg.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.mu.Lock()
			w.status.State = WatchdogIdle
			w.mu.Unlock()
			w.log("Watchdog: stopped")
			return
		case <-ticker.C:
			w.check(ctx)
		}
	}
}

func (w *Watchdog) check(ctx context.Context) {
	// Дефект D-A25. Нет подключения — нет предмета проверки. Молчание здесь честнее
	// приговора: судить о здоровье того, чего нет, невозможно.
	//
	// Счётчики при этом сбрасываются, а не просто замораживаются. Иначе отказы, набранные
	// до отключения, дожили бы до следующего подключения и приговорили бы его чужой
	// историей — ровно это и делало Э-6 (100 циклов) бессмысленным: поведение на сотом
	// цикле определялось бы накопленным мусором, а не самим циклом.
	if w.ShouldCheck != nil && !w.ShouldCheck() {
		w.mu.Lock()
		if w.status.FailCount != 0 || w.status.State != WatchdogIdle {
			w.status.FailCount = 0
			w.status.LastError = ""
			w.status.LatencyMs = 0
			w.status.State = WatchdogIdle
		}
		w.mu.Unlock()
		return
	}

	checkCtx, cancel := context.WithTimeout(ctx, w.cfg.CheckTimeout)
	defer cancel()

	w.mu.Lock()
	w.status.TotalChecks++
	w.status.LastCheckAt = time.Now()
	w.mu.Unlock()

	start := time.Now()
	err := w.doCheck(checkCtx)
	latency := time.Since(start).Milliseconds()

	w.mu.Lock()
	defer w.mu.Unlock()

	if err != nil {
		w.status.FailCount++
		w.status.TotalFails++
		w.status.LastError = err.Error()
		w.status.LatencyMs = 0

		if w.status.FailCount >= w.cfg.FailThreshold {
			w.status.State = WatchdogFailed
			w.log(fmt.Sprintf("Watchdog: DEAD (%d failures): %v", w.status.FailCount, err))
			if w.OnDead != nil {
				go w.OnDead()
			}
		} else {
			w.status.State = WatchdogDegraded
			w.log(fmt.Sprintf("Watchdog: FAIL #%d/%d: %v",
				w.status.FailCount, w.cfg.FailThreshold, err))
			if w.OnFail != nil {
				go w.OnFail(w.status.FailCount, err.Error())
			}
		}
	} else {
		wasFailured := w.status.FailCount > 0
		w.everSucceeded = true
		w.status.FailCount = 0
		w.status.LastError = ""
		w.status.LatencyMs = latency
		w.status.State = WatchdogHealthy
		// Через `go`, как OnDead/OnRecover ниже: обработчик вызывается под w.mu, а движок в нём
		// трогает собственные мьютексы и может захотеть спросить сторожа о статусе — прямой
		// вызов дал бы взаимную блокировку.
		if w.OnHealthy != nil {
			go w.OnHealthy(latency)
		}
		if wasFailured {
			w.log(fmt.Sprintf("Watchdog: RECOVERED (%dms)", latency))
			if w.OnRecover != nil {
				go w.OnRecover()
			}
		}
	}
}

func (w *Watchdog) doCheck(ctx context.Context) error {
	url := w.cfg.CheckURL
	w.mu.RLock()
	failCount := w.status.FailCount
	w.mu.RUnlock()
	if failCount > 0 && len(w.cfg.FallbackCheckURLs) > 0 {
		url = w.cfg.FallbackCheckURLs[(failCount-1)%len(w.cfg.FallbackCheckURLs)]
	}
	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// GetStatus возвращает текущий статус (thread-safe)
func (w *Watchdog) GetStatus() WatchdogStatus {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.status
}

// UpdateProxyAddr обновляет адрес прокси (после переключения узла)
func (w *Watchdog) UpdateProxyAddr(addr string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.cfg.ProxyAddr = addr
	w.rebuildClient()
}

// Reset сбрасывает счётчик после успешного переподключения. Зовётся из
// applySingBoxConfig на каждый (пере)коннект — поэтому также сбрасывает
// everSucceeded: новое подключение ещё не подтверждено, даже если предыдущее было.
func (w *Watchdog) Reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status.FailCount = 0
	w.status.State = WatchdogHealthy
	w.status.LastError = ""
	w.everSucceeded = false
}

// ResetCounters сбрасывает счётчики сбоев, НЕ трогая everSucceeded.
//
// P1-5 (аудит 2026-09-01). Нужна для OnRecover: тот вызывается по определению ПОСЛЕ успешной
// проверки, то есть в момент, когда everSucceeded только что стал true. Раньше OnRecover звал
// полный Reset(), и флаг немедленно стирался — то есть сигнал «этот узел работал» уничтожался
// ровно тогда, когда он был получен.
//
// Последствие было обратным замыслу: при следующем сбое emergencySwitch вычислял
// neverConfirmedHealthy = true и намеренно ОБХОДИЛ и грацию MinUptimeSec, и sticky-session
// (CanSwitch(forced=true) разрешает переключение безусловно). Узел, доказавший
// работоспособность, получал обращение как с мертворождённым: мгновенная смена IP посреди
// активной сессии — ровно то, что весь Sticky Session обязан предотвращать.
//
// Полный Reset() (со сбросом everSucceeded) остаётся только за applySingBoxConfig, где он и
// задуман: там действительно НОВОЕ подключение, ещё ничем не подтверждённое.
func (w *Watchdog) ResetCounters() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status.FailCount = 0
	w.status.State = WatchdogHealthy
	w.status.LastError = ""
}

// HasEverSucceeded сообщает, прошла ли хоть одна проверка успешно с момента
// последнего Reset() (т.е. с момента текущего подключения). См. комментарий у поля.
func (w *Watchdog) HasEverSucceeded() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.everSucceeded
}

// SetHealthConfirmedForTest — тестовый сеттер everSucceeded. Пакет engine не видит
// приватное поле напрямую (другой пакет), а имитировать реальную успешную HTTP/SOCKS
// проверку в юнит-тесте engine дорого и не нужно — важно только конечное состояние.
func (w *Watchdog) SetHealthConfirmedForTest(v bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.everSucceeded = v
}

// SetStateForTest — тестовый сеттер State/FailCount (тот же мотив, что у
// SetHealthConfirmedForTest выше): живой отчёт пользователя 2026-09-05 нашёл, что
// engine.emergencySwitch() обязана обходить Sticky Session, когда Watchdog уже объявил
// WatchdogFailed — воспроизвести это через реальный HTTP-цикл check() в юните engine дорого
// и не нужно, важен только факт «Watchdog сейчас считает канал мёртвым».
func (w *Watchdog) SetStateForTest(s WatchdogState, failCount int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status.State = s
	w.status.FailCount = failCount
}

// ─── Минимальный SOCKS5 для Watchdog ─────────────────────────────────────────

// doSOCKS5Connect выполняет минимальный SOCKS5 CONNECT к целевому адресу.
func doSOCKS5Connect(conn net.Conn, targetAddr string, timeout time.Duration) error {
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	// Приветствие: ver=5, nmethods=1, method=0 (no auth)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fmt.Errorf("socks5 hello: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := readFullConn(conn, resp); err != nil {
		return fmt.Errorf("socks5 hello resp: %w", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return fmt.Errorf("socks5: auth required or unsupported")
	}

	// CONNECT запрос
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fmt.Errorf("parse target: %w", err)
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port&0xff))
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 connect req: %w", err)
	}

	// Ответ
	hdr := make([]byte, 4)
	if _, err := readFullConn(conn, hdr); err != nil {
		return fmt.Errorf("socks5 connect resp: %w", err)
	}
	if hdr[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed: code=%d", hdr[1])
	}
	// Читаем остаток адреса в ответе
	switch hdr[3] {
	case 0x01:
		readFullConn(conn, make([]byte, 6))
	case 0x03:
		ln := make([]byte, 1)
		readFullConn(conn, ln)
		readFullConn(conn, make([]byte, int(ln[0])+2))
	case 0x04:
		readFullConn(conn, make([]byte, 18))
	}
	return nil
}

func readFullConn(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
