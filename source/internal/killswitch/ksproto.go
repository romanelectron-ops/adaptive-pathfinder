package killswitch

import (
	"encoding/json"
	"errors"
	"io"
	"sync"
)

// Протокол управления Kill Switch через локальный канал (Вариант A, D-32/D-33).
//
// Модель: движок (трей/CLI, НЕ admin) — клиент; служба apf-svc (SYSTEM) — сервер-исполнитель netsh.
// Один запрос → один ответ на соединение (KS-операции редкие, стриминг не нужен). Транспорт —
// named pipe на Windows (kspipe_windows.go); здесь — платформо-независимые типы и диспетчер,
// которые тестируются через net.Pipe без ОС-зависимостей.

const (
	OpEnable  = "enable"
	OpDisable = "disable"
	OpRecover = "recover"
	OpStatus  = "status"
	// OpCaps — запрос возможностей СЕРВЕРНОГО бэкенда (R-1.1). Клиент обязан отвечать движку
	// не своими возможностями, а возможностями того, кто реально ставит правила: служба может
	// быть поднята и с netsh-, и с WFP-бэкендом (APF_KS_BACKEND).
	OpCaps = "caps"
	// OpEnsureTun — досоздать permit для TUN, когда интерфейс поднялся (R-6.1/C-10).
	OpEnsureTun = "ensure_tun"
	// OpReset — быстрый сброс правил APF ПРАВАМИ ИСПОЛНИТЕЛЯ (R-4.1/C-3). Без него движок звал
	// killswitch.QuickReset() внутри своего неадминского процесса: на служебном пути это молча
	// падало, а админский трей мог снести правила живой службы.
	OpReset = "reset"
)

// Request — команда движка службе.
type Request struct {
	Op    string `json:"op"`
	VPNIP string `json:"vpnip,omitempty"` // РАЗРЕШЁННЫЙ IP (нормализован Я-31.0)
	Tun   string `json:"tun,omitempty"`   // имя TUN (apf0)
	Port  int    `json:"port,omitempty"`  // резерв (SetVPNEndpoint)
	Ports []int  `json:"ports,omitempty"` // ListenPort и т.п.
	// Full — для OpReset: полный откат (ResetAll, включая DNS) вместо быстрого (QuickReset).
	Full bool `json:"full,omitempty"`
}

// Response — ответ службы.
type Response struct {
	OK        bool   `json:"ok"`
	Enabled   bool   `json:"enabled"`
	Recovered bool   `json:"recovered,omitempty"`
	Error     string `json:"error,omitempty"`
	// Caps — возможности серверного бэкенда (ответ на OpCaps, R-1.1).
	Caps Capabilities `json:"caps,omitempty"`
}

// ksExecutor — минимальный контракт исполнителя (его реализует windowsKS).
type ksExecutor interface {
	Enable(tun string, ports []int) error
	Disable() error
	IsEnabled() bool
}

// vpnEndpointSetter — опциональное расширение (windowsKS реализует).
type vpnEndpointSetter interface{ SetVPNEndpoint(ip string, port int) }

// capsProvider — опциональное расширение: бэкенд декларирует возможности (R-1.1).
// Опционально, чтобы ksExecutor остался минимальным контрактом исполнителя.
type capsProvider interface{ Capabilities() Capabilities }

// executorCaps возвращает возможности исполнителя. Исполнитель, не умеющий их декларировать,
// трактуется КОНСЕРВАТИВНО (proxy-only): заявить TunMode за чужой бэкенд — значит разрешить
// движку применить KS там, где он не защищает (ровно C-1).
func executorCaps(ks ksExecutor) Capabilities {
	if p, ok := ks.(capsProvider); ok {
		return p.Capabilities()
	}
	return Capabilities{ProxyMode: true}
}

// recoverFn — инжектируемый crash-recover (RecoverIfNeeded). Служба зовёт под SYSTEM (D-33).
var recoverFn = RecoverIfNeeded

// resetFn — инжектируемый быстрый сброс правил APF (QuickReset). Служба зовёт под SYSTEM (R-4.1).
var resetFn = QuickReset

// resetAllFn — инжектируемый ПОЛНЫЙ откат сетевых изменений APF (ResetAll, включая DNS).
var resetAllFn = ResetAll

// Dispatch исполняет одну команду над ks и возвращает ответ. Побочные эффекты — только через ks/recover.
func Dispatch(ks ksExecutor, req Request) Response {
	switch req.Op {
	case OpEnable:
		if s, ok := ks.(vpnEndpointSetter); ok {
			s.SetVPNEndpoint(req.VPNIP, req.Port)
		}
		if err := ks.Enable(req.Tun, req.Ports); err != nil {
			return Response{OK: false, Enabled: ks.IsEnabled(), Error: err.Error()}
		}
		return Response{OK: true, Enabled: ks.IsEnabled()}
	case OpDisable:
		if err := ks.Disable(); err != nil {
			return Response{OK: false, Enabled: ks.IsEnabled(), Error: err.Error()}
		}
		return Response{OK: true, Enabled: ks.IsEnabled()}
	case OpRecover:
		rec := recoverFn()
		return Response{OK: true, Enabled: ks.IsEnabled(), Recovered: rec}
	case OpStatus:
		return Response{OK: true, Enabled: ks.IsEnabled()}
	case OpCaps:
		return Response{OK: true, Enabled: ks.IsEnabled(), Caps: executorCaps(ks)}
	case OpReset:
		// Сначала снимаем состояние бэкенда (для WFP это закрытие движка = снятие всех фильтров),
		// затем чистим netsh-правила: они могли остаться от прошлой сессии/другого бэкенда.
		_ = ks.Disable()
		if req.Full {
			if err := resetAllFn(); err != nil {
				return Response{OK: false, Enabled: ks.IsEnabled(), Error: err.Error()}
			}
		} else {
			resetFn()
		}
		return Response{OK: true, Enabled: ks.IsEnabled()}
	case OpEnsureTun:
		e, ok := ks.(tunPermitEnsurer)
		if !ok {
			// Бэкенд без allow-by-interface физически не может выполнить операцию — это ошибка,
			// а не «нечего делать»: движок обязан узнать, что VPN-режим не защищён (C-1).
			return Response{OK: false, Enabled: ks.IsEnabled(), Error: "backend does not support tun permit"}
		}
		if err := e.EnsureTunPermit(req.Tun); err != nil {
			return Response{OK: false, Enabled: ks.IsEnabled(), Error: err.Error()}
		}
		return Response{OK: true, Enabled: ks.IsEnabled()}
	default:
		return Response{OK: false, Error: "unknown op: " + req.Op}
	}
}

// ServeConn читает один Request, исполняет через Dispatch, пишет один Response. Серверная сторона
// без авторизации — используется там, где транспорт сам гарантирует, что клиент свой.
func ServeConn(conn io.ReadWriter, ks ksExecutor) error {
	return serveConn(conn, ks, nil)
}

// dispatchMu сериализует Dispatch между ПАРАЛЛЕЛЬНЫМИ pipe-соединениями (найдено живым
// инцидентом 2026-08-19, docs/TZ_CONFIG_RELOAD_AND_KS_SAFETY_v1.0.md): ServePipe
// (kspipe_windows.go) обслуживает каждое подключение в СВОЕЙ горутине (до maxPipeConns
// одновременно), и все они дёргают ОДИН И ТОТ ЖЕ разделяемый ks-исполнитель (windowsKS) без
// какой-либо синхронизации между собой. При частых повторных Reload/reconnect (типичная
// ситуация с нестабильными бесплатными узлами — Watchdog видит сбой, движок переподключается,
// это повторяется несколько раз подряд) engine.go шлёт несколько почти одновременных
// Enable-запросов. Внутри windowsKS.Enable() это гонка НА НАСТОЯЩЕМ состоянии ОС: cleanupRules()
// одного вызова может снести allow-правило, которое только что поставил другой, а порядок
// netsh-команд между двумя параллельными Enable() непредсказуемо чередуется — итоговая
// firewall-политика (blockoutbound) может остаться с allow-списком, не соответствующим НИ ОДНОМУ
// из запрошенных узлов. Живой симптом: sing-box не может достучаться до СОБСТВЕННОГО VPN-сервера
// («forbidden by its access permissions») при любом узле — не адресный баг, а гонка состояния.
// Единственная точка вызова Dispatch в проде — эта функция (serveConn), поэтому локальной
// блокировки здесь достаточно, без изменения сигнатур/тестов, вызывающих Dispatch напрямую.
var dispatchMu sync.Mutex

// maxRequestBytes — жёсткий потолок ОДНОГО запроса протокола KS (P5, аудит 2026-09-07,
// находка A3 F-5). Раньше `json.NewDecoder(conn).Decode` читал тело без всякого предела и ДО
// авторизации: пайп `\\.\pipe\APF-KS` обслуживает процесс службы под SYSTEM, и любой, кто
// вправе его открыть, мог одним бесконечным потоком байт заставить эту службу расти в памяти
// сколько угодно — предаутентификационный memory-DoS.
//
// Число выбрано от МАКСИМАЛЬНОГО ЛЕГИТИМНОГО сообщения, а не «на глазок»: самый «толстый»
// запрос, который вообще может собрать этот протокол (op=ensure_tun, IPv6 в полной форме,
// имя TUN длиной 256 байт — на порядок больше реального «apf0», 64 порта в Ports, Port+Full),
// сериализуется в 749 байт (замер — TestServeConn_LegitimateMaximalRequestStillAccepted).
// 8 КиБ даёт ~11-кратный запас на любое будущее расширение Request и при этом остаётся
// величиной, которую невозможно превратить в давление на память: даже все maxPipeConns
// соединений сразу — это десятки килобайт.
const maxRequestBytes = 8 << 10

// errRequestTooLarge — превышение maxRequestBytes. Отдельная ошибка, а не io.ErrUnexpectedEOF
// от io.LimitReader: «клиент прислал слишком много» и «соединение оборвалось на середине» —
// разные события, и в логе службы их нельзя путать.
var errRequestTooLarge = errors.New("request too large")

// limitedReader — io.LimitReader, который на исчерпании лимита возвращает ОШИБКУ, а не EOF.
type limitedReader struct {
	r    io.Reader
	left int64
}

func newLimitedReader(r io.Reader, n int64) *limitedReader { return &limitedReader{r: r, left: n} }

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.left <= 0 {
		return 0, errRequestTooLarge
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	return n, err
}

// serveConn — общий серверный путь с необязательной авторизацией (B-0403 · R-5.2, C-9).
//
//	Вход:      соединение, исполнитель, authorize (nil ⇒ проверка не выполняется).
//	Тело:      прочитать запрос (НЕ БОЛЕЕ maxRequestBytes) → спросить authorize → исполнить.
//	           Порядок важен: до чтения запроса контекст безопасности клиента named pipe может
//	           быть ещё не установлен, а ответить не вычитав запрос нельзя — клиент заблокируется
//	           на своей записи. Именно поэтому защита от недоверенного клиента ДО авторизации —
//	           не «не читать», а «читать ограниченно»: см. maxRequestBytes. Dispatch — под
//	           dispatchMu (см. её комментарий): второй параллельный клиент ждёт, а не гонится.
//	Выход:     ошибка декодирования/авторизации; ответ клиенту записывается ВСЕГДА. Соединение
//	           закрывает вызывающая сторона (ServePipe) сразу по возврату — превышение лимита
//	           означает немедленный разрыв.
//	Fail-safe: отказ авторизации ⇒ `{ok:false,error:"access denied"}` БЕЗ подробностей (SID, номер
//	           сессии) — их незачем сообщать тому, кому мы только что отказали. Dispatch НЕ вызывается.
//	Инвариант: неавторизованный клиент не может изменить состояние фаервола ни одной командой И
//	           не может заставить сервер прочитать больше maxRequestBytes байт.
func serveConn(conn io.ReadWriter, ks ksExecutor, authorize func() error) error {
	var req Request
	if err := json.NewDecoder(newLimitedReader(conn, maxRequestBytes)).Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(Response{OK: false, Error: "decode: " + err.Error()})
		return err
	}
	if authorize != nil {
		if err := authorize(); err != nil {
			_ = json.NewEncoder(conn).Encode(Response{OK: false, Error: "access denied"})
			return err
		}
	}
	dispatchMu.Lock()
	resp := Dispatch(ks, req)
	dispatchMu.Unlock()
	return json.NewEncoder(conn).Encode(resp)
}

// sendRequest пишет Request и читает Response. Клиентская сторона (движок).
func sendRequest(conn io.ReadWriter, req Request) (Response, error) {
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return Response{}, err
	}
	return resp, nil
}
