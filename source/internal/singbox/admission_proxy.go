// admission_proxy.go — лимит одновременно подключённых УСТРОЙСТВ («Входов») для роли «Выход»
// (docs/TZ_APF_RELAY_v1.0.md §10). Публичный порт (тот, что в ссылке) слушает этот прокси,
// а не сам sing-box напрямую — так лимит действует ОДИНАКОВО и для прямых подключений, и
// для подключений через relay (ExitClient дозванивается СЮДА же, не в обход, см. TZ §10.2).
//
// [консилиум, CRITICAL×2] Первая версия этого раздела ТЗ предлагала (а) сдвиг порта sing-box
// на "+2000" без защиты от переполнения диапазона портов и без учёта, что это ломает уже
// существующий счётчик подключений (ServerClashAPIPort считается от другого порта, чем
// реально слушает sing-box), и (б) опрос QueryConnectionsCount на КАЖДОЕ новое соединение —
// классическая TOCTOU-гонка при всплеске одновременных подключений. Обе находки исправлены
// здесь: sing-box слушает эфемерный порт (127.0.0.1:0, ОС сама выбирает — вызывающая сторона
// узнаёт его после Start()), а решение впустить/отклонить принимает локальный учёт под
// мьютексом, не сетевой опрос.
//
// [2026-09-29, живой тест ПК+телефон] Лимит считал TCP-СОЕДИНЕНИЯ, а не устройства. VLESS без
// мультиплексирования открывает отдельное соединение на каждое соединение приложения, поэтому
// ОДИН телефон с браузером упирался в лимит «5» за секунды: в журнале ~300 строк «Лимит
// подключений (5) исчерпан — новый Вход отклонён» от одного устройства, страницы грузились
// обрывками. Интерфейс при этом подписывал счётчик «Подключено устройств». Теперь лимит —
// именно по устройствам:
//   - устройство = адрес источника (IPv4 — адрес целиком; IPv6 — префикс /64, потому что одно
//     устройство ходит с несколькими временными адресами из одной подсети; см. deviceKey);
//   - соединения уже допущенного устройства пускаются всегда (до maxConnsPerDevice — защита
//     от исчерпания дескрипторов, а не лимит «сколько можно пользоваться»);
//   - место устройства держится, пока у него есть соединения, и ещё deviceIdleGrace после
//     последнего — иначе между двумя страницами (ноль соединений на секунду) его место мог
//     бы занять чужой «Вход»;
//   - по прямому подключению адрес источника — настоящий адрес того, кто постучался. Через
//     relay его сообщает сам посредник (AdmitAndDial), см. internal/relay. Честная граница:
//     два устройства за ОДНИМ NAT (общий Wi-Fi роутера, одна раздача) с точки зрения «Выхода»
//     — один адрес, то есть одно устройство; отличить их по TCP невозможно.
package singbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/netutil"
)

// driftCheckInterval — как часто AdmissionProxy сверяет свой счётчик соединений с реальным
// Clash-API (только логирование расхождения — источник решения впустить/отклонить остаётся
// локальный учёт, см. комментарий пакета выше).
const driftCheckInterval = 45 * time.Second

// driftWarnThreshold — расхождение больше этого значения несколько проверок подряд —
// признак утечки (соединение закрылось, но счётчик не декрементировался).
const driftWarnThreshold = 1

const (
	// deviceIdleGrace — сколько место устройства держится после закрытия его последнего
	// соединения (см. комментарий пакета).
	deviceIdleGrace = 2 * time.Minute

	// maxConnsPerDevice — потолок одновременных соединений ОДНОГО допущенного устройства.
	// Это не «лимит пользования»: браузер + приложения держат десятки соединений, сотни —
	// уже аномалия (сканер, утечка, вредоносное приложение). Потолок защищает процесс «Выхода»
	// от исчерпания дескрипторов, когда лимит устройств уже пройден.
	maxConnsPerDevice = 1024

	// rejectLogEvery — не чаще одной строки об отказе на устройство за этот срок. Раньше на
	// каждое отклонённое соединение шла строка — журнал забивался (~300 строк за минуту).
	rejectLogEvery = time.Minute

	// relayDeviceKey — ключ устройства, когда адрес источника неизвестен (relay старой версии
	// не передаёт его): все такие подключения считаются одним устройством.
	relayDeviceKey = "relay"

	// unknownDeviceKey — источник есть, но не разбирается как IP-адрес (не должно случаться
	// для TCP; защитный ключ, чтобы не пускать такое подключение вне учёта).
	unknownDeviceKey = "unknown"
)

var (
	// errDeviceLimit — новое устройство не пущено: все места заняты.
	errDeviceLimit = errors.New("лимит устройств исчерпан")
	// errDeviceConnCap — у допущенного устройства слишком много одновременных соединений.
	errDeviceConnCap = errors.New("слишком много соединений от одного устройства")
)

// deviceSlot — учёт одного устройства.
type deviceSlot struct {
	active   int       // открытые сейчас соединения
	lastSeen time.Time // момент закрытия последнего соединения (пока active > 0 не важен)
}

// deviceKey — ключ устройства по адресу источника (без порта). IPv4 (в т.ч. IPv4-in-IPv6) —
// адрес целиком; IPv6 — префикс /64: устройство меняет временные (privacy) адреса внутри
// своей /64, и без свёртки один телефон занимал бы несколько мест.
func deviceKey(host string) string {
	if host == "" {
		return relayDeviceKey
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return unknownDeviceKey
	}
	addr = addr.WithZone("").Unmap()
	if addr.Is4() {
		return addr.String()
	}
	return netip.PrefixFrom(addr, 64).Masked().String()
}

// AdmissionProxy — TCP-прокси с лимитом одновременно подключённых устройств.
type AdmissionProxy struct {
	publicLn net.Listener
	OnLog    func(string)

	// targetMu защищает internalTarget/clashAPIPort — оба меняются на лету через Retarget
	// (hot-reload роли «Выход», TZ_RELAY_HARDENING_2026-08-29.md кластер A): публичный
	// listener НИКОГДА не пересоздаётся при смене внутреннего порта sing-box, поэтому уже
	// принятые «Входы» не видят даже кратковременного разрыва — меняется только то, куда
	// пойдут НОВЫЕ (после Retarget) подключения.
	targetMu       sync.RWMutex
	internalTarget string
	clashAPIPort   int // 0 = сверка с ClashAPI выключена (например, в тестах)

	// devMu сериализует составную операцию «проверить лимит → занять место» (тот же смысл, что
	// у прежнего admitMu: [консилиум, HIGH, находка №8, кластер E] без общей секции при
	// всплеске одновременных подключений несколько горутин видели одно старое значение и все
	// проходили проверку — лимит можно было превысить). Защищает devices/lastRejectLog.
	devMu         sync.Mutex
	devices       map[string]*deviceSlot
	lastRejectLog map[string]time.Time
	now           func() time.Time // шов для тестов; nil = time.Now

	maxClients atomic.Int64 // лимит УСТРОЙСТВ; <= 0 — лимит выключен (fail-open)
	connCount  atomic.Int64 // все открытые сейчас соединения — для сверки с Clash-API

	driftStreak atomic.Int64

	lastRemoteMu sync.Mutex
	lastRemote   string
}

// NewAdmissionProxy — publicLn уже должен слушать на публичном порту (тот, что в ссылке).
// internalTarget — куда пробрасывать пропущенные соединения (обычно "127.0.0.1:<эфемерный
// порт sing-box>"). maxClients — лимит УСТРОЙСТВ; <= 0 трактуется как "лимит не задан" —
// пускаются все (fail-open, а не fail-closed, чтобы опечатка в конфиге не заблокировала роль
// «Выход» целиком; настоящий дефолт по платформе подставляется на уровне вызывающей стороны,
// см. docs/TZ_APF_RELAY_v1.0.md §10.1). Потолок соединений на устройство действует всегда.
func NewAdmissionProxy(publicLn net.Listener, internalTarget string, maxClients int, clashAPIPort int) *AdmissionProxy {
	p := &AdmissionProxy{
		publicLn:       publicLn,
		internalTarget: internalTarget,
		clashAPIPort:   clashAPIPort,
		devices:        make(map[string]*deviceSlot),
		lastRejectLog:  make(map[string]time.Time),
	}
	p.maxClients.Store(int64(maxClients))
	return p
}

// Retarget атомарно переключает внутренний адрес/clash-api-порт, куда AdmissionProxy
// форвардит НОВЫЕ подключения — не трогая publicLn (TZ_RELAY_HARDENING_2026-08-29.md,
// кластер A: hot-reload роли «Выход» без разрыва уже подключённых «Входов»). Уже принятые
// (и уже сшитые Splice) соединения продолжают говорить со СТАРЫМ внутренним адресом, на
// который они были подключены в момент accept — это ожидаемо и безопасно: их sing-box-конец
// либо тот же процесс, если hot-reload ещё не успел его остановить, либо соединение и так уже
// оборвётся своим чередом, когда старый процесс/инстанс завершится. Вызывающая сторона обязана
// вызывать Retarget только ПОСЛЕ подтверждённого успешного старта нового sing-box на новом
// internalTarget — до этого момента лучше держать старый (пусть и уже неактуальный) адрес, чем
// переключить на заведомо ещё не поднявшийся.
func (p *AdmissionProxy) Retarget(internalTarget string, clashAPIPort int) {
	p.targetMu.Lock()
	p.internalTarget = internalTarget
	p.clashAPIPort = clashAPIPort
	p.targetMu.Unlock()
}

func (p *AdmissionProxy) target() (addr string, clashAPIPort int) {
	p.targetMu.RLock()
	defer p.targetMu.RUnlock()
	return p.internalTarget, p.clashAPIPort
}

// SetMaxClients меняет лимит одновременных УСТРОЙСТВ без пересоздания AdmissionProxy —
// hot-reload может менять пользовательский maxClients, не только internalTarget. Уже
// допущенные устройства при уменьшении лимита не выбрасываются: новые просто не пройдут,
// пока число устройств не упадёт ниже лимита.
func (p *AdmissionProxy) SetMaxClients(maxClients int) {
	p.maxClients.Store(int64(maxClients))
}

func (p *AdmissionProxy) log(format string, args ...interface{}) {
	if p.OnLog != nil {
		p.OnLog(fmt.Sprintf(format, args...))
	}
}

func (p *AdmissionProxy) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

// Serve принимает соединения, пока listener не закроется или ctx не отменится. Блокирует —
// вызывающая сторона запускает в отдельной горутине (тот же goTracked-паттерн, что и
// остальные фоновые задачи Engine).
func (p *AdmissionProxy) Serve(ctx context.Context) {
	go p.driftCheckLoop(ctx)
	go func() {
		<-ctx.Done()
		p.publicLn.Close()
	}()
	for {
		conn, err := p.publicLn.Accept()
		if err != nil {
			return
		}
		go p.handleConn(conn)
	}
}

// Count — сколько УСТРОЙСТВ подключено сейчас (у кого есть хотя бы одно открытое соединение).
// Именно это число показывает интерфейс как «Подключено устройств». Устройство, чьё место ещё
// держится после закрытия последнего соединения (deviceIdleGrace), здесь не считается — оно
// не подключено, оно лишь не отдаёт своё место.
func (p *AdmissionProxy) Count() int {
	p.devMu.Lock()
	defer p.devMu.Unlock()
	n := 0
	for _, s := range p.devices {
		if s.active > 0 {
			n++
		}
	}
	return n
}

// ConnCount — сколько TCP-соединений открыто сейчас (для диагностики и сверки с Clash-API).
func (p *AdmissionProxy) ConnCount() int { return int(p.connCount.Load()) }

// LastRemoteIP — адрес источника последнего ПРИНЯТОГО (не отклонённого лимитом) подключения,
// для диагностики «точно ли Вход достучался».
func (p *AdmissionProxy) LastRemoteIP() string {
	p.lastRemoteMu.Lock()
	defer p.lastRemoteMu.Unlock()
	return p.lastRemote
}

func (p *AdmissionProxy) setLastRemote(host string) {
	if host == "" {
		return
	}
	p.lastRemoteMu.Lock()
	p.lastRemote = host
	p.lastRemoteMu.Unlock()
}

// pruneIdleLocked снимает устройства без соединений, чья отсрочка истекла. devMu удержан.
func (p *AdmissionProxy) pruneIdleLocked(now time.Time) {
	for k, s := range p.devices {
		if s.active == 0 && now.Sub(s.lastSeen) >= deviceIdleGrace {
			delete(p.devices, k)
		}
	}
}

// admit занимает место под ещё одно соединение устройства key. При успехе возвращает release —
// его обязан вызвать (ровно один раз) тот, кто закрывает соединение; повторный вызов безопасен.
func (p *AdmissionProxy) admit(key string) (release func(), err error) {
	p.devMu.Lock()
	now := p.clock()
	p.pruneIdleLocked(now)

	slot := p.devices[key]
	if slot == nil {
		if max := p.maxClients.Load(); max > 0 && int64(len(p.devices)) >= max {
			p.devMu.Unlock()
			return nil, errDeviceLimit
		}
		slot = &deviceSlot{}
		p.devices[key] = slot
	}
	if slot.active >= maxConnsPerDevice {
		p.devMu.Unlock()
		return nil, errDeviceConnCap
	}
	slot.active++
	p.devMu.Unlock()
	p.connCount.Add(1)

	var once sync.Once
	return func() {
		once.Do(func() {
			p.connCount.Add(-1)
			p.devMu.Lock()
			slot.active--
			slot.lastSeen = p.clock()
			p.devMu.Unlock()
		})
	}, nil
}

// logReject пишет об отказе не чаще rejectLogEvery на устройство.
func (p *AdmissionProxy) logReject(key, host string, err error) {
	p.devMu.Lock()
	now := p.clock()
	if last, ok := p.lastRejectLog[key]; ok && now.Sub(last) < rejectLogEvery {
		p.devMu.Unlock()
		return
	}
	if len(p.lastRejectLog) > 256 { // редкий случай: сканирование с множества адресов
		p.lastRejectLog = make(map[string]time.Time)
	}
	p.lastRejectLog[key] = now
	devices := len(p.devices)
	p.devMu.Unlock()

	if errors.Is(err, errDeviceConnCap) {
		p.log("Устройство %s открыло слишком много соединений (%d) — новое отклонено", host, maxConnsPerDevice)
		return
	}
	p.log("Лимит устройств (%d) исчерпан — новое устройство %s не пущено (подключено: %d)",
		p.maxClients.Load(), host, devices)
}

func (p *AdmissionProxy) handleConn(conn net.Conn) {
	host, _, splitErr := net.SplitHostPort(conn.RemoteAddr().String())
	if splitErr != nil {
		host = conn.RemoteAddr().String()
	}
	key := deviceKey(host)
	release, err := p.admit(key)
	if err != nil {
		p.logReject(key, host, err)
		conn.Close()
		return
	}
	defer release()
	p.setLastRemote(host)

	internalTarget, _ := p.target()
	target, err := net.DialTimeout("tcp", internalTarget, 5*time.Second)
	if err != nil {
		p.log("AdmissionProxy: внутренняя цель %s недоступна: %v", internalTarget, err)
		conn.Close()
		return
	}
	netutil.Splice(conn, target)
}

// admittedConn — соединение с внутренней целью, чьё закрытие отдаёт место устройства.
type admittedConn struct {
	net.Conn
	release func()
}

func (c *admittedConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}

// AdmitAndDial — путь для подключений через relay: посредник передаёт адрес настоящего
// «Входа» (sourceIP; пусто — relay старой версии, тогда все такие подключения считаются одним
// устройством relayDeviceKey), а ExitClient вместо звонка на публичный порт получает готовое
// соединение с внутренней целью. Лимит устройств действует тот же, что и для прямых
// подключений (ТЗ §10.2). Закрытие возвращённого соединения освобождает место.
func (p *AdmissionProxy) AdmitAndDial(ctx context.Context, sourceIP string) (net.Conn, error) {
	key := deviceKey(sourceIP)
	release, err := p.admit(key)
	if err != nil {
		p.logReject(key, sourceIP, err)
		return nil, err
	}
	p.setLastRemote(sourceIP)

	internalTarget, _ := p.target()
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", internalTarget)
	if err != nil {
		release()
		p.log("AdmissionProxy: внутренняя цель %s недоступна: %v", internalTarget, err)
		return nil, err
	}
	return &admittedConn{Conn: conn, release: release}, nil
}

// driftCheckLoop — фоновая сверка счётчика СОЕДИНЕНИЙ с реальным Clash-API. НЕ участвует в
// решении впустить/отклонить (см. комментарий пакета) — только предупреждает в лог, если
// расхождение держится несколько проверок подряд (признак утечки, не разовый шум таймингов
// между "соединение уже закрылось" и "sing-box ещё не разобрался с закрытием"). Сверяются
// именно соединения, не устройства: Clash-API устройств не знает.
func (p *AdmissionProxy) driftCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(driftCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, clashAPIPort := p.target()
			if clashAPIPort <= 0 {
				continue // сверка выключена (например, в тестах) — см. комментарий конструктора
			}
			snap, err := QueryConnectionsCount(clashAPIPort)
			if err != nil {
				continue // clash-api временно недоступен — не считаем это дрейфом счётчика
			}
			local := p.connCount.Load()
			diff := local - int64(snap.Count)
			if diff < 0 {
				diff = -diff
			}
			if diff > driftWarnThreshold {
				streak := p.driftStreak.Add(1)
				if streak >= 2 {
					p.log("⚠ AdmissionProxy: локальный счётчик соединений (%d) разошёлся с Clash-API (%d) "+
						"%d проверок подряд — возможна утечка соединения", local, snap.Count, streak)
				}
			} else {
				p.driftStreak.Store(0)
			}
		}
	}
}
