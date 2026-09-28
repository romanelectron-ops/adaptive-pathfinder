// admission_proxy.go — лимит одновременных подключённых «Входов» для роли «Выход»
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
// узнаёт его после Start()), а решение впустить/отклонить принимает атомарный локальный
// счётчик, не сетевой опрос.
package singbox

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/netutil"
)

// driftCheckInterval — как часто AdmissionProxy сверяет свой атомарный счётчик с реальным
// Clash-API (только логирование расхождения — источник решения впустить/отклонить остаётся
// локальный счётчик, см. комментарий пакета выше).
const driftCheckInterval = 45 * time.Second

// driftWarnThreshold — расхождение больше этого значения несколько проверок подряд —
// признак утечки (соединение закрылось, но счётчик не декрементировался).
const driftWarnThreshold = 1

// AdmissionProxy — TCP-прокси с лимитом одновременных активных соединений.
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

	// admitMu сериализует ровно составную операцию «проверить лимит → инкрементировать»
	// в handleConn. [консилиум, HIGH, находка №8, TZ_RELAY_HARDENING_2026-08-29.md кластер E]
	// count.Load()+сравнение+count.Add(1) раздельно, без этого мьютекса, не атомарны как
	// единое целое — при всплеске почти одновременных подключений несколько горутин видят
	// одно и то же старое значение и все проходят проверку, прежде чем хотя бы одна успевает
	// инкрементировать: лимит подключений можно превысить. Декремент (Count() как таковой)
	// самодостаточен как атомарная операция и в этом мьютексе не нуждается.
	admitMu    sync.Mutex
	maxClients atomic.Int64
	count      atomic.Int64

	driftStreak atomic.Int64

	lastRemoteMu sync.Mutex
	lastRemote   string
}

// NewAdmissionProxy — publicLn уже должен слушать на публичном порту (тот, что в ссылке).
// internalTarget — куда пробрасывать пропущенные соединения (обычно "127.0.0.1:<эфемерный
// порт sing-box>"). maxClients <= 0 трактуется как "лимит не задан" — Accept пропускает всех
// (используется, когда MaxConnectedClients не сконфигурирован пользователем и платформенный
// дефолт почему-то не подставлен — fail-open, а не fail-closed, чтобы опечатка в конфиге не
// заблокировала роль «Выход» целиком; настоящий дефолт по платформе подставляется на уровне
// вызывающей стороны, см. docs/TZ_APF_RELAY_v1.0.md §10.1).
func NewAdmissionProxy(publicLn net.Listener, internalTarget string, maxClients int, clashAPIPort int) *AdmissionProxy {
	p := &AdmissionProxy{
		publicLn:       publicLn,
		internalTarget: internalTarget,
		clashAPIPort:   clashAPIPort,
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

// SetMaxClients меняет лимit одновременных «Входов» без пересоздания AdmissionProxy —
// hot-reload может менять пользовательский maxClients, не только internalTarget.
func (p *AdmissionProxy) SetMaxClients(maxClients int) {
	p.maxClients.Store(int64(maxClients))
}

func (p *AdmissionProxy) log(format string, args ...interface{}) {
	if p.OnLog != nil {
		p.OnLog(fmt.Sprintf(format, args...))
	}
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

// Count — текущее число активных подключений (для UI/диагностики — тот же смысл, что
// connected_clients_count у QueryConnectionsCount, но без сетевого опроса).
func (p *AdmissionProxy) Count() int { return int(p.count.Load()) }

// LastRemoteIP — адрес источника последнего ПРИНЯТОГО (не отклонённого лимитом) подключения,
// для диагностики «точно ли Вход достучался» (тот же смысл, что last_client_ip раньше через
// ClashAPI/QueryConnectionsCount — тут не сетевой опрос, а прямой учёт на приёме).
func (p *AdmissionProxy) LastRemoteIP() string {
	p.lastRemoteMu.Lock()
	defer p.lastRemoteMu.Unlock()
	return p.lastRemote
}

func (p *AdmissionProxy) handleConn(conn net.Conn) {
	p.admitMu.Lock()
	max := p.maxClients.Load()
	if max > 0 && p.count.Load() >= max {
		p.admitMu.Unlock()
		p.log("Лимит подключений (%d) исчерпан — новый Вход отклонён", max)
		conn.Close()
		return
	}
	p.count.Add(1)
	p.admitMu.Unlock()
	defer p.count.Add(-1)

	if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
		p.lastRemoteMu.Lock()
		p.lastRemote = host
		p.lastRemoteMu.Unlock()
	}

	internalTarget, _ := p.target()
	target, err := net.DialTimeout("tcp", internalTarget, 5*time.Second)
	if err != nil {
		p.log("AdmissionProxy: внутренняя цель %s недоступна: %v", internalTarget, err)
		conn.Close()
		return
	}
	netutil.Splice(conn, target)
}

// driftCheckLoop — фоновая сверка атомарного счётчика с реальным Clash-API. НЕ участвует в
// решении впустить/отклонить (см. комментарий пакета) — только предупреждает в лог, если
// расхождение держится несколько проверок подряд (признак утечки, не разовый шум таймингов
// между "соединение уже закрылось" и "sing-box ещё не разобрался с закрытием").
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
			local := p.count.Load()
			diff := local - int64(snap.Count)
			if diff < 0 {
				diff = -diff
			}
			if diff > driftWarnThreshold {
				streak := p.driftStreak.Add(1)
				if streak >= 2 {
					p.log("⚠ AdmissionProxy: локальный счётчик (%d) разошёлся с Clash-API (%d) "+
						"%d проверок подряд — возможна утечка соединения", local, snap.Count, streak)
				}
			} else {
				p.driftStreak.Store(0)
			}
		}
	}
}
