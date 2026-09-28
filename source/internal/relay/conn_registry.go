// conn_registry.go — connRegistry: общий примитив учёта активных проксируемых (сплайсированных)
// соединений (TZ_RELAY_HARDENING_2026-08-29.md кластер G). До этого файла три места —
// RelayServer.handleEntry (tunnel_server.go), ExitClient.handleNewStream (tunnel_exit_client.go)
// и EntryBridge.handleLocalConn (tunnel_entry_bridge.go) — сшивали байты через splice() либо
// вовсе не отслеживая горутину (находка №14: ExitClient), либо отслеживая через собственный
// sync.WaitGroup без принудительного закрытия зависших соединений (находка №6:
// EntryBridge.Stop() мог виснуть навсегда, если удалённая сторона не закрывала канал сама —
// обрыв мобильной сети без FIN/RST, обычное дело). Три независимых WaitGroup — три места, где
// при следующей правке легко снова разойтись; общий реестр даёт одну проверенную реализацию.
package relay

import (
	"net"
	"sync"
	"time"
)

// connShutdownGrace — сколько ждать естественного завершения активных сессий при
// graceful shutdown, прежде чем закрывать их принудительно. Не «сразу разрываем всё» (это не
// было бы graceful) и не «ждём бесконечно» (это и есть находка №6) — компромисс: пользователь,
// нажавший «Остановить», не должен видеть зависший интерфейс дольше нескольких секунд, а уже
// идущая передача данных получает разумный шанс закончиться сама.
const connShutdownGrace = 5 * time.Second

// connRegistry отслеживает набор net.Conn, активных в рамках одной проксируемой сессии.
type connRegistry struct {
	mu    sync.Mutex
	conns map[net.Conn]struct{}
	wg    sync.WaitGroup
	// shuttingDown — [найдено go test -race при написании regression-тестов кластера C,
	// 2026-08-30, НЕ в исходном отчёте консилиума] защита от того самого случая, о котором
	// явно предупреждает документация sync.WaitGroup: "calls with a positive delta that start
	// when the counter is zero must happen before a Wait" — без этого флага новое подключение
	// (add(), реальный сценарий: клиент подключается ровно в момент, когда пользователь нажал
	// «Остановить») могло вызвать wg.Add(1) КОНКУРЕНТНО с уже идущим wg.Wait() внутри
	// shutdown() — гонка данных на внутреннем состоянии WaitGroup, поймана детектором, не
	// гипотетическая (см. добавленный тест TestConnRegistry_Add_ConcurrentWithShutdown).
	shuttingDown bool
}

func newConnRegistry() *connRegistry {
	return &connRegistry{conns: make(map[net.Conn]struct{})}
}

// add регистрирует conns (обычно оба конца одной сшитой splice()-пары) как одну единицу
// активности. Возвращённый done ОБЯЗАН быть вызван ровно один раз (обычно `defer done()`
// сразу после add) независимо от исхода — снимает регистрацию и освобождает внутренний
// WaitGroup. Безопасно вызывать done() из defer даже если shutdown() уже принудительно закрыл
// эти conns — двойное закрытие net.Conn просто возвращает ошибку, которую вызывающая сторона
// (splice/netutil.Splice) уже готова игнорировать при завершении.
func (r *connRegistry) add(conns ...net.Conn) (done func()) {
	r.mu.Lock()
	if r.shuttingDown {
		// shutdown() уже начал(ся) — возможно, уже вызвал wg.Wait() в своей горутине. Звать
		// wg.Add(1) отсюда было бы тем самым небезопасным сочетанием "Add конкурентно с Wait",
		// которое прямо не гарантируется контрактом sync.WaitGroup. Раз мы всё равно
		// останавливаемся — просто закрываем conns сразу же самостоятельно, регистрировать их
		// уже незачем.
		r.mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
		return func() {}
	}
	r.wg.Add(1)
	for _, c := range conns {
		r.conns[c] = struct{}{}
	}
	r.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			for _, c := range conns {
				delete(r.conns, c)
			}
			r.mu.Unlock()
			r.wg.Done()
		})
	}
}

// shutdown — ждёт естественного завершения ВСЕХ зарегистрированных сессий до grace, затем
// принудительно закрывает всё, что ещё зарегистрировано (закрытие net.Conn гарантированно
// разблокирует зависший Read/Write на этом conn с обеих сторон — ровно то, чего не хватало
// EntryBridge.Stop(), находка №6). Возвращается, только когда каждый add() получил свой done()
// — то есть вызывающая сторона (Stop()/graceful shutdown) НИКОГДА не виснет дольше
// grace + время на фактическое закрытие уже происходящих системных вызовов.
func (r *connRegistry) shutdown(grace time.Duration) {
	// shuttingDown выставляется ПОД ТЕМ ЖЕ мьютексом, что add() проверяет его — это и есть
	// синхронизация, устраняющая гонку с wg.Add(1) (см. комментарий у поля и у add() выше):
	// либо add() успел захватить лок и вызвать wg.Add(1) ДО этой строки (тогда unlock у add()
	// happens-before lock здесь — Wait() ниже гарантированно дождётся именно этой регистрации),
	// либо add() увидит shuttingDown=true и wg.Add(1) вообще не вызовет.
	r.mu.Lock()
	r.shuttingDown = true
	r.mu.Unlock()

	doneCh := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(doneCh)
	}()

	select {
	case <-doneCh:
		return
	case <-time.After(grace):
	}

	r.mu.Lock()
	conns := make([]net.Conn, 0, len(r.conns))
	for c := range r.conns {
		conns = append(conns, c)
	}
	r.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
	<-doneCh
}
