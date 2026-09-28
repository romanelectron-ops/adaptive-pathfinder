// tunnel_protocol.go — общие константы и хелперы протокола relay-посредника
// (docs/TZ_APF_RELAY_v1.0.md §2). Используется и сервером (tunnel_server.go), и обоими
// клиентами (tunnel_exit_client.go, tunnel_entry_bridge.go).
package relay

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/netutil"
)

// Команды протокола — построчный текстовый handshake поверх TCP (докс §2). После
// успешного handshake STREAM/ENTRY-соединение становится «немым» каналом сырых байт —
// дальше никто их не парсит.
const (
	cmdExit      = "EXIT"
	cmdStream    = "STREAM"
	cmdEntry     = "ENTRY"
	cmdNewStream = "NEWSTREAM"
	cmdOK        = "OK"
	cmdErr       = "ERR"
	cmdPing      = "PING"
	cmdPong      = "PONG"
)

// streamDialTimeoutNs/streamLateArrivalWindowNs — [найдено go test -race при написании
// regression-тестов кластера C, 2026-08-30, НЕ в исходном отчёте консилиума] atomic.Int64
// (наносекунды), а не голый var time.Duration: единственный писатель — regression-тесты
// (tunnel_server_test.go), сжимающие эти таймауты до миллисекунд, чтобы не ждать реальные
// ~21с; единственный читатель — handleEntry (tunnel_server.go), в горутине на каждое входящее
// соединение. Голый var ловился детектором данных гонок как WARNING: DATA RACE между записью
// теста (defer-восстановление значения ПОСЛЕ возврата из функции теста) и чтением ещё
// работающей фоновой горутины-подчистки того же теста — не гипотетически, поймано реальным
// прогоном. atomic.Load/Store — единственный способ сделать это корректно без нового
// production-only канала синхронизации ради теста.
var streamDialTimeoutNs atomic.Int64
var streamLateArrivalWindowNs atomic.Int64

func init() {
	// streamDialTimeout — сколько Entry ждёт итоговое OK/ERR после ENTRY, и сколько Relay ждёт
	// парную STREAM после отправки NEWSTREAM (докс §2.2/§2.3). [консилиум, HIGH, находка №7,
	// TZ_RELAY_HARDENING_2026-08-29.md кластер C] ОБЯЗАН быть больше суммы обоих dial'ов
	// ExitClient.handleNewStream (relayConn + localConn, каждый до exitClientDialTimeout,
	// tunnel_exit_client.go) — иначе relay отдавал "exit timeout" раньше, чем ExitClient
	// физически успевал ответить на деградированной, но нормальной мобильной сети (целевой
	// сценарий фичи, докс §4). Раньше было зафиксировано отдельным числом (5с), никак не
	// связанным с exitClientDialTimeout — рассинхрон нашёлся консилиумом. Выражение, а не
	// отдельная константа — расхождение между ними физически невозможно в дальнейшем.
	streamDialTimeoutNs.Store(int64(2*exitClientDialTimeout + 5*time.Second))
	// streamLateArrivalWindow — [консилиум, MEDIUM, находка №15, TZ_RELAY_HARDENING_2026-08-29.md
	// кластер C] окно короткоживущей горутины-подчистки в handleEntry: select между приёмом
	// STREAM и срабатыванием streamDialTimeout недетерминирован, если обе ветки готовы почти
	// одновременно — соединение, "проигравшее" гонку буквально на миллисекунды, без этой
	// подчистки осталось бы висеть до системного таймаута ОС. Секунды с запасом достаточно —
	// это исключительно окно самой гонки select, не полноценный таймаут дозвона.
	streamLateArrivalWindowNs.Store(int64(2 * time.Second))
}

func streamDialTimeout() time.Duration { return time.Duration(streamDialTimeoutNs.Load()) }

func streamLateArrivalWindow() time.Duration { return time.Duration(streamLateArrivalWindowNs.Load()) }

const (
	// handshakeReadTimeout — сколько relay ждёт первую строку (EXIT/STREAM/ENTRY) от только
	// что принятого соединения, прежде чем считать его мусором и закрыть.
	handshakeReadTimeout = 5 * time.Second
	// pingInterval — как часто relay проверяет живость control-канала Exit'а (докс §2.1).
	pingInterval = 30 * time.Second
	// pongTimeout — сколько ждать PONG после PING сверх pingInterval, прежде чем считать
	// control-канал мёртвым (упавшим без FIN/RST — частый случай на мобильных сетях).
	pongTimeout = 10 * time.Second

	// entryRetryAttempts/entryRetryDelay — ретрай ENTRY при "ERR no such exit" на стороне
	// EntryBridge (докс §2.3): основной сценарий мастера — партнёр только что включил роль
	// «Выход», ExitClient ещё не успел зарегистрироваться.
	entryRetryAttempts = 3
	entryRetryDelay    = 2 * time.Second

	// maxProtocolLineLength — защита от неограниченного роста памяти при чтении строки
	// handshake без завершающего \n (DoS, докс §2.1) — ни одна легитимная строка протокола
	// (команда + hex-идентификаторы) не приближается к этому размеру.
	maxProtocolLineLength = 512

	// controlIOTimeout — [консилиум, CRITICAL, находка №2, TZ_RELAY_HARDENING_2026-08-29.md]
	// дедлайн на КАЖДУЮ запись строки протокола, симметрично readLine (у которой дедлайн уже
	// был). Без него conn.Write на control-канале, полученном от недоверенной стороны сети,
	// мог зависнуть навсегда, если тот перестал читать сокет (slow-read/zero-window — не
	// детектируется TCP keepalive): злоумышленник регистрируется «Выходом», не читает свой
	// сокет, и relay навсегда виснет внутри writeLine на push NEWSTREAM, который выполняется
	// СИНХРОННО внутри обработчика чужого ENTRY-запроса — слот MaxConnsPerIP атакующего никогда
	// не освобождается (defer releaseSlot ждёт возврата из handleEntry). Фикс — в самом
	// writeLine, а не в найденном месте вызова: так защищены разом все текущие (EXIT/OK, PING,
	// NEWSTREAM, PONG, STREAM/OK, ENTRY) и любые будущие вызовы, а не только тот, что нашёл
	// консилиум — дисциплина таймаутов должна быть свойством протокольного слоя, не памятью
	// разработчика о том, что «здесь уже нашли один раз».
	controlIOTimeout = 10 * time.Second
)

const (
	relayTokenSize = 32 // 256 бит — relay-token (докс §2.1)
	exitIDSize     = 16 // 128 бит — apf_exitid (докс §3)
	sessionIDSize  = 16 // 128 бит — session-id (докс §2.2)
)

// newRandomHex — общий генератор случайных идентификаторов (relay-token/exit-id/session-id).
func newRandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("relay: сгенерировать случайный идентификатор: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// writeLine пишет одну строку протокола с завершающим \n, под дедлайном controlIOTimeout
// (см. её комментарий — устраняет удалённый DoS через зависшую запись на недоверенном
// control-канале). SetWriteDeadline не влияет на параллельное чтение того же conn (readLine
// в другой горутине того же соединения) — TCPConn различает read/write дедлайны независимо.
func writeLine(conn net.Conn, line string) error {
	if err := conn.SetWriteDeadline(time.Now().Add(controlIOTimeout)); err != nil {
		return err
	}
	defer conn.SetWriteDeadline(time.Time{})
	_, err := conn.Write([]byte(line + "\n"))
	return err
}

// readLine читает ровно одну строку протокола (до \n, не включая его), байт за байтом —
// НЕ через bufio.Reader. Это намеренно: bufio.Reader может прочитать из сокета за один
// системный вызов больше байт, чем нужно для строки, и буферизовать «лишнее» внутри себя;
// если после этого код переключается на сырое чтение STREAM/ENTRY-соединения напрямую через
// net.Conn (что и происходит сразу после handshake — соединение становится «немым» каналом
// io.Copy), эти буферизованные байты потерялись бы навсегда — начало TLS/Reality-рукопожатия
// обрубается, соединение выглядит битым без единой понятной причины. Байт-за-байтом чтение
// короткой (до maxProtocolLineLength) handshake-строки не оставляет на net.Conn ничего
// непрочитанного сверх самой строки — последующий io.Copy(dst, conn) видит поток данных
// ровно с того места, где заканчивается \n.
func readLine(conn net.Conn, timeout time.Duration) (string, error) {
	if timeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return "", err
		}
		defer conn.SetReadDeadline(time.Time{})
	}
	var buf []byte
	one := make([]byte, 1)
	for {
		n, err := conn.Read(one)
		if n > 0 {
			if one[0] == '\n' {
				return strings.TrimRight(string(buf), "\r"), nil
			}
			buf = append(buf, one[0])
			if len(buf) > maxProtocolLineLength {
				return "", fmt.Errorf("relay: строка протокола длиннее %d байт", maxProtocolLineLength)
			}
		}
		if err != nil {
			return "", err
		}
	}
}

// splice — общий хелпер для Relay (Entry↔Stream), ExitClient (Stream↔локальный sing-box) и
// EntryBridge (локальное sing-box-соединение↔Relay). Обёртка над netutil.Splice (см. её
// комментарий — общий код с internal/singbox/admission_proxy.go, не может жить в этом
// пакете напрямую из-за направления импорта relay→singbox).
func splice(a, b net.Conn) { netutil.Splice(a, b) }
