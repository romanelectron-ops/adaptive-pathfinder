// tunnel_server.go — RelayServer: rendezvous+pipe посредник для Вход-Выход
// (docs/TZ_APF_RELAY_v1.0.md §1-§2). Единственный компонент всей схемы, которому нужен
// белый IP — работает на отдельном узле (свой VPS/Pi пользователя, см. ТЗ §6), не на
// устройствах «Вход»/«Выход».
//
// Не расшифровывает и не парсит проксируемый трафик (VLESS+Reality уже даёт end-to-end
// шифрование, см. TZ_APF_VHOD_VYHOD_v1.0.md §2) — только сшивает байты между двумя
// TCP-соединениями после текстового handshake (EXIT/STREAM/ENTRY, tunnel_protocol.go).
package relay

import (
	"crypto/subtle"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RelayServerConfig — настройки RelayServer. Нулевые значения полей означают «дефолт»,
// см. DefaultRelayServerConfig.
type RelayServerConfig struct {
	// MaxRegisteredExits — сколько (exit-id → relay-token) пар одновременно помнит relay
	// (докс §2.1, защита от DoS через бесконечную TOFU-регистрацию случайных id).
	MaxRegisteredExits int
	// MaxConnsPerIP — сколько одновременных TCP-соединений (любого типа — EXIT/STREAM/ENTRY)
	// разрешено с одного IP-источника (докс §2.1).
	MaxConnsPerIP int
	// NewExitRatePerMinute/EntryRatePerMinute — частота НОВЫХ (ещё не виденных) EXIT- и
	// ENTRY-запросов с одного IP в минуту (докс §2.1/§2.3, token-bucket).
	NewExitRatePerMinute int
	EntryRatePerMinute   int
	// OnLog — необязательный callback для диагностики (тот же приём, что Engine.OnLog).
	OnLog func(string)
}

// DefaultRelayServerConfig — разумные дефолты для одиночного relay, обслуживающего
// небольшое число пользователей (личный/семейный масштаб, см. TZ §6 — не рассчитан на
// публичный сервис с тысячами пользователей без отдельного шардирования).
func DefaultRelayServerConfig() RelayServerConfig {
	return RelayServerConfig{
		MaxRegisteredExits:   10000,
		MaxConnsPerIP:        20,
		NewExitRatePerMinute: 6,
		EntryRatePerMinute:   30,
	}
}

// RelayServer — слушает один TCP-порт, маршрутизирует новые соединения по первому слову
// handshake-строки (EXIT/STREAM/ENTRY).
type RelayServer struct {
	cfg RelayServerConfig

	mu    sync.RWMutex
	exits map[string]*exitBinding // exit-id → TOFU-привязка (переживает разрыв связи)

	pendingMu sync.Mutex
	pending   map[string]*pendingSession // session-id → ожидает парную STREAM

	connMu   sync.Mutex
	connsPerIP map[string]int

	newExitLimiter  *rateLimiter
	entryLimiter    *rateLimiter

	ln       net.Listener
	registry *connRegistry
}

// exitSession — ТЕКУЩЕЕ TCP-соединение control-канала «Выхода». Живёт ровно столько, сколько
// живёт конкретное TCP-соединение — при разрыве связи (сон, смена сети) исчезает.
type exitSession struct {
	exitID string
	token  string
	conn   net.Conn

	writeMu  sync.Mutex
	lastSeen atomic.Int64 // unix nano

	// wantsSrc — «Выход» прислал CAPS src: NEWSTREAM для него дополняется адресом «Входа».
	wantsSrc atomic.Bool

	closeOnce sync.Once
	done      chan struct{}
}

// exitBinding — TOFU-привязка exit-id → token, ЖИВЁТ ДОЛЬШЕ конкретного TCP-соединения.
//
// P1 (аудит 2026-09-01, security-раздел, доп. находка — захват exit-id). Раньше token и
// живая сессия лежали в ОДНОЙ записи (exitSession), которая целиком удалялась из s.exits при
// обрыве control-канала (runExitControl → бывший removeExit). Реальный «Выход» на телефоне
// уходит в сон/переключается Wi-Fi↔LTE и переподключается с экспоненциальным backoff
// (~1→30с) — всё это время exit-id в s.exits не значился вовсе, и handleExit трактовал его
// как «виден впервые» (законный TOFU-путь для НОВОГО id), позволяя ЛЮБОМУ, кто пришлёт
// EXIT <exit-id> <свои-байты> первым в этом окне, захватить чужой идентификатор. Настоящий
// владелец, вернувшись из backoff со своим (правильным) токеном, после этого получал бы
// «exit-id занят другим владельцем» — НАВСЕГДА, поскольку токен уже не совпадает с только что
// зарегистрированным чужим. Всё, что нужно атакующему, — публичный exit-id (он идёт в ссылку,
// которую пересылают в мессенджере) и окно в несколько секунд.
//
// Фикс: token переживает разрыв связи — sess обнуляется на отключении (см.
// disconnectExitSession), token и lastActive остаются в карте. Новая попытка регистрации
// ВСЕГДА сравнивается с уже известным token, независимо от того, подключён сейчас кто-то или
// нет — «виден впервые» теперь означает именно это, а не «сейчас никого нет на связи».
type exitBinding struct {
	token      string
	lastActive time.Time    // обновляется при регистрации/переподключении с верным token
	sess       *exitSession // nil, если сейчас никто не подключён — TOFU жив, live-сессии нет
}

type pendingSession struct {
	exitID string
	ch     chan streamHandoff
}

// streamHandoff — то, что STREAM-обработчик передаёт ENTRY-обработчику через pendingSession.ch.
// [консилиум, MEDIUM, находка №21, TZ_RELAY_HARDENING_2026-08-29.md кластер G] releaseSlot
// раньше освобождался сразу по возврату из handleStream — то есть в момент handshake'а, а не
// когда STREAM-соединение реально закрывается (реальная передача данных идёт в ДРУГОЙ горутине,
// handleEntry, уже не учтённой в connsPerIP). Теперь releaseSlot едет вместе с conn и
// вызывается ТАМ, где conn реально перестаёт использоваться — в handleEntry, после splice()
// (или сразу, если splice() до него не дошло).
type streamHandoff struct {
	conn        net.Conn
	releaseSlot func()
}

// NewRelayServer создаёт сервер поверх уже открытого listener'а — вызывающая сторона решает,
// на каком адресе слушать (обычно ":<port>" для приёма отовсюду, relay ведь и существует
// ради белого IP).
func NewRelayServer(ln net.Listener, cfg RelayServerConfig) *RelayServer {
	if cfg.MaxRegisteredExits <= 0 {
		cfg.MaxRegisteredExits = DefaultRelayServerConfig().MaxRegisteredExits
	}
	if cfg.MaxConnsPerIP <= 0 {
		cfg.MaxConnsPerIP = DefaultRelayServerConfig().MaxConnsPerIP
	}
	if cfg.NewExitRatePerMinute <= 0 {
		cfg.NewExitRatePerMinute = DefaultRelayServerConfig().NewExitRatePerMinute
	}
	if cfg.EntryRatePerMinute <= 0 {
		cfg.EntryRatePerMinute = DefaultRelayServerConfig().EntryRatePerMinute
	}
	return &RelayServer{
		cfg:            cfg,
		exits:          make(map[string]*exitBinding),
		pending:        make(map[string]*pendingSession),
		connsPerIP:     make(map[string]int),
		newExitLimiter: newRateLimiter(),
		entryLimiter:   newRateLimiter(),
		ln:             ln,
		registry:       newConnRegistry(),
	}
}

// Shutdown — [консилиум, MEDIUM, находка №22, TZ_RELAY_HARDENING_2026-08-29.md кластер G] ждёт
// естественного завершения активных ENTRY↔STREAM сессий до grace, затем закрывает оставшиеся
// принудительно (тот же приём, что и у EntryBridge.Stop()/ExitClient.Run — см. conn_registry.go).
// Не трогает listener — симметрично уже сложившемуся в cmd/apf-relay контракту: сначала
// закрывается listener (Serve() возвращается сам), затем вызывается Shutdown() для активных
// сессий. Раньше здесь ничего не было — "graceful shutdown" apf-relay обрывал все сессии
// одномоментно (RST вместо FIN) несмотря на комментарий в коде, называющий это "graceful".
func (s *RelayServer) Shutdown(grace time.Duration) {
	s.registry.shutdown(grace)
}

func (s *RelayServer) log(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if s.cfg.OnLog != nil {
		s.cfg.OnLog(msg)
	} else {
		log.Printf("[relay] %s", msg)
	}
}

// Serve принимает соединения, пока listener не закроется. Блокирует вызывающую горутину —
// вызывающая сторона сама решает, в какой горутине это запускать (тот же контракт, что у
// net/http Server.Serve).
func (s *RelayServer) Serve() error {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *RelayServer) handleConn(conn net.Conn) {
	ip := remoteIP(conn)

	if !s.acquireConnSlot(ip) {
		s.log("отклонено: лимит одновременных соединений с %s исчерпан", ip)
		conn.Close()
		return
	}
	releaseSlot := func() { s.releaseConnSlot(ip) }

	line, err := readLine(conn, handshakeReadTimeout)
	if err != nil {
		releaseSlot()
		conn.Close()
		return
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		releaseSlot()
		writeLine(conn, cmdErr+" пустой handshake")
		conn.Close()
		return
	}

	switch fields[0] {
	case cmdExit:
		defer releaseSlot()
		s.handleExit(conn, ip, fields)
	case cmdStream:
		// [находка №21] releaseSlot НЕ освобождается здесь через defer — handleStream либо
		// вызовет его сам на всех отказных путях, либо передаст владение им дальше вместе с
		// conn (см. streamHandoff) тому, кто реально закроет это соединение.
		s.handleStream(conn, fields, releaseSlot)
	case cmdEntry:
		defer releaseSlot()
		s.handleEntry(conn, ip, fields)
	default:
		releaseSlot()
		writeLine(conn, cmdErr+" неизвестная команда")
		conn.Close()
	}
}

// ─── EXIT — регистрация control-канала (докс §2.1) ────────────────────────────────────────

func (s *RelayServer) handleExit(conn net.Conn, ip string, fields []string) {
	if len(fields) != 3 {
		writeLine(conn, cmdErr+" неверный формат EXIT")
		conn.Close()
		return
	}
	exitID, token := fields[1], fields[2]

	sess := &exitSession{exitID: exitID, token: token, conn: conn, done: make(chan struct{})}
	sess.lastSeen.Store(time.Now().UnixNano())

	// [P9, аудит BLACKBOX_2026-09-07, находки A2/B3 #10] «Проверить и зарегистрировать» —
	// ОДНА критическая секция под s.mu.Lock, а не проверка под RLock и запись под отдельным
	// Lock позже. Раньше между ними был зазор, в который помещался второй такой же EXIT:
	//   • TOCTOU. Два одновременных EXIT с ОДНИМ новым exit-id и РАЗНЫМИ токенами оба видели
	//     `known == false`, оба шли по TOFU-пути и оба регистрировались — владельцем
	//     становился тот, кто писал в карту последним. Та же дыра захвата exit-id, что и в
	//     exit_hijack_test.go, только в другом окне: не «пока владелец офлайн», а «пока
	//     владелец ещё регистрируется». Замерено тестом: 3 из 4 конкурентов получали OK.
	//   • Гонка данных. `existing.sess` читался вообще без блокировки, тогда как
	//     disconnectExitSession пишет `b.sess = nil` под этим же s.mu (поймано `-race`:
	//     tunnel_server.go:333 против tunnel_server.go:265 в прежней нумерации).
	// Лимитер и резервирование слота тоже внутри секции: у них свои мьютексы, порядок
	// захвата всегда s.mu → их собственный, обратного порядка в пакете нет (проверено:
	// rateLimiter.allow и reserveExitSlotLocked ничего не знают про s.mu).
	s.mu.Lock()
	existing, known := s.exits[exitID]
	// evicted — старое соединение того же владельца; закрывается ПОСЛЕ выхода из секции:
	// close() дёргает conn.Close(), а его обработчик (runExitControl → disconnectExitSession)
	// сам придёт за s.mu.
	var evicted *exitSession
	if known {
		// [консилиум, MEDIUM, находка №16, TZ_RELAY_HARDENING_2026-08-29.md кластер B]
		// ConstantTimeCompare вместо "!=" — обычное сравнение строк Go завершается на первом
		// несовпадающем байте (тайминг-канал), а exit-id публичен (идёт в ссылку) — у
		// атакующего уже есть половина пары. С TLS (tunnel_tls.go) сетевая утечка токена
		// закрыта, но тайминг — второй эшелон защиты того же секрета, не заменяющий первый.
		//
		// existing.token сравнивается независимо от того, подключён ли сейчас кто-то
		// (existing.sess может быть nil — см. doc-comment exitBinding): TOFU-привязка
		// проверяется ВСЕГДА, а не только пока жив конкретный TCP-канал.
		if subtle.ConstantTimeCompare([]byte(existing.token), []byte(token)) != 1 {
			s.mu.Unlock()
			// [консилиум, CRITICAL] Без этой проверки — захват чужого exit-id: кто угодно,
			// зная/угадавший чужой exit-id, мог бы вытеснять настоящего владельца бесконечно.
			s.log("EXIT %s: попытка перерегистрации с чужим токеном (источник %s)", exitID, ip)
			writeLine(conn, cmdErr+" exit-id занят другим владельцем")
			conn.Close()
			return
		}
		// Тот же владелец переподключается — штатно вытесняем старое соединение, если оно
		// ещё живо (может уже быть nil, если предыдущее отключение уже разобрано).
		evicted = existing.sess
	} else {
		// TOFU: exit-id виден впервые — запоминаем токен как эталонный.
		if !s.newExitLimiter.allow(ip, float64(s.cfg.NewExitRatePerMinute)/60.0, float64(s.cfg.NewExitRatePerMinute)) {
			s.mu.Unlock()
			writeLine(conn, cmdErr+" слишком много новых регистраций, попробуйте позже")
			conn.Close()
			return
		}
		if !s.reserveExitSlotLocked(exitID) {
			s.mu.Unlock()
			writeLine(conn, cmdErr+" relay перегружен")
			conn.Close()
			return
		}
	}
	// Новая запись целиком, а не правка существующей: поля опубликованной exitBinding после
	// этого меняет только disconnectExitSession (под тем же s.mu) — читателям (handleEntry,
	// handleStream) достаточно взять нужное поле под RLock, не боясь правки «на лету».
	s.exits[exitID] = &exitBinding{token: token, lastActive: time.Now(), sess: sess}
	s.mu.Unlock()

	if evicted != nil {
		evicted.close()
	}

	if err := writeLine(conn, cmdOK); err != nil {
		s.disconnectExitSession(exitID, sess)
		return
	}

	s.log("EXIT %s зарегистрирован (источник %s)", exitID, ip)
	s.runExitControl(sess)
}

// reserveExitSlot проверяет лимит MaxRegisteredExits для НОВОГО (ещё не известного) exit-id.
// При достижении лимита пытается освободить место, вытеснив САМУЮ ДАВНО НЕАКТИВНУЮ привязку
// среди тех, у кого сейчас нет живого соединения (sess == nil) — легитимный «Выход», давно
// не выходивший на связь, уступает место новому, а любой СЕЙЧАС подключённый — никогда.
// true — место есть (или найдено); false — relay действительно перегружен подключёнными
// «Выходами», отказ обоснован.
//
// Сам берёт s.mu — вариант для вызова ИЗВНЕ критической секции. Внутри handleExit
// используется reserveExitSlotLocked: там проверка-и-регистрация обязаны быть одной
// неделимой операцией (P9), и повторный Lock был бы взаимоблокировкой.
func (s *RelayServer) reserveExitSlot(newExitID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reserveExitSlotLocked(newExitID)
}

// reserveExitSlotLocked — то же самое, но ВЫЗЫВАЕТСЯ С УЖЕ ВЗЯТЫМ s.mu (на запись).
func (s *RelayServer) reserveExitSlotLocked(newExitID string) bool {
	if len(s.exits) < s.cfg.MaxRegisteredExits {
		return true
	}
	var oldestID string
	var oldestAt time.Time
	for id, b := range s.exits {
		if b.sess != nil {
			continue // сейчас на связи — не трогаем
		}
		if oldestID == "" || b.lastActive.Before(oldestAt) {
			oldestID, oldestAt = id, b.lastActive
		}
	}
	if oldestID == "" {
		return false // все зарегистрированные exit-id сейчас подключены — реальная перегрузка
	}
	delete(s.exits, oldestID)
	return true
}

// disconnectExitSession — control-канал закрылся (сеть, сон устройства). Обнуляет ТОЛЬКО
// живую сессию, TOFU-привязка (token) остаётся в карте — см. doc-comment exitBinding про то,
// почему её раннее удаление здесь было уязвимостью захвата exit-id.
func (s *RelayServer) disconnectExitSession(exitID string, sess *exitSession) {
	s.mu.Lock()
	if b, ok := s.exits[exitID]; ok && b.sess == sess {
		b.sess = nil
		b.lastActive = time.Now()
	}
	s.mu.Unlock()
}

func (s *RelayServer) runExitControl(sess *exitSession) {
	defer s.disconnectExitSession(sess.exitID, sess)
	defer sess.close()

	pingStop := make(chan struct{})
	defer close(pingStop)
	go func() {
		ticker := time.NewTicker(pingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := sess.writeLine(cmdPing); err != nil {
					return
				}
			case <-pingStop:
				return
			case <-sess.done:
				return
			}
		}
	}()

	for {
		line, err := readLine(sess.conn, pingInterval+pongTimeout)
		if err != nil {
			return
		}
		if strings.TrimSpace(line) == cmdPong {
			sess.lastSeen.Store(time.Now().UnixNano())
			continue
		}
		if f := strings.Fields(line); len(f) > 0 && f[0] == cmdCaps {
			for _, c := range f[1:] {
				if c == capSrc {
					sess.wantsSrc.Store(true)
				}
			}
		}
	}
}

func (sess *exitSession) writeLine(line string) error {
	sess.writeMu.Lock()
	defer sess.writeMu.Unlock()
	return writeLine(sess.conn, line)
}

func (sess *exitSession) close() {
	sess.closeOnce.Do(func() {
		sess.conn.Close()
		close(sess.done)
	})
}

// ─── ENTRY — запрос Входа (докс §2.3) ──────────────────────────────────────────────────────

func (s *RelayServer) handleEntry(conn net.Conn, ip string, fields []string) {
	if len(fields) != 2 {
		writeLine(conn, cmdErr+" неверный формат ENTRY")
		conn.Close()
		return
	}
	exitID := fields[1]

	if !s.entryLimiter.allow(ip, float64(s.cfg.EntryRatePerMinute)/60.0, float64(s.cfg.EntryRatePerMinute)) {
		writeLine(conn, cmdErr+" слишком много запросов, попробуйте позже")
		conn.Close()
		return
	}

	// [P9] Поле sess берётся ПОД тем же локом, что и сама привязка: его пишет
	// disconnectExitSession (b.sess = nil) под s.mu — читать его после RUnlock значило бы
	// гоняться с разбором обрыва control-канала за указателем на живую сессию.
	s.mu.RLock()
	binding, ok := s.exits[exitID]
	var exitSess *exitSession
	if ok {
		exitSess = binding.sess
	}
	s.mu.RUnlock()
	// "no such exit" — ОДИНАКОВЫЙ ответ и для действительно неизвестного id, и для известного,
	// но сейчас не подключённого (binding.sess == nil): не сообщаем зондирующему разницу между
	// «такого exit-id никогда не было» и «есть, но офлайн» — то же решение, что уже было для
	// незнакомого id, просто расширенное на офлайн-случай TOFU-привязки.
	if !ok || exitSess == nil {
		writeLine(conn, cmdErr+" no such exit")
		conn.Close()
		return
	}

	sessionID, err := newRandomHex(sessionIDSize)
	if err != nil {
		writeLine(conn, cmdErr+" internal error")
		conn.Close()
		return
	}
	ch := make(chan streamHandoff, 1)
	s.pendingMu.Lock()
	s.pending[sessionID] = &pendingSession{exitID: exitID, ch: ch}
	s.pendingMu.Unlock()

	cleanup := func() {
		s.pendingMu.Lock()
		delete(s.pending, sessionID)
		s.pendingMu.Unlock()
	}

	newStream := cmdNewStream + " " + sessionID
	if exitSess.wantsSrc.Load() && ip != "" {
		// Адрес «Входа» — для лимита устройств на стороне «Выхода» (см. cmdCaps).
		newStream += " " + ip
	}
	if err := exitSess.writeLine(newStream); err != nil {
		cleanup()
		writeLine(conn, cmdErr+" exit unreachable")
		conn.Close()
		return
	}

	select {
	case handoff := <-ch:
		if err := writeLine(conn, cmdOK); err != nil {
			handoff.releaseSlot()
			handoff.conn.Close()
			conn.Close()
			return
		}
		done := s.registry.add(conn, handoff.conn)
		defer func() {
			done()
			handoff.releaseSlot()
		}()
		splice(conn, handoff.conn)
	case <-time.After(streamDialTimeout()):
		cleanup()
		writeLine(conn, cmdErr+" exit timeout")
		conn.Close()
		// [консилиум, MEDIUM, находка №15, TZ_RELAY_HARDENING_2026-08-29.md кластер C] select
		// выше недетерминирован, если обе ветки готовы почти одновременно — STREAM мог
		// оказаться в ch буквально через мгновение после того, как выбрана ветка таймаута.
		// Без этой подчистки такое соединение (и его releaseSlot) осталось бы висеть до
		// системного таймаута ОС — короткоживущая горутина ловит редкий поздний приход и
		// закрывает/освобождает слот сама, не блокируя основной обработчик.
		go func() {
			select {
			case handoff := <-ch:
				handoff.conn.Close()
				handoff.releaseSlot()
			case <-time.After(streamLateArrivalWindow()):
			}
		}()
	}
}

// ─── STREAM — Exit открывает поток в ответ на NEWSTREAM (докс §2.2) ────────────────────────

func (s *RelayServer) handleStream(conn net.Conn, fields []string, releaseSlot func()) {
	if len(fields) != 3 {
		releaseSlot()
		writeLine(conn, cmdErr+" неверный формат STREAM")
		conn.Close()
		return
	}
	sessionID, token := fields[1], fields[2]

	// [консилиум, MEDIUM, находка №17, TZ_RELAY_HARDENING_2026-08-29.md кластер B] Читаем
	// pending-запись, но НЕ удаляем её здесь — раньше delete происходил ДО проверки токена:
	// неверный токен от кого угодно, перехватившего/угадавшего session-id, необратимо сжигал
	// легитимную сессию (настоящий «Выход» с верным токеном следом получал "unknown session").
	s.pendingMu.Lock()
	pend, ok := s.pending[sessionID]
	s.pendingMu.Unlock()

	if !ok {
		releaseSlot()
		writeLine(conn, cmdErr+" unknown session")
		conn.Close()
		return
	}

	// [P9] Эталонный токен копируется ПОД локом — по тем же причинам, что и sess в handleEntry:
	// поля привязки принадлежат s.mu, а не тому, кто первым достал указатель.
	s.mu.RLock()
	binding, exitOK := s.exits[pend.exitID]
	var exitToken string
	if exitOK {
		exitToken = binding.token
	}
	s.mu.RUnlock()
	// ConstantTimeCompare — тот же принцип, что и у EXIT-регистрации выше (находка №16/№18,
	// тайминг-канал против того же секрета).
	if !exitOK || subtle.ConstantTimeCompare([]byte(exitToken), []byte(token)) != 1 {
		releaseSlot()
		writeLine(conn, cmdErr+" unauthorized")
		conn.Close()
		return
	}

	// Токен подтверждён — ТЕПЕРЬ атомарно изымаем запись (единственное использование
	// session-id, докс §2.2, устраняет находку консилиума про возможное смешение трафика двух
	// разных пар при коллизии/повторном использовании id). Самозванец с неверным токеном
	// выше вообще не дошёл до этой точки — легитимная попытка следом по-прежнему пройдёт.
	s.pendingMu.Lock()
	_, stillPending := s.pending[sessionID]
	if stillPending {
		delete(s.pending, sessionID)
	}
	s.pendingMu.Unlock()
	if !stillPending {
		releaseSlot()
		writeLine(conn, cmdErr+" unknown session")
		conn.Close()
		return
	}

	if err := writeLine(conn, cmdOK); err != nil {
		releaseSlot()
		conn.Close()
		return
	}
	// Отдаём соединение (и владение releaseSlot — находка №21) ENTRY-обработчику — он (splice
	// в handleEntry) владеет и закрытием conn, и освобождением слота дальше; здесь их вызывать
	// НЕ нужно.
	pend.ch <- streamHandoff{conn: conn, releaseSlot: releaseSlot}
}

func (s *RelayServer) acquireConnSlot(ip string) bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.connsPerIP[ip] >= s.cfg.MaxConnsPerIP {
		return false
	}
	s.connsPerIP[ip]++
	return true
}

func (s *RelayServer) releaseConnSlot(ip string) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	s.connsPerIP[ip]--
	if s.connsPerIP[ip] <= 0 {
		delete(s.connsPerIP, ip)
	}
}

func remoteIP(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}

// ─── Простой token-bucket rate limiter, по ключу (обычно IP) ───────────────────────────────
//
// [консилиум, HIGH] Карта корзин растёт на каждый НОВЫЙ ключ и не имеет фонового вытеснения
// старых записей — приемлемо для личного/семейного масштаба relay (TZ §6), для которого этот
// шаг и написан; для публичного сервиса с большим числом уникальных IP потребовалась бы
// периодическая чистка (не в объёме этого шага).
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
}

type tokenBucket struct {
	tokens     float64
	lastRefill time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{buckets: make(map[string]*tokenBucket)}
}

func (rl *rateLimiter) allow(key string, ratePerSec, burst float64) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b, ok := rl.buckets[key]
	now := time.Now()
	if !ok {
		b = &tokenBucket{tokens: burst - 1, lastRefill: now}
		rl.buckets[key] = b
		return true
	}
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * ratePerSec
	if b.tokens > burst {
		b.tokens = burst
	}
	b.lastRefill = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
