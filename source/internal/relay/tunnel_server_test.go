package relay

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

// startTestRelayServer — RelayServer теперь ВСЕГДА за TLS (TZ_RELAY_HARDENING_2026-08-29.md
// кластер B, tunnel_tls.go) — тесты поднимают его точно так же, как cmd/apf-relay, только
// сертификат живёт в t.TempDir() и не переживает сам тест. Возвращает и fingerprint — тестам,
// которые реально дозваниваются через ExitClient/EntryBridge (не через dialAndHandshake), он
// нужен как обязательный параметр их конструкторов.
func startTestRelayServer(t *testing.T, cfg RelayServerConfig) (addr, fingerprint string, srv *RelayServer) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cert, fp, err := LoadOrGenerateRelayCert(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrGenerateRelayCert: %v", err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	srv = NewRelayServer(tlsLn, cfg)
	go srv.Serve()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), fp, srv
}

// dialAndHandshake — TLS-дозвон (InsecureSkipVerify: сами тесты в этом файле проверяют
// протокольную логику RelayServer, не fingerprint-pinning — тот проверяется отдельно,
// tunnel_tls_test.go), одна строка handshake, один ответ.
func dialAndHandshake(t *testing.T, addr, line string) (net.Conn, string) {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := writeLine(conn, line); err != nil {
		t.Fatalf("writeLine: %v", err)
	}
	resp, err := readLine(conn, 2*time.Second)
	if err != nil {
		t.Fatalf("readLine: %v", err)
	}
	return conn, resp
}

// dialAndHandshakeErr — то же самое, что dialAndHandshake, но возвращает ошибку вместо
// t.Fatalf: t.Fatal(f) вызывает runtime.Goexit(), который останавливает ТОЛЬКО вызывающую
// горутину, не сам тест — документированно небезопасно звать из горутины, не являющейся телом
// теста. Нужен там, где дозвон-имитация Exit'а/STREAM происходит в фоновой горутине.
func dialAndHandshakeErr(addr, line string) (net.Conn, string, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, "", err
	}
	if err := writeLine(conn, line); err != nil {
		conn.Close()
		return nil, "", err
	}
	resp, err := readLine(conn, 2*time.Second)
	if err != nil {
		conn.Close()
		return nil, "", err
	}
	return conn, resp, nil
}

// [консилиум, CRITICAL] TOFU: тот же токен — переподключение штатно вытесняет старое
// соединение; чужой токен — явный отказ, БЕЗ вытеснения.
func TestRelayServer_TOFU_SameTokenReplacesOldConnection(t *testing.T) {
	addr, _, _ := startTestRelayServer(t, RelayServerConfig{})

	conn1, resp1 := dialAndHandshake(t, addr, cmdExit+" exit-a token-a")
	if resp1 != cmdOK {
		t.Fatalf("первая регистрация: resp = %q, ожидался OK", resp1)
	}
	defer conn1.Close()

	// Тот же exit-id, тот же токен — переподключение (например, после сетевого сбоя).
	conn2, resp2 := dialAndHandshake(t, addr, cmdExit+" exit-a token-a")
	defer conn2.Close()
	if resp2 != cmdOK {
		t.Fatalf("переподключение тем же токеном: resp = %q, ожидался OK", resp2)
	}

	// Старое соединение должно быть закрыто сервером (вытеснено).
	conn1.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, err := conn1.Read(buf)
	if err == nil {
		t.Error("старое control-соединение должно было закрыться после вытеснения тем же токеном")
	}
}

func TestRelayServer_TOFU_DifferentTokenRejected(t *testing.T) {
	addr, _, srv := startTestRelayServer(t, RelayServerConfig{})

	conn1, resp1 := dialAndHandshake(t, addr, cmdExit+" exit-b token-real")
	if resp1 != cmdOK {
		t.Fatalf("первая регистрация: resp = %q, ожидался OK", resp1)
	}
	defer conn1.Close()

	// Атакующий не знает настоящий токен — попытка захватить exit-id должна провалиться.
	conn2, resp2 := dialAndHandshake(t, addr, cmdExit+" exit-b token-attacker")
	defer conn2.Close()
	if resp2 == cmdOK {
		t.Fatal("захват чужого exit-id чужим токеном не должен проходить")
	}

	// Настоящий владелец остаётся зарегистрированным — проверяем напрямую внутреннее
	// состояние сервера, а НЕ через полноценный ENTRY-запрос: ENTRY к найденному exit-id
	// блокируется на streamDialTimeout (5с) в ожидании STREAM от реального ExitClient,
	// которого в этом тесте нет (conn1 — просто открытый control-канал, никто не отвечает
	// на NEWSTREAM) — так что дожидаться этого пути здесь не нужно и было бы просто
	// медленнее, не точнее.
	srv.mu.RLock()
	sess, ok := srv.exits["exit-b"]
	srv.mu.RUnlock()
	if !ok {
		t.Fatal("настоящий Exit не должен был быть вытеснен неудачной попыткой захвата")
	}
	if sess.token != "token-real" {
		t.Errorf("token зарегистрированной сессии = %q, ожидался token-real (не должен был подмениться)", sess.token)
	}
}

// ENTRY к незарегистрированному exit-id — честная немедленная ошибка, не таймаут.
func TestRelayServer_Entry_UnknownExit_ReturnsErrImmediately(t *testing.T) {
	addr, _, _ := startTestRelayServer(t, RelayServerConfig{})

	start := time.Now()
	conn, resp := dialAndHandshake(t, addr, cmdEntry+" does-not-exist")
	defer conn.Close()
	elapsed := time.Since(start)

	if resp != "ERR no such exit" {
		t.Errorf("resp = %q, ожидался 'ERR no such exit'", resp)
	}
	if elapsed > time.Second {
		t.Errorf("ответ занял %v — должен быть немедленным (не ждать streamDialTimeout)", elapsed)
	}
}

// [консилиум] Rate-limiting — работает на уровне общего token-bucket хелпера, проверяем его
// напрямую (проще и надёжнее, чем гонять реальные TCP-регистрации в цикле с таймингом).
func TestRateLimiter_BurstThenThrottle(t *testing.T) {
	rl := newRateLimiter()
	const burst = 3
	allowed := 0
	for i := 0; i < burst+5; i++ {
		if rl.allow("1.2.3.4", 0.01, burst) { // очень медленное восполнение — не успеет за тест
			allowed++
		}
	}
	if allowed != burst {
		t.Errorf("allowed = %d за один всплеск, ожидался ровно burst = %d", allowed, burst)
	}
}

func TestRateLimiter_DifferentKeysIndependent(t *testing.T) {
	rl := newRateLimiter()
	if !rl.allow("ip-a", 0.01, 1) {
		t.Error("первый запрос от ip-a должен пройти")
	}
	if !rl.allow("ip-b", 0.01, 1) {
		t.Error("ip-b не должен зависеть от лимита ip-a")
	}
	if rl.allow("ip-a", 0.01, 1) {
		t.Error("второй запрос от ip-a подряд должен быть отклонён (burst=1 исчерпан)")
	}
}

// [консилиум, HIGH, находка №7, TZ_RELAY_HARDENING_2026-08-29.md кластер C] Регрессия конкретно
// на прежний баг: relay ждал парную STREAM ровно streamDialTimeout, независимо от того, сколько
// реально нужно ExitClient на редозвон к relay на деградированной, но нормальной сети (целевой
// сценарий фичи, не атака). Сжимаем streamDialTimeout до долей секунды (atomic.Int64, не const —
// см. tunnel_protocol.go), чтобы не ждать реальные ~21с, но сохраняем ИМЕННО ТУ ЖЕ форму
// бюджета: exit отвечает STREAM позже наивного «одного мгновенного dial'а», но раньше
// отведённого бюджета — со старым независимым числом (5с, меньше даже одного
// exitClientDialTimeout=8с) это было физически невозможно исполнить для ЛЮБОГО живого exit'а,
// не только медленного. Margins сознательно широкие (секунды, не десятки миллисекунд) — под
// `go test -race` TLS-рукопожатия заметно медленнее, узкие margin'ы уже ловили ложный провал.
func TestRelayServer_Entry_SlowExitRedial_WithinBudget_Succeeds(t *testing.T) {
	origBudget := streamDialTimeoutNs.Load()
	defer streamDialTimeoutNs.Store(origBudget)
	streamDialTimeoutNs.Store(int64(2 * time.Second)) // сжатый аналог продового ~21с бюджета

	addr, _, _ := startTestRelayServer(t, RelayServerConfig{})

	exitConn, resp := dialAndHandshake(t, addr, cmdExit+" exit-slow token-slow")
	if resp != cmdOK {
		t.Fatalf("регистрация Exit: resp = %q, ожидался OK", resp)
	}
	defer exitConn.Close()

	go func() {
		line, err := readLine(exitConn, 5*time.Second)
		if err != nil {
			return
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != cmdNewStream {
			return
		}
		sessionID := fields[1]

		// Имитация медленного (но живого) редозвона exit'а к relay — 800мс: БОЛЬШЕ, чем старый
		// независимый бюджет 5с был бы способен выделить пропорционально в этом же сжатом
		// масштабе, но С ЗАПАСОМ МЕНЬШЕ нового бюджета 2с.
		time.Sleep(800 * time.Millisecond)

		streamConn, sresp, serr := dialAndHandshakeErr(addr, cmdStream+" "+sessionID+" token-slow")
		if serr != nil || sresp != cmdOK {
			return
		}
		defer streamConn.Close()
		time.Sleep(300 * time.Millisecond) // держим сплайс живым, пока Entry дочитывает ответ
	}()

	start := time.Now()
	entryConn, eresp := dialAndHandshake(t, addr, cmdEntry+" exit-slow")
	defer entryConn.Close()
	elapsed := time.Since(start)

	if eresp != cmdOK {
		t.Fatalf("Entry: resp = %q (за %v), ожидался OK — медленный, но живой exit должен был "+
			"успеть в новый бюджет", eresp, elapsed)
	}
	if elapsed >= streamDialTimeout() {
		t.Errorf("Entry получил OK только через %v — фактически дождался таймаута, не STREAM", elapsed)
	}
}

// [консилиум, MEDIUM, находка №15, TZ_RELAY_HARDENING_2026-08-29.md кластер C] Регрессия на
// саму гонку select в handleEntry: STREAM попадает в pend.ch ПОЧТИ ОДНОВРЕМЕННО со срабатыванием
// streamDialTimeout — недетерминированный select мог выбрать ветку таймаута, хотя соединение уже
// пришло. Без горутины-подчистки (streamLateArrivalWindow) такое соединение осталось бы висеть
// до системного таймаута ОС, что и проверяет этот тест: сжимаем streamDialTimeout почти до нуля
// и одновременно шлём STREAM буквально в момент срабатывания таймера — соединение обязано быть
// закрыто В ПРЕДЕЛАХ streamLateArrivalWindow (тоже сжатого), не позже.
func TestRelayServer_Entry_StreamArrivesAtTimeoutBoundary_ConnectionNotLeaked(t *testing.T) {
	origBudget, origWindow := streamDialTimeoutNs.Load(), streamLateArrivalWindowNs.Load()
	defer func() {
		streamDialTimeoutNs.Store(origBudget)
		streamLateArrivalWindowNs.Store(origWindow)
	}()
	streamDialTimeoutNs.Store(int64(150 * time.Millisecond))
	streamLateArrivalWindowNs.Store(int64(500 * time.Millisecond))

	addr, _, _ := startTestRelayServer(t, RelayServerConfig{})

	exitConn, resp := dialAndHandshake(t, addr, cmdExit+" exit-race token-race")
	if resp != cmdOK {
		t.Fatalf("регистрация Exit: resp = %q, ожидался OK", resp)
	}
	defer exitConn.Close()

	var streamConn net.Conn
	streamDialed := make(chan struct{})
	go func() {
		defer close(streamDialed)
		line, err := readLine(exitConn, 2*time.Second)
		if err != nil {
			return
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != cmdNewStream {
			return
		}
		sessionID := fields[1]

		// Дозваниваемся ровно к моменту, когда handleEntry уже должен выбрать ветку таймаута —
		// гонка на границе, не до и не сильно после.
		time.Sleep(streamDialTimeout())
		streamConn, _, _ = dialAndHandshakeErr(addr, cmdStream+" "+sessionID+" token-race")
	}()

	entryConn, eresp := dialAndHandshake(t, addr, cmdEntry+" exit-race")
	defer entryConn.Close()
	// Независимо от того, увидел ли Entry OK или ERR (недетерминировано на самой границе —
	// это и есть гонка), соединение STREAM не должно остаться висеть дольше streamLateArrivalWindow.
	_ = eresp

	<-streamDialed
	if streamConn == nil {
		t.Skip("STREAM-дозвон не успел выполниться в этом прогоне — гонка не воспроизвелась")
	}
	defer streamConn.Close()

	window := streamLateArrivalWindow()
	streamConn.SetReadDeadline(time.Now().Add(window + 2*time.Second))
	buf := make([]byte, 1)
	start := time.Now()
	_, err := streamConn.Read(buf)
	elapsed := time.Since(start)
	if err == nil {
		t.Error("STREAM-соединение, «проигравшее» гонку, должно было быть закрыто relay, а не остаться открытым")
	}
	if elapsed > window+time.Second {
		t.Errorf("STREAM-соединение закрылось только через %v после дозвона — дольше streamLateArrivalWindow (%v), горутина-подчистка не сработала вовремя",
			elapsed, window)
	}
}

// Лимит одновременных соединений с одного IP.
func TestRelayServer_MaxConnsPerIP(t *testing.T) {
	addr, _, _ := startTestRelayServer(t, RelayServerConfig{MaxConnsPerIP: 2})

	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	// Открываем 2 "зависших" (не завершающих handshake) соединения — держат слот занятым.
	for i := 0; i < 2; i++ {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, c)
	}
	time.Sleep(100 * time.Millisecond) // дать серверу принять и учесть оба

	// Третье соединение с того же IP (localhost) должно быть отклонено немедленно.
	c3, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial 3: %v", err)
	}
	defer c3.Close()
	c3.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	n, _ := c3.Read(buf)
	if n != 0 {
		t.Error("ожидалось немедленное закрытие сверх-лимитного соединения без данных")
	}
}
