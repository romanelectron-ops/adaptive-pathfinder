package relay

import (
	"context"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// [2026-09-29] Лимит устройств роли «Выход» (internal/singbox/admission_proxy.go) должен
// различать «Входы», пришедшие через relay. Для этого relay дописывает в NEWSTREAM адрес
// «Входа» — но только «Выходу», который прислал «CAPS src». Тесты фиксируют совместимость в
// обе стороны и сквозную доставку адреса до ExitClient.DialLocal.

// rawExitConn регистрирует «Выход» вручную (без ExitClient) — так эмулируется и СТАРЫЙ «Выход»
// (без CAPS), и новый (с CAPS), и читаются сырые строки control-канала relay.
func rawExitConn(t *testing.T, relayAddr, fingerprint, exitID, token string, sendCaps bool) net.Conn {
	t.Helper()
	// Сроки — с запасом под загруженную машину (ревью 2026-09-30, ложные падения на 100% CPU).
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	conn, err := dialRelayTLS(ctx, relayAddr, fingerprint, 15*time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := writeLine(conn, cmdExit+" "+exitID+" "+token); err != nil {
		t.Fatalf("write EXIT: %v", err)
	}
	if resp, err := readLine(conn, 15*time.Second); err != nil || resp != cmdOK {
		t.Fatalf("EXIT не принят: %q %v", resp, err)
	}
	if sendCaps {
		if err := writeLine(conn, cmdCaps+" "+capSrc); err != nil {
			t.Fatalf("write CAPS: %v", err)
		}
		time.Sleep(150 * time.Millisecond) // relay разбирает CAPS асинхронно, в цикле control-канала
	}
	return conn
}

// entryKnock — «Вход» стучится в relay; возвращает поля первой строки, которую relay
// прислал «Выходу» по control-каналу.
func entryKnock(t *testing.T, relayAddr, fingerprint, exitID string, exitControl net.Conn) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entry, err := dialRelayTLS(ctx, relayAddr, fingerprint, 3*time.Second)
	if err != nil {
		t.Fatalf("dial relay (entry): %v", err)
	}
	t.Cleanup(func() { entry.Close() })
	if err := writeLine(entry, cmdEntry+" "+exitID); err != nil {
		t.Fatalf("write ENTRY: %v", err)
	}
	line, err := readLine(exitControl, 3*time.Second)
	if err != nil {
		t.Fatalf("«Выход» не получил NEWSTREAM: %v", err)
	}
	return strings.Fields(line)
}

// Старый «Выход» (CAPS не шлёт) получает прежний двухполевой NEWSTREAM — его разбор
// (`len(fields) != 2`) не ломается.
func TestRelay_ExitWithoutCaps_GetsTwoFieldNewStream(t *testing.T) {
	relayAddr, fingerprint, _ := startTestRelayServer(t, RelayServerConfig{})
	exitID, token, err := GenerateExitCredentials()
	if err != nil {
		t.Fatal(err)
	}
	exit := rawExitConn(t, relayAddr, fingerprint, exitID, token, false)
	fields := entryKnock(t, relayAddr, fingerprint, exitID, exit)
	if len(fields) != 2 || fields[0] != cmdNewStream {
		t.Fatalf("старый «Выход» получил %v, ожидалось ровно [NEWSTREAM <sid>]", fields)
	}
}

// Новый «Выход» (CAPS src) получает третье поле — адрес «Входа», как его видит relay.
func TestRelay_ExitWithCapsSrc_GetsEntryAddress(t *testing.T) {
	relayAddr, fingerprint, _ := startTestRelayServer(t, RelayServerConfig{})
	exitID, token, err := GenerateExitCredentials()
	if err != nil {
		t.Fatal(err)
	}
	exit := rawExitConn(t, relayAddr, fingerprint, exitID, token, true)
	fields := entryKnock(t, relayAddr, fingerprint, exitID, exit)
	if len(fields) != 3 || fields[0] != cmdNewStream {
		t.Fatalf("«Выход» с CAPS получил %v, ожидалось [NEWSTREAM <sid> <ip>]", fields)
	}
	if fields[2] != "127.0.0.1" {
		t.Errorf("адрес «Входа» = %q, ожидался 127.0.0.1 (loopback-тест)", fields[2])
	}
}

// Сквозной путь: ExitClient с DialLocal получает адрес «Входа» и сам открывает соединение
// (здесь — с echo-сервером); байты идут туда и обратно.
func TestRelay_DialLocal_ReceivesSourceIP_EndToEnd(t *testing.T) {
	relayAddr, fingerprint, _ := startTestRelayServer(t, RelayServerConfig{})
	echoAddr := echoListener(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	exitID, token, err := GenerateExitCredentials()
	if err != nil {
		t.Fatal(err)
	}
	srcCh := make(chan string, 4)
	exitClient := NewExitClient(relayAddr, exitID, token, "127.0.0.1:1", fingerprint) // LocalTarget НЕ должен использоваться
	exitClient.DialLocal = func(ctx context.Context, sourceIP string) (net.Conn, error) {
		srcCh <- sourceIP
		var d net.Dialer
		return d.DialContext(ctx, "tcp", echoAddr)
	}
	go exitClient.Run(ctx)

	deadline := time.Now().Add(3 * time.Second)
	for !exitClient.IsConnected() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !exitClient.IsConnected() {
		t.Fatal("ExitClient не зарегистрировался")
	}
	time.Sleep(200 * time.Millisecond) // relay успевает разобрать CAPS

	bridge := NewEntryBridge(relayAddr, exitID, fingerprint)
	localAddr, err := bridge.Start(ctx)
	if err != nil {
		t.Fatalf("EntryBridge.Start: %v", err)
	}
	defer bridge.Stop()

	conn, err := net.DialTimeout("tcp", localAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo через DialLocal: %q %v", buf, err)
	}

	select {
	case got := <-srcCh:
		if got != "127.0.0.1" {
			t.Errorf("DialLocal получил sourceIP=%q, ожидался 127.0.0.1", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DialLocal не был вызван")
	}
}

// Отказ DialLocal (например, лимит устройств) закрывает сторону relay — «Вход» не зависает.
func TestRelay_DialLocalRefuses_EntryConnectionClosed(t *testing.T) {
	relayAddr, fingerprint, _ := startTestRelayServer(t, RelayServerConfig{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	exitID, token, err := GenerateExitCredentials()
	if err != nil {
		t.Fatal(err)
	}
	exitClient := NewExitClient(relayAddr, exitID, token, "127.0.0.1:1", fingerprint)
	exitClient.DialLocal = func(ctx context.Context, sourceIP string) (net.Conn, error) {
		return nil, io.ErrClosedPipe
	}
	go exitClient.Run(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for !exitClient.IsConnected() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !exitClient.IsConnected() {
		t.Fatal("ExitClient не зарегистрировался")
	}

	bridge := NewEntryBridge(relayAddr, exitID, fingerprint)
	localAddr, err := bridge.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Stop()

	conn, err := net.DialTimeout("tcp", localAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte("x"))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("ожидалось закрытие соединения «Входа» после отказа DialLocal, но пришли данные")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("«Вход» завис до таймаута вместо закрытия соединения после отказа DialLocal")
	}
}

// ─── [ревью 1.1.10, C1/F1] гонка CAPS: «Вход» в окне между регистрацией «Выхода» и его CAPS ──

// setCapsWaitWindow сжимает/растягивает окно ожидания CAPS на время теста (capsWaitWindowNs —
// atomic по той же причине, что и streamDialTimeoutNs: писатель — тест, читатели — горутины
// relay). Возвращает прежнее значение через t.Cleanup.
func setCapsWaitWindow(t *testing.T, d time.Duration) {
	t.Helper()
	old := capsWaitWindowNs.Swap(int64(d))
	t.Cleanup(func() { capsWaitWindowNs.Store(old) })
}

// timedEntryKnock — «Вход» стучится в relay, как entryKnock, но отдельно от TLS-дозвона
// замеряет, сколько «Выход» ждал NEWSTREAM с момента отправки ENTRY; afterEntry (может быть
// nil) вызывается сразу после отправки ENTRY — так тесты «доставляют» CAPS в нужный момент.
func timedEntryKnock(t *testing.T, relayAddr, fingerprint, exitID string, exitControl net.Conn, afterEntry func()) ([]string, time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	entry, err := dialRelayTLS(ctx, relayAddr, fingerprint, 15*time.Second)
	if err != nil {
		t.Fatalf("dial relay (entry): %v", err)
	}
	t.Cleanup(func() { entry.Close() })
	start := time.Now()
	if err := writeLine(entry, cmdEntry+" "+exitID); err != nil {
		t.Fatalf("write ENTRY: %v", err)
	}
	if afterEntry != nil {
		afterEntry()
	}
	line, err := readLine(exitControl, 8*time.Second)
	if err != nil {
		t.Fatalf("«Выход» не получил NEWSTREAM: %v", err)
	}
	return strings.Fields(line), time.Since(start)
}

// (а) ENTRY приходит СРАЗУ после регистрации «Выхода», а его CAPS — через 100 мс. Раньше relay
// отвечал двухполевым NEWSTREAM немедленно (флаг wantsSrc ещё не выставлен), и ExitClient
// открывал поток как устройство «relay» — фантом в лимите. Теперь relay ждёт CAPS и шлёт адрес.
func TestRelay_EntryBeforeCaps_WaitsAndGetsEntryAddress(t *testing.T) {
	setCapsWaitWindow(t, 3*time.Second) // заведомо длиннее 100 мс задержки CAPS
	relayAddr, fingerprint, _ := startTestRelayServer(t, RelayServerConfig{})
	exitID, token, err := GenerateExitCredentials()
	if err != nil {
		t.Fatal(err)
	}
	exit := rawExitConn(t, relayAddr, fingerprint, exitID, token, false) // зарегистрирован, CAPS ещё нет

	fields, waited := timedEntryKnock(t, relayAddr, fingerprint, exitID, exit, func() {
		time.AfterFunc(100*time.Millisecond, func() { writeLine(exit, cmdCaps+" "+capSrc) })
	})
	if len(fields) != 3 || fields[0] != cmdNewStream {
		t.Fatalf("ENTRY в окне до CAPS получил %v, ожидалось [NEWSTREAM <sid> <ip>] (иначе — фантомное устройство «relay»)", fields)
	}
	if fields[2] != "127.0.0.1" {
		t.Errorf("адрес «Входа» = %q, ожидался 127.0.0.1", fields[2])
	}
	if waited < 50*time.Millisecond {
		t.Errorf("relay ответил за %v — раньше, чем пришёл CAPS (100 мс): ожидание не сработало", waited)
	}
	if waited > 2*time.Second {
		t.Errorf("relay ждал %v — до конца окна вместо снятия ожидания по приходу CAPS", waited)
	}
}

// (б) «Выход» без CAPS вовсе (старая версия): первый поток МОЛОДОЙ сессии задерживается не
// дольше окна и получает прежний двухполевой NEWSTREAM; у зрелой сессии задержки нет совсем —
// иначе каждый поток старого «Выхода» платил бы окном.
func TestRelay_ExitWithoutCaps_WaitBoundedThenMatureNotDelayed(t *testing.T) {
	// Окно взято с запасом относительно шума планировщика: под -race на загруженной машине
	// обычная доставка NEWSTREAM занимала до ~0.6 с, и порог «половина окна» при окне 0.8 с давал
	// ложные провалы. Повторное ожидание, если бы оно было, стоило бы почти целое окно.
	const window = 2 * time.Second
	setCapsWaitWindow(t, window)
	relayAddr, fingerprint, _ := startTestRelayServer(t, RelayServerConfig{})
	exitID, token, err := GenerateExitCredentials()
	if err != nil {
		t.Fatal(err)
	}
	beforeRegister := time.Now()
	exit := rawExitConn(t, relayAddr, fingerprint, exitID, token, false)

	fields, _ := timedEntryKnock(t, relayAddr, fingerprint, exitID, exit, nil)
	sinceRegister := time.Since(beforeRegister)
	if len(fields) != 2 || fields[0] != cmdNewStream {
		t.Fatalf("«Выход» без CAPS получил %v, ожидалось ровно [NEWSTREAM <sid>]", fields)
	}
	// Дедлайн окна отсчитывается от создания сессии (не раньше beforeRegister): ответ не может
	// прийти раньше него (допуск — грубость таймера Windows) и не должен уходить сильно за него.
	if sinceRegister < window-100*time.Millisecond {
		t.Errorf("молодая сессия без CAPS: ответ через %v после регистрации, окно ожидания %v не выдержано", sinceRegister, window)
	}
	if sinceRegister > window+3*time.Second {
		t.Errorf("молодая сессия без CAPS: ответ через %v — ожидание не ограничено окном %v", sinceRegister, window)
	}

	// Окно истекло — сессия «зрелая»: следующие потоки идут без задержки.
	for i := 0; i < 2; i++ {
		fields, waited := timedEntryKnock(t, relayAddr, fingerprint, exitID, exit, nil)
		if len(fields) != 2 {
			t.Fatalf("зрелая сессия, поток %d: %v, ожидалось 2 поля", i, fields)
		}
		if waited > window*3/4 {
			t.Errorf("зрелая сессия, поток %d: задержка %v — окно ожидания CAPS повторилось для каждого потока", i, waited)
		}
	}
}

// (в) Вытеснение сессии не оставляет висящих ожиданий: «Вход» ждёт CAPS у молодой сессии, тот же
// владелец переподключается (старую закрывают) — ожидание обязано сняться сразу, а не
// досиживать окно; ENTRY получает честный отказ, запись pending не остаётся.
func TestRelay_ExitEvictedWhileEntryWaitsForCaps_NoHangingWait(t *testing.T) {
	setCapsWaitWindow(t, 20*time.Second) // если ожидание НЕ снимется — тест упрётся в таймаут чтения
	relayAddr, fingerprint, srv := startTestRelayServer(t, RelayServerConfig{})
	exitID, token, err := GenerateExitCredentials()
	if err != nil {
		t.Fatal(err)
	}
	_ = rawExitConn(t, relayAddr, fingerprint, exitID, token, false) // молодая сессия без CAPS

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entry, err := dialRelayTLS(ctx, relayAddr, fingerprint, 3*time.Second)
	if err != nil {
		t.Fatalf("dial relay (entry): %v", err)
	}
	t.Cleanup(func() { entry.Close() })
	if err := writeLine(entry, cmdEntry+" "+exitID); err != nil {
		t.Fatalf("write ENTRY: %v", err)
	}
	// pending заводится в handleEntry ДО ожидания CAPS — по нему видно, что обработчик ENTRY
	// уже нашёл сессию и вот-вот (или уже) стоит в awaitCaps.
	pendingCount := func() int {
		srv.pendingMu.Lock()
		defer srv.pendingMu.Unlock()
		return len(srv.pending)
	}
	for deadline := time.Now().Add(5 * time.Second); pendingCount() == 0 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	if pendingCount() != 1 {
		t.Fatal("handleEntry не дошёл до ожидания CAPS")
	}

	start := time.Now()
	_ = rawExitConn(t, relayAddr, fingerprint, exitID, token, false) // тот же владелец → старая сессия закрыта

	resp, err := readLine(entry, 5*time.Second)
	switch {
	case err == nil:
		if !strings.HasPrefix(resp, cmdErr) {
			t.Errorf("ответ «Входу» = %q, ожидался отказ (ERR ...)", resp)
		}
	default:
		// Проверяется именно «ожидание не повисло». Закрытие relay'ем своей стороны сразу после
		// записи ERR на Windows нередко приходит клиенту как сброс соединения раньше самой
		// строки — это тот же снятый ожидающий обработчик, а не зависание; зависание выглядит
		// как таймаут чтения (на прежнем коде — именно он).
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatalf("«Вход» не получил ответа после вытеснения сессии (ожидание повисло): %v", err)
		}
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("ожидание CAPS снялось только через %v после вытеснения", took)
	}
	if n := pendingCount(); n != 0 {
		t.Errorf("после отказа осталось %d записей pending, ожидалось 0", n)
	}
}

// awaitCaps на голом exitSession: все ветки выхода и отсутствие утечки горутин.
func TestAwaitCaps_ReturnsOnEveryExitPath_NoGoroutineLeak(t *testing.T) {
	newSess := func(window time.Duration) *exitSession {
		c, _ := net.Pipe() // close() закрывает conn — нужна настоящая заглушка
		return &exitSession{
			conn: c, done: make(chan struct{}), capsReady: make(chan struct{}),
			capsDeadline: time.Now().Add(window),
		}
	}
	waitReturn := func(sess *exitSession) <-chan struct{} {
		ch := make(chan struct{})
		go func() { sess.awaitCaps(); close(ch) }()
		return ch
	}
	mustBlock := func(t *testing.T, ch <-chan struct{}, what string) {
		t.Helper()
		select {
		case <-ch:
			t.Fatalf("awaitCaps вернулся сам по себе (%s), хотя ни одно событие не наступило", what)
		case <-time.After(100 * time.Millisecond):
		}
	}
	mustReturn := func(t *testing.T, ch <-chan struct{}, what string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Fatalf("awaitCaps не вернулся: %s", what)
		}
	}

	t.Run("зрелая сессия (окно истекло) — без задержки", func(t *testing.T) {
		sess := newSess(-time.Second)
		mustReturn(t, waitReturn(sess), "зрелая сессия")
	})
	t.Run("сессия без полей ожидания (собрана вручную) — без задержки", func(t *testing.T) {
		mustReturn(t, waitReturn(&exitSession{}), "нулевой exitSession")
	})
	t.Run("CAPS пришёл", func(t *testing.T) {
		sess := newSess(time.Minute)
		ch := waitReturn(sess)
		mustBlock(t, ch, "до CAPS")
		sess.markCapsReady()
		sess.markCapsReady() // идемпотентно
		mustReturn(t, ch, "после markCapsReady")
	})
	t.Run("окно истекло само", func(t *testing.T) {
		sess := newSess(150 * time.Millisecond)
		start := time.Now()
		mustReturn(t, waitReturn(sess), "по таймеру окна")
		if el := time.Since(start); el < 100*time.Millisecond {
			t.Errorf("вернулся за %v — раньше конца окна 150 мс", el)
		}
	})
	t.Run("сессия закрыта (вытеснение/обрыв)", func(t *testing.T) {
		sess := newSess(time.Minute)
		ch := waitReturn(sess)
		mustBlock(t, ch, "до закрытия сессии")
		sess.close()
		mustReturn(t, ch, "после закрытия сессии")
	})

	// Много ждущих на одной сессии: все освобождаются одним событием, горутины не копятся.
	before := runtime.NumGoroutine()
	sess := newSess(time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); sess.awaitCaps() }()
	}
	time.Sleep(100 * time.Millisecond)
	sess.close()
	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	mustReturn(t, finished, "200 ждущих после закрытия сессии")
	for deadline := time.Now().Add(2 * time.Second); runtime.NumGoroutine() > before+5 && time.Now().Before(deadline); {
		time.Sleep(20 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before+5 {
		t.Errorf("горутин было %d, стало %d — ожидания CAPS не освободились", before, after)
	}
}
