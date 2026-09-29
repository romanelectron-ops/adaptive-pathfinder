package relay

import (
	"context"
	"io"
	"net"
	"strings"
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialRelayTLS(ctx, relayAddr, fingerprint, 3*time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := writeLine(conn, cmdExit+" "+exitID+" "+token); err != nil {
		t.Fatalf("write EXIT: %v", err)
	}
	if resp, err := readLine(conn, 3*time.Second); err != nil || resp != cmdOK {
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
