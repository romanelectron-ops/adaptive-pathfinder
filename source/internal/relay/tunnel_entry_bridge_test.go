package relay

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// echoListener — минимальная замена локального sing-box inbound для тестов: эхо-сервер.
func echoListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// [консилиум, HIGH] Основной сценарий мастера (докс §2.3, §11.1): «Вход» вставляет ссылку и
// подключается РАНЬШЕ, чем ExitClient партнёра успел зарегистрироваться на relay. Без
// ретрая это падало бы с первой попытки — здесь Exit регистрируется с намеренной задержкой,
// внутри окна ретраев EntryBridge.
func TestEntryBridge_RetriesUntilExitRegisters(t *testing.T) {
	relayAddr, fingerprint, _ := startTestRelayServer(t, RelayServerConfig{})
	echoAddr := echoListener(t)

	const exitID = "race-exit"
	const token = "race-token"

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Exit регистрируется с задержкой — гарантированно ПОСЛЕ первой попытки ENTRY, но
	// внутри окна ретраев (entryRetryAttempts×entryRetryDelay).
	exitClient := NewExitClient(relayAddr, exitID, token, echoAddr, fingerprint)
	go func() {
		time.Sleep(1500 * time.Millisecond)
		exitClient.Run(ctx)
	}()

	bridge := NewEntryBridge(relayAddr, exitID, fingerprint)
	localAddr, err := bridge.Start(ctx)
	if err != nil {
		t.Fatalf("EntryBridge.Start: %v", err)
	}
	defer bridge.Stop()

	conn, err := net.DialTimeout("tcp", localAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial EntryBridge: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello-through-relay-with-retry")
	conn.SetDeadline(time.Now().Add(12 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v (ретрай ENTRY не дождался регистрации Exit)", err)
	}
	if string(got) != string(payload) {
		t.Errorf("echo = %q, ожидалось %q", got, payload)
	}
}

func TestEntryBridge_StopReleasesPort(t *testing.T) {
	relayAddr, fingerprint, _ := startTestRelayServer(t, RelayServerConfig{})
	ctx := context.Background()

	bridge := NewEntryBridge(relayAddr, "unused-exit", fingerprint)
	addr1, err := bridge.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	bridge.Stop()

	// После Stop порт свободен — новый Start успешно поднимается заново (не обязательно на
	// том же порту, но без ошибки "already running"/конфликта).
	addr2, err := bridge.Start(ctx)
	if err != nil {
		t.Fatalf("повторный Start после Stop: %v", err)
	}
	defer bridge.Stop()
	t.Logf("addr1=%s addr2=%s", addr1, addr2)

	// Старый listener больше не принимает соединения.
	conn, err := net.DialTimeout("tcp", addr1, 500*time.Millisecond)
	if err == nil {
		conn.Close()
		if addr1 != addr2 {
			t.Error("старый адрес EntryBridge всё ещё принимает соединения после Stop()")
		}
	}
}

// Повторный Stop() — обязательный сценарий для примитива с ручным жизненным циклом
// (аналог второго Close() у файлового дескриптора): вызывающая сторона (Engine.Stop()/
// Disconnect(), см. комментарий у acceptLoop) не обязана помнить, звала ли она Stop() уже
// — второй вызов, в том числе на уже остановленном bridge без единого соединения, обязан
// быть no-op, а не паниковать на закрытии уже закрытого listener'а/канала отмены.
func TestEntryBridge_StopIsIdempotent_NoPanic(t *testing.T) {
	relayAddr, fingerprint, _ := startTestRelayServer(t, RelayServerConfig{})
	ctx := context.Background()

	bridge := NewEntryBridge(relayAddr, "unused-exit", fingerprint)
	if _, err := bridge.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	bridge.Stop()
	bridge.Stop() // не должен паниковать
	bridge.Stop() // и третий раз тоже
}

// Stop() ДО единого Start() — тоже штатный случай (например, узел так и не был подключён,
// но код отключения зовёт Stop() безусловно) — не должен паниковать на нулевых полях.
func TestEntryBridge_StopWithoutStart_NoPanic(t *testing.T) {
	bridge := NewEntryBridge("127.0.0.1:1", "unused-exit", "deadbeef")
	bridge.Stop()
}

// Партнёр так и не включил роль «Выход» за всё окно ретраев (entryRetryAttempts×
// entryRetryDelay) — dialEntryWithRetry обязан в итоге сдаться, а не повиснуть навсегда:
// handleLocalConn должен закрыть локальное соединение, чтобы sing-box outbound увидел явный
// отказ и мог отработать собственный fallback, а не зависнуть в ожидании данных, которые
// никогда не придут.
func TestEntryBridge_ExitNeverRegisters_LocalConnClosedAfterRetriesExhausted(t *testing.T) {
	relayAddr, fingerprint, _ := startTestRelayServer(t, RelayServerConfig{})
	// Намеренно НЕ поднимаем ExitClient с этим exitID — партнёр так и не пришёл.

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	bridge := NewEntryBridge(relayAddr, "exit-that-never-shows-up", fingerprint)
	localAddr, err := bridge.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer bridge.Stop()

	conn, err := net.DialTimeout("tcp", localAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial EntryBridge: %v", err)
	}
	defer conn.Close()

	// entryRetryAttempts=3, entryRetryDelay=2s → ~4-6с до отказа. Достаточный запас deadline.
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Error("ожидалось закрытие локального соединения после исчерпания ретраев ENTRY, " +
			"вместо этого Read вернул данные/завис")
	}
}

func TestEntryBridge_StartTwiceWithoutStop_Errors(t *testing.T) {
	relayAddr, fingerprint, _ := startTestRelayServer(t, RelayServerConfig{})
	ctx := context.Background()

	bridge := NewEntryBridge(relayAddr, "unused-exit", fingerprint)
	if _, err := bridge.Start(ctx); err != nil {
		t.Fatalf("первый Start: %v", err)
	}
	defer bridge.Stop()

	if _, err := bridge.Start(ctx); err == nil {
		t.Error("повторный Start без Stop() должен вернуть ошибку")
	}
}
