package relay

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// Полный сквозной loopback-тест протокола (docs/PLAN_APF_RELAY_v1.0.md, фаза B.8):
// RelayServer + ExitClient (нацелен на TCP echo-listener) + EntryBridge — доказывает
// протокол целиком БЕЗ реальной сети/белого IP. Гонять с -race — конкурентный доступ к
// картам сессий/токенов (RelayServer.exits/pending) — самое вероятное место гонки.
func TestRelay_FullLoopback_EchoRoundTrip(t *testing.T) {
	relayAddr, fingerprint, _ := startTestRelayServer(t, RelayServerConfig{})
	echoAddr := echoListener(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	exitID, token, err := GenerateExitCredentials()
	if err != nil {
		t.Fatalf("GenerateExitCredentials: %v", err)
	}

	exitClient := NewExitClient(relayAddr, exitID, token, echoAddr, fingerprint)
	go exitClient.Run(ctx)

	// Ждём, пока ExitClient реально зарегистрируется, прежде чем поднимать EntryBridge —
	// отдельный тест на гонку старта уже есть (TestEntryBridge_RetriesUntilExitRegisters),
	// этот тест проверяет "счастливый путь" целиком.
	deadline := time.Now().Add(3 * time.Second)
	for !exitClient.IsRunning() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !exitClient.IsRunning() {
		t.Fatal("ExitClient не зарегистрировался за отведённое время")
	}

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

	payload := []byte("сквозной тест протокола relay, включая кириллицу")
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("echo = %q, ожидалось %q", got, payload)
	}
}

// Несколько одновременных Входов к одному Выходу — каждый получает СВОЙ поток, без
// смешения байт между сессиями (устраняет находку консилиума про возможную коллизию
// session-id при параллельных ENTRY).
func TestRelay_FullLoopback_ConcurrentEntries_NoCrossTalk(t *testing.T) {
	relayAddr, fingerprint, _ := startTestRelayServer(t, RelayServerConfig{})
	echoAddr := echoListener(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	exitID, token, err := GenerateExitCredentials()
	if err != nil {
		t.Fatalf("GenerateExitCredentials: %v", err)
	}
	exitClient := NewExitClient(relayAddr, exitID, token, echoAddr, fingerprint)
	go exitClient.Run(ctx)

	deadline := time.Now().Add(3 * time.Second)
	for !exitClient.IsRunning() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !exitClient.IsRunning() {
		t.Fatal("ExitClient не зарегистрировался")
	}

	bridge := NewEntryBridge(relayAddr, exitID, fingerprint)
	localAddr, err := bridge.Start(ctx)
	if err != nil {
		t.Fatalf("EntryBridge.Start: %v", err)
	}
	defer bridge.Stop()

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", localAddr, 2*time.Second)
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			payload := []byte{byte('A' + idx), byte('A' + idx), byte('A' + idx), byte('A' + idx)}
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write(payload); err != nil {
				errs <- err
				return
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil {
				errs <- err
				return
			}
			for _, b := range got {
				if b != payload[0] {
					errs <- err
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("параллельная сессия провалилась или байты смешались: %v", err)
		}
	}
}
