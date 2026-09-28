package relay

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// fakeExitHandshakeServer — минимальный TLS-сервер, отвечающий ровно на EXIT-handshake, без
// полноценного RelayServer — изолирует тест ExitClient.runOnce от логики самого relay. TLS
// обязателен здесь так же, как и в самом ExitClient (TZ_RELAY_HARDENING_2026-08-29.md
// кластер B, dialRelayTLS) — иначе рукопожатие клиента отвалилось бы ещё до отправки EXIT.
func fakeExitHandshakeServer(t *testing.T, respond string) (addr, fingerprint string) {
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
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := tlsLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err := readLine(conn, time.Second); err != nil {
			return
		}
		writeLine(conn, respond)
		// держим соединение открытым немного, чтобы serve() успел войти в чтение
		time.Sleep(50 * time.Millisecond)
	}()
	return ln.Addr().String(), fp
}

func TestExitClient_RunOnce_OK_ReportsConnected(t *testing.T) {
	addr, fingerprint := fakeExitHandshakeServer(t, cmdOK)
	c := NewExitClient(addr, "exit-x", "token-x", "127.0.0.1:1", fingerprint)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connected, err := c.runOnce(ctx)
	if !connected {
		t.Error("connected должен быть true после OK от relay")
	}
	// err ожидаема — соединение обрывается сразу после (fakeExitHandshakeServer закрывает
	// его), это нормальный «конец сессии», не провал самого handshake.
	_ = err
}

func TestExitClient_RunOnce_ERR_ReportsNotConnected(t *testing.T) {
	addr, fingerprint := fakeExitHandshakeServer(t, "ERR exit-id занят другим владельцем")
	c := NewExitClient(addr, "exit-y", "token-y", "127.0.0.1:1", fingerprint)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connected, err := c.runOnce(ctx)
	if connected {
		t.Error("connected должен быть false при ERR от relay")
	}
	if err == nil {
		t.Error("ожидалась ошибка при ERR-ответе")
	}
}

func TestExitClient_RunOnce_UnreachableRelay_ReportsNotConnected(t *testing.T) {
	c := NewExitClient("127.0.0.1:1", "exit-z", "token-z", "127.0.0.1:1", "irrelevant-unreachable-dial-fails-first")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connected, err := c.runOnce(ctx)
	if connected {
		t.Error("connected должен быть false, когда relay недоступен")
	}
	if err == nil {
		t.Error("ожидалась ошибка dial")
	}
}

// [консилиум, HIGH, находка №11, TZ_RELAY_HARDENING_2026-08-29.md кластер H] IsConnected()
// обязан стать true, пока control-канал реально держится после OK, и вернуться в false сразу
// же, как только соединение оборвалось (фейковый сервер закрывает его через ~50мс) — в отличие
// от IsRunning(), который в этот момент ещё долго остаётся true (горутина Run продолжает жить
// в backoff-цикле).
func TestExitClient_RunOnce_OK_SetsConnectedTrueThenFalseOnDrop(t *testing.T) {
	addr, fingerprint := fakeExitHandshakeServer(t, cmdOK)
	c := NewExitClient(addr, "exit-conn", "token-conn", "127.0.0.1:1", fingerprint)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		c.runOnce(ctx)
		close(done)
	}()

	deadline := time.Now().Add(time.Second)
	sawConnected := false
	for time.Now().Before(deadline) {
		if c.IsConnected() {
			sawConnected = true
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !sawConnected {
		t.Fatal("IsConnected() ни разу не стал true после OK от relay")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runOnce не вернулся после закрытия соединения фейковым сервером")
	}
	if c.IsConnected() {
		t.Error("IsConnected() = true после того, как control-канал оборвался")
	}
}

// Регрессия на сам дефект находки №11: relay недоступен весь тест — ExitClient уходит в
// backoff-цикл, IsRunning() (горутина Run жива) остаётся true, но IsConnected() обязан
// оставаться false ВСЁ ЭТО ВРЕМЯ. Раньше единственным полем было IsRunning(), которое в этом
// сценарии молча врало пользователю «подключён».
func TestExitClient_Run_UnreachableRelay_IsConnectedStaysFalseWhileRunning(t *testing.T) {
	c := NewExitClient("127.0.0.1:1", "exit-w", "token-w", "127.0.0.1:1", "irrelevant-unreachable-dial-fails-first")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for !c.IsRunning() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !c.IsRunning() {
		t.Fatal("IsRunning() не стал true после запуска Run()")
	}

	for i := 0; i < 10; i++ {
		if c.IsConnected() {
			t.Fatal("IsConnected() = true, хотя relay недоступен весь тест")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !c.IsRunning() {
		t.Fatal("IsRunning() перестал быть true во время теста — горутина неожиданно завершилась")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run() не вернулся после отмены ctx")
	}
	if c.IsRunning() {
		t.Error("IsRunning() = true после возврата Run()")
	}
	if c.IsConnected() {
		t.Error("IsConnected() = true после возврата Run()")
	}
}

// [консилиум] Backoff — конкретные параметры, не абстрактный факт "растёт".
func TestJitter_WithinTwentyPercentBounds(t *testing.T) {
	base := 10 * time.Second
	for i := 0; i < 200; i++ {
		got := jitter(base)
		min := base - base/5
		max := base + base/5
		if got < min || got > max {
			t.Fatalf("jitter(%v) = %v, вне диапазона [%v, %v]", base, got, min, max)
		}
	}
}

func TestExitClient_Run_BackoffGrowsAndCapsAtMax(t *testing.T) {
	// Считаем итерации backoff чисто арифметически (то же выражение, что в Run) — не гоняем
	// реальные 30+ секунд в тесте.
	backoff := exitClientInitialBackoff
	steps := 0
	for backoff < exitClientMaxBackoff && steps < 100 {
		backoff = time.Duration(float64(backoff) * exitClientBackoffFactor)
		if backoff > exitClientMaxBackoff {
			backoff = exitClientMaxBackoff
		}
		steps++
	}
	if backoff != exitClientMaxBackoff {
		t.Fatalf("backoff не достиг потолка: %v", backoff)
	}
	if steps == 0 || steps > 10 {
		t.Errorf("неожиданное число шагов до потолка: %d (со стартом %v, потолком %v, ×%v)",
			steps, exitClientInitialBackoff, exitClientMaxBackoff, exitClientBackoffFactor)
	}
}
