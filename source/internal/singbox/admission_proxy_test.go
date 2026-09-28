package singbox

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func echoListenerForAdmissionTest(t *testing.T) string {
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

// [консилиум, CRITICAL] TOCTOU: N горутин одновременно бьют Accept — лимит не должен быть
// превышен ни разу, даже под гонкой. Гонять с -race.
func TestAdmissionProxy_ConcurrentConnections_LimitNeverExceeded(t *testing.T) {
	internalAddr := echoListenerForAdmissionTest(t)

	publicLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	const limit = 3
	proxy := NewAdmissionProxy(publicLn, internalAddr, limit, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go proxy.Serve(ctx)

	const attempts = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	var passed, rejected int
	var maxObservedCount int64

	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", publicLn.Addr().String(), 2*time.Second)
			if err != nil {
				mu.Lock()
				rejected++
				mu.Unlock()
				return
			}
			defer conn.Close()

			// proxy.Count() сам по себе безопасен (атомарная загрузка внутри AdmissionProxy),
			// но maxObservedCount — общая переменная ТЕСТА, и её нельзя читать вне mu:
			// раньше сравнение "c > maxObservedCount" делалось ДО захвата mu (двойная
			// проверка ради "оптимизации"), из-за чего одна горутина читала переменную
			// в момент, когда другая писала её под mu.Lock() ниже — гонка чтение/запись,
			// подтверждённая детектором (-race, admission_proxy_test.go:68 vs :71).
			// Здесь не нужна производительность мьютекса на "быстром пути": горутин
			// всего attempts=20, поэтому сравнение и обновление делаем одним махом под
			// одним и тем же mu — семантика (зафиксировать максимум увиденного Count()
			// среди всех горутин) сохраняется в точности, просто без гонки.
			c := proxy.Count()
			mu.Lock()
			if int64(c) > maxObservedCount {
				maxObservedCount = int64(c)
			}
			mu.Unlock()

			payload := []byte("x")
			conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
			if _, err := conn.Write(payload); err != nil {
				mu.Lock()
				rejected++
				mu.Unlock()
				return
			}
			buf := make([]byte, 1)
			if _, err := io.ReadFull(conn, buf); err != nil {
				mu.Lock()
				rejected++
				mu.Unlock()
				return
			}
			mu.Lock()
			passed++
			mu.Unlock()
			time.Sleep(50 * time.Millisecond) // держим соединение открытым, чтобы создать реальную конкуренцию за слоты
		}()
	}
	wg.Wait()

	if maxObservedCount > limit {
		t.Errorf("наблюдался счётчик подключений %d > лимита %d — лимит был пробит", maxObservedCount, limit)
	}
	if passed+rejected != attempts {
		t.Errorf("passed(%d)+rejected(%d) != attempts(%d)", passed, rejected, attempts)
	}
	t.Logf("passed=%d rejected=%d maxObserved=%d limit=%d", passed, rejected, maxObservedCount, limit)
}

func TestAdmissionProxy_CounterDecrementsAfterClose(t *testing.T) {
	internalAddr := echoListenerForAdmissionTest(t)
	publicLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	proxy := NewAdmissionProxy(publicLn, internalAddr, 5, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go proxy.Serve(ctx)

	conn, err := net.DialTimeout("tcp", publicLn.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if proxy.Count() != 1 {
		t.Fatalf("Count() = %d, ожидался 1 после одного подключения", proxy.Count())
	}
	conn.Close()
	time.Sleep(100 * time.Millisecond)
	if proxy.Count() != 0 {
		t.Errorf("Count() = %d, ожидался 0 после закрытия соединения", proxy.Count())
	}
}

// maxClients <= 0 — лимит выключен (fail-open), все соединения проходят.
func TestAdmissionProxy_ZeroLimit_AllowsAll(t *testing.T) {
	internalAddr := echoListenerForAdmissionTest(t)
	publicLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	proxy := NewAdmissionProxy(publicLn, internalAddr, 0, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go proxy.Serve(ctx)

	for i := 0; i < 10; i++ {
		conn, err := net.DialTimeout("tcp", publicLn.Addr().String(), time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conn.Close()
	}
}
