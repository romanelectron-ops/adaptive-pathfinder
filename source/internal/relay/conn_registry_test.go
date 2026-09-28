package relay

import (
	"net"
	"sync"
	"testing"
	"time"
)

// Ничего не зарегистрировано — shutdown() возвращается немедленно, не ждёт grace впустую.
func TestConnRegistry_Shutdown_Empty_ReturnsImmediately(t *testing.T) {
	r := newConnRegistry()
	start := time.Now()
	r.shutdown(5 * time.Second)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("shutdown() без зарегистрированных соединений занял %v, ожидалось почти мгновенно", elapsed)
	}
}

// done() уже был вызван до shutdown() — естественное завершение, shutdown() не должен ждать
// grace целиком (иначе весь смысл "ждать естественное завершение первым делом" теряется).
func TestConnRegistry_Shutdown_AlreadyDone_ReturnsQuickly(t *testing.T) {
	r := newConnRegistry()
	a, b := net.Pipe()
	done := r.add(a, b)
	done()
	a.Close()
	b.Close()

	start := time.Now()
	r.shutdown(5 * time.Second)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("shutdown() после уже вызванного done() занял %v, ожидалось почти мгновенно", elapsed)
	}
}

// [консилиум, HIGH, находка №6, TZ_RELAY_HARDENING_2026-08-29.md кластер G] Сердце фикса:
// «зависшее» соединение (симулирует удалённую сторону, не закрывающую канал — обрыв мобильной
// сети без FIN/RST) не должно заставлять shutdown() ждать бесконечно — принудительное закрытие
// после grace обязано разблокировать горутину, которая держит соединение.
func TestConnRegistry_Shutdown_HungConnection_ForceClosedAfterGrace(t *testing.T) {
	r := newConnRegistry()
	a, b := net.Pipe()

	doneCalled := make(chan struct{})
	go func() {
		done := r.add(a, b)
		defer func() {
			done()
			close(doneCalled)
		}()
		buf := make([]byte, 1)
		a.Read(buf) // блокируется, пока кто-то не закроет a — тот же приём, что и в splice()
	}()

	// Дать горутине время реально дойти до блокирующего Read(), не полагаясь на порядок
	// планировщика.
	deadline := time.Now().Add(2 * time.Second)
	for {
		select {
		case <-doneCalled:
			t.Fatal("горутина завершилась ДО shutdown() — тест не проверяет то, что должен")
		default:
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	start := time.Now()
	r.shutdown(200 * time.Millisecond)
	elapsed := time.Since(start)
	if elapsed > 3*time.Second {
		t.Fatalf("shutdown() занял %v — обязан вернуться вскоре после grace (200мс), не виснуть", elapsed)
	}

	select {
	case <-doneCalled:
	case <-time.After(time.Second):
		t.Fatal("done() так и не был вызван после принудительного закрытия — горутина осталась висеть")
	}
}

// [найдено go test -race при написании regression-тестов кластера C, 2026-08-30, НЕ в исходном
// отчёте консилиума] Регрессия конкретно на находку: add() и shutdown() вызванные ПОЧТИ
// ОДНОВРЕМЕННО из разных горутин (реальный сценарий — новое подключение приходит ровно в
// момент, когда пользователь нажал «Остановить») раньше гонялись за sync.WaitGroup —
// wg.Add(1) внутри add() мог исполниться конкурентно с уже идущим wg.Wait() внутри
// shutdown() без единой синхронизации между ними, что sync.WaitGroup прямо не гарантирует
// (см. комментарий у поля shuttingDown в conn_registry.go). Гоняется много раз с -race, чтобы
// поймать именно гонку, не только логический результат.
func TestConnRegistry_Add_ConcurrentWithShutdown_NoRace(t *testing.T) {
	for i := 0; i < 200; i++ {
		r := newConnRegistry()
		a, b := net.Pipe()

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			done := r.add(a, b)
			done()
		}()
		go func() {
			defer wg.Done()
			r.shutdown(10 * time.Millisecond)
		}()
		wg.Wait()

		a.Close()
		b.Close()
	}
}

// Несколько сессий разом: часть завершается сама раньше grace, часть виснет — shutdown()
// обязан дождаться первых и принудительно закрыть вторые, вернувшись за ограниченное время.
func TestConnRegistry_Shutdown_MixedNaturalAndHung(t *testing.T) {
	r := newConnRegistry()

	// Сессия 1 — завершается сама почти сразу.
	a1, b1 := net.Pipe()
	go func() {
		done := r.add(a1, b1)
		defer done()
		buf := make([]byte, 1)
		a1.Read(buf)
	}()
	go func() { time.Sleep(20 * time.Millisecond); b1.Close() }()

	// Сессия 2 — виснет, дожидается принудительного закрытия.
	a2, b2 := net.Pipe()
	hungDone := make(chan struct{})
	go func() {
		done := r.add(a2, b2)
		defer func() {
			done()
			close(hungDone)
		}()
		buf := make([]byte, 1)
		a2.Read(buf)
	}()

	time.Sleep(100 * time.Millisecond) // обе горутины успели зарегистрироваться

	start := time.Now()
	r.shutdown(150 * time.Millisecond)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("shutdown() со смешанными сессиями занял %v — обязан вернуться за ограниченное время", elapsed)
	}
	select {
	case <-hungDone:
	default:
		t.Error("зависшая сессия не была принудительно завершена")
	}
}
