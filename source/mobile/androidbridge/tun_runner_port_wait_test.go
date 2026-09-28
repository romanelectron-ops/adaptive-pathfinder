package androidbridge

// FU-1 (ТЗ v1.6, продолжение консилиума P0-1, 2026-09-14) — тесты waitForListenPortRelease
// (+ socksListenPort) В ИЗОЛЯЦИИ, через шов listenProbeFn и укороченные
// portReleaseTimeout/portReleasePoll. Тот же принцип, что и у остального пакета (см.
// tun_runner_test.go, tun_test.go): ни один тест здесь не создаёт InProcessRunner/tunRunner,
// не трогает t.inner и не запускает ReloadWithFreshTun целиком — engine.applySingBoxConfig
// (единственная точка, реально прикрытая барьером hostguard) сюда не вызывается вовсе, поэтому
// тестировать полный ReloadWithFreshTun значило бы держаться на честном слове, а не на барьере.
// Проверяется только сам helper. Реальные ОС-порты НЕ открываются: listenProbeFn — чистая
// функция-шов, подменяемая на время теста; net.Listen никогда не вызывается напрямую.
//
// Имена тестов намеренно начинаются с TestPortWait_ — под `-run "PortWait|..."` (см. лот).

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/singbox"
)

// noopPortListener — заглушка net.Listener: waitForListenPortRelease только берёт и сразу же
// закрывает listener; реальный сокет не нужен и не открывается.
type noopPortListener struct{}

func (noopPortListener) Accept() (net.Conn, error) { return nil, errors.New("noop") }
func (noopPortListener) Close() error              { return nil }
func (noopPortListener) Addr() net.Addr            { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0} }

// busyUntilPortReleased возвращает listenProbeFn-совместимую функцию: "занято" (ошибка bind),
// пока released.Load()==false, "свободно" после. calls считает КАЖДОЕ обращение — нужен тестам
// fail-safe пути (port<=0 обязан НЕ обращаться к функции ни разу).
func busyUntilPortReleased(released *atomic.Bool, calls *atomic.Int32) func(string) (net.Listener, error) {
	return func(addr string) (net.Listener, error) {
		calls.Add(1)
		if released.Load() {
			return noopPortListener{}, nil
		}
		return nil, fmt.Errorf("listen tcp %s: bind: address already in use", addr)
	}
}

// withShortPortWait укорачивает portReleaseTimeout/portReleasePoll на время теста — тот же
// приём, что withShortPortRelease в internal/engine/engine_p0_1_connect_race_test.go (P0-1).
func withShortPortWait(t *testing.T) {
	t.Helper()
	origTimeout, origPoll := portReleaseTimeout, portReleasePoll
	portReleaseTimeout = 150 * time.Millisecond
	portReleasePoll = 5 * time.Millisecond
	t.Cleanup(func() {
		portReleaseTimeout, portReleasePoll = origTimeout, origPoll
	})
}

func withPortProbe(t *testing.T, fn func(string) (net.Listener, error)) {
	t.Helper()
	orig := listenProbeFn
	listenProbeFn = fn
	t.Cleanup(func() { listenProbeFn = orig })
}

// ─── waitForListenPortRelease ────────────────────────────────────────────────────

// Порт свободен сразу — быстрый путь: без ожидания, без ошибки, ровно одна проверка обеих
// точек входа (port, port+1).
func TestPortWait_FreePortIsInstant(t *testing.T) {
	withShortPortWait(t)
	var calls atomic.Int32
	var free atomic.Bool
	free.Store(true)
	withPortProbe(t, busyUntilPortReleased(&free, &calls))

	start := time.Now()
	err := waitForListenPortRelease(context.Background(), 19999)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("свободный порт — ошибок быть не должно: %v", err)
	}
	if elapsed >= portReleasePoll {
		t.Errorf("свободный порт обязан вернуться БЕЗ ожидания: elapsed=%v >= portReleasePoll=%v",
			elapsed, portReleasePoll)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("ожидалось ровно 2 обращения к listenProbeFn (port и port+1), получено %d", got)
	}
}

// Порт занят, но освобождается асинхронно через пару поллингов (не на самом Stop, а спустя
// время) — ожидание обязано дождаться, а не сдаться раньше срока.
func TestPortWait_WaitsForAsyncRelease(t *testing.T) {
	withShortPortWait(t)
	var calls atomic.Int32
	var released atomic.Bool
	withPortProbe(t, busyUntilPortReleased(&released, &calls))

	// Освобождаем порт из фона через ~20мс — заметно больше portReleasePoll(5мс, несколько
	// поллингов пройдёт впустую), заметно меньше portReleaseTimeout(150мс).
	go func() {
		time.Sleep(20 * time.Millisecond)
		released.Store(true)
	}()

	start := time.Now()
	err := waitForListenPortRelease(context.Background(), 19999)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("поллинг обязан дождаться освобождения порта, а не сдаться: %v", err)
	}
	if elapsed < 20*time.Millisecond {
		t.Errorf("вернулось раньше фактического освобождения порта: elapsed=%v", elapsed)
	}
	if elapsed >= portReleaseTimeout {
		t.Errorf("должно было дождаться ДО таймаута: elapsed=%v >= portReleaseTimeout=%v",
			elapsed, portReleaseTimeout)
	}
	if got := calls.Load(); got < 4 { // минимум 2 неудачных раунда (port+port+1) + успешный
		t.Errorf("ожидался хотя бы один повторный раунд поллинга, обращений к listenProbeFn=%d", got)
	}
}

// Порт НИКОГДА не освобождается — ожидание обязано вернуться ОГРАНИЧЕННО, после таймаута, а не
// зависнуть навсегда (само по себе прохождение теста в разумное время это и доказывает).
func TestPortWait_NeverReleasedBoundedTimeout(t *testing.T) {
	withShortPortWait(t)
	var calls atomic.Int32
	var neverReleased atomic.Bool // остаётся false до конца теста
	withPortProbe(t, busyUntilPortReleased(&neverReleased, &calls))

	start := time.Now()
	err := waitForListenPortRelease(context.Background(), 19999)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("порт никогда не освобождается — ожидалась ошибка таймаута, получен nil")
	}
	if elapsed < portReleaseTimeout {
		t.Errorf("вернулось РАНЬШЕ таймаута (%v): elapsed=%v — значит порт не ждали как следует",
			portReleaseTimeout, elapsed)
	}
	// Ограниченность: не должно уйти намного дальше тайм-аута плюс один интервал поллинга —
	// граница с запасом (10×poll), чтобы не сделать тест хрупким на медленном CI, но всё ещё
	// на порядки меньше, чем "зависло навсегда".
	if slack := elapsed - portReleaseTimeout; slack > 10*portReleasePoll {
		t.Errorf("таймаут не ограничен: превышение над portReleaseTimeout=%v составило %v",
			portReleaseTimeout, slack)
	}
	if calls.Load() == 0 {
		t.Error("ожидание обязано было сделать хотя бы одну пробу")
	}
}

// Отмена контекста ПОСРЕДИ ожидания обязана прервать его немедленно — Stop/Disconnect (то, что
// в реальном коде отменяет ctx у ReloadWithFreshTun) не должны зависать на этом ожидании, даже
// если portReleaseTimeout выставлен большим.
func TestPortWait_ContextCancelAbortsPromptly(t *testing.T) {
	withShortPortWait(t)
	portReleaseTimeout = 2 * time.Second // заведомо больше отмены ниже — если бы ctx не уважался,
	// тест провисел бы все 2с
	var calls atomic.Int32
	var neverReleased atomic.Bool
	withPortProbe(t, busyUntilPortReleased(&neverReleased, &calls))

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := waitForListenPortRelease(ctx, 19999)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("отменённый контекст обязан прервать ожидание с ошибкой, получен nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("ошибка обязана оборачивать context.Canceled, получено: %v", err)
	}
	if elapsed >= 300*time.Millisecond {
		t.Errorf("отмена контекста обязана прерывать ожидание НЕМЕДЛЕННО: elapsed=%v "+
			"(portReleaseTimeout=%v, т.е. без уважения ctx тест провисел бы куда дольше)",
			elapsed, portReleaseTimeout)
	}
}

// ListenPort<=0 (Android-конфигурация без локального SOCKS/HTTP-входа, либо гипотетический
// нулевой/отрицательный порт) — проверка пропускается ЦЕЛИКОМ, ни разу не обращаясь к
// listenProbeFn. Тот же fail-safe контракт, что у engine.probeListenPort.
func TestPortWait_NonPositivePortSkipsProbe(t *testing.T) {
	withShortPortWait(t)
	for _, port := range []int{0, -1, -10808} {
		var calls atomic.Int32
		withPortProbe(t, func(string) (net.Listener, error) {
			calls.Add(1)
			return nil, errors.New("listenProbeFn НЕ должен вызываться при port<=0")
		})

		err := waitForListenPortRelease(context.Background(), port)
		if err != nil {
			t.Errorf("port=%d: ожидался nil (пропуск ожидания), получено %v", port, err)
		}
		if got := calls.Load(); got != 0 {
			t.Errorf("port=%d: listenProbeFn вызван %d раз(а), ожидалось 0 (fail-safe пропуск)",
				port, got)
		}
	}
}

// ─── socksListenPort (извлечение порта для waitForListenPortRelease) ───────────────

// Обычная клиентская конфигурация (см. config_builder.go: socks на base, http на base+1,
// опционально tun третьим inbound'ом) — обязана вернуть SOCKS-порт, а не первый попавшийся.
func TestPortWait_SocksListenPortPicksSocksInboundOverOthers(t *testing.T) {
	cfg := &singbox.Config{
		Inbounds: []singbox.Inbound{
			{Type: "tun", Tag: "tun-in"}, // ListenPort=0 (не публикуется у tun) — не должен выбраться
			{Type: "http", Tag: "http-in", ListenPort: 10809},
			{Type: "socks", Tag: "socks-in", ListenPort: 10808},
		},
	}
	if got := socksListenPort(cfg); got != 10808 {
		t.Errorf("socksListenPort() = %d, ожидался SOCKS-порт 10808", got)
	}
}

// Нет socks-inbound'а вовсе (гипотетическая TUN-only конфигурация) — fail-safe 0, не паника и
// не первый попавшийся другой порт.
func TestPortWait_SocksListenPortNoSocksInboundReturnsZero(t *testing.T) {
	cfg := &singbox.Config{
		Inbounds: []singbox.Inbound{
			{Type: "tun", Tag: "tun-in"},
			{Type: "http", Tag: "http-in", ListenPort: 10809},
		},
	}
	if got := socksListenPort(cfg); got != 0 {
		t.Errorf("socksListenPort() без socks-inbound = %d, ожидался 0 (fail-safe)", got)
	}
}

// cfg==nil и пустой Inbounds — те же fail-safe 0, без паники.
func TestPortWait_SocksListenPortNilAndEmptyAreFailSafe(t *testing.T) {
	if got := socksListenPort(nil); got != 0 {
		t.Errorf("socksListenPort(nil) = %d, ожидался 0", got)
	}
	if got := socksListenPort(&singbox.Config{}); got != 0 {
		t.Errorf("socksListenPort(&Config{}) = %d, ожидался 0", got)
	}
}
