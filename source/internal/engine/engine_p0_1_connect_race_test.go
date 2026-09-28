package engine

// P0-1 (ТЗ v1.6) — connect port-10808 EADDRINUSE / гонка подключения.
//
// Тесты воспроизводят ДВА корня живого бага (телефон <test-phone>, 2026-09-14) через инъекции,
// БЕЗ запуска sing-box/сети (барьер hostguard остаётся включён; мы проверяем оркестрацию, а
// не реальный туннель):
//
//   RC-A: две ScanAndConnect-цепочки идут внахлёст, потому что connMu сериализует только
//         applySingBoxConfig, а не весь цикл скан→выбор→connect. Фикс — single-flight цикла
//         (connCycleActive). См. TestConnectCycleGuard_* / TestScanAndConnect_*.
//   RC-B: на холодном реконнекте порт входа ещё держит НАШ ЖЕ прежний инстанс (Stop/Close не
//         синхронны), а probeListenPort трактует это как «второй экземпляр APF» и заклинивает
//         подключение навсегда. Фикс — ensureListenPortFree (вернуть порт себе + дождаться
//         реального release, и лишь потом объявлять чужой процесс). См. TestEnsureListenPortFree_*.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/singbox"
)

// ─── фейковый Runner (singbox.Runner) с управляемым жизненным циклом ────────────

type fakeProc struct {
	mu          sync.Mutex
	running     bool
	startCalls  int
	stopCalls   int
	reloadCalls int
	startErr    error
	onStop      func() // хук: смоделировать освобождение порта на Stop (напр. Windows Kill)
}

func (f *fakeProc) IsInstalled() bool                    { return true }
func (f *fakeProc) Version() (string, error)             { return "fake", nil }
func (f *fakeProc) WriteConfig(*singbox.Config) error    { return nil }
func (f *fakeProc) Start(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.startCalls++
	if f.startErr != nil {
		return f.startErr
	}
	f.running = true
	return nil
}
func (f *fakeProc) Stop() error {
	f.mu.Lock()
	f.stopCalls++
	f.running = false
	cb := f.onStop
	f.mu.Unlock()
	if cb != nil {
		cb()
	}
	return nil
}
func (f *fakeProc) Reload(context.Context, *singbox.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reloadCalls++
	return nil
}
func (f *fakeProc) IsRunning() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running
}
func (f *fakeProc) StopCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stopCalls
}

// noopListener — заглушка net.Listener для listenProbeFn: probeListenPort только берёт и сразу
// закрывает listener, реальный сокет не нужен (и не открывается — чтобы тест не трогал ОС-порты).
type noopListener struct{}

func (noopListener) Accept() (net.Conn, error) { return nil, errors.New("noop") }
func (noopListener) Close() error              { return nil }
func (noopListener) Addr() net.Addr            { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0} }

// stuckPortProbe возвращает listenProbeFn, который «занят» пока released==false, и свободен
// после. Возвращает также *atomic.Bool для управления состоянием.
func busyUntil(released *atomic.Bool) func(string) (net.Listener, error) {
	return func(addr string) (net.Listener, error) {
		if released.Load() {
			return noopListener{}, nil
		}
		return nil, fmt.Errorf("listen tcp %s: bind: address already in use", addr)
	}
}

func withShortPortRelease(t *testing.T) {
	t.Helper()
	origTimeout, origPoll := portReleaseTimeout, portReleasePoll
	portReleaseTimeout = 200 * time.Millisecond
	portReleasePoll = 2 * time.Millisecond
	t.Cleanup(func() {
		portReleaseTimeout, portReleasePoll = origTimeout, origPoll
	})
}

func withProbe(t *testing.T, fn func(string) (net.Listener, error)) {
	t.Helper()
	orig := listenProbeFn
	listenProbeFn = fn
	t.Cleanup(func() { listenProbeFn = orig })
}

// ─── RC-B: самолечение порта вместо ложного «второй экземпляр» ──────────────────

// Ядро P0-1 RC-B, с явным ДО/ПОСЛЕ в одном тесте:
//   ДО (голая probeListenPort): порт занят НАШИМ зомби → ошибка → реконнект заклинен навсегда.
//   ПОСЛЕ (ensureListenPortFree): порт возвращается себе (Stop освобождает его на реализации,
//   где Stop реально его отпускает — Windows Kill) → холодный старт продолжается.
func TestEnsureListenPortFree_ReclaimsSelfHeldPortAfterStop(t *testing.T) {
	withShortPortRelease(t)
	e := newTestEngine()
	e.cfg.ListenPort = 10808

	var released atomic.Bool // порт занят нашим зомби
	withProbe(t, busyUntil(&released))

	proc := &fakeProc{}
	// Наш прежний инстанс завис: IsRunning()==false (движок считает его остановленным), а порт
	// держится. Stop() моделирует реальное освобождение (Windows: Process.Kill освобождает порт).
	proc.onStop = func() { released.Store(true) }
	e.SetRunner(proc)

	// ДО фикса: голая проба видит «занято» — прежний холодный путь именно так и заклинивал.
	if err := e.probeListenPort(); err == nil {
		t.Fatal("подготовка теста неверна: probeListenPort должна видеть занятый порт")
	}

	// ПОСЛЕ фикса: порт возвращается себе, холодный старт продолжается.
	if err := e.ensureListenPortFree(); err != nil {
		t.Fatalf("ensureListenPortFree обязана вернуть НАШ же зависший порт себе, а не падать: %v", err)
	}
	if proc.StopCount() == 0 {
		t.Error("ensureListenPortFree должна была попытаться вернуть порт через proc.Stop()")
	}
}

// Порт освобождается асинхронно (не на Stop, а спустя пару поллингов) — поллинг обязан дождаться.
func TestEnsureListenPortFree_WaitsForAsyncRelease(t *testing.T) {
	withShortPortRelease(t)
	e := newTestEngine()
	e.cfg.ListenPort = 10808

	var released atomic.Bool
	withProbe(t, busyUntil(&released))
	e.SetRunner(&fakeProc{}) // Stop — no-op (порт держит недостижимый инстанс, освободится сам)

	// Освобождаем порт из фона через ~10мс — раньше, чем таймаут 200мс.
	go func() {
		time.Sleep(10 * time.Millisecond)
		released.Store(true)
	}()

	if err := e.ensureListenPortFree(); err != nil {
		t.Fatalf("поллинг обязан был дождаться освобождения порта, а не сдаться: %v", err)
	}
}

// Порт НЕ освобождается никогда — только тогда объявляем чужой процесс (после попытки вернуть
// себе + таймаут), а не мгновенно, как раньше.
func TestEnsureListenPortFree_ForeignProcessStillFailsAfterTimeout(t *testing.T) {
	withShortPortRelease(t)
	e := newTestEngine()
	e.cfg.ListenPort = 10808

	var neverReleased atomic.Bool // остаётся false
	withProbe(t, busyUntil(&neverReleased))
	proc := &fakeProc{}
	e.SetRunner(proc)

	start := time.Now()
	err := e.ensureListenPortFree()
	if err == nil {
		t.Fatal("порт держит ПОСТОРОННИЙ процесс — подключение обязано быть отклонено")
	}
	if !strings.Contains(err.Error(), "посторонний") {
		t.Errorf("ошибка должна указывать на посторонний процесс, получено: %v", err)
	}
	if time.Since(start) < portReleaseTimeout {
		t.Errorf("отказ раньше таймаута (%v) — значит порт не ждали", portReleaseTimeout)
	}
	if proc.StopCount() == 0 {
		t.Error("перед объявлением чужого процесса должны были попытаться вернуть порт себе")
	}
}

// Свободный порт — мгновенный успех, без Stop и без ожидания (быстрый путь не сломан).
func TestEnsureListenPortFree_FreePortIsInstant(t *testing.T) {
	withShortPortRelease(t)
	e := newTestEngine()
	e.cfg.ListenPort = 10808

	var free atomic.Bool
	free.Store(true)
	withProbe(t, busyUntil(&free))
	proc := &fakeProc{}
	e.SetRunner(proc)

	if err := e.ensureListenPortFree(); err != nil {
		t.Fatalf("свободный порт — ошибок быть не должно: %v", err)
	}
	if proc.StopCount() != 0 {
		t.Error("на свободном порту Stop дёргать незачем")
	}
}

// ─── RC-A: single-flight цикла ScanAndConnect ───────────────────────────────────

// Примитив single-flight под -race: сколько бы горутин ни ворвалось, внутри «цикла» в любой
// момент не больше одной. Именно этого не хватало: connMu держит только applySingBoxConfig.
func TestConnectCycleGuard_SingleFlightUnderRace(t *testing.T) {
	e := newTestEngine()
	var inside, maxInside atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !e.connCycleActive.CompareAndSwap(false, true) {
				return // цикл уже идёт — второй не начинаем
			}
			defer e.connCycleActive.Store(false)
			cur := inside.Add(1)
			for {
				m := maxInside.Load()
				if cur <= m || maxInside.CompareAndSwap(m, cur) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			inside.Add(-1)
		}()
	}
	wg.Wait()
	if got := maxInside.Load(); got > 1 {
		t.Fatalf("одновременно внутри цикла оказалось %d горутин — наложение не сериализовано", got)
	}
	if e.connCycleActive.Load() {
		t.Error("после всех цикл остался «занят» — защёлка не отпускается")
	}
}

// Пока цикл идёт, повторный ScanAndConnect обязан быть no-op: НЕ начинать свой скан
// (никакого "Starting scan"), вернуть nil, и НЕ трогать защёлку идущего цикла. Полностью
// офлайн: дубликат отсекается ДО скана.
func TestScanAndConnect_SkipsWhileCycleInProgress(t *testing.T) {
	e := newTestEngine()
	var scanStarts atomic.Int32
	e.OnLog = func(msg string) {
		if strings.Contains(msg, "Starting scan") {
			scanStarts.Add(1)
		}
	}

	// Симулируем идущий цикл (то, что делает первая ScanAndConnect).
	if !e.connCycleActive.CompareAndSwap(false, true) {
		t.Fatal("защёлка обязана быть свободна в начале")
	}

	err := e.ScanAndConnect()
	if err != nil {
		t.Fatalf("дубликат ScanAndConnect — доброкачественный no-op, ожидался nil, получено: %v", err)
	}
	if got := scanStarts.Load(); got != 0 {
		t.Fatalf("дубликат ScanAndConnect НЕ должен запускать скан (сеть), но 'Starting scan' логов=%d", got)
	}
	if !e.connCycleActive.Load() {
		t.Fatal("дубликат не должен был снимать защёлку идущего цикла")
	}

	// Цикл завершился — защёлка свободна, следующий вызов вправе начаться.
	e.connCycleActive.Store(false)
	if !e.connCycleActive.CompareAndSwap(false, true) {
		t.Fatal("после завершения цикла защёлка должна освобождаться")
	}
	e.connCycleActive.Store(false)
}

// Живая гонка целиком: ПОКА один ScanAndConnect реально идёт (запаркован в проверке узла,
// удерживая nodeCheckMu, взятый тестом), второй, наложившийся, обязан быть отсечён — ровно тот
// сценарий из лога 19:08:48/19:08:50. Проверяем по числу «Starting scan»: с фиксом ровно 1.
// Без фикса второй тоже логировал бы «Starting scan» (=2) и делал бы редундантный реконнект.
// Полностью офлайн: контекст движка отменён, emergencyFallback выключен, узел задан IP-литералом.
func TestScanAndConnect_OverlappingCycleIsRejected(t *testing.T) {
	e := newTestEngine()
	e.cfg.ListenPort = 10808
	e.emergencyFallback = nil // L3-фаза tryFallback (сеть) выключена — тест офлайн

	node := &models.Node{
		ID: "fav-1", Name: "fav", Protocol: models.ProtoShadowsocks,
		Address: "127.0.0.1", Port: 8388, Method: "aes-256-gcm", Password: "p",
		Score: 1.0, Status: models.StatusOK, Latency: 10, LastChecked: time.Now(),
	}
	e.mu.Lock()
	e.nodes = []*models.Node{node}
	e.mu.Unlock()
	e.PinNode(node.ID) // делает узел предпочтительным (preferredCandidates → tryPreferredNodesFirst)

	var scanStarts atomic.Int32
	e.OnLog = func(msg string) {
		if strings.Contains(msg, "Starting scan") {
			scanStarts.Add(1)
		}
	}

	// Держим nodeCheckMu — первый цикл запаркуется в checkNodeSerialized, удерживая защёлку цикла.
	e.nodeCheckMu.Lock()

	done := make(chan struct{})
	go func() {
		_ = e.ScanAndConnect() // цикл A: пройдёт защёлку, залогирует "Starting scan", запаркуется
		close(done)
	}()

	// Ждём, пока A точно захватил защёлку цикла (залогировал "Starting scan").
	deadline := time.Now().Add(2 * time.Second)
	for scanStarts.Load() < 1 {
		if time.Now().After(deadline) {
			e.nodeCheckMu.Unlock()
			t.Fatal("первый ScanAndConnect не стартовал за 2с")
		}
		time.Sleep(time.Millisecond)
	}

	// Цикл B — наложение. С фиксом обязан быть отсечён.
	if err := e.ScanAndConnect(); err != nil {
		e.nodeCheckMu.Unlock()
		t.Fatalf("наложенный ScanAndConnect — доброкачественный no-op, получено: %v", err)
	}
	if got := scanStarts.Load(); got != 1 {
		e.nodeCheckMu.Unlock()
		t.Fatalf("наложение НЕ предотвращено: 'Starting scan' логов=%d (ожидалось 1 — второй должен быть отсечён)", got)
	}

	// Отпускаем узел-проверку и отменяем контекст — цикл A сматывается офлайн (checker/детектор
	// на отменённом ctx мгновенно возвращают «не проверено», applyTorFallback выключен).
	e.cancelCurrentCtx()
	e.nodeCheckMu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("первый ScanAndConnect не завершился после снятия блокировки")
	}
	if e.connCycleActive.Load() {
		t.Error("после завершения цикла защёлка осталась занятой")
	}
}
