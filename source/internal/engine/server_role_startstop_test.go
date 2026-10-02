package engine

// server_role_startstop_test.go — ревью 1.1.10 (compat F5): одиночный запуск роли «Выход»
// (single-flight) и отмена запуска остановкой. Запуск теперь ждёт порт sing-box до двух минут,
// а runner виден остальному коду только после возврата Start: за это окно «Остановить» было
// тихим no-op, а второй «Запустить» создавал второй runner.
//
// Настоящий sing-box и настоящий netsh здесь недопустимы (hostguard блокирует запуск sing-box
// под go test, а netsh снимает firewall-правило по имени — им же пользуется работающая на
// машине роль «Выход»): runner подменяется фейком через newServerRunnerFn, firewall — через
// ensureInboundFirewallRuleFn/removeInboundFirewallRuleFn. Публичный listener (шов listenPublicFn)
// в тестах успешного запуска — 127.0.0.1:0, а не «все интерфейсы»: иначе Windows показывал бы
// владельцу запрос брандмауэра для каждого нового тестового exe.

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/singbox"
)

// fakeServerRunner — singbox.ServerRunner без процесса. Start вызывает startFn (номер вызова с 1),
// так что тест сам решает, блокируется ли запуск, слушает ли он контекст и чем кончается.
type fakeServerRunner struct {
	mu         sync.Mutex
	startCalls int
	stopCalls  int
	running    bool
	// startCtxErr — ctx.Err() на момент возврата из последнего Start: видно, дошла ли отмена.
	startCtxErr error

	startFn func(ctx context.Context, call int) error
	entered chan int // получает номер вызова при КАЖДОМ входе в Start
	release chan error

	// writeConfigHook — вызывается из WriteConfig (до Start): позволяет остановить запуск в точке
	// «конфиг пишется, sing-box ещё не стартовал».
	writeConfigHook func()

	// isRunningEntered/isRunningGate — IsRunning блокируется, пока не закрыт gate (как
	// Process.IsRunning на мьютексе процесса, который держит Start).
	isRunningEntered chan struct{}
	isRunningGate    chan struct{}
}

func newFakeServerRunner() *fakeServerRunner {
	f := &fakeServerRunner{
		entered: make(chan int, 16),
		release: make(chan error, 4),
	}
	// По умолчанию — как настоящий awaitReady: ждёт порт, слушает контекст, иначе ждёт решения теста.
	f.startFn = func(ctx context.Context, call int) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-f.release:
			return err
		}
	}
	return f
}

func (f *fakeServerRunner) IsInstalled() bool        { return true }
func (f *fakeServerRunner) Version() (string, error) { return "test", nil }
func (f *fakeServerRunner) GenerateIdentity() (singbox.ServerIdentity, error) {
	return singbox.ServerIdentity{}, nil
}
func (f *fakeServerRunner) WriteConfig(*singbox.ServerDoc) error {
	if f.writeConfigHook != nil {
		f.writeConfigHook()
	}
	return nil
}

func (f *fakeServerRunner) Start(ctx context.Context) error {
	f.mu.Lock()
	f.startCalls++
	call := f.startCalls
	f.mu.Unlock()
	f.entered <- call

	err := f.startFn(ctx, call)

	f.mu.Lock()
	f.startCtxErr = ctx.Err()
	if err == nil {
		f.running = true
	}
	f.mu.Unlock()
	return err
}

func (f *fakeServerRunner) Stop() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopCalls++
	f.running = false
	return nil
}

func (f *fakeServerRunner) IsRunning() bool {
	if f.isRunningGate != nil {
		f.isRunningEntered <- struct{}{}
		<-f.isRunningGate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running
}

func (f *fakeServerRunner) counters() (start, stop int, ctxErr error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.startCalls, f.stopCalls, f.startCtxErr
}

// serverRoleStubs — счётчики подменённых швов.
type serverRoleStubs struct {
	runnersCreated atomic.Int32
	rulesRemoved   atomic.Int32
}

// withServerRoleStubs подменяет швы роли «Выход» на время теста: runner — фейк, firewall — no-op
// со счётчиком, ожидание отмены — короткое (тест не ждёт секунды).
func withServerRoleStubs(t *testing.T, r *fakeServerRunner) *serverRoleStubs {
	t.Helper()
	st := &serverRoleStubs{}
	origNew, origEnsure, origRemove, origWait := newServerRunnerFn, ensureInboundFirewallRuleFn, removeInboundFirewallRuleFn, serverRoleStartCancelWait
	newServerRunnerFn = func() singbox.ServerRunner {
		st.runnersCreated.Add(1)
		return r
	}
	ensureInboundFirewallRuleFn = func(string, string, int) error { return nil }
	removeInboundFirewallRuleFn = func(string) { st.rulesRemoved.Add(1) }
	serverRoleStartCancelWait = 5 * time.Second
	t.Cleanup(func() {
		newServerRunnerFn, ensureInboundFirewallRuleFn, removeInboundFirewallRuleFn, serverRoleStartCancelWait =
			origNew, origEnsure, origRemove, origWait
	})
	return st
}

// newServerRoleTestEngine — движок с журналом в срез (потокобезопасно).
func newServerRoleTestEngine(t *testing.T) (*Engine, func() string) {
	t.Helper()
	e := newTestEngine()
	var mu sync.Mutex
	var lines []string
	e.OnLog = func(msg string) {
		mu.Lock()
		lines = append(lines, msg)
		mu.Unlock()
	}
	return e, func() string {
		mu.Lock()
		defer mu.Unlock()
		return strings.Join(lines, "\n")
	}
}

func startServerRoleAsync(e *Engine) <-chan error {
	ch := make(chan error, 1)
	go func() { ch <- e.StartServerRole(18443, "", singbox.ServerIdentity{}) }()
	return ch
}

func waitStartEntered(t *testing.T, r *fakeServerRunner) int {
	t.Helper()
	select {
	case call := <-r.entered:
		return call
	case <-time.After(10 * time.Second):
		t.Fatal("runner.Start не был вызван за 10 с")
		return 0
	}
}

func waitStartResult(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("StartServerRole не вернулся за 10 с")
		return nil
	}
}

// Пока первый запуск ждёт порт, второй обязан отвергаться сразу и не создавать второй runner.
// На старом коде второй вызов проходил внутрь: runner==nil (публикуется после Start), создавался
// второй runner и второй Start поверх того же порта/конфига.
func TestStartServerRole_SecondStartRejectedWhileFirstStarting(t *testing.T) {
	r := newFakeServerRunner()
	stubs := withServerRoleStubs(t, r)
	e, logs := newServerRoleTestEngine(t)

	first := startServerRoleAsync(e)
	waitStartEntered(t, r)

	// Через горутину с таймаутом: без single-flight второй вызов ушёл бы в runner.Start и завис
	// бы там — тест должен УПАСТЬ с понятным сообщением, а не повиснуть до общего таймаута.
	err := waitStartResult(t, startServerRoleAsync(e))
	if !errors.Is(err, ErrServerRoleStarting) {
		t.Fatalf("второй StartServerRole во время запуска: ожидался ErrServerRoleStarting, получено %v", err)
	}
	if !strings.Contains(err.Error(), "запуск роли «Выход» уже выполняется") {
		t.Errorf("текст отказа должен быть понятным пользователю: %q", err.Error())
	}
	if n := stubs.runnersCreated.Load(); n != 1 {
		t.Errorf("создано runner-ов: %d, ожидался один (второй запуск не должен создавать свой)", n)
	}
	if start, _, _ := r.counters(); start != 1 {
		t.Errorf("runner.Start вызван %d раз, ожидался один — отвергнутый запуск до runner не дошёл", start)
	}
	if !strings.Contains(logs(), "повторный запуск отвергнут") {
		t.Errorf("отказ должен быть виден в журнале: %q", logs())
	}

	// Первый запуск заканчивается обычным отказом sing-box — слот обязан освободиться и после него.
	r.release <- errors.New("stub: sing-box не открыл порт")
	firstErr := waitStartResult(t, first)
	if firstErr == nil || errors.Is(firstErr, ErrServerRoleStarting) || errors.Is(firstErr, context.Canceled) {
		t.Fatalf("первый запуск: ожидался обычный отказ sing-box, получено %v", firstErr)
	}
	r.startFn = func(context.Context, int) error { return errors.New("stub: отказ") }
	if err := e.StartServerRole(18443, "", singbox.ServerIdentity{}); err == nil || errors.Is(err, ErrServerRoleStarting) {
		t.Fatalf("после окончания первого запуска слот должен быть свободен, получено %v", err)
	}
}

// StopServerRole во время запуска отменяет контекст запуска: runner.Start получает отмену,
// запуск возвращает «отменён», runner не публикуется. На старом коде Stop видел
// serverRoleRunner==nil, тихо возвращал nil, а Start продолжал ждать порт до конца.
func TestStopServerRole_CancelsPendingStart(t *testing.T) {
	r := newFakeServerRunner()
	stubs := withServerRoleStubs(t, r)
	e, logs := newServerRoleTestEngine(t)

	first := startServerRoleAsync(e)
	waitStartEntered(t, r)

	if err := e.StopServerRole(); err != nil {
		t.Fatalf("StopServerRole во время запуска: %v", err)
	}
	startErr := waitStartResult(t, first)
	if !errors.Is(startErr, context.Canceled) {
		t.Fatalf("запуск, прерванный остановкой, должен вернуть ошибку с context.Canceled, получено %v", startErr)
	}
	if !strings.Contains(startErr.Error(), "запуск отменён") {
		t.Errorf("текст отмены должен отличаться от отказа запуска: %q", startErr.Error())
	}
	if _, _, ctxErr := r.counters(); ctxErr == nil {
		t.Error("runner.Start вернулся, но его контекст не был отменён — Stop не прервал ожидание порта")
	}

	e.serverRoleMu.Lock()
	published := e.serverRoleRunner
	e.serverRoleMu.Unlock()
	if published != nil {
		t.Error("отменённый запуск не должен публиковать runner")
	}
	if e.IsServerRoleRunning() {
		t.Error("после отменённого запуска роль не должна считаться запущенной")
	}
	if stubs.rulesRemoved.Load() < 1 {
		t.Error("StopServerRole обязан снять firewall-правило процесса APF (teardown не вызван)")
	}
	if !strings.Contains(logs(), "запуск прерван остановкой роли") {
		t.Errorf("в журнале нет записи об отмене запуска: %q", logs())
	}
}

// После отмены роль запускается снова, и так несколько раз подряд: слот освобождается ДО того,
// как StopServerRole вернулся (Stop дожидается конца запуска), поэтому «Остановить» и сразу
// «Запустить» никогда не упирается в «уже выполняется».
func TestStartServerRole_CanStartAgainAfterCancelledStart(t *testing.T) {
	r := newFakeServerRunner()
	withServerRoleStubs(t, r)
	e, _ := newServerRoleTestEngine(t)

	for i := 1; i <= 3; i++ {
		first := startServerRoleAsync(e)
		if call := waitStartEntered(t, r); call != i {
			t.Fatalf("попытка %d: runner.Start вызван под номером %d", i, call)
		}
		if err := e.StopServerRole(); err != nil {
			t.Fatalf("попытка %d: StopServerRole: %v", i, err)
		}
		// Слот свободен сразу после возврата Stop — без ожидания результата первого вызова.
		serverRoleStartMu.Lock()
		_, busy := serverRoleStarts[e]
		serverRoleStartMu.Unlock()
		if busy {
			t.Fatalf("попытка %d: StopServerRole вернулся, а слот запуска всё ещё занят", i)
		}
		if err := waitStartResult(t, first); !errors.Is(err, context.Canceled) {
			t.Fatalf("попытка %d: ожидалась отмена, получено %v", i, err)
		}
	}
}

// Остановка ДО старта sing-box (запуск ещё пишет конфиг): runner.Start вообще не вызывается,
// работающий старый процесс не трогается — Stop сам остановит всё, что есть.
func TestStopServerRole_CancelBeforeRunnerStartSkipsStart(t *testing.T) {
	r := newFakeServerRunner()
	withServerRoleStubs(t, r)
	e, logs := newServerRoleTestEngine(t)

	wcEntered := make(chan struct{})
	wcRelease := make(chan struct{})
	r.writeConfigHook = func() {
		close(wcEntered)
		<-wcRelease
	}

	first := startServerRoleAsync(e)
	select {
	case <-wcEntered:
	case <-time.After(10 * time.Second):
		t.Fatal("WriteConfig не был вызван за 10 с")
	}

	stopDone := make(chan error, 1)
	go func() { stopDone <- e.StopServerRole() }()
	// Запись в журнал «запуск прерван» идёт ПОСЛЕ st.cancel(): дождавшись её, отмена гарантированно
	// уже выставлена, и WriteConfig можно отпускать.
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(logs(), "остановка во время запуска") {
		if time.Now().After(deadline) {
			t.Fatal("StopServerRole не начал прерывание запуска за 10 с")
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(wcRelease)

	if err := waitStartResult(t, first); !errors.Is(err, context.Canceled) {
		t.Fatalf("ожидалась отмена запуска, получено %v", err)
	}
	if err := <-stopDone; err != nil {
		t.Fatalf("StopServerRole: %v", err)
	}
	if start, _, _ := r.counters(); start != 0 {
		t.Errorf("runner.Start вызван %d раз, хотя остановка пришла до старта sing-box", start)
	}
}

// Запуск, который не слушает отмену (создание процесса ОС не прерывается), не должен вешать
// StopServerRole навсегда: Stop возвращается по истечении serverRoleStartCancelWait, слот при
// этом остаётся занятым (запуск ещё идёт), а когда запуск вернётся — он честно сообщает «отменён».
func TestStopServerRole_DoesNotHangOnStartIgnoringCancel(t *testing.T) {
	r := newFakeServerRunner()
	withServerRoleStubs(t, r)
	serverRoleStartCancelWait = 50 * time.Millisecond
	e, logs := newServerRoleTestEngine(t)

	r.startFn = func(_ context.Context, _ int) error { return <-r.release } // контекст игнорируется

	first := startServerRoleAsync(e)
	waitStartEntered(t, r)

	began := time.Now()
	if err := e.StopServerRole(); err != nil {
		t.Fatalf("StopServerRole: %v", err)
	}
	if took := time.Since(began); took > 5*time.Second {
		t.Fatalf("StopServerRole завис на запуске, не слушающем отмену: %v", took)
	}
	if !strings.Contains(logs(), "не вернулся за") {
		t.Errorf("в журнале нет записи о том, что запуск не вернулся после отмены: %q", logs())
	}
	if err := waitStartResult(t, startServerRoleAsync(e)); !errors.Is(err, ErrServerRoleStarting) {
		t.Errorf("запуск ещё идёт — новый запуск обязан отвергаться, получено %v", err)
	}

	r.release <- errors.New("stub: sing-box не открыл порт")
	if err := waitStartResult(t, first); err == nil || !strings.Contains(err.Error(), "запуск отменён") {
		t.Errorf("запуск, вернувшийся после отмены, обязан сообщить «отменён», получено %v", err)
	}
}

// Гонка на границе: sing-box успел открыть порт в тот же миг, когда пришла остановка (Start
// вернул nil при уже отменённом контексте). Такая роль не публикуется, а свой sing-box
// останавливается: иначе StopServerRole, вернувшись, оставил бы за собой поднятый процесс.
func TestStartServerRole_CancelRacingWithSuccessStopsRunner(t *testing.T) {
	r := newFakeServerRunner()
	withServerRoleStubs(t, r)
	e, _ := newServerRoleTestEngine(t)

	r.startFn = func(ctx context.Context, _ int) error {
		<-ctx.Done()
		return nil // порт открылся, хотя остановка уже пришла
	}

	first := startServerRoleAsync(e)
	waitStartEntered(t, r)
	if err := e.StopServerRole(); err != nil {
		t.Fatalf("StopServerRole: %v", err)
	}
	if err := waitStartResult(t, first); !errors.Is(err, context.Canceled) {
		t.Fatalf("запуск, обогнанный остановкой, должен вернуть отмену, получено %v", err)
	}
	if _, stop, _ := r.counters(); stop < 1 {
		t.Error("sing-box, поднявшийся одновременно с остановкой, не был остановлен")
	}
	e.serverRoleMu.Lock()
	published := e.serverRoleRunner
	e.serverRoleMu.Unlock()
	if published != nil {
		t.Error("роль, обогнанная остановкой, не должна публиковаться")
	}
	if r.IsRunning() {
		t.Error("runner остался запущенным после остановки")
	}
}

// УСПЕШНЫЙ запуск не отменяет контекст, под которым живёт sing-box (ревью 2026-09-30, критично).
// Process.Start создаёт процесс через exec.CommandContext(ctx, …): отмена контекста убивает
// дочерний процесс. Первая версия single-flight отменяла контекст в defer при ЛЮБОМ возврате —
// каждый успешный «Запустить» убивал только что поднятый sing-box: роль показывала «запущена»,
// публичный порт слушал AdmissionProxy, а sing-box за ним был мёртв. Девять прежних тестов этого
// не видели: ни один не доходил до успешного конца. Фейк-runner здесь, как настоящий Process,
// запоминает переданный контекст, а тест проверяет его ПОСЛЕ возврата StartServerRole.
func TestStartServerRole_SuccessKeepsRunnerContextAlive(t *testing.T) {
	r := newFakeServerRunner()
	withServerRoleStubs(t, r)
	origListen := listenPublicFn
	listenPublicFn = func(int) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }
	t.Cleanup(func() { listenPublicFn = origListen })

	var captured context.Context
	r.startFn = func(ctx context.Context, _ int) error {
		captured = ctx
		return nil
	}
	e, _ := newServerRoleTestEngine(t)

	if err := e.StartServerRole(18443, "", singbox.ServerIdentity{}); err != nil {
		t.Fatalf("StartServerRole: %v", err)
	}
	if captured == nil {
		t.Fatal("runner.Start не получил контекст")
	}
	if err := captured.Err(); err != nil {
		t.Fatalf("после УСПЕШНОГО запуска контекст sing-box отменён (%v): процесс, привязанный к нему через exec.CommandContext, был бы убит", err)
	}
	if !e.IsServerRoleRunning() {
		t.Error("запуск удался, но IsServerRoleRunning=false")
	}

	// Остановка роли освобождает контекст запущенного sing-box — уже после runner.Stop.
	if err := e.StopServerRole(); err != nil {
		t.Fatalf("StopServerRole: %v", err)
	}
	if captured.Err() == nil {
		t.Error("после StopServerRole контекст запущенного sing-box должен быть освобождён")
	}
	if _, stop, _ := r.counters(); stop < 1 {
		t.Error("StopServerRole не остановил runner")
	}
}

// Перезапуск роли поверх работающей (горячая перезагрузка): контекст нового успешного запуска
// тоже жив, а контекст предыдущего освобождён (его sing-box остановлен перед новым Start).
func TestStartServerRole_HotReloadKeepsNewContextAlive(t *testing.T) {
	r := newFakeServerRunner()
	withServerRoleStubs(t, r)
	origListen := listenPublicFn
	listenPublicFn = func(int) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }
	t.Cleanup(func() { listenPublicFn = origListen })

	var ctxs []context.Context
	r.startFn = func(ctx context.Context, _ int) error {
		ctxs = append(ctxs, ctx)
		return nil
	}
	e, _ := newServerRoleTestEngine(t)
	t.Cleanup(func() { _ = e.StopServerRole() })

	for i := 0; i < 2; i++ {
		if err := e.StartServerRole(18443, "", singbox.ServerIdentity{}); err != nil {
			t.Fatalf("StartServerRole #%d: %v", i+1, err)
		}
	}
	if len(ctxs) != 2 {
		t.Fatalf("runner.Start вызван %d раз, ожидалось 2", len(ctxs))
	}
	if ctxs[0].Err() == nil {
		t.Error("контекст предыдущего запуска должен быть освобождён после успешного перезапуска")
	}
	if err := ctxs[1].Err(); err != nil {
		t.Fatalf("контекст нового успешного запуска отменён (%v) — его sing-box был бы убит", err)
	}
}

// StopServerRole без запуска — идемпотентный no-op (прежний контракт), runner не создаётся.
func TestStopServerRole_IdempotentWithoutStart(t *testing.T) {
	r := newFakeServerRunner()
	stubs := withServerRoleStubs(t, r)
	e, _ := newServerRoleTestEngine(t)

	for i := 0; i < 2; i++ {
		if err := e.StopServerRole(); err != nil {
			t.Fatalf("StopServerRole #%d без запуска: %v", i+1, err)
		}
	}
	if n := stubs.runnersCreated.Load(); n != 0 {
		t.Errorf("Stop не должен создавать runner, создано: %d", n)
	}
	if e.IsServerRoleRunning() {
		t.Error("роль не запускалась, IsServerRoleRunning=true")
	}
}

// IsServerRoleRunning/GetServerRoleStatus не держат serverRoleMu, пока ждут runner.IsRunning():
// Process.Start держит мьютекс процесса весь срок ожидания порта (до 120 с), и IsRunning на нём
// стоит. Под serverRoleMu опрос статуса из UI на время горячей перезагрузки парализовал бы и
// Stop, и сам Start. На старом коде замок оставался занят на всё время IsRunning.
func TestServerRoleStatus_DoesNotHoldMutexWhileWaitingOnRunner(t *testing.T) {
	for name, poll := range map[string]func(*Engine){
		"IsServerRoleRunning": func(e *Engine) { e.IsServerRoleRunning() },
		"GetServerRoleStatus": func(e *Engine) { e.GetServerRoleStatus() },
	} {
		t.Run(name, func(t *testing.T) {
			r := newFakeServerRunner()
			r.isRunningEntered = make(chan struct{}, 1)
			r.isRunningGate = make(chan struct{})
			e, _ := newServerRoleTestEngine(t)
			e.serverRoleMu.Lock()
			e.serverRoleRunner = r
			e.serverRoleMu.Unlock()

			done := make(chan struct{})
			go func() {
				defer close(done)
				poll(e)
			}()
			select {
			case <-r.isRunningEntered:
			case <-time.After(10 * time.Second):
				t.Fatal("IsRunning не был вызван за 10 с")
			}

			if !e.serverRoleMu.TryLock() {
				t.Error("serverRoleMu занят, пока опрос статуса ждёт runner.IsRunning — Stop/Start встанут")
			} else {
				e.serverRoleMu.Unlock()
			}
			close(r.isRunningGate)
			<-done
		})
	}
}
