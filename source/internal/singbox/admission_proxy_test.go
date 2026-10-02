package singbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
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

// newTestProxy — прокси без реального listener-а: логика допуска работает без сокетов.
// Часы подменяются шагами через возвращённый указатель на время.
func newTestProxy(limit int) (*AdmissionProxy, *time.Time) {
	p := NewAdmissionProxy(nil, "127.0.0.1:1", limit, 0)
	clock := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return clock }
	return p, &clock
}

// Живой тест 2026-09-29: ОДИН телефон открывает десятки соединений — все обязаны пройти при
// лимите в одно устройство (раньше упирался в лимит «5» и получал обрывы).
func TestAdmission_SameDevice_ManyConnections_AllAdmitted(t *testing.T) {
	p, _ := newTestProxy(1)
	const conns = 200
	releases := make([]func(), 0, conns)
	for i := 0; i < conns; i++ {
		rel, err := p.admit(deviceKey("203.0.113.5"))
		if err != nil {
			t.Fatalf("соединение %d одного и того же устройства отклонено: %v", i, err)
		}
		releases = append(releases, rel)
	}
	if got := p.Count(); got != 1 {
		t.Errorf("Count() = %d устройств, ожидалось 1", got)
	}
	if got := p.ConnCount(); got != conns {
		t.Errorf("ConnCount() = %d, ожидалось %d", got, conns)
	}
	for _, rel := range releases {
		rel()
	}
	if p.ConnCount() != 0 || p.Count() != 0 {
		t.Errorf("после закрытия всех: устройств=%d соединений=%d, ожидалось 0/0", p.Count(), p.ConnCount())
	}
}

func TestAdmission_SecondDevice_RejectedAtLimit(t *testing.T) {
	p, _ := newTestProxy(1)
	if _, err := p.admit(deviceKey("203.0.113.5")); err != nil {
		t.Fatalf("первое устройство отклонено: %v", err)
	}
	_, err := p.admit(deviceKey("203.0.113.6"))
	if !errors.Is(err, errDeviceLimit) {
		t.Fatalf("второе устройство при лимите 1: err=%v, ожидался errDeviceLimit", err)
	}
	// Первое устройство при этом продолжает открывать соединения.
	if _, err := p.admit(deviceKey("203.0.113.5")); err != nil {
		t.Errorf("допущенное устройство потеряло возможность открывать соединения: %v", err)
	}
}

// Между двумя страницами у устройства на секунду ноль соединений — его место не должен
// занять чужой «Вход» в пределах evictIdleAfter. [ревью 1.1.10, F5] После evictIdleAfter при
// ДОСТИГНУТОМ лимите новый источник вытесняет простаивающее место (роуминг/двойной стек), а
// вернувшийся прежний считается новым устройством.
func TestAdmission_IdleSlot_HeldUntilEvictIdleAfter_ThenEvictedByNewcomer(t *testing.T) {
	p, clock := newTestProxy(1)
	rel, err := p.admit(deviceKey("203.0.113.5"))
	if err != nil {
		t.Fatal(err)
	}
	rel() // ноль соединений, место держится

	if _, err := p.admit(deviceKey("203.0.113.6")); !errors.Is(err, errDeviceLimit) {
		t.Fatalf("чужое устройство заняло место сразу после закрытия последнего соединения: err=%v", err)
	}
	if p.Count() != 0 {
		t.Errorf("Count() = %d: устройство без соединений не считается подключённым", p.Count())
	}

	*clock = clock.Add(evictIdleAfter - time.Second)
	if _, err := p.admit(deviceKey("203.0.113.6")); !errors.Is(err, errDeviceLimit) {
		t.Fatalf("место вытеснено раньше evictIdleAfter: err=%v", err)
	}

	*clock = clock.Add(2 * time.Second) // простой перевалил за evictIdleAfter, но не за deviceIdleGrace
	relB, err := p.admit(deviceKey("203.0.113.6"))
	if err != nil {
		t.Fatalf("после evictIdleAfter новый источник не вытеснил простаивающее место: %v", err)
	}
	if p.Count() != 1 || len(p.devices) != 1 {
		t.Errorf("после вытеснения: Count=%d, мест=%d, ожидалось 1/1", p.Count(), len(p.devices))
	}

	// Вытесненный вернулся — он теперь НОВОЕ устройство и упирается в лимит, пока B держит место.
	if _, err := p.admit(deviceKey("203.0.113.5")); !errors.Is(err, errDeviceLimit) {
		t.Fatalf("вытесненное устройство вернулось на своё старое место: err=%v", err)
	}
	relB() // и даже когда B простаивает менее evictIdleAfter — место не отдаётся
	if _, err := p.admit(deviceKey("203.0.113.5")); !errors.Is(err, errDeviceLimit) {
		t.Fatalf("вернувшееся вытесненное устройство вытеснило свежее место B: err=%v", err)
	}
}

// Пока лимит НЕ достигнут, действует прежняя отсрочка deviceIdleGrace: место держится за
// вернувшимся с тем же адресом устройством, чужой «Вход» его не отнимает (он получает свободное
// место), а по истечении отсрочки место освобождается совсем.
func TestAdmission_ReturningDeviceWithinGrace_KeepsItsSlot(t *testing.T) {
	p, clock := newTestProxy(2)
	rel, _ := p.admit(deviceKey("203.0.113.5"))
	rel()
	*clock = clock.Add(deviceIdleGrace / 2) // > evictIdleAfter, но лимит (2) не достигнут

	if _, err := p.admit(deviceKey("203.0.113.6")); err != nil {
		t.Fatalf("новое устройство при свободном месте не пущено: %v", err)
	}
	if len(p.devices) != 2 {
		t.Fatalf("мест занято %d, ожидалось 2: при недостигнутом лимите простаивающее место вытеснять нельзя", len(p.devices))
	}
	slotBefore := p.devices[deviceKey("203.0.113.5")]
	if _, err := p.admit(deviceKey("203.0.113.5")); err != nil {
		t.Fatalf("вернувшееся в пределах отсрочки устройство не пущено: %v", err)
	}
	if p.devices[deviceKey("203.0.113.5")] != slotBefore {
		t.Error("вернувшееся устройство получило НОВОЕ место вместо своего прежнего")
	}

	// Отсрочка истекла целиком — место снимается независимо от лимита.
	p2, clock2 := newTestProxy(5)
	rel2, _ := p2.admit(deviceKey("203.0.113.5"))
	rel2()
	*clock2 = clock2.Add(deviceIdleGrace + time.Second)
	if _, err := p2.admit(deviceKey("203.0.113.6")); err != nil {
		t.Fatal(err)
	}
	if _, held := p2.devices[deviceKey("203.0.113.5")]; held {
		t.Error("место осталось за устройством после истечения deviceIdleGrace")
	}
}

// Вытесняется САМОЕ ДАВНЕЕ простаивающее место, а не любое.
func TestAdmission_EvictsOldestIdleSlotFirst(t *testing.T) {
	p, clock := newTestProxy(2)
	relA, _ := p.admit(deviceKey("203.0.113.5"))
	relA() // A простаивает с t0
	*clock = clock.Add(10 * time.Second)
	relB, _ := p.admit(deviceKey("203.0.113.6"))
	relB()                                           // B простаивает с t0+10с
	*clock = clock.Add(evictIdleAfter + time.Second) // оба старше evictIdleAfter

	if _, err := p.admit(deviceKey("203.0.113.7")); err != nil {
		t.Fatalf("новое устройство не вытеснило простаивающее место: %v", err)
	}
	if _, ok := p.devices[deviceKey("203.0.113.5")]; ok {
		t.Error("остался самый давний простаивающий A — вытеснен не тот")
	}
	if _, ok := p.devices[deviceKey("203.0.113.6")]; !ok {
		t.Error("вытеснен более свежий B вместо давнего A")
	}
}

// Устройство с открытыми соединениями не вытесняется НИКОГДА, сколько бы оно ни держало их.
func TestAdmission_ActiveDeviceNeverEvicted(t *testing.T) {
	p, clock := newTestProxy(1)
	if _, err := p.admit(deviceKey("203.0.113.5")); err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(10 * deviceIdleGrace)
	if _, err := p.admit(deviceKey("203.0.113.6")); !errors.Is(err, errDeviceLimit) {
		t.Fatalf("активное устройство вытеснено: err=%v", err)
	}
	if p.Count() != 1 {
		t.Errorf("Count() = %d, ожидалось 1", p.Count())
	}
}

// Лимит уменьшили на лету — мест занято больше, чем разрешено. Вытеснение «всё или ничего»:
// если простаивающих мест не хватает, чтобы освободить нужное число, не вытесняется никто.
func TestAdmission_LoweredLimit_EvictionIsAllOrNothing(t *testing.T) {
	p, clock := newTestProxy(3)
	relA, _ := p.admit(deviceKey("203.0.113.5"))
	relB, _ := p.admit(deviceKey("203.0.113.6"))
	if _, err := p.admit(deviceKey("203.0.113.7")); err != nil { // C остаётся активным
		t.Fatal(err)
	}
	relA()
	relB()
	*clock = clock.Add(evictIdleAfter + time.Second)

	p.SetMaxClients(1) // мест 3, лимит 1: для нового нужно освободить 3, а простаивают лишь 2
	if _, err := p.admit(deviceKey("203.0.113.8")); !errors.Is(err, errDeviceLimit) {
		t.Fatalf("err=%v, ожидался errDeviceLimit", err)
	}
	if len(p.devices) != 3 {
		t.Errorf("мест осталось %d, ожидалось 3: отказ не должен стоить чужих мест", len(p.devices))
	}

	p.SetMaxClients(2) // теперь нужно освободить 2 — простаивающих ровно 2
	if _, err := p.admit(deviceKey("203.0.113.8")); err != nil {
		t.Fatalf("err=%v: 2 простаивающих места достаточно, чтобы освободить 2", err)
	}
	if len(p.devices) != 2 {
		t.Errorf("мест %d, ожидалось 2 (активный C + новый)", len(p.devices))
	}
}

// [ревью 1.1.10, F5-ux] Строка отказа считает «занято слотов» и отдельно — те, что лишь
// удерживаются после отключения; счётчик интерфейса (Count) их не считает.
func TestAdmission_RejectLog_SeparatesHeldSlots(t *testing.T) {
	p, _ := newTestProxy(2)
	var lines []string
	p.OnLog = func(s string) { lines = append(lines, s) }
	if _, err := p.admit(deviceKey("203.0.113.5")); err != nil { // A активен
		t.Fatal(err)
	}
	relB, _ := p.admit(deviceKey("203.0.113.6"))
	relB() // B удерживается после отключения

	_, err := p.admit(deviceKey("203.0.113.7"))
	if !errors.Is(err, errDeviceLimit) {
		t.Fatalf("err=%v, ожидался errDeviceLimit", err)
	}
	p.logReject(deviceKey("203.0.113.7"), "203.0.113.7", err)
	if len(lines) != 1 {
		t.Fatalf("строк журнала %d, ожидалась 1", len(lines))
	}
	want := "занято слотов: 2 (из них удерживаются после отключения: 1)"
	if !strings.Contains(lines[0], want) {
		t.Errorf("строка %q не содержит %q", lines[0], want)
	}
	if strings.Contains(lines[0], "подключено:") {
		t.Errorf("строка %q всё ещё называет удерживаемые слоты «подключено»", lines[0])
	}
	if got := p.Count(); got != 1 {
		t.Errorf("Count() = %d: удерживаемый слот не должен считаться подключённым устройством", got)
	}
}

func TestIsAdmissionRejection(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"лимит устройств", errDeviceLimit, true},
		{"потолок соединений", errDeviceConnCap, true},
		{"лимит, обёрнутый %w", fmt.Errorf("DialLocal: %w", errDeviceLimit), true},
		{"потолок, обёрнутый дважды", fmt.Errorf("a: %w", fmt.Errorf("b: %w", errDeviceConnCap)), true},
		{"nil", nil, false},
		{"чужая ошибка", errors.New("connection refused"), false},
		{"io.EOF", io.EOF, false},
		{"строка, похожая на текст отказа", errors.New(errDeviceLimit.Error()), false}, // сравнение по значению, не по тексту
	}
	for _, c := range cases {
		if got := IsAdmissionRejection(c.err); got != c.want {
			t.Errorf("%s: IsAdmissionRejection(%v) = %v, ожидалось %v", c.name, c.err, got, c.want)
		}
	}
	// И реальные ошибки admit — те самые, что увидит ExitClient.
	p, _ := newTestProxy(1)
	if _, err := p.admit(deviceKey("203.0.113.5")); err != nil {
		t.Fatal(err)
	}
	_, err := p.admit(deviceKey("203.0.113.6"))
	if !IsAdmissionRejection(err) {
		t.Errorf("реальный отказ admit (%v) не распознан как отказ лимита", err)
	}
}

// ─── [ревью 1.1.10, F3] цикл Accept переживает ошибки ────────────────────────────────────

type tempAcceptErr struct{}

func (tempAcceptErr) Error() string   { return "accept: временный сбой (тест)" }
func (tempAcceptErr) Timeout() bool   { return false }
func (tempAcceptErr) Temporary() bool { return true }

// flakyListener — первые failFirst вызовов Accept возвращают ошибку, дальше делегируют
// настоящему listener'у.
type flakyListener struct {
	net.Listener
	mu        sync.Mutex
	failFirst int
	err       error
	calls     int
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	l.calls++
	fail := l.calls <= l.failFirst
	l.mu.Unlock()
	if fail {
		return nil, l.err
	}
	return l.Listener.Accept()
}

func (l *flakyListener) Calls() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

// Первая Accept — временная ошибка, вторая — реальное соединение: оно обязано быть принято и
// обслужено. Раньше Serve умирал на первой ошибке, а порт оставался слушающим «в никуда».
func TestServe_TemporaryAcceptError_KeepsAccepting(t *testing.T) {
	internalAddr := echoListenerForAdmissionTest(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	flaky := &flakyListener{Listener: ln, failFirst: 1, err: tempAcceptErr{}}
	proxy := NewAdmissionProxy(flaky, internalAddr, 1, 0)
	var logMu sync.Mutex
	var logged []string
	proxy.OnLog = func(s string) { logMu.Lock(); logged = append(logged, s); logMu.Unlock() }

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() { proxy.Serve(ctx); close(served) }()

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("соединение после временной ошибки Accept не принято (цикл Serve умер?): %v", err)
	}
	if flaky.Calls() < 2 {
		t.Errorf("Accept вызван %d раз, ожидалось не меньше 2", flaky.Calls())
	}
	logMu.Lock()
	if len(logged) != 1 || !strings.Contains(logged[0], "ошибка Accept") {
		t.Errorf("журнал = %q, ожидалась одна строка про ошибку Accept", logged)
	}
	logMu.Unlock()

	cancel()
	select {
	case <-served:
	case <-time.After(3 * time.Second):
		t.Fatal("Serve не вернулся после отмены ctx")
	}
}

// Не-временная (произвольная) ошибка — тоже повтор с паузой, а не выход: по требованию ревью
// выходит только закрытый listener или отменённый ctx. Пауза растёт, но ограничена сверху.
func TestServe_ArbitraryAcceptErrors_BackOffAndRecover(t *testing.T) {
	internalAddr := echoListenerForAdmissionTest(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	flaky := &flakyListener{Listener: ln, failFirst: 4, err: errors.New("accept: too many open files")}
	proxy := NewAdmissionProxy(flaky, internalAddr, 0, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go proxy.Serve(ctx)

	start := time.Now()
	c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte("y"))
	buf := make([]byte, 1)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("после серии ошибок Accept соединение не обслужено: %v", err)
	}
	// 4 ошибки = паузы 5+10+20+40 = 75 мс; главное — пауза есть (не «горячий» цикл).
	if el := time.Since(start); el < 60*time.Millisecond {
		t.Errorf("серия из 4 ошибок Accept прошла за %v — паузы между попытками не выдерживаются", el)
	}
}

// Закрытый listener и отменённый ctx — единственные выходы из Serve.
func TestServe_ClosedListener_Returns(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	proxy := NewAdmissionProxy(ln, "127.0.0.1:1", 1, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan struct{})
	go func() { proxy.Serve(ctx); close(served) }()
	time.Sleep(50 * time.Millisecond)
	ln.Close()
	select {
	case <-served:
	case <-time.After(3 * time.Second):
		t.Fatal("Serve не вернулся после закрытия listener'а — вечный цикл повторов")
	}
}

// ─── [ревью 1.1.10, F5] keepalive на принятых TCP-соединениях ─────────────────────────────

func TestEnableKeepAlive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	client, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	if !enableKeepAlive(server) {
		t.Error("enableKeepAlive вернул false для обычного TCP-соединения")
	}
	// Не-TCP (обёртка, net.Pipe) — false и без паники: остаётся дефолт listener'а.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if enableKeepAlive(a) {
		t.Error("enableKeepAlive вернул true для net.Pipe")
	}
	if keepAliveIdle+time.Duration(keepAliveCount)*keepAliveInterval >= 150*time.Second {
		t.Error("срок обнаружения мёртвого пира не короче ~150 с дефолта Go — keepalive ничего не даёт")
	}
}

// Проводка keepalive: handleConn включает его у ДОПУЩЕННОГО соединения и не трогает отклонённое.
// Раньше тест звал enableKeepAlive напрямую — вызов из handleConn можно было убрать незаметно.
func TestHandleConn_KeepAliveOnlyForAdmittedConnections(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	// Внутренняя цель — закрытый порт: handleConn после допуска сразу получает отказ dial и выходит.
	proxy := NewAdmissionProxy(ln, "127.0.0.1:1", 1, 0)

	var calls atomic.Int32
	orig := keepAliveFn
	keepAliveFn = func(net.Conn) bool { calls.Add(1); return true }
	defer func() { keepAliveFn = orig }()

	// Допущенное (устройство «unknown» — net.Pipe не даёт разбираемого адреса): keepalive включён.
	a, b := net.Pipe()
	defer b.Close()
	proxy.handleConn(a)
	if n := calls.Load(); n != 1 {
		t.Fatalf("keepAliveFn вызван %d раз для допущенного соединения, ожидался 1", n)
	}

	// Лимит исчерпан другим устройством: новое соединение отклоняется и keepalive не получает.
	// Отдельный прокси: слот «unknown» из первой части ещё удерживается паузой после отключения.
	proxy2 := NewAdmissionProxy(ln, "127.0.0.1:1", 1, 0)
	release, err := proxy2.admit("other-device")
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	defer release()
	c, d := net.Pipe()
	defer d.Close()
	proxy2.handleConn(c)
	if n := calls.Load(); n != 1 {
		t.Errorf("keepAliveFn вызван для отклонённого соединения (всего вызовов: %d, ожидался 1)", n)
	}
}

func TestAdmission_PerDeviceConnCap(t *testing.T) {
	p, _ := newTestProxy(5)
	key := deviceKey("203.0.113.5")
	for i := 0; i < maxConnsPerDevice; i++ {
		if _, err := p.admit(key); err != nil {
			t.Fatalf("соединение %d до потолка отклонено: %v", i, err)
		}
	}
	if _, err := p.admit(key); !errors.Is(err, errDeviceConnCap) {
		t.Fatalf("сверх потолка: err=%v, ожидался errDeviceConnCap", err)
	}
	// Потолок одного устройства не мешает другим.
	if _, err := p.admit(deviceKey("203.0.113.6")); err != nil {
		t.Errorf("другое устройство отклонено из-за потолка первого: %v", err)
	}
}

// Лимит <= 0 — выключен (fail-open): любое число устройств проходит.
func TestAdmission_ZeroLimit_AllowsAllDevices(t *testing.T) {
	p, _ := newTestProxy(0)
	for i := 0; i < 50; i++ {
		if _, err := p.admit(deviceKey(fmt.Sprintf("203.0.113.%d", i))); err != nil {
			t.Fatalf("устройство %d отклонено при выключенном лимите: %v", i, err)
		}
	}
}

func TestDeviceKey(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"203.0.113.5", "203.0.113.5"},
		{"::ffff:203.0.113.5", "203.0.113.5"}, // IPv4-in-IPv6 = тот же IPv4
		{"", relayDeviceKey},
		{"это-не-адрес", unknownDeviceKey},
		{"2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64"},
		{"2001:db8:1:2:1111:2222:3333:4444", "2001:db8:1:2::/64"}, // временный адрес того же устройства
		{"fe80::1%eth0", "fe80::/64"},                             // зона отбрасывается
	}
	for _, c := range cases {
		if got := deviceKey(c.in); got != c.want {
			t.Errorf("deviceKey(%q) = %q, ожидалось %q", c.in, got, c.want)
		}
	}
	if deviceKey("2001:db8:1:2::1") == deviceKey("2001:db8:1:3::1") {
		t.Error("разные /64 обязаны быть разными устройствами")
	}
}

// [консилиум, CRITICAL] TOCTOU: N горутин одновременно просятся — устройств одновременно не
// должно оказаться больше лимита ни разу, даже под гонкой. Гонять с -race.
func TestAdmission_ConcurrentDevices_LimitNeverExceeded(t *testing.T) {
	const limit = 3
	const attempts = 40
	p, _ := newTestProxy(limit)

	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := 0
	start := make(chan struct{})
	hold := make(chan struct{})
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			rel, err := p.admit(deviceKey(fmt.Sprintf("203.0.113.%d", i+1)))
			if err != nil {
				return
			}
			mu.Lock()
			admitted++
			mu.Unlock()
			<-hold // держим соединение, чтобы создать реальную конкуренцию за места
			rel()
		}(i)
	}
	close(start)
	time.Sleep(200 * time.Millisecond)
	if got := p.Count(); got > limit {
		t.Errorf("одновременно подключено %d устройств > лимита %d", got, limit)
	}
	close(hold)
	wg.Wait()
	if admitted != limit {
		t.Errorf("допущено %d устройств, ожидалось ровно %d (лимит)", admitted, limit)
	}
}

// Настоящий сокет: одно устройство (127.0.0.1) — много соединений сквозь прокси при лимите 1.
func TestAdmissionProxy_Sockets_OneDeviceManyConnections(t *testing.T) {
	internalAddr := echoListenerForAdmissionTest(t)
	publicLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	proxy := NewAdmissionProxy(publicLn, internalAddr, 1, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go proxy.Serve(ctx)

	const conns = 12
	clients := make([]net.Conn, 0, conns)
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()
	for i := 0; i < conns; i++ {
		c, err := net.DialTimeout("tcp", publicLn.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		clients = append(clients, c)
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write([]byte("x")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		buf := make([]byte, 1)
		if _, err := io.ReadFull(c, buf); err != nil {
			t.Fatalf("соединение %d одного устройства не обслужено (лимит 1 устройство): %v", i, err)
		}
	}
	if got := proxy.Count(); got != 1 {
		t.Errorf("Count() = %d устройств, ожидалось 1", got)
	}
	if got := proxy.ConnCount(); got != conns {
		t.Errorf("ConnCount() = %d, ожидалось %d", got, conns)
	}
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
		t.Fatalf("Count() = %d, ожидалось 1 устройство после одного подключения", proxy.Count())
	}
	conn.Close()
	// Закрытие доходит до прокси через Splice не мгновенно (под -race и при загруженном
	// процессоре — заметно дольше 100 мс, так тест уже флакал): ждём до 2 с, а не спим вслепую.
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		if proxy.Count() == 0 && proxy.ConnCount() == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if proxy.Count() != 0 || proxy.ConnCount() != 0 {
		t.Errorf("после закрытия: устройств=%d соединений=%d, ожидалось 0/0", proxy.Count(), proxy.ConnCount())
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

// Relay-путь: AdmitAndDial занимает место по адресу, который сообщил посредник, и отдаёт его
// при закрытии соединения. Байты доходят до внутренней цели.
func TestAdmitAndDial_AdmitsBySourceAndReleasesOnClose(t *testing.T) {
	internalAddr := echoListenerForAdmissionTest(t)
	proxy := NewAdmissionProxy(nil, internalAddr, 1, 0)

	c1, err := proxy.AdmitAndDial(context.Background(), "198.51.100.10")
	if err != nil {
		t.Fatalf("первое устройство через relay: %v", err)
	}
	if proxy.Count() != 1 {
		t.Fatalf("Count() = %d, ожидалось 1", proxy.Count())
	}
	c1.SetDeadline(time.Now().Add(2 * time.Second))
	c1.Write([]byte("z"))
	buf := make([]byte, 1)
	if _, err := io.ReadFull(c1, buf); err != nil || buf[0] != 'z' {
		t.Fatalf("байты не дошли до внутренней цели: %v %q", err, buf)
	}

	// То же устройство — ещё соединение: пускается.
	c1b, err := proxy.AdmitAndDial(context.Background(), "198.51.100.10")
	if err != nil {
		t.Fatalf("второе соединение того же устройства: %v", err)
	}
	// Другое устройство при лимите 1 — нет.
	if _, err := proxy.AdmitAndDial(context.Background(), "198.51.100.11"); !errors.Is(err, errDeviceLimit) {
		t.Fatalf("второе устройство через relay: err=%v, ожидался errDeviceLimit", err)
	}

	c1.Close()
	c1b.Close()
	c1b.Close() // повторное закрытие не должно ломать счётчик
	if proxy.ConnCount() != 0 {
		t.Errorf("ConnCount() = %d после закрытия, ожидалось 0", proxy.ConnCount())
	}
}

// Relay без адреса источника (старая версия посредника): все такие подключения — одно
// устройство relayDeviceKey.
func TestAdmitAndDial_NoSource_CountsAsOneRelayDevice(t *testing.T) {
	internalAddr := echoListenerForAdmissionTest(t)
	proxy := NewAdmissionProxy(nil, internalAddr, 1, 0)
	a, err := proxy.AdmitAndDial(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := proxy.AdmitAndDial(context.Background(), "")
	if err != nil {
		t.Fatalf("второе соединение relay без адреса источника отклонено: %v", err)
	}
	defer b.Close()
	if proxy.Count() != 1 {
		t.Errorf("Count() = %d, ожидалось 1 (одно relay-устройство)", proxy.Count())
	}
}

func TestAdmission_RejectLogIsRateLimited(t *testing.T) {
	p, clock := newTestProxy(1)
	var lines []string
	p.OnLog = func(s string) { lines = append(lines, s) }
	if _, err := p.admit(deviceKey("203.0.113.5")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		_, err := p.admit(deviceKey("203.0.113.6"))
		p.logReject(deviceKey("203.0.113.6"), "203.0.113.6", err)
	}
	if len(lines) != 1 {
		t.Fatalf("за минуту 100 отказов одному устройству дали %d строк лога, ожидалась 1", len(lines))
	}
	*clock = clock.Add(rejectLogEvery + time.Second)
	_, err := p.admit(deviceKey("203.0.113.6"))
	p.logReject(deviceKey("203.0.113.6"), "203.0.113.6", err)
	if len(lines) != 2 {
		t.Errorf("через минуту ожидалась вторая строка лога, всего %d", len(lines))
	}
}
