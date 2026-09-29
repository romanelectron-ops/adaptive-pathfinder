package singbox

import (
	"context"
	"errors"
	"fmt"
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
// занять чужой «Вход», пока не истекла отсрочка.
func TestAdmission_DeviceSlotHeldDuringGrace_ThenReleased(t *testing.T) {
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

	*clock = clock.Add(deviceIdleGrace - time.Second)
	if _, err := p.admit(deviceKey("203.0.113.6")); !errors.Is(err, errDeviceLimit) {
		t.Fatalf("место освободилось раньше срока отсрочки: err=%v", err)
	}

	*clock = clock.Add(2 * time.Second) // отсрочка истекла
	if _, err := p.admit(deviceKey("203.0.113.6")); err != nil {
		t.Fatalf("после истечения отсрочки новое устройство не пущено: %v", err)
	}
}

func TestAdmission_ReturningDeviceWithinGrace_KeepsItsSlot(t *testing.T) {
	p, clock := newTestProxy(1)
	rel, _ := p.admit(deviceKey("203.0.113.5"))
	rel()
	*clock = clock.Add(deviceIdleGrace / 2)
	if _, err := p.admit(deviceKey("203.0.113.5")); err != nil {
		t.Fatalf("вернувшееся в пределах отсрочки устройство не пущено: %v", err)
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
