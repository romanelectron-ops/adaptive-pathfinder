package engine

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// ─── B-0403 · R-3.2 · проба локальных портов входа ───────────────────────────

type stubListener struct{ closed int }

func (s *stubListener) Accept() (net.Conn, error) { return nil, errors.New("stub") }
func (s *stubListener) Close() error              { s.closed++; return nil }
func (s *stubListener) Addr() net.Addr            { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func withListenProbe(t *testing.T, fn func(string) (net.Listener, error)) {
	t.Helper()
	old := listenProbeFn
	t.Cleanup(func() { listenProbeFn = old })
	listenProbeFn = fn
}

// Позитив: проверяются ОБА порта (SOCKS5 и HTTP=+1), и оба пробных сокета закрываются —
// иначе проба сама заняла бы порт, который через мгновение нужен sing-box.
func TestProbeListenPort_ProbesBothPortsAndClosesThem(t *testing.T) {
	var asked []string
	stubs := []*stubListener{}
	withListenProbe(t, func(addr string) (net.Listener, error) {
		asked = append(asked, addr)
		s := &stubListener{}
		stubs = append(stubs, s)
		return s, nil
	})

	e := &Engine{cfg: &models.AppConfig{ListenPort: 10808}}
	if err := e.probeListenPort(); err != nil {
		t.Fatalf("probeListenPort: %v", err)
	}

	want := []string{"127.0.0.1:10808", "127.0.0.1:10809"}
	if len(asked) != len(want) {
		t.Fatalf("проверено портов %v, ожидалось %v", asked, want)
	}
	for i := range want {
		if asked[i] != want[i] {
			t.Errorf("проба[%d] = %q, want %q", i, asked[i], want[i])
		}
	}
	for i, s := range stubs {
		if s.closed != 1 {
			t.Errorf("пробный сокет[%d] закрыт %d раз(а), ожидался ровно один", i, s.closed)
		}
	}
}

func TestProbeListenPort_BasePortBusy(t *testing.T) {
	withListenProbe(t, func(addr string) (net.Listener, error) {
		return nil, fmt.Errorf("bind %s: address already in use", addr)
	})

	e := &Engine{cfg: &models.AppConfig{ListenPort: 10808}}
	err := e.probeListenPort()
	if err == nil {
		t.Fatal("занятый порт обязан прерывать подключение")
	}
	if !strings.Contains(err.Error(), "10808") {
		t.Errorf("в сообщении нет номера занятого порта: %v", err)
	}
}

// Порт HTTP-входа (ListenPort+1) не менее важен: именно его прописывает системный прокси.
func TestProbeListenPort_HTTPPortBusy(t *testing.T) {
	withListenProbe(t, func(addr string) (net.Listener, error) {
		if strings.HasSuffix(addr, ":10809") {
			return nil, errors.New("address already in use")
		}
		return &stubListener{}, nil
	})

	e := &Engine{cfg: &models.AppConfig{ListenPort: 10808}}
	err := e.probeListenPort()
	if err == nil {
		t.Fatal("занятый HTTP-порт обязан прерывать подключение")
	}
	if !strings.Contains(err.Error(), "10809") {
		t.Errorf("в сообщении нет номера занятого порта: %v", err)
	}
}

// Fail-safe: ListenPort<=0 — вход не публикуется (Android), проверять нечего.
func TestProbeListenPort_NonPositivePortSkipped(t *testing.T) {
	called := 0
	withListenProbe(t, func(string) (net.Listener, error) {
		called++
		return &stubListener{}, nil
	})

	for _, p := range []int{0, -1} {
		e := &Engine{cfg: &models.AppConfig{ListenPort: p}}
		if err := e.probeListenPort(); err != nil {
			t.Fatalf("ListenPort=%d: %v", p, err)
		}
	}
	if called != 0 {
		t.Errorf("при непубликуемом входе проб быть не должно, их %d", called)
	}
}

// Сквозная проверка на настоящем сокете: без швов, реальный net.Listen.
func TestProbeListenPort_RealBusyPortDetected(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("нет возможности занять локальный порт: %v", err)
	}
	defer occupied.Close()

	port := occupied.Addr().(*net.TCPAddr).Port
	e := &Engine{cfg: &models.AppConfig{ListenPort: port}}
	if err := e.probeListenPort(); err == nil {
		t.Fatal("реально занятый порт не обнаружен")
	}
}
