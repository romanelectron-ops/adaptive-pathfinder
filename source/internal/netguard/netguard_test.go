package netguard

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Тесты идут в тестовом бинарнике, значит барьер здесь действует по-настоящему —
// подменять ничего не нужно, и проверяется ровно то, что будет в реальном прогоне.

func TestUnderTest_BarrierIsActive(t *testing.T) {
	if !UnderTest() {
		t.Fatal("UnderTest() = false внутри go test — барьер не распознал тестовый бинарник")
	}
	if Overridden() {
		t.Skip("барьер снят переменной окружения — проверять нечего")
	}
	if !Blocking() {
		t.Fatal("Blocking() = false: барьер бездействует там, где обязан действовать")
	}
}

// Контракт IsLoopback.
//
// Вход:  адрес в том виде, в каком его получает DialContext ("host:port").
// Выход: ведёт ли он на эту же машину.
// Инвариант: ошибка в любую сторону дорога — «да» вместо «нет» открывает дыру в барьере,
// «нет» вместо «да» ломает тесты с httptest-серверами и локальным SOCKS.
func TestIsLoopback(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8080", true},
		{"127.0.0.53:53", true}, // вся сеть 127.0.0.0/8, не только .1
		{"[::1]:443", true},
		{"localhost:10808", true},
		{"LocalHost:10808", true}, // регистр имени значения не имеет
		{"127.0.0.1", true},       // без порта тоже разбирается
		{"1.1.1.1:443", false},
		{"example.com:80", false},
		{"[2606:4700:4700::1111]:443", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsLoopback(c.addr); got != c.want {
			t.Errorf("IsLoopback(%q) = %v, ожидалось %v", c.addr, got, c.want)
		}
	}
}

// Контракт Guard — главный.
//
// Вход:  адрес соединения.
// Тело:  петля пропускается к базовому набору, остальное отвергается.
// Выход: соединение либо *ErrBlocked.
// Инвариант: базовая функция для непетлевого адреса НЕ вызывается вовсе — иначе сокет
//
//	успел бы уйти наружу до отказа.
func TestGuard_BlocksInternet_AllowsLoopback(t *testing.T) {
	if !Blocking() {
		t.Skip("барьер снят переменной окружения")
	}
	ResetBlocked()

	baseCalls := 0
	base := func(ctx context.Context, network, addr string) (net.Conn, error) {
		baseCalls++
		return nil, errors.New("базовый набор соединения вызван")
	}
	guarded := Guard(base)

	// 1. Наружу — отказ, и базовая функция не тронута.
	_, err := guarded(context.Background(), "tcp", "1.1.1.1:443")
	var blocked *ErrBlocked
	if !errors.As(err, &blocked) {
		t.Fatalf("выход наружу дал %v, ожидался *ErrBlocked", err)
	}
	if blocked.Addr != "1.1.1.1:443" {
		t.Errorf("ErrBlocked.Addr = %q, ожидался адрес соединения", blocked.Addr)
	}
	if baseCalls != 0 {
		t.Fatal("базовый набор соединения вызван для непетлевого адреса — " +
			"сокет успел бы уйти наружу до отказа")
	}
	if !strings.Contains(err.Error(), forceEnv) {
		t.Errorf("текст отказа не подсказывает выход из положения: %q", err)
	}

	// 2. На петлю — пропускается (базовая функция вызвана; её собственная ошибка не в счёт).
	_, _ = guarded(context.Background(), "tcp", "127.0.0.1:9")
	if baseCalls != 1 {
		t.Fatal("петля не пропущена: httptest-серверы и локальный SOCKS перестали бы работать")
	}

	if got := BlockedCount(); got != 1 {
		t.Errorf("BlockedCount() = %d, ожидался 1", got)
	}
	if addrs := BlockedAddrs(); len(addrs) != 1 || addrs[0] != "1.1.1.1:443" {
		t.Errorf("BlockedAddrs() = %v, ожидался [1.1.1.1:443]", addrs)
	}
}

// Барьер не должен ломать то, ради чего он существует: тесты на httptest-серверах.
func TestClient_WorksAgainstHttptest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	resp, err := Client(5 * time.Second).Get(srv.URL)
	if err != nil {
		t.Fatalf("запрос к httptest-серверу отвергнут: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("код ответа %d, ожидался 200", resp.StatusCode)
	}
}

// Подмена http.DefaultTransport — страховка от пропущенной точки выхода.
func TestDefaultTransport_IsGuarded(t *testing.T) {
	if !Blocking() {
		t.Skip("барьер снят переменной окружения")
	}
	_, err := http.Get("http://example.com") //nolint:noctx // проверяется именно отказ барьера
	var blocked *ErrBlocked
	if !errors.As(err, &blocked) {
		t.Fatalf("http.Get наружу дал %v, ожидался *ErrBlocked: "+
			"значит http.DefaultTransport не закрыт и любой пропущенный вызов уйдёт в сеть", err)
	}
}
