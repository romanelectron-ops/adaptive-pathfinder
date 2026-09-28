// checker_lot09_directprobe_test.go — ПРЯМАЯ проба канала (LOT-09, 2026-09-06).
//
// Зачем она есть. Проба через SOCKS (HTTPHealthCheckInfoAt) доказывает только, что исходящий
// канал sing-box до узла жив. Приложения пользователя ходят через TUN, а socks-in и tun-in в
// sing-box — два независимых inbound-пути. Отсюда симптом, из-за которого весь лот и заведён:
// «ВПН подключен, а сайт не открывается». Прямая проба идёт тем же путём, что браузер.
//
// Все тесты — на httptest (петля). В реальную сеть не ходит ни один; отдельный тест ниже
// доказывает, что барьер netguard у этой пробы действительно стоит.
package checker

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/netguard"
)

// traceBody — тело в формате cdn-cgi/trace, ровно как у настоящей цели.
const traceBody = "fl=14f99\nh=1.1.1.1\nip=203.0.113.7\nts=1757000000.1\nvisit_scheme=https\nloc=NL\ntls=TLSv1.3\n"

func TestDirectProbe_Success_ParsesSameFieldsAsSocksProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(traceBody))
	}))
	defer srv.Close()

	c := New(1, 5)
	info, err := c.HTTPHealthCheckDirectInfoAt(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("прямая проба обязана пройти на живой цели: %v", err)
	}
	if info.Country != "NL" {
		t.Errorf("loc= разобран неверно: Country=%q, ожидалось NL", info.Country)
	}
	if info.ExitIP != "203.0.113.7" {
		t.Errorf("ip= разобран неверно: ExitIP=%q, ожидалось 203.0.113.7", info.ExitIP)
	}
	if info.LatencyMs < 0 {
		t.Errorf("отрицательная задержка: %d", info.LatencyMs)
	}
}

// Критерий «живой» обязан совпадать с пробой через SOCKS: любой ответ настоящего сервера
// (включая 403/429, которые Cloudflare регулярно отдаёт на адреса дата-центров) — успех,
// провал только у 5xx и у транспортной ошибки. Иначе результаты двух проб несравнимы, и
// движок сравнивал бы разное с разным.
func TestDirectProbe_LivenessCriterionMatchesSocksProbe(t *testing.T) {
	cases := []struct {
		status int
		wantOK bool
	}{
		{200, true},
		{204, true},
		{403, true},
		{429, true},
		{500, false},
		{503, false},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(traceBody))
		}))
		c := New(1, 5)
		_, err := c.HTTPHealthCheckDirectInfoAt(context.Background(), srv.URL)
		srv.Close()
		if tc.wantOK && err != nil {
			t.Errorf("HTTP %d: ожидался успех, получена ошибка %v", tc.status, err)
		}
		if !tc.wantOK && err == nil {
			t.Errorf("HTTP %d: ожидался провал, проба сочла канал живым", tc.status)
		}
	}
}

// Провал транспорта: сервер поднят и тут же закрыт — соединение отвергается на петле,
// в сеть никто не ходит.
func TestDirectProbe_TransportFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	c := New(1, 2)
	if _, err := c.HTTPHealthCheckDirectInfoAt(context.Background(), url); err == nil {
		t.Fatal("прямая проба к закрытому порту обязана вернуть ошибку, а не «канал жив»")
	}
}

// ГЛАВНОЕ ОТЛИЧИЕ ОТ ПРОБЫ ЧЕРЕЗ SOCKS: у той барьера netguard нет осознанно (её сокет уходит
// на петлю, к SOCKS самого APF), а прямая проба уходит на НАСТОЯЩИЙ внешний адрес — и обязана
// барьер уважать, иначе `go test` полез бы в интернет. Проверяем именно тип отказа: «сеть
// запрещена» и «сеть недоступна» — разные диагнозы (см. netguard.ErrBlocked).
func TestDirectProbe_RespectsNetguardBarrier(t *testing.T) {
	if !netguard.Blocking() {
		t.Skip("барьер снят переменной окружения — проверять нечего")
	}
	c := New(1, 2)
	_, err := c.HTTPHealthCheckDirectInfoAt(context.Background(), DefaultHealthCheckURL())
	if err == nil {
		t.Fatal("прямая проба ушла в реальную сеть из тестового прогона — барьер netguard не применён")
	}
	var blocked *netguard.ErrBlocked
	if !errors.As(err, &blocked) {
		t.Fatalf("ошибка не от барьера netguard: %v (проба ходила в сеть по-настоящему?)", err)
	}
}
