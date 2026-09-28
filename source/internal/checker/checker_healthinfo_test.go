// checker_healthinfo_test.go — ТЗ v1.3 F1.2 (консилиум 2026-09-03, NL-1/V3): HTTP-проверка через
// туннель возвращает и exit-IP, а не только страну; запасные цели без тела (generate_204) дают
// пустые поля без ошибки.
package checker

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Позитив: loc= и ip= разбираются из тела cdn-cgi/trace независимо от порядка строк.
func TestHTTPHealthCheckInfoAt_ParsesCountryAndExitIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "fl=123f\nh=cloudflare.com\nip=203.0.113.7\nts=1.0\nloc=NL\nsni=plaintext\n")
	}))
	defer srv.Close()

	c := New(2, 5)
	proxyAddr := startMockSOCKS5(t, srv.Listener.Addr().String())
	info, err := c.HTTPHealthCheckInfoAt(context.Background(), proxyAddr, srv.URL)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if info.Country != "NL" {
		t.Errorf("country=%q want NL", info.Country)
	}
	if info.ExitIP != "203.0.113.7" {
		t.Errorf("exitIP=%q want 203.0.113.7", info.ExitIP)
	}
	if info.LatencyMs < 0 {
		t.Errorf("latency=%d want >= 0", info.LatencyMs)
	}
}

// Fail-safe: цель без тела (как generate_204) — успех с пустыми страной/IP, не ошибка.
func TestHTTPHealthCheckInfoAt_NoBodyTarget_EmptyFieldsNoError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(2, 5)
	proxyAddr := startMockSOCKS5(t, srv.Listener.Addr().String())
	info, err := c.HTTPHealthCheckInfoAt(context.Background(), proxyAddr, srv.URL)
	if err != nil {
		t.Fatalf("204 без тела должен быть успехом, got: %v", err)
	}
	if info.Country != "" || info.ExitIP != "" {
		t.Errorf("поля должны быть пустыми: country=%q ip=%q", info.Country, info.ExitIP)
	}
}

// Негатив: 5xx — провал, поля не заполняются даже если тело похоже на trace.
func TestHTTPHealthCheckInfoAt_ServerError_Fails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, "loc=US\nip=1.2.3.4\n")
	}))
	defer srv.Close()

	c := New(2, 5)
	proxyAddr := startMockSOCKS5(t, srv.Listener.Addr().String())
	info, err := c.HTTPHealthCheckInfoAt(context.Background(), proxyAddr, srv.URL)
	if err == nil {
		t.Fatal("502 должен быть провалом")
	}
	if info.Country != "" || info.ExitIP != "" {
		t.Errorf("при провале поля должны быть пустыми: %+v", info)
	}
}

// Инвариант совместимости: старая обёртка HTTPHealthCheckAt отдаёт ту же страну/задержку.
func TestHTTPHealthCheckAt_WrapperMatchesInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "loc=DE\nip=198.51.100.9\n")
	}))
	defer srv.Close()

	c := New(2, 5)
	proxyAddr := startMockSOCKS5(t, srv.Listener.Addr().String())
	_, country, err := c.HTTPHealthCheckAt(context.Background(), proxyAddr, srv.URL)
	if err != nil || country != "DE" {
		t.Fatalf("wrapper: country=%q err=%v, want DE/nil", country, err)
	}
	if DefaultHealthCheckURL() != cfTraceURL {
		t.Errorf("DefaultHealthCheckURL()=%q должен совпадать с cfTraceURL=%q", DefaultHealthCheckURL(), cfTraceURL)
	}
}
