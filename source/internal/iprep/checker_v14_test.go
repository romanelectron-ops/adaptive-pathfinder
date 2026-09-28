// checker_v14_test.go — ТЗ v1.4, C-12 (лот L1-PAN).
//
// К2-E (П15) уже перевёл ip-api.com на https, поставил нейтральный User-Agent и ограничил
// оба json.Decode io.LimitReader(1 МБ) — см. checker_k2e_test.go. C-12 не откатывает это, а
// доделывает то, что К2-E оставил открытым (черновик ТЗ этот лот изначально не назначал —
// назначен консилиумом, возражение O-5):
//
//  1. Отказ https-запроса к ip-api.com (бесплатный тариф может его не обслуживать) должен
//     оседать как «репутация неизвестна» (все булевы поля false, RiskScore == 0,
//     Label() == "unknown"), а НЕ как «узел плохой» (высокий RiskScore / IsProxy=true) —
//     и без ошибки, доходящей до вызывающего.
//  2. В лог должна идти ОДНА строка на источник (ip-api.com / proxycheck.io), а не одна на
//     каждый проверяемый узел. До фикса CheckIP логирует "... failed for <ip>: ..." на
//     каждый вызов — при проверке пула из N узлов с недоступным по 403 API это N
//     одинаковых по сути строк вместо одной.
package iprep

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// forbiddenHandler отвечает 403 с телом, которое не соответствует ни одной успешной схеме
// ip-api/proxycheck (валидный JSON, но status != success/ok) — как в жизни на бесплатном
// тарифе, отказывающем в https.
func forbiddenHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"status":"fail","message":"reserved range"}`))
	}
}

// TestV14_C12_BothAPIsForbidden_YieldsUnknownNotBad — узел не штрафуется отказом источника.
func TestV14_C12_BothAPIsForbidden_YieldsUnknownNotBad(t *testing.T) {
	srv := httptest.NewServer(forbiddenHandler())
	defer srv.Close()

	origIP, origPC := ipAPIBaseURL, proxyCheckBaseURL
	ipAPIBaseURL, proxyCheckBaseURL = srv.URL, srv.URL
	defer func() { ipAPIBaseURL, proxyCheckBaseURL = origIP, origPC }()

	c := NewChecker(nil)
	info, err := c.CheckIP(context.Background(), "203.0.113.9")
	if err != nil {
		t.Fatalf("отказ обоих источников не должен возвращать ошибку вызывающему: %v", err)
	}
	if info == nil {
		t.Fatal("info не должен быть nil")
	}

	// Поле репутации пусто: ни один сигнал "это плохой узел" не выставлен.
	if info.IsProxy || info.IsVPN || info.IsDatacenter || info.IsHosting || info.IsResidential {
		t.Errorf("отказ API должен давать нейтральную (пустую) репутацию, получено %+v", info)
	}
	if info.RiskScore != 0 {
		t.Errorf("отказ API не должен штрафовать узел: RiskScore = %d, want 0", info.RiskScore)
	}
	if got := info.Label(); got != "unknown" {
		t.Errorf("Label() = %q, want %q (репутация неизвестна, а не «плохой узел»)", got, "unknown")
	}
}

// TestV14_C12_LogOncePerSource_NotPerNode — при проверке нескольких узлов на фоне
// недоступного источника в лог должна попасть одна строка на источник, а не одна на узел.
func TestV14_C12_LogOncePerSource_NotPerNode(t *testing.T) {
	srv := httptest.NewServer(forbiddenHandler())
	defer srv.Close()

	origIP, origPC := ipAPIBaseURL, proxyCheckBaseURL
	ipAPIBaseURL, proxyCheckBaseURL = srv.URL, srv.URL
	defer func() { ipAPIBaseURL, proxyCheckBaseURL = origIP, origPC }()

	var mu sync.Mutex
	var failLines []string
	logFn := func(s string) {
		if strings.Contains(s, "failed") {
			mu.Lock()
			failLines = append(failLines, s)
			mu.Unlock()
		}
	}

	c := NewChecker(logFn)
	ips := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4", "198.51.100.5"}
	for _, ip := range ips {
		if _, err := c.CheckIP(context.Background(), ip); err != nil {
			t.Fatalf("CheckIP(%s): %v", ip, err)
		}
	}

	mu.Lock()
	n := len(failLines)
	got := append([]string(nil), failLines...)
	mu.Unlock()

	// Ровно один источник отказа на этом стенде (оба URL указывают на один и тот же
	// forbiddenHandler, но код различает "ip-api.com" и "proxycheck.io" как два разных
	// источника) => ожидается ровно 2 строки на 5 проверенных узлов, а не 10.
	if n != 2 {
		t.Errorf("ожидалось 2 строки отказа (по одной на источник) на %d проверенных узлов, получено %d: %v",
			len(ips), n, got)
	}
}
