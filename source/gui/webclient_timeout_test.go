package main

// Живой инцидент ПК 2026-09-29: кнопка «Запустить» роли «Выход» показывала красное
// «context deadline exceeded (Client.Timeout exceeded while awaiting headers)», хотя служба
// запуск успешно завершала (порт слушается, правила файрвола заведены). Причина — единый
// таймаут 5 с у webClient на ВСЕ запросы, а запуск роли (остановка прежней + UPnP + 2×netsh +
// ожидание sing-box до 30 с) законно длится дольше. Тесты фиксируют новый контракт: срок
// ожидания зависит от запроса, а не общий.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestRequestTimeout_Table — сроки по классам запросов. Опрос состояния обязан оставаться
// коротким (иначе зависшая служба вешает интерфейс), долгие действия — получать запас.
func TestRequestTimeout_Table(t *testing.T) {
	cases := []struct {
		method, path string
		want         time.Duration
	}{
		{http.MethodGet, "/api/state", timeoutPoll},
		{http.MethodGet, "/api/nodes", timeoutPoll},
		{http.MethodGet, "/api/server-role/status", timeoutPoll},
		{http.MethodPost, "/api/save-config", timeoutAction},
		{http.MethodPost, "/api/server-role/stop", timeoutAction},
		{http.MethodPost, "/api/server-role/start", timeoutRoleRun},
		{http.MethodPost, "/api/chain-partner/connect", timeoutRoleRun},
		{http.MethodPost, "/api/catalog/refresh", timeoutCatalog},
		{http.MethodPost, "/api/dpi/canary-test", timeoutNetwork},
		{http.MethodGet, "/api/logs/export", timeoutNetwork},
	}
	for _, c := range cases {
		if got := requestTimeout(c.method, c.path); got != c.want {
			t.Errorf("requestTimeout(%s %s) = %v, ожидалось %v", c.method, c.path, got, c.want)
		}
	}
	if timeoutPoll > 10*time.Second {
		t.Errorf("timeoutPoll = %v: опрос состояния не должен ждать дольше 10 с", timeoutPoll)
	}
	if timeoutRoleRun <= 30*time.Second {
		t.Errorf("timeoutRoleRun = %v: запуск роли ждёт sing-box до 30 с — запас обязателен", timeoutRoleRun)
	}
}

// TestNewWebClient_NoGlobalTimeout — http.Client не должен иметь общего Timeout: он перебил
// бы срок, выбранный для конкретного запроса (контекстом).
func TestNewWebClient_NoGlobalTimeout(t *testing.T) {
	c := newWebClient(1)
	if c.http.Timeout != 0 {
		t.Errorf("http.Client.Timeout = %v, ожидался 0 (срок задаётся на каждый запрос)", c.http.Timeout)
	}
}

// TestServerRoleStart_SlowerThanOldFiveSecondLimit_Succeeds — воспроизведение самого
// инцидента: служба отвечает на server-role/start за 5.5 с (дольше прежнего лимита 5 с).
// До исправления вызов падал с «context deadline exceeded», теперь обязан дождаться ответа.
func TestServerRoleStart_SlowerThanOldFiveSecondLimit_Succeeds(t *testing.T) {
	dir := withTempDataDir(t)
	writeToken(t, dir, "tok")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/server-role/start" {
			http.NotFound(w, r)
			return
		}
		time.Sleep(5500 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newWebClient(testPort(t, srv))
	start := time.Now()
	if err := c.ServerRoleStart(map[string]interface{}{"uuid": "x"}, 8443, ""); err != nil {
		t.Fatalf("ServerRoleStart на медленной (5.5 с) службе вернул ошибку: %v", err)
	}
	if d := time.Since(start); d < 5*time.Second {
		t.Fatalf("тест не воспроизводит медленный ответ: вызов занял всего %v", d)
	}
}

// TestGetState_HungService_FailsFast — обратная сторона: обычный опрос состояния не должен
// ждать долго (иначе зависшая служба вешает интерфейс на минуту).
func TestGetState_HungService_FailsFast(t *testing.T) {
	dir := withTempDataDir(t)
	writeToken(t, dir, "tok")
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	c := newWebClient(testPort(t, srv))
	start := time.Now()
	c.GetState()
	if d := time.Since(start); d > timeoutPoll+2*time.Second {
		t.Fatalf("GetState на зависшей службе ждал %v, ожидалось около %v", d, timeoutPoll)
	}
}
