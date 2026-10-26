package singbox

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/localauth"
)

func TestQueryConnectionsCount_ParsesRealResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/connections" {
			t.Errorf("неожиданный путь запроса: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"downloadTotal": 1234,
			"uploadTotal": 5678,
			"connections": [
				{"id": "a", "metadata": {"sourceIP": "192.168.1.50"}},
				{"id": "b", "metadata": {"sourceIP": "10.0.0.7"}}
			]
		}`))
	}))
	defer srv.Close()

	port := srv.Listener.Addr().(*net.TCPAddr).Port
	snap, err := QueryConnectionsCount(port)
	if err != nil {
		t.Fatalf("QueryConnectionsCount: %v", err)
	}
	if snap.Count != 2 {
		t.Errorf("Count = %d, ожидалось 2", snap.Count)
	}
	if snap.LastRemote != "10.0.0.7" {
		t.Errorf("LastRemote = %q, ожидался IP последнего подключения (10.0.0.7)", snap.LastRemote)
	}
}

func TestQueryConnectionsCount_ZeroConnections(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"downloadTotal":0,"uploadTotal":0,"connections":[]}`))
	}))
	defer srv.Close()

	port := srv.Listener.Addr().(*net.TCPAddr).Port
	snap, err := QueryConnectionsCount(port)
	if err != nil {
		t.Fatalf("QueryConnectionsCount: %v", err)
	}
	if snap.Count != 0 {
		t.Errorf("Count = %d, ожидалось 0", snap.Count)
	}
	if snap.LastRemote != "" {
		t.Errorf("LastRemote = %q, ожидалась пустая строка при 0 соединений", snap.LastRemote)
	}
}

// Fail-safe: sing-box не запущен / порт закрыт — ошибка без паники, а не "0 подключений"
// (см. контракт QueryConnectionsCount и GetServerRoleStatus — эти два случая нельзя путать).
func TestQueryConnectionsCount_ConnectionRefused_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	srv.Close() // порт теперь точно закрыт

	_, err := QueryConnectionsCount(port)
	if err == nil {
		t.Fatal("ожидалась ошибка при недоступном clash-api, получен nil")
	}
}

func TestQueryConnectionsCount_HTTPErrorStatus_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	port := srv.Listener.Addr().(*net.TCPAddr).Port
	_, err := QueryConnectionsCount(port)
	if err == nil {
		t.Fatal("ожидалась ошибка при HTTP 500 от clash-api")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("ошибка должна упоминать код статуса, получено: %v", err)
	}
}

func TestQueryConnectionsCount_MalformedJSON_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("не json"))
	}))
	defer srv.Close()

	port := srv.Listener.Addr().(*net.TCPAddr).Port
	_, err := QueryConnectionsCount(port)
	if err == nil {
		t.Fatal("ожидалась ошибка при неразбираемом JSON")
	}
}

// Лот L4: Clash API роли «Выход» защищён секретом; опрос шлёт его в Authorization, без него сервер
// отвечает 401 и счётчик остаётся «неизвестно» (а не «0 подключений»).
func TestQueryConnectionsCount_SendsClashSecret(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if gotAuth != localauth.BearerHeader() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"connections":[{"id":"a","metadata":{"sourceIP":"192.0.2.9"}}]}`))
	}))
	defer srv.Close()

	port := srv.Listener.Addr().(*net.TCPAddr).Port
	snap, err := QueryConnectionsCount(port)
	if err != nil || snap.Count != 1 {
		t.Fatalf("snap=%+v err=%v (заголовок Authorization: %q)", snap, err, gotAuth)
	}
}

// Серверный конфиг роли «Выход» несёт тот же секрет, что и опрос.
func TestBuildServerConfig_ClashAPIHasSessionSecret(t *testing.T) {
	doc := BuildServerConfig(testIdentity(t), 8443, "example.org:443")
	if doc.Experimental == nil || doc.Experimental.ClashAPI == nil {
		t.Fatal("clash_api не объявлен")
	}
	if got := doc.Experimental.ClashAPI.Secret; got == "" || got != localauth.ClashSecret() {
		t.Errorf("secret = %q, ожидался секрет сессии", got)
	}
}
