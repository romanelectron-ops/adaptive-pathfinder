package singbox

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
