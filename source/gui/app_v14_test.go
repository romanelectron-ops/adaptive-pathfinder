package main

// S-8/S-2 (ТЗ v1.4, лот L1b-CLI).
//
// S-8: web.Server.Close() (K2-W) не вызывался ни одним владельцем процесса. gui/app.go —
// шов stopProcess(webCloser, engineStopper), используемый из shutdown(). Проверяется сама
// функция-шов (реального web.Server/Wails-окна тесту не поднять — правило лота: бинарники не
// запускать) — без неё до этой правки shutdown() звал только a.engine.Stop() напрямую.
//
// S-2: App.OpenWebUI() — обе проверяемые здесь ветки (нет remote; handoff вернул ошибку)
// возвращаются ДО wailsruntime.BrowserOpenURL. Успешная ветка не тестируется юнит-тестом: сам
// wails runtime (getFrontend, pkg/runtime/runtime.go) при отсутствии реального контекста
// Wails-приложения делает log.Fatalf → os.Exit(1) — вызвать её в `go test` означало бы убить
// тестовый процесс целиком (задокументировано в assumptions result.json).

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/config"
)

type fakeWebCloser struct{ closed bool }

func (f *fakeWebCloser) Close() { f.closed = true }

type fakeEngineStopper struct{ stopped bool }

func (f *fakeEngineStopper) Stop() { f.stopped = true }

// TestStopProcess_ClosesWebThenStopsEngine — S-8: путь остановки обязан звать web.Server.Close()
// (шов webCloser) и engine.Stop() (шов engineStopper).
func TestStopProcess_ClosesWebThenStopsEngine(t *testing.T) {
	fc := &fakeWebCloser{}
	fe := &fakeEngineStopper{}
	stopProcess(fc, fe)
	if !fc.closed {
		t.Fatal("stopProcess не вызвал web.Server.Close()")
	}
	if !fe.stopped {
		t.Fatal("stopProcess не вызвал engine.Stop()")
	}
}

// TestStopProcess_NilSafe — нет web.Server (типичный случай для GUI, см. App.webSrv) — не
// должно панковать, engine всё равно останавливается.
func TestStopProcess_NilSafe(t *testing.T) {
	fe := &fakeEngineStopper{}
	stopProcess(nil, fe)
	if !fe.stopped {
		t.Fatal("stopProcess(nil, eng) должен всё равно остановить движок")
	}
	stopProcess(nil, nil) // не должен паниковать вовсе
}

func testPortApp(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host:port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return port
}

// TestOpenWebUI_OwnerMode_NoRemote_ReturnsClearError — владелец (a.engine != nil, a.remote ==
// nil) не имеет собственного web.Server — открывать нечего, явная ошибка вместо тихого no-op.
func TestOpenWebUI_OwnerMode_NoRemote_ReturnsClearError(t *testing.T) {
	a := &App{}
	if err := a.OpenWebUI(); err == nil {
		t.Fatal("ожидалась ошибка при a.remote == nil")
	}
}

// TestOpenWebUI_ObserverMode_HandoffFails_ReturnsWrappedError — наблюдатель есть, но handoff
// не удался (сервер вернул ошибку) — OpenWebUI обязан вернуть ошибку, не паниковать и НЕ
// доходить до wailsruntime.BrowserOpenURL (см. пояснение вверху файла).
func TestOpenWebUI_ObserverMode_HandoffFails_ReturnsWrappedError(t *testing.T) {
	dir := t.TempDir()
	config.SetDataDirOverride(dir)
	defer config.SetDataDirOverride("")
	if err := os.WriteFile(filepath.Join(dir, "webui_token"), []byte("tok"), 0600); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "handoff недоступен"})
	}))
	defer srv.Close()

	a := &App{remote: newWebClient(testPortApp(t, srv))}
	if err := a.OpenWebUI(); err == nil {
		t.Fatal("ожидалась ошибка при неудачном handoff")
	}
}
