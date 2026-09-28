package main

// S-2/S-8 (ТЗ v1.4, лот L1b-CLI).
//
// S-2: пункт меню «Открыть Web UI» (mWebUI.ClickedCh, S-2 п.4 ТЗ) раньше открывал голый
// "http://127.0.0.1:<port>" — после лота L1-WEB все /api/* требуют токен, встроенный JS
// страницы получал бы 401 на каждый fetch. TestPre_S2_* воспроизводит дефект: сервер требует
// handoff (POST /api/ui/handoff под Bearer-токеном), а до этой правки трей не читал файл
// токена и не делал такой запрос вовсе — красный сразу после появления requireAuth на сервере,
// до какой-либо правки этого файла.
//
// S-8: web.Server.Close() не вызывался владельцем — тест на инжектируемый шов
// stopProcess(webCloser, engineStopper), без реального трея/сети (правило лота).

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/config"
)

func withTempDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	config.SetDataDirOverride(dir)
	t.Cleanup(func() { config.SetDataDirOverride("") })
	return dir
}

func testPort(t *testing.T, srv *httptest.Server) int {
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

// TestPre_S2_ReadWebUIToken_MissingFile_Vulnerability — до фикса этого файла readWebUIToken
// не существовал вовсе (компиляция сама по себе была невозможна — тот же приём, что и в
// L1-WEB для полностью нового поведения). Здесь фиксируется контракт функции: отсутствующий
// файл — понятная ошибка, не паника/пустая строка молча.
func TestPre_S2_ReadWebUIToken_MissingFile_Vulnerability(t *testing.T) {
	withTempDataDir(t) // каталог есть, webui_token в нём нет
	if _, err := readWebUIToken(); err == nil {
		t.Fatal("ожидалась ошибка чтения отсутствующего файла токена")
	}
}

// TestS2_WebUIHandoffURL_ReadsTokenAndReturnsUIURLWithKey — центральный сценарий S-2 п.4:
// читает токен из файла, шлёт его в Authorization на POST /api/ui/handoff, возвращает
// ".../ui?k=<k>" БЕЗ постоянного токена в URL.
func TestS2_WebUIHandoffURL_ReadsTokenAndReturnsUIURLWithKey(t *testing.T) {
	dir := withTempDataDir(t)
	if err := os.WriteFile(filepath.Join(dir, "webui_token"), []byte("secret-token"), 0600); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ui/handoff" || r.Method != http.MethodPost {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer secret-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"k": "onetime456"})
	}))
	defer srv.Close()

	port := testPort(t, srv)
	base := "http://127.0.0.1:" + strconv.Itoa(port)
	url, err := webUIHandoffURL(&http.Client{Timeout: 5 * time.Second}, base)
	if err != nil {
		t.Fatalf("webUIHandoffURL: %v", err)
	}
	want := base + "/ui?k=onetime456"
	if url != want {
		t.Fatalf("url = %q, want %q", url, want)
	}
	if strings.Contains(url, "secret-token") {
		t.Fatalf("постоянный токен не должен попадать в URL: %q", url)
	}
}

// TestS2_WebUIHandoffURL_NoTokenFile_ReturnsError — стойкость: нет файла токена (Web UI ещё
// не поднялся/не успел его записать) — понятная ошибка, не панику и не запрос без заголовка.
func TestS2_WebUIHandoffURL_NoTokenFile_ReturnsError(t *testing.T) {
	withTempDataDir(t)
	if _, err := webUIHandoffURL(&http.Client{Timeout: time.Second}, "http://127.0.0.1:1"); err == nil {
		t.Fatal("ожидалась ошибка без файла токена")
	}
}

// TestS2_WebUIHandoffURL_ServerError_PropagatesError — сервер отдал {"error": "..."} —
// функция обязана вернуть ошибку, а не битый/пустой URL.
func TestS2_WebUIHandoffURL_ServerError_PropagatesError(t *testing.T) {
	dir := withTempDataDir(t)
	if err := os.WriteFile(filepath.Join(dir, "webui_token"), []byte("tok"), 0600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "handoff недоступен"})
	}))
	defer srv.Close()

	base := "http://127.0.0.1:" + strconv.Itoa(testPort(t, srv))
	if _, err := webUIHandoffURL(&http.Client{Timeout: 5 * time.Second}, base); err == nil {
		t.Fatal("ожидалась ошибка при {\"error\":...} в ответе сервера")
	}
}

// ─── S-8 ────────────────────────────────────────────────────────────────────────────────

type fakeWebCloser struct{ closed bool }

func (f *fakeWebCloser) Close() { f.closed = true }

type fakeEngineStopper struct{ stopped bool }

func (f *fakeEngineStopper) Stop() { f.stopped = true }

// TestS8_StopProcess_ClosesWebThenStopsEngine — путь остановки (onExit/mQuit, через
// stopOwnedProcess) обязан звать web.Server.Close() и engine.Stop().
func TestS8_StopProcess_ClosesWebThenStopsEngine(t *testing.T) {
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

func TestS8_StopProcess_NilSafe(t *testing.T) {
	stopProcess(nil, nil) // не должен паниковать (наблюдатель — ни eng, ни web.Server)
}

// TestS8_StopOwnedProcess_ObserverMode_NilSafe — трей-наблюдатель: apfEngine==nil,
// apfWebSrv никогда не Store() (см. startAPF: горутина Web UI не запускается в этой ветке) —
// stopOwnedProcess не должен паниковать при выходе.
func TestS8_StopOwnedProcess_ObserverMode_NilSafe(t *testing.T) {
	apfEngine = nil
	stopOwnedProcess()
}
