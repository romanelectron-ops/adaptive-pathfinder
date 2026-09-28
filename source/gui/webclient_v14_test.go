package main

// S-2 (ТЗ v1.4, лот L1b-CLI): gui/webclient.go — единственный не-браузерный HTTP-клиент к
// /api/* в проекте (72 вхождения getJSON/postJSON). После лота L1-WEB (server.go) ВСЕ /api/*
// требуют Authorization: Bearer <token> либо cookie apf_ui. До этой правки клиент не слал ни
// то, ни другое — получал бы 401 на каждый вызов сразу после пересборки/перезапуска
// процесса-владельца (см. token_contract, AGENTS/L1-WEB/result.json).
//
// TestPre_S2_* воспроизводит дефект живым прогоном против сервера-заглушки, требующего
// заголовок — красный ДО фикса (getJSON не посылал Authorization).

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/config"
)

// testPort — извлекает числовой порт из httptest.Server (слушает 127.0.0.1:<port>).
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

// withTempDataDir — S-2 тесты читают webui_token из config.DataDir(); подменяем на временный
// каталог швом config.SetDataDirOverride (см. internal/config/config.go), чтобы не трогать
// реальный %APPDATA%\APF машины (правило лота).
func withTempDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	config.SetDataDirOverride(dir)
	t.Cleanup(func() { config.SetDataDirOverride("") })
	return dir
}

func writeToken(t *testing.T, dir, token string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "webui_token"), []byte(token), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
}

// TestPre_S2_NoAuthorizationHeader_Vulnerability — дефект: getJSON не читал файл токена и не
// слал Authorization ни на один запрос. Сервер-заглушка отвечает 401 без заголовка — до фикса
// getJSON().err != nil на КАЖДЫЙ вызов, что и требовалось показать (не столько сам факт
// ошибки, сколько её причина — см. проверку заголовка ниже).
func TestPre_S2_NoAuthorizationHeader_Vulnerability(t *testing.T) {
	dir := withTempDataDir(t)
	writeToken(t, dir, "secret-token")

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if gotAuth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	c := newWebClient(testPort(t, srv))
	var out map[string]string
	if err := c.getJSON("/api/state", &out); err != nil {
		t.Fatalf("getJSON: %v (Authorization отправлен как %q)", err, gotAuth)
	}
	if gotAuth != "Bearer secret-token" {
		t.Fatalf("Authorization = %q, ожидалось \"Bearer secret-token\" — токен-файл не читается", gotAuth)
	}
}

// TestS2_PostJSON_SendsAuthorization — то же для postJSON (второй из двух центральных методов).
func TestS2_PostJSON_SendsAuthorization(t *testing.T) {
	dir := withTempDataDir(t)
	writeToken(t, dir, "tok-post")

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if gotAuth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	c := newWebClient(testPort(t, srv))
	var out map[string]string
	if err := c.postJSON("/api/connect", nil, &out); err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if gotAuth != "Bearer tok-post" {
		t.Fatalf("Authorization = %q, ожидалось \"Bearer tok-post\"", gotAuth)
	}
}

// TestS2_ExportLogBytes_SendsAuthorization — единственный метод, который раньше обходил
// getJSON/postJSON (голый c.http.Get).
func TestS2_ExportLogBytes_SendsAuthorization(t *testing.T) {
	dir := withTempDataDir(t)
	writeToken(t, dir, "tok-export")

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if gotAuth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte("log contents"))
	}))
	defer srv.Close()

	c := newWebClient(testPort(t, srv))
	data, err := c.ExportLogBytes()
	if err != nil {
		t.Fatalf("ExportLogBytes: %v", err)
	}
	if string(data) != "log contents" {
		t.Fatalf("unexpected body: %q", data)
	}
	if gotAuth != "Bearer tok-export" {
		t.Fatalf("Authorization = %q, ожидалось \"Bearer tok-export\"", gotAuth)
	}
}

// TestS2_Retry401_RereadsTokenFile — служба-владелец перезапустилась с новым токеном (токен
// НЕ персистентен между перезапусками, см. token_contract). Клиент с УСТАРЕВШИМ кэшем обязан
// перечитать файл и повторить запрос ровно один раз, не сдаваться сразу на первом 401.
func TestS2_Retry401_RereadsTokenFile(t *testing.T) {
	dir := withTempDataDir(t)
	writeToken(t, dir, "new-token")

	var attempts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		attempts = append(attempts, auth)
		if auth != "Bearer new-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	c := newWebClient(testPort(t, srv))
	c.token = "stale-token" // симулируем кэш от предыдущего запуска процесса-владельца

	var out map[string]string
	if err := c.getJSON("/api/state", &out); err != nil {
		t.Fatalf("запрос не восстановился после 401 перечитыванием токена: %v", err)
	}
	if len(attempts) != 2 || attempts[0] != "Bearer stale-token" || attempts[1] != "Bearer new-token" {
		t.Fatalf("ожидались попытки [Bearer stale-token, Bearer new-token], получено %v", attempts)
	}
}

// TestS2_Retry401_GivesUpAfterOneRetry — файл токена сам недоступен/тоже устарел: клиент не
// должен зациклиться, ровно одна повторная попытка и явная ошибка/401 наружу.
func TestS2_Retry401_GivesUpAfterOneRetry(t *testing.T) {
	dir := withTempDataDir(t)
	writeToken(t, dir, "still-wrong")

	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newWebClient(testPort(t, srv))
	var out map[string]string
	err := c.getJSON("/api/state", &out)
	if err == nil {
		t.Fatalf("ожидалась ошибка декодирования пустого 401-тела, получен nil")
	}
	if calls != 2 {
		t.Fatalf("ожидалось ровно 2 попытки (исходная + один retry), получено %d", calls)
	}
}

// TestS2_Handoff_ReturnsUIURLWithKey — S-2 п.4: Handoff() бьёт в POST /api/ui/handoff под
// токеном и возвращает ".../ui?k=<k>", НЕ содержащий сам постоянный токен.
func TestS2_Handoff_ReturnsUIURLWithKey(t *testing.T) {
	dir := withTempDataDir(t)
	writeToken(t, dir, "permanent-secret")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ui/handoff" || r.Method != http.MethodPost {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer permanent-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"k": "onetimekey123"})
	}))
	defer srv.Close()

	port := testPort(t, srv)
	c := newWebClient(port)
	url, err := c.Handoff()
	if err != nil {
		t.Fatalf("Handoff: %v", err)
	}
	want := fmt.Sprintf("http://127.0.0.1:%d/ui?k=onetimekey123", port)
	if url != want {
		t.Fatalf("url = %q, want %q", url, want)
	}
	if strings.Contains(url, "permanent-secret") {
		t.Fatalf("постоянный токен не должен попадать в URL: %q", url)
	}
}

// TestS2_Handoff_ServerError_PropagatesError — сервер отдал {"error": "..."} — Handoff должен
// вернуть ошибку, а не пустой/битый URL.
func TestS2_Handoff_ServerError_PropagatesError(t *testing.T) {
	dir := withTempDataDir(t)
	writeToken(t, dir, "tok")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "handoff key generation failed"})
	}))
	defer srv.Close()

	c := newWebClient(testPort(t, srv))
	if _, err := c.Handoff(); err == nil {
		t.Fatal("ожидалась ошибка при {\"error\":...} в ответе сервера")
	}
}

// TestS2_ReadWebUIToken_MissingFile_ReturnsError — стойкость: отсутствующий файл токена не
// паникует, а поведение как раньше — не смогли аутентифицироваться (сервер вернёт 401).
func TestS2_ReadWebUIToken_MissingFile_ReturnsError(t *testing.T) {
	withTempDataDir(t) // каталог есть, файла webui_token в нём нет
	if _, err := readWebUIToken(); err == nil {
		t.Fatal("ожидалась ошибка чтения отсутствующего файла токена")
	}
}
