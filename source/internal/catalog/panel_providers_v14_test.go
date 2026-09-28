// panel_providers_v14_test.go — ТЗ v1.4, S-12 (лот L1-PAN).
//
// Проблема (см. TZ_APF_v1.4_FINAL.md §S-12, консилиум O-4): panel_providers.go читает тела
// ответов панелей провайдеров тремя местами (:80 3x-ui, :145 marzban token, :170 marzban
// inbounds) через "body, _ := io.ReadAll(resp.Body)" — без ограничения размера и с
// проглоченной ошибкой чтения. Образец правильного кода в этом же файле — HiddifyProvider.Fetch
// (:253): "io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))" с необёрнутой проверкой err.
//
// Тесты ниже:
//  1. TestV14_S12_*_ReadErrorNotSwallowed — соединение обрывается посреди тела ответа. ДО
//     фикса код проглатывает ошибку чтения (`_`) и падает позже на "...: parse: ..." (или,
//     реже, тихо пропускает битые данные) — то есть настоящая причина (обрыв соединения)
//     теряется. ПОСЛЕ фикса ошибка должна дойти до вызывающего с пометкой "read".
//  2. TestV14_S12_ThreeXUI_OversizedResponse_Truncated — единственный валидный JSON-документ
//     длиной >10 МиБ (закрывающие скобки идут ПОСЛЕ 10-мегабайтной отметки). ДО фикса
//     io.ReadAll читает весь ответ целиком → JSON валиден → Fetch завершается без ошибки
//     (что и есть путь к неограниченному потреблению памяти на реальном сервере). ПОСЛЕ
//     фикса io.LimitReader обрезает тело на 10 МиБ, JSON оказывается незакрытым → Fetch
//     возвращает ошибку разбора, не читая тело целиком.
//
// Ответ нужного размера отдаётся потоково (io.Writer в цикле с одним переиспользуемым
// буфером), без аллокации 10+ МБ в памяти самого теста — только сетевой трафик локального
// httptest.Server. Никакой реальной сети.
package catalog

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── помощники ──────────────────────────────────────────────────────────────

// hijackAndKill отдаёт заголовок с Content-Length больше, чем реально будет отправлено,
// пишет часть тела, затем обрывает TCP-соединение (Hijack+Close) без корректного закрытия
// потока. http.Client в такой ситуации возвращает ошибку чтения тела (несовпадение с
// объявленным Content-Length), а не тихо укороченный body.
func hijackAndKill(w http.ResponseWriter, sentPrefix string) {
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(sentPrefix)+4096))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(sentPrefix)); err != nil {
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	_ = conn.(*net.TCPConn)
	conn.Close()
}

// writeOversizedJSONArray пишет валидный JSON-документ вида
// {"<arrKey>":[{"<strKey>":"<totalBytes total длины поля>", ...остальные поля...}]}
// суммарной длиной БОЛЬШЕ totalBytes, где "лишний" объём находится в одном длинном строковом
// поле в середине документа — так что усечение на границе totalBytes рвёт документ ровно
// посреди строки (незакрытая кавычка), а полное чтение даёт корректный JSON.
// Пишется потоково через один переиспользуемый буфер, без выделения totalBytes целиком.
func writeOversizedJSONArray(w http.ResponseWriter, prefix, suffix string, paddingBytes int) {
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write([]byte(prefix)); err != nil {
		return
	}
	const chunkSize = 1 << 20 // 1 МиБ — переиспользуемый буфер, не 10+ МБ за раз
	chunk := make([]byte, chunkSize)
	for i := range chunk {
		chunk[i] = 'a'
	}
	remaining := paddingBytes
	for remaining > 0 {
		n := chunkSize
		if remaining < n {
			n = remaining
		}
		if _, err := w.Write(chunk[:n]); err != nil {
			return
		}
		remaining -= n
	}
	w.Write([]byte(suffix))
}

// ── S-12: ошибка чтения не должна проглатываться ────────────────────────────

func TestV14_S12_ThreeXUI_ReadErrorNotSwallowed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/panel/api/inbounds/list", func(w http.ResponseWriter, r *http.Request) {
		hijackAndKill(w, `{"obj":[`) // валидным JSON это не станет никогда
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := &ThreeXUIProvider{cfg: PaidProviderConfig{URL: srv.URL}, client: srv.Client()}
	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Fatal("обрыв соединения посреди тела должен вернуть ошибку, а не nil")
	}
	if !strings.Contains(err.Error(), "read") {
		t.Errorf("ошибка чтения не должна проглатываться и подменяться ошибкой разбора: получено %q", err.Error())
	}
}

func TestV14_S12_Marzban_TokenReadErrorNotSwallowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijackAndKill(w, `{"access_token":"ab`)
	}))
	defer srv.Close()

	p := &MarzbanProvider{cfg: PaidProviderConfig{URL: srv.URL, Username: "a", Password: "b"}, client: srv.Client()}
	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Fatal("обрыв соединения на этапе токена должен вернуть ошибку, а не nil")
	}
	if !strings.Contains(err.Error(), "read") {
		t.Errorf("ошибка чтения токена не должна проглатываться: получено %q", err.Error())
	}
}

func TestV14_S12_Marzban_InboundsReadErrorNotSwallowed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/token", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"tok"}`)
	})
	mux.HandleFunc("/api/inbounds", func(w http.ResponseWriter, r *http.Request) {
		hijackAndKill(w, `{"vless":[`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := &MarzbanProvider{cfg: PaidProviderConfig{URL: srv.URL, Username: "a", Password: "b"}, client: srv.Client()}
	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Fatal("обрыв соединения на этапе inbounds должен вернуть ошибку, а не nil")
	}
	if !strings.Contains(err.Error(), "read") {
		t.Errorf("ошибка чтения inbounds не должна проглатываться: получено %q", err.Error())
	}
}

// ── S-12: ответ без лимита размера ───────────────────────────────────────────

// TestV14_S12_ThreeXUI_OversizedResponse_Truncated — ответ >10 МиБ, единственный валидный
// JSON-документ. До фикса читается целиком и успешно разбирается (демонстрация
// неограниченного потребления памяти на проде). После фикса io.LimitReader(10 МиБ) обрезает
// тело до закрытия JSON, разбор проваливается.
func TestV14_S12_ThreeXUI_OversizedResponse_Truncated(t *testing.T) {
	const limit = 10 * 1024 * 1024
	prefix := `{"obj":[{"id":1,"remark":"`
	suffix := `","protocol":"vless","port":443,"enable":true,"settings":"{}","streamSettings":"{}"}]}`
	// Отступ в 2 МиБ от лимита гарантирует, что обрезка на границе лимита происходит
	// строго внутри длинной строки (до закрывающей кавычки), а не случайно рядом с ней.
	padding := limit + 2*1024*1024

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/panel/api/inbounds/list", func(w http.ResponseWriter, r *http.Request) {
		writeOversizedJSONArray(w, prefix, suffix, padding)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := &ThreeXUIProvider{cfg: PaidProviderConfig{URL: srv.URL}, client: srv.Client()}
	_, err := p.Fetch(context.Background())
	if err == nil {
		t.Fatal("ответ длиннее 10 МиБ должен приводить к ошибке разбора (тело обрезано лимитом), а не к успеху")
	}
	t.Logf("OK: %v", err)
}
