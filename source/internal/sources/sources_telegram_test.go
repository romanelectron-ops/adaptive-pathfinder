// sources_telegram_test.go — fetchTelegramChannel (источник узлов из публичной веб-версии
// t.me/s/<канал>, живой запрос пользователя 2026-08-28) до этого файла не имел НИ ОДНОГО
// теста, несмотря на нетривиальную логику: извлечение ссылок регуляркой из HTML вперемешку с
// разметкой, html.UnescapeString "&amp;" → "&" (без этого разбирается только первый query-
// параметр ссылки), дедуп повторов на странице, fail-safe к мусорным фрагментам. Пробел найден
// при сверке internal/sources/*.go с существующими *_test.go в рамках верификационного прогона.
package sources

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"context"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// Основной сценарий: ссылка внутри HTML-разметки канала, с "&amp;" между query-параметрами
// (именно так Telegram отдаёт HTML — раньше это резало запрос до первого параметра).
func TestFetchTelegramChannel_ExtractsAndUnescapesLinks(t *testing.T) {
	link := "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?type=tcp&amp;security=tls&amp;sni=example.com#node"
	page := `<div class="tgme_widget_message_text">Держите рабочий узел: ` + link + ` берите, пока не protухла</div>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(page))
	}))
	defer srv.Close()

	mgr := New(&models.AppConfig{})
	src := models.SourceConfig{ID: "tg-test", Name: "TG Test", URL: srv.URL, Type: "telegram"}
	nodes, err := mgr.fetchTelegramChannel(context.Background(), src)
	if err != nil {
		t.Fatalf("fetchTelegramChannel: unexpected error: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d: %+v", len(nodes), nodes)
	}
	n := nodes[0]
	if n.Protocol != models.ProtoVLESS || n.Address != "1.2.3.4" || n.Port != 443 {
		t.Errorf("узел разобран неверно: %+v", n)
	}
	// Второй "&amp;"-параметр (sni) — прямое доказательство, что unescape коснулся ВСЕХ
	// разделителей, а не только первого.
	if n.TLS == nil || !n.TLS.Enabled || n.TLS.ServerName != "example.com" {
		t.Errorf("TLS/SNI после второго &amp;-разделителя не распознан: %+v", n.TLS)
	}
	if n.Source != "tg-test" {
		t.Errorf("Source = %q, want tg-test (узлы канала должны быть помечены его ID)", n.Source)
	}
}

// Один и тот же узел, повторно упомянутый на странице канала (обычное дело — посты
// репостятся/закрепляются), не должен размножаться в пуле.
func TestFetchTelegramChannel_DeduplicatesRepeatedLinks(t *testing.T) {
	link := "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443#name"
	page := link + " и повтор той же ссылки в другом посте той же страницы: " + link
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(page))
	}))
	defer srv.Close()

	mgr := New(&models.AppConfig{})
	src := models.SourceConfig{ID: "tg-dup", URL: srv.URL, Type: "telegram"}
	nodes, err := mgr.fetchTelegramChannel(context.Background(), src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 1 {
		t.Errorf("одна и та же ссылка дважды на странице должна дать 1 узел, got %d", len(nodes))
	}
}

// Fail-safe (см. комментарий у fetchTelegramChannel в sources.go): фрагмент, который регулярка
// приняла за похожий на ссылку, но который parser.ParseLink реально не смог разобрать (битый
// base64 у vmess), не должен валить всю выгрузку источника — хорошая ссылка рядом всё равно
// должна дойти до пула.
func TestFetchTelegramChannel_UnparsableFragmentDoesNotBreakGoodOnes(t *testing.T) {
	good := "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443#ok"
	bad := "vmess://%%%not-valid-base64%%%" // base64.Decode гарантированно падает на "%"
	page := "пост с битой ссылкой: " + bad + " пост с рабочей: " + good
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(page))
	}))
	defer srv.Close()

	mgr := New(&models.AppConfig{})
	src := models.SourceConfig{ID: "tg-mixed", URL: srv.URL, Type: "telegram"}
	nodes, err := mgr.fetchTelegramChannel(context.Background(), src)
	if err != nil {
		t.Fatalf("битый фрагмент не должен приводить к ошибке всего источника: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected ровно 1 (только рабочая ссылка), got %d: %+v", len(nodes), nodes)
	}
	if nodes[0].Protocol != models.ProtoVLESS {
		t.Errorf("остался не тот узел: %+v", nodes[0])
	}
}

// Страница без единой ссылки протокола (обычный разговорный пост канала) — 0 узлов, без ошибки.
func TestFetchTelegramChannel_NoLinksOnPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html><body>сегодня без новых узлов, ждите вечером</body></html>"))
	}))
	defer srv.Close()

	mgr := New(&models.AppConfig{})
	src := models.SourceConfig{ID: "tg-empty", URL: srv.URL, Type: "telegram"}
	nodes, err := mgr.fetchTelegramChannel(context.Background(), src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(nodes))
	}
}

// Единственная фатальная ошибка источника — сам HTTP-запрос (недоступный канал/бан по гео и
// т.п.), а не содержимое страницы.
func TestFetchTelegramChannel_NonOKStatusIsFatal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()

	mgr := New(&models.AppConfig{})
	src := models.SourceConfig{ID: "tg-404", URL: srv.URL, Type: "telegram"}
	_, err := mgr.fetchTelegramChannel(context.Background(), src)
	if err == nil {
		t.Error("HTTP-ошибка канала (404) должна быть фатальной для источника")
	}
}

// fetchSource — общий диспетчер по SourceConfig.Type; убеждаемся, что "telegram" реально
// маршрутизируется в fetchTelegramChannel (а не проваливается в default/"unknown source type"
// — легко сломать при рефакторинге диспетчера, ошибка была бы тихой: источник просто
// переставал бы отдавать узлы).
func TestFetchTelegramChannel_ViaFetchSource_Dispatch(t *testing.T) {
	link := "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443#x"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(link))
	}))
	defer srv.Close()

	mgr := New(&models.AppConfig{})
	src := models.SourceConfig{ID: "tg-dispatch", URL: srv.URL, Type: "telegram"}
	nodes, err := mgr.fetchSource(context.Background(), src)
	if err != nil {
		t.Fatalf("fetchSource(telegram): %v", err)
	}
	if len(nodes) != 1 {
		t.Errorf("expected 1 node via fetchSource dispatch, got %d", len(nodes))
	}
}
