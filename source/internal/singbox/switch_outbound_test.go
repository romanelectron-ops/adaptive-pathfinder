package singbox

// Тесты Process.SwitchOutbound (TZ_SINGBOX_HOTSWITCH_WINDOWS_v1.0) — горячее переключение
// активного узла уже запущенной группы-селектора (BuildPool) через Clash API, без Stop/Start.
// Цель метода: убрать пересоздание процесса sing-box.exe на КАЖДОЕ переключение на Windows
// (нет SIGHUP там) — на реальной машине пользователя это давало задержки 20-68с ~12 раз за
// сессию (см. RCA «5 почему» в самом ТЗ).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Метод обязан отказать СРАЗУ, не отправляя ни одного запроса в сеть, если процесс не
// запущен — переключать нечего.
func TestSwitchOutbound_FailsWhenNotRunning(t *testing.T) {
	p := &Process{running: false, controllerAddr: "127.0.0.1:1"}
	err := p.SwitchOutbound(context.Background(), "proxy", "pool-1")
	if err == nil {
		t.Fatal("процесс не запущен, а SwitchOutbound вернул успех")
	}
	if !strings.Contains(err.Error(), "не запущен") {
		t.Errorf("сообщение не называет причину: %v", err)
	}
}

// Метод обязан отказать СРАЗУ, если текущий конфиг не объявлял clash_api — иначе запрос
// ушёл бы в никуда (пустой адрес), и ошибка была бы куда менее понятной.
func TestSwitchOutbound_FailsWhenControllerNotConfigured(t *testing.T) {
	p := &Process{running: true, controllerAddr: ""}
	err := p.SwitchOutbound(context.Background(), "proxy", "pool-1")
	if err == nil {
		t.Fatal("clash_api не объявлен, а SwitchOutbound вернул успех")
	}
	if !strings.Contains(err.Error(), "clash_api") {
		t.Errorf("сообщение не называет причину: %v", err)
	}
}

// Отменённый контекст обязан остановить попытку до сетевого запроса.
func TestSwitchOutbound_FailsOnCancelledContext(t *testing.T) {
	p := &Process{running: true, controllerAddr: "127.0.0.1:1"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.SwitchOutbound(ctx, "proxy", "pool-1"); err == nil {
		t.Fatal("контекст отменён, а SwitchOutbound вернул успех")
	}
}

// Основной сценарий: реальный HTTP-раунд-трип (httptest.Server, не фейк транспорта) —
// проверяем метод/путь/тело запроса и то, что успешный ответ 204 не считается ошибкой.
func TestSwitchOutbound_SendsCorrectPUTRequest(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	p := &Process{running: true, controllerAddr: strings.TrimPrefix(srv.URL, "http://")}
	if err := p.SwitchOutbound(context.Background(), "proxy", "pool-3"); err != nil {
		t.Fatalf("SwitchOutbound: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("метод = %q, ожидался PUT (тот же, что реально поддерживает sing-box, см. "+
			"vendor/.../clashapi/proxies.go updateProxy)", gotMethod)
	}
	if gotPath != "/proxies/proxy" {
		t.Errorf("путь = %q, ожидался /proxies/proxy (тег группы-селектора)", gotPath)
	}
	if gotBody["name"] != "pool-3" {
		t.Errorf("тело запроса name = %q, ожидался pool-3", gotBody["name"])
	}
}

// Clash API отказывает (например, тега pool-99 нет в текущей группе — sing-box возвращает
// 400 "Selector update error: not found", vendor/.../clashapi/proxies.go:178-182) —
// SwitchOutbound обязан вернуть ошибку, а не молча считать переключение успешным.
func TestSwitchOutbound_PropagatesServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"Selector update error: not found"}`))
	}))
	defer srv.Close()

	p := &Process{running: true, controllerAddr: strings.TrimPrefix(srv.URL, "http://")}
	err := p.SwitchOutbound(context.Background(), "proxy", "pool-99")
	if err == nil {
		t.Fatal("сервер отказал 400, а SwitchOutbound вернул успех")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("причина отказа сервера потеряна: %v", err)
	}
}

// Недоступный контроллер (процесс не поднял clash_api, либо уже умер) — сетевая ошибка,
// не паника и не «тихий успех».
func TestSwitchOutbound_FailsWhenControllerUnreachable(t *testing.T) {
	restore := switchTimeout
	switchTimeout = 200 * time.Millisecond
	defer func() { switchTimeout = restore }()

	// Порт заведомо закрыт — тот же приём, что у awaitReady-тестов (readyPort: 1).
	p := &Process{running: true, controllerAddr: "127.0.0.1:1"}
	if err := p.SwitchOutbound(context.Background(), "proxy", "pool-1"); err == nil {
		t.Fatal("контроллер недоступен, а SwitchOutbound вернул успех")
	}
}
