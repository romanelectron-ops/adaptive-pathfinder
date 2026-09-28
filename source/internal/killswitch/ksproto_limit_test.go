package killswitch

// ksproto_limit_test.go — P5 (аудит BLACKBOX_2026-09-07, находка A3 F-5):
// `json.NewDecoder(conn).Decode` в serveConn читал тело запроса БЕЗ ограничения размера и
// ДО авторизации клиента. Именованный канал `\\.\pipe\APF-KS` обслуживается процессом
// службы под SYSTEM: любой, кто вправе открыть пайп, мог до всякой проверки личности
// заставить службу аллоцировать сколько угодно памяти одним бесконечным потоком байт
// (предаутентификационный memory-DoS процесса SYSTEM).
//
// Порядок «сначала Decode, потом authorize» изменить нельзя — он продиктован транспортом
// (контекст безопасности клиента named pipe устанавливается только после того, как клиент
// что-то записал; см. doc-comment serveConn и TestServeConn_MalformedRequestNotReportedAsAccessDenied).
// Поэтому инвариант формулируется через ОБЪЁМ: сколько бы неавторизованный клиент ни слал,
// сервер обязан вычитать ограниченное число байт и оборвать обмен внятной ошибкой.

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// preAuthReadBudget — сколько байт до-авторизационного тела тест считает приемлемым.
// Заведомо больше любого разумного лимита протокола (команды KS — сотни байт) и заведомо
// меньше того, что успевает влить атакующий за секунду.
const preAuthReadBudget = 64 << 10

// probeOversizedRequest шлёт серверу НЕЗАВЕРШЁННЫЙ JSON, растущий до capBytes, и возвращает:
// сколько байт сервер реально вычитал, ответ сервера и был ли ответ вообще получен.
func probeOversizedRequest(t *testing.T, authorize func() error, capBytes int) (consumed int, resp Response, gotResp bool) {
	t.Helper()

	cli, srv := net.Pipe()
	served := make(chan struct{})
	go func() { _ = serveConn(srv, &fakeExec{}, authorize); srv.Close(); close(served) }()

	writtenCh := make(chan int, 1)
	go func() {
		n := 0
		_ = cli.SetWriteDeadline(time.Now().Add(15 * time.Second))
		// Объект открыт, строковое значение поля не закрывается никогда — Decode обязан
		// читать «ещё» до тех пор, пока ему это позволяют.
		k, err := cli.Write([]byte(`{"op":"status","tun":"`))
		n += k
		chunk := bytes.Repeat([]byte("A"), 4096)
		for err == nil && n < capBytes {
			k, err = cli.Write(chunk)
			n += k
		}
		writtenCh <- n
	}()

	_ = cli.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewDecoder(cli).Decode(&resp); err == nil {
		gotResp = true
	}
	cli.Close()
	consumed = <-writtenCh
	<-served
	return consumed, resp, gotResp
}

// Главный инвариант P5: поток произвольного размера не превращается в произвольный объём
// памяти сервера — сервер обрывает чтение на лимите и отвечает ошибкой размера.
func TestServeConn_PreAuthRequestSizeIsBounded(t *testing.T) {
	const capBytes = 1 << 20 // 1 МиБ — уже неприемлемо для протокола из коротких команд

	consumed, resp, gotResp := probeOversizedRequest(t, nil, capBytes)

	if !gotResp {
		t.Fatalf("сервер не ответил на переросший запрос: вычитано %d байт — ограничения размера нет", consumed)
	}
	if consumed >= preAuthReadBudget {
		t.Errorf("сервер вычитал %d байт (бюджет %d) — лимит либо отсутствует, либо непригодно велик",
			consumed, preAuthReadBudget)
	}
	if resp.OK {
		t.Error("переросший запрос обслужен как валидный")
	}
	if !strings.Contains(strings.ToLower(resp.Error), "too large") {
		t.Errorf("Error = %q — ожидалась внятная ошибка размера, а не общий сбой разбора", resp.Error)
	}
}

// Неавторизованный клиент не может заставить службу SYSTEM прочитать большое тело: отказ по
// размеру наступает РАНЬШЕ, чем дело доходит до авторизации (и до Dispatch).
func TestServeConn_UnauthorizedClientCannotForceUnboundedRead(t *testing.T) {
	const capBytes = 1 << 20

	authCalled := false
	consumed, resp, gotResp := probeOversizedRequest(t,
		func() error { authCalled = true; return errors.New("клиент из чужой сессии") }, capBytes)

	if !gotResp {
		t.Fatalf("сервер не ответил неавторизованному клиенту: вычитано %d байт", consumed)
	}
	if consumed >= preAuthReadBudget {
		t.Errorf("неавторизованный клиент заставил сервер вычитать %d байт (бюджет %d)",
			consumed, preAuthReadBudget)
	}
	if authCalled {
		t.Error("авторизация вызвана для запроса, который отвергнут по размеру — лишняя работа до отказа")
	}
	if resp.OK {
		t.Error("неавторизованный переросший запрос обслужен")
	}
}

// Обратная сторона лимита: он не должен резать ЛЕГИТИМНЫЙ максимум протокола. Собираем
// заведомо самый «толстый» законный запрос (длинное имя TUN, IPv6 в полной форме, большой
// список портов) и требуем, чтобы он исполнялся как прежде.
func TestServeConn_LegitimateMaximalRequestStillAccepted(t *testing.T) {
	ports := make([]int, 64)
	for i := range ports {
		ports[i] = 10000 + i
	}
	req := Request{
		Op:    OpEnable,
		VPNIP: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		Tun:   strings.Repeat("a", 256), // IFNAMSIZ/Windows-имена короче на порядок
		Port:  65535,
		Ports: ports,
		Full:  true,
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	t.Logf("самый «толстый» легитимный запрос: %d байт", len(raw))

	f := &fakeExec{}
	resp := roundTrip(t, f, req)
	if !resp.OK || !resp.Enabled {
		t.Fatalf("легитимный максимальный запрос отвергнут: %+v", resp)
	}
}
