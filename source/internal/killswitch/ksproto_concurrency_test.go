package killswitch

// ksproto_concurrency_test.go — целевой стресс-тест для dispatchMu (см. её комментарий
// в ksproto.go): живой инцидент 2026-08-19 — несколько ПАРАЛЛЕЛЬНЫХ named-pipe
// соединений от engine (быстрые повторные Reload/reconnect на нестабильном узле) били
// в ОДИН И ТОТ ЖЕ разделяемый ksExecutor без синхронизации между собой, и порядок
// netsh-команд между двумя параллельными Enable() непредсказуемо чередовался.
//
// fakeExec (ksproto_test.go) НЕ имеет собственной блокировки — её поля (enabled и т.п.)
// защищены ИСКЛЮЧИТЕЛЬНО тем, что serveConn берёт dispatchMu на всё тело Dispatch. Если
// бы dispatchMu отсутствовала или была снята преждевременно, `go test -race` поймал бы
// гонку на fakeExec.enabled при параллельных ServeConn — то есть сам факт зелёного -race
// здесь — прямая проверка требования "Dispatch — под dispatchMu" из комментария ksproto.go.

import (
	"net"
	"sync"
	"testing"
	"time"
)

// TestDispatch_ConcurrentServeConn_NoRaceOnSharedExecutor гоняет много параллельных
// pipe-соединений (как maxPipeConns в kspipe_windows.go) против ОДНОГО общего
// исполнителя и чередует Enable/Disable/Status. Под -race любое чтение/запись
// f.enabled вне dispatchMu было бы поймано.
func TestDispatch_ConcurrentServeConn_NoRaceOnSharedExecutor(t *testing.T) {
	shared := &fakeExec{}

	const clients = 16
	const roundsPerClient = 25
	var wg sync.WaitGroup
	wg.Add(clients)

	for i := 0; i < clients; i++ {
		go func(id int) {
			defer wg.Done()
			for r := 0; r < roundsPerClient; r++ {
				op := OpEnable
				switch r % 3 {
				case 1:
					op = OpDisable
				case 2:
					op = OpStatus
				}
				cli, srv := net.Pipe()
				done := make(chan struct{})
				go func() {
					_ = ServeConn(srv, shared)
					srv.Close()
					close(done)
				}()
				_ = cli.SetDeadline(time.Now().Add(3 * time.Second))
				_, _ = sendRequest(cli, Request{Op: op, VPNIP: "1.2.3.4", Tun: "apf0"})
				cli.Close()
				<-done
			}
		}(i)
	}

	wg.Wait()
	// Дошли без находки -race → dispatchMu действительно сериализует Dispatch между
	// параллельными соединениями, как и требует её контракт в ksproto.go.
}

// TestDispatch_ConcurrentEnable_LeavesConsistentFinalState — после серии параллельных
// Enable-запросов над общим исполнителем, финальное состояние обязано быть тем, что
// вернул ПОСЛЕДНИЙ реально выполненный Dispatch (сериализованный dispatchMu), а не
// каким-то промежуточным чередованием: IsEnabled() должно совпадать с ok/err последнего
// по времени завершения ответа.
func TestDispatch_ConcurrentEnable_LeavesConsistentFinalState(t *testing.T) {
	shared := &fakeExec{}
	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			cli, srv := net.Pipe()
			done := make(chan struct{})
			go func() { _ = ServeConn(srv, shared); srv.Close(); close(done) }()
			_ = cli.SetDeadline(time.Now().Add(3 * time.Second))
			_, _ = sendRequest(cli, Request{Op: OpEnable, VPNIP: "1.2.3.4"})
			cli.Close()
			<-done
		}()
	}
	wg.Wait()

	// Все запросы были Enable без failEnable → в конце обязано быть enabled=true,
	// независимо от порядка чередования (не должно "потеряться" из-за гонки).
	if !shared.IsEnabled() {
		t.Error("после серии параллельных успешных Enable() исполнитель должен быть enabled=true")
	}
}
