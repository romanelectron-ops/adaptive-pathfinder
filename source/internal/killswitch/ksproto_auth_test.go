package killswitch

import (
	"errors"
	"net"
	"testing"
	"time"
)

// ─── B-0403 · R-5.2 (C-9) · авторизация на серверной стороне ─────────────────

// roundTripAuth — как roundTrip, но с проверкой авторизации на сервере.
func roundTripAuth(t *testing.T, ks ksExecutor, req Request, authorize func() error) Response {
	t.Helper()
	cli, srv := net.Pipe()
	done := make(chan struct{})
	go func() { _ = serveConn(srv, ks, authorize); srv.Close(); close(done) }()
	_ = cli.SetDeadline(time.Now().Add(3 * time.Second))
	resp, err := sendRequest(cli, req)
	cli.Close()
	<-done
	if err != nil {
		t.Fatalf("sendRequest(%s): %v", req.Op, err)
	}
	return resp
}

// Главный инвариант R-5.2: неавторизованный клиент не меняет состояние фаервола НИ ОДНОЙ командой.
func TestServeConn_UnauthorizedClientChangesNothing(t *testing.T) {
	for _, op := range []string{OpEnable, OpDisable, OpReset, OpRecover, OpEnsureTun} {
		t.Run(op, func(t *testing.T) {
			exec := &fakeExec{enabled: true}
			resp := roundTripAuth(t, exec, Request{Op: op, Tun: "apf0"},
				func() error {
					return errors.New("клиент из сессии 3 не владеет консолью")
				})

			if resp.OK {
				t.Fatalf("op %s исполнен для неавторизованного клиента", op)
			}
			if resp.Error != "access denied" {
				t.Errorf("Error = %q, want %q", resp.Error, "access denied")
			}
			// Состояние исполнителя не тронуто — значит Dispatch не вызывался.
			if !exec.enabled {
				t.Error("состояние исполнителя изменено вопреки отказу в доступе")
			}
		})
	}
}

// Отказ не должен рассказывать отвергнутому клиенту, ПОЧЕМУ отказано.
func TestServeConn_DenialLeaksNoDetails(t *testing.T) {
	resp := roundTripAuth(t, &fakeExec{}, Request{Op: OpStatus},
		func() error {
			return errors.New("клиент из сессии 3 не владеет консолью (активна 1)")
		})

	if resp.Error != "access denied" {
		t.Errorf("клиенту ушли подробности отказа: %q", resp.Error)
	}
}

func TestServeConn_AuthorizedClientIsServed(t *testing.T) {
	exec := &fakeExec{}
	resp := roundTripAuth(t, exec, Request{Op: OpEnable, Tun: "apf0"}, func() error { return nil })

	if !resp.OK || !resp.Enabled {
		t.Fatalf("авторизованный клиент не обслужен: %+v", resp)
	}
}

// Совместимость: ServeConn без авторизации ведёт себя как прежде (транспорт сам гарантирует своего).
func TestServeConn_NilAuthorizeKeepsOldBehaviour(t *testing.T) {
	exec := &fakeExec{}
	resp := roundTripAuth(t, exec, Request{Op: OpEnable, Tun: "apf0"}, nil)
	if !resp.OK {
		t.Fatalf("без авторизации запрос обязан исполняться: %+v", resp)
	}
}

// Битый запрос обрабатывается ДО авторизации: клиент получает внятную ошибку декодирования,
// а не «access denied», по которому невозможно понять, что случилось.
func TestServeConn_MalformedRequestNotReportedAsAccessDenied(t *testing.T) {
	cli, srv := net.Pipe()
	done := make(chan struct{})
	authorized := false
	go func() {
		_ = serveConn(srv, &fakeExec{}, func() error { authorized = true; return nil })
		srv.Close()
		close(done)
	}()
	_ = cli.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = cli.Write([]byte("это не json\n"))
	buf := make([]byte, 512)
	n, _ := cli.Read(buf)
	cli.Close()
	<-done

	if n == 0 {
		t.Fatal("сервер не ответил на битый запрос")
	}
	if authorized {
		t.Error("авторизация вызвана для запроса, который не удалось разобрать")
	}
}
