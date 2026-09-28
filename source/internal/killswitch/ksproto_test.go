package killswitch

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// Я-31.4 (протокол/диспетчер) — round-trip через net.Pipe (без ОС-зависимостей).

type fakeExec struct {
	enabled    bool
	vpnIP      string
	failEnable bool
}

func (f *fakeExec) Enable(tun string, ports []int) error {
	if f.failEnable {
		f.enabled = false
		return errors.New("boom")
	}
	f.enabled = true
	return nil
}
func (f *fakeExec) Disable() error                     { f.enabled = false; return nil }
func (f *fakeExec) IsEnabled() bool                    { return f.enabled }
func (f *fakeExec) SetVPNEndpoint(ip string, port int) { f.vpnIP = ip }

// roundTrip прогоняет один запрос через ServeConn(server) + sendRequest(client) на net.Pipe.
func roundTrip(t *testing.T, ks ksExecutor, req Request) Response {
	t.Helper()
	cli, srv := net.Pipe()
	done := make(chan struct{})
	go func() { _ = ServeConn(srv, ks); srv.Close(); close(done) }()
	_ = cli.SetDeadline(time.Now().Add(3 * time.Second))
	resp, err := sendRequest(cli, req)
	cli.Close()
	<-done
	if err != nil {
		t.Fatalf("sendRequest(%s): %v", req.Op, err)
	}
	return resp
}

// (Позитив) enable → OK, enabled=true, vpnIP проброшен через SetVPNEndpoint.
func TestKSProto_Enable(t *testing.T) {
	f := &fakeExec{}
	resp := roundTrip(t, f, Request{Op: OpEnable, VPNIP: "1.2.3.4", Tun: "apf0", Ports: []int{1080}})
	if !resp.OK || !resp.Enabled {
		t.Errorf("enable resp = %+v, want OK+Enabled", resp)
	}
	if !f.enabled {
		t.Error("executor not enabled")
	}
	if f.vpnIP != "1.2.3.4" {
		t.Errorf("vpnIP=%q want 1.2.3.4 (SetVPNEndpoint not called)", f.vpnIP)
	}
}

// (Позитив) disable → OK, enabled=false.
func TestKSProto_Disable(t *testing.T) {
	f := &fakeExec{enabled: true}
	resp := roundTrip(t, f, Request{Op: OpDisable})
	if !resp.OK || resp.Enabled {
		t.Errorf("disable resp = %+v, want OK & !Enabled", resp)
	}
	if f.enabled {
		t.Error("executor still enabled")
	}
}

// (Позитив) status → отражает состояние.
func TestKSProto_Status(t *testing.T) {
	f := &fakeExec{enabled: true}
	resp := roundTrip(t, f, Request{Op: OpStatus})
	if !resp.OK || !resp.Enabled {
		t.Errorf("status resp = %+v, want OK+Enabled", resp)
	}
}

// (Recover) recover → OK, Recovered отражает recoverFn.
func TestKSProto_Recover(t *testing.T) {
	orig := recoverFn
	defer func() { recoverFn = orig }()
	recoverFn = func() bool { return true }

	f := &fakeExec{}
	resp := roundTrip(t, f, Request{Op: OpRecover})
	if !resp.OK || !resp.Recovered {
		t.Errorf("recover resp = %+v, want OK+Recovered", resp)
	}
}

// (Негатив) неизвестный op → OK=false, error содержит "unknown op".
func TestKSProto_UnknownOp(t *testing.T) {
	f := &fakeExec{}
	resp := roundTrip(t, f, Request{Op: "frobnicate"})
	if resp.OK {
		t.Error("unknown op must not be OK")
	}
	if !strings.Contains(resp.Error, "unknown op") {
		t.Errorf("error=%q want contains 'unknown op'", resp.Error)
	}
}

// (Fail-safe) сбой Enable → OK=false, error непуст, enabled=false.
func TestKSProto_EnableFailure(t *testing.T) {
	f := &fakeExec{failEnable: true}
	resp := roundTrip(t, f, Request{Op: OpEnable, VPNIP: "1.2.3.4"})
	if resp.OK {
		t.Error("failed enable must not be OK")
	}
	if resp.Error == "" {
		t.Error("expected non-empty error")
	}
	if resp.Enabled || f.enabled {
		t.Error("must not be enabled after failure")
	}
}

// (Стойкость) битый JSON на входе → ServeConn возвращает ошибку, не паникует.
func TestKSProto_ServeConn_BadJSON(t *testing.T) {
	cli, srv := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- ServeConn(srv, &fakeExec{}); srv.Close() }()
	_ = cli.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = cli.Write([]byte("{ this is not json ]"))
	cli.Close()
	if err := <-done; err == nil {
		t.Error("expected decode error for malformed JSON")
	}
}
