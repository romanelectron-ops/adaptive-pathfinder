//go:build windows

package killswitch

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// Я-31.4b — логика serviceClientKS через инжектируемый dialConnFn (net.Pipe + ServeConn).

// serveWith подключает клиента к in-memory серверу ServeConn(ks) и возвращает восстановитель шва.
func serveWith(t *testing.T, ks ksExecutor) func() {
	t.Helper()
	orig := dialConnFn
	dialConnFn = func(_ time.Duration) (io.ReadWriteCloser, error) {
		cli, srv := net.Pipe()
		go func() { _ = ServeConn(srv, ks); srv.Close() }()
		return cli, nil
	}
	return func() { dialConnFn = orig }
}

func TestServiceClient_EnableDisable(t *testing.T) {
	fake := &fakeExec{}
	restore := serveWith(t, fake)
	defer restore()

	c := &serviceClientKS{}
	c.SetVPNEndpoint("1.2.3.4", 1080)
	if err := c.Enable("apf0", []int{1080}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if !c.IsEnabled() || !fake.enabled {
		t.Error("client/executor should be enabled after Enable")
	}
	if fake.vpnIP != "1.2.3.4" {
		t.Errorf("vpnIP not propagated to service: %q", fake.vpnIP)
	}
	if err := c.Disable(); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if c.IsEnabled() || fake.enabled {
		t.Error("should be disabled after Disable")
	}
}

func TestServiceClient_EnableFailurePropagated(t *testing.T) {
	restore := serveWith(t, &fakeExec{failEnable: true})
	defer restore()

	c := &serviceClientKS{}
	if err := c.Enable("apf0", nil); err == nil {
		t.Error("expected error propagated from service on failed enable")
	}
	if c.IsEnabled() {
		t.Error("client must not report enabled after service failure")
	}
}

func TestServiceClient_DialUnavailable(t *testing.T) {
	orig := dialConnFn
	defer func() { dialConnFn = orig }()
	dialConnFn = func(_ time.Duration) (io.ReadWriteCloser, error) { return nil, ErrServiceUnavailable }

	c := &serviceClientKS{}
	if err := c.Enable("apf0", nil); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("expected ErrServiceUnavailable, got %v", err)
	}
}
