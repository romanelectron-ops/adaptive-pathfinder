// remote_target_test.go — ТЗ v1.3 F5.3: таблица заглушек → отказ; свои LAN/CGNAT/публичные → ок.
package netutil

import "testing"

func TestValidateRemoteTarget_Table(t *testing.T) {
	reject := []string{
		"example.com:8443", "vpn.example.com:443", "localhost:443", "127.0.0.1:443", "[::1]:443",
		"5.6.7.8:8443", "1.2.3.4:443", "0.0.0.0:443", "203.0.113.7:8443", "192.0.2.1:443",
		"198.51.100.5:443", "169.254.1.1:443", "host.test:443", "srv.invalid:443", "nas.local:443",
		"your-server:443", "10.0.0.1", "10.0.0.1:0", "10.0.0.1:70000", "", ":443", "a b:443",
	}
	for _, in := range reject {
		if err := ValidateRemoteTarget(in); err == nil {
			t.Errorf("%q должен отвергаться", in)
		}
	}
	accept := []string{
		"192.168.1.10:8443", "10.8.0.1:443", "172.16.5.5:443", "100.64.1.2:443", // RFC1918/CGNAT — свои серверы
		"1.1.1.1:443", "9.9.9.9:443", "vpn.mydomain.ru:443", "myhost:443", "[2a02:6b8::1]:443",
		"  8.8.8.8:53  ",
	}
	for _, in := range accept {
		if err := ValidateRemoteTarget(in); err != nil {
			t.Errorf("%q должен приниматься: %v", in, err)
		}
	}
}

func TestValidateRemoteHost(t *testing.T) {
	if err := ValidateRemoteHost("worker.example.workers.dev"); err == nil {
		t.Error("*.example.* — заглушка")
	}
	if err := ValidateRemoteHost("my-worker.workers.dev"); err != nil {
		t.Errorf("настоящий домен воркера: %v", err)
	}
	if err := ValidateRemoteHost("192.168.0.5"); err != nil {
		t.Errorf("LAN-хост без порта: %v", err)
	}
}
