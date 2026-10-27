package engine

import "testing"

func TestRoutineSingBoxLine(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		// реальные формы из apf.log (с цветовыми кодами sing-box)
		{"[sing-box] \x1b[36mINFO\x1b[0m[0050] [\x1b[38;5;230m819748566\x1b[0m 387ms] inbound/tun[tun-in]: inbound connection to 203.0.113.7:7307", true},
		{"[sing-box] \x1b[36mINFO\x1b[0m[0050] [\x1b[38;5;121m3204374382\x1b[0m 0ms] inbound/tun[tun-in]: inbound connection from 172.19.0.1:49858", true},
		{"[sing-box] INFO[0050] [1 0ms] inbound/tun[tun-in]: inbound packet connection from [fdfe:dcba:9876::1]:61748", true},
		{"[sing-box] INFO[0050] [1 0ms] inbound/tun[tun-in]: inbound packet connection to [fdfe:dcba:9876::2]:53", true},
		{"[sing-box] INFO[0257] [1 0ms] dns: cached CNAME www.example.org. 15 IN CNAME x.example.net.", true},
		{"[sing-box] INFO[0001] [1 0ms] inbound/socks[socks-in]: inbound connection from 127.0.0.1:50000", true},
		// нужное остаётся
		{"[sing-box] INFO[0257] [1 99ms] outbound/shadowsocks[race-0]: outbound connection to 203.0.113.7:443", false},
		{"[sing-box] INFO[0257] [1 5ms] outbound/direct[direct]: outbound connection to 198.51.100.9:443", false},
		{"[sing-box] INFO[0257] [1 5ms] dns: exchanged A www.example.org. 15 IN A 203.0.113.9", false},
		{"[sing-box] ERROR[0012] [1 236ms] connection: report handshake success: connection reset by peer", false},
		{"[sing-box] WARN[0012] [1 0ms] inbound/tun[tun-in]: inbound connection from 172.19.0.1:1 dropped", false},
		// строки самого APF никогда не фильтруются
		{"Connected! SOCKS5→127.0.0.1:10808  HTTP→127.0.0.1:10809", false},
		{"Каталог: inbound connection from users", false},
	}
	for _, c := range cases {
		if got := routineSingBoxLine(c.msg); got != c.want {
			t.Errorf("routineSingBoxLine(%q) = %v, want %v", c.msg, got, c.want)
		}
	}
}

func TestKsOpTimeout(t *testing.T) {
	old := ksCallTimeout
	ksCallTimeout = 10
	defer func() { ksCallTimeout = old }()
	for _, op := range []string{"Reset", "QuickReset", "ResetAll"} {
		if got := ksOpTimeout(op); got != 10*ksResetTimeoutFactor {
			t.Errorf("ksOpTimeout(%q) = %v, want %v", op, got, 10*ksResetTimeoutFactor)
		}
	}
	for _, op := range []string{"Enable", "Disable", "EnsureTunPermit", "AllowProbeTargets", "SetVPNEndpoint"} {
		if got := ksOpTimeout(op); got != 10 {
			t.Errorf("ksOpTimeout(%q) = %v, want 10", op, got)
		}
	}
}
