// config_normalize_test.go — ТЗ v1.3 F5.2: таблица входов → дефолт + WARN; корректный конфиг
// не трогается и не даёт предупреждений.
package models

import (
	"strings"
	"testing"
)

func TestNormalize_ValidConfigUntouched(t *testing.T) {
	c := DefaultConfig()
	c.WebUIPort = 9090
	c.ListenPort = 10808
	before := *c
	warns := c.Normalize()
	if len(warns) != 0 {
		t.Fatalf("дефолтный конфиг не должен давать предупреждений: %v", warns)
	}
	if c.ListenPort != before.ListenPort || c.WebUIPort != before.WebUIPort || c.ConnectionMode != before.ConnectionMode {
		t.Errorf("дефолтный конфиг изменён: %+v", *c)
	}
}

// TestNormalize_NodeCheckTopN — режим «Все рабочие» (NodeCheckTopNAll) проходит нормализацию
// нетронутым и без WARN, тогда как любое ДРУГОЕ значение > 300 по-прежнему клампится к 300
// (сигналом «без ограничения» служит лишь точное совпадение, а не «больше 300 вообще»).
func TestNormalize_NodeCheckTopN(t *testing.T) {
	cases := []struct {
		name   string
		in     int
		want   int
		noWarn bool
	}{
		{"all-sentinel passes untouched", NodeCheckTopNAll, NodeCheckTopNAll, true},
		{"zero stays zero (engine default)", 0, 0, true},
		{"in-range untouched", 150, 150, true},
		{"below-10 clamps up", 5, 10, false},
		{"above-300 non-sentinel clamps down", 5000, 300, false},
		{"negative to zero", -1, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := DefaultConfig()
			c.NodeCheckTopN = tc.in
			warns := c.Normalize()
			if c.NodeCheckTopN != tc.want {
				t.Fatalf("node_check_top_n: in=%d got=%d want=%d", tc.in, c.NodeCheckTopN, tc.want)
			}
			hadTopNWarn := false
			for _, w := range warns {
				if strings.Contains(w, "node_check_top_n") {
					hadTopNWarn = true
				}
			}
			if tc.noWarn && hadTopNWarn {
				t.Fatalf("не ждали WARN про node_check_top_n для in=%d, получили: %v", tc.in, warns)
			}
			if !tc.noWarn && !hadTopNWarn {
				t.Fatalf("ждали WARN про node_check_top_n для in=%d, не было", tc.in)
			}
		})
	}
}

func TestNormalize_Table(t *testing.T) {
	d := DefaultConfig()
	c := DefaultConfig()
	c.ListenPort = 0
	c.WebUIPort = 70000
	c.CheckInterval = -1
	c.MaxLatency = 10
	c.MinUptimeSec = -5
	c.DNSLeakTestInterval = -1
	c.MultiHopCount = 7
	c.ConnectionMode = "vpn "
	c.SelectionMode = "auto"
	c.StickySessionPolicy = "x"
	c.AdBlockProfile = "STRICT"
	c.Mode = "weird"
	c.Sources = []SourceConfig{
		{ID: "ok", URL: " https://example.org/sub ", Enabled: true},
		{ID: "bad", URL: "ftp://x", Enabled: true},
		{ID: "noscheme", URL: "example.org/sub", Enabled: true},
		{ID: "off", URL: "garbage", Enabled: false},
		{ID: "tor", URL: "", Enabled: true, Type: "tor"},
	}
	warns := c.Normalize()

	if c.ListenPort != d.ListenPort || c.WebUIPort != d.WebUIPort || c.CheckInterval != d.CheckInterval || c.MaxLatency != d.MaxLatency {
		t.Errorf("порты/интервалы не откатились на дефолт: %+v", *c)
	}
	if c.MinUptimeSec != 0 || c.DNSLeakTestInterval != 0 || c.MultiHopCount != 2 {
		t.Errorf("отрицательные/недопустимые значения: uptime=%d dns=%d hops=%d", c.MinUptimeSec, c.DNSLeakTestInterval, c.MultiHopCount)
	}
	if c.ConnectionMode != ModeVPN {
		t.Errorf("connection_mode 'vpn ' → vpn, got %q", c.ConnectionMode)
	}
	if c.SelectionMode != "balanced" {
		t.Errorf("selection_mode auto → balanced, got %q", c.SelectionMode)
	}
	if c.StickySessionPolicy != "" {
		t.Errorf("sticky_session_policy x → \"\", got %q", c.StickySessionPolicy)
	}
	if c.AdBlockProfile != "strict" {
		t.Errorf("adblock_profile STRICT → strict, got %q", c.AdBlockProfile)
	}
	if c.Mode != d.Mode {
		t.Errorf("mode weird → %q, got %q", d.Mode, c.Mode)
	}
	if !c.Sources[0].Enabled || c.Sources[0].URL != "https://example.org/sub" {
		t.Errorf("корректный источник должен остаться включённым с trim: %+v", c.Sources[0])
	}
	if c.Sources[1].Enabled || c.Sources[2].Enabled {
		t.Errorf("источники с плохим URL должны выключаться: %+v %+v", c.Sources[1], c.Sources[2])
	}
	if !c.Sources[4].Enabled {
		t.Errorf("встроенный источник без URL не трогаем: %+v", c.Sources[4])
	}
	joined := strings.Join(warns, "\n")
	for _, want := range []string{"listen_port", "webui_port", "check_interval_sec", "max_latency_ms", "multihop_count",
		"sticky_session_policy", "sources[bad]", "sources[noscheme]"} {
		if !strings.Contains(joined, want) {
			t.Errorf("нет предупреждения про %s: %v", want, warns)
		}
	}
	// trim/lower и документированные алиасы (auto→balanced) — не предупреждение.
	if strings.Contains(joined, "connection_mode") || strings.Contains(joined, "adblock_profile") || strings.Contains(joined, "selection_mode") {
		t.Errorf("trim/lower/алиас — не предупреждение: %v", warns)
	}
	var nilCfg *AppConfig
	if nilCfg.Normalize() != nil {
		t.Error("nil-safe")
	}
}

func TestNormalize_WebUIPortZeroIsDisabled(t *testing.T) {
	c := DefaultConfig()
	c.WebUIPort = 0
	if warns := c.Normalize(); len(warns) != 0 || c.WebUIPort != 0 {
		t.Errorf("webui_port=0 (выключено) должен оставаться: %d %v", c.WebUIPort, warns)
	}
	c.WebUIPort = c.ListenPort
	if warns := c.Normalize(); c.WebUIPort == c.ListenPort || len(warns) == 0 {
		t.Errorf("webui_port==listen_port должен разводиться: %d %v", c.WebUIPort, warns)
	}
}
