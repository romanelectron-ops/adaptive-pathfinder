package killswitch

import (
	"errors"
	"runtime"
	"testing"
)

// ─── B-0403 · R-1.1 · модель возможностей бэкенда ────────────────────────────

func TestCapabilities_SupportsMode(t *testing.T) {
	proxyOnly := Capabilities{ProxyMode: true}
	full := Capabilities{ProxyMode: true, TunMode: true}
	none := Capabilities{}

	cases := []struct {
		name string
		caps Capabilities
		mode string
		want bool
	}{
		// Суть C-1: netsh не умеет разрешать трафик по интерфейсу туннеля, поэтому в VPN- и
		// hybrid-режиме он не защищает, а полностью глушит связь. Гейт обязан это знать.
		{"netsh против vpn", proxyOnly, "vpn", false},
		{"netsh против hybrid", proxyOnly, "hybrid", false},
		{"netsh против proxy", proxyOnly, "proxy", true},
		{"netsh против пустого режима (=proxy)", proxyOnly, "", true},
		{"netsh против неизвестного режима (=proxy)", proxyOnly, "какой-то", true},

		{"WFP против vpn", full, "vpn", true},
		{"WFP против hybrid", full, "hybrid", true},
		{"WFP против proxy", full, "proxy", true},

		// noop-бэкенд (неподдерживаемая ОС) не защищает ничего и не должен притворяться.
		{"noop против proxy", none, "proxy", false},
		{"noop против vpn", none, "vpn", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.caps.SupportsMode(tc.mode); got != tc.want {
				t.Errorf("SupportsMode(%q) = %v, want %v", tc.mode, got, tc.want)
			}
		})
	}
}

// capsExec — исполнитель, умеющий декларировать возможности.
type capsExec struct {
	fakeExec
	caps Capabilities
}

func (c *capsExec) Capabilities() Capabilities { return c.caps }

// Fail-safe R-1.1: исполнитель, не умеющий декларировать возможности, трактуется
// консервативно. Обратное (считать его всемогущим) — это и есть C-1.
func TestExecutorCaps_ConservativeFallback(t *testing.T) {
	got := executorCaps(&fakeExec{})
	if !got.ProxyMode {
		t.Error("proxy-режим обязан считаться поддержанным: иначе KS не применится вообще нигде")
	}
	if got.TunMode {
		t.Error("TunMode за молчащий бэкенд заявлять нельзя — это разрешило бы KS там, где он не защищает")
	}
}

func TestExecutorCaps_UsesProviderWhenAvailable(t *testing.T) {
	want := Capabilities{ProxyMode: true, TunMode: true}
	if got := executorCaps(&capsExec{caps: want}); got != want {
		t.Errorf("executorCaps = %+v, want %+v", got, want)
	}
}

// OpCaps обязан отдавать возможности СЕРВЕРНОГО бэкенда: служба может быть поднята
// и с netsh, и с WFP (APF_KS_BACKEND), а клиент об этом знать не может.
func TestDispatch_OpCaps_ReturnsExecutorCaps(t *testing.T) {
	exec := &capsExec{caps: Capabilities{ProxyMode: true, TunMode: true}}
	resp := roundTrip(t, exec, Request{Op: OpCaps})
	if !resp.OK {
		t.Fatalf("OpCaps: OK=false, err=%q", resp.Error)
	}
	if resp.Caps != exec.caps {
		t.Errorf("Caps = %+v, want %+v", resp.Caps, exec.caps)
	}
}

func TestDispatch_OpCaps_SilentBackendIsProxyOnly(t *testing.T) {
	resp := roundTrip(t, &fakeExec{}, Request{Op: OpCaps})
	if !resp.OK {
		t.Fatalf("OpCaps: OK=false, err=%q", resp.Error)
	}
	if resp.Caps.TunMode {
		t.Error("по каналу пришло TunMode=true от бэкенда, который его не декларировал")
	}
}

// ─── B-0403 · R-4.1 · OpReset ────────────────────────────────────────────────

func TestDispatch_OpReset_QuickPath(t *testing.T) {
	oldQuick, oldAll := resetFn, resetAllFn
	defer func() { resetFn, resetAllFn = oldQuick, oldAll }()

	quick, all := 0, 0
	resetFn = func() { quick++ }
	resetAllFn = func() error { all++; return nil }

	exec := &fakeExec{enabled: true}
	resp := roundTrip(t, exec, Request{Op: OpReset})
	if !resp.OK {
		t.Fatalf("OpReset: OK=false, err=%q", resp.Error)
	}
	if quick != 1 || all != 0 {
		t.Errorf("quick=%d all=%d, ожидался ровно один быстрый сброс", quick, all)
	}
	// Состояние бэкенда снимается ПЕРЕД чисткой правил: для WFP это закрытие движка.
	if exec.enabled {
		t.Error("Disable исполнителя не вызван — фильтры WFP пережили бы reset")
	}
}

func TestDispatch_OpReset_FullPath(t *testing.T) {
	oldQuick, oldAll := resetFn, resetAllFn
	defer func() { resetFn, resetAllFn = oldQuick, oldAll }()

	quick, all := 0, 0
	resetFn = func() { quick++ }
	resetAllFn = func() error { all++; return nil }

	resp := roundTrip(t, &fakeExec{}, Request{Op: OpReset, Full: true})
	if !resp.OK {
		t.Fatalf("OpReset(Full): OK=false, err=%q", resp.Error)
	}
	if all != 1 || quick != 0 {
		t.Errorf("quick=%d all=%d, ожидался ровно один полный откат", quick, all)
	}
}

func TestDispatch_OpReset_FullPathReportsError(t *testing.T) {
	oldAll := resetAllFn
	defer func() { resetAllFn = oldAll }()
	resetAllFn = func() error { return errors.New("netsh упал") }

	resp := roundTrip(t, &fakeExec{}, Request{Op: OpReset, Full: true})
	if resp.OK {
		t.Fatal("сбой полного отката обязан доходить до движка, а не теряться")
	}
	if resp.Error == "" {
		t.Error("пустой текст ошибки")
	}
}

// R-6.1/C-10: бэкенд без allow-by-interface обязан ОТВЕТИТЬ ОШИБКОЙ, а не «нечего делать» —
// иначе движок решит, что VPN-режим защищён, хотя весь трафик через apf0 заблокирован.
func TestDispatch_OpEnsureTun_UnsupportedBackendIsError(t *testing.T) {
	resp := roundTrip(t, &fakeExec{}, Request{Op: OpEnsureTun, Tun: "apf0"})
	if resp.OK {
		t.Fatal("бэкенд без EnsureTunPermit не должен отвечать OK")
	}
}

// ─── B-0403 · R-1.1 · выбор локального бэкенда ───────────────────────────────

// Под `go test` WFP-бэкенд выбираться не должен ни при каких запросах: открытие
// динамической сессии FWPM — это уже вмешательство в фаервол хоста (барьер hostguard).
func TestNewLocalBackend_NeverPicksWFPUnderTest(t *testing.T) {
	for _, needTun := range []bool{false, true} {
		ks := NewLocalBackend(needTun)
		if ks == nil {
			t.Fatalf("NewLocalBackend(%v) вернул nil", needTun)
		}
		if runtime.GOOS == "windows" && ks.Capabilities().TunMode {
			t.Errorf("NewLocalBackend(%v) выбрал бэкенд с TunMode под go test", needTun)
		}
	}
}

// Все локальные бэкенды обязаны отвечать на Capabilities() без паники и без nil-ресивера.
func TestNew_DeclaresCapabilities(t *testing.T) {
	caps := New().Capabilities()
	switch runtime.GOOS {
	case "windows":
		if !caps.ProxyMode || caps.TunMode {
			t.Errorf("netsh-бэкенд: %+v, ожидалось proxy-only", caps)
		}
	case "linux", "android":
		if !caps.ProxyMode || !caps.TunMode {
			t.Errorf("%s-бэкенд: %+v, ожидались оба режима", runtime.GOOS, caps)
		}
	default:
		if caps.ProxyMode || caps.TunMode {
			t.Errorf("noop-бэкенд не должен ничего декларировать: %+v", caps)
		}
	}
}
