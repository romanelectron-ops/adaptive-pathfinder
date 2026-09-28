// engine_v13_f5_test.go — ТЗ v1.3 F5.3/F5.4: guard заглушечных адресов, PatchConfig применяет
// DPI-настройки без перезапуска и без deadlock (регрессия инцидента 2026-09-02).
package engine

import (
	"strings"
	"sync"
	"testing"
	"time"
)

const goodSTLSAddr = "192.168.1.10:8443" // RFC1918 — свой сервер, разрешён (V4)

// F5.3: заглушки отвергаются в момент сохранения, менеджер остаётся выключенным.
func TestSetShadowTLSConfig_RejectsPlaceholderAddr(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	for _, bad := range []string{"5.6.7.8:8443", "example.com:8443", "203.0.113.7:8443", "localhost:8443"} {
		if err := e.SetShadowTLSConfig(true, "pw", "", "", bad); err == nil {
			t.Errorf("%s должен отвергаться", bad)
		}
		if e.shadowTLS.IsEnabled() {
			t.Errorf("после отказа на %s менеджер должен остаться выключенным", bad)
		}
	}
	if err := e.SetShadowTLSConfig(true, "pw", "", "", goodSTLSAddr); err != nil {
		t.Fatalf("свой LAN-сервер должен приниматься: %v", err)
	}
	if !e.shadowTLS.IsEnabled() || !e.cfg.ShadowTLSEnabled {
		t.Error("после валидного адреса менеджер и cfg должны быть включены")
	}
}

// F5.4 (регрессия 2026-09-02): PatchConfig {shadowtls_enabled:false} РЕАЛЬНО выключает
// менеджер, не стирая пароль/адрес; повторное включение патчем поднимает его снова.
func TestPatchConfig_ShadowTLSToggle_AppliesToManager(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	if err := e.SetShadowTLSConfig(true, "pw", "", "", goodSTLSAddr); err != nil {
		t.Fatal(err)
	}
	if err := e.PatchConfig(map[string]interface{}{"shadowtls_enabled": false}); err != nil {
		t.Fatal(err)
	}
	if e.shadowTLS.IsEnabled() {
		t.Fatal("после патча shadowtls_enabled=false менеджер должен быть выключен")
	}
	if e.cfg.ShadowTLSPassword != "pw" || e.cfg.ShadowTLSServerAddr != goodSTLSAddr {
		t.Errorf("выключение не должно стирать секреты: pw=%q addr=%q", e.cfg.ShadowTLSPassword, e.cfg.ShadowTLSServerAddr)
	}
	if err := e.PatchConfig(map[string]interface{}{"shadowtls_enabled": true}); err != nil {
		t.Fatal(err)
	}
	if !e.shadowTLS.IsEnabled() {
		t.Fatal("после патча shadowtls_enabled=true менеджер должен подняться на сохранённых секретах")
	}
	// Заглушка в сохранённом конфиге → при применении остаётся выключенным + уведомление.
	var notified string
	e.OnLeakDetected = func(kind, details string) { notified = kind + ": " + details }
	if err := e.PatchConfig(map[string]interface{}{"shadowtls_server_addr": "example.com:8443"}); err != nil {
		t.Fatal(err)
	}
	if e.shadowTLS.IsEnabled() {
		t.Error("с адресом-заглушкой менеджер должен выключиться")
	}
	if !strings.Contains(notified, "ShadowTLS") {
		t.Errorf("ожидалось уведомление в UI, got %q", notified)
	}
}

// F5.4: ключи, требующие перезапуска, возвращаются вызывающему.
func TestPatchConfigDetailed_NeedsRestart(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	need, err := e.PatchConfigDetailed(map[string]interface{}{"listen_port": 20808, "notify_on_switch": true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(need, ",") != "listen_port" {
		t.Errorf("needsRestart=%v want [listen_port]", need)
	}
	need, err = e.PatchConfigDetailed(map[string]interface{}{"notify_on_switch": false})
	if err != nil || len(need) != 0 {
		t.Errorf("обычный ключ: need=%v err=%v", need, err)
	}
}

// F5.4 (-race): PatchConfig ∥ SetShadowTLSConfig не заклинивают друг друга.
func TestPatchConfig_ParallelWithSetShadowTLS_NoDeadlock(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for i := 0; i < 15; i++ {
			wg.Add(2)
			go func(i int) {
				defer wg.Done()
				_ = e.PatchConfig(map[string]interface{}{"traffic_padding_enabled": i%2 == 0, "shadowtls_enabled": i%3 == 0})
			}(i)
			go func(i int) {
				defer wg.Done()
				_ = e.SetShadowTLSConfig(i%2 == 0, "pw", "", "", goodSTLSAddr)
			}(i)
		}
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("deadlock: PatchConfig ∥ SetShadowTLSConfig не завершились за 20 с")
	}
}

// F5.2 внутри PatchConfig: значения нормализуются теми же правилами (webui_port==listen_port
// разводится, selection_mode приводится).
func TestPatchConfig_NormalizesMergedConfig(t *testing.T) {
	withTempDataDir(t)
	e := newTestEngine()
	if err := e.PatchConfig(map[string]interface{}{"listen_port": 9090, "webui_port": 9090}); err != nil {
		t.Fatal(err)
	}
	if e.cfg.WebUIPort == e.cfg.ListenPort {
		t.Errorf("webui_port и listen_port не должны совпадать: %d/%d", e.cfg.WebUIPort, e.cfg.ListenPort)
	}
}
