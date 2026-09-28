package engine

import (
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/session"
	"github.com/apf/adaptive-pathfinder/internal/singbox"
)

// wireTrafficMonitorStats — единственный практический источник activeConns/lastActivity
// для StickySessionManager в проде (аудит: "Sticky Session выродился — TrackConn не
// вызывается"). Реальный трафик идёт через libbox/TUN в обход Go net.Conn, поэтому
// TrackConn(delta)/OnActivity() из session.NewTrackedConn/NewTrackedTransport никогда не
// вызываются на реальном пути — вместо них конструктор подключает StickySessionManager к
// уже существующему опросу Clash API (TrafficMonitor.poll, каждые 2с).

func TestNew_WiresTrafficMonitorOnStats(t *testing.T) {
	e := newTestEngine()
	if e.trafficMonitor == nil {
		t.Fatal("trafficMonitor не создан конструктором")
	}
	if e.trafficMonitor.OnStats == nil {
		t.Fatal("New() должен подключить trafficMonitor.OnStats к stickySession (wireTrafficMonitorStats)")
	}
}

func TestTrafficMonitorOnStats_DrivesStickySessionCanSwitch(t *testing.T) {
	e := newTestEngine()
	e.stickySession.SetPolicy(session.PolicySticky)

	// Прямой вызов колбэка — эквивалент того, что TrafficMonitor.poll() только что
	// получил от Clash API живой ответ с активным соединением и идущим трафиком.
	e.trafficMonitor.OnStats(singbox.TrafficStats{Conns: 1, UpSpeed: 100})

	dec := e.stickySession.CanSwitch(false)
	if dec.Allow {
		t.Errorf("sticky: CanSwitch должен запретить переключение после OnStats с активным "+
			"соединением, получено разрешение (%s)", dec.Reason)
	}

	// Опрос сообщает, что соединений больше нет: activeConns=0 гарантированно снимает
	// ПЕРВОЕ условие IsSessionActive (activeConns>0), но SyncFromTraffic(0, false)
	// намеренно НЕ трогает lastActivity (см. её комментарий) — второе условие
	// (недавняя активность по таймауту) продолжает жить своим сроком независимо от
	// счётчика соединений, поэтому здесь проверяем именно activeConns через CanSwitch,
	// а не IsSessionActive (которая ещё какое-то время останется true по таймеру, и это
	// корректное поведение, не то, что тестирует этот сценарий).
	e.trafficMonitor.OnStats(singbox.TrafficStats{Conns: 0})

	dec = e.stickySession.CanSwitch(false)
	if !dec.Allow {
		t.Errorf("sticky: CanSwitch должен разрешить переключение когда OnStats сообщил "+
			"Conns=0 и молодая сессия истекла, получено: %s", dec.Reason)
	}
}

func TestPatchConfig_PortChange_RewiresTrafficMonitorOnStats(t *testing.T) {
	e := newTestEngine()
	oldMonitor := e.trafficMonitor

	if err := e.PatchConfig(map[string]interface{}{
		"listen_port": float64(e.cfg.ListenPort + 1),
	}); err != nil {
		t.Fatalf("PatchConfig: %v", err)
	}

	if e.trafficMonitor == oldMonitor {
		t.Fatal("trafficMonitor должен пересоздаться при смене listen_port")
	}
	if e.trafficMonitor.OnStats == nil {
		t.Error("после пересоздания trafficMonitor OnStats должен быть подключён заново")
	}
}
