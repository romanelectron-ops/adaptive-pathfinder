package singbox

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"

	libbox "github.com/sagernet/sing-box/experimental/libbox"
)

var errNotImplementedInTest = errors.New("stubPlatformInterface: не реализовано в тесте")

// Контракт NewInProcessRunner — отвергает отсутствующий PlatformInterface.
//
// Вход:      nil libbox.PlatformInterface.
// Отвергает: с внятной причиной — иначе следующий Start() падал бы на nil-указателе
// внутри libbox, а не на понятной ошибке конструктора.
func TestNewInProcessRunner_RejectsNilPlatformInterface(t *testing.T) {
	if _, err := NewInProcessRunner(nil); err == nil {
		t.Fatal("NewInProcessRunner(nil) = nil ошибка — конструктор обязан отвергать пустой PlatformInterface")
	}
}

// stubPlatformInterface — минимальная заглушка libbox.PlatformInterface для тестов
// жизненного цикла InProcessRunner, где до реального поднятия TUN дело не доходит
// (WriteConfig/Start без конфигурации, Stop до старта, IsRunning в состоянии покоя).
// Настоящий сквозной прогон (реальный TUN, реальная сеть) — предмет приёмки на устройстве
// (Ш-6 ТЗ Э-4), не модульного теста.
type stubPlatformInterface struct{}

func (stubPlatformInterface) LocalDNSTransport() libbox.LocalDNSTransport { return nil }
func (stubPlatformInterface) UsePlatformAutoDetectInterfaceControl() bool { return true }
func (stubPlatformInterface) AutoDetectInterfaceControl(fd int32) error   { return nil }
func (stubPlatformInterface) OpenTun(options libbox.TunOptions) (int32, error) {
	return 0, errNotImplementedInTest
}
func (stubPlatformInterface) UseProcFS() bool { return false }
func (stubPlatformInterface) FindConnectionOwner(ipProtocol int32, sourceAddress string, sourcePort int32, destinationAddress string, destinationPort int32) (*libbox.ConnectionOwner, error) {
	return nil, errNotImplementedInTest
}
func (stubPlatformInterface) StartDefaultInterfaceMonitor(listener libbox.InterfaceUpdateListener) error {
	return nil
}
func (stubPlatformInterface) CloseDefaultInterfaceMonitor(listener libbox.InterfaceUpdateListener) error {
	return nil
}
func (stubPlatformInterface) GetInterfaces() (libbox.NetworkInterfaceIterator, error) {
	return nil, errNotImplementedInTest
}
func (stubPlatformInterface) UnderNetworkExtension() bool      { return false }
func (stubPlatformInterface) IncludeAllNetworks() bool         { return false }
func (stubPlatformInterface) ReadWIFIState() *libbox.WIFIState { return nil }
func (stubPlatformInterface) SystemCertificates() libbox.StringIterator {
	return nil
}
func (stubPlatformInterface) ClearDNSCache() {}
func (stubPlatformInterface) SendNotification(notification *libbox.Notification) error {
	return errNotImplementedInTest
}

func newTestRunner(t *testing.T) *InProcessRunner {
	t.Helper()
	r, err := NewInProcessRunner(stubPlatformInterface{})
	if err != nil {
		t.Fatalf("NewInProcessRunner: %v", err)
	}
	return r
}

// Контракт Start без WriteConfig (fail-safe).
//
// Инвариант: без записанной конфигурации Start не пытается угадать её — честная ошибка,
// а не пустой запуск.
func TestInProcessRunner_StartWithoutConfig(t *testing.T) {
	r := newTestRunner(t)
	if err := r.Start(context.Background()); err == nil {
		t.Fatal("Start() без WriteConfig = nil — соединение поднялось бы с невесть какой конфигурацией")
	}
}

// Контракт Stop до старта — идемпотентность (тот же контракт, что у Process.Stop).
func TestInProcessRunner_StopBeforeStart(t *testing.T) {
	r := newTestRunner(t)
	if err := r.Stop(); err != nil {
		t.Fatalf("Stop() до старта = %v, ожидался nil (идемпотентность)", err)
	}
}

// Контракт IsRunning в состоянии покоя — источник истины CommandServer.Instance(),
// а не локальный флаг.
func TestInProcessRunner_IsRunningFalseAtRest(t *testing.T) {
	r := newTestRunner(t)
	if r.IsRunning() {
		t.Fatal("IsRunning() = true до первого Start()")
	}
}

// Контракт IsInstalled/Version — код уже вкомпилирован, версия из единого источника.
func TestInProcessRunner_IsInstalledAndVersion(t *testing.T) {
	r := newTestRunner(t)
	if !r.IsInstalled() {
		t.Error("IsInstalled() = false — sing-box вкомпилирован, отдельной установки нет")
	}
	if v, err := r.Version(); err != nil || v != SingBoxVersion {
		t.Errorf("Version() = (%q, %v), ожидалось (%q, nil)", v, err, SingBoxVersion)
	}
}

// Регрессия на находку Ш-6 (приёмка на устройстве): StartOrReloadService у sing-box
// разыменовывает *options.AutoRedirect БЕЗ проверки на nil (command_server.go, v1.13.16) —
// Start() передавал буквальный nil и падал nil pointer dereference → SIGABRT → процесс
// целиком, на первом же реальном подключении на телефоне. Тесты выше не ловили это:
// TestInProcessRunner_StartWithoutConfig нарочно проверяет только отказ БЕЗ конфигурации
// (см. её комментарий) — успешный путь Start() с реальной конфигурацией был предметом
// приёмки на устройстве, не модульного теста. Этот тест закрывает именно тот пробел:
// конфигурация без inbound'ов (не открывает TUN, не слушает порт — OpenTun() у
// stubPlatformInterface вообще не вызывается) достаточна, чтобы дойти до настоящего
// StartOrReloadService и упасть на прежнем коде.
//
// Инвариант, который тест обязан ловить ЛЮБОЙ ценой — Start() никогда не паникует, при
// любых флагах сборки. Две находки того же прогона на устройстве — обе стороны
// libbox.CommandServer, не наши — терпимы через t.Skip, а не t.Fatal:
//   - CommandServer ВСЕГДА взводит PlatformLogWriter (box.go:137), а тот безусловно
//     требует experimental clash-server (box.go:134-138) — без -tags with_clash_api сборка
//     линкует только заглушку (include/clashapi_stub.go), и Start() честно отказывает, а
//     не паникует. Этот же флаг ТЕПЕРЬ ОБЯЗАТЕЛЕН для gomobile bind (build_aar.ps1) — без
//     него VPN-режим отказывал бы на КАЖДОМ подключении на реальном устройстве, будь узел
//     живой или нет.
//   - PlatformLogWriter тем же путём взводит needCacheFile, а инициализация cache-file
//     (chown) не поддержана на Windows — по-настоящему пройти этот путь целиком может
//     только Linux/Android; на этом хосте тест обязан остановиться на честном отказе.
func TestInProcessRunner_StartWithRealConfig_DoesNotPanic(t *testing.T) {
	r := newTestRunner(t)
	cfg := &Config{
		Log: LogConfig{Level: "error"},
		DNS: DNSConfig{
			Servers: []DNSServer{{Type: "local", Tag: "local"}},
		},
		Outbounds: []Outbound{{Type: "direct", Tag: "direct"}},
		Route: RouteConfig{
			Final:                 "direct",
			DefaultDomainResolver: &DomainResolver{Server: "local"},
		},
	}
	if err := r.WriteConfig(cfg); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}

	err := r.Start(context.Background())
	switch {
	case err == nil:
		if !r.IsRunning() {
			t.Fatal("IsRunning() = false после успешного Start()")
		}
		if stopErr := r.Stop(); stopErr != nil {
			t.Fatalf("Stop(): %v", stopErr)
		}
	case strings.Contains(err.Error(), "with_clash_api"):
		t.Skipf("сборка без -tags with_clash_api (нужен для gomobile bind тоже, см. "+
			"build_aar.ps1) — панику уже не проверить дальше этой точки, а панику мы и "+
			"ловим: %v", err)
	case runtime.GOOS == "windows" && strings.Contains(err.Error(), "chown"):
		t.Skipf("cache-file требует chown — Windows не поддерживает, Android поддерживает: %v", err)
	default:
		t.Fatalf("Start() с валидной безынбаундной конфигурацией: %v (это НЕ должно быть "+
			"panic ни при каких флагах сборки — если тест упал именно так, регрессия вернулась)", err)
	}
}

// InProcessRunner структурно удовлетворяет Runner — компилируется, только если сигнатуры
// совпадают дословно; регрессия здесь ловится на этапе сборки, не теста.
var _ Runner = (*InProcessRunner)(nil)
