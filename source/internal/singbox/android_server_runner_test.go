package singbox

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

// Контракт NewAndroidServerRunner — отвергает отсутствующий PlatformInterface, тот же
// контракт, что уже проверен для NewInProcessRunner (TestNewInProcessRunner_RejectsNilPlatformInterface).
func TestNewAndroidServerRunner_RejectsNilPlatformInterface(t *testing.T) {
	if _, err := NewAndroidServerRunner(nil); err == nil {
		t.Fatal("NewAndroidServerRunner(nil) = nil ошибка — конструктор обязан отвергать пустой PlatformInterface")
	}
}

func newTestAndroidServerRunner(t *testing.T) *AndroidServerRunner {
	t.Helper()
	r, err := NewAndroidServerRunner(stubPlatformInterface{})
	if err != nil {
		t.Fatalf("NewAndroidServerRunner: %v", err)
	}
	return r
}

// Контракт Start без WriteConfig (fail-safe) — зеркало TestInProcessRunner_StartWithoutConfig.
func TestAndroidServerRunner_StartWithoutConfig(t *testing.T) {
	r := newTestAndroidServerRunner(t)
	if err := r.Start(context.Background()); err == nil {
		t.Fatal("Start() без WriteConfig = nil — сервер поднялся бы с невесть какой конфигурацией")
	}
}

// Контракт Stop до старта — идемпотентность.
func TestAndroidServerRunner_StopBeforeStart(t *testing.T) {
	r := newTestAndroidServerRunner(t)
	if err := r.Stop(); err != nil {
		t.Fatalf("Stop() до старта = %v, ожидался nil (идемпотентность)", err)
	}
}

// Контракт IsRunning в состоянии покоя — источник истины CommandServer.Instance().
func TestAndroidServerRunner_IsRunningFalseAtRest(t *testing.T) {
	r := newTestAndroidServerRunner(t)
	if r.IsRunning() {
		t.Fatal("IsRunning() = true до первого Start()")
	}
}

// Контракт IsInstalled/Version.
func TestAndroidServerRunner_IsInstalledAndVersion(t *testing.T) {
	r := newTestAndroidServerRunner(t)
	if !r.IsInstalled() {
		t.Error("IsInstalled() = false — sing-box вкомпилирован, отдельной установки нет")
	}
	if v, err := r.Version(); err != nil || v != SingBoxVersion {
		t.Errorf("Version() = (%q, %v), ожидалось (%q, nil)", v, err, SingBoxVersion)
	}
}

// GenerateIdentity не зависит от состояния запуска.
func TestAndroidServerRunner_GenerateIdentity(t *testing.T) {
	r := newTestAndroidServerRunner(t)
	id, err := r.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if id.UUID == "" || id.PrivateKey == "" || id.PublicKey == "" || id.ShortID == "" {
		t.Fatalf("GenerateIdentity() вернул неполную идентичность: %+v", id)
	}
}

// Регрессия консилиума 2026-08-10 (CRITICAL) — та же граница validateServerDoc, что уже
// проверена для windowsServerRunner (TestWindowsServerRunner_WriteConfig_Rejects*), здесь
// проверяется, что AndroidServerRunner её действительно вызывает, а не дублирует по-своему.
func TestAndroidServerRunner_WriteConfig_RejectsNilDoc(t *testing.T) {
	r := newTestAndroidServerRunner(t)
	if err := r.WriteConfig(nil); err == nil {
		t.Fatal("WriteConfig(nil) = nil, ожидался явный отказ")
	}
}

func TestAndroidServerRunner_WriteConfig_RejectsEmptyInbounds(t *testing.T) {
	r := newTestAndroidServerRunner(t)
	if err := r.WriteConfig(&ServerDoc{}); err == nil {
		t.Fatal("WriteConfig(doc без Inbounds) = nil, ожидался явный отказ")
	}
}

func TestAndroidServerRunner_WriteConfig_RejectsOutOfRangePort(t *testing.T) {
	r := newTestAndroidServerRunner(t)
	id := testIdentity(t)
	for _, port := range []int{0, -1, 65536} {
		doc := BuildServerConfig(id, port, "www.microsoft.com")
		if err := r.WriteConfig(doc); err == nil {
			t.Errorf("WriteConfig(listenPort=%d) = nil, ожидался явный отказ", port)
		}
	}
}

func TestAndroidServerRunner_WriteConfig_AcceptsValidPort(t *testing.T) {
	r := newTestAndroidServerRunner(t)
	id := testIdentity(t)
	doc := BuildServerConfig(id, 18443, "www.microsoft.com")
	if err := r.WriteConfig(doc); err != nil {
		t.Errorf("WriteConfig(listenPort=18443) = %v, ожидался успех", err)
	}
}

// Регрессия Ш-6 (см. TestInProcessRunner_StartWithRealConfig_DoesNotPanic) переиспользована
// для серверного пути: Start() с валидной конфигурацией обязан не паниковать ни при каких
// флагах сборки. На этом хосте (Windows, без -tags with_clash_api/chown-поддержки) реальное
// поднятие inbound-листенера до сети не доходит — тот же честный отказ на более раннем шаге
// (cache-file/clash-api), что и у клиентского теста; сам факт реального сетевого прослушивания
// остаётся предметом приёмки на устройстве (Ш-Выход-2-приёмка), не модульного теста.
func TestAndroidServerRunner_StartWithRealConfig_DoesNotPanic(t *testing.T) {
	r := newTestAndroidServerRunner(t)
	id := testIdentity(t)
	doc := BuildServerConfig(id, 18443, "www.microsoft.com")
	if err := r.WriteConfig(doc); err != nil {
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
		t.Skipf("сборка без -tags with_clash_api (нужен и для gomobile bind, см. build_aar.ps1): %v", err)
	case strings.Contains(err.Error(), "with_utls"):
		// Тот же класс, что and with_clash_api: `go test` на хосте не передаёт теги
		// gomobile-сборки (build_aar.ps1 передаёт with_clash_api,with_utls,with_gvisor —
		// см. vhod-vyhod-tz-plan-status). ServerDoc — единственная конфигурация в этом
		// пакете, где Reality реально требуется на старте (клиентский аналог,
		// TestInProcessRunner_StartWithRealConfig_DoesNotPanic, намеренно безынбаундный и
		// это не задевает) — сама AAR-сборка уже несёт нужный тег, здесь лишь честный
		// пропуск хостовой сборки без него.
		t.Skipf("сборка без -tags with_utls (нужен для Reality, см. build_aar.ps1): %v", err)
	case runtime.GOOS == "windows" && strings.Contains(err.Error(), "chown"):
		t.Skipf("cache-file требует chown — Windows не поддерживает, Android поддерживает: %v", err)
	default:
		t.Fatalf("Start() с валидной серверной конфигурацией: %v (это НЕ должно быть panic ни при "+
			"каких флагах сборки)", err)
	}
}

// AndroidServerRunner структурно удовлетворяет ServerRunner — компилируется, только если
// сигнатуры совпадают дословно.
var _ ServerRunner = (*AndroidServerRunner)(nil)
