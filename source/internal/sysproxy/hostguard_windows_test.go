//go:build windows

package sysproxy

import (
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/windows/registry"

	"github.com/apf/adaptive-pathfinder/internal/hostguard"
)

// РЕГРЕССИОННЫЙ ЩИТ. Этот файл существует из-за реального инцидента: `go test ./internal/...`
// включал системный HTTP-прокси на 127.0.0.1:<порт>, где sing-box не слушал, и у пользователя
// пропадал интернет во всех приложениях, читающих системные настройки Windows.
//
// Запись в HKCU не требует прав администратора, поэтому «мы же не под админом» тут не защищает.
// Здесь два уровня проверки:
//  1. TestMain — снимок реальных значений реестра ДО и ПОСЛЕ всего прогона пакета. Ловит ЛЮБУЮ
//     утечку мутации, включая ту, которую добавят в будущем.
//  2. Точечные тесты — экспортируемые функции под барьером обязаны быть no-op.

type proxySnapshot struct {
	enable    uint64
	enableErr error
	server    string
	serverErr error
}

func readProxySnapshot() proxySnapshot {
	var s proxySnapshot
	k, err := registry.OpenKey(registry.CURRENT_USER, inetKey, registry.QUERY_VALUE)
	if err != nil {
		s.enableErr, s.serverErr = err, err
		return s
	}
	defer k.Close()
	s.enable, _, s.enableErr = k.GetIntegerValue("ProxyEnable")
	s.server, _, s.serverErr = k.GetStringValue("ProxyServer")
	return s
}

func (s proxySnapshot) String() string {
	return fmt.Sprintf("ProxyEnable=%d(err=%v) ProxyServer=%q(err=%v)",
		s.enable, s.enableErr, s.server, s.serverErr)
}

func TestMain(m *testing.M) {
	// П1 (аудит 2026-09-01, находка №14): notifyWinINETSettingsChanged зовёт РЕАЛЬНЫЙ
	// wininet.dll!InternetSetOptionW безусловно (не под барьером hostguard — это чистое
	// in-memory уведомление, не мутация ОС, см. её doc-comment в sysproxy_windows.go). Она
	// не трогает реестр и потому не может пробить щит выше — но тот же принцип "ВСЕ швы
	// подменяемы под тестом", которым живёт этот файл, требует не полагаться на "должно
	// быть безопасно вызвать", а сделать это явно неверифицируемым фактом под go test.
	// Не восстанавливается: TestMain завершается через os.Exit ниже, defer до него не
	// дожил бы — процесс всё равно умирает сразу после, восстанавливать не для чего.
	notifyWinINETSettingsChanged = func() {}

	before := readProxySnapshot()
	code := m.Run()
	after := readProxySnapshot()

	if !hostguard.Overridden() && (before.enable != after.enable || before.server != after.server) {
		fmt.Fprintf(os.Stderr,
			"\n!!! БАРЬЕР hostguard ПРОБИТ: пакет sysproxy изменил системный прокси ХОСТА !!!\n"+
				"  было:  %s\n  стало: %s\n"+
				"  Это ровно тот дефект, из-за которого во время тестов пропадал интернет.\n"+
				"  Проверьте, что все мутаторы начинаются с hostguard.Allow(...).\n\n",
			before, after)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

// (1) Позитив барьера: экспортируемый SetHTTPProxy под `go test` — успешный no-op.
func TestSetHTTPProxy_BlockedByHostguard(t *testing.T) {
	if hostguard.Overridden() {
		t.Skip("барьер снят через APF_ALLOW_HOST_MUTATION (изолированная ВМ)")
	}
	before := readProxySnapshot()
	if err := SetHTTPProxy("127.0.0.1", 1081); err != nil {
		t.Fatalf("под барьером SetHTTPProxy должен быть успешным no-op, получено: %v", err)
	}
	after := readProxySnapshot()
	if before.enable != after.enable || before.server != after.server {
		t.Fatalf("SetHTTPProxy изменил реестр под барьером:\n  было:  %s\n  стало: %s", before, after)
	}
}

// (2) Позитив барьера: Disable тоже не трогает реестр — иначе тест «снятия» затирал бы
// НАСТОЯЩИЙ прокси пользователя, который тот мог включить сам.
func TestDisable_BlockedByHostguard(t *testing.T) {
	if hostguard.Overridden() {
		t.Skip("барьер снят через APF_ALLOW_HOST_MUTATION (изолированная ВМ)")
	}
	before := readProxySnapshot()
	if err := Disable(); err != nil {
		t.Fatalf("под барьером Disable должен быть успешным no-op, получено: %v", err)
	}
	after := readProxySnapshot()
	if before.enable != after.enable || before.server != after.server {
		t.Fatalf("Disable изменил реестр под барьером:\n  было:  %s\n  стало: %s", before, after)
	}
}

// (2b) Тот же позитив барьера для RecoverStale (задача найдена живым инцидентом
// 2026-08-13 — см. internal/sysproxy/marker.go) — под барьером обязана быть no-op, даже
// если marker-файл существует и "совпадает" с реестром. markerPathFn подменяется на
// temp-путь по той же причине, что и в marker_test.go: config.DataDir() на Windows не
// перенаправляется переменными окружения, реальный %APPDATA% трогать нельзя даже файлом.
func TestRecoverStale_BlockedByHostguard(t *testing.T) {
	if hostguard.Overridden() {
		t.Skip("барьер снят через APF_ALLOW_HOST_MUTATION (изолированная ВМ)")
	}
	origPath := markerPathFn
	markerPathFn = func() string { return t.TempDir() + `\sysproxy_active.marker` }
	defer func() { markerPathFn = origPath }()

	before := readProxySnapshot()
	writeMarker(before.server, 0) // заведомо мусорная метка — не должна ни на что повлиять
	defer clearMarker()

	RecoverStale()

	after := readProxySnapshot()
	if before.enable != after.enable || before.server != after.server {
		t.Fatalf("RecoverStale изменил реестр под барьером:\n  было:  %s\n  стало: %s", before, after)
	}
}

// (3) Стойкость: сколько бы раз ни звали — реестр не меняется и ошибок нет.
func TestProxyMutators_RepeatedCallsStayNoop(t *testing.T) {
	if hostguard.Overridden() {
		t.Skip("барьер снят через APF_ALLOW_HOST_MUTATION (изолированная ВМ)")
	}
	before := readProxySnapshot()
	for i := 0; i < 20; i++ {
		if err := SetHTTPProxy("127.0.0.1", 1080+i); err != nil {
			t.Fatalf("итерация %d: %v", i, err)
		}
		if err := Disable(); err != nil {
			t.Fatalf("итерация %d (disable): %v", i, err)
		}
	}
	if after := readProxySnapshot(); before.enable != after.enable || before.server != after.server {
		t.Fatalf("после 20 циклов реестр изменился:\n  было:  %s\n  стало: %s", before, after)
	}
}
