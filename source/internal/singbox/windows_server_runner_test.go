package singbox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Контракт: без установленного бинарника IsInstalled — false и Start честно отказывает
// (тот же контракт, что уже проверен для Process.Start — TestProcessIsInstalledFalse и
// соседние тесты в этом пакете), не паникует и не «поднимается» без бинарника.
func TestWindowsServerRunner_NotInstalled(t *testing.T) {
	dir := t.TempDir()
	r := NewWindowsServerRunner(dir, dir)

	if r.IsInstalled() {
		t.Fatal("IsInstalled() = true в пустом каталоге")
	}

	id, err := r.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() не должен зависеть от установленного бинарника: %v", err)
	}
	doc := BuildServerConfig(id, 18443, "www.microsoft.com")
	if err := r.WriteConfig(doc); err != nil {
		t.Fatalf("WriteConfig() не должен зависеть от установленного бинарника: %v", err)
	}

	if err := r.Start(context.Background()); err == nil {
		t.Fatal("Start() без установленного бинарника = nil, ожидался отказ")
	}
	if r.IsRunning() {
		t.Fatal("IsRunning() = true после неудачного Start()")
	}
}

// Контракт: WriteConfig пишет валидный JSON серверного документа на диск (тот же файл,
// что потом читает `sing-box run -c`) и передаёт правильный порт готовности —
// зеркало TestProcessWriteConfig для клиентского Config.
func TestWindowsServerRunner_WriteConfig(t *testing.T) {
	dir := t.TempDir()
	r := NewWindowsServerRunner(dir, dir).(*windowsServerRunner)

	id := testIdentity(t)
	doc := BuildServerConfig(id, 18443, "www.microsoft.com")
	if err := r.WriteConfig(doc); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, serverRoleConfigName))
	if err != nil {
		t.Fatalf("конфиг не записан на диск: %v", err)
	}
	// Роль «Выход» обязана иметь СВОЙ файл: клиент («Вход») пишет current.json, и общий файл
	// ломал одновременную работу ролей детерминированно — запуск «Выхода» затирал конфиг
	// работающего клиента, а следующее переподключение клиента поднимало его с СЕРВЕРНЫМ
	// конфигом (найдено проверкой 2026-08-24, ТЗ прямо требует независимости ролей).
	if _, err := os.Stat(filepath.Join(dir, "current.json")); err == nil {
		t.Error("роль «Выход» записала клиентский current.json — конфиг клиента будет затёрт")
	}
	var decoded ServerDoc
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("записанный файл не парсится как ServerDoc: %v", err)
	}
	if len(decoded.Inbounds) != 1 || decoded.Inbounds[0].ListenPort != 18443 {
		t.Fatalf("записанный конфиг = %+v, ожидался inbound на 18443", decoded.Inbounds)
	}

	r.proc.mu.Lock()
	readyPort := r.proc.readyPort
	r.proc.mu.Unlock()
	if readyPort != 18443 {
		t.Errorf("readyPort = %d, ожидался 18443 (порт единственного inbound)", readyPort)
	}
}

// Контракт: Stop до старта и IsRunning в состоянии покоя — идемпотентность, тот же
// контракт, что уже действует у Process напрямую (TestProcessStopIdle,
// TestProcessIsRunningInitial) — здесь проверяется, что обёртка ServerRunner его не теряет.
func TestWindowsServerRunner_IdleStateIsSafe(t *testing.T) {
	dir := t.TempDir()
	r := NewWindowsServerRunner(dir, dir)

	if r.IsRunning() {
		t.Fatal("IsRunning() = true до первого Start()")
	}
	if err := r.Stop(); err != nil {
		t.Fatalf("Stop() до старта = %v, ожидался nil (идемпотентность)", err)
	}
}

// Регрессия (консилиум 2026-08-10, CRITICAL): раньше WriteConfig принимал listenPort=0
// (или отсутствующий Inbounds) без единой проверки, port просто оставался 0, и Start()
// уходил в ветку awaitReady «признака готовности нет» — 2 секунды сна и молчаливый успех,
// хотя реальный sing-box слушал не тот порт (или вовсе случайный эфемерный от ОС). WriteConfig
// обязан отвергать такой doc явной ошибкой ДО того, как он попадёт в Process.
func TestWindowsServerRunner_WriteConfig_RejectsZeroPort(t *testing.T) {
	dir := t.TempDir()
	r := NewWindowsServerRunner(dir, dir)

	id := testIdentity(t)
	doc := BuildServerConfig(id, 0, "www.microsoft.com")
	if err := r.WriteConfig(doc); err == nil {
		t.Fatal("WriteConfig(listenPort=0) = nil, ожидался явный отказ")
	}
}

func TestWindowsServerRunner_WriteConfig_RejectsOutOfRangePort(t *testing.T) {
	dir := t.TempDir()
	r := NewWindowsServerRunner(dir, dir)
	id := testIdentity(t)

	for _, port := range []int{-1, 65536, 100000} {
		doc := BuildServerConfig(id, port, "www.microsoft.com")
		if err := r.WriteConfig(doc); err == nil {
			t.Errorf("WriteConfig(listenPort=%d) = nil, ожидался явный отказ (вне диапазона 1..65535)", port)
		}
	}
}

// Более лёгкий реальный вход, чем даже listenPort=0 явно: doc без единого Inbound вообще
// (например, ServerDoc{} собран вручную, не через BuildServerConfig) — тоже обязан отвергаться,
// а не молча превращаться в port=0 через len(doc.Inbounds)>0 фоллбэк.
func TestWindowsServerRunner_WriteConfig_RejectsEmptyInbounds(t *testing.T) {
	dir := t.TempDir()
	r := NewWindowsServerRunner(dir, dir)

	if err := r.WriteConfig(&ServerDoc{}); err == nil {
		t.Fatal("WriteConfig(doc без Inbounds) = nil, ожидался явный отказ")
	}
}

// Регрессия: валидный порт (сегодняшнее поведение) продолжает работать — фикс не должен
// случайно отвергать легитимные конфиги.
func TestWindowsServerRunner_WriteConfig_AcceptsValidPort(t *testing.T) {
	dir := t.TempDir()
	r := NewWindowsServerRunner(dir, dir)
	id := testIdentity(t)

	for _, port := range []int{1, 8443, 65535} {
		doc := BuildServerConfig(id, port, "www.microsoft.com")
		if err := r.WriteConfig(doc); err != nil {
			t.Errorf("WriteConfig(listenPort=%d) = %v, ожидался успех", port, err)
		}
	}
}

// [консилиум, MEDIUM, находка №19, TZ_RELAY_HARDENING_2026-08-29.md] Раньше правило строилось
// только по program= — разрешало вход на ЛЮБОЙ порт, который когда-либо откроет данный exe, не
// только нужный. Сформированная команда обязана содержать И program=, И localport=/protocol=TCP.
func TestEnsureInboundFirewallRule_CommandIncludesProgramAndLocalPort(t *testing.T) {
	orig := execCommandFn
	var gotArgs []string
	execCommandFn = func(name string, args ...string) ([]byte, error) {
		if name != "netsh" {
			t.Errorf("execCommandFn вызван с name=%q, ожидался netsh", name)
		}
		gotArgs = args
		return nil, nil
	}
	t.Cleanup(func() { execCommandFn = orig })

	if err := EnsureInboundFirewallRule("APF Test Rule", `C:\apf\apf.exe`, 28443); err != nil {
		t.Fatalf("EnsureInboundFirewallRule: %v", err)
	}

	joined := strings.Join(gotArgs, " ")
	if !strings.Contains(joined, `program=C:\apf\apf.exe`) {
		t.Errorf("команда не содержит program=: %q", joined)
	}
	if !strings.Contains(joined, "localport=28443") {
		t.Errorf("команда не содержит localport=28443: %q", joined)
	}
	if !strings.Contains(joined, "protocol=TCP") {
		t.Errorf("команда не содержит protocol=TCP: %q", joined)
	}
}

// Регрессия на сам механизм переиздания правила при hot-reload (кластер A): Start() обязан
// передавать АКТУАЛЬНЫЙ порт из последнего WriteConfig, не порт из более раннего вызова.
func TestWindowsServerRunner_Start_PassesCurrentPortToFirewallRule(t *testing.T) {
	orig := execCommandFn
	// Все вызовы, а не последний: после отказа Start() добавляется снятие правила (delete) —
	// проверяем ПЕРВЫЙ вызов, то есть заведение правила (add).
	var calls [][]string
	execCommandFn = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, args)
		return nil, nil
	}
	t.Cleanup(func() { execCommandFn = orig })

	dir := t.TempDir()
	binName := "sing-box"
	if runtime.GOOS == "windows" {
		binName = "sing-box.exe"
	}
	if err := os.WriteFile(filepath.Join(dir, binName), []byte("stub"), 0755); err != nil {
		t.Fatal(err)
	}

	r := NewWindowsServerRunner(dir, dir)
	id := testIdentity(t)
	if err := r.WriteConfig(BuildServerConfig(id, 28443, "www.microsoft.com")); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	// Start() отказывает дальше (не настоящий sing-box), но правило файрвола заводится
	// ДО попытки запустить процесс — этого достаточно для проверки переданного порта.
	_ = r.Start(context.Background())

	if len(calls) == 0 {
		t.Fatal("Start() не вызвал netsh ни разу")
	}
	joined := strings.Join(calls[0], " ")
	if !strings.Contains(joined, "localport=28443") {
		t.Errorf("Start() передал в EnsureInboundFirewallRule не тот порт: %q", joined)
	}
}

// Регрессия: реальный установленный бинарник — сборка отказывает на невалидном конфиге
// ("stub"-файл вместо настоящего sing-box не годится для этого теста, нужен фактический
// установленный sing-box), проверяем только доступный на CI/хосте путь — IsInstalled ложь
// в чистом каталоге не должна маскироваться платформой.
func TestWindowsServerRunner_BinaryNameMatchesPlatform(t *testing.T) {
	dir := t.TempDir()
	binName := "sing-box"
	if runtime.GOOS == "windows" {
		binName = "sing-box.exe"
	}
	if err := os.WriteFile(filepath.Join(dir, binName), []byte("stub"), 0755); err != nil {
		t.Fatal(err)
	}

	r := NewWindowsServerRunner(dir, dir)
	if !r.IsInstalled() {
		t.Errorf("IsInstalled() = false, хотя бинарник %q присутствует", binName)
	}
	if v, err := r.Version(); err == nil {
		t.Errorf("Version() = %q, nil — «stub»-файл не исполняемый sing-box, ожидалась ошибка exec", v)
	}
}
