package singbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// testVLESSNode — минимальный валидный узел для сборки полного (не голого baseConfig)
// конфига: `sing-box check` отвергает route-правила, ссылающиеся на outbound "direct" в
// конфигурации без единого outbound'а, — это ошибка про отсутствие ссылки, а не про схему,
// которую эти тесты проверяют. BuildSingle всегда добавляет и direct, и proxy.
func testVLESSNode() *models.Node {
	return &models.Node{
		Protocol: models.ProtoVLESS,
		Address:  "example.com",
		Port:     443,
		UUID:     "12345678-1234-1234-1234-123456789012",
		Flow:     "xtls-rprx-vision",
		TLS: &models.TLSConfig{
			Enabled:    true,
			ServerName: "www.microsoft.com",
			Reality: &models.RealityConfig{
				PublicKey: "MGoTPk4nnB8UhE7yD_5dCBUvZ8sEZoLTGjZLnhQXi2s",
				ShortID:   "0123abcd",
			},
		},
	}
}

// findRealSingBoxBinary ищет настоящий (не «поддельный») бинарник sing-box для тестов,
// которым нужен реальный разбор конфигурации (`sing-box check`), а не структура Go.
//
// Находка 2026-08-10 (приёмка Э-Выход-1): TunOptions.DNSHijack — поле, которого у
// sing-box 1.13.16 давно нет (option.TunInboundOptions) — жило в config_builder.go
// НЕЗАМЕЧЕННЫМ, потому что ни один существующий тест не гонял TUN-конфигурацию через
// настоящий бинарник. TestInProcessRunner_StartWithRealConfig_DoesNotPanic намеренно
// без inbound'ов (см. её комментарий), «поддельные» файлы в TestProcessIsInstalledTrue и
// подобных — не исполняются вовсе. Этот файл закрывает именно этот пробел.
//
// Путь ищется по порядку: переменная окружения APF_SINGBOX_BIN (явное указание) → рядом
// с уже собранным Process (обычные каталоги стенда). Если бинарника нет нигде — тест
// пропускается ЯВНО (t.Skip с причиной), а не молчит: отсутствие реального бинарника на
// машине разработки — обычное дело, не повод притворяться, что проверка прошла.
func findRealSingBoxBinary(t *testing.T) string {
	t.Helper()

	binName := "sing-box"
	if runtime.GOOS == "windows" {
		binName = "sing-box.exe"
	}

	if p := os.Getenv("APF_SINGBOX_BIN"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	candidates := []string{
		filepath.Join(`D:\APF-Stand\singbox-standup`, binName),
		filepath.Join(`D:\APF-Stand\phone`, binName),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}

	t.Skip("реальный бинарник sing-box не найден (APF_SINGBOX_BIN не задан и не найден в " +
		"стандартных каталогах стенда) — тест схемы конфигурации пропущен, не провален")
	return ""
}

// Регрессия на находку 2026-08-10: TUN-конфигурация, которую строит Builder, обязана
// проходить `sing-box check` РЕАЛЬНОГО бинарника целевой версии (SingBoxVersion) — не
// только собираться в Go-структуру. Ловит расхождение схемы (поля, которых больше нет, или
// ещё нет) ДО устройства, а не после часов приёмки на телефоне.
func TestTUNConfig_RealBinaryAcceptsSchema(t *testing.T) {
	bin := findRealSingBoxBinary(t)

	b := NewBuilder(10808, true)
	cfg, err := b.BuildSingle(testVLESSNode())
	if err != nil {
		t.Fatalf("BuildSingle: %v", err)
	}

	data, err := ToJSON(cfg)
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "current.json")
	if err := os.WriteFile(cfgPath, data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := exec.Command(bin, "check", "-c", cfgPath).CombinedOutput()
	if err != nil {
		t.Fatalf("`sing-box check` отверг TUN-конфигурацию, которую строит Builder: %v\n%s",
			err, out)
	}
}

// Тот же контракт для конфигурации БЕЗ TUN (обычный режим «прокси») — убеждается, что
// починка TUN-схемы не сломала путь, который и так работал.
func TestProxyConfig_RealBinaryAcceptsSchema(t *testing.T) {
	bin := findRealSingBoxBinary(t)

	b := NewBuilder(10808, false)
	cfg, err := b.BuildSingle(testVLESSNode())
	if err != nil {
		t.Fatalf("BuildSingle: %v", err)
	}

	data, err := ToJSON(cfg)
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "current.json")
	if err := os.WriteFile(cfgPath, data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := exec.Command(bin, "check", "-c", cfgPath).CombinedOutput()
	if err != nil {
		t.Fatalf("`sing-box check` отверг конфигурацию режима «прокси»: %v\n%s", err, out)
	}
}

// Тот же контракт для серверной (роль «Выход», Э-Выход-1) конфигурации — подтверждено
// живым прогоном 2026-08-10 (собственный тестовый сервер + adb reverse), здесь закрепляется
// постоянной регрессией.
func TestServerConfig_RealBinaryAcceptsSchema(t *testing.T) {
	bin := findRealSingBoxBinary(t)

	identity, err := GenerateServerIdentity()
	if err != nil {
		t.Fatalf("GenerateServerIdentity: %v", err)
	}
	doc := BuildServerConfig(identity, 28444, "www.microsoft.com")

	data, err := ToServerJSON(doc)
	if err != nil {
		t.Fatalf("ToServerJSON: %v", err)
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "current.json")
	if err := os.WriteFile(cfgPath, data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := exec.Command(bin, "check", "-c", cfgPath).CombinedOutput()
	if err != nil {
		t.Fatalf("`sing-box check` отверг серверную (Выход) конфигурацию: %v\n%s", err, out)
	}
}
