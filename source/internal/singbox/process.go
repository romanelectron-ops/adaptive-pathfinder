package singbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/netguard"
)

// SingBoxVersion — версия sing-box: и для автозагрузки на десктопе, и для нативной
// библиотеки Android (её кладёт tools/android/fetch_singbox.ps1, читая эту же константу).
//
// ВЕРСИЯ СВЯЗАНА СО СБОРЩИКОМ КОНФИГУРАЦИИ, а не выбирается свободно (дефект D-A27).
// config_builder.go выдаёт схему sing-box 1.12+: DNS-серверы с полем "type" вместо
// legacy "address", поля TUN инлайном в inbound (1.11+), "action": "reject" в правилах
// DNS (1.12+). Бинарник старее этих версий откажется разбирать конфигурацию целиком:
//
//	FATAL decode config at current.json: dns.servers[0].type: json: unknown field "type"
//
// Было закреплено 1.9.4 при сборщике на 1.12+, и подключение не поднималось НИ РАЗУ —
// ни на телефоне, ни на десктопе. Тесты этого не ловили: они не запускали настоящий
// бинарник против настоящей конфигурации. Теперь ловит TestGeneratedConfig_BinaryAccepts.
//
// При смене версии обязательно: пересобрать nativeLib для Android
// (tools\android\fetch_singbox.ps1 -Apply) и прогнать тот самый тест.
const SingBoxVersion = "1.13.16"

// Process управляет жизненным циклом sing-box процесса
type Process struct {
	binPath    string
	configPath string
	cmd        *exec.Cmd
	mu         sync.Mutex
	running    bool
	logCh      chan string
	OnLog      func(string)

	// readyPort — локальный порт, по открытию которого судим о готовности (дефект D-A31).
	// Заполняется в WriteConfig из самой конфигурации; 0 означает «признака готовности нет»
	// (чистый TUN-режим без входящих портов) — тогда остаётся прежнее поведение.
	readyPort int
	// controllerAddr — "host:port" Clash API текущего конфига (TZ_SINGBOX_HOTSWITCH_
	// WINDOWS_v1.0), тем же приёмом, что и readyPort: заполняется в WriteConfig из самой
	// конфигурации, "" — контроллер не объявлен (SwitchOutbound в этом случае обязан
	// отказать, а не гадать порт). Пул-конфиги (BuildPool) объявляют его всегда через
	// baseConfig; одиночные пробы (node_check.go) могут не объявлять вовсе.
	controllerAddr string
	// exitCh закрывается наблюдателем, когда процесс завершился. Канал, а не флаг: Start
	// держит мьютекс до конца, и наблюдатель до него всё равно не достучится.
	exitCh chan struct{}

	// outTail — последние строки вывода sing-box ТЕКУЩЕГО запуска: по ним classifyEarlyExit
	// отличает «конфиг узла отвергнут» от «не занялся локальный порт/TUN» (ТЗ HOTSWITCH §8 A1).
	// Свой мьютекс: пишут горячие горутины копирования вывода, пока Start держит p.mu.
	outMu   sync.Mutex
	outTail []string
}

// outTailMax — сколько последних строк вывода хранить для классификации раннего выхода.
// FATAL sing-box — последняя строка перед смертью; запас на сопутствующие предупреждения.
const outTailMax = 20

func (p *Process) resetOutTail() {
	p.outMu.Lock()
	p.outTail = p.outTail[:0]
	p.outMu.Unlock()
}

// captureOutput — приёмник строк вывода sing-box: запоминает хвост и передаёт строку в журнал.
func (p *Process) captureOutput(line string) {
	p.outMu.Lock()
	p.outTail = append(p.outTail, line)
	if len(p.outTail) > outTailMax {
		p.outTail = append(p.outTail[:0], p.outTail[len(p.outTail)-outTailMax:]...)
	}
	p.outMu.Unlock()
	p.log(line)
}

func (p *Process) outTailSnapshot() []string {
	p.outMu.Lock()
	defer p.outMu.Unlock()
	return append([]string(nil), p.outTail...)
}

// NewProcess создаёт менеджер процесса для КЛИЕНТСКОГО sing-box (конфиг current.json).
func NewProcess(binDir, dataDir string) *Process {
	return NewProcessNamed(binDir, dataDir, "current.json")
}

// NewProcessNamed — то же, но с явным именем файла конфигурации.
//
// Нужно, потому что на Windows одновременно могут работать ДВЕ независимые роли: клиент
// («Вход») и сервер («Выход»). ТЗ прямо требует, чтобы включение одной не выключало другую.
// Пока обе роли использовали NewProcess, они делили один current.json, и это ломалось
// детерминированно, а не только в гонке: запуск роли «Выход» затирал конфиг работающего
// клиента, а следующее переподключение клиента поднимало его уже с СЕРВЕРНЫМ конфигом.
// Плюс гонка: клиентский путь защищён connMu, серверный — своим serverRoleMu, общего замка
// между ними нет, поэтому запись одного могла вклиниться между WriteConfig и Start другого.
// Разные файлы убирают саму возможность пересечения (найдено проверкой 2026-08-24).
func NewProcessNamed(binDir, dataDir, configName string) *Process {
	binName := binaryName(processGOOS())
	return &Process{
		binPath:    filepath.Join(binDir, binName),
		configPath: filepath.Join(dataDir, configName),
		logCh:      make(chan string, 256),
	}
}

// binaryName возвращает имя файла sing-box для платформы.
//
// Android — особый случай: с версии 10 (API 29) выполнение файлов из каталога данных
// приложения запрещено (W^X). Единственный каталог, откуда запуск разрешён, — это
// nativeLibraryDir, а туда упаковщик кладёт только файлы вида lib*.so. Поэтому на Android
// бинарник sing-box поставляется в APK как jniLibs/<abi>/libsingbox.so и запускается оттуда;
// это не библиотека, а обычный исполняемый файл под маскировочным именем.
func binaryName(goos string) string {
	switch goos {
	case "windows":
		return "sing-box.exe"
	case "android":
		return "libsingbox.so"
	default:
		return "sing-box"
	}
}

// IsInstalled проверяет наличие бинарника
func (p *Process) IsInstalled() bool {
	_, err := os.Stat(p.binPath)
	return err == nil
}

// BinPath — полный путь до бинарника sing-box, которым управляет этот Process. Нужен
// windowsServerRunner, чтобы завести файрвол-разрешение именно на РЕАЛЬНО используемый
// exe (см. EnsureInboundFirewallRule в windows_server_runner.go) — путь известен только
// здесь (собран из binDir в NewProcessNamed), наружу раньше не отдавался.
func (p *Process) BinPath() string { return p.binPath }

// Version возвращает версию установленного sing-box
func (p *Process) Version() (string, error) {
	out, err := exec.Command(p.binPath, "version").Output()
	if err != nil {
		return "", err
	}
	// "sing-box version 1.9.4\n..."
	line := strings.Split(string(out), "\n")[0]
	parts := strings.Fields(line)
	if len(parts) >= 3 {
		return parts[2], nil
	}
	return string(out), nil
}

// Download скачивает sing-box с GitHub Releases
func (p *Process) Download(ctx context.Context, onProgress func(pct int)) error {
	url := buildDownloadURL(SingBoxVersion)
	p.log(fmt.Sprintf("Downloading sing-box v%s...", SingBoxVersion))
	p.log(fmt.Sprintf("URL: %s", url))

	// Создаём директорию
	if err := os.MkdirAll(filepath.Dir(p.binPath), 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// Скачиваем архив во временный файл
	tmpFile, err := os.CreateTemp("", "singbox-*.zip")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := procHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}

	total := resp.ContentLength
	var downloaded int64

	reader := &progressReader{
		r:     resp.Body,
		total: total,
		onProgress: func(n int64) {
			downloaded += n
			if total > 0 && onProgress != nil {
				onProgress(int(downloaded * 100 / total))
			}
		},
	}

	if _, err := io.Copy(tmpFile, reader); err != nil {
		return fmt.Errorf("download write: %w", err)
	}

	// Распаковываем
	p.log("Extracting sing-box...")
	if err := extractBinary(tmpFile.Name(), p.binPath); err != nil {
		return fmt.Errorf("extract: %w", err)
	}

	// chmod на Linux/macOS
	if runtime.GOOS != "windows" {
		os.Chmod(p.binPath, 0755)
	}

	ver, _ := p.Version()
	p.log(fmt.Sprintf("sing-box installed: %s", ver))
	return nil
}

// WriteConfig записывает конфиг во временный файл
func (p *Process) WriteConfig(cfg *Config) error {
	data, err := ToJSON(cfg)
	if err != nil {
		return err
	}
	if err := p.writeConfigFile(data); err != nil {
		return err
	}
	p.mu.Lock()
	p.readyPort = readinessPort(cfg)
	p.controllerAddr = controllerAddress(cfg)
	p.mu.Unlock()
	return nil
}

// WriteRawConfig — то же самое, что WriteConfig, но для конфигурации, которая не является
// клиентским *Config (docs/TZ_APF_VHOD_VYHOD_v1.0.md §10: серверный inbound — новый JSON-код,
// не обвязка вокруг ToJSON/readinessPort, которые заточены под socks/http/tun-инбаунды
// клиента). readyPort передаётся явно — у вызывающей стороны (ServerRunner) он и так уже
// известен (порт, на котором сама же сгенерировала inbound), интроспекция JSON не нужна.
//
// Остальной жизненный цикл (Start/Stop/validate — «sing-box check/run -c configPath») не
// различает, откуда взялся файл: это уже подтверждено в WriteConfig, здесь переиспользуется
// без изменений.
func (p *Process) WriteRawConfig(data []byte, readyPort int) error {
	if err := p.writeConfigFile(data); err != nil {
		return err
	}
	p.mu.Lock()
	p.readyPort = readyPort
	p.mu.Unlock()
	return nil
}

// writeConfigFile — находка консилиума 2026-08-10 (low) + решение владельца проекта
// 2026-08-11 (см. docs/TZ_REALITY_KEY_PROTECTION_2026-08-11.md): для роли «Выход» этот
// файл несёт Reality private key звена в открытом виде. os.WriteFile(...,0600) на Windows
// НЕ создаёт реальной ACL-защиты (0600 — POSIX-биты, Windows использует NTFS ACL, это
// разные механизмы) — сознательно принятый риск, а не забытый TODO: роль «Выход»
// запускается ТОЛЬКО как обычное десктоп-приложение под аккаунтом пользователя (не
// Windows-служба), поэтому каталог данных уже наследует ACL профиля пользователя
// (%APPDATA%\APF), недоступного другим локальным учёткам без прав администратора. Если
// это когда-нибудь изменится (роль «Выход» как служба SCM/другая системная учётка) —
// нужна явная ACL-рестрикция через icacls, см. ТЗ выше, вариант 1.
func (p *Process) writeConfigFile(data []byte) error {
	dir := filepath.Dir(p.configPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(p.configPath, data, 0600)
}

// readinessPort выбирает порт, по которому видно, что sing-box действительно поднялся.
//
// Вход:      конфигурация.
// Тело:      среди входящих ищется первый локальный TCP-порт, socks предпочтительнее.
// Выход:     номер порта либо 0, если публиковать нечего.
// Fail-safe: 0 — признака нет, готовность не проверяется (прежнее поведение).
// Инвариант: возвращается только порт, который sing-box обязан открыть при успешном старте.
func readinessPort(cfg *Config) int {
	if cfg == nil {
		return 0
	}
	fallbackPort := 0
	for _, in := range cfg.Inbounds {
		if in.ListenPort <= 0 {
			continue
		}
		if in.Type == "socks" {
			return in.ListenPort
		}
		if fallbackPort == 0 {
			fallbackPort = in.ListenPort
		}
	}
	return fallbackPort
}

// controllerAddress достаёт "host:port" Clash API из конфигурации (TZ_SINGBOX_HOTSWITCH_
// WINDOWS_v1.0) — тот же приём, что readinessPort: значение читается из УЖЕ построенного
// конфига, а не пересобирается по отдельным правилам где-то ещё.
//
// Выход: адрес либо "", если clash_api в конфиге не объявлен (SwitchOutbound обязан
// отказать явной ошибкой в этом случае, а не пытаться угадать порт).
func controllerAddress(cfg *Config) string {
	if cfg == nil || cfg.Experimental == nil || cfg.Experimental.ClashAPI == nil {
		return ""
	}
	return cfg.Experimental.ClashAPI.ExternalController
}

// Start запускает sing-box с текущим конфигом
func (p *Process) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return fmt.Errorf("already running")
	}
	if !p.IsInstalled() {
		return localStartError(fmt.Errorf("sing-box not found at %s", p.binPath))
	}

	// ТЗ HOTSWITCH §8 A5: отдельного процесса `sing-box check` перед запуском больше нет.
	// Он удваивал число создаваемых процессов на КАЖДУЮ попытку (живой лог ПК 2026-09-21: 16 из
	// 16 стартов шли ≥10.8с, половина времени — на check), а защиты не давал: отвергнутую
	// конфигурацию `run` отвергает сам и умирает за десятки миллисекунд — это ловит awaitReady
	// (ранний выход) и классифицирует по FATAL-строке. В Reload check к тому же шёл уже ПОСЛЕ
	// Stop(), то есть работающий экземпляр он не спасал никогда.
	p.resetOutTail()
	p.cmd = exec.CommandContext(ctx, p.binPath, "run", "-c", p.configPath)

	// Перехватываем stdout/stderr
	p.cmd.Stdout = &logWriter{prefix: "[sing-box] ", fn: p.captureOutput}
	p.cmd.Stderr = &logWriter{prefix: "[sing-box] ", fn: p.captureOutput}

	if err := p.cmd.Start(); err != nil {
		// ОС не создала процесс — к данным узла это отношения не имеет.
		p.cmd = nil
		return localStartError(fmt.Errorf("start sing-box: %w", err))
	}

	p.running = true
	p.exitCh = make(chan struct{})
	p.log(fmt.Sprintf("sing-box started (PID %d)", p.cmd.Process.Pid))

	go p.watchProcess()

	return p.awaitReady(ctx)
}

// awaitReady — дожидается, пока sing-box действительно начнёт работать (дефект D-A31).
//
// Вход:      запущенный процесс и readyPort из конфигурации.
// Тело:      опрос порта до готовности, до смерти процесса или до истечения срока.
// Выход:     nil, только если порт принял соединение.
// Fail-safe: процесс умер или срок вышел → ошибка, процесс добивается. Молчаливого
//
//	«ну наверное поднялось» не остаётся ни в одной ветке.
//
// Инвариант: Start возвращает nil, только если туннель на этот момент жив.
//
// Что здесь было. Стояло startSleepFn(2 * time.Second); return nil — две секунды сна и
// безусловный успех. Ошибка конфигурации убивает sing-box за 30 мс, но ответ всё равно
// приходил положительный, и движок объявлял «Connected! SOCKS5→127.0.0.1:10808». Ровно это
// и наблюдалось на устройстве (лог 08-05 16:04:46–48): FATAL, «sing-box exited: exit status 1»,
// а через две миллисекунды — «Connected!». Дальше срабатывал детектор утечек и честно писал,
// что туннеля нет, но состояние подключения уже было объявлено успешным.
//
// Это прямое нарушение D-2 (fail-closed): отказ обязан выглядеть как отказ. Пользователь,
// увидевший «Connected», начинает пользоваться сетью, считая её защищённой.
//
// Держать мьютекс всё это время допустимо: Start и так владел им целиком, а Stop/IsRunning
// на время старта обязаны ждать — иначе они увидят полусостояние.
func (p *Process) awaitReady(ctx context.Context) error {
	if p.readyPort <= 0 {
		// Признака готовности нет (например, чистый TUN без входящих портов) — остаётся
		// прежняя пауза. Лучше, чем выдумывать проверку, которой нечем распорядиться.
		startSleepFn(2 * time.Second)
		// Но умерший за эту паузу процесс — всё равно отказ: раньше его ловил отдельный
		// `sing-box check` (снят, ТЗ HOTSWITCH §8 A5), теперь — эта проверка.
		select {
		case <-p.exitCh:
			return p.earlyExitLocked()
		default:
		}
		return nil
	}

	deadline := timeNowFn().Add(ReadyTimeout)
	for {
		select {
		case <-p.exitCh:
			return p.earlyExitLocked()
		case <-ctx.Done():
			p.killLocked()
			// Локальный класс: к узлу при старте никто не ходил. Причина (ctx.Err) остаётся в
			// цепочке — движок по errors.Is(err, context.Canceled) отличает свою же отмену
			// (Stop/Restart — «без суждения») от истёкшего срока пробы.
			return localStartError(fmt.Errorf("запуск sing-box прерван: %w", ctx.Err()))
		default:
		}

		if err := readyProbeFn(p.readyPort); err == nil {
			return nil
		}

		if timeNowFn().After(deadline) {
			p.killLocked()
			return readyTimeoutError(fmt.Errorf("sing-box не открыл локальный порт %d за %s: процесс запущен, "+
				"но входящих соединений не принимает", p.readyPort, ReadyTimeout))
		}
		startSleepFn(readyPollInterval)
	}
}

// earlyExitLocked — процесс умер сразу после запуска: сбрасывает состояние и возвращает
// классифицированную ошибку (classifyEarlyExit по его же последней FATAL-строке).
func (p *Process) earlyExitLocked() error {
	p.running = false
	p.cmd = nil
	base := errors.New("sing-box завершился сразу после запуска — причина в строках " +
		"[sing-box] выше по журналу (обычно отвергнутая конфигурация)")
	if errors.Is(classifyEarlyExit(p.outTailSnapshot()), ErrLocalStart) {
		return localStartError(base)
	}
	return configRejectedError(base)
}

// killLocked добивает процесс, когда старт признан неудачным. Вызывается только из-под
// уже взятого мьютекса, поэтому Stop() здесь не годится — он берёт тот же мьютекс.
func (p *Process) killLocked() {
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	p.running = false
	p.cmd = nil
}

// Stop останавливает sing-box
func (p *Process) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running || p.cmd == nil {
		return nil
	}

	p.log("Stopping sing-box...")

	if p.cmd.Process != nil {
		if err := p.cmd.Process.Kill(); err != nil {
			return err
		}
	}

	p.running = false
	p.cmd = nil
	p.log("sing-box stopped")
	return nil
}

// Reload — горячая перезагрузка конфига (Hot-Swap)
// Записывает новый конфиг и перезапускает процесс
func (p *Process) Reload(ctx context.Context, cfg *Config) error {
	p.log("Hot-swapping config...")

	if err := p.WriteConfig(cfg); err != nil {
		return localStartError(err) // запись файла конфигурации на диск — сторона машины
	}

	// sing-box поддерживает SIGHUP для reload на Linux
	// На Windows — перезапуск
	if reloadGOOS() == "windows" {
		if err := p.Stop(); err != nil {
			return localStartError(err)
		}
		reloadSleepFn(500 * time.Millisecond)
		return p.Start(ctx)
	}

	// Linux/macOS: SIGHUP — стандартный сигнал перезагрузки конфига
	p.mu.Lock()
	if p.cmd != nil && p.cmd.Process != nil {
		p.cmd.Process.Signal(syscall.SIGHUP)
	}
	p.mu.Unlock()

	return nil
}

// switchTimeout — сколько ждать ответа Clash API на переключение (TZ_SINGBOX_HOTSWITCH_
// WINDOWS_v1.0). Короткий НАМЕРЕННО: локальный HTTP-запрос к уже живому процессу занимает
// миллисекунды; если контроллер не отвечает за секунды — это ПРИЗНАК, что с уже запущенным
// процессом что-то не так, и вызывающая сторона обязана откатиться на обычный Reload
// (Stop+Start), а не ждать дольше в надежде, что «само пройдёт».
var switchTimeout = 2 * time.Second

// switchOutboundFn — реальный HTTP-вызов Clash API. var, а не метод: swap на фейк в тестах
// без реального sing-box (тот же приём, что у readyProbeFn выше).
var switchOutboundFn = func(controllerAddr, selectorTag, targetTag string, timeout time.Duration) error {
	body, err := json.Marshal(map[string]string{"name": targetTag})
	if err != nil {
		return fmt.Errorf("switchOutbound: marshal request: %w", err)
	}
	url := fmt.Sprintf("http://%s/proxies/%s", controllerAddr, selectorTag)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("switchOutbound: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("switchOutbound: clash api недоступен: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("switchOutbound: clash api вернул %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// SwitchOutbound переключает активный узел уже запущенной группы-селектора через Clash API
// (PUT /proxies/{selectorTag}), БЕЗ Stop/Start — единственная цель существования этого
// метода (TZ_SINGBOX_HOTSWITCH_WINDOWS_v1.0, RCA «5 почему»): на реальной машине пользователя
// Reload() на Windows пересоздаёт процесс sing-box.exe на КАЖДОЕ переключение (нет SIGHUP),
// и создание нового процесса ОС давало задержки 20-68с ~12 раз за сессию.
//
// Вход:      selectorTag — тег группы (у APF всегда "proxy", тот же якорь route/kill switch,
//
//	что у BuildSingle/BuildRace/BuildPool); targetTag — тег кандидата ВНУТРИ уже
//	загруженной группы (BuildPool.Outbounds).
//
// Тело:      HTTP PUT к контроллеру, взятому из ПОСЛЕДНЕГО записанного конфига (WriteConfig
//
//	→ controllerAddr). Не пытается угадать порт заново — если конфиг не объявлял
//	clash_api, отказывает сразу, не отправляя запрос в никуда.
//
// Выход:     nil — переключение подтверждено сервером; иначе ошибка.
// Fail-safe: ЛЮБАЯ ошибка здесь (контроллер не объявлен, процесс не запущен, таймаут,
//
//	неожиданный статус-код) — сигнал вызывающей стороне откатиться на обычный
//	Reload (Stop+Start). Этот метод НИКОГДА сам не убивает и не перезапускает
//	процесс — в отличие от awaitReady/killLocked, здесь нет частичного состояния,
//	которое нужно было бы подчищать: процесс как был жив, так и остаётся жив.
func (p *Process) SwitchOutbound(ctx context.Context, selectorTag, targetTag string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return errors.New("switchOutbound: sing-box не запущен")
	}
	if p.controllerAddr == "" {
		return errors.New("switchOutbound: clash_api не объявлен в текущем конфиге")
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf("switchOutbound: отменено: %w", ctx.Err())
	default:
	}

	if err := switchOutboundFn(p.controllerAddr, selectorTag, targetTag, switchTimeout); err != nil {
		return err
	}
	p.log(fmt.Sprintf("switchOutbound: %s -> %s (без пересоздания процесса)", selectorTag, targetTag))
	return nil
}

// IsRunning возвращает текущее состояние процесса
func (p *Process) IsRunning() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running
}

func (p *Process) watchProcess() {
	cmd, exited := p.cmd, p.exitCh
	if cmd == nil {
		return
	}
	err := cmd.Wait()
	// Сначала будим ожидающего в awaitReady, и только потом идём за мьютекс: мьютекс всё
	// это время держит Start, и порядок «сначала лок» означал бы взаимную блокировку.
	if exited != nil {
		close(exited)
	}
	p.mu.Lock()
	p.running = false
	p.mu.Unlock()
	if err != nil {
		p.log(fmt.Sprintf("sing-box exited: %v", err))
	} else {
		p.log("sing-box exited normally")
	}
}

func (p *Process) log(msg string) {
	if p.OnLog != nil {
		p.OnLog(msg)
	}
}

// ─── URL для скачивания ───────────────────────────────────────────────────────

// Injection vars — overridden in tests to exercise OS/network branches.
var (
	processGOOS = func() string { return runtime.GOOS }
	// netguard вместо http.DefaultClient — см. httpClientForDownload (Т-5).
	procHTTPClient = netguard.Client(0)
	startSleepFn   = time.Sleep
	reloadGOOS     = func() string { return runtime.GOOS }
	reloadSleepFn  = time.Sleep
	timeNowFn      = time.Now

	// readyProbeFn — проба готовности (дефект D-A31). Пробуем именно соединиться, а не
	// «занят ли порт»: занятость означала бы лишь, что кто-то слушает, а нам нужно
	// подтверждение, что слушает поднявшийся sing-box и он принимает соединения.
	//
	// netguard здесь не нужен и был бы вреден: адрес заведомо петлевой, а барьер
	// проверяет именно выход в сеть (см. internal/netguard).
	readyProbeFn = func(port int) error {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), readyDialTimeout)
		if err != nil {
			return err
		}
		return conn.Close()
	}
)

// ReadyTimeout — сколько ждать, пока sing-box откроет свой порт (дефект D-A31).
//
// На устройстве от «sing-box started» до «tcp server started» проходит порядка 10 мс, а живой
// отказ конфигурации приходит ещё быстрее (его ловит ранний выход, не этот срок). Ожидание почти
// всегда заканчивается на первой же пробе; срок нужен только для медленной техники.
//
// 30 с, а не прежние 10 (ТЗ HOTSWITCH §8 A4): на ПК пользователя 2026-09-21 единственный
// удачный старт открыл порт через 8.76 с после PID, а все провалы обрезались ровно на 10.1 с —
// то есть срок резал живые, но медленные запуски. Цены у запаса нет: здоровый старт выходит
// на первой пробе, мёртвый процесс ловится ранним выходом, отмена — контекстом.
var ReadyTimeout = 30 * time.Second

const (
	readyPollInterval = 150 * time.Millisecond
	readyDialTimeout  = 700 * time.Millisecond
)

func buildDownloadURL(version string) string {
	goos := processGOOS()
	goarch := runtime.GOARCH

	// Маппинг arch
	archMap := map[string]string{
		"amd64": "amd64",
		"arm64": "arm64",
		"386":   "386",
		"arm":   "armv7",
	}
	arch, ok := archMap[goarch]
	if !ok {
		arch = goarch
	}

	// Имя архива
	var archiveName string
	switch goos {
	case "windows":
		archiveName = fmt.Sprintf("sing-box-%s-windows-%s.zip", version, arch)
	case "darwin":
		archiveName = fmt.Sprintf("sing-box-%s-darwin-%s.tar.gz", version, arch)
	default: // linux, android
		archiveName = fmt.Sprintf("sing-box-%s-linux-%s.tar.gz", version, arch)
	}

	return fmt.Sprintf(
		"https://github.com/SagerNet/sing-box/releases/download/v%s/%s",
		version, archiveName,
	)
}

// extractBinary — распаковывает sing-box из zip или tar.gz
func extractBinary(archivePath, destPath string) error {
	if strings.HasSuffix(archivePath, ".zip") {
		return extractZip(archivePath, destPath)
	}
	return extractTarGz(archivePath, destPath)
}

// extractZip и extractTarGz — старый shell-based путь распаковки (недостижим из
// production-кода: engine.go пользуется исключительно Downloader.Download из downloader.go,
// который делает то же самое через archive/zip/archive/tar, без этой проблемы — см. TODO
// ниже, оставшийся с тех пор, как downloader.go его и заменил). Держится ради
// Process.Download (используется только в тестах пакета) — исправлен на месте, а не удалён,
// чтобы не расширять эту правку до чистки мёртвого кода.
func extractZip(src, dest string) error {
	// Используем unzip через shell на системах где он есть
	// В production — заменить на archive/zip
	binName := filepath.Base(dest)
	tmpDir := filepath.Dir(dest) + "\\tmp_extract"
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`Expand-Archive -Path "%s" -DestinationPath "%s" -Force; `+
			`Copy-Item "%s\*\%s" "%s"`,
			src, tmpDir, tmpDir, binName, dest,
		),
	)
	out, err := cmd.CombinedOutput()
	// Чистим временную папку независимо от исхода — неудачная Copy-Item может оставить
	// частично распакованное дерево, мешающее следующей попытке.
	defer os.RemoveAll(tmpDir)
	if err != nil {
		return fmt.Errorf("extract zip: %w\n%s", err, out)
	}
	// Находка консилиума 2026-08-10 (low): Expand-Archive и Copy-Item соединены через ";"
	// (безусловный разделитель PowerShell, не "&&") — если Copy-Item отказал (например,
	// wildcard "*\binName" не совпал с реальной структурой архива), по умолчанию пишется
	// non-terminating error в поток ошибок, а код возврата процесса powershell при этом
	// остаётся 0. cmd.CombinedOutput() вернул бы err=nil, хотя dest так и не появился —
	// Process.Download() посчитал бы установку успешной. Явная проверка результата, а не
	// только кода возврата процесса, закрывает этот путь молчаливого отказа.
	if _, statErr := os.Stat(dest); statErr != nil {
		return fmt.Errorf("extract zip: %s не появился после распаковки (output: %s)", dest, out)
	}
	return nil
}

func extractTarGz(src, dest string) error {
	binName := filepath.Base(dest)
	dir := filepath.Dir(dest)
	cmd := exec.Command("sh", "-c",
		fmt.Sprintf(`tar xzf "%s" -C "%s" --wildcards "*/sing-box" 2>/dev/null && `+
			`find "%s" -name "%s" -not -path "%s" | head -1 | xargs -I{} mv {} "%s"`,
			src, dir, dir, binName, dest, dest,
		),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("extract tar.gz: %w\n%s", err, out)
	}
	// Тот же класс отказа, что у extractZip выше: `find | head -1 | xargs -I{} mv` при
	// пустом результате find ничего не делает и завершается кодом 0.
	if _, statErr := os.Stat(dest); statErr != nil {
		return fmt.Errorf("extract tar.gz: %s не появился после распаковки (output: %s)", dest, out)
	}
	return nil
}

// ─── Вспомогательные типы ─────────────────────────────────────────────────────

type progressReader struct {
	r          io.Reader
	total      int64
	onProgress func(int64)
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.r.Read(p)
	if n > 0 {
		pr.onProgress(int64(n))
	}
	return n, err
}

type logWriter struct {
	prefix string
	fn     func(string)
	buf    []byte
}

func (lw *logWriter) Write(p []byte) (int, error) {
	lw.buf = append(lw.buf, p...)
	for {
		idx := -1
		for i, b := range lw.buf {
			if b == '\n' {
				idx = i
				break
			}
		}
		if idx < 0 {
			break
		}
		line := string(lw.buf[:idx])
		lw.buf = lw.buf[idx+1:]
		if lw.fn != nil && strings.TrimSpace(line) != "" {
			lw.fn(lw.prefix + line)
		}
	}
	return len(p), nil
}
