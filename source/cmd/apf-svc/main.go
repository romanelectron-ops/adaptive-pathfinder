// cmd/apf-svc — APF Windows Service.
// Запускается как системная служба Windows, работает в фоне без UI.
//
// Установка:
//
//	apf-svc.exe install    — регистрирует службу
//	apf-svc.exe start      — запускает службу
//	apf-svc.exe stop       — останавливает службу
//	apf-svc.exe remove     — удаляет службу
//	apf-svc.exe status     — показывает статус
//	apf-svc.exe run        — запускает напрямую (для отладки)
//
// Сборка:
//
//	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H windowsgui" -o apf-svc.exe ./cmd/apf-svc
package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/engine"
	"github.com/apf/adaptive-pathfinder/internal/killswitch"
	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/singleinstance"
	"github.com/apf/adaptive-pathfinder/internal/web"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	svcName        = "APFService"
	svcDisplayName = "APF Adaptive PathFinder"
	svcDesc        = "Intelligent VPN bypass service. Automatically finds and connects to the best available server."
)

// ─── S-8 (ТЗ v1.4): web.Server.Close() не вызывался ни одним владельцем процесса ───────────
//
// K2-W добавил Server.Close() (internal/web/server.go), но ни один владелец процесса
// (cmd/apf, cmd/apf-svc, cmd/apf-tray, gui/app.go) его не звал — фоновые горутины сервера
// (trackedGo, например apiCatalogRefresh) переживали остановку движка. webCloser/
// engineStopper — минимальные интерфейсы-швы: тест проверяет сам факт и порядок вызова без
// реальной службы Windows/сети (правило лота — бинарники не запускать).
type webCloser interface{ Close() }
type engineStopper interface{ Stop() }

// stopProcess — единая точка штатной остановки: сначала Web UI (если был поднят), потом
// движок (если он у этого процесса вообще есть — observer-режим apfService.Execute его не
// поднимает).
func stopProcess(webSrv webCloser, eng engineStopper) {
	if webSrv != nil {
		webSrv.Close()
	}
	if eng != nil {
		eng.Stop()
	}
}

// ─── Точка входа ─────────────────────────────────────────────────────────────

func main() {
	if len(os.Args) < 2 {
		// Запущен без аргументов — пробуем как службу
		runAsService()
		return
	}

	cmd := os.Args[1]
	switch cmd {
	case "install":
		installService()
	case "remove", "uninstall":
		removeService()
	case "start":
		startService()
	case "stop":
		stopService()
	case "status":
		showStatus()
	case "run":
		// Прямой запуск (отладка без регистрации как служба)
		runDirect()
	default:
		fmt.Printf("Использование: apf-svc.exe [install|remove|start|stop|status|run]\n")
		os.Exit(1)
	}
}

// ─── Запуск как Windows Service ───────────────────────────────────────────────

func runAsService() {
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("Failed to determine if running as service: %v", err)
	}

	if isService {
		// Запущен менеджером служб Windows
		if err := svc.Run(svcName, &apfService{}); err != nil {
			writeEventLog(fmt.Sprintf("Service failed: %v", err), eventlog.Error)
		}
	} else {
		// Запущен вручную без аргументов — подсказываем
		fmt.Println("APF Service. Use 'install' to register as Windows Service.")
		fmt.Println("Or use 'run' to start directly.")
	}
}

// ─── apfService — реализация svc.Handler ─────────────────────────────────────

type apfService struct{}

func (s *apfService) Execute(args []string, req <-chan svc.ChangeRequest, resp chan<- svc.Status) (ssec bool, errno uint32) {
	// Сообщаем что запускаемся
	resp <- svc.Status{State: svc.StartPending}

	elog := openEventLog()
	defer elog.Close()

	// openEventLog() может вернуть nil (журнал недоступен, ушли в файл), поэтому все НОВЫЕ
	// сообщения идут через эту обёртку, а не напрямую в elog.
	svcLog := func(m string) {
		if elog != nil {
			elog.Info(1, m)
		} else {
			log.Println(m)
		}
	}

	// Инициализируем APF. Загружаем сохранённый config.json ПОВЕРХ дефолтов — иначе
	// служба игнорирует настройки пользователя (например auto_connect:false) и всегда
	// использует голый DefaultConfig(); это и было корневой причиной инцидента
	// 2026-08-19 (см. docs/TZ_CONFIG_RELOAD_AND_KS_SAFETY_v1.0.md). AutoConnect больше
	// НЕ форсируется — служба обязана уважать реальный выбор пользователя, как и любой
	// другой процесс.
	cfg := models.DefaultConfig()
	resolvedConfigPath := config.ConfigPath()
	if found, err := config.LoadInto(cfg); err != nil {
		svcLog(fmt.Sprintf("Конфиг не загружен (%v), использую значения по умолчанию", err))
	} else if found {
		svcLog("Конфиг загружен: " + resolvedConfigPath)
	} else if userPath, ok := config.FindInteractiveUserConfigPath(); ok {
		// Служба работает от SYSTEM: её собственный %APPDATA% указывает на профиль SYSTEM,
		// а не на профиль реального пользователя, поэтому обычный ConfigPath() выше бьёт
		// мимо (found=false) даже когда файл реально существует. Найдено живым инцидентом
		// 2026-08-19 (docs/TZ_CONFIG_RELOAD_AND_KS_SAFETY_v1.0.md) — LoadInto() отработал
		// «успешно» (без ошибки), но искал не там, и служба тихо осталась на
		// DefaultConfig() (AutoConnect: true) несмотря на этот же самый фикс.
		if _, err := config.LoadIntoFrom(userPath, cfg); err != nil {
			svcLog(fmt.Sprintf("Конфиг пользователя не загружен (%v): %s", err, userPath))
		} else {
			svcLog("Конфиг пользователя загружен (профиль SYSTEM не видит его напрямую): " + userPath)
			resolvedConfigPath = userPath
		}
	}
	// ТЗ v1.3 F5.2: одна нормализация на всех точках входа — неверное значение = дефолт + WARN.
	for _, w := range cfg.Normalize() {
		svcLog("Конфиг: " + w)
	}

	// B-0403 · R-3.1 (C-2). Обратный порядок запуска (трей поднялся раньше службы) редок, но
	// возможен. Второй движок в этом случае не поднимаем: правила Kill Switch носят одинаковые
	// имена, и Disable любого из двух владельцев снял бы защиту у обоих.
	// Служба при этом остаётся полезной — именно она нужна трею как привилегированный
	// исполнитель KS по named-pipe (ServePipe ниже), и это движком не является.
	var eng *engine.Engine
	observer := false

	lock, siErr := singleinstance.AcquireEngine()
	switch {
	case errors.Is(siErr, singleinstance.ErrAlreadyRunning):
		observer = true
		cfg.AutoConnect = false
		svcLog("APF уже запущен другим процессом: служба НЕ поднимает движок и не выполняет " +
			"AutoConnect; работаем только как привилегированный исполнитель Kill Switch")
	case siErr != nil:
		// Fail-open: невозможность проверить — не повод оставлять систему без службы.
		svcLog(fmt.Sprintf("Проверка единственности экземпляра не удалась: %v (продолжаем)", siErr))
	default:
		defer lock.Close()
	}

	// webSrv — S-8 (ТЗ v1.4): захватывается через канал (не голым присваиванием общей
	// переменной из горутины), чтобы вызов Close() на пути остановки ниже не был гонкой данных
	// под `go test -race`. web.New() сам по себе не блокирует (это делает srv.Start()) —
	// синхронный приём из webStarted добавляет исчезающе малую задержку и убирает гонку.
	var webSrv *web.Server
	if !observer {
		// Каталог узлов/кэша (nodes_cache.json, cache.db, watchdog-история) должен следовать
		// за тем же профилем, что и resolvedConfigPath выше, а не за нативным %APPDATA%
		// процесса-службы (SYSTEM) — иначе служба и интерактивный пользователь видят два
		// разных nodes_cache.json на диске (P1.1, docs/TZ_WINDOWS_CONSILIUM_FINDINGS_v1.0.md).
		// Обязательно ДО engine.NewServiceHost(cfg) — dataDir прошивается в подкомпоненты
		// (singbox.NewProcess, killswitch.SetSentinelDir, bypass.NewManager и др.) в момент
		// конструктора, не при каждом последующем обращении к config.DataDir().
		config.SetDataDirOverride(filepath.Dir(resolvedConfigPath))
		// NewServiceHost (не New()): этот процесс сам обслуживает KS-пайп (ServePipe ниже) —
		// см. Engine.ksSelfService, P0.1 в docs/TZ_WINDOWS_CONSILIUM_FINDINGS_v1.0.md.
		eng = engine.NewServiceHost(cfg)
		eng.OnLog = svcLog
		// Настройки, сохранённые через PatchConfig/SaveConfig (панель GUI/веб-дашборд),
		// должны попадать в ТОТ ЖЕ файл, откуда конфиг был реально загружен выше — иначе
		// служба под SYSTEM писала бы изменения в свой собственный (недоступный
		// пользователю) профиль. См. docs/TZ_CONFIG_RELOAD_AND_KS_SAFETY_v1.0.md.
		eng.SetConfigSavePath(resolvedConfigPath)

		if err := eng.Start(); err != nil {
			if elog != nil {
				elog.Error(1, fmt.Sprintf("Engine start failed: %v", err))
			}
			resp <- svc.Status{State: svc.Stopped}
			return false, 1
		}

		// Запускаем Web UI
		webStarted := make(chan *web.Server, 1)
		go func() {
			srv := web.New(eng, cfg.WebUIPort)
			webStarted <- srv
			srv.Start()
		}()
		webSrv = <-webStarted
	}

	// Вариант A (B-0402.3): служебный KS-канал. Трей/CLI (НЕ admin) делегируют сюда Enable/Disable/
	// Recover, а мы под SYSTEM выполняем netsh без повторных UAC (D-32). Crash-recovery (D-33)
	// выполняет engine.Start → killswitch.RecoverIfNeeded под SYSTEM. Исполнитель — отдельный
	// killswitch.New() (наши права позволяют netsh напрямую).
	//
	// R-3.1: канал поднимается ДАЖЕ в режиме наблюдателя. ServePipe — не движок, он лишь
	// исполняет команды того единственного процесса, который владеет движком.
	ksStop := make(chan struct{})
	defer close(ksStop)
	ksLog := svcLog
	// Выбор бэкенда KS: по умолчанию netsh (провалидирован). WFP (B-0402.4) — опционально через
	// APF_KS_BACKEND=wfp (для приёмки на admin-стенде; ещё не runtime-верифицирован).
	var ksExec killswitch.KillSwitch = killswitch.New()
	if strings.EqualFold(os.Getenv("APF_KS_BACKEND"), "wfp") {
		if wfp, ok := killswitch.NewWFPBackend(); ok {
			ksExec = wfp
			// R-6.1: без логгера предупреждение «LUID туннеля ещё не разрешился» уходило бы
			// в никуда, а именно оно объясняет, почему трафик приложений заблокирован.
			killswitch.SetWFPLogger(ksLog)
			ksLog("KS backend: WFP (FWPM, экспериментальный)")
		}
	}
	go killswitch.ServePipe(ksStop, ksExec, ksLog)

	if observer {
		svcLog("APF Service started в режиме наблюдателя (движок принадлежит другому процессу)")
	} else {
		svcLog(fmt.Sprintf("APF Service started, Web UI: http://localhost:%d", cfg.WebUIPort))
	}

	// Сообщаем что работаем
	resp <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue,
	}

	// Обрабатываем команды от SCM
	for req := range req {
		switch req.Cmd {
		case svc.Interrogate:
			resp <- req.CurrentStatus

		case svc.Stop, svc.Shutdown:
			svcLog("APF Service stopping...")
			resp <- svc.Status{State: svc.StopPending}
			// S-8 (ТЗ v1.4): web.Server.Close() перед eng.Stop() — в режиме наблюдателя ни
			// движка, ни своего Web UI нет (оба остаются typed-nil-safe нетипизированным nil,
			// см. webCloser/engineStopper ниже), останавливать нечего.
			var closer webCloser
			if webSrv != nil {
				closer = webSrv
			}
			var stopper engineStopper
			if eng != nil {
				stopper = eng
			}
			stopProcess(closer, stopper)
			resp <- svc.Status{State: svc.Stopped}
			return false, 0

		case svc.Pause:
			if eng != nil {
				eng.Stop()
			}
			resp <- svc.Status{State: svc.Paused, Accepts: svc.AcceptStop | svc.AcceptPauseAndContinue}

		case svc.Continue:
			if eng != nil {
				_ = eng.Start()
			}
			resp <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue}
		}
	}

	return false, 0
}

// ─── Управление службой ───────────────────────────────────────────────────────

func installService() {
	exePath, err := os.Executable()
	if err != nil {
		fatalf("Cannot get executable path: %v", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		fatalf("Cannot connect to service manager: %v", err)
	}
	defer m.Disconnect()

	// StartManual, НЕ StartAutomatic — по прямому требованию пользователя
	// 2026-08-25: служба не должна тихо подниматься при каждой загрузке Windows
	// независимо от того, открывал ли пользователь приложение. Запуск теперь
	// инициирует сам GUI/трей при своём старте (см. ensureServiceStarted в
	// gui/servicestart.go и cmd/apf-tray/main.go) — служба живёт ровно пока
	// нужна приложению, а не как постоянный фоновый демон.
	wantConfig := mgr.Config{
		StartType:   mgr.StartManual,
		DisplayName: svcDisplayName,
		Description: svcDesc,
	}

	// Если служба уже зарегистрирована (апгрейд поверх старой установки) —
	// ПЕРЕКОНФИГУРИРОВАТЬ её, а не молча отступать. Раньше здесь был fatalf
	// «already exists», из-за чего апгрейд подменял только сам apf-svc.exe на
	// диске, а регистрация службы в SCM (в частности StartType) оставалась от
	// самого первого install — живой прогон 2026-08-25 поймал это ровно на
	// этом фиксе: бинарник обновился, StartType остался Automatic.
	//
	// ВАЖНО (пойман тем же живым прогоном, второй заход): нельзя просто
	// собрать mgr.Config{StartType: ..., DisplayName: ..., Description: ...}
	// и передать в UpdateConfig — она транслируется напрямую в Win32
	// ChangeServiceConfig(dwServiceType, dwStartType, dwErrorControl, ...), а
	// там 0 — это НЕ «не менять», это буквальный (невалидный) тип службы.
	// «Не менять» кодируется отдельной сигнальной константой
	// SERVICE_NO_CHANGE (windows.SERVICE_NO_CHANGE), которую голый
	// mgr.Config зачения не проставляет — нулевые поля Go-структуры уходят
	// в вызов как есть. Из-за этого первая версия фикса (без чтения текущего
	// конфига) молча проваливала ChangeServiceConfig целиком (невалидный
	// ServiceType=0), UpdateConfig возвращала ошибку, и StartType так и
	// оставался Automatic — именно это увидел пользователь при повторной
	// установке. Правильный путь — прочитать ТЕКУЩИЙ конфиг через s.Config()
	// и поменять в нём только нужные поля, остальное остаётся as-is.
	if s, err := m.OpenService(svcName); err == nil {
		defer s.Close()
		current, err := s.Config()
		if err != nil {
			fatalf("Cannot read existing service config: %v", err)
		}
		current.StartType = mgr.StartManual
		current.DisplayName = svcDisplayName
		current.Description = svcDesc
		current.BinaryPathName = exePath
		if err := s.UpdateConfig(current); err != nil {
			fatalf("Cannot update existing service config: %v", err)
		}
		fmt.Printf("✓ Служба '%s' переконфигурирована (StartType: Manual).\n", svcDisplayName)
		return
	}

	// Создаём службу заново (чистая установка).
	s, err := m.CreateService(svcName, exePath, wantConfig)
	if err != nil {
		fatalf("Cannot create service: %v", err)
	}
	defer s.Close()

	// Устанавливаем eventlog
	err = eventlog.InstallAsEventCreate(svcName, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		s.Delete()
		fatalf("Cannot install event log source: %v", err)
	}

	fmt.Printf("✓ Служба '%s' установлена.\n", svcDisplayName)
	fmt.Printf("  Запустить: apf-svc.exe start\n")
	fmt.Printf("  Или через: services.msc\n")
}

func removeService() {
	m, err := mgr.Connect()
	if err != nil {
		fatalf("Cannot connect to service manager: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		fatalf("Service %s not found: %v", svcName, err)
	}
	defer s.Close()

	// Сначала останавливаем — тот же баг, что был найден и исправлен в stopService()
	// (живой прогон 2026-08-19/20): фиксированный Sleep вместо ожидания настоящего
	// Stopped оставлял процесс ещё живым к моменту Delete(), и вызывающий код
	// (installer/apf.nsi Section "Uninstall": Delete "$INSTDIR\apf-svc.exe" сразу
	// после ExecWait remove) натыкался на залоченный файл — NSIS в /S тихо
	// пропускал удаление файла и, как следствие, RMDir каталога, оставляя службу
	// (до её собственного отложенного удаления SCM) и бинарник на диске (живой
	// прогон 2026-08-20: подтверждено на APF-STAND).
	status, err := s.Control(svc.Stop)
	if err == nil {
		deadline := time.Now().Add(15 * time.Second)
		for status.State != svc.Stopped && time.Now().Before(deadline) {
			time.Sleep(300 * time.Millisecond)
			status, err = s.Query()
			if err != nil {
				break
			}
		}
	}

	if err := s.Delete(); err != nil {
		fatalf("Cannot delete service: %v", err)
	}
	eventlog.Remove(svcName)
	fmt.Printf("✓ Служба '%s' удалена.\n", svcName)
}

func startService() {
	m, err := mgr.Connect()
	if err != nil {
		fatalf("Cannot connect to service manager: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		fatalf("Service %s not found. Run 'install' first.", svcName)
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		fatalf("Cannot start service: %v", err)
	}
	fmt.Printf("✓ Служба '%s' запущена.\n", svcName)
}

func stopService() {
	m, err := mgr.Connect()
	if err != nil {
		fatalf("Cannot connect to service manager: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		fatalf("Service %s not found.", svcName)
	}
	defer s.Close()

	status, err := s.Control(svc.Stop)
	if err != nil {
		fatalf("Cannot stop service: %v", err)
	}

	// Control() возвращает состояние в момент ПРИЁМА запроса (обычно StopPending),
	// не факт остановки — процесс ещё может держать файл apf-svc.exe открытым
	// (важно для установщика: перезапись бинарника сразу после Control() может
	// упереться в блокировку файла). Дожидаемся реального Stopped.
	deadline := time.Now().Add(15 * time.Second)
	for status.State != svc.Stopped && time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		status, err = s.Query()
		if err != nil {
			fatalf("Cannot query service state: %v", err)
		}
	}
	fmt.Printf("✓ Служба остановлена (состояние: %v).\n", status.State)
}

func showStatus() {
	m, err := mgr.Connect()
	if err != nil {
		fatalf("Cannot connect to service manager: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		fmt.Printf("Служба '%s' не установлена.\n", svcName)
		return
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		fatalf("Cannot query service: %v", err)
	}

	stateStr := map[svc.State]string{
		svc.Stopped:         "Остановлена",
		svc.StartPending:    "Запускается...",
		svc.StopPending:     "Останавливается...",
		svc.Running:         "Работает",
		svc.ContinuePending: "Возобновляется...",
		svc.PausePending:    "Приостанавливается...",
		svc.Paused:          "Приостановлена",
	}[status.State]

	fmt.Printf("Служба: %s\n", svcDisplayName)
	fmt.Printf("Статус: %s\n", stateStr)
	fmt.Printf("PID:    %d\n", status.ProcessId)
}

// runDirect — запуск без регистрации как служба (для отладки)
func runDirect() {
	fmt.Println("APF Service: direct mode (not a Windows Service)")
	fmt.Println("Press Ctrl+C to stop.")

	cfg := models.DefaultConfig()
	resolvedConfigPath := config.ConfigPath()
	if found, err := config.LoadInto(cfg); err != nil {
		log.Printf("Конфиг не загружен (%v), использую значения по умолчанию", err)
	} else if found {
		log.Printf("Конфиг загружен: %s", resolvedConfigPath)
	} else if userPath, ok := config.FindInteractiveUserConfigPath(); ok {
		// См. комментарий в Execute() — тот же обход для случая, когда run вызван от SYSTEM.
		if _, err := config.LoadIntoFrom(userPath, cfg); err != nil {
			log.Printf("Конфиг пользователя не загружен (%v): %s", err, userPath)
		} else {
			log.Printf("Конфиг пользователя загружен: %s", userPath)
			resolvedConfigPath = userPath
		}
	}
	for _, w := range cfg.Normalize() { // ТЗ v1.3 F5.2
		log.Printf("Конфиг: %s", w)
	}

	// R-3.1 (C-2): отладочный прямой запуск — такой же владелец, как служба и трей.
	lock, siErr := singleinstance.AcquireEngine()
	switch {
	case errors.Is(siErr, singleinstance.ErrAlreadyRunning):
		log.Fatalf("APF уже запущен (служба или другой экземпляр) — второй движок не поднимается")
	case siErr != nil:
		log.Printf("Проверка единственности экземпляра не удалась: %v (продолжаем)", siErr)
	default:
		defer lock.Close()
	}

	// См. комментарий в Execute() — тот же перенос каталога данных за resolvedConfigPath
	// (P1.1). runDirect не поднимает killswitch.ServePipe, поэтому self-dial (P0.1) здесь не
	// грозит — New(), не NewServiceHost(), остаётся корректным.
	config.SetDataDirOverride(filepath.Dir(resolvedConfigPath))
	eng := engine.New(cfg)
	eng.OnLog = func(msg string) { log.Printf("[APF] %s", msg) }
	eng.SetConfigSavePath(resolvedConfigPath)

	if err := eng.Start(); err != nil {
		log.Fatalf("Engine start: %v", err)
	}

	srv := web.New(eng, cfg.WebUIPort)
	log.Printf("Web UI: http://localhost:%d", cfg.WebUIPort)

	if err := srv.Start(); err != nil {
		log.Printf("Web UI error: %v", err)
	}
}

// ─── Вспомогательные функции ──────────────────────────────────────────────────

func openEventLog() *eventlog.Log {
	elog, err := eventlog.Open(svcName)
	if err != nil {
		// Fallback: логируем в файл
		logFile := filepath.Join(os.TempDir(), "apf-svc.log")
		f, _ := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		log.SetOutput(f)
		return nil
	}
	return elog
}

func writeEventLog(msg string, etype uint16) {
	elog, err := eventlog.Open(svcName)
	if err != nil {
		log.Println(msg)
		return
	}
	defer elog.Close()
	switch etype {
	case eventlog.Error:
		elog.Error(1, msg)
	case eventlog.Warning:
		elog.Warning(1, msg)
	default:
		elog.Info(1, msg)
	}
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ОШИБКА: "+format+"\n", args...)
	fmt.Fprintf(os.Stderr, "Совет: запустите от имени администратора.\n")
	os.Exit(1)
}
