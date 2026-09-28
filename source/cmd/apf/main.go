// APF — Adaptive PathFinder
// Интеллектуальный сетевой шлюз для автоматического обхода блокировок
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/engine"
	"github.com/apf/adaptive-pathfinder/internal/killswitch"
	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/singleinstance"
	appver "github.com/apf/adaptive-pathfinder/internal/version"
	"github.com/apf/adaptive-pathfinder/internal/watchdog"
	"github.com/apf/adaptive-pathfinder/internal/web"
	"github.com/spf13/cobra"
)

var (
	version = appver.Version
	cfgPath string
)

const watchdogEventFile = "watchdog_last_event.json"
const watchdogHistoryFile = "watchdog_events.json"
const watchdogHistoryLimit = 30

func main() {
	root := &cobra.Command{
		Use:   "apf",
		Short: "Adaptive PathFinder — интеллектуальный сетевой шлюз",
		Long: fmt.Sprintf(`
 █████╗ ██████╗ ███████╗
██╔══██╗██╔══██╗██╔════╝
███████║██████╔╝█████╗  
██╔══██║██╔═══╝ ██╔══╝  
██║  ██║██║     ██║     
╚═╝  ╚═╝╚═╝     ╚═╝  v%s

Adaptive PathFinder — умный обход блокировок.
`, version),
		// ИСПРАВЛЕНИЕ: если запущен без подкоманды — сразу стартуем
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStartFn(cmd)
		},
	}

	// Флаги на корневой команде (работают и без "start")
	root.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к конфигурации")
	root.Flags().Bool("no-webui", false, "не запускать Web UI")
	root.Flags().Bool("no-autoconnect", false, "не подключаться автоматически")
	root.Flags().Bool("no-watchdog", false, "не запускать watchdog recovery-процесс")

	// Команда: start (явная, для совместимости)
	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Запустить APF",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStartFn(cmd)
		},
	}
	startCmd.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к конфигурации")
	startCmd.Flags().Bool("no-webui", false, "не запускать Web UI")
	startCmd.Flags().Bool("no-autoconnect", false, "не подключаться автоматически")
	startCmd.Flags().Bool("no-watchdog", false, "не запускать watchdog recovery-процесс")

	// Команда: add
	addCmd := &cobra.Command{
		Use:   "add [ссылка]",
		Short: "Добавить узел по ссылке",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Загружаем существующий конфиг, иначе последующее сохранение (внутри
			// AddNodeFromLink) затирало бы остальные настройки пользователя чистыми
			// дефолтами (см. docs/TZ_CONFIG_RELOAD_AND_KS_SAFETY_v1.0.md).
			cfg := models.DefaultConfig()
			if _, err := config.LoadInto(cfg); err != nil {
				log.Printf("Конфиг не загружен (%v), использую значения по умолчанию", err)
			}
			for _, w := range cfg.Normalize() { // ТЗ v1.3 F5.2
				log.Printf("Конфиг: %s", w)
			}
			eng := engine.New(cfg)
			if err := eng.AddNodeFromLink(args[0]); err != nil {
				return fmt.Errorf("add node: %w", err)
			}
			fmt.Println("Node added successfully.")
			return nil
		},
	}

	// Команда: version
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Показать версию",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("APF version %s\n", version)
		},
	}

	// Команда: watchdog
	// Следит за PID и выполняет reset сети после падения.
	watchdogCmd := &cobra.Command{
		Use:   "watchdog",
		Short: "Watchdog: восстановление сети после аварийного выхода",
		RunE: func(cmd *cobra.Command, args []string) error {
			pidStr, _ := cmd.Flags().GetString("pid")
			if pidStr == "" {
				return fmt.Errorf("--pid is required")
			}
			pid, err := strconv.Atoi(pidStr)
			if err != nil || pid <= 0 {
				return fmt.Errorf("invalid --pid: %s", pidStr)
			}

			pollMs, _ := cmd.Flags().GetInt("poll-ms")
			graceMs, _ := cmd.Flags().GetInt("grace-ms")
			marker, _ := cmd.Flags().GetString("marker")

			log.SetFlags(log.Ltime | log.Lmsgprefix)
			log.SetPrefix("[APF-WD] ")
			log.Printf("Watching PID %d ...", pid)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Stop watchdog on Ctrl+C.
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sig
				cancel()
			}()

			err = watchdog.Run(ctx, watchdog.Config{
				PID:         pid,
				PollEvery:   time.Duration(pollMs) * time.Millisecond,
				GracePeriod: time.Duration(graceMs) * time.Millisecond,
			})
			if err != nil {
				return handleWatchdogRunErr(err, pid)
			}

			// Если есть marker и он удалён — APF завершился штатно, reset не нужен.
			if marker != "" {
				if _, statErr := os.Stat(marker); os.IsNotExist(statErr) {
					log.Printf("Marker removed. Normal shutdown detected, skip reset.")
					_ = writeWatchdogEvent(map[string]interface{}{
						"event":       "normal_shutdown",
						"pid":         pid,
						"reset_done":  false,
						"timestamp":   time.Now().Format(time.RFC3339Nano),
						"description": "APF exited normally; watchdog reset skipped",
					})
					return nil
				}
				_ = os.Remove(marker)
			}

			log.Printf("PID %d exited. Running network reset...", pid)
			if err := killswitch.ResetAll(); err != nil {
				log.Printf("Reset warning: %v", err)
				_ = writeWatchdogEvent(map[string]interface{}{
					"event":       "crash_reset_failed",
					"pid":         pid,
					"reset_done":  false,
					"error":       err.Error(),
					"timestamp":   time.Now().Format(time.RFC3339Nano),
					"description": "APF process exited and network reset failed",
				})
				return err
			}
			_ = writeWatchdogEvent(map[string]interface{}{
				"event":       "crash_reset_done",
				"pid":         pid,
				"reset_done":  true,
				"timestamp":   time.Now().Format(time.RFC3339Nano),
				"description": "APF process exited and watchdog restored network",
			})
			log.Printf("Network reset complete.")
			return nil
		},
	}
	watchdogCmd.Flags().String("pid", "", "PID процесса APF (обязателен)")
	watchdogCmd.Flags().Int("poll-ms", 750, "интервал проверки PID (мс)")
	watchdogCmd.Flags().Int("grace-ms", 2000, "пауза перед началом мониторинга (мс)")
	watchdogCmd.Flags().String("marker", "", "путь к marker-файлу штатного завершения")

	root.AddCommand(startCmd, addCmd, versionCmd, watchdogCmd)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// runStartFn — основная логика запуска (используется и root, и start командой)
func runStartFn(cmd *cobra.Command) error {
	// Загружаем сохранённый конфиг поверх дефолтов (см.
	// docs/TZ_CONFIG_RELOAD_AND_KS_SAFETY_v1.0.md) — без этого auto_connect/
	// enable_kill_switch/прочие настройки пользователя молча терялись при каждом
	// перезапуске. --config/-c задаёт явный путь; раньше флаг существовал, но нигде не
	// читался.
	cfg := models.DefaultConfig()
	var loadErr error
	var found bool
	if cfgPath != "" {
		found, loadErr = config.LoadIntoFrom(cfgPath, cfg)
	} else {
		found, loadErr = config.LoadInto(cfg)
	}
	if loadErr != nil {
		log.Printf("Конфиг не загружен (%v), использую значения по умолчанию", loadErr)
	} else if found {
		log.Printf("Конфиг загружен: %s", pickConfigPath(cfgPath))
	}
	// ТЗ v1.3 F5.2: одна нормализация на всех точках входа — неверное значение = дефолт + WARN.
	for _, w := range cfg.Normalize() {
		log.Printf("Конфиг: %s", w)
	}

	noWebUI, _ := cmd.Flags().GetBool("no-webui")
	noAuto, _ := cmd.Flags().GetBool("no-autoconnect")
	noWatchdog, _ := cmd.Flags().GetBool("no-watchdog")
	if noAuto {
		cfg.AutoConnect = false
	}

	log.SetFlags(log.Ltime | log.Lmsgprefix)
	log.SetPrefix("[APF] ")
	log.Printf("Starting v%s", version)

	// B-0403 · R-3.1 (C-2): владение системными ресурсами захватывается ДО watchdog и
	// engine.New. Два движка сразу — это два набора правил Kill Switch с одинаковыми
	// именами: Disable любого из них снимает защиту у обоих (нарушение TG-1).
	lock, siErr := singleinstance.AcquireEngine()
	switch {
	case errors.Is(siErr, singleinstance.ErrAlreadyRunning):
		return fmt.Errorf("APF уже запущен (служба APF или другой экземпляр). Второй движок не "+
			"поднимается: он поставил бы дублирующие правила Kill Switch и снял бы чужие при "+
			"выходе. Панель управления работающего экземпляра: http://127.0.0.1:%d", cfg.WebUIPort)
	case siErr != nil:
		// Fail-open: «не смогли выяснить» — не повод не запускаться (см. singleinstance).
		log.Printf("Проверка единственности экземпляра не удалась: %v (продолжаем)", siErr)
	default:
		defer lock.Close()
		if lock.Scope() != singleinstance.ScopeGlobal {
			log.Printf("Взаимоисключение действует только в текущей сессии (%s): службу APF, "+
				"работающую в сессии 0, оно не увидит", lock.Scope())
		}
	}

	var watchdogMarker string
	if !noWatchdog {
		var err error
		watchdogMarker, err = startSelfWatchdog()
		if err != nil {
			log.Printf("Watchdog warning: %v", err)
		} else {
			log.Printf("Watchdog started (marker: %s)", watchdogMarker)
			defer os.Remove(watchdogMarker) // штатная остановка: marker удаляется
		}
	}

	// Создаём Engine
	eng := engine.New(cfg)
	eng.OnLog = func(msg string) {
		log.Printf("%s", msg)
	}
	eng.OnStateChange = func(state *models.ConnectionState) {
		if state.Connected {
			log.Printf("Connected via %s → %s", state.Mode, nodeName(state.ActiveNode))
		} else {
			log.Printf("Disconnected")
		}
	}

	// Запускаем Engine
	if err := eng.Start(); err != nil {
		return fmt.Errorf("engine start: %w", err)
	}

	// Запускаем Web UI
	//
	// S-8 (ТЗ v1.4): webStarted теперь несёт сам *web.Server (не просто bool) — единственный
	// способ получить его в webSrv БЕЗ гонки данных (`go test -race`): запись в канал и приём
	// из него синхронизированы happens-before, обычная запись в общую переменную из горутины
	// с последующим чтением после `case <-time.After(...)` таковой бы не была.
	var webSrv *web.Server
	if !noWebUI {
		webStarted := make(chan *web.Server, 1)
		go func() {
			srv := web.New(eng, cfg.WebUIPort)
			// Сигналим что сервер создан (до ListenAndServe)
			webStarted <- srv
			if err := srv.Start(); err != nil {
				log.Printf("[WEB] Error: %v", err)
			}
		}()

		// Ждём чуть-чуть чтобы сервер успел занять порт
		select {
		case webSrv = <-webStarted:
			time.Sleep(50 * time.Millisecond)
		case <-time.After(2 * time.Second):
		}

		log.Printf("Web UI → http://127.0.0.1:%d", cfg.WebUIPort)
	}

	printBanner(cfg)

	// Ждём сигнала остановки
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Printf("Stopping...")
	// S-8: web.Server.Close() перед eng.Stop() — closer остаётся нетипизированным nil, если
	// Web UI не поднимали (noWebUI) или он не успел стартовать за 2с (webSrv==nil выше), иначе
	// typed-nil-в-интерфейсе заставил бы stopAPF решить, что закрывать есть что.
	var closer webCloser
	if webSrv != nil {
		closer = webSrv
	}
	stopAPF(closer, eng)
	return nil
}

func startSelfWatchdog() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve executable: %w", err)
	}

	if err := os.MkdirAll(config.DataDir(), 0700); err != nil {
		return "", fmt.Errorf("create data dir: %w", err)
	}
	marker := filepath.Join(config.DataDir(), fmt.Sprintf("watchdog-%d.marker", os.Getpid()))
	if err := os.WriteFile(marker, []byte(time.Now().Format(time.RFC3339Nano)), 0600); err != nil {
		return "", fmt.Errorf("create marker: %w", err)
	}

	cmd := exec.Command(
		exe,
		"watchdog",
		"--pid", strconv.Itoa(os.Getpid()),
		"--grace-ms", "2500",
		"--marker", marker,
	)
	if err := cmd.Start(); err != nil {
		_ = os.Remove(marker)
		return "", fmt.Errorf("start watchdog process: %w", err)
	}
	return marker, nil
}

// ─── S-9 (ТЗ v1.4): writeWatchdogEvent не писался при watchdog.ErrCheckUnavailable ─────────
//
// Проблема: watchdogCmd.RunE выходил по голому `return err`, минуя writeWatchdogEvent —
// единственная из четырёх исходных веток watchdog.Run() (normal_shutdown/crash_reset_done/
// crash_reset_failed — уже писали события), которая молчала. Диагностика "watchdog не смог
// определить, жив ли APF" терялась, хотя это отдельный (не "процесс умер") исход P3
// (internal/watchdog/watchdog.go: ErrCheckUnavailable, K3-S).

// consecutiveErrsRe — извлекает число неудачных проверок из текста ошибки
// watchdog.ErrCheckUnavailable ("...: PID %d, %d неудачных проверок подряд, последняя: %v",
// internal/watchdog/watchdog.go — ЧУЖОЙ файл, не в владении этого лота, поэтому число не
// приходит отдельным полем Config/error). Best-effort: 0, если формат сообщения когда-нибудь
// изменится — событие всё равно пишется с полным текстом ошибки (поле "error").
var consecutiveErrsRe = regexp.MustCompile(`(\d+)\s+неудачных проверок подряд`)

func parseConsecutiveCheckErrors(errText string) int {
	m := consecutiveErrsRe.FindStringSubmatch(errText)
	if len(m) != 2 {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// handleWatchdogRunErr — извлечено из watchdogCmd.RunE, чтобы тест мог прогнать ветку
// ErrCheckUnavailable без реального watchdog.Run/сигналов ОС/подписанного PID (правило лота —
// бинарники не запускать). Возвращает err без изменений (вызывающий код передаёt его дальше
// cobra) — единственный побочный эффект специфичный для этой функции — запись события через
// writeWatchdogEvent, СТРОГО когда err — ErrCheckUnavailable (errors.Is, не строковое
// сравнение — тот же приём, что уже использует internal/watchdog).
func handleWatchdogRunErr(err error, pid int) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, watchdog.ErrCheckUnavailable) {
		_ = writeWatchdogEvent(map[string]interface{}{
			"event":              "check_unavailable",
			"pid":                pid,
			"reset_done":         false,
			"consecutive_errors": parseConsecutiveCheckErrors(err.Error()),
			"error":              err.Error(),
			"timestamp":          time.Now().Format(time.RFC3339Nano),
			"description":        "watchdog: не удалось проверить живость PID; сброс сети пропущен (P3/S-9) — про процесс ничего не известно, выдавать это за его смерть нельзя",
		})
	}
	return err
}

// ─── S-8 (ТЗ v1.4): web.Server.Close() не вызывался ни одним владельцем процесса ───────────
//
// K2-W добавил Server.Close() (internal/web/server.go), но ни один владелец процесса
// (cmd/apf, cmd/apf-svc, cmd/apf-tray, gui/app.go) его не звал — фоновые горутины сервера
// (trackedGo, например apiCatalogRefresh) переживали остановку движка. webCloser/
// engineStopper — минимальные интерфейсы-швы: тест проверяет сам факт и порядок вызова без
// реального HTTP-сервера/сети (правило лота — бинарники не запускать).
type webCloser interface{ Close() }
type engineStopper interface{ Stop() }

// stopAPF — единая точка штатной остановки: сначала Web UI (если был поднят), потом движок.
func stopAPF(webSrv webCloser, eng engineStopper) {
	if webSrv != nil {
		webSrv.Close()
	}
	if eng != nil {
		eng.Stop()
	}
}

func writeWatchdogEvent(event map[string]interface{}) error {
	if err := os.MkdirAll(config.DataDir(), 0700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(config.DataDir(), watchdogEventFile), raw, 0600); err != nil {
		return err
	}
	return appendWatchdogHistory(event)
}

func appendWatchdogHistory(event map[string]interface{}) error {
	path := filepath.Join(config.DataDir(), watchdogHistoryFile)
	var history []map[string]interface{}

	raw, err := os.ReadFile(path)
	if err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &history)
	}
	history = append(history, event)
	if len(history) > watchdogHistoryLimit {
		history = history[len(history)-watchdogHistoryLimit:]
	}
	out, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0600)
}

func printBanner(cfg *models.AppConfig) {
	fmt.Printf("\n")
	fmt.Printf("  ╔═══════════════════════════════════════╗\n")
	fmt.Printf("  ║   APF Adaptive PathFinder running     ║\n")
	fmt.Printf("  ║                                       ║\n")
	fmt.Printf("  ║  Web UI  →  http://localhost:%-5d    ║\n", cfg.WebUIPort)
	fmt.Printf("  ║  SOCKS5  →  127.0.0.1:%-5d           ║\n", cfg.ListenPort)
	fmt.Printf("  ║  HTTP    →  127.0.0.1:%-5d           ║\n", cfg.ListenPort+1)
	fmt.Printf("  ║                                       ║\n")
	fmt.Printf("  ║  Ctrl+C to stop                       ║\n")
	fmt.Printf("  ╚═══════════════════════════════════════╝\n\n")
}

func nodeName(n *models.Node) string {
	if n == nil {
		return "none"
	}
	return n.Name
}

// pickConfigPath — путь конфига для лог-сообщения: явный --config, иначе стандартный.
func pickConfigPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return config.ConfigPath()
}
