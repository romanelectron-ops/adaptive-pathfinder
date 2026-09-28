// cmd/apf-tray — APF System Tray приложение для Windows.
// Сидит в трее, показывает статус подключения, управляет APF Engine.
//
// Сборка:
//
//	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H windowsgui" -o APF-Tray.exe ./cmd/apf-tray
//
// Зависимость: github.com/getlantern/systray
//
//	go get github.com/getlantern/systray
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/config"
	"github.com/apf/adaptive-pathfinder/internal/engine"
	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/netguard"
	"github.com/apf/adaptive-pathfinder/internal/singleinstance"
	"github.com/apf/adaptive-pathfinder/internal/web"
	"github.com/getlantern/systray"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// svcName — имя службы, должно совпадать с svcName в cmd/apf-svc/main.go
// (два разных бинарника main, общую константу импортировать неоткуда).
const svcName = "APFService"

// serviceStartWaitTimeout/serviceStartPollInterval — см. waitServiceRunning.
const (
	serviceStartWaitTimeout  = 2 * time.Second
	serviceStartPollInterval = 100 * time.Millisecond
)

// ─── Глобальные переменные ────────────────────────────────────────────────────

var (
	apfEngine *engine.Engine
	apfConfig *models.AppConfig
	apfLock   *singleinstance.Lock
	// webPort пишет горутина Web UI, а читает обработчик клика по пункту меню — только атомарно.
	webPort atomic.Int32
	// apfWebSrv — S-8 (ТЗ v1.4): та же горутина Web UI пишет её один раз после web.New(), путь
	// остановки (onExit/mQuit) читает — atomic.Pointer вместо голого присваивания, иначе
	// `go test -race` (гипотетически) увидел бы гонку между записью в startAPF и чтением в
	// обработчике клика/выхода.
	apfWebSrv atomic.Pointer[web.Server]
)

// ─── Точка входа ──────────────────────────────────────────────────────────────

func main() {
	// systray.Run блокирует поток, onReady вызывается когда трей готов
	systray.Run(onReady, onExit)
}

// ─── Tray Setup ───────────────────────────────────────────────────────────────

func onReady() {
	// Иконка трея (встроенная — красная точка пока не подключены)
	systray.SetIcon(iconDisconnected())
	systray.SetTitle("APF")
	systray.SetTooltip("APF Adaptive PathFinder — отключено")

	// ── Меню ────────────────────────────────────────────────────────────────

	mStatus := systray.AddMenuItem("○  Не подключено", "Текущий статус APF")
	mStatus.Disable()

	systray.AddSeparator()

	mConnect := systray.AddMenuItem("▶  Подключить", "Найти и подключиться к лучшему серверу")
	mDisconnect := systray.AddMenuItem("■  Отключить", "Разорвать VPN соединение")
	mDisconnect.Disable()
	mSwitch := systray.AddMenuItem("⇄  Сменить сервер", "Принудительно переключиться на другой сервер")
	mSwitch.Disable()

	systray.AddSeparator()

	mWebUI := systray.AddMenuItem("🌐  Открыть Web UI", "Открыть панель управления в браузере")
	mWebUI.Disable()

	systray.AddSeparator()

	// Подменю настроек
	mSettings := systray.AddMenuItem("⚙  Настройки", "")
	mKillSwitch := mSettings.AddSubMenuItem("Kill Switch: ВКЛ", "Блокировать трафик при потере VPN")
	mAutoStart := mSettings.AddSubMenuItem("Автозапуск: ВЫКЛ", "Запускать APF при старте Windows")

	systray.AddSeparator()

	mAbout := systray.AddMenuItem("ℹ  APF v1.0.7", "Adaptive PathFinder")
	mAbout.Disable()
	mQuit := systray.AddMenuItem("✕  Выход", "Остановить APF и закрыть")

	// ── Инициализация APF ────────────────────────────────────────────────────

	// Одна горутина, НЕ две независимые (было: go ensureServiceStarted() отдельно от
	// go func(){ startAPF ... }()) — см. waitServiceRunning ниже: до фикса
	// ensureServiceStarted() и startAPF()→AcquireEngine() гонялись параллельно без
	// всякой синхронизации между собой, поэтому GUI-часть аудита (та же гонка
	// singleinstance) касалась и трея. Последовательный вызов внутри одной горутины
	// по-прежнему не блокирует onReady()/меню — тот же неблокирующий контракт, что и раньше.
	go func() {
		ensureServiceStarted()
		observer, err := startAPF(mStatus, mWebUI, mConnect, mDisconnect, mSwitch)
		switch {
		case err != nil:
			log.Printf("APF start error: %v", err)
			mStatus.SetTitle("✗  Ошибка запуска APF")

		case observer:
			// R-3.1 (C-2): движком владеет служба или другой экземпляр. Трей остаётся
			// наблюдателем: показывает статус и открывает чужой Web UI, но НИЧЕМ не управляет —
			// иначе два движка начали бы затирать правила Kill Switch друг друга.
			log.Printf("APF уже запущен другим процессом — трей в режиме наблюдателя")
			mStatus.SetTitle("⚠  APF уже запущен (служба)")
			mConnect.Disable()
			mDisconnect.Disable()
			mSwitch.Disable()
			mKillSwitch.Disable()
			systray.SetTooltip("APF — управляется службой; трей в режиме наблюдателя")
			// webPort на этот момент — apfConfig.WebUIPort «как настроено», не то, на чём
			// реально сидит владелец (он мог перебрать диапазон, если настроенный порт
			// занял посторонний процесс — см. config.WritePortFile). Уточняем перед тем,
			// как показать ссылку пользователю, иначе «Открыть Web UI» вела бы в никуда.
			if real, ok := config.ReadPortFile(); ok {
				webPort.Store(int32(real))
			}
			mWebUI.SetTitle(fmt.Sprintf("🌐  Открыть Web UI (%d)", webPort.Load()))
			mWebUI.Enable()
		}
	}()

	// ── Обработка кликов ─────────────────────────────────────────────────────

	killSwitchEnabled := true
	autoStartEnabled := isAutoStartEnabled()
	if autoStartEnabled {
		mAutoStart.SetTitle("Автозапуск: ВКЛ")
	}

	for {
		select {
		case <-mConnect.ClickedCh:
			if apfEngine != nil {
				mStatus.SetTitle("🔄  Подключение...")
				go apfEngine.ScanAndConnect()
			}

		case <-mDisconnect.ClickedCh:
			if apfEngine != nil {
				apfEngine.Stop()
				updateTrayDisconnected(mStatus, mConnect, mDisconnect, mSwitch)
			}

		case <-mSwitch.ClickedCh:
			if apfEngine != nil {
				apfEngine.ForceSwitchNow()
				mStatus.SetTitle("🔄  Смена сервера...")
			}

		case <-mWebUI.ClickedCh:
			openWebUI()

		case <-mKillSwitch.ClickedCh:
			killSwitchEnabled = !killSwitchEnabled
			if apfEngine != nil {
				patch := map[string]interface{}{"enable_kill_switch": killSwitchEnabled}
				apfEngine.PatchConfig(patch)
			}
			if killSwitchEnabled {
				mKillSwitch.SetTitle("Kill Switch: ВКЛ")
			} else {
				mKillSwitch.SetTitle("Kill Switch: ВЫКЛ")
			}

		case <-mAutoStart.ClickedCh:
			autoStartEnabled = !autoStartEnabled
			setAutoStart(autoStartEnabled)
			if autoStartEnabled {
				mAutoStart.SetTitle("Автозапуск: ВКЛ")
			} else {
				mAutoStart.SetTitle("Автозапуск: ВЫКЛ")
			}

		case <-mQuit.ClickedCh:
			stopOwnedProcess()
			systray.Quit()
			return
		}
	}
}

// ─── S-8 (ТЗ v1.4): web.Server.Close() не вызывался ни одним владельцем процесса ───────────
//
// K2-W добавил Server.Close() (internal/web/server.go), но ни один владелец процесса
// (cmd/apf, cmd/apf-svc, cmd/apf-tray, gui/app.go) его не звал — фоновые горутины сервера
// (trackedGo, например apiCatalogRefresh) переживали остановку движка. webCloser/
// engineStopper — минимальные интерфейсы-швы: тест проверяет сам факт и порядок вызова без
// реального трея/сети (правило лота — бинарники не запускать).
type webCloser interface{ Close() }
type engineStopper interface{ Stop() }

func stopProcess(webSrv webCloser, eng engineStopper) {
	if webSrv != nil {
		webSrv.Close()
	}
	if eng != nil {
		eng.Stop()
	}
}

// stopOwnedProcess — путь штатной остановки трея-владельца (mQuit.ClickedCh/onExit): читает
// package-level apfWebSrv/apfEngine и передаёт их в stopProcess через тот же инжектируемый
// шов, что уже покрыт тестом (main_v14_test.go). Наблюдатель (apfEngine==nil, свой web.Server
// никогда не поднимался) — оба аргумента остаются нетипизированным nil, stopProcess это
// корректно пропускает.
func stopOwnedProcess() {
	var closer webCloser
	if srv := apfWebSrv.Load(); srv != nil {
		closer = srv
	}
	var stopper engineStopper
	if apfEngine != nil {
		stopper = apfEngine
	}
	stopProcess(closer, stopper)
}

func onExit() {
	stopOwnedProcess()
	// Освобождаем владение раньше, чем это сделает ядро при завершении процесса: иначе
	// перезапуск трея «сам в себя» на короткое время видел бы себя же как второй экземпляр.
	if apfLock != nil {
		_ = apfLock.Close()
		apfLock = nil
	}
}

// ─── APF Engine ───────────────────────────────────────────────────────────────

// startAPF поднимает движок и Web UI.
//
//	Выход: (observer=true) — движком уже владеет другой процесс, мы ничего не запускали;
//	       (observer=false, err==nil) — движок наш;
//	       (err!=nil) — движок не поднялся.
func startAPF(
	mStatus, mWebUI, mConnect, mDisconnect, mSwitch *systray.MenuItem,
) (bool, error) {
	// Загружаем сохранённый config.json поверх дефолтов — см.
	// docs/TZ_CONFIG_RELOAD_AND_KS_SAFETY_v1.0.md. AutoConnect больше не форсируется:
	// трей, как и любой другой процесс, обязан уважать реальный выбор пользователя.
	apfConfig = models.DefaultConfig()
	if found, err := config.LoadInto(apfConfig); err != nil {
		log.Printf("[APF] конфиг не загружен (%v), использую значения по умолчанию", err)
	} else if found {
		log.Printf("[APF] конфиг загружен: %s", config.ConfigPath())
	}
	webPort.Store(int32(apfConfig.WebUIPort))

	// B-0403 · R-3.1 (C-2): захват владения ДО engine.New.
	lock, siErr := singleinstance.AcquireEngine()
	switch {
	case errors.Is(siErr, singleinstance.ErrAlreadyRunning):
		return true, nil
	case siErr != nil:
		// Fail-open: невозможность проверить — не повод не запускаться.
		log.Printf("[APF] проверка единственности экземпляра не удалась: %v (продолжаем)", siErr)
	default:
		apfLock = lock
		if lock.Scope() != singleinstance.ScopeGlobal {
			log.Printf("[APF] взаимоисключение действует только в текущей сессии (%s): "+
				"службу APF в сессии 0 оно не увидит", lock.Scope())
		}
	}

	apfEngine = engine.New(apfConfig)

	// Обновляем трей при смене статуса.
	//
	// Находка при доводке трея (2026-08-12): mDisconnect/mSwitch создавались
	// заблокированными (Disable() сразу после AddMenuItem) в расчёте, что этот
	// колбэк их разблокирует при успешном подключении — но колбэк раньше трогал
	// только иконку/тултип/текст статуса, ни разу не вызывая Enable() ни у одного
	// пункта меню. Пункты «Отключить»/«Сменить сервер» оставались недоступны
	// НАВСЕГДА с момента старта трея, даже после реального подключения —
	// единственный обходной путь был через Web UI, а не сам трей.
	apfEngine.OnStateChange = func(state *models.ConnectionState) {
		if state.Connected {
			nodeName := ""
			latency := int64(0)
			if state.ActiveNode != nil {
				nodeName = state.ActiveNode.Name
				latency = state.ActiveNode.Latency
			}
			tooltip := fmt.Sprintf("APF: %s", nodeName)
			if latency > 0 {
				tooltip += fmt.Sprintf(" (%dms)", latency)
			}
			systray.SetIcon(iconConnected())
			systray.SetTooltip(tooltip)
			statusText := fmt.Sprintf("✓  %s", nodeName)
			if latency > 0 {
				statusText += fmt.Sprintf(" · %dms", latency)
			}
			mStatus.SetTitle(statusText)
			mConnect.Disable()
			mDisconnect.Enable()
			mSwitch.Enable()
		} else {
			updateTrayDisconnected(mStatus, mConnect, mDisconnect, mSwitch)
		}
	}

	apfEngine.OnLog = func(msg string) {
		log.Printf("[APF] %s", msg)
	}

	if err := apfEngine.Start(); err != nil {
		return false, err
	}

	// Запускаем Web UI
	go func() {
		srv := web.New(apfEngine, apfConfig.WebUIPort)
		apfWebSrv.Store(srv) // S-8: доступен пути остановки (stopOwnedProcess) сразу после New()
		go func() {
			// R-3.2: прежний код «перебирал» порты циклом с немедленным break и всегда
			// подписывал пункт меню желаемым портом. Перебор делает сам сервер, поэтому
			// спрашиваем у него ФАКТИЧЕСКИЙ порт — иначе кнопка вела бы в никуда.
			// Start() блокирует, а порт выбирает в первые же миллисекунды: даём ему момент.
			time.Sleep(300 * time.Millisecond)
			webPort.Store(int32(srv.Port()))
			mWebUI.SetTitle(fmt.Sprintf("🌐  Открыть Web UI (%d)", webPort.Load()))
			mWebUI.Enable()
		}()
		if err := srv.Start(); err != nil {
			log.Printf("[APF] Web UI: %v", err)
		}
	}()

	// Мониторинг статуса в трее
	go statusUpdater(mStatus)

	return false, nil
}

func statusUpdater(mStatus *systray.MenuItem) {
	// Мигание при подключении
	tick := 0
	for {
		time.Sleep(1 * time.Second)
		tick++
		if apfEngine == nil {
			continue
		}
		state := apfEngine.GetState()
		if !state.Connected && tick%2 == 0 {
			// Пульсирующая анимация пока не подключены
			mStatus.SetTitle("○  Поиск серверов...")
		} else if !state.Connected {
			mStatus.SetTitle("○  Не подключено")
		}
	}
}

// ─── Служба Windows ───────────────────────────────────────────────────────────

// ensureServiceStarted — по требованию пользователя 2026-08-25 служба APFService
// зарегистрирована с StartManual (см. installService() в cmd/apf-svc/main.go): она
// НЕ поднимается сама при загрузке Windows, а живёт ровно пока нужна приложению.
// Здесь трей, как основная точка входа для пользователя, инициирует её запуск при
// собственном старте. Best-effort: служба нужна прежде всего как привилегированный
// исполнитель Kill Switch (см. killswitch.ServePipe в apf-svc) — если её не удалось
// поднять (нет прав, не установлена и т.п.), трей всё равно продолжает работу и
// сам становится владельцем движка через обычную гонку AcquireEngine() ниже;
// сообщение в лог, не паника и не блокировка запуска трея.
func ensureServiceStarted() {
	if runtime.GOOS != "windows" {
		return
	}
	m, err := mgr.Connect()
	if err != nil {
		log.Printf("[APF] служба: подключение к SCM не удалось (%v) — продолжаю без неё", err)
		return
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		log.Printf("[APF] служба APFService не установлена — продолжаю без неё")
		return
	}
	defer s.Close()

	status, err := s.Query()
	if err == nil && status.State == svc.Running {
		return
	}
	if err := s.Start(); err != nil {
		log.Printf("[APF] не удалось запустить службу APFService (%v) — "+
			"Kill Switch может быть недоступен, трей продолжает работу сам", err)
		return
	}
	log.Printf("[APF] служба APFService запущена по требованию трея")
	waitServiceRunning(s)
}

// waitServiceRunning — тот же приём и то же обоснование, что у gui/servicestart.go
// (аудит: гонка singleinstance между трей/GUI и свежезапущенной службой). apfService.Execute
// (cmd/apf-svc/main.go) сообщает SCM свой svc.Running ТОЛЬКО ПОСЛЕ собственного
// singleinstance.AcquireEngine() — к моменту, когда мы увидим здесь Running, служба уже
// либо стала владельцем движка, либо уступила его. Ограничено по времени
// (serviceStartWaitTimeout) — не укладывается служба, дальше решает обычная гонка
// AcquireEngine() в startAPF, как и раньше.
func waitServiceRunning(s *mgr.Service) {
	deadline := time.Now().Add(serviceStartWaitTimeout)
	for time.Now().Before(deadline) {
		status, err := s.Query()
		if err != nil {
			return
		}
		if status.State == svc.Running {
			return
		}
		time.Sleep(serviceStartPollInterval)
	}
}

// ─── Автозапуск ───────────────────────────────────────────────────────────────

func isAutoStartEnabled() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	out, err := exec.Command("reg", "query",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"/v", "APF").Output()
	return err == nil && len(out) > 0
}

func setAutoStart(enable bool) {
	if runtime.GOOS != "windows" {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if enable {
		exec.Command("reg", "add",
			`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
			"/v", "APF", "/t", "REG_SZ",
			"/d", `"`+exe+`"`,
			"/f").Run()
	} else {
		exec.Command("reg", "delete",
			`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
			"/v", "APF", "/f").Run()
	}
}

// ─── Браузер / Web UI (S-2, ТЗ v1.4) ───────────────────────────────────────────
//
// Проблема (S-2 п.4): после лота L1-WEB ВСЕ /api/* (кроме GET "/" и GET "/ui") требуют
// Authorization: Bearer <token> либо cookie apf_ui. Пункт меню «Открыть Web UI» раньше
// открывал голый "http://127.0.0.1:<port>" — страница "/" загрузилась бы (публичная точка
// входа), но встроенный JS без токена/cookie получал бы 401 на каждый fetch('/api/...') —
// UI визуально есть, данных нет. Решение: перед открытием браузера сам трей (единственный
// не-браузерный клиент здесь — обычно к /api/ не обращается, см. ВНИМАНИЕ в брифе лота)
// читает постоянный токен из файла и обменивает его на одноразовый handoff-ключ
// (POST /api/ui/handoff), затем открывает ".../ui?k=<k>" — постоянный токен в URL не попадает
// никогда.

// readWebUIToken — %APPDATA%\APF\webui_token (config.DataDir(), тот же путь, что
// internal/web/server.go:authTokenFilePath() — сам не экспортирует эту функцию, контракт
// зафиксирован текстом ТЗ S-2 и result.json лота L1-WEB).
func readWebUIToken() (string, error) {
	path := filepath.Join(config.DataDir(), "webui_token")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("токен не найден по пути %s: %w", path, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// webUIHandoffURL — POST baseURL+"/api/ui/handoff" под Bearer-токеном → одноразовый ключ k
// (TTL 10с) → baseURL+"/ui?k=<k>". client инжектируется тестом (httptest.Server, без
// реального сервиса/сети — правило лота).
func webUIHandoffURL(client *http.Client, baseURL string) (string, error) {
	token, err := readWebUIToken()
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/ui/handoff", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var body struct {
		K     string `json:"k"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("handoff: разбор ответа: %w", err)
	}
	if body.Error != "" {
		return "", fmt.Errorf("handoff: %s", body.Error)
	}
	if body.K == "" {
		return "", fmt.Errorf("handoff: сервер не вернул одноразовый ключ")
	}
	return baseURL + "/ui?k=" + body.K, nil
}

// openWebUI — обработчик клика по «Открыть Web UI» (mWebUI.ClickedCh): handoff, при отказе —
// честный fallback на голый "/" (не хуже прежнего поведения; постоянный токен в URL по-прежнему
// не появляется — просто открывается страница без данных, как и было ДО лота L1-WEB/L1b-CLI).
func openWebUI() {
	base := fmt.Sprintf("http://127.0.0.1:%d", webPort.Load())
	url, err := webUIHandoffURL(netguard.Client(5*time.Second), base)
	if err != nil {
		log.Printf("[APF] Открыть Web UI: handoff не удался (%v) — открываю без ключа", err)
		url = base
	}
	openBrowser(url)
}

// ─── Браузер ──────────────────────────────────────────────────────────────────

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Start()
}

// ─── Иконки трея ─────────────────────────────────────────────────────────────
// Минимальные ICO иконки закодированные в байтах.
// В реальном проекте замените на нормальные иконки через go-embed.

func iconConnected() []byte {
	// 16x16 зелёная точка — минимальный ICO
	return iconGreen16
}

func iconDisconnected() []byte {
	// 16x16 серая точка
	return iconGray16
}

// Минимальные 16x16 ICO иконки (1px, монохромные — замените на нормальные)
var iconGreen16 = []byte{
	0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x10, 0x00, 0x00, 0x01, 0x00,
	0x20, 0x00, 0x68, 0x04, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x28, 0x00,
	0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00,
	// 16x16 пикселей зелёного цвета (#2ea043)
	0x43, 0xa0, 0x2e, 0xff, 0x43, 0xa0, 0x2e, 0xff, 0x43, 0xa0, 0x2e, 0xff,
	0x43, 0xa0, 0x2e, 0xff,
}

var iconGray16 = []byte{
	0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x10, 0x00, 0x00, 0x01, 0x00,
	0x20, 0x00, 0x68, 0x04, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x28, 0x00,
	0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00,
	// 16x16 серые пиксели (#8b949e)
	0x9e, 0x94, 0x8b, 0xff, 0x9e, 0x94, 0x8b, 0xff, 0x9e, 0x94, 0x8b, 0xff,
	0x9e, 0x94, 0x8b, 0xff,
}

func updateTrayDisconnected(mStatus, mConnect, mDisconnect, mSwitch *systray.MenuItem) {
	mStatus.SetTitle("○  Не подключено")
	mConnect.Enable()
	mDisconnect.Disable()
	mSwitch.Disable()
	systray.SetIcon(iconDisconnected())
	systray.SetTooltip("APF — отключено")
}
