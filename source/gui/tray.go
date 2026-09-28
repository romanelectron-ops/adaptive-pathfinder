package main

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/getlantern/systray"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// Доводка десктопа под Windows (2026-08-12). До этой правки `HideWindowOnClose:
// true` (main.go) прятало окно по клику на «X», но иконки в трее не было вообще
// — комментарий рядом («сворачиваем в трей вместо закрытия») обещал то, чего
// код не делал. Спрятанное окно было некуда возвращать: единственный путь назад
// — Диспетчер задач. Тот же github.com/getlantern/systray, что уже работает в
// cmd/apf-tray (те же иконки/паттерн ClickedCh), запущен ВНУТРИ этого процесса
// рядом с окном Wails — не отдельным бинарником, иначе пользователь видел бы
// два несвязанных приложения вместо одного.
//
// Threading (важно, не очевидно): systray.Run обязан уйти в горутину и
// стартовать ДО wails.Run на главной горутине — см. main.go. Обе библиотеки
// хотят Win32-цикл сообщений на «своём» потоке; getlantern/systray сама
// фиксирует поток вызывающей горутины через runtime.LockOSThread() в своём
// init(), поэтому обратный порядок (или синхронный вызов) даёт взаимную
// блокировку на старте, а не мягкий сбой — эта деталь не проверяема на этом
// хосте (правило проекта — GUI не запускается на хосте), только чтением
// исходников systray и практикой сообщества Wails (issue-discussion #4514).

var (
	trayApp *App

	trayMu         sync.RWMutex
	trayStatus     *systray.MenuItem
	trayConnect    *systray.MenuItem
	trayDisconnect *systray.MenuItem
)

// startTray запускает системный трей в отдельной горутине. Вызывать из main()
// ДО wails.Run — не из App.startup (тот срабатывает уже после того, как Wails
// мог забрать себе цикл сообщений главного потока).
func startTray(app *App) {
	trayApp = app
	go systray.Run(onTrayReady, onTrayExit)
}

func onTrayReady() {
	systray.SetIcon(trayIconDisconnected)
	systray.SetTitle("APF")
	systray.SetTooltip("APF Adaptive PathFinder — отключено")

	mShow := systray.AddMenuItem("Открыть APF", "Показать окно")
	systray.AddSeparator()
	mStatus := systray.AddMenuItem("○  Не подключено", "Текущий статус APF")
	mStatus.Disable()
	systray.AddSeparator()
	mConnect := systray.AddMenuItem("▶  Подключить", "Найти и подключиться к лучшему серверу")
	mDisconnect := systray.AddMenuItem("■  Отключить", "Разорвать соединение")
	mDisconnect.Disable()
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("✕  Выход", "Остановить APF и закрыть")

	trayMu.Lock()
	trayStatus, trayConnect, trayDisconnect = mStatus, mConnect, mDisconnect
	trayMu.Unlock()

	for {
		select {
		case <-mShow.ClickedCh:
			if trayApp != nil && trayApp.ctx != nil {
				wailsruntime.WindowShow(trayApp.ctx)
			}

		case <-mConnect.ClickedCh:
			if trayApp != nil {
				_ = trayApp.Connect()
			}

		case <-mDisconnect.ClickedCh:
			if trayApp != nil {
				trayApp.Disconnect()
			}

		case <-mQuit.ClickedCh:
			// Порядок важен: сначала гасим иконку трея (иначе она «зависает» в
			// панели до перезапуска explorer.exe — типичная жалоба на системные
			// трей-приложения), потом просим Wails закрыться. wailsruntime.Quit
			// — единственный путь мимо HideWindowOnClose (см. пояснение выше);
			// обычный клик по «X» на это НЕ похож, тот только прячет окно.
			systray.Quit()
			if trayApp != nil && trayApp.ctx != nil {
				wailsruntime.Quit(trayApp.ctx)
			}
			return
		}
	}
}

func onTrayExit() {}

// updateTrayState обновляет иконку/тултип/пункты меню трея. Зовётся и
// владельцем (Engine.OnStateChange в app.go), и наблюдателем
// (startObserverPolling в app.go) — оба уже получают *models.ConnectionState
// с той же частотой, что и событие apf:state для фронтенда, лишний канал не
// заводится. nil-проверка на trayStatus — не ошибка, а обычное состояние в
// первые миллисекунды после старта: onTrayReady ещё не успел создать пункты
// меню в своей горутине, следующее обновление (секунда спустя у наблюдателя,
// или следующая смена состояния у владельца) само всё досчитает.
//
// Контракт VerifyState (idle/checking/verified/failed, введён 2026-09-06 для Android/Web —
// models.VerifyIdle/Checking/Verified/Failed) — та же таблица состояний, что и orb во
// фронтенде (index.html, VERIFY_STATE_UI/resolveVerifyState). Раньше здесь была независимая
// ad-hoc проверка state.Connected && !state.Verified — ЕДИНСТВЕННОЕ место, вычисляющее
// текст/иконку трея, теперь resolveTrayVerifyState() ниже, без второй копии этой логики.
func updateTrayState(state *models.ConnectionState) {
	trayMu.RLock()
	status, connect, disconnect := trayStatus, trayConnect, trayDisconnect
	trayMu.RUnlock()
	if status == nil {
		return
	}

	nodeName := ""
	var latency int64
	if state.ActiveNode != nil {
		nodeName = state.ActiveNode.Name
		latency = state.ActiveNode.Latency
	}

	switch resolveTrayVerifyState(state) {
	case models.VerifyVerified:
		systray.SetIcon(trayIconConnected)
		tooltip := "APF: " + nodeName
		statusText := "✓  " + nodeName
		if latency > 0 {
			tooltip += fmt.Sprintf(" (%dms)", latency)
			statusText += fmt.Sprintf(" · %dms", latency)
		}
		systray.SetTooltip(tooltip)
		status.SetTitle(statusText)
		connect.Disable()
		disconnect.Enable()

	case models.VerifyChecking:
		// Сокет sing-box поднят, но узел ещё не подтвердил рабочий канал — жёлтая иконка
		// вместо зелёной, не показываем "подключено" раньше времени. Текст — дословно
		// контрактный (см. ApfCore.kt/server.go «Проверяю канал…»), не свой вариант.
		systray.SetIcon(trayIconVerifying)
		systray.SetTooltip("APF: проверяю канал…")
		statusText := "⏳  Проверяю канал…"
		if nodeName != "" {
			statusText += " (" + nodeName + ")"
		}
		status.SetTitle(statusText)
		connect.Disable()
		disconnect.Enable()

	case models.VerifyFailed:
		// Новое 4-е состояние: туннель поднят, но проверка канала провалилась насовсем (не
		// "ещё проверяю"). Раньше физически не отрисовывалось — connected&&!verified уходил
		// в тот же жёлтый "ищу узел" независимо от того, идёт проверка или она уже провалена.
		systray.SetIcon(trayIconFailed)
		systray.SetTooltip("APF: туннель поднят, но трафик не идёт")
		statusText := "⚠️  Трафик не идёт"
		if nodeName != "" {
			statusText += " (" + nodeName + ")"
		}
		status.SetTitle(statusText)
		connect.Disable()
		disconnect.Enable()

	default: // models.VerifyIdle
		systray.SetIcon(trayIconDisconnected)
		systray.SetTooltip("APF — отключено")
		status.SetTitle("○  Не подключено")
		connect.Enable()
		disconnect.Disable()
	}
}

// resolveTrayVerifyState — единая точка вычисления состояния трея из контракта VerifyState.
// Деградация (последний блок) — ТОЛЬКО если движок ещё не отдаёт VerifyState вовсе (пустая
// строка): 1:1 воспроизводит прежнюю двух-булеву модель (3 исхода вместо 4, без отдельного
// failed) — не меняем поведение там, где новых данных ещё нет (тот же принцип, что у
// resolveVerifyState() в index.html).
func resolveTrayVerifyState(state *models.ConnectionState) string {
	if state.VerifyState != "" {
		return state.VerifyState
	}
	if state.Connected && state.Verified {
		return models.VerifyVerified
	}
	if state.Connected {
		return models.VerifyChecking
	}
	return models.VerifyIdle
}

// solidTrayIcon строит валидный однотонный 16×16 32-битный .ico в памяти.
//
// Раньше здесь лежали вручную вписанные байтовые массивы (скопированные из
// cmd/apf-tray/main.go), которые ОБЪЯВЛЯЛИ полноценный заголовок 16×16×32bpp
// (ICONDIRENTRY.bytesInRes=0x468=1128, ровно BITMAPINFOHEADER(40)+XOR(1024)+
// AND-маска(64)), но реально несли пиксельных данных всего на 4 пикселя —
// на порядок меньше объявленного. Windows (`CreateIconFromResourceEx` внутри
// `systray.SetIcon`) не могла разобрать такой буфер и отказывала с «Unable to
// set icon» — из-за чего вместо цветной точки в трее было пустое место.
// Собирать иконку в коде вместо переноса магических байт устраняет саму
// возможность такого рассинхрона заголовка и данных.
func solidTrayIcon(r, g, b byte) []byte {
	const w, h = 16, 16
	xorSize := w * h * 4
	andRowBytes := ((w + 31) / 32) * 4 // AND-маска паддится до 4 байт на строку
	andSize := andRowBytes * h
	dataSize := 40 + xorSize + andSize

	buf := make([]byte, 6+16+dataSize)
	buf[2], buf[3] = 1, 0 // ICONDIR.type = 1 (icon)
	buf[4], buf[5] = 1, 0 // ICONDIR.count = 1

	e := buf[6:22] // ICONDIRENTRY
	e[0], e[1] = w, h
	e[4], e[5] = 1, 0  // planes
	e[6], e[7] = 32, 0 // bitCount
	binary.LittleEndian.PutUint32(e[8:12], uint32(dataSize))
	binary.LittleEndian.PutUint32(e[12:16], 22) // imageOffset

	bih := buf[22:62] // BITMAPINFOHEADER
	binary.LittleEndian.PutUint32(bih[0:4], 40)
	binary.LittleEndian.PutUint32(bih[4:8], uint32(w))
	binary.LittleEndian.PutUint32(bih[8:12], uint32(h*2)) // XOR + AND
	binary.LittleEndian.PutUint16(bih[12:14], 1)
	binary.LittleEndian.PutUint16(bih[14:16], 32)
	binary.LittleEndian.PutUint32(bih[20:24], uint32(xorSize))

	pix := buf[62 : 62+xorSize] // XOR: BGRA, непрозрачный сплошной цвет
	for i := 0; i < w*h; i++ {
		pix[i*4+0], pix[i*4+1], pix[i*4+2], pix[i*4+3] = b, g, r, 0xff
	}
	// AND-маска остаётся нулевой (buf уже zero-initialized) — полностью
	// непрозрачно, видимость и так задаёт альфа-канал XOR-данных.
	return buf
}

var (
	trayIconConnected    = solidTrayIcon(0x2e, 0xa0, 0x43) // #2ea043 зелёный
	trayIconVerifying    = solidTrayIcon(0xf5, 0xa6, 0x23) // #f5a623 жёлтый — тот же var(--ye), что и orb во фронтенде
	trayIconDisconnected = solidTrayIcon(0x8b, 0x94, 0x9e) // #8b949e серый
	trayIconFailed       = solidTrayIcon(0xf2, 0x57, 0x57) // #f25757 красный — тот же var(--re), что и .status-orb.failed во фронтенде
)
