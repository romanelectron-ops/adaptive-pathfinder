// APF GUI — Desktop приложение на Wails v2
// Wails позволяет писать нативные приложения Windows/macOS/Linux
// с Go-бэкендом и HTML/JS/CSS фронтендом в одном бинарнике.
package main

import (
	"embed"
	"log"
	"net/http"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed frontend/dist
var assets embed.FS

// noCacheIndexMiddleware — P1.3 (docs/TZ_WINDOWS_CONSILIUM_FINDINGS_v1.0.md): index.html
// уходит клиенту БЕЗ единого кэш-заголовка/валидатора (embed.FS не хранит реальное время
// модификации → Last-Modified не ставится; ETag не выставляется нигде). WebView2 может
// эвристически закэшировать такой ответ в профиле %AppData%\APF.exe\EBWebView, который не
// привязан к сборке и переживает переустановку — пользователь после свежей пересборки видит
// СТАРЫЙ DOM (нет help-иконок/дропдауна выбора узла и т.п., хотя в собранном dist они есть).
// Хэшированные assets/*.js/css (Vite) остаются кэшируемыми — этот middleware трогает только
// сам index.html, который всегда запрашивается по одному фиксированному URL.
func noCacheIndexMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	app := NewApp()

	// Доводка десктопа под Windows (2026-08-12, gui/tray.go): systray.Run обязан
	// уйти в горутину и стартовать ДО wails.Run на главной горутине — обратный
	// порядок или синхронный вызов взаимно блокируют цикл сообщений Win32,
	// которого хотят обе библиотеки. Подробности — в doc-комментарии tray.go.
	startTray(app)

	err := wails.Run(&options.App{
		Title:             "APF — Adaptive PathFinder",
		Width:             900,
		Height:            620,
		MinWidth:          720,
		MinHeight:         520,
		DisableResize:     false,
		Fullscreen:        false,
		Frameless:         false,
		StartHidden:       false,
		HideWindowOnClose: true, // сворачиваем в трей вместо закрытия

		AssetServer: &assetserver.Options{
			Assets:     assets,
			Middleware: noCacheIndexMiddleware,
		},

		BackgroundColour: &options.RGBA{R: 13, G: 17, B: 23, A: 255},

		Windows: &windows.Options{
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
			DisableWindowIcon:    false,
			// Тёмная рамка окна под тёмный UI
			Theme: windows.Dark,
		},

		OnStartup:  app.startup,
		OnShutdown: app.shutdown,
		OnDomReady: app.domReady,

		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		log.Fatalf("APF: wails.Run failed: %v", err)
	}
}
