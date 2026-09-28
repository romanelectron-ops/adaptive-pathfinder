package web

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// P0-3 (аудит 2026-09-01): экранирование в обоих интерфейсах.
//
// Встроенный UI и Wails-окно — это строки HTML/JS, которые не проверялись НИКАКИМ тестом:
// TestApiUI смотрит только код 200 и наличие подстроки. Поэтому дефект («esc покрывает лишь
// часть спецсимволов», «часть полей вставляется вообще без esc») прожил незамеченным, хотя
// источник данных — имя узла из публичной подписки, то есть строка, которую пишет кто угодно.
//
// Проверяем ТЕКСТ страницы, а не поведение JS: полноценный прогон JS требовал бы движка
// (goja/headless), а инвариант «в функции экранирования перечислены все пять символов» и
// «опасные точки вставки обёрнуты в esc» проверяется статически и стоит десяток строк.

// escapedChars — символы, без которых экранирование бесполезно в атрибутном контексте.
var escapedChars = []struct {
	name string
	frag string
}{
	{"амперсанд", `&amp;`},
	{"меньше", `&lt;`},
	{"больше", `&gt;`},
	{"двойная кавычка", `&quot;`},
	{"одинарная кавычка", `&#39;`},
}

func TestEmbeddedUI_EscapeCoversAllDangerousChars(t *testing.T) {
	idx := strings.Index(webUI, "function esc(")
	if idx < 0 {
		t.Fatal("во встроенном UI не найдена функция esc — проверять нечего")
	}
	body := webUI[idx:min(idx+400, len(webUI))]
	for _, c := range escapedChars {
		if !strings.Contains(body, c.frag) {
			t.Errorf("esc() встроенного UI не экранирует %s (%s) — вставка в атрибут или "+
				"внутрь onclick='...' выводит в исполняемый код", c.name, c.frag)
		}
	}
}

// Точки, где раньше данные из подписки/стороннего API вставлялись без экранирования.
// Каждая строка — реальная находка аудита.
func TestEmbeddedUI_DangerousInsertionsAreEscaped(t *testing.T) {
	unescaped := []struct {
		frag string
		why  string
	}{
		{`'+n.protocol+'`, "протокол узла из подписки"},
		{`'+p.id+'`, "id провайдера каталога внутри onclick"},
		{`' + r.id + '`, "id bypass-правила внутри onclick"},
		{`'+r.prefer_country+'`, "поле bypass-правила"},
		{`'+(info.ip||'—')+'`, "ответ стороннего API репутации IP"},
		{`'+(info.isp||'—')+'`, "ответ стороннего API репутации IP"},
		{`'+(info.asn||'—')+'`, "ответ стороннего API репутации IP"},
		{`'+(info.country||'—')+'`, "ответ стороннего API репутации IP"},
		{`'+(info.source||'—')+'`, "ответ стороннего API репутации IP"},
		{`'+s.update_interval_hours+'`, "поле источника"},
	}
	for _, u := range unescaped {
		if strings.Contains(webUI, u.frag) {
			t.Errorf("во встроенном UI осталась неэкранированная вставка %q (%s)", u.frag, u.why)
		}
	}
}

// Wails-окно опаснее встроенного UI: там window.go.main.App даёт доступ ко всем Go-биндингам,
// включая EmergencyWipe и SetMasterPassword, и CSP не выставлен.
func TestWailsUI_EscapeAndChainVizAreSafe(t *testing.T) {
	path := wailsIndexPath(t)
	if path == "" {
		t.Skip("gui/frontend/src/index.html не найден — модуль распространён отдельно")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("чтение %s: %v", path, err)
	}
	html := string(data)

	idx := strings.Index(html, "function esc(")
	if idx < 0 {
		t.Fatal("в Wails-окне не найдена функция esc")
	}
	body := html[idx:min(idx+600, len(html))]
	for _, c := range escapedChars {
		if !strings.Contains(body, c.frag) {
			t.Errorf("esc() Wails-окна не экранирует %s (%s)", c.name, c.frag)
		}
	}

	// updateChainViz — та самая точка, где имя узла вставлялось голой интерполяцией.
	rawInterp := regexp.MustCompile(`chain-node active"[^>]*\$\{n\.(name|address|port)\}`)
	if rawInterp.MatchString(html) {
		t.Error("updateChainViz вставляет поля узла без esc() — узел с именем " +
			`'<img src=x onerror=...>' из публичной подписки выполнит код`)
	}
	if strings.Contains(html, "${n.name}</div>") {
		t.Error("имя узла вставляется в chain-viz без экранирования")
	}
}

func wailsIndexPath(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for i := 0; i < 6; i++ {
		p := filepath.Join(dir, "gui", "frontend", "src", "index.html")
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
