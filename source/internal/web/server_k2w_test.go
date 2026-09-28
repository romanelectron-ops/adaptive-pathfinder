// server_k2w_test.go — K2-W (свод C, трек 1, аудит 2026-09-07): правки Web UI.
//
// Источники находок: C_SVOD.md (трек 1, пп.9/10/14/17/18), E1/result.md (§2в — расчёт
// контраста .help-ico), E2/result.md (§4 — асимметрия подтверждений на снятие защиты),
// B3/result.md (FSM врёт), B4/result.md (#5 — наложение wiz-setup/wiz-privacy), F1 (raw
// goroutine в apiCatalogRefresh).
//
// Как и xss_escaping_test.go/server_verify_badge_test.go, часть тестов ниже проверяет ТЕКСТ
// встроенного webUI (HTML/CSS/JS как строка), а не поведение JS в браузере — полноценный
// прогон JS требовал бы headless-движка; инвариант «нужная строка/подстрока присутствует или
// отсутствует» проверяется статически и ловит регрессию тем же способом, каким её нашёл
// аудит (grep по файлу).
package web

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/apf/adaptive-pathfinder/internal/engine"
)

// ── П17: контраст .help-ico ≥3:1 (WCAG 2.1 1.4.11, UI-компоненты) ────────────────────────

// srgbToLinear — линеаризация одного канала sRGB (0..1) по формуле WCAG.
func srgbToLinear(c float64) float64 {
	if c <= 0.03928 {
		return c / 12.92
	}
	return math.Pow((c+0.055)/1.055, 2.4)
}

// relLuminance — относительная яркость WCAG для #RRGGBB.
func relLuminance(hex string) float64 {
	hex = strings.TrimPrefix(hex, "#")
	r, _ := strconv.ParseInt(hex[0:2], 16, 0)
	g, _ := strconv.ParseInt(hex[2:4], 16, 0)
	b, _ := strconv.ParseInt(hex[4:6], 16, 0)
	rl := srgbToLinear(float64(r) / 255)
	gl := srgbToLinear(float64(g) / 255)
	bl := srgbToLinear(float64(b) / 255)
	return 0.2126*rl + 0.7152*gl + 0.0722*bl
}

// contrastRatio — контраст WCAG между двумя #RRGGBB (порядок не важен).
func contrastRatio(hexA, hexB string) float64 {
	la, lb := relLuminance(hexA), relLuminance(hexB)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// cssVars извлекает переменные вида --name:#hex из блока :root{...} встроенного webUI.
func cssVars(t *testing.T) map[string]string {
	t.Helper()
	idx := strings.Index(webUI, ":root{")
	if idx < 0 {
		t.Fatal("во встроенном UI не найден блок :root{...} с токенами цвета")
	}
	end := strings.Index(webUI[idx:], "}")
	if end < 0 {
		t.Fatal(":root{...} не закрыт")
	}
	block := webUI[idx : idx+end]
	vars := map[string]string{}
	re := regexp.MustCompile(`(--[a-z0-9]+):(#[0-9a-fA-F]{6})`)
	for _, m := range re.FindAllStringSubmatch(block, -1) {
		vars[m[1]] = m[2]
	}
	return vars
}

// helpIcoColorVar извлекает имя CSS-переменной, использованной как color в правиле .help-ico.
func helpIcoColorVar(t *testing.T) string {
	t.Helper()
	idx := strings.Index(webUI, ".help-ico{")
	if idx < 0 {
		t.Fatal("во встроенном UI не найден класс .help-ico")
	}
	end := strings.Index(webUI[idx:], "}")
	if end < 0 {
		t.Fatal(".help-ico{...} не закрыт")
	}
	rule := webUI[idx : idx+end]
	re := regexp.MustCompile(`[^-]color:var\((--[a-z0-9]+)\)`)
	m := re.FindStringSubmatch(rule)
	if m == nil {
		t.Fatalf(".help-ico не задаёт color через var(--...): %q", rule)
	}
	return m[1]
}

// TestHelpIcoContrast_MeetsWCAG — П17 (E1 §2в): до фикса .help-ico красился var(--t3)=#484f58
// на фоне var(--bg)=#0d1117 — расчёт по формуле WCAG даёт ≈2.29:1, ниже порога 3:1 даже для
// UI-компонентов/крупного текста (WCAG 2.1 1.4.11). ~22 применения по файлу — единственная
// точка входа в справку почти на каждой настройке. Тест вычисляет контраст РЕАЛЬНОГО текущего
// токена .help-ico против --bg и падает, если он ниже 3:1 — ловит как старое значение (--t3),
// так и любой будущий откат к недостаточно контрастному токену.
func TestHelpIcoContrast_MeetsWCAG(t *testing.T) {
	vars := cssVars(t)
	bg, ok := vars["--bg"]
	if !ok {
		t.Fatal("--bg не найден в :root")
	}
	varName := helpIcoColorVar(t)
	hex, ok := vars[varName]
	if !ok {
		t.Fatalf(".help-ico использует var(%s), но он не определён в :root", varName)
	}
	got := contrastRatio(hex, bg)
	const threshold = 3.0
	if got < threshold {
		t.Errorf(".help-ico: контраст %s (%s) на %s (--bg) = %.2f:1, ниже порога WCAG %.0f:1 "+
			"для UI-компонентов — до фикса был var(--t3)=#484f58 ≈2.29:1", varName, hex, bg, got, threshold)
	}
	// Регрессия конкретно на признанный виновник аудита: явно НЕ должен остаться --t3.
	if varName == "--t3" {
		t.Errorf(".help-ico всё ещё использует var(--t3) (%s) — контраст с --bg ≈%.2f:1, найденный дефект E1 §2в не исправлен", hex, got)
	}
}

// ── П10: fsm_state снят с экрана диагностики (B3 — таблица FSM мертва и врёт) ────────────

// TestDiagFSM_RemovedFromDiagnosticsScreen — server.go:2261-2263 (до фикса) показывал
// fsm_state мёртвой машины состояний (TunnelFSM.Connect движком не вызывается, B3 §подтверждено
// по коду engine.go:480 и др.) как будто это правда. Поле снято с экрана диагностики целиком.
func TestDiagFSM_RemovedFromDiagnosticsScreen(t *testing.T) {
	if strings.Contains(webUI, `id="diag-fsm"`) {
		t.Error(`диагностика всё ещё содержит id="diag-fsm" — врущее поле fsm_state не снято с экрана (П10)`)
	}
	if strings.Contains(webUI, `<span class="srow-title">FSM</span>`) {
		t.Error(`диагностика всё ещё содержит подпись "FSM" — врущее поле не снято с экрана (П10)`)
	}
	if strings.Contains(webUI, "d.fsm_state") {
		t.Error("JS всё ещё читает d.fsm_state — привязка к врущему полю не убрана (П10)")
	}
}

// ── П9: Traffic Padding помечен «не реализовано», активных тумблеров нет ────────────────

// TestTrafficPadding_NotActivePromise — движок отдаёт padding_enabled=false не потому, что
// пользователь его не включил, а потому что защита не применяется к туннелю (см. C_SVOD.md
// трек1 п.9, B1 #5/B3 #4/D6). До фикса на экране DPI стоял активный тумблер setPadding(),
// обещающий маскировку трафика, которой нет. Тумблер должен быть либо убран, либо помечен
// «не реализовано» без интерактивного элемента, который выглядит рабочим.
func TestTrafficPadding_NotActivePromise(t *testing.T) {
	idx := strings.Index(webUI, "Traffic Padding")
	if idx < 0 {
		t.Fatal("панель Traffic Padding не найдена во встроенном UI")
	}
	// Панель должна явно предупреждать, что защита не реализована — берём достаточно большое
	// окно текста после заголовка, чтобы захватить и заголовок, и info-box, и обе строки.
	window := webUI[idx:min2(idx+1600, len(webUI))]
	if !strings.Contains(window, "не реализовано") {
		t.Error("панель Traffic Padding не помечена как «не реализовано» (П9)")
	}
	if strings.Contains(webUI, "setPadding(this,") {
		t.Error(`во встроенном UI остался активный тумблер onclick="setPadding(this,...)" — ` +
			"он обещает защиту, которой движок не применяет (П9)")
	}
	if strings.Contains(webUI, `id="t-pad-std"`) || strings.Contains(webUI, `id="t-pad-agg"`) {
		t.Error("тумблеры Traffic Padding (t-pad-std/t-pad-agg) всё ещё присутствуют как интерактивные элементы (П9)")
	}
}

// ── П14: confirm() на ВЫКЛЮЧЕНИЕ Kill Switch/IPv6, включение — без изменений ────────────

// extractFunc возвращает исходный текст JS-функции name(...) {...} из webUI по балансу
// фигурных скобок (простые функции без вложенных строк с '{'/'}' — этого достаточно для
// функций сервера, они не содержат JS-объектных литералов с фигурными скобками в текстах).
func extractFunc(t *testing.T, name string) string {
	t.Helper()
	idx := strings.Index(webUI, "function "+name+"(")
	if idx < 0 {
		t.Fatalf("функция %s не найдена во встроенном UI", name)
	}
	open := strings.Index(webUI[idx:], "{")
	if open < 0 {
		t.Fatalf("у функции %s не найдено открывающей { ", name)
	}
	start := idx + open
	depth := 0
	for i := start; i < len(webUI); i++ {
		switch webUI[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return webUI[idx : i+1]
			}
		}
	}
	t.Fatalf("не удалось найти конец функции %s (не сбалансированы скобки)", name)
	return ""
}

// TestTogInstant_KillSwitchOffRequiresConfirm — server.go:togInstant (было server.go:3409-3425
// до правок) применяло enable_kill_switch:false мгновенно, без единого вопроса — асимметрично
// Wails, где ВКЛЮЧЕНИЕ Kill Switch уже подтверждается (E2 §4). Включение должно остаться
// без confirm(), выключение — получить его.
func TestTogInstant_KillSwitchOffRequiresConfirm(t *testing.T) {
	body := extractFunc(t, "togInstant")
	if !strings.Contains(body, "confirm(") {
		t.Fatal("togInstant не содержит confirm() — подтверждение на выключение Kill Switch не добавлено (П14)")
	}
	if !regexp.MustCompile(`!turningOn\s*&&\s*key===['"]enable_kill_switch['"]`).MatchString(body) &&
		!regexp.MustCompile(`key===['"]enable_kill_switch['"]\s*&&\s*!turningOn`).MatchString(body) {
		t.Error("togInstant: confirm() не гейтится условием «выключение enable_kill_switch» — " +
			"либо confirm не на том месте, либо ловит и включение тоже (должно остаться без confirm)")
	}
}

// TestToggleIPv6_OffRequiresConfirm — server.go:toggleIPv6 (Leak Guard card) применяло
// enabled:!enabled мгновенно без confirm(); турнинг off должен теперь спрашивать (П14).
func TestToggleIPv6_OffRequiresConfirm(t *testing.T) {
	body := extractFunc(t, "toggleIPv6")
	if !strings.Contains(body, "confirm(") {
		t.Fatal("toggleIPv6 не содержит confirm() — подтверждение на выключение IPv6 Leak Block не добавлено (П14)")
	}
	// confirm должен быть внутри ветки "if(enabled)" (сейчас включён → собираемся выключить),
	// и должен идти РАНЬШЕ fetch() — иначе не гейтит запрос.
	confirmIdx := strings.Index(body, "confirm(")
	fetchIdx := strings.Index(body, "fetch(")
	ifEnabledIdx := strings.Index(body, "if(enabled)")
	if ifEnabledIdx < 0 || confirmIdx < ifEnabledIdx {
		t.Error("toggleIPv6: confirm() не находится внутри ветки if(enabled) (выключение) — " +
			"проверьте, что включение осталось без confirm")
	}
	if fetchIdx < 0 || confirmIdx > fetchIdx {
		t.Error("toggleIPv6: confirm() идёт после fetch() — не гейтит запрос к /api/leakguard/ipv6")
	}
}

// TestDisableCrypto_AlreadyHasConfirm — регрессия: подтверждение на отключение шифрования
// (мастер-пароля) уже существовало ДО этого лота (server.go:3591 в аудите E2 §4) и по брифу
// П14 изменяться не должно. Тест защищает инвариант от случайного удаления в будущем.
func TestDisableCrypto_AlreadyHasConfirm(t *testing.T) {
	body := extractFunc(t, "disableCrypto")
	if !strings.Contains(body, "confirm(") {
		t.Error("disableCrypto лишилась confirm() — регрессия по сравнению с состоянием до аудита 2026-09-07")
	}
}

// ── B4 #5: startWizFlow больше не накладывает #wiz-setup и #wiz-privacy ─────────────────

// TestStartWizFlow_HidesOtherPanel — startPrivacyWizard() кликает по пункту «Мастер» (что
// показывает #wiz-setup через переключатель страниц), затем зовёт startWizFlow('privacy'),
// который до фикса включал #wiz-privacy, но не выключал #wiz-setup — оба блока оставались
// видимыми одновременно (B4 #5, server.go:4199-4207/:4328-4331 в нумерации аудита).
func TestStartWizFlow_HidesOtherPanel(t *testing.T) {
	body := extractFunc(t, "startWizFlow")
	setupBranch := regexp.MustCompile(`flow===['"]setup['"]\)\{([^}]*)\}`).FindStringSubmatch(body)
	if setupBranch == nil {
		t.Fatal("не найдена ветка flow==='setup' в startWizFlow")
	}
	if !strings.Contains(setupBranch[1], "priv.style.display='none'") &&
		!strings.Contains(setupBranch[1], `priv.style.display="none"`) {
		t.Error("startWizFlow: ветка flow==='setup' не прячет #wiz-privacy — панели могут наложиться (B4 #5)")
	}
	privBranch := regexp.MustCompile(`flow===['"]privacy['"]\)\{([^}]*)\}`).FindStringSubmatch(body)
	if privBranch == nil {
		t.Fatal("не найдена ветка flow==='privacy' в startWizFlow")
	}
	if !strings.Contains(privBranch[1], "setup.style.display='none'") &&
		!strings.Contains(privBranch[1], `setup.style.display="none"`) {
		t.Error("startWizFlow: ветка flow==='privacy' не прячет #wiz-setup — воспроизводит живую находку B4 #5 (наложение при заходе через Помощь → Privacy Wizard)")
	}
}

// ── П18: apiCatalogRefresh больше не запускает голую go func() вне трекинга ─────────────

// TestApiCatalogRefresh_BackgroundStopsOnServerClose — до фикса apiCatalogRefresh запускал
// `go func(){...}()` с context.Background() (F1): такая горутина переживает завершение
// обработчика/теста/остановку сервера. Инжектируем через catalogRefreshFn наблюдаемую
// подмену RefreshCatalog, которая блокируется на ctx.Done(), и проверяем, что s.Close()
// действительно отменяет её контекст в разумное время — без фикса ctx никогда не отменится
// (context.Background() не имеет Done()), и тест зависал бы до таймаута select.
func TestApiCatalogRefresh_BackgroundStopsOnServerClose(t *testing.T) {
	s := newTestServer(t)

	started := make(chan struct{})
	cancelled := make(chan struct{})
	orig := catalogRefreshFn
	defer func() { catalogRefreshFn = orig }()
	catalogRefreshFn = func(eng *engine.Engine, ctx context.Context) (int, error) {
		close(started)
		<-ctx.Done()
		close(cancelled)
		return 0, ctx.Err()
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/catalog/refresh", nil)
	s.apiCatalogRefresh(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("apiCatalogRefresh: код ответа = %d, ожидался 200", w.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("не удалось разобрать ответ: %v", err)
	}
	if resp["status"] != "refreshing" {
		t.Fatalf(`status = %q, ожидался "refreshing"`, resp["status"])
	}

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("фоновая горутина apiCatalogRefresh не стартовала за 2с")
	}

	s.Close()

	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("s.Close() не отменил контекст фоновой задачи apiCatalogRefresh за 2с — " +
			"голая go func() без трекинга регрессировала (П18)")
	}
}

func min2(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── B4 #4 (опционально): кнопки pin/favorite/ban/connect-once в строке таблицы узлов ────

// TestNodeRowActions_WiredToExistingRoutes — до фикса значки 📌/⭐/🚫 в таблице узлов
// (server.go:3127-3133 в нумерации аудита) только ОТОБРАЖАЛИ состояние — 11 существующих
// маршрутов (/api/pin, /api/favorite, /api/node/ban, /api/connect-once и др.) не были
// доступны ни одной кнопкой в строке. Проверяем, что renderNodes теперь строит кнопки,
// вызывающие все четыре маршрута.
func TestNodeRowActions_WiredToExistingRoutes(t *testing.T) {
	body := extractFunc(t, "renderNodes")
	wantCalls := []string{"doPinNode(", "doFavoriteNode(", "doBanNode(", "doConnectOnce("}
	for _, c := range wantCalls {
		if !strings.Contains(body, c) {
			t.Errorf("renderNodes: не найден вызов %s в строке таблицы узлов (B4 #4)", c)
		}
	}
	// Значение n.id обязано идти через esc() перед вставкой в onclick="...('...')" — тот же
	// приём, что esc(p.id)/esc(r.id) выше по файлу (P0-3, найденная и закрытая XSS-дыра).
	if !strings.Contains(body, "esc(n.id") {
		t.Error("renderNodes: id узла вставляется в onclick без esc() — потенциальный XSS через имя/id из подписки (B4 #4)")
	}
}

// TestNodeRowActionFuncs_CallExpectedEndpoints — каждая из 4 функций обязана бить в СВОЙ,
// а не чужой, уже существующий маршрут (перепутать местами — тихая, трудно замечаемая
// регрессия: например, кнопка «избранное» вместо /api/favorite могла бы случайно уйти
// в /api/pin и молча закреплять узел вместо добавления в избранное).
func TestNodeRowActionFuncs_CallExpectedEndpoints(t *testing.T) {
	cases := []struct {
		fn       string
		endpoint string
	}{
		{"doPinNode", "/api/pin"},
		{"doFavoriteNode", "/api/favorite"},
		{"doBanNode", "/api/node/ban"},
		{"doConnectOnce", "/api/connect-once"},
	}
	for _, c := range cases {
		body := extractFunc(t, c.fn)
		if !strings.Contains(body, "B+'"+c.endpoint+"'") {
			t.Errorf("%s не вызывает fetch(B+'%s') — проверьте, что кнопка бьёт в правильный маршрут (B4 #4)", c.fn, c.endpoint)
		}
	}
}

// TestDoBanNode_BanRequiresConfirm — забанить узел из таблицы — риск того же класса, что и
// остальные подтверждаемые действия над узлом в этом файле (Android подтверждает бан узла
// диалогом); разбанить обратно — без вопроса, симметрично остальным П14-подобным решениям
// этого лота (спрашиваем только при усилении ограничения, не при снятии).
func TestDoBanNode_BanRequiresConfirm(t *testing.T) {
	body := extractFunc(t, "doBanNode")
	if !strings.Contains(body, "confirm(") {
		t.Fatal("doBanNode не содержит confirm() — бан узла применяется без подтверждения (B4 #4)")
	}
	if !strings.Contains(body, "banned&&!confirm(") {
		t.Error("doBanNode: confirm() не гейтится условием banned (постановка в бан) — разбан не должен спрашивать")
	}
}
