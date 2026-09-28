package main

// L2-D (ТЗ v1.4, волна W2): структурные проверки gui/frontend/src/index.html — по образцу
// K2-D/K2-W (тест в Go, читает исходник фронтенда и сверяет id/тексты/подтверждения, а не
// поднимает реальный Wails-рантайм — правило лота, wails dev/build не запускать). Один общий
// helper readGuiSourceFile — из bindings_v14_test.go (тот же пакет main).

import (
	"regexp"
	"strings"
	"testing"
)

var (
	reOnclickCall = regexp.MustCompile(`onclick="([a-zA-Z_]\w*)\(`)
	reWindowFn    = regexp.MustCompile(`(?m)^window\.(\w+)\s*=`)
	reGlobalFn    = regexp.MustCompile(`(?m)^function (\w+)\s*\(`)
)

// TestNoOnclickReferencesUndefinedFunction — acceptance лота L2-D дословно: «ни одного
// onclick, ссылающегося на несуществующую функцию». Проверяет ВСЕ onclick="..." (статические
// и собранные JS-шаблонами для строк таблицы узлов/источников/каталога/bypass), не только
// вызовы App.*, которые уже проверяет bindings_v14_test.go отдельно.
func TestNoOnclickReferencesUndefinedFunction(t *testing.T) {
	html := readGuiSourceFile(t, "frontend/src/index.html")
	defined := map[string]bool{}
	for _, m := range reWindowFn.FindAllStringSubmatch(html, -1) {
		defined[m[1]] = true
	}
	for _, m := range reGlobalFn.FindAllStringSubmatch(html, -1) {
		defined[m[1]] = true
	}
	seen := map[string]bool{}
	for _, m := range reOnclickCall.FindAllStringSubmatch(html, -1) {
		name := m[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		if !defined[name] {
			t.Errorf(`onclick="%s(...)" ссылается на функцию, не определённую ни как `+
				`window.%s=, ни как function %s(...)`, name, name, name)
		}
	}
	if len(seen) == 0 {
		t.Fatal("не нашли ни одного onclick=\"...\" в index.html — регэксп или путь сломаны")
	}
}

// ─── 2026-09-23: интерфейс не тянет ничего из интернета ──────────────────────────────────
//
// Живой случай 1.1.8 на ПК: окно Wails было сплошь цвета BackgroundColour. Wails показывает окно
// и WebView только по NavigationCompleted (= событие load), а load ждал stylesheet с
// fonts.googleapis.com. Сверх того, интерфейс VPN-клиента обязан открываться без сети (APF
// нужен именно при блокировках и под Kill Switch) и не должен ходить в Google с реального IP до
// поднятия туннеля. Любой внешний src/href/url()/@import в index.html — регресс.
var reExternalResource = regexp.MustCompile(`(?i)(?:\b(?:src|href)\s*=\s*["']\s*(?:https?:)?//|url\(\s*["']?\s*(?:https?:)?//|@import\s+(?:url\()?\s*["']?\s*(?:https?:)?//)`)

func TestIndexHTML_NoExternalResources(t *testing.T) {
	html := readGuiSourceFile(t, "frontend/src/index.html")
	if loc := reExternalResource.FindStringIndex(html); loc != nil {
		start := loc[0] - 40
		if start < 0 {
			start = 0
		}
		end := loc[1] + 80
		if end > len(html) {
			end = len(html)
		}
		t.Fatalf("index.html подключает внешний ресурс — окно не откроется без сети и светит IP "+
			"до туннеля: …%s…", html[start:end])
	}
	for _, want := range []string{"'Cascadia Mono'", "'Segoe UI'"} {
		if !strings.Contains(html, want) {
			t.Errorf("в стеке шрифтов нет системного запасного %s — без внешних шрифтов текст "+
				"уйдёт в дефолтный шрифт браузера", want)
		}
	}
}

// ─── U-14: toast для завершённых действий ────────────────────────────────────────────────

func TestU14_ToastInfrastructureExists(t *testing.T) {
	html := readGuiSourceFile(t, "frontend/src/index.html")
	for _, want := range []string{"function showToast(", "#toast-stack", ".toast {", "ensureToastStack"} {
		if !strings.Contains(html, want) {
			t.Errorf("не найдено %q — инфраструктура toast (U-14) отсутствует", want)
		}
	}
	if !strings.Contains(html, "if (cls === 'ok' || cls === 'err') showToast(msg, cls)") {
		t.Error("addLog не вызывает showToast для классов 'ok'/'err' — U-14 не подключён к существующему журналу")
	}
}

func TestU14_ConnectErrorsAreCaught(t *testing.T) {
	html := readGuiSourceFile(t, "frontend/src/index.html")
	if !strings.Contains(html, "apf:connect_error") {
		t.Error("не найдено событие apf:connect_error — асинхронная ошибка App.Connect() владельца молча терялась (U-14)")
	}
	// doConnect/doScan обязаны ловить исключение из await App.Connect() (наблюдатель шлёт
	// синхронный HTTP-запрос и может вернуть ошибку прямо в промис) — раньше это был
	// необработанный отклонённый промис без единого следа для пользователя.
	fnBodies := map[string]string{
		"doConnect": extractFunctionBody(t, html, "window.doConnect = async function() {"),
		"doScan":    extractFunctionBody(t, html, "window.doScan = async function() {"),
	}
	for name, body := range fnBodies {
		if !strings.Contains(body, "catch") {
			t.Errorf("%s не оборачивает await App.Connect() в try/catch", name)
		}
	}
}

// extractFunctionBody — грубый вырез текста от маркера начала функции до соответствующей
// закрывающей '}' на нулевом уровне вложенности. Достаточно для plain-text проверок этого
// файла (не заменяет полноценный JS-парсер, но не пытается его изображать).
func extractFunctionBody(t *testing.T, html, startMarker string) string {
	t.Helper()
	idx := strings.Index(html, startMarker)
	if idx < 0 {
		t.Fatalf("не найден маркер %q", startMarker)
	}
	rest := html[idx+len(startMarker):]
	depth := 1
	for i, r := range rest {
		switch r {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return rest[:i]
			}
		}
	}
	t.Fatalf("не нашли конец функции для маркера %q", startMarker)
	return ""
}

// ─── U-15: недостижимая подсказка / мёртвый тумблер / A18 ───────────────────────────────

func TestU15a_LockedToggleTooltipUsesWrapper(t *testing.T) {
	html := readGuiSourceFile(t, "frontend/src/index.html")
	if strings.Count(html, `<span class="toggle-wrap">`) < 2 {
		t.Error("ожидались 2 обёртки .toggle-wrap (Dashboard + Настройки тумблера режима VPN) — E2 #17")
	}
	if !strings.Contains(html, "el.closest('.toggle-wrap') || el") {
		t.Error("setConnectionLockedControls не переключён на title у .toggle-wrap — подсказка заблокированного тумблера всё ещё недостижима (pointer-events:none блокирует hover)")
	}
}

func TestU15b_SourceToggleHasOnclick(t *testing.T) {
	html := readGuiSourceFile(t, "frontend/src/index.html")
	if !strings.Contains(html, "onclick=\"toggleSource(") {
		t.Error("тумблер источника (renderSources) по-прежнему без onclick — D3 §6.2")
	}
	if !strings.Contains(html, "window.toggleSource = async function(idx)") {
		t.Error("не найдена реализация window.toggleSource")
	}
}

func TestU15g_SaveButtonRemoved(t *testing.T) {
	html := readGuiSourceFile(t, "frontend/src/index.html")
	// Функциональные следы, не упоминания в объясняющих комментариях (история про то, что
	// раньше делал saveAllSettings, — легитимный контекст, не предмет этой проверки).
	if strings.Contains(html, "window.saveAllSettings =") {
		t.Error("window.saveAllSettings всё ещё определена — решение лота: удалить (кнопка ничего не делала, чего не было бы уже применено немедленно), см. result.md")
	}
	if strings.Contains(html, `onclick="saveAllSettings()"`) {
		t.Error("кнопка «Сохранить» всё ещё в разметке")
	}
}

func TestA18_DeadDegradationBranchRemoved(t *testing.T) {
	html := readGuiSourceFile(t, "frontend/src/index.html")
	body := extractFunctionBody(t, html, "function resolveVerifyState(s) {")
	if strings.Contains(body, "var(--re)") {
		t.Error("resolveVerifyState всё ещё красит какую-то ветку в var(--re) (красный) — A18 требовал убрать красный idle вместе с мёртвой деградацией")
	}
	if strings.Contains(body, "s.connected") {
		t.Error("resolveVerifyState всё ещё содержит ad-hoc деградацию по s.connected/s.verified — мёртвый код (движок всегда отдаёт verify_state) должен быть удалён")
	}
}

// ─── U-16-desktop: единое имя + confirm на WebRTC off ───────────────────────────────────

func TestU16_ChangeServerButtonNameUnified(t *testing.T) {
	html := readGuiSourceFile(t, "frontend/src/index.html")
	if strings.Count(html, "⇄</span> Сменить сервер") < 2 {
		t.Error(`ожидались 2 вхождения "⇄ Сменить сервер" (Dashboard + Настройки) — единое имя по контракту §1.1`)
	}
}

func TestU16_WebRTCOffHasConfirm(t *testing.T) {
	html := readGuiSourceFile(t, "frontend/src/index.html")
	body := extractFunctionBody(t, html, "window.toggleWebRTC = async function(el) {")
	if !strings.Contains(body, "confirm(") {
		t.Error("toggleWebRTC всё ещё без confirm() на выключение — единственная из шести опасных защит без подтверждения (контракт §4.2 п.6)")
	}
	if !strings.Contains(body, "Выключить блокировку WebRTC?") {
		t.Error(`текст confirm не совпадает дословно с контрактом §4.3 ("Выключить блокировку WebRTC?")`)
	}
}

// ─── U-17-desktop: предупреждение «узлы не сохранены» ───────────────────────────────────

func TestU17_LastPersistErrorWired(t *testing.T) {
	html := readGuiSourceFile(t, "frontend/src/index.html")
	if !strings.Contains(html, "App.GetLastPersistError()") {
		t.Error("index.html не вызывает App.GetLastPersistError() — U-17-desktop не подключён")
	}
	if !strings.Contains(html, `id="nodes-persist-warn"`) {
		t.Error(`элемент #nodes-persist-warn не найден рядом со списком узлов`)
	}
	if !strings.Contains(html, "узлы не сохранены:") {
		t.Error(`текст предупреждения не совпадает с контрактом §7.2 ("узлы не сохранены: <причина>")`)
	}
}

// ─── S-3-frontend: приватный ключ только явным подтверждённым действием ─────────────────

func TestS3_ExportIdentityRequiresConfirm(t *testing.T) {
	html := readGuiSourceFile(t, "frontend/src/index.html")
	body := extractFunctionBody(t, html, "window.doStartServerRole = async function() {")
	if !strings.Contains(body, "App.ServerRoleExportIdentity()") {
		t.Error("doStartServerRole не вызывает App.ServerRoleExportIdentity() — при пустом PrivateKey (наблюдатель, S-3 сервера уже редактирует GET) роль «Выход» тихо стартовала бы с пустым ключом")
	}
	if !strings.Contains(body, "confirm(") {
		t.Error("экспорт ключа звена целиком не запрашивает подтверждения пользователя (S-3-frontend требует явное подтверждённое действие)")
	}
	if !strings.Contains(body, "srIdentity.PrivateKey") {
		t.Error("doStartServerRole не проверяет srIdentity.PrivateKey перед стартом — условие экспорта отсутствует")
	}
}

// ─── C-20-ui: «через туннель» только для TUN-bound замера ───────────────────────────────

func TestC20_TunnelWordingGatedByVerifiedVia(t *testing.T) {
	html := readGuiSourceFile(t, "frontend/src/index.html")
	body := extractFunctionBody(t, html, "function verifiedInfoText(n) {")
	if !strings.Contains(body, "last_verified_via === 'tun'") {
		t.Error(`"через туннель" не привязано к last_verified_via==='tun' — риск того же нарушения C-20, что уже нашёл живой прогон на Android/Web`)
	}
	if !strings.Contains(body, "через прокси-канал узла") {
		t.Error(`SOCKS5-замер не подписан честно "через прокси-канал узла" (контракт §2.4)`)
	}
}

// TestC20_NoRawTunnelWordingNearLatencyField — grep-страж из решения ТЗ C-20: слово «через
// туннель» не должно стоять рядом со значением last_verified_latency_ms без разбора via.
// Единственное место, где это слово вообще стоит рядом с задержкой узла, — сама функция
// verifiedInfoText, и там оно уже под условием (проверено тестом выше). Ищем другие места.
func TestC20_NoRawTunnelWordingNearLatencyField(t *testing.T) {
	html := readGuiSourceFile(t, "frontend/src/index.html")
	for _, line := range strings.Split(html, "\n") {
		if strings.Contains(line, "last_verified_latency_ms") && strings.Contains(line, "через туннель") {
			t.Errorf("строка подписывает last_verified_latency_ms словом «через туннель» напрямую, без проверки via: %q", strings.TrimSpace(line))
		}
	}
}

// ─── C-21-ui: метка каталога vs фактический выход ───────────────────────────────────────

func TestC21_DualCountryLabelWired(t *testing.T) {
	html := readGuiSourceFile(t, "frontend/src/index.html")
	for _, want := range []string{"n.catalog_country", "n.exit_country", "n.country_mismatch"} {
		if !strings.Contains(html, want) {
			t.Errorf("не найдено использование поля %s — C-21-ui не подключён во фронте", want)
		}
	}
}

// ─── V13-5-wails: тост needs_restart ─────────────────────────────────────────────────────

func TestV13_5_NeedsRestartSurfaced(t *testing.T) {
	html := readGuiSourceFile(t, "frontend/src/index.html")
	if !strings.Contains(html, "needsRestart") {
		t.Error("needsRestart нигде не читается во фронте — PatchConfig теперь возвращает его, но никто не использует")
	}
	if strings.Count(html, "применится после перезапуска APF") < 1 {
		t.Error(`не найден текст "применится после перезапуска APF" — тост needs_restart не показывается пользователю`)
	}
}

// ─── R12-4-ui: 12 no-op полей models.AppConfig — не должны выглядеть рабочими ────────────

// noOpAppConfigJSONKeys — полный список из docs/TZ_APF_ROADMAP_v1.2.md:372 (P5), по JSON-
// тегам models.AppConfig (internal/models/node.go), кроме EmergencyHotkey (уже покрыт P1.1,
// см. gui/app.go registerEmergencyHotkey) и DNSLeakTestInterval (уже оживлён отдельно от
// этого лота, по тексту R12-4 ТЗ v1.4). Ключи, а не Go-имена полей: PascalCase-имя вроде
// BypassList ложно совпало бы с совершенно другой, РАБОЧЕЙ функцией renderBypassList()
// (App.GetBypassRules/AddBypassDomain — список доменов-исключений, не models.AppConfig.
// BypassList) — снято этим лотом как находка при первом прогоне теста.
//
// Проверка: ни один JSON-ключ не появляется как data-key/PatchConfig-ключ в Wails UI — то
// есть интерфейс не изображает контрол для настройки, которой физически не существует (Ц3).
// Все десять отсутствуют полностью → R12-4-ui для Wails не требует ни удаления, ни оживления
// ни одного контрола (в отличие от Android/Web, где решение может быть другим — вне
// периметра L2-D).
var noOpAppConfigJSONKeys = []string{
	"setup_done", "user_country", "notify_on_switch", "notify_on_fail", "encrypt_storage",
	"max_latency_ms", "dns_over_tls", "bypass_list", "force_list", "singbox_path",
}

func TestR12_4_NoOpFieldsHaveNoDeadControlInWails(t *testing.T) {
	html := readGuiSourceFile(t, "frontend/src/index.html")
	for _, key := range noOpAppConfigJSONKeys {
		if strings.Contains(html, key) {
			t.Errorf("JSON-ключ %q из списка 12 no-op AppConfig (docs/TZ_APF_ROADMAP_v1.2.md:372) "+
				"упомянут в index.html — если это UI-контрол, R12-4 требует его оживить или убрать", key)
		}
	}
}
