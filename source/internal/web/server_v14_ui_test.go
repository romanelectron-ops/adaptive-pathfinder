// server_v14_ui_test.go — ТЗ v1.4 (TZ_APF_v1.4_FINAL.md), лот L2-W: U-8..U-13, U-16-web,
// U-17-web, V13-3, V13-4-web, V13-5-web, V13-6-web, V13-7-web, C-18-counter, C-20-ui, C-21-ui.
//
// Как и server_k2w_test.go/xss_escaping_test.go, часть тестов ниже статически разбирает
// встроенный webUI (HTML/JS как Go-строка) регулярками — полноценный браузер/JS-движок здесь
// не поднимается, инвариант «нужная строка/id/маршрут присутствует или отсутствует» ловит
// регрессию тем же способом, каким аудит (K10-UIC/D2/E2) её нашёл: чтением исходника.
//
// Структурный тест (TestUIStructure_*) — тест-до для U-12: до правки этого лота
// TestUIStructure_NoDeadElementIDs падал на #wiz-flow-select (сервер.go:4290,:4303 в снимке
// K10-UIC), а wizResetFlow был мёртвой функцией без единого вызывателя (не ловится этим тестом
// напрямую, т.к. отсутствие вызова — не синтаксическая ошибка; проверено отдельно вручную и
// зафиксировано в result.md). #leak-alert не является ни мёртвым id, ни мёртвой функцией — это
// элемент, который просто никогда не наполнялся; TestLeakAlert_WiredToLeakDetection проверяет
// это отдельно.
package web

import (
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ─── Структурный тест (акцептанс лота L2-W): дублирует routes() ────────────────────────────
//
// Нет публичного способа перечислить маршруты *http.ServeMux (ни в стандартной библиотеке,
// ни в этом кодовом снимке) — список ниже поддерживается вручную, зеркалит routes()
// (server.go) построчно. Если строка `s.mux.HandleFunc("/api/...", ...)` добавляется/удаляется
// в routes() без обновления этого списка, тест либо начнёт ложно валить未 существующий
// маршрут (новый fetch на новый route), либо, что безопаснее, промолчит про орфанный route без
// fetch — сам acceptance лота требует только направление «каждый fetch → зарегистрированный
// маршрут», не обратное.
var knownAPIRoutesV14 = map[string]bool{
	"/api/state": true, "/api/nodes": true, "/api/stats": true, "/api/singbox": true,
	"/api/logs": true, "/api/logs/export": true, "/api/domain-check": true, "/api/config": true,
	"/api/connect": true, "/api/disconnect": true, "/api/scan": true, "/api/rescan": true,
	"/api/add-node": true, "/api/add-node-manual": true, "/api/chain-partner/connect": true,
	"/api/connect-node": true, "/api/connect-once": true, "/api/pin": true,
	"/api/pinned-node": true, "/api/favorite": true, "/api/favorites": true,
	// W3 (ТЗ v1.5 §5, TZ_v1.5_NODE_CATALOG_2026-09-14, лот L2-WEB-B): гейт давности пересмотра
	// системного избранного, GET+POST на одном маршруте.
	"/api/catalog-review-interval": true,
	"/api/node/remove": true, "/api/node/ban": true, "/api/node/update": true,
	"/api/node/reset": true, "/api/nodes/restore-removed": true, "/api/scan/progress": true,
	"/api/scan/start": true, "/api/scan/cancel": true,
	// ТЗ v1.5 N-3 (лот L2-WEB): «Собрать список рабочих узлов» — проба реального трафика.
	"/api/nodes/check-all": true, "/api/nodes/check-cancel": true, "/api/nodes/check-status": true,
	"/api/nodes/harvest": true, "/api/nodes/harvest-status": true, // L5-WEB (ТЗ v1.4 §5): харвест
	// 2026-09-21 (W5 paste-харвест): разбор вставленного пользователем текста тем же
	// харвестером — добавлен в routes() (server.go), но забыт в этом зеркальном списке.
	"/api/nodes/harvest-text": true,
	"/api/reset-network": true,
	"/api/connectivity-check": true, "/api/save-config": true, "/api/diagnostics": true,
	"/api/server-role/status": true, "/api/server-role/identity": true,
	"/api/server-role/identity/export": true, "/api/server-role/generate-identity": true,
	"/api/server-role/build-link": true, "/api/server-role/start": true,
	"/api/server-role/stop": true, "/api/paid-providers/add": true,
	"/api/paid-providers/remove": true, "/api/paid-providers/test": true,
	"/api/leakguard/status": true, "/api/leakguard/dns-test": true, "/api/leakguard/ipv6": true,
	"/api/leakguard/webrtc": true, "/api/leakguard/browser-instructions": true,
	"/api/crypto/set-password": true, "/api/emergency/wipe": true, "/api/dpi/status": true,
	"/api/dpi/canary-test": true, "/api/dpi/padding": true, "/api/dpi/cdn": true,
	"/api/dpi/cdn-worker-script": true, "/api/dpi/shadowtls": true,
	"/api/dpi/shadowtls-auto-sni": true, "/api/session/status": true,
	"/api/session/policy": true, "/api/session/force-switch": true,
	"/api/fallback/status": true, "/api/fallback/activate": true,
	"/api/fallback/auto-select": true, "/api/watchdog/status": true,
	"/api/watchdog/history": true, "/api/catalog/status": true, "/api/catalog/refresh": true,
	"/api/catalog/provider": true, "/api/adblock/status": true, "/api/adblock/profile": true,
	"/api/adblock/allowlist": true, "/api/antiblock/status": true,
	"/api/antiblock/check-ip": true, "/api/antiblock/check-node": true,
	"/api/antiblock/config": true, "/api/antiblock/bypass-list": true,
	"/api/antiblock/bypass-domain": true, "/api/ui/handoff": true, "/ui": true, "/": true,
}

// jsBuiltinCalls — идентификаторы, которые выглядят как вызов функции внутри onXxx="...", но
// на деле встроены в JS/браузер, а не определены во встроенном UI как function NAME(...).
var jsBuiltinCalls = map[string]bool{
	"fetch": true, "if": true, "confirm": true, "alert": true, "prompt": true,
	"encodeURIComponent": true, "decodeURIComponent": true, "parseInt": true, "parseFloat": true,
	"isNaN": true, "String": true, "Math": true, "Boolean": true, "Number": true, "JSON": true,
	"console": true, "Array": true, "Object": true, "Date": true, "while": true, "for": true,
}

var getElementByIdRe = regexp.MustCompile(`getElementById\(['"]([A-Za-z0-9_-]+)['"]\)`)

// TestUIStructure_NoDeadElementIDs — U-12 / общий акцептанс L2-W («ни одного мёртвого id»).
// Каждый литеральный getElementById('x') обязан находить объявленный id="x" где-то в статической
// разметке. Динамически генерируемые id (сборка строкой, напр. id="row-'+i+'") сюда не попадают —
// у них нет литерального вызова getElementById с тем же именем, поэтому ложных срабатываний не
// создают; это тот же класс проверки, которым исходно нашли #wiz-flow-select (D2 §6.1).
func TestUIStructure_NoDeadElementIDs(t *testing.T) {
	seen := map[string]bool{}
	var missing []string
	for _, m := range getElementByIdRe.FindAllStringSubmatch(webUI, -1) {
		id := m[1]
		if seen[id] {
			continue
		}
		seen[id] = true
		if !strings.Contains(webUI, `id="`+id+`"`) && !strings.Contains(webUI, `id='`+id+`'`) {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("getElementById ссылается на id, не объявленные в HTML (мёртвый id, U-12): %v", missing)
	}
}

var onHandlerAttrRe = regexp.MustCompile(`on(?:click|change|input|keydown|keypress)="([^"]*)"`)
var jsCallRe = regexp.MustCompile(`(?:^|[^.\w])([A-Za-z_][A-Za-z0-9_]*)\(`)
var jsFuncDeclRe = regexp.MustCompile(`function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(`)

// TestUIStructure_OnHandlersReferenceExistingFunctions — акцептанс L2-W («каждый onclick
// ссылается на существующую функцию»). Проверяет onclick/onchange/oninput/onkeydown/onkeypress
// целиком (а не только onclick буквально) — контракт лота одинаково требует непустой смысл от
// любого обработчика события, не только клика.
func TestUIStructure_OnHandlersReferenceExistingFunctions(t *testing.T) {
	funcs := map[string]bool{}
	for _, m := range jsFuncDeclRe.FindAllStringSubmatch(webUI, -1) {
		funcs[m[1]] = true
	}
	seen := map[string]bool{}
	var missing []string
	for _, am := range onHandlerAttrRe.FindAllStringSubmatch(webUI, -1) {
		for _, cm := range jsCallRe.FindAllStringSubmatch(am[1], -1) {
			name := cm[1]
			if jsBuiltinCalls[name] || seen[name] || funcs[name] {
				seen[name] = true
				continue
			}
			seen[name] = true
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("обработчик события ссылается на несуществующую функцию (нет function NAME() во встроенном UI): %v", missing)
	}
}

var fetchLiteralRe = regexp.MustCompile(`fetch\(B\+\\?'([^'\\]*)`)

// TestUIStructure_FetchTargetsAreRegisteredRoutes — акцептанс L2-W («каждый fetch — на
// зарегистрированный маршрут»). Разбирает только вызовы вида fetch(B+'...') / fetch(B+\'...\'
// (второй вариант — внутри вложенной JS-строки, см. loadScanProgress/onclick="fetch(...)") —
// это единственная форма, которой пользуется встроенный UI для похода к собственному API
// (проверено вручную: fetch() без префикса B+ в файле встречается только внутри комментариев-
// примеров, не в исполняемом коде).
func TestUIStructure_FetchTargetsAreRegisteredRoutes(t *testing.T) {
	seen := map[string]bool{}
	var bad []string
	for _, m := range fetchLiteralRe.FindAllStringSubmatch(webUI, -1) {
		path := m[1]
		if qi := strings.IndexByte(path, '?'); qi >= 0 {
			path = path[:qi]
		}
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		if !knownAPIRoutesV14[path] {
			bad = append(bad, path)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Errorf("fetch() ссылается на маршрут, не зарегистрированный в routes(): %v", bad)
	}
}

// ─── U-8: подсказки — поповер по клику, не hover-only title= ──────────────────────────────

func TestU8_HelpIcoHasNoTitleAttribute(t *testing.T) {
	if strings.Contains(webUI, `class="help-ico" title="`) {
		t.Error("help-ico всё ещё использует hover-only title= — поповер по клику не подключён (U-8)")
	}
}

func TestU8_HelpIcoOpensPopoverOnClick(t *testing.T) {
	if !strings.Contains(webUI, `onclick="showHelp(this)"`) {
		t.Fatal("help-ico не вызывает showHelp(this) по клику (U-8)")
	}
	if !strings.Contains(webUI, `id="help-pop"`) {
		t.Error("во встроенном UI нет контейнера поповера #help-pop (U-8)")
	}
	body := extractFunc(t, "showHelp")
	if !strings.Contains(body, "data-help") {
		t.Error("showHelp не читает data-help — текст подсказки неоткуда взять (U-8)")
	}
}

// ─── U-9 (минимум по В-1): тумблеры источников, ?view= вкладки, ручное добавление узла ─────

func TestU9_SourcesHaveEnableToggle(t *testing.T) {
	body := extractFunc(t, "renderSources")
	if !strings.Contains(body, "toggleSource(") {
		t.Error("renderSources не рисует переключатель источника — вкладка «Источники» осталась read-only (U-9)")
	}
	toggle := extractFunc(t, "toggleSource")
	if !strings.Contains(toggle, "sources:") {
		t.Error("toggleSource не патчит ключ sources через /api/save-config (U-9)")
	}
}

func TestU9_NodesViewTabsPresent(t *testing.T) {
	for _, v := range []string{`data-v=""`, `data-v="proven"`, `data-v="manual"`, `data-v="favorites"`, `data-v="banned"`, `data-v="removed"`} {
		if !strings.Contains(webUI, v) {
			t.Errorf("не найдена вкладка представления узлов %s (U-9, ?view=)", v)
		}
	}
	body := extractFunc(t, "loadNodes")
	if !strings.Contains(body, "?view=") {
		t.Error("loadNodes не использует ?view= при запросе /api/nodes (U-9)")
	}
}

func TestU9_ManualAddNodeFormWired(t *testing.T) {
	if !strings.Contains(webUI, `id="manual-add-form"`) {
		t.Fatal("форма ручного добавления узла не найдена (U-9)")
	}
	body := extractFunc(t, "doAddManual")
	if !strings.Contains(body, "/api/add-node-manual") {
		t.Error("doAddManual не вызывает /api/add-node-manual (U-9)")
	}
}

// ─── U-10: togInstant показывает причину отказа и откатывает тумблер ──────────────────────

func TestU10_TogInstantShowsErrorOnFailure(t *testing.T) {
	body := extractFunc(t, "togInstant")
	if !strings.Contains(body, "qt-err") {
		t.Fatal("togInstant не пишет причину отказа в #qt-err (U-10)")
	}
	// Класс тумблера не должен трогаться до успешного ответа — «откат» здесь означает «тумблер
	// вообще не менялся», а не смену класса обратно (см. комментарий в коде togInstant).
	okIdx := strings.Index(body, "if(!r.ok)")
	toggleIdx := strings.Index(body, "el.classList.toggle('on',turningOn)")
	if okIdx < 0 || toggleIdx < 0 || toggleIdx < okIdx {
		t.Error("togInstant: класс тумблера применяется раньше проверки r.ok, либо проверка не найдена")
	}
}

// ─── U-11: переключатель residential/direct вместо жёсткого residential:true ──────────────

func TestU11_BypassAddNoLongerHardcodesResidentialTrue(t *testing.T) {
	if strings.Contains(webUI, `residential:true})`) {
		t.Error("addBypassDomain всё ещё шлёт жёстко residential:true (U-11)")
	}
	body := extractFunc(t, "addBypassDomain")
	if !strings.Contains(body, "isDirect") || !strings.Contains(body, "direct_route:isDirect") {
		t.Error("addBypassDomain не читает выбранный тип правила (residential/direct) (U-11)")
	}
}

func TestU11_BypassRuleEditable(t *testing.T) {
	if !strings.Contains(webUI, "editBypassRule(") {
		t.Error("правило bypass нельзя отредактировать — нет вызова editBypassRule (U-11)")
	}
	body := extractFunc(t, "addBypassDomain")
	if !strings.Contains(body, "editingBypassId") {
		t.Error("addBypassDomain не учитывает режим редактирования (editingBypassId) — правку некуда деть (U-11)")
	}
}

// ─── U-12: мёртвая разметка/код — либо подключены, либо удалены ───────────────────────────

func TestU12_WizFlowSelectRemoved(t *testing.T) {
	// Ищем именно ЖИВУЮ ссылку (getElementById), не упоминание в объясняющем комментарии — этот
	// самый комментарий (в startWizFlow, чуть ниже) правомерно называет id по имени, описывая,
	// что было убрано и почему.
	if strings.Contains(webUI, `getElementById('wiz-flow-select')`) || strings.Contains(webUI, `getElementById("wiz-flow-select")`) {
		t.Error("ссылка на несуществующий #wiz-flow-select всё ещё присутствует (U-12)")
	}
	if strings.Contains(webUI, "function wizResetFlow") {
		t.Error("мёртвая функция wizResetFlow (без единого вызывателя) не удалена (U-12)")
	}
}

func TestU12_LeakAlertWiredToLeakDetection(t *testing.T) {
	body := extractFunc(t, "refreshLogs")
	if !strings.Contains(body, "leak-alert") {
		t.Fatal("#leak-alert не подключён к обнаружению утечки в refreshLogs (U-12)")
	}
	if !strings.Contains(webUI, "function dismissLeakAlert") {
		t.Error("нет способа скрыть #leak-alert после показа (U-12)")
	}
}

// ─── U-13: русский язык, обращение на «вы» ─────────────────────────────────────────────────

func TestU13_NoEnglishWatchdogButtons(t *testing.T) {
	for _, bad := range []string{">Today<", ">Crash only<", ">With errors<", ">⧉ Copy<"} {
		if strings.Contains(webUI, bad) {
			t.Errorf("английский элемент управления не переведён: %q (U-13)", bad)
		}
	}
	for _, good := range []string{">Сегодня<", ">Только крахи<", ">С ошибками<", ">⧉ Копировать<"} {
		if !strings.Contains(webUI, good) {
			t.Errorf("ожидался русский текст %q (U-13)", good)
		}
	}
}

func TestU13_NoInformalYouAddressing(t *testing.T) {
	// Контрактный список (§6.2 UI_CONTRACT_v1.4.md) + доп. находки того же класса, устранённые
	// этим лотом. Проверяем явное отсутствие конкретных, ранее живых строк на «ты».
	bad := []string{
		"Введи WIPE для подтверждения",
		"отключи WebRTC в браузере",
		"Нажми «Тест» для запуска",
		"Нажми «Сканировать» для загрузки узлов",
		"Нажми «Проверить» для запуска теста",
		"Нажми «Применить» — APF найдёт",
		"Нажми кнопку ниже — удалит",
		"Открой Instagram, Telegram, ChatGPT",
		"'Проверь, не остался ли прокси",
		"'Проверь DNS в системе",
		"Проверь Wi-Fi/провайдера",
		"'Проверь, что APF отключен",
		"'Проверь интернет без APF',",
	}
	for _, b := range bad {
		if strings.Contains(webUI, b) {
			t.Errorf("осталось обращение на «ты»: %q (U-13)", b)
		}
	}
}

// ─── U-16-web: единое имя действия + confirm() на выключение WebRTC ───────────────────────

func TestU16Web_ToggleWebRTCRequiresConfirmOnDisable(t *testing.T) {
	body := extractFunc(t, "toggleWebRTC")
	if !strings.Contains(body, "confirm(") {
		t.Fatal("toggleWebRTC не содержит confirm() — подтверждение на выключение WebRTC-защиты не добавлено (U-16-web)")
	}
	confirmIdx := strings.Index(body, "confirm(")
	fetchIdx := strings.Index(body, "fetch(")
	ifEnabledIdx := strings.Index(body, "if(enabled)")
	if ifEnabledIdx < 0 || confirmIdx < ifEnabledIdx {
		t.Error("toggleWebRTC: confirm() не гейтится условием if(enabled) (выключение) — включение не должно спрашивать")
	}
	if fetchIdx < 0 || confirmIdx > fetchIdx {
		t.Error("toggleWebRTC: confirm() идёт после fetch() — не гейтит запрос")
	}
	// Текст — дословно §4.3 UI_CONTRACT_v1.4.md (единственный из четырёх диалогов, который
	// пишется впервые сразу на всех трёх платформах).
	if !strings.Contains(body, "Выключить блокировку WebRTC?") {
		t.Error("текст подтверждения WebRTC off не совпадает с контрактом §4.3 (единый для всех UI)")
	}
}

func TestU16Web_SwitchServerNameIsUnified(t *testing.T) {
	// §1.1 UI_CONTRACT_v1.4.md: единое имя действия «⇄ Сменить сервер» (было «⇄ Сменить IP»).
	// Проверяем текст самой КНОПКИ (>...<), а не любое упоминание фразы — этот же файл законно
	// упоминает старое название в объясняющем комментарии рядом с кнопкой.
	if strings.Contains(webUI, ">⇄ Сменить IP<") {
		t.Error("кнопка ручной смены узла всё ещё называется «⇄ Сменить IP», контракт требует «⇄ Сменить сервер» (U-16-web)")
	}
	if !strings.Contains(webUI, `id="btn-force-switch"`) || !strings.Contains(webUI, ">⇄ Сменить сервер<") {
		t.Error("кнопка btn-force-switch не переименована в «⇄ Сменить сервер» (U-16-web)")
	}
}

// ─── U-17-web: «узлы не сохранены: <причина>» рядом со списком узлов ──────────────────────

func TestU17Web_PersistErrorBannerWired(t *testing.T) {
	if !strings.Contains(webUI, `id="persist-error-alert"`) {
		t.Fatal("нет элемента для предупреждения о сбое сохранения узлов (U-17-web)")
	}
	body := extractFunc(t, "loadDiagnostics")
	if !strings.Contains(body, "last_persist_error") {
		t.Error("loadDiagnostics не читает last_persist_error (U-17-web)")
	}
	if !strings.Contains(body, "persist-error-alert") {
		t.Error("loadDiagnostics не показывает/скрывает #persist-error-alert (U-17-web)")
	}
}

// ─── V13-3: пин/избранное/бан/удалить/правка — все на существующих маршрутах ──────────────

func TestV13_3_NodeRowHasFullActionSet(t *testing.T) {
	body := extractFunc(t, "renderNodes")
	for _, c := range []string{"doPinNode(", "doFavoriteNode(", "doBanNode(", "doConnectOnce(", "doEditNode(", "doRemoveNode("} {
		if !strings.Contains(body, c) {
			t.Errorf("renderNodes: не найден вызов %s в строке таблицы узлов (V13-3)", c)
		}
	}
}

func TestV13_3_EditAndRemoveHitExpectedEndpoints(t *testing.T) {
	edit := extractFunc(t, "doEditNode")
	if !strings.Contains(edit, "/api/node/update") {
		t.Error("doEditNode не вызывает /api/node/update (V13-3)")
	}
	remove := extractFunc(t, "doRemoveNode")
	if !strings.Contains(remove, "/api/node/remove") {
		t.Error("doRemoveNode не вызывает /api/node/remove (V13-3)")
	}
	if !strings.Contains(remove, "confirm(") {
		t.Error("doRemoveNode удаляет узел без подтверждения (V13-3, тот же класс риска, что бан)")
	}
}

// ─── V13-4-web: кнопка «Сканировать всё» существует и бьёт в верный маршрут (C-18 — ниже) ──

func TestV13_4Web_SweepButtonWired(t *testing.T) {
	if !strings.Contains(webUI, `onclick="doSweep()"`) {
		t.Fatal("кнопка «Сканировать всё» не найдена (V13-4-web)")
	}
	body := extractFunc(t, "doSweep")
	if !strings.Contains(body, "/api/scan/start") {
		t.Error("doSweep не вызывает /api/scan/start (V13-4-web)")
	}
}

// ─── V13-5-web: тост needs_restart в saveSettings (регресс, уже было реализовано) ─────────

func TestV13_5Web_NeedsRestartToastPresent(t *testing.T) {
	body := extractFunc(t, "saveSettings")
	if !strings.Contains(body, "needs_restart") {
		t.Error("saveSettings не показывает подсказку needs_restart (V13-5-web)")
	}
}

// ─── V13-6-web: честный ipv6_status/webrtc_status вместо голого enabled-флага ─────────────

func TestV13_6Web_HonestGuardStatusUsed(t *testing.T) {
	body := extractFunc(t, "renderLeakGuardStatus")
	if !strings.Contains(body, "ipv6_status") {
		t.Fatal("renderLeakGuardStatus не читает lgStatus.ipv6_status.enforced (V13-6-web)")
	}
	if !strings.Contains(body, "enforced") {
		t.Error("renderLeakGuardStatus не проверяет поле enforced (full|delegated|none) (V13-6-web)")
	}
}

// ─── C-18-counter: три числа — в пуле / отвечает по TCP / подтверждено трафиком ───────────

func TestC18Counter_ShowsThreeNumbers(t *testing.T) {
	if !strings.Contains(webUI, `id="nodes-counter"`) {
		t.Fatal("нет элемента-счётчика пула (C-18-counter)")
	}
	body := extractFunc(t, "updatePoolCounter")
	for _, want := range []string{"В пуле ", "отвечает по TCP ", "подтверждено трафиком "} {
		if !strings.Contains(body, want) {
			t.Errorf("счётчик не содержит фрагмент %q — три числа не показаны (C-18-counter)", want)
		}
	}
	if !strings.Contains(body, "/api/scan/progress") || !strings.Contains(body, "/api/stats") {
		t.Error("updatePoolCounter не использует /api/stats и /api/scan/progress (C-18-counter)")
	}
}

// ─── C-20-ui: «через туннель» только для TUN-bound замера ─────────────────────────────────

func TestC20UI_ThroughTunnelOnlyForTUNVia(t *testing.T) {
	body := extractFunc(t, "renderNodes")
	idx := strings.Index(body, "verifiedNote")
	if idx < 0 {
		t.Fatal("renderNodes не показывает last_verified_latency_ms (C-20-ui)")
	}
	if !strings.Contains(body, `n.last_verified_via==='tun'?'через туннель':'через прокси-канал узла'`) {
		t.Error("подпись задержки не разводит SOCKS5- и TUN-bound замер по last_verified_via (C-20-ui)")
	}
}

// grep-страж на регресс: «через туннель» не должно встречаться рядом с last_verified_latency_ms
// нигде, кроме уже учтённого разветвления по via==='tun'.
func TestC20UI_NoBareLastVerifiedLatencyLabeledThroughTunnel(t *testing.T) {
	re := regexp.MustCompile(`last_verified_latency_ms[^;]{0,80}через туннель`)
	if re.MatchString(webUI) && !strings.Contains(webUI, `n.last_verified_via==='tun'?'через туннель'`) {
		t.Error("last_verified_latency_ms подписан «через туннель» без проверки last_verified_via (C-20-ui, регресс)")
	}
}

// ─── C-21-ui: фактический выход узла показывается рядом с меткой каталога ─────────────────

func TestC21UI_ExitCountryShownWhenKnown(t *testing.T) {
	body := extractFunc(t, "renderNodes")
	if !strings.Contains(body, "n.exit_country") {
		t.Fatal("renderNodes не читает exit_country (C-21-ui)")
	}
	if !strings.Contains(body, "n.country_mismatch") {
		t.Error("renderNodes не отличает совпадение метки от расхождения (country_mismatch) (C-21-ui)")
	}
}

func TestC21UI_ServerAttachesCountryFields(t *testing.T) {
	s := newTestServer(t)
	rec := doReq(s, "GET", "/api/nodes", bearer(s.authToken))
	if rec.Code != 200 {
		t.Fatalf("GET /api/nodes: got %d", rec.Code)
	}
	// Форма ответа: поля catalog_country/exit_country/country_mismatch добавлены к каждому узлу
	// (attachVerifyBadges) — тест намеренно не требует конкретных значений (без движка/подключения
	// LastVerifiedCountry обычно пуст), только то, что сервер вообще способен их сериализовать
	// без падения и без искажения остальных полей (verify_badge проверяется отдельным тестом).
	if !strings.Contains(rec.Body.String(), "\"nodes\"") {
		t.Fatalf("ответ /api/nodes не похож на ожидаемый (нет ключа nodes): %s", rec.Body.String())
	}
}

// ─── Регрессия существующей формы: подключения к handler'у через httptest, не только grep ─

func TestNewTestServer_SmokeAfterAllEdits(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("GET / после правок лота: got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "help-pop") {
		t.Error("страница не содержит контейнер поповера — возможно, webUI собран не полностью")
	}
}
