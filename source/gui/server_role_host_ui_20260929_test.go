package main

// Живой инцидент 2026-09-29 («IP не меняется»): страница «Роль Выход» подставляла найденный
// внешний адрес в «Хост» только при Direct/UPnP ИЛИ пустом поле, а поле уже было заполнено
// локальным адресом при открытии страницы. Плюс ревью F2 (тексты «только в той же сети» неверны
// для loopback/0.0.0.0/CGNAT) и F4 (запуск роли блокируется до ~120 с, а кнопка не реагировала).
//
// Тесты гоняют НАСТОЯЩИЙ код функций из gui/frontend/src/index.html под node с заглушками App и
// document (как index_html_v14_test.go, реальный Wails-рантайм не поднимается — wails dev/build
// на этой машине не запускать). Нет node в PATH — поведенческие тесты пропускаются, структурные
// (Kotlin-часть, которую нельзя собрать под go test) остаются.

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// srNodeOrSkip возвращает путь к node либо пропускает тест.
func srNodeOrSkip(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node не найден в PATH — поведенческая проверка JS-функций index.html пропущена")
	}
	return p
}

// srRunNodeJSON пишет фрагмент кода страницы и harness во временный каталог, запускает node и
// разбирает JSON со stdout. Любая ошибка выполнения JS — сбой теста с выводом stderr.
func srRunNodeJSON(t *testing.T, fnSrc, harness string, out interface{}) {
	t.Helper()
	node := srNodeOrSkip(t)
	dir := t.TempDir()
	fnPath := filepath.Join(dir, "fn.js")
	harnessPath := filepath.Join(dir, "harness.js")
	if err := os.WriteFile(fnPath, []byte(fnSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(harnessPath, []byte(harness), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, harnessPath, fnPath)
	stdout, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("node завершился с ошибкой: %v\nstderr: %s\nstdout: %s", err, stderr, stdout)
	}
	if err := json.Unmarshal(stdout, out); err != nil {
		t.Fatalf("не разобрали JSON со stdout node: %v\n%s", err, stdout)
	}
}

// srFunctionSource вырезает целиком функцию (маркер начала + тело + закрывающая скобка).
func srFunctionSource(t *testing.T, html, startMarker string) string {
	t.Helper()
	return startMarker + extractFunctionBody(t, html, startMarker) + "}"
}

// ─── doDetectReachability: подстановка найденного адреса в «Хост» ─────────────────────────

const srDetectHarness = `
const fs = require('fs')
const src = fs.readFileSync(process.argv[2], 'utf8')
// eval/new Function здесь исполняют ТОЛЬКО вырезку из собственного исходника страницы index.html
// (тестовый harness под node, ввода извне нет).
globalThis.window = {}
let regen = 0
globalThis.doGenerateServerLink = async function() { regen++; return 'link' }
eval(src)

// Заглушка netutil.LinkHostWarning: непусто для LAN/CGNAT/loopback/0.0.0.0, пусто для публичного
// адреса и доменного имени (документационные диапазоны 203.0.113.x / 198.51.100.x — «публичные»).
function warnFor(h) {
  const bad = /^(10\.|192\.168\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|127\.|0\.0\.0\.0|198\.1[89]\.)/
  return bad.test(h) ? ('предупреждение про ' + h) : ''
}
function mkEl(o) { return Object.assign({ textContent: '', className: '', value: '', style: {}, disabled: false }, o || {}) }

async function run(name, r, host, panelVisible) {
  const els = {
    'sr-reachability-result': mkEl(),
    'sr-port': mkEl({ value: '8443' }),
    'sr-host': mkEl({ value: host }),
    'sr-link-panel': mkEl({ style: { display: panelVisible ? '' : 'none' } }),
  }
  globalThis.document = { getElementById: function(id) { return els[id] } }
  globalThis.App = {
    LinkHostWarning: async function(h) { return warnFor(h) },
    ServerRoleDetectReachability: async function() { return r },
  }
  regen = 0
  globalThis.srHostUnverified = false
  await window.doDetectReachability()
  const res = els['sr-reachability-result']
  return { name: name, host: els['sr-host'].value, text: res.textContent, cls: res.className, regen: regen,
           unverified: globalThis.srHostUnverified === true }
}

;(async function() {
  const stun = { method: 3, explanation: 'Нужен проброс порта на роутере — вот как', external_host: '203.0.113.5', external_port: 8443, has_address: true }
  const out = []
  out.push(await run('stun_lan_field', stun, '10.0.0.37', true))
  out.push(await run('stun_lan_field_panel_hidden', stun, '10.0.0.37', false))
  out.push(await run('stun_domain_field', stun, 'exit.example.org', true))
  out.push(await run('stun_public_ip_field', stun, '198.51.100.9', true))
  out.push(await run('stun_empty_field', stun, '', false))
  out.push(await run('stun_loopback_field', stun, '127.0.0.1', false))
  out.push(await run('cgnat_method4', { method: 4, explanation: 'Нужен посредник', external_host: '100.72.1.9', external_port: 8443, has_address: true }, '10.0.0.37', true))
  out.push(await run('cgnat_method4_empty_field', { method: 4, explanation: 'Нужен посредник', external_host: '100.72.1.9', external_port: 8443, has_address: true }, '', false))
  out.push(await run('undetermined', { method: 5, explanation: 'Не удалось определить внешний адрес', external_host: '', external_port: 0, has_address: false }, '10.0.0.37', true))
  const upnp = { method: 2, explanation: 'Порт открыт автоматически — всё готово', external_host: '198.51.100.7', external_port: 8443, has_address: true }
  // Ревью 2026-09-30: единое правило подстановки для UPnP/Direct/STUN — нормальный ручной домен не
  // затирается, приватный «внешний» адрес роутера (двойной NAT) не подставляется.
  out.push(await run('upnp_keeps_domain', upnp, 'exit.example.org', false))
  out.push(await run('upnp_replaces_lan_field', upnp, '10.0.0.37', true))
  out.push(await run('upnp_private_external', { method: 2, explanation: 'Порт открыт автоматически — всё готово', external_host: '192.168.0.1', external_port: 8443, has_address: true }, '10.0.0.37', false))
  // Настоящий Explain(MethodUndetermined) из internal/relay заканчивается точкой: склейка не должна
  // давать «..».
  out.push(await run('undetermined_real_explain', { method: 5, explanation: 'Не удалось определить внешний адрес автоматически. Если этот компьютер выходит в интернет через раздачу с другого телефона или у оператора общий адрес (CGNAT), проброс порта невозможен — нужен relay-посредник; если вы за домашним роутером — пробросьте порт вручную (инструкция ниже).', external_host: '', external_port: 0, has_address: false }, '10.0.0.37', true))
  out.push(await run('tunnel_test_range_address', { method: 3, explanation: 'Нужен проброс порта на роутере — вот как', external_host: '198.18.0.5', external_port: 8443, has_address: true }, '10.0.0.37', true))
  console.log(JSON.stringify(out))
})().catch(function(e) { console.error(String(e && e.stack || e)); process.exit(1) })
`

type srDetectResult struct {
	Name       string `json:"name"`
	Host       string `json:"host"`
	Text       string `json:"text"`
	Cls        string `json:"cls"`
	Regen      int    `json:"regen"`
	Unverified bool   `json:"unverified"`
}

func srRunDetect(t *testing.T) map[string]srDetectResult {
	t.Helper()
	html := readGuiSourceFile(t, "frontend/src/index.html")
	src := srFunctionSource(t, html, "window.doDetectReachability = async function() {")
	var list []srDetectResult
	srRunNodeJSON(t, src, srDetectHarness, &list)
	m := map[string]srDetectResult{}
	for _, r := range list {
		m[r.Name] = r
	}
	return m
}

func srWantContains(t *testing.T, name, text string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(text, w) {
			t.Errorf("%s: в тексте результата нет %q; текст: %s", name, w, text)
		}
	}
}

// Ядро инцидента: поле «Хост» заполнено локальным адресом, STUN нашёл публичный — адрес обязан
// заменить локальный и быть виден в тексте. На старом коде поле оставалось 10.0.0.37.
func TestDetectReachability_StunReplacesUselessHost(t *testing.T) {
	res := srRunDetect(t)
	for _, name := range []string{"stun_lan_field", "stun_lan_field_panel_hidden", "stun_loopback_field", "stun_empty_field"} {
		r := res[name]
		if r.Host != "203.0.113.5" {
			t.Errorf("%s: «Хост» = %q, ожидался найденный внешний адрес 203.0.113.5", name, r.Host)
		}
		srWantContains(t, name, r.Text,
			"подставлен вероятный внешний адрес 203.0.113.5", "после проброса порта 8443", "relay")
	}
	// Ссылка, уже показанная в панели, собрана со старым хостом — её обязаны пересобрать; если
	// панель скрыта, пересобирать нечего.
	if res["stun_lan_field"].Regen != 1 {
		t.Errorf("панель со ссылкой показана, но после подстановки ссылка не пересобрана (regen=%d)", res["stun_lan_field"].Regen)
	}
	if res["stun_lan_field_panel_hidden"].Regen != 0 {
		t.Errorf("панель скрыта, а ссылка пересобиралась (regen=%d)", res["stun_lan_field_panel_hidden"].Regen)
	}
}

// Значение, введённое пользователем вручную и «нормальное» (публичный IP/домен), затирать нельзя.
func TestDetectReachability_StunKeepsGoodManualHost(t *testing.T) {
	res := srRunDetect(t)
	cases := map[string]string{"stun_domain_field": "exit.example.org", "stun_public_ip_field": "198.51.100.9"}
	for name, keep := range cases {
		r := res[name]
		if r.Host != keep {
			t.Errorf("%s: «Хост» = %q — нормальное ручное значение %q затёрто", name, r.Host, keep)
		}
		// Найденный адрес всё равно должен быть виден, иначе снова «IP не меняется» без объяснений.
		srWantContains(t, name, r.Text, "203.0.113.5", "не подставлен")
		if r.Regen != 0 {
			t.Errorf("%s: ссылка пересобиралась без подстановки (regen=%d)", name, r.Regen)
		}
	}
}

// method 4 — STUN-адрес приватный/CGNAT: не подставляем никогда (даже в пустое поле, как делал
// старый код) и советуем relay.
func TestDetectReachability_CGNATIsNeverSubstituted(t *testing.T) {
	res := srRunDetect(t)
	if r := res["cgnat_method4"]; r.Host != "10.0.0.37" {
		t.Errorf("cgnat_method4: «Хост» = %q, CGNAT-адрес не должен заменять поле", r.Host)
	}
	if r := res["cgnat_method4_empty_field"]; r.Host != "" {
		t.Errorf("cgnat_method4_empty_field: «Хост» = %q, CGNAT-адрес подставлен в пустое поле", r.Host)
	}
	for _, name := range []string{"cgnat_method4", "cgnat_method4_empty_field"} {
		r := res[name]
		srWantContains(t, name, r.Text, "relay", "не подставлен")
		if strings.Contains(r.Text, "пробросить порт") {
			t.Errorf("%s: при CGNAT нельзя советовать проброс порта: %s", name, r.Text)
		}
	}
}

// method 5 — «не удалось определить»: информационный текст, не ошибка и не «isGood».
func TestDetectReachability_UndeterminedIsInformational(t *testing.T) {
	r := srRunDetect(t)["undetermined"]
	if r.Host != "10.0.0.37" {
		t.Errorf("метод 5 изменил «Хост»: %q", r.Host)
	}
	if r.Cls != "add-feedback" {
		t.Errorf("метод 5: класс %q — это не ошибка и не успех, ожидался нейтральный add-feedback", r.Cls)
	}
	if !strings.HasPrefix(r.Text, "ℹ ") || strings.Contains(r.Text, "✗") || strings.Contains(r.Text, "✓") {
		t.Errorf("метод 5 должен показываться как информационный (ℹ): %s", r.Text)
	}
	srWantContains(t, "undetermined", r.Text, "Не удалось определить внешний адрес", "оставлен как есть")
}

// method 3 — подсказка про ручной проброс остаётся, но добавлена оговорка про раздачу с телефона.
// UPnP считается успехом (ok), а подстановка идёт по ЕДИНОМУ правилу для всех методов: публичный
// адрес + бесполезное значение поля. Нормальный ручной домен не затирается даже при UPnP, приватный
// «внешний» адрес роутера (двойной NAT) не подставляется (ревью 2026-09-30).
func TestDetectReachability_ManualPortHintAndUPnP(t *testing.T) {
	res := srRunDetect(t)
	srWantContains(t, "stun_domain_field", res["stun_domain_field"].Text,
		"нужно пробросить на роутере вручную", "раздаче с телефона", "проброс невозможен", "нужен relay")

	if u := res["upnp_replaces_lan_field"]; u.Host != "198.51.100.7" || u.Cls != "add-feedback ok" || u.Unverified {
		t.Errorf("UPnP при бесполезном (LAN) поле: host=%q cls=%q unverified=%v, ожидалось подставленное 198.51.100.7, ok, подтверждено",
			u.Host, u.Cls, u.Unverified)
	}
	if u := res["upnp_keeps_domain"]; u.Host != "exit.example.org" || u.Cls != "add-feedback ok" {
		t.Errorf("UPnP при нормальном ручном домене: host=%q cls=%q — домен затирать нельзя, успех (ok) остаётся", u.Host, u.Cls)
	} else {
		srWantContains(t, "upnp_keeps_domain", u.Text, "198.51.100.7", "не подставлен")
	}
	if u := res["upnp_private_external"]; u.Host != "10.0.0.37" {
		t.Errorf("UPnP с приватным внешним адресом (двойной NAT): host=%q — приватный адрес подставлен", u.Host)
	} else {
		srWantContains(t, "upnp_private_external", u.Text, "недостижим снаружи", "не подставлен")
	}
}

// Пометка «адрес не подтверждён»: подставленный STUN-адрес (порт не проброшен) ставит её, подтверждённый
// UPnP-адрес — нет; рядом со ссылкой это меняет «✓ можно передавать» на честное «после проброса».
func TestDetectReachability_UnverifiedFlag(t *testing.T) {
	res := srRunDetect(t)
	if !res["stun_lan_field"].Unverified {
		t.Error("STUN-адрес подставлен, но пометка «не подтверждён» не поставлена")
	}
	if res["upnp_replaces_lan_field"].Unverified {
		t.Error("UPnP-адрес подтверждён проходом порта — пометка «не подтверждён» стоять не должна")
	}
	if res["stun_domain_field"].Unverified {
		t.Error("адрес не подставлен (введён домен) — пометка стоять не должна")
	}
}

// Настоящий текст Explain(MethodUndetermined) кончается точкой — склейка не должна давать «..».
// Адрес из тест-диапазона 198.18/15 не подставляется, а причина названа нейтрально (не «CGNAT»).
func TestDetectReachability_TextPolish(t *testing.T) {
	res := srRunDetect(t)
	if r := res["undetermined_real_explain"]; strings.Contains(r.Text, "..") {
		t.Errorf("двойная точка в тексте метода 5: %s", r.Text)
	}
	r := res["tunnel_test_range_address"]
	if r.Host != "10.0.0.37" {
		t.Errorf("адрес 198.18.x подставлен в «Хост»: %q", r.Host)
	}
	if strings.Contains(r.Text, "CGNAT") && !strings.Contains(r.Text, "тестовый") {
		t.Errorf("причина названа как CGNAT для тест-диапазона: %s", r.Text)
	}
	srWantContains(t, "tunnel_test_range_address", r.Text, "недостижим снаружи")
}

// ─── updateServerLinkAvailabilityNote (ревью F2) ──────────────────────────────────────────

const srNoteHarness = `
const fs = require('fs')
const src = fs.readFileSync(process.argv[2], 'utf8')
function note(warn, running, unverified) {
  const el = { textContent: '' }
  const panel = { style: { display: '' } }
  const doc = { getElementById: function(id) { return id === 'sr-link-availability' ? el : (id === 'sr-link-panel' ? panel : null) } }
  const f = new Function('document', 'srLinkWarning', 'srRunning', 'srHostUnverified', src + '\nreturn updateServerLinkAvailabilityNote')
  f(doc, warn, running, !!unverified)()
  return el.textContent
}
console.log(JSON.stringify({
  warn_running: note('предупреждение', true),
  warn_stopped: note('предупреждение', false),
  ok_running: note('', true),
  ok_stopped: note('', false),
  unverified_running: note('', true, true),
  unverified_stopped: note('', false, true),
}))
`

func TestLinkAvailabilityNote_NoSameNetworkPromise(t *testing.T) {
	html := readGuiSourceFile(t, "frontend/src/index.html")
	src := srFunctionSource(t, html, "function updateServerLinkAvailabilityNote() {")
	var got map[string]string
	srRunNodeJSON(t, src, srNoteHarness, &got)
	for _, k := range []string{"warn_running", "warn_stopped"} {
		txt := got[k]
		if strings.Contains(txt, "той же сети") || strings.Contains(txt, "в одной сети") {
			t.Errorf("%s: подпись обещает «ту же сеть» — для loopback/0.0.0.0/CGNAT это неверно: %s", k, txt)
		}
		srWantContains(t, k, txt, "см. предупреждение выше")
	}
	srWantContains(t, "ok_running", got["ok_running"], "уже можно передавать")
	srWantContains(t, "ok_stopped", got["ok_stopped"], "Запустить")
	// Подставлен неподтверждённый внешний адрес: «✓ можно передавать» было бы ложью (тот же класс,
	// что инцидент 09-29), честно — «после проброса порта или через relay».
	for _, k := range []string{"unverified_running", "unverified_stopped"} {
		txt := got[k]
		if strings.Contains(txt, "✓") || strings.Contains(txt, "уже можно передавать") {
			t.Errorf("%s: для неподтверждённого адреса подпись обещает готовность: %s", k, txt)
		}
		srWantContains(t, k, txt, "проброс", "relay")
	}

	// То же обещание не должно жить и в подписи, которую пишет doGenerateServerLink.
	for _, bad := range []string{"работает только в одной сети с этим устройством", "только в той же сети, что и это устройство"} {
		if strings.Contains(html, bad) {
			t.Errorf("в index.html осталась формулировка %q — ревью F2", bad)
		}
	}
}

// ─── doStartServerRole: блокировка кнопки на время долгого запуска (ревью F4) ────────────

const srStartHarness = `
const fs = require('fs')
const src = fs.readFileSync(process.argv[2], 'utf8')
function tick() { return new Promise(function(r) { setImmediate(r) }) }
function mkEl(o) { return Object.assign({ textContent: '', className: '', value: '', style: {}, disabled: false }, o || {}) }

function build(app, hostValue) {
  const els = {
    'sr-btn-start': mkEl({ textContent: '▶ Запустить' }),
    'sr-fb': mkEl(),
    'sr-host': mkEl({ value: hostValue }),
    'sr-port': mkEl({ value: '8443' }),
    'sr-reality-dest': mkEl(),
    'sr-relay-addr': mkEl(),
    'sr-relay-fingerprint': mkEl(),
  }
  const doc = { getElementById: function(id) { return els[id] } }
  const win = {}
  const f = new Function('App', 'document', 'window', 'confirm', 'addLog', 'updateServerRoleStatusUI', 'doGenerateServerLink',
    'let srIdentity = { PrivateKey: "k", UUID: "u" }; let srStarting = false;\n' + src + '\nreturn window.doStartServerRole')
  const fn = f(app, doc, win, function() { return true }, function() {}, function() {}, async function() { return 'link' })
  return { els: els, fn: fn }
}

;(async function() {
  const out = {}

  // 1) долгий запуск: во время вызова кнопка заблокирована и подписана, повторный клик игнорируется
  let starts = 0
  let release
  const gate = new Promise(function(r) { release = r })
  const slow = build({
    PatchConfig: async function() {},
    ServerRoleStart: async function() { starts++; await gate },
  }, '203.0.113.5')
  const p1 = slow.fn()
  await tick()
  out.during = { disabled: slow.els['sr-btn-start'].disabled, label: slow.els['sr-btn-start'].textContent, fb: slow.els['sr-fb'].textContent }
  const p2 = slow.fn() // повторный клик (на старом коде — вторая параллельная попытка, поэтому не await до release)
  await tick()
  release()
  await p1
  await p2
  out.slow_after = { disabled: slow.els['sr-btn-start'].disabled, label: slow.els['sr-btn-start'].textContent, starts: starts, fb: slow.els['sr-fb'].textContent }

  // 2) запуск упал — блокировка обязана сняться (finally)
  const failing = build({
    PatchConfig: async function() {},
    ServerRoleStart: async function() { throw new Error('таймаут окна') },
  }, '203.0.113.5')
  await failing.fn()
  out.fail_after = { disabled: failing.els['sr-btn-start'].disabled, label: failing.els['sr-btn-start'].textContent, fb: failing.els['sr-fb'].textContent, cls: failing.els['sr-fb'].className }

  // 3) ранний return по проверке (пустой хост) не должен оставлять кнопку заблокированной, а
  //    следующий клик — тихо игнорироваться из-за «залипшего» флага
  let starts3 = 0
  const early = build({
    PatchConfig: async function() {},
    ServerRoleStart: async function() { starts3++ },
  }, '')
  await early.fn()
  out.early_after = { disabled: early.els['sr-btn-start'].disabled, label: early.els['sr-btn-start'].textContent, fb: early.els['sr-fb'].textContent }
  early.els['sr-host'].value = '203.0.113.5'
  await early.fn()
  out.early_retry_starts = starts3

  console.log(JSON.stringify(out))
})().catch(function(e) { console.error(String(e && e.stack || e)); process.exit(1) })
`

func TestStartServerRole_ButtonLockedWhileStarting(t *testing.T) {
	html := readGuiSourceFile(t, "frontend/src/index.html")
	src := srFunctionSource(t, html, "window.doStartServerRole = async function() {")
	var got struct {
		During struct {
			Disabled bool   `json:"disabled"`
			Label    string `json:"label"`
			Fb       string `json:"fb"`
		} `json:"during"`
		SlowAfter struct {
			Disabled bool   `json:"disabled"`
			Label    string `json:"label"`
			Starts   int    `json:"starts"`
			Fb       string `json:"fb"`
		} `json:"slow_after"`
		FailAfter struct {
			Disabled bool   `json:"disabled"`
			Label    string `json:"label"`
			Fb       string `json:"fb"`
			Cls      string `json:"cls"`
		} `json:"fail_after"`
		EarlyAfter struct {
			Disabled bool   `json:"disabled"`
			Label    string `json:"label"`
			Fb       string `json:"fb"`
		} `json:"early_after"`
		EarlyRetryStarts int `json:"early_retry_starts"`
	}
	srRunNodeJSON(t, src, srStartHarness, &got)

	if !got.During.Disabled {
		t.Error("во время запуска кнопка «Запустить» не заблокирована — повторный клик запустит вторую попытку")
	}
	srWantContains(t, "during(кнопка)", got.During.Label, "Запуск… (до 2 минут)")
	srWantContains(t, "during(sr-fb)", got.During.Fb, "Запуск… (до 2 минут)")
	if got.SlowAfter.Starts != 1 {
		t.Errorf("повторный клик во время запуска дошёл до ServerRoleStart: вызовов %d, ожидался 1", got.SlowAfter.Starts)
	}
	if got.SlowAfter.Disabled || got.SlowAfter.Label != "▶ Запустить" {
		t.Errorf("после успешного запуска кнопка не восстановлена: disabled=%v label=%q", got.SlowAfter.Disabled, got.SlowAfter.Label)
	}
	if got.FailAfter.Disabled || got.FailAfter.Label != "▶ Запустить" {
		t.Errorf("после ошибки запуска кнопка осталась заблокированной/переименованной: disabled=%v label=%q",
			got.FailAfter.Disabled, got.FailAfter.Label)
	}
	srWantContains(t, "fail(sr-fb)", got.FailAfter.Fb, "✗ Ошибка", "таймаут окна")
	if got.EarlyAfter.Disabled || got.EarlyAfter.Label != "▶ Запустить" {
		t.Errorf("после раннего return по проверке кнопка осталась заблокированной: disabled=%v label=%q",
			got.EarlyAfter.Disabled, got.EarlyAfter.Label)
	}
	if got.EarlyRetryStarts != 1 {
		t.Errorf("после раннего return следующий клик проигнорирован (флаг «идёт запуск» залип): вызовов %d", got.EarlyRetryStarts)
	}
}

// Harness выше САМ вставляет «let srStarting = false» перед вырезанной функцией — значит, удаление
// объявления из настоящего index.html им не поймать, а в module-скрипте это ReferenceError при
// первом клике по «Запустить» (замечание ревью 2026-09-30). Поэтому объявление проверяется отдельно:
// в настоящем index.html оно есть ровно одно и раньше doStartServerRole.
func TestStartServerRole_SrStartingDeclaredOnceInPage(t *testing.T) {
	html := readGuiSourceFile(t, "frontend/src/index.html")
	if n := strings.Count(html, "let srStarting = false"); n != 1 {
		t.Fatalf("«let srStarting = false» встречается %d раз, ожидалось ровно 1 (иначе doStartServerRole падает с ReferenceError или флаг двоится)", n)
	}
	if strings.Index(html, "let srStarting = false") > strings.Index(html, "window.doStartServerRole = async function() {") {
		t.Error("объявление srStarting стоит ПОСЛЕ doStartServerRole")
	}
	if n := strings.Count(html, "let srHostUnverified = false"); n != 1 {
		t.Fatalf("«let srHostUnverified = false» встречается %d раз, ожидалось ровно 1", n)
	}
}

// ─── Android (MainActivity.kt): собрать Kotlin под go test нельзя — структурные проверки ─────

func srReadKotlinOrSkip(t *testing.T, file string) string {
	t.Helper()
	p := filepath.Join("..", "..", "android", "android-project", "app", "src", "main", "java", "com", "apf", "app", file)
	data, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("Kotlin-исходник %s недоступен из этого дерева (%v) — проверка пропущена", file, err)
	}
	return string(data)
}

func TestAndroidLocalIpCandidates_SkipsServiceInterfaces(t *testing.T) {
	kt := srReadKotlinOrSkip(t, "MainActivity.kt")
	body := extractFunctionBody(t, kt, "private fun localIpCandidates(): List<Pair<String, String>> {")
	for _, want := range []string{
		`name == "lo"`, `startsWith("tun")`, `startsWith("dummy")`, `startsWith("ppp")`,
		"isLinkLocalAddress", `"172.19.0.1"`, `startsWith("wlan")`, `startsWith("eth")`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("localIpCandidates не содержит %s — служебные интерфейсы/собственный TUN APF снова попадут в кандидаты «Host»", want)
		}
	}
	// Порядок: wlan*/eth* (частные) → прочие частные → остальные.
	iPrim := strings.Index(body, "return primary + privateOther + other")
	if iPrim < 0 {
		t.Error("порядок кандидатов не «wlan/eth → прочие частные → остальные»")
	}
}

func TestAndroidDetectButton_ReplacesUselessHostLikeWails(t *testing.T) {
	kt := srReadKotlinOrSkip(t, "MainActivity.kt")
	start := strings.Index(kt, `text = "🌐 Определить адрес автоматически"`)
	end := strings.Index(kt, "container.addView(tvReachabilityResult)")
	if start < 0 || end < start {
		t.Fatal("не нашли блок кнопки «Определить адрес автоматически» в MainActivity.kt")
	}
	block := kt[start:end]
	if strings.Contains(block, "isGood || etHost.text.isBlank()") || strings.Contains(block, "filled = isGood ||") {
		t.Error("осталось старое условие подстановки (Direct/UPnP безусловно) — инцидент «IP не меняется», ревью 2026-09-30")
	}
	for _, want := range []string{
		"linkHostWarningOrEmpty(extHost)", "linkHostWarningOrEmpty(curHost)", "method != 4",
		"method == 5", "раздаче с другого телефона", "curUseless", "foundPublic",
		"filled = foundPublic && curUseless",
		// Паритет с Wails: после подстановки показанная ссылка пересобирается (иначе владелец
		// копирует ссылку со старым хостом), точки в тексте не двоятся.
		"buildServerLinkFromFields(true)", "addSentence(",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("в логике кнопки нет %q — паритет с Wails (doDetectReachability) нарушен", want)
		}
	}
	// Вспомогательная функция существует и не роняет диалог при сбое моста.
	if !strings.Contains(kt, "private fun linkHostWarningOrEmpty(host: String): String") {
		t.Error("не объявлена linkHostWarningOrEmpty — блок кнопки на неё ссылается")
	}
}
