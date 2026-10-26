package web

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Дефект (найден ревью лота L5, существовал раньше): ID провайдера вставлялся в атрибут onclick
// внутрь JS-строки: onclick="toggleProvider('<id>',…)". esc() превращает апостроф в &#39;, но HTML-
// парсер раскодирует сущность ОБРАТНО в «'» до выполнения JS — значит ID с апострофом ломал
// строку, а ID вида x');код;// выполнял чужой код. ID провайдера может задать пользователь
// (Engine.AddPaidProvider принимает готовый ID).
//
// Тест гоняет НАСТОЯЩИЙ код renderCatalog/toggleProvider из отдаваемой страницы под node с
// заглушками document/fetch и повторяет шаги браузера: раскодирует значения атрибутов и
// выполняет onclick с подставленным this. Нет node в PATH — тест пропускается.
const providerIDHarness = `
const fs = require('fs')
const src = fs.readFileSync(process.argv[2], 'utf8')
let catalogData = [], B = '', html = '', fetched = []
globalThis.fetch = async function(url, opt) { fetched.push({ url: url, body: JSON.parse(opt.body) }); return { json: async function() { return [] } } }
globalThis.document = { getElementById: function() { return { set innerHTML(v) { html = v }, get innerHTML() { return html } } } }
async function loadCatalog() {}
// Исполняется ТОЛЬКО вырезка из собственного исходника страницы (harness под node, ввода извне нет).
eval(src)
// inline-обработчик исполняется в глобальной области: открываем ему функции из вырезки.
if (typeof toggleProviderBtn === 'function') globalThis.toggleProviderBtn = toggleProviderBtn
if (typeof toggleProvider === 'function') globalThis.toggleProvider = toggleProvider

// То, что делает HTML-парсер с значением атрибута.
function decode(s) {
  return s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&')
}

const EVIL = "x');globalThis.pwned=1;//\"><img src=x onerror=alert(1)>&amp; \\"
catalogData = [{ id: EVIL, name: 'n', type: 'free', enabled: true, node_count: 1, trust_score: 0.5, speed_class: 'fast', last_updated: '2026-01-01T00:00:00Z' }]
renderCatalog()

;(async function() {
  const m = /<button[^>]*?data-id="([^"]*)"[^>]*?data-enabled="([^"]*)"[^>]*?onclick="([^"]*)"/.exec(html)
  if (!m) { console.log(JSON.stringify({ error: 'кнопка с data-id/data-enabled/onclick не найдена', html: html })); return }
  const onclick = decode(m[3])
  const fake = { dataset: { id: decode(m[1]), enabled: decode(m[2]) } }
  await new Function(onclick).call(fake)
  await new Promise(function(r) { setTimeout(r, 20) })
  console.log(JSON.stringify({
    evil: EVIL, onclick: onclick, dataID: fake.dataset.id,
    rawImgInHTML: html.indexOf('<img') >= 0, pwned: globalThis.pwned === 1, fetched: fetched,
  }))
})().catch(function(e) { console.error(String(e && e.stack || e)); process.exit(1) })
`

func TestWebUI_CatalogButtonDoesNotSpliceProviderIDIntoJS(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node не найден в PATH — поведенческая проверка JS Web UI пропущена")
	}
	s := newTestServer(t)
	w := httptest.NewRecorder()
	s.apiUI(w, httptest.NewRequest("GET", "/", nil))
	page := w.Body.String()

	// esc() — одна строка; renderCatalog + toggleProviderBtn + toggleProvider идут подряд до doCatalogRefresh.
	escStart := strings.Index(page, "function esc(s){")
	if escStart < 0 {
		t.Fatal("не нашли function esc в странице")
	}
	escEnd := escStart + strings.Index(page[escStart:], "\n")
	a := strings.Index(page, "function renderCatalog(){")
	b := strings.Index(page, "async function doCatalogRefresh()")
	if a < 0 || b < 0 || b < a {
		t.Fatalf("не нашли границы renderCatalog..doCatalogRefresh (a=%d b=%d)", a, b)
	}
	snippet := page[escStart:escEnd] + "\n" + page[a:b]

	dir := t.TempDir()
	snipPath := filepath.Join(dir, "snippet.js")
	harnessPath := filepath.Join(dir, "harness.js")
	if err := os.WriteFile(snipPath, []byte(snippet), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(harnessPath, []byte(providerIDHarness), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	stdout, err := exec.CommandContext(ctx, node, harnessPath, snipPath).Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("node завершился с ошибкой: %v\nstderr: %s\nstdout: %s", err, stderr, stdout)
	}

	var res struct {
		Error        string `json:"error"`
		HTML         string `json:"html"`
		Evil         string `json:"evil"`
		Onclick      string `json:"onclick"`
		DataID       string `json:"dataID"`
		RawImgInHTML bool   `json:"rawImgInHTML"`
		Pwned        bool   `json:"pwned"`
		Fetched      []struct {
			URL  string `json:"url"`
			Body struct {
				ID      string `json:"id"`
				Enabled bool   `json:"enabled"`
			} `json:"body"`
		} `json:"fetched"`
	}
	if err := json.Unmarshal(stdout, &res); err != nil {
		t.Fatalf("не разобрали JSON со stdout node: %v\n%s", err, stdout)
	}
	if res.Error != "" {
		t.Fatalf("%s\n%s", res.Error, res.HTML)
	}
	if strings.Contains(res.Onclick, "x'") || strings.Contains(res.Onclick, "pwned") || strings.Contains(res.Onclick, res.Evil) {
		t.Errorf("onclick содержит фрагмент ID: %q", res.Onclick)
	}
	if res.Pwned {
		t.Error("ID провайдера выполнился как код (globalThis.pwned установлен)")
	}
	if res.RawImgInHTML {
		t.Error("в HTML карточки остался неэкранированный <img> из ID")
	}
	if res.DataID != res.Evil {
		t.Errorf("data-id после разбора браузером = %q, ожидалось исходное %q", res.DataID, res.Evil)
	}
	if len(res.Fetched) != 1 || res.Fetched[0].Body.ID != res.Evil || res.Fetched[0].Body.Enabled {
		t.Errorf("на сервер ушло %+v, ожидался один запрос с исходным ID и enabled=false (провайдер был включён)", res.Fetched)
	}
}

// Статическая страховка: ID/имя не вставляются в onclick внутри JS-строки ни в одном месте страницы
// (esc() даёт &#39;, а парсер HTML раскодирует его обратно в апостроф до выполнения JS).
func TestWebUI_NoIDSplicedIntoOnclickJS(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	s.apiUI(w, httptest.NewRequest("GET", "/", nil))
	page := w.Body.String()
	bs := string(rune(92))
	// Любой обработчик on...="..." со СКЛЕЙКОЙ значения в JS-строку (а не только onclick с id первым
	// аргументом: формы fn(this,'id'), onchange, oninput и т.п. устроены так же опасно). Склейка выглядит
	// как «обратная косая, кавычка, кавычка, плюс» (или плюс, кавычка, обратная косая, кавычка) внутри
	// значения атрибута; строковые константы вроде fetch(B+<кавычка>/api/x<кавычка>) - не склейка.
	q := regexp.QuoteMeta(bs)
	bad := regexp.MustCompile(`on[a-z]+="[^"]*(` + q + `''\s*\+|\+\s*'` + q + `')`)
	if locs := bad.FindAllStringIndex(page, -1); len(locs) > 0 {
		first := page[locs[0][0]:min(locs[0][0]+120, len(page))]
		t.Errorf("в странице осталось %d мест, где значение вставляется в onclick внутри JS-строки, например: %s", len(locs), first)
	}
}
